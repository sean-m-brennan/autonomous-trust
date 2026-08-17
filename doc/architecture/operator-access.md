*Previous: [Reputation against blockchain](reputation-vs-blockchain-analysis.md)*

# Operator Access (PIV + MFA)

How a **human operator** authenticates to an AutonomousTrust fleet with a
PIV/CAC smartcard plus a second factor, activates a local node, discovers what
the fleet can do, and issues requests, all from a terminal UI. This is the
human-facing counterpart to peer admission ([ZTA
Integration](zta-integration.md)). The same verifier machinery that decides
whether a *peer* may join also decides whether a *person* may operate, with a
challenge-response and a second factor layered on top. What the operator path
adds to what a peer must show is possession, knowledge, and liveness.

The implementation plan is `doc/NV059/work/PIV_MFA_OPERATOR_ACCESS_PLAN.md`
(phases P0-P6). This document describes the shipped design.

---

## 1. Why a separate access path

A peer proves it is a legitimate node by presenting a credential the border
guard can chain to a trusted CA (see [ZTA Integration §11](zta-integration.md)).
A human operator needs more.

1. **Possession + knowledge.** A certificate on a card proves the card exists.
 The operator must additionally prove they hold the card *now* (the private
 key never leaves it, PKCS#11 sign-only) and know a PIN or second factor. A bare
 cert on the wire cannot prove liveness.
2. **A non-replayable challenge.** Peer admission accepts a static credential,
 while operator activation must defeat replay, so it binds a fresh, single-use,
 TTL'd nonce to the AT identity and requires a signature over it.
3. **Continuous session posture.** A peer, once admitted, is governed by
 reputation. An operator session must additionally lock on card removal, time
 out when idle, and force step-up re-authentication for privileged actions.
4. **Request-only role.** The operator node registers **no serving
 capabilities**, consuming capabilities from the fleet and providing none. This
 keeps the operator node from becoming a dependency other peers rely on.

The design reuses the audited verifier stack rather than forking it. A
`PivVerifier` is a **strict superset** of `X509Verifier`. A bare cert verifies
chain-only, which is the peer path, and a PIV envelope additionally requires the
challenge-response, which is the operator path. So `verifier_type="mfa"` with a PIV
factor serves **both** peer admission and operator activation with no change to
the admission gate.

---

## 2. Architecture

```
   ┌──────────────────────────────────────────────────────────┐
   │  Terminal UI  (src/autonomous-trust-operator/, Textual)   │
   │   Activate · Directory · Request · Activity · Status       │
   └───────────────┬───────────────────────────▲──────────────┘
                   │ external_control (Tasks)   │ external_feedback
                   │                            │ (ResourceDirectory, TaskResult)
        ┌──────────▼────────────────────────────┴───────────┐
        │  OperatorNodeBridge  (Inspector pattern)            │
        │  node runs in a daemon thread; UI only sees queues  │
        └──────────┬────────────────────────────▲────────────┘
                   │                             │
        ┌──────────▼─────────────────────────────┴───────────┐
        │  OperatorNode : AutonomousTrust  (request-only)     │
        │   PIV+MFA activation · session · resource directory │
        └─────────────────────────────────────────────────────┘
```

The split mirrors the existing **Inspector** pattern. The AT node runs in its
own thread or process, the UI never imports AT internals, and the UI drains
DTO-shaped objects off `external_feedback` and pushes `Task` DTOs onto
`external_control`.
This keeps the (synchronous, Textual) UI decoupled from the message loop and
makes every screen testable headless.

Two distributions carry it.

- **`core/_python/operator/`.** The node-side core (activation, session, DDIL
 posture, resource directory, `OperatorNode`). Imports as
 `autonomous_trust.core.operator`. No UI dependency.
- **`src/autonomous-trust-operator/`.** The Textual TUI (`autonomous_trust.
 operator`): app, screens, node bridge. Depends on the core but not vice-versa.

---

## 3. PIV verifier and the challenge-response

The `identity/zta/piv/` package holds two modules.

- **`pkcs11.py`.** `PivToken` ABC with two implementations, `PyKcs11Token`
 (lazy `PyKCS11`, PIV auth slot 9A, `CKA_ID` `0x01`, EC raw→DER signature
 conversion) for a real card and `SoftwareToken` (pure `cryptography`) for
 dev/CI/no-hardware. The token signs a nonce, and the private key never leaves
 it. Also `probe_token()`, a **PIN-less** card-present probe.
 `find_pkcs11_module()` resolves the module from an explicit path, an
 environment variable, and a search, in that order, and the probe returns a
 `TokenProbe(present, module_path, detail)`. `PyKcs11Token` cannot answer
 presence pre-PIN because its constructor logs in, so the status line on the
 console uses the probe and shows `detail` to distinguish a missing
 module or binding from an empty reader.
- **`piv_verifier.py`.** `PivVerifier` + `PivCredential` (a length-prefixed
 envelope of cert / nonce / signature).

The activation flow runs in three steps.

1. The verifier issues a **challenge**, a fresh random nonce bound to the AT
 identity id and stamped with a TTL. It is single-use (consumed on
 verification) and expires.
2. The token signs the nonce (RSA-PKCS1v15 or ECDSA, SHA-256).
3. `PivVerifier.verify_credential` unpacks the envelope, then
 - delegates **chain + expiry + revocation** verbatim to `X509Verifier`,
 - consumes the challenge (rejecting replayed, expired, or
 wrong-identity nonces),
 - and verifies the signature against the public key in the cert.

A bare cert (no envelope) skips steps 1-3 and runs chain-only, which is the peer
path. A
DER cert begins `0x30 0x82…`, never the `0x0000…` length prefix of an envelope,
so the two forms never alias.

The identity binding of the credential is `zta_credential_hash = SHA-256(cert DER)`,
stable across second-factor rotation and excluded from identity equality (so
rotating the second factor is not a new identity). See [ZTA Integration
§6](zta-integration.md).

---

## 4. MFA chain

`identity/zta/mfa.py` provides `MfaChain(Verifier)` with `CombinePolicy.AND`.

- **AND semantics.** All factors must be `VERIFIED`, the first
 `REJECTED`/`EXPIRED`/`REVOKED` short-circuits, and any `DEFERRED`/`UNAVAILABLE`
 yields `DEFERRED` (fail-safe handoff to DDIL posture, never a silent pass).
- **Composite credential** (`MfaCredential`, magic-prefixed `MFA1` + one blob per
 factor). On a composite, blob *i* dispatches to factor *i* and **all** factors
 are required. On a **bare** credential, meaning a wire cert from a peer, only
 the primary factors run, and secondary factors (`secondary_factor=True`, e.g.
 TOTP) are skipped. One chain therefore serves both operator activation (composite, all
 factors) and peer admission (bare, primary only).
- **Hash passthrough.** The combined `credential_hash` is always that of the
 **primary** (first) factor, so identity binding is stable regardless of
 second-factor rotation. `check_revocation` likewise delegates to the primary factor.

The second factor is **TOTP** by default (`identity/zta/totp.py`, `pyotp`, RFC
6238), which is DDIL-friendly (no IdP round-trip) and independent of the PIV
IdP. OIDC and FIDO2 are configured alternatives and future work.

Policy wiring lives in `zta_policy.py`, where `verifier_type="mfa"` takes a
`factors` list and `_build_factor` constructs each factor
(`x509`/`piv`/`totp`/`oidc`, unknown → `NullVerifier`). The additions are
additive and optional. The C policy parser ignores unknown keys, so this is
parity-safe.

---

## 5. Activation and identity binding

`operator/activate.py` (+ `__main__.py` CLI) binds a verified credential to the
local node.

- `bind_piv_credential` / `bind_identity_file` write `zta_credential`,
 `zta_credential_issuer`, and `zta_credential_hash` into the node `Identity`.
- `write_operator_policy` emits the operator `zta_policy` (request-only role,
 DDIL relay flags).
- `activate(token, …, totp_secret, totp_code)` runs the **real** challenge-
 response, AND-verifying the PIV envelope and TOTP code through the chain. A
 missing or invalid second factor → `REJECTED`. `enroll_totp` /
 `load_totp_secret` persist the TOTP secret in the TOTP factor of the policy.

The CLI dev path is `--software-cert` / `--software-key`, which activate via
`SoftwareToken` with no card. **Note.** `python -m
autonomous_trust.core.operator` fails, because the loader in the backend
redirector has no `get_code` for runpy. Use the concrete
`autonomous_trust.core._python.operator` for `-m`.

---

## 6. Session lifecycle

`operator/session.py` defines `OperatorSession`, clock-injectable for tests.

| Event | Behavior |
|---|---|
| **Card removal** (`is_available()` → False) | Lock the session and **zeroize** in-memory secrets immediately. |
| **Idle timeout** | Lock after `idle_timeout`. |
| **Step-up** | A request whose `required_tier ≥ step_up_tier` forces a fresh PIV challenge before it dispatches. The first high-tier request always steps up (`_last_step_up=None` sentinel). |
| **Periodic re-verify** | Re-run verification every `reverify_interval_sec`. |

`authorize(...)` returns a `RequestDecision` of `ALLOW`, `STEP_UP_REQUIRED`, or
`LOCKED`. The PIN is held only to open the PKCS#11 session and is never
persisted.

---

## 7. DDIL posture

`operator/ddil.py` provides `evaluate_operator_posture(validation_state,
allow_relay, priv_requires_full)`, returning `OperatorPosture(tier_cap,
privileged_allowed)`.

- **DIRECT** validation, or a **sanctioned RELAYED** validation through a
 connected gateway → uncapped standing, privileged origination allowed.
- **NONE**, or an unsanctioned relay → capped at tier 1 (presence/communication),
 privileged origination blocked **until** validation completes (direct or
 relayed).

This is **fail-safe and hierarchy-relayed**. It prefers delegated PIV validation
over a connected gateway (`operator_allow_ddil_relay`), and absent any relay
path it caps rather than hard-denies, never failing open and never failing
closed bluntly. The posture turns on validation, relay, and standing. It is stricter than the `allow_ddil_fallback` of peer admission,
which may admit a reputation-capped peer, because an operator *originates*
privileged actions.

---

## 8. Resource directory

`operator/resource_directory.py` is a **pure read-model**: `build_directory(
descriptors, providers, peers, my_tier)` → a `ResourceDirectory` of
`Resource{name, kind, description, required_tier, arg_schema, providers[],
my_reach}`.

`my_reach` ∈ {`INVOKABLE`, `LOCKED_BY_TIER`, `UNKNOWN`}. Tier gating is
**execution-time only**, so locked resources are **shown, not hidden**. The
operator can see what exists and what standing it would take to invoke it.

`operator/operator_node.py`:

- `directory_from_state(...)` is a pure adapter from live node state
 (local capabilities, peer capabilities, peers, tier, reputations, online uuids)
 to a directory snapshot (tested with duck-typed fakes).
- `OperatorNode(AutonomousTrust)` is the request-only node. It drains
 `PeerCapabilities` from unhandled messages, emits directory snapshots on
 `external_feedback`, and issues a directed `caps_query` sweep on
 `request_caps_refresh`.

### Capability descriptors on the wire

Capabilities now carry optional runtime descriptor fields
(`description`/`kind`/`arg_schema`). On the wire, `caps_response` becomes a JSON
**array of descriptor objects** (`{name, required_tier, description, kind,
arg_schema}`), but the receiver is **tolerant**, since each item may be a bare
name string (legacy) or a descriptor object, so the change is
backward-compatible.
All fields are bounded and sanitized on both emit and receive (untrusted peer
input is clamped, not rejected). The proto/persist wire form is unchanged, and
descriptors are runtime-only and excluded from serialization. This lets
remote-only capabilities carry a known `required_tier` so the directory can
compute reach instead of forcing `UNKNOWN`. Pinned cross-language by conformance
`peer-caps-descriptor-exchange` (including over-limit boundary cases). See [ZTA
Python Parity](zta-python-parity.md) for the parity discipline this follows.

---

## 9. Request submission and results

`RequestView` (TUI) auto-renders an argument form from the `arg_schema` of a
resource, coerces inputs to the declared types, and gates **submit** on
`my_reach` (tier-locked resources are visible but non-submittable) and on the
session.

`app.submit_request` runs the session authorization.

- `ALLOW` → build a `Task` DTO (injectable `task_builder`) and put it on
 `external_control`.
- `LOCKED_BY_TIER` / `LOCKED` → refused with a reason.
- `STEP_UP_REQUIRED` → route to Activate; after a fresh MFA challenge
 (`complete_step_up`) the pending request auto-resubmits.

`ActivityView` is a UUID-keyed ledger of every submitted task and the
`TaskResult` that returns, with a proof-verification badge
(`TaskResult.verify_proof()`) and round-trip latency. Out-of-order or unmatched results surface as their own row
rather than being dropped.

---

## 10. Terminal UI

`src/autonomous-trust-operator/` is a tabbed Textual `OperatorApp` over
`OperatorNodeBridge`.

| Screen | Purpose |
|---|---|
| **Activate** | PIN + MFA entry; clear pass/fail and failure-reason messaging. |
| **Directory** | Filterable resource table + provider drill-down (survives periodic re-renders). |
| **Request** | Resource picker → dynamic arg form → submit (tier-locked = non-submittable). |
| **Activity** | Live submitted-task / result ledger with proof badges + latency. |
| **Status** | Node/session/directory summary. |

**Framework gotcha.** A view method named `_render` overrides
`textual.widget.Widget._render` (the Visual producer) and crashes reflow on tab
re-show. The status helper is named `_render_status`, not `_render`.

---

## 11. Testing (and the live-card boundary)

The two artifacts that gate a *real* DoD CAC/PIV (the issuing-CA bundle (DoD
Root + DoD ID CA-xx intermediate) and a live CRL/OCSP source) are
program-environment-only. So **all development and CI run against a self-minted
test PKI**; validating a real card against the real DoD chain is a
program-environment step, not a local one (plan §7.1).

Staging keeps the live card as the last variable.

1. **Unit.** Mint CA, leaf, and CRL with a test PKI and drive
 `X509Verifier`/`PivVerifier`/`MfaChain`/`TotpVerifier` directly. No card, no
 daemon. (`tests/a_unit/test_piv_verifier.py`, `test_mfa.py`, `test_totp.py`,
 `test_operator_session.py`, `test_operator_ddil.py`,
 `test_resource_directory.py`, `test_operator_node.py`.)
2. **Software token.** `SoftwareToken` stands in for the PKCS#11 module, and the
 operator package assembles a usable mock in `operator/demo.py`
 (`mint_demo_pki`, `software_activator`, a `DemoNode` that serves a seeded
 directory and answers `Task`s with synthetic `TaskResult`s). `--demo`
 activates (real challenge-response), browses, submits, and shows results with
 zero card/cohort/network. The live card later is just a swap of the PKCS#11
 module path + slot.
3. **Live card.** OpenSC/vendor module + reader + the real issuing-CA bundle of the card,
  + PIN, inside the program environment.

The Textual screens are covered by headless Pilot tests
(`tests/a_unit/test_operator_tui.py`). Demo PIN and MFA are both ignored, since a
software token has no PIN and no TOTP is enrolled, so just press Activate.

### Revocation at admission (P6)

A chain-valid but **revoked** certificate previously still admitted, because the
admission gate called only `verify_credential` (chain + expiry), never
`check_revocation`. As of P6 the gate checks chain, expiry, and
revocation, calling `check_revocation` after a `VERIFIED` result on both the
Python (`idprocess._zta_admit`) and C (`welcoming_committee`) sides. Only an affirmative `REVOKED` blocks, and
`UNAVAILABLE` (no CRL/OCSP configured) still admits. Pinned cross-language by
conformance `zta-x509-reject-revoked-credential`. See [ZTA Integration
§11](zta-integration.md).

---

## 12. Security considerations

- PIV private key **never leaves the card** (PKCS#11 sign-only), and the PIN is
 held only to open the session, never persisted.
- **Challenge nonce** is fresh, single-use, identity-bound, and TTL'd (replay
 defense).
- **Factor independence.** TOTP does not share an IdP with PIV, so one IdP
 cannot gate both factors.
- **Identity binding** via `zta_credential_hash` prevents transferring a
 credential to another AT identity, and it is excluded from equality so
 rotation ≠ new identity.
- **DDIL posture is fail-safe.** Prefer hierarchical relay, otherwise cap at
 tier 1 and block privileged origination, never failing open and never a blunt
 deny.
- **Secret zeroization** on logout / card removal / idle lock.
- **Revocation is enforced at admission** (§11), so a revoked operator or peer
 credential is rejected, not merely logged.
- Untrusted peer descriptor input is **bounded and sanitized** (clamped, not
 rejected) on both emit and receive.
- Run `/security-review` on the diff before merge.

---

## References

- `doc/NV059/work/PIV_MFA_OPERATOR_ACCESS_PLAN.md`: implementation plan (P0-P6).
- [ZTA Integration](zta-integration.md): peer admission, verifier interface,
 policy, the admission gate.
- [ZTA Python Parity](zta-python-parity.md): the Python↔C parity discipline the
 verifier and descriptor work follow.
- [Identity Protocol](identity-protocol.md): Phase 3 border-guard admission.
- [Trust Tiers](trust-tiers.md): the tier gradient that gates resource reach.
- NIST SP 800-73 (PIV), RFC 6238 (TOTP), NIST SP 800-207 (ZTA).

---

*Next: [The app-facing peer carrier](app-peer-carrier.md)*
