[< ZTA Integration](zta-integration.md)

# ZTA: Python Parity

The canonical ZTA design and contract live in [zta-integration.md](zta-integration.md);
that document specifies the verifier interface (§5), verification statuses (§5), identity
binding (§6), policy configuration (§7), DDIL fallback, and the admission semantics (§11).
This companion documents the **Python implementation** that brings `idprocess.py` to
parity with the C subsystem — closing the gap recorded in zta-integration.md §15.3
("The current ZTA integration is C-only").

The Python side mirrors the C semantics field-for-field and reason-string-for-reason-string
so that a peer presenting the same credential is admitted-or-rejected identically by either
implementation, and so the conformance corpus can pin the behavior symmetrically.

## 1. Module layout

New package `src/autonomous-trust/autonomous_trust/core/_python/identity/zta/`:

| File | Mirrors (C) | Contents |
|------|-------------|----------|
| `zta_verifier.py` | `zta_verifier.h`, `x509_verifier.{h,c}` | `ZtaStatus` enum, `ZtaResult`, `Verifier` ABC, `NullVerifier`, `X509Verifier` |
| `zta_policy.py` | `zta_policy.{h,c}` | `ZtaPolicy` dataclass + `to_json`/`from_json` + `create_verifier()` |
| `__init__.py` | — | re-exports |

`ZtaStatus` values match C `zta_status_t` exactly: `VERIFIED`, `REJECTED`, `DEFERRED`,
`EXPIRED`, `REVOKED`, `UNAVAILABLE`. `ZtaResult` carries `status`, `reason`,
`credential_hash` (32-byte SHA-256), `ttl_sec`.

## 2. X509Verifier (cryptography, not OpenSSL CLI)

The C `x509_verifier.c` uses OpenSSL `X509_STORE` + `X509_verify_cert`. The Python mirror
uses `cryptography` (pyca) and reproduces the same decision order as
`x509_verify_credential`:

1. No credential bytes → `REJECTED` "no credential data".
2. Parse cert (try DER, then PEM) → on failure `REJECTED` "failed to parse X.509 certificate".
3. Compute `credential_hash` = SHA-256 of the DER encoding (identity binding).
4. Expiry check first, for a distinct status → `EXPIRED` "certificate has expired".
5. Chain validation against the CA bundle → `VERIFIED` "certificate chain verified", else
   `REJECTED` with a reason.

**Chain validation** matches the OpenSSL `X509_STORE` model where *every* cert in the CA
bundle (root **and** intermediate) is a trusted anchor: load all bundle certs into a
subject-indexed store; from the leaf, find the cert whose subject equals the current cert's
issuer, verify the signature with `cert.verify_directly_issued_by(issuer)` and each cert's
validity window, and accept once an issuer that is itself in the store (a trusted anchor) is
reached. Depth-bounded. This admits leaf→intermediate(anchor) and leaf→intermediate→root
chains and rejects unknown-issuer certs — verified against the existing test CA
(`src/c/test/zta_test_ca/output/`: `drone_alpha`→VERIFIED, `unknown_ca`→REJECTED,
`expired`→EXPIRED).

`NullVerifier` always returns `VERIFIED` (the runtime-disabled path, per §5).

**OCSP/CRL** are optional in both implementations (empty `ocsp_url`/`crl_path` disables
them). The Python `check_revocation` supports a CRL file (serial-number match → `REVOKED`,
else "CRL loaded; not revoked") and treats an unreachable/unset OCSP responder as
`UNAVAILABLE`, mirroring C. The admission gate (§4) calls only `verify_credential`; OCSP-
backed live revocation during periodic re-verification is a documented follow-up (there is
no Python ZTA *process* yet — see §6).

## 3. Identity binding / wire parity

C serializes the ZTA fields into `identity.proto` fields 6–8 (`identity.c:349–398`); Python
`Identity` previously ignored them. Phase 2 adds `zta_credential` / `zta_issuer` /
`zta_credential_hash` to `Identity.__init__`, `publish()`, `sync_to_message()`, and
`sync_from_message()` so the credential rides the announce/propose/confirm payloads exactly
as on the C side. A node loads its own credential from its config dir at identity init.

## 4. Admission gate

Inserted in `idprocess.py:welcoming_committee`, in the `announce` branch, **after**
`id_obj.validate()` and **before** the `peer_potentials` cache / `propose` broadcast — the
position-mirror of the C gate in `id_proc.c:handle_welcoming_committee`. The policy is
loaded from the process configurations under key `"zta_policy"` (same key C uses). Behavior
follows zta-integration.md §11:

- policy absent / `enabled` false / `require_at_admission` false → gate is a no-op.
- `VERIFIED` → proceed to propose, no reputation cap.
- `DEFERRED` / `UNAVAILABLE` → if `allow_ddil_fallback`, admit but tag the peer for the
  `ddil_fallback_reputation_cap`; else drop.
- `REJECTED` / `EXPIRED` / `REVOKED` → drop (return handled, no propose).

Observability: `_probes` emit/counter on `id.welcome` (`zta_verified` / `zta_rejected` /
`zta_deferred`) so the conformance adapter can assert an `admitted` / `zta_status`
observable.

## 5. Configuration

`ZtaPolicy` is a `Configuration` subclass loaded from `zta_policy.cfg.json` with the same
field names/defaults as the C `zta_policy_t` (zta-integration.md §7). When the file is
absent the policy defaults to disabled, so existing deployments are unaffected.

## 6. Scope vs. the C subsystem

This brings Python to parity for the **admission decision** (verify at join, DDIL fallback,
reputation cap) and wire binding. Not (yet) ported, and explicitly out of scope here:
the background **ZTA process** (periodic re-verification, revocation alerts, delegated
verification / distributed PDP — zta-integration.md §8–9) and the **audit log** (§10).
These remain C-only; the Python gate logs decisions through the standard logger. Porting
them is a follow-up tracked in zta-integration.md §15.

## 7. Conformance

Identity scenarios under `conformance/scenarios/identity/` pin the admission decision on
both sides: `zta-x509-admit-valid`, `zta-x509-reject-unsigned`,
`zta-x509-reject-untrusted-issuer`, `zta-x509-reject-expired`, `zta-ddil-defer`. Fixtures
load the `zta_policy` + CA bundle and attach a per-participant credential (reusing the test
CA certs); the adapters assert an `admitted` / `zta_status` observable. Schema stays `"1"`.
The C conformance runner must be built with `-DAT_ZTA=ON` for these to run on the C side.

[ZTA Integration >](zta-integration.md)
