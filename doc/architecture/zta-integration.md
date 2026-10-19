*Previous: [The dual implementation](native-ffi-dual-implementation.md)*

# Zero Trust architecture integration

## 1. Why certificate management is not enough

Certificate-based trust is the foundation of Zero Trust Architecture (ZTA). NIST
SP 800-207 defines ZTA around a Policy Decision Point (PDP) that verifies
identity via certificates for every access request [1]. This creates a
dependency chain.

```
Trust -> PDP decision -> Identity verification -> Certificate validation -> CA/OCSP/CRL availability
```

Break any link (the CA is unreachable, the OCSP responder is down, the CRL is
stale) and trust collapses. SP 800-207 acknowledges this in S5.2
(Denial-of-Service or Network Disruption): "Enterprise resources cannot connect
to each other without the PA's permission," and an attacker who "disrupts or
denies access to the PEP(s) or PE/PA... can adversely impact enterprise
operations" [1]. The standard offers replication/cyber-resiliency as the
mitigation, but that still requires connectivity to at least one instance.

This is not an implementation bug. It is structural, and it has three parts.

1. **Certificate state is binary.** Valid or invalid. No gradient, no "trusted for low-risk but not high-risk operations."
2. **Validation requires connectivity to a central authority.** OCSP, CRL, and PDP queries all need real-time access to infrastructure that may be unreachable.
3. **Credentials prove identity, not behavior.** A valid certificate proves identity was verified at issuance time. It says nothing about current behavior. A compromised endpoint with valid credentials passes every certificate check.
4. **Revocation is inherently delayed.** Even in well-connected environments, revocation propagation takes time. In DDIL environments, it may take hours or days.

In connected enterprise environments, certificate management is already painful:
77% of organizations experienced certificate-related outages in a 24-month
period, with an average cost of $11.1 million per organization per year [2][3].
High-profile failures (Equifax 2017, Ericsson/O2 2018, Let's Encrypt root expiry
2021) occur with full connectivity to certificate infrastructure [4][5][6].

### Where it breaks entirely

**Tactical/DDIL environments.** The DoD CRL can exceed 50 MB, and tactical
SATCOM links at 9.6-256 kbps cannot reliably download it [7]. Tactical edge systems
frequently lose connectivity to OCSP responders and must choose between
fail-open (insecure) and fail-closed (mission denial) [8].

**Space and DTN.** One-way light time to Mars ranges from 4 to 24 minutes. A
certificate rotation requiring two round-trips takes 1-4 hours minimum. BPSec
(RFC 9172) defers key management entirely: "Key management is outside the scope
of this document" [9]. Current space missions use manual key rotation via
limited ground contact windows, with no in-flight revocation mechanism [10].

**Multi-agency operations.** The Federal PKI involves hundreds of
cross-certifications [11]. When cross-certifications lapse, trust paths between
agencies break. In disaster response or coalition operations, each participant
brings its own PKI, and interoperability depends on fragile bridge CAs.

The trend is worsening. The CA/Browser Forum has proposed 47-day certificate
lifetimes by 2029 (Ballot SC-081) [12], multiplying the operational burden 4-8x
and the frequency of potential failure points proportionally.

---

## 2. The layered architecture: ZTA + AT

ZTA and AT are complementary layers, not alternatives. ZTA opens the door, and
AT decides what happens inside the room.

| | Zero Trust | AutonomousTrust |
|---|---|---|
| **Evaluates** | Credentials, device posture, context | Behavior over time |
| **Trust model** | Binary (allow/deny) | Continuous gradient (0.0-1.0) |
| **Adapts** | When policies are updated by humans | Continuously, autonomously |
| **Fails when** | PDP is unreachable or wrong | Never fully, degrades gracefully |
| **Scales via** | More policy rules | More peer observations |

A peer needs valid ZTA credentials to reach an AT agent (satisfying the
mandate), but once connected, AT takes over. The certificate is no longer the
operative trust boundary. Behavioral reputation is. A ZTA-authenticated peer
enters the network at neutral reputation (0.5) and must earn higher trust
through demonstrated behavior. Authentication is not trust.

### Failure mode transformation

| Certificate Failure | ZTA-Only Impact | ZTA + AT Impact |
|---|---|---|
| **Expired cert** | Service outage | Brief re-authentication; AT reputation persists across the renewal |
| **Compromised cert** | Full access until revocation propagates | Attacker has neutral reputation (new identity) or divergent behavior (existing identity), AT detects it |
| **CA compromise** | Catastrophic trust collapse across all relying parties | AT trust is independent of CA; network continues on behavioral trust |
| **OCSP/CRL unreachable** | Fail-open (insecure) or fail-closed (outage) | AT trust evaluation continues unimpaired |
| **PDP unavailable** | Enterprise operations impacted; PA's permission required to connect (SP 800-207 S5.2) | AT peers continue operating on behavioral trust |
| **Cross-cert lapse** | Inter-agency authentication fails | AT trust between peers persists; re-established when connectivity returns |
| **Stale cached revocation** | False sense of security | AT behavioral scoring detects changed behavior regardless of credential state |

### AT-informed certificate management

The AT reputation signal can inform automated certificate lifecycle decisions:

- **Strong AT reputation + expiring cert.** Auto-renew with confidence (behavior is verified, risk is low)
- **Degrading AT reputation + valid cert.** Flag for scrutiny, shorten cert lifetime, or investigate
- **Post-rotation re-authentication.** AT reputation carries over, minimizing disruption
- **Bandwidth-constrained CRL distribution.** Prioritize CRL delivery to peers with low/declining AT reputation; high-reputation peers can safely operate with stale revocation data

---

## 3. Design principles

1. **ZTA remains mandatory when available.** AT does not override or bypass ZTA: it extends it.
2. **AT provides continuity when ZTA fails.** The value proposition is graceful degradation, not ZTA replacement.
3. **Credential state informs reputation, not the reverse.** ZTA revocation penalizes AT reputation. AT reputation can inform cert lifecycle decisions. Neither layer unilaterally controls the other.
4. **Configuration, not hardcoding.** Different deployments (enterprise, tactical, space) have different ZTA availability profiles. The integration must be tunable.
5. **Honest about gaps.** When operating without ZTA verification, the system logs it rather than pretending verification happened.

---

## 4. Architecture overview

The ZTA subsystem is compiled conditionally via `AT_ZTA=ON` in CMake, which
defines `AT_ZTA_ENABLED` globally. When compiled in, it can be enabled or
disabled at runtime via `zta_policy.cfg.json`. When disabled at runtime, all ZTA
code paths are no-ops.

```
+------------------+     +-----------------+     +------------------+
| Identity Protocol|---->| ZTA Verifier    |---->| ZTA Audit Log    |
| (admission)      |     | (pluggable)     |     | (JSONL)          |
+------------------+     +-----------------+     +------------------+
         |                    |       |
         v                    v       v
+------------------+     +-------+ +-------+
| Reputation System|     | X.509 | | OIDC  |
| (behavioral)     |     +-------+ +-------+
+------------------+
         ^
         |
+------------------+
| ZTA Process      |
| (periodic re-    |
|  verification)   |
+------------------+
```

### Key design decisions

1. **Master switch.** ZTA can be compiled in but disabled at runtime. This allows a single binary to serve both ZTA-mandated and non-ZTA deployments.
2. **Pluggable backends.** The verifier interface (`zta_verifier_t`) is a vtable with function pointers. New credential types (SAML, JWT, etc.) can be added without modifying core code.
3. **Reputation integration.** ZTA verification results feed into the reputation system as one signal among many, not a binary kill switch. A revocation applies a configurable reputation penalty; it does not forcibly disconnect the peer.
4. **DDIL fallback.** When verification infrastructure is unreachable, peers can still be admitted with a reputation cap, preserving network formation in disconnected environments.
5. **Audit trail.** Every verification attempt, deferral, and resolution is logged to a JSONL file for compliance review.

---

## 5. Pluggable verifier interface

The `zta_verifier_t` struct (`src/c/extensions/zta/zta_verifier.h`)
defines a vtable with five operations:

| Operation | Purpose |
|-----------|---------|
| `verify_credential` | Validate a credential (signature chain, expiry, revocation status) |
| `check_revocation` | Check if a previously verified credential has been revoked |
| `is_available` | Test whether verification infrastructure is currently reachable |
| `credential_hash` | Compute a deterministic SHA-256 hash for identity binding |
| `destroy` | Free verifier resources |

Any function pointer may be NULL; a NULL pointer is treated as returning
`ZTA_UNAVAILABLE`.

### Verification status

| Status | Meaning |
|--------|---------|
| `ZTA_VERIFIED` | Credential is valid and verified |
| `ZTA_REJECTED` | Credential is invalid (bad signature, unknown issuer) |
| `ZTA_DEFERRED` | Verification deferred (infrastructure unreachable, DDIL scenario) |
| `ZTA_EXPIRED` | Credential has expired |
| `ZTA_REVOKED` | Credential has been revoked |
| `ZTA_UNAVAILABLE` | Verifier cannot perform this operation |

### Backend implementations

**X.509 verifier** (`x509_verifier.h`): OpenSSL-based certificate verification
against a CA bundle (PEM). Supports optional OCSP responder and CRL file for
revocation checking. Configurable connection timeout (default 2000ms).

**OIDC verifier** (`oidc_verifier.h`): Stub for token-based credentials.
Currently returns `ZTA_UNAVAILABLE` for all operations. Validates the interface
design and provides a template for future token-based deployments.

**Null verifier.** Always returns `ZTA_VERIFIED`. Used when ZTA is compiled in
but disabled at runtime.

---

## 6. Identity binding

When ZTA is enabled, the `public_identity_t` struct (`identity.h`) carries
additional fields:

| Field | Type | Purpose |
|-------|------|---------|
| `zta_credential_hash` | `uint8_t[32]` | SHA-256 of the ZTA credential presented at admission |
| `zta_issuer` | `char[64]` | Credential issuer identifier |
| `zta_credential` | `uint8_t *` | Raw credential bytes (heap-allocated) |
| `zta_credential_len` | `size_t` | Length of the raw credential |

These fields are serialized in the identity protobuf (`identity.proto` fields
6-8) and exchanged during peer discovery. The credential hash provides a stable
binding between the AT identity (UUID + Ed25519 key) and the ZTA credential that
was valid at admission time.

Credential rotation updates the binding, and AT reputation is unaffected by
routine rotation. This is by design, since the behavioral trust history persists
across credential renewals.

---

## 7. Policy configuration

The `zta_policy_t` struct (`zta_policy.h`) is loaded from `zta_policy.cfg.json`:

```json
{
  "enabled": false,
  "require_at_admission": true,
  "reverify_interval_sec": 3600,
  "revocation_reputation_penalty": 0.8,
  "allow_ddil_fallback": true,
  "ddil_fallback_reputation_cap": 0.5,
  "audit_deferred_verifications": true,
  "delegated_verification_min_reputation": 0.7,
  "delegated_verification_quorum": 1,
  "verifier_type": "x509",
  "ca_bundle_path": "/etc/pki/tls/certs/ca-bundle.crt",
  "ocsp_url": "",
  "crl_path": ""
}
```

### Field reference

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Master switch. When false, all ZTA code paths are no-ops. |
| `require_at_admission` | bool | `true` | Require valid ZTA credential for peer admission. |
| `reverify_interval_sec` | int | `3600` | Periodic re-verification interval in seconds. 0 disables. |
| `revocation_reputation_penalty` | double | `0.8` | Reputation reduction applied on revocation (0.0-1.0 scale). |
| `allow_ddil_fallback` | bool | `true` | Allow admission when ZTA infrastructure is unreachable. |
| `ddil_fallback_reputation_cap` | double | `0.5` | Maximum reputation for peers admitted without ZTA verification. |
| `audit_deferred_verifications` | bool | `true` | Log deferred checks to the audit trail. |
| `delegated_verification_min_reputation` | double | `0.7` | Minimum reputation a peer must have for its delegated verification to be accepted. |
| `delegated_verification_quorum` | int | `1` | Number of independent delegated verifications required to lift a DDIL reputation cap. |
| `verifier_type` | string | `"x509"` | Backend to use: `"x509"`, `"oidc"`, or `"null"`. |
| `ca_bundle_path` | string | | Path to CA bundle (PEM) for X.509 verification. |
| `ocsp_url` | string | | OCSP responder URL. Empty string disables OCSP. |
| `crl_path` | string | | CRL file path. Empty string disables CRL checking. |

### Environment-specific tuning

**Enterprise** (full connectivity): Short `reverify_interval_sec` (300-900),
high `revocation_reputation_penalty` (0.9-1.0), `allow_ddil_fallback` false.

**Tactical/DDIL.** Moderate `reverify_interval_sec` (1800-3600),
`allow_ddil_fallback` true, `ddil_fallback_reputation_cap` 0.3-0.5. The AT
reputation gossip protocol uses minimal bandwidth compared to CRL distribution
(50+ MB DoD CRLs vs. compact reputation scores). Compromised-but-credentialed
assets are detected via behavioral divergence even when ZTA credentials are
valid. Reputation persists locally and converges via gossip when connectivity
resumes.

**Space/DTN.** Long `reverify_interval_sec` (7200+), `allow_ddil_fallback` true,
`ddil_fallback_reputation_cap` 0.5. Rely primarily on AT behavioral trust. AT
complements BPSec (RFC 9172) by adding the behavioral layer that BPSec
explicitly defers. BPSec answers "is this bundle authentic?" AT answers "should
we trust this relay?" A relay with valid BPSec credentials but degrading
forwarding reliability loses AT reputation and is routed around.

**Multi-agency.** The AT bilateral negotiation protocol handles
cross-organizational trust without requiring PKI interoperability or
cross-certification. New participants enter at neutral reputation regardless of
ZTA authentication status and earn trust through demonstrated behavior. When
cross-cert trust paths break, AT trust between peers persists, so authentication
can be re-established when connectivity returns without losing behavioral trust
history.

---

## 8. Delegated verification (distributed PDP)

In prolonged DDIL scenarios, no peer in the group may be able to reach ZTA
infrastructure (OCSP, CRL endpoints). Without mitigation, every DDIL-admitted
peer stays capped at `ddil_fallback_reputation_cap` indefinitely, preventing the
network from reaching full trust depth.

Delegated verification turns the AT group itself into a distributed Policy
Decision Point. A member whose own re-verification proves a peer's credential
tells the rest of the group (`zta_verified`, a *vouch*). A member whose own
check finds a credential revoked tells them too (`zta_revoked`, an *alert*).
Both runtimes send and act on both (ISSUES §2.20). The decisions live in one
pure module per runtime, `zta_delegation.{h,c}` and `zta/delegation.py`, and
the conformance scenarios `identity/zta-delegation-vouch` and
`identity/zta-delegation-alert` pin every verdict on both sides.

### Who hears a finding

The checks below apply to both verbs, in this order.

1. **The sender is a member of this node's group** (its group address map).
   The sender is the one the transport names. A finding carries no
   voucher field, so a payload cannot speak for someone else.
2. **The finding is about the credential this node recorded** for that peer.
   The credential hash must match the one on the peer's record here. A
   finding about a peer this node holds no credential for is ignored.
3. **The status fits the verb**: a vouch says `VERIFIED`, an alert says
   `REVOKED`.

### Vouches

A vouch counts only for a peer this node is waiting on: its own last check
could not answer (`UNAVAILABLE`/`DEFERRED`, the DDIL case). It counts only from
a member at or above `delegated_verification_min_reputation`. When
`delegated_verification_quorum` distinct members have vouched, the peer's
standing becomes `proved` and its DDIL ceiling lifts. This happens once.
Further vouches are `settled`.

1. Peer A admits Peer B in DDIL mode (reputation capped at 0.5).
2. Peer C reaches the OCSP responder and proves B's credential during its
   re-verification sweep. C sends `zta_verified` about B to every other member.
3. A checks that C is a member, that the hash is B's recorded credential, and
   that C's reputation is at or above the bar.
4. At quorum, A publishes `proved` for B, and B can earn reputation above 0.5.

A node vouches only for a peer whose credential it proved. A credential that
chains but is not bound under `binding_mode: prefer` stays `capped` here and is
not vouched for.

### Alerts

An alert is a hint, never a verdict. On receipt, this node re-checks the
peer's credential with its own verifier at once and acts on its own answer:

- `VERIFIED`: the alert changes nothing.
- `REVOKED` or `REJECTED`: the peer's standing becomes `failed` under the full
  `revocation_reputation_penalty`. `EXPIRED` costs half the penalty.
- No answer (DDIL): the alert is counted, from members at or above the
  reputation bar. At `delegated_verification_quorum` distinct alerters, the
  peer is bounded `capped` at `ddil_fallback_reputation_cap` until this node's
  own check settles it.

The re-check is not gated on the sender's reputation. It costs one verifier
lookup, and the answer is this node's own. Nothing rate-limits it yet.

This node's own answer, from an alert's re-check or from the sweep, clears
whatever vouches and alerts were counted for that peer.

### Trust gating

Delegated verification does not trust whoever relays a finding. The
`delegated_verification_min_reputation` threshold (default 0.7) sets the
reputation a member needs before its vouch or its alert counts. The node asks
its own reputation process (`local_rep_query` / `local_rep_response`, local
IPC) and caches the answer for 10 minutes. A finding that arrives before the
sender's reputation is known is held (32 at most) and offered again when the
answer comes. A `local_rep_response` that arrives off the wire is refused in
both runtimes. Before this, a member could forge one and set its own score past
the bar. The bar prevents two attacks:

- An attacker admitted in DDIL mode vouching for a confederate (the attacker's own reputation is too low).
- A recently compromised peer issuing findings while its reputation degrades.

The `delegated_verification_quorum` (default 1) can be raised for
higher-assurance environments. With quorum 3, three independent members must
each prove the credential before the cap lifts, so a single compromised
verifier cannot lift caps on its own.

### Audit trail

Findings from members are logged (INFO when counted or acted on, WARNING when
ignored, with the reason). They are not written to the ZTA audit log
(§10). This node's own deferred verifications and their resolution are.

### Configuration

| Field | Default | Description |
|-------|---------|-------------|
| `delegated_verification_min_reputation` | `0.7` | Vouching peer must have at least this reputation |
| `delegated_verification_quorum` | `1` | Number of independent vouches needed to lift cap |

**Tactical deployment.** Quorum 1 (any trusted peer's verification suffices).
Favors rapid cap-lifting over Byzantine resilience.

**High-assurance deployment.** Quorum 2-3 with
`delegated_verification_min_reputation` 0.8+. Multiple independent verifications
required.

**Space/DTN deployment.** Quorum 1, `delegated_verification_min_reputation` 0.6.
Ground stations that verify during contact windows can vouch for peers that
haven't had a contact window yet.

---

## 9. ZTA process

The `zta_process_run` function (`zta_process.h`) implements a background process
that:

1. **Periodically re-verifies** peer credentials against ZTA infrastructure at the configured interval.
2. **Applies reputation penalties** for revoked or expired credentials.
3. **Resolves deferred verifications** when infrastructure becomes available.
4. **Tells the group what it found** (§8): `zta_revoked` when its own check finds a credential revoked, `zta_verified` when it proves one, sent encrypted to every other member. It receives both and acts on them the same way.
5. **Enforces reputation caps** on peers admitted without ZTA verification.

When ZTA is disabled at runtime, the process exits immediately.

### Protocol messages

ZTA peers exchange three message types via the network layer:

| Message | Constant | Purpose |
|---------|----------|---------|
| `zta_revoked` | `ZTA_PROTO_REVOCATION_ALERT` | Alert the group about a detected revocation |
| `zta_verified` | `ZTA_PROTO_VERIFICATION` | Share a verification result with peers |
| `zta_reverify` | `ZTA_PROTO_REVERIFY_REQ` | Request peers to re-verify a specific peer |

The first two are built in both runtimes. Each is sent encrypted to each
other member, addressed to process `zta_verify`, with the body
`{"credential_hash": hex, "peer_uuid", "reason", "status"}`. Python has no
`zta_verify` process. Its ZTA rides the identity process, and the ZTA
extension declares the alias (`Extension.process_aliases`), so the Python
network process delivers those frames to identity. `zta_reverify` is defined
and still unused: nothing sends it and nothing handles it.

---

## 10. Audit logging

The `zta_audit_log_t` (`zta_audit.h`) provides a thread-safe, append-only audit
log in JSONL format (one JSON object per line). The default log path is
`/var/at/zta_audit.jsonl`.

Each entry records:

- Timestamp
- Peer UUID
- Action type (`"admission_check"`, `"periodic_reverify"`, `"revocation_detected"`, etc.)
- Verification result (status, reason, credential hash, TTL)
- Whether the verification was deferred
- If deferred: when and how it was resolved

The audit log maintains an in-memory list of up to 256 unresolved deferred
entries. When the ZTA process resolves a deferral (infrastructure becomes
reachable), it writes a resolution entry linking back to the original deferral.

This audit trail supports compliance review, in the form "we could not verify
peer X at time T due to OCSP being unreachable, we verified at time T+N, and the
result was VERIFIED."

---

## 11. Integration with admission protocol

The ZTA check occurs during Phase 3 (Border Guard Mode) of the [identity
protocol](identity-protocol.md). When a new peer announces, the border guard
runs three steps.

1. Validates the AT identity (UUID, keys, and package hash, against the allowlist when one ships; see [identity-protocol.md](identity-protocol.md)), unchanged.
2. If `require_at_admission` is true, verifies the ZTA credential via the configured verifier.
3. If verification returns `ZTA_VERIFIED`, the gate then **checks revocation** (`check_revocation` on the verified credential's hash). `verify_credential` walks only the chain and expiry, so a chain-valid but revoked certificate would otherwise admit, and the explicit revocation check closes that gap. Only an affirmative `ZTA_REVOKED` blocks. `ZTA_UNAVAILABLE`, the default when no CRL/OCSP source is configured, does **not**, so deployments without a revocation source are unaffected. A surviving credential is proposed for group voting with no reputation cap (starts at 0.5 neutral, can earn higher).
4. If verification returns `ZTA_DEFERRED` and `allow_ddil_fallback` is true, the peer is admitted with a reputation cap of `ddil_fallback_reputation_cap`. The deferral is recorded in the audit log.
5. If verification returns `ZTA_REJECTED` or `ZTA_EXPIRED` (or the revocation check in step 3 returns `ZTA_REVOKED`), the peer is not proposed.
6. If `require_at_admission` is false, the ZTA check is skipped entirely.

Both implementations match here: Python `idprocess._zta_admit` and C
`welcoming_committee` (`id_proc.c`) both run the revocation check after a
`VERIFIED` chain result, and the CRL serial match itself is at parity
(`X509Verifier.check_revocation` ↔ `x509_check_revocation`). Pinned
cross-language by conformance `zta-x509-reject-revoked-credential`. The
human-operator analog of this gate is described in [Operator
Access](operator-access.md).

---

## 12. Compliance alignment

Implementing AT with ZTA does not conflict with ZTA mandates. It extends them.

> The full per-tenet / per-pillar **traceability matrix** (SP 800-207, DoD ZT RA
> v2.0, SP 800-160 Vol. 2, CSF 2.0, CISA ZTMM, OMB M-22-09, DoD ZT Strategy →
> AT mechanism, with I/IP/P/D status and gap→Option mapping) is the SOW Task 1.4
> deliverable at `doc/NV059/work/NIST_DOD_ZT_TRACEABILITY.md`. The summary below
> is the high-level alignment; that document is authoritative.

| Standard/Framework | Requirement | AT Alignment |
|---|---|---|
| NIST SP 800-207 [1] | Minimize implicit trust | AT makes trust explicit, continuous, and behavioral |
| NIST SP 800-160 Vol. 2 [13] | Distributed decision-making as resilience technique | AT's decentralized trust evaluation is precisely this |
| NIST CSF 2.0 [14] | Continuous monitoring | AT's transaction scoring is continuous monitoring at the peer level |
| DoD Zero Trust Strategy [15] | Operate in DDIL environments | AT requires no centralized infrastructure |
| CISA ZT Maturity Model | Progressive trust evaluation | AT's trust gradient (0.0-1.0) is progressive by design |
| OMB M-22-09 | Agency-level ZTA implementation | AT extends ZTA without conflicting with it |

Every ZTA requirement (identity verification, least privilege, session
management, micro-segmentation) remains in place. AT adds a capability the ZTA
architecture cannot provide, namely trust evaluation that is continuous,
autonomous, and behavioral, operating without human policy authoring and without
centralized infrastructure.

---

## 13. Building with ZTA

```bash
cd src/c
mkdir build && cd build
cmake .. -DAT_ZTA=ON
make -j$(nproc)
```

`AT_ZTA=ON` builds `libat_zta` from `src/c/extensions/zta/`, which brings
OpenSSL; the core library needs neither (FEATURE_SPLIT_PLAN Phase 6). The ZTA
fields of `public_identity_t` are unconditional, so no struct depends on the
flag. A node turns ZTA on with its `zta_policy.cfg.json`, and one whose policy
enables it without the library refuses to start. See extensions.md, "ZTA".

### Running tests

```bash
# All tests including ZTA
ctest --output-on-failure

# ZTA tests only
ctest -R "zta_" --output-on-failure
```

The ZTA-specific tests are:
- `zta_verifier_test` (verifier interface and null/X.509 backends
- `zta_policy_test`) policy serialization and verifier creation
- `zta_audit_test`, audit log init, record, defer, resolve

### Source files

Modified:
- `src/protobuf/.../identity/identity.proto` (ZTA binding fields (6-8)
- `src/c/autonomous_trust/identity/identity.h` / `identity.c`) extended `public_identity_t`, serialization
- `src/c/autonomous_trust/identity/id_proc.c` (ZTA check during admission
- `src/c/autonomous_trust/utilities/msg_types.h` / `msg_types.c`) `ZTA_REVOCATION_ALERT` and `ZTA_VERIFICATION_RESULT` message types
- `src/c/CMakeLists.txt`, `AT_ZTA` option, conditional compilation, ZTA test targets

New:
- `src/c/extensions/zta/zta_verifier.h` / `.c` (pluggable verifier interface and null backend
- `src/c/extensions/zta/x509_verifier.h` / `.c`) OpenSSL X.509 backend
- `src/c/extensions/zta/oidc_verifier.h` / `.c` (OIDC stub backend
- `src/c/extensions/zta/zta_policy.h` / `.c`) policy configuration and JSON serialization
- `src/c/extensions/zta/zta_process.h` / `.c` (background re-verification process
- `src/c/extensions/zta/zta_audit.h` / `.c`) compliance audit log
- `src/c/extensions/zta/zta_protocol.h` (protocol message constants
- `src/c/test/zta_verifier_test.c`, `zta_policy_test.c`, `zta_audit_test.c`) unit tests
- `config/cfg/zta_policy.cfg.json` (default policy configuration
- `examples/zta/`) 4-peer Docker Compose demo with mock OCSP

---

## 14. Demo

See [examples/zta/](../../examples/zta/) for a 4-peer Docker Compose scenario
demonstrating ZTA verification, DDIL fallback, and mid-session revocation. Run:

```bash
cd examples/zta_demo
./run-demo.sh
```

The demo creates:
- **mock-ocsp.** Mock OCSP responder with control endpoints for revoking certificates
- **command-post.** Trust anchor with full OCSP connectivity
- **squad-leader.** Peer with valid credential
- **drone-alpha.** Peer whose certificate is revoked mid-demo
- **drone-bravo.** Peer that starts in a DDIL scenario (OCSP unreachable)

---

## 15. Open design questions

1. **Retroactive reputation adjustment, answered 2026-08-17, both
   runtimes.** When a peer operates for an extended period without ZTA
   verification and then verification fails, reputation is unwound
   **to the last proved verification**, recomputed over the pre-anchor
   window by the same evidence arithmetic the §10.3 warm start uses,
   so the unwind inherits its shrinkage and a short pre-anchor history
   cannot justify a high score. The anchor is a chain index recorded
   when the peer proves, not a clock reading. A peer never proved
   keeps nothing.

 The claim this question rested on, that "the current implementation
 applies a single penalty at detection time", was false. No penalty
 was applied in either runtime: the C `_send_reputation_penalty` was
 discarded twice over (a zero `task_uuid` sentinel, and a negative
 score off the [0, 1] scale §11.2 fixed), and
 `ddil_fallback_reputation_cap` was logged as enforced while being
 read by nothing. A ZTA verdict now reaches reputation as an authority
 finding, a `ZtaStanding` carrying `proved` / `capped` / `failed`,
 rather than as a score the scale cannot express. The unwind reaches back to
 the last *proved* verification, bounded by the evidence arithmetic in
 [Reputation](reputation.md).
2. **Multi-operator ZTA, answered 2026-08-06, both runtimes.** In coalition/multi-agency scenarios (LunaNet, joint ops), peers may have certs from different CAs. The ZTA policy now names trust anchors explicitly and an identity carries a repeated `ZtaCredential{der, binding, issuer}` (proto field 16), so admission is *any-of* across configured anchors and each verified credential earns authority for its own anchor (`zta_anchors`, the observer's finding, never serialized). Group federation then requires a *proved* shared anchor rather than a declared gateway role, gatewayhood is emergent in AT, so a declared rule would rest on a claim by the peer itself and an attacker would simply decline to claim.

 What the question above got wrong is the assumption that this needs cross-certification or CA trust negotiation. It needs neither. Nothing has to make two CAs recognize each other, only make *this node* recognize both, and a holder-asserted binding (§1.5) lets a foreign CA's credential bind to an AT identity without that CA knowing AT exists. Coalition deployment is in fact what forces the holder-asserted route, a foreign CA will not put an AT uuid in a SAN, so the CA-asserted route is unavailable exactly where coalitions need it.

Both items are closed in both runtimes: item 1 on 2026-08-17, item 2 on
2026-08-06.

The integration is not C-only. The Python identity process (`idprocess.py`)
performs ZTA checks at admission time (`_zta_admit`, gated in
`welcoming_committee`), with verification, capping, and carriage at parity with
C: X.509 verification, DDIL reputation capping, and wire-level credential
carriage. **Background re-verification is at parity as of 2026-08-17:**
Python sweeps admitted peers on `reverify_interval_sec` inside IdentityProcess
rather than in a process of its own, detecting post-admission revocation and
lifting a DDIL cap once the infrastructure returns. See [ZTA Python
Parity](zta-python-parity.md) for that implementation and for what remains
C-only (the audit log). Delegated verification and revocation alerts are in both runtimes (§8).

**As of 2026-08-06 the credential→identity *binding* gate, named trust anchors,
multi-credential admission, and derived gateway authority exist in BOTH
runtimes**, pinned by 168/168 conformance cases with 0 asymmetric.
`binding_mode: require` is therefore a fleet-wide guarantee rather than a
per-runtime one: a C `welcoming_committee` and a Python one refuse the same
credentials. The C side is a mirror, not a reimplementation,
`zta/zta_binding.{h,c}`, `identity.c::zta_binding_preimage`,
`zta_policy_t.anchors`/`binding_mode`/`san_uri_template`, a repeated-credential
list on `public_identity_t` (proto field 16), `id_proc.c::_zta_admit`, and
`_gateway_authorized`.

---

## References

[1] NIST. "Zero Trust Architecture." SP 800-207, August 2020.
https://doi.org/10.6028/NIST.SP.800-207

[2] KeyFactor/Ponemon Institute. "2023 State of Machine Identity Management."

[3] Ponemon Institute. "The Impact of Digital Certificates on the Enterprise."
Commissioned by Venafi, 2019.

[4] U.S. House Committee on Oversight and Government Reform. "The Equifax Data
Breach." December 2018.

[5] Ofcom. Investigation into O2/Ericsson network outage, December 6, 2018.

[6] Let's Encrypt. "DST Root CA X3 Expiration (September 2021)."
https://letsencrypt.org/docs/dst-root-ca-x3-expiration-september-2021/

[7] DISA. "DoD Public Key Infrastructure (PKI) and Public Key Enabling (PKE)."
DoD Instruction 8520.02, May 2011 (updated 2019).

[8] NSA. "Embrace a Zero Trust Security Model." Cybersecurity Information Sheet,
February 2021.

[9] IETF. "Bundle Protocol Security (BPSec)." RFC 9172, January 2022.
https://datatracker.ietf.org/doc/html/rfc9172

[10] NASA/JPL. "DTN Security Key Management." DTN Working Group presentations,
IETF, 2015-2022.

[11] Federal PKI Management Authority. Annual Reports.
https://www.idmanagement.gov/fpki/

[12] CA/Browser Forum. Ballot SC-081, "Reduce the Maximum Validity Period of DV
and OV Certificates." Proposed 2024.

[13] NIST. "Developing Cyber-Resilient Systems." SP 800-160 Vol. 2, Rev. 1,
December 2021. https://doi.org/10.6028/NIST.SP.800-160v2r1

[14] NIST. "Cybersecurity Framework 2.0." February 2024.
https://doi.org/10.6028/NIST.CSWP.29

[15] DoD. "Department of Defense Zero Trust Strategy." November 2022.
https://dodcio.defense.gov/Portals/0/Documents/Library/DoD-ZTStrategy.pdf

---

*Next: [Zero Trust parity in Python](zta-python-parity.md)*
