[< Security Hardening](security-hardening.md)

# Zero Trust Architecture Integration

## 1. Why Certificate Management Is Not Enough

Certificate-based trust is the foundation of Zero Trust Architecture (ZTA). NIST SP 800-207 defines ZTA around a Policy Decision Point (PDP) that verifies identity via certificates for every access request [1]. This creates a dependency chain:

```
Trust -> PDP decision -> Identity verification -> Certificate validation -> CA/OCSP/CRL availability
```

Break any link -- the CA is unreachable, the OCSP responder is down, the CRL is stale -- and trust collapses. SP 800-207 acknowledges this: "If the PE and PA are not available, no new connection requests can be approved" (SS7.3) [1]. The standard offers redundancy as the only mitigation, but redundancy still requires connectivity to at least one instance.

This is not an implementation bug. It is structural:

1. **Certificate state is binary.** Valid or invalid. No gradient, no "trusted for low-risk but not high-risk operations."
2. **Validation requires connectivity to a central authority.** OCSP, CRL, and PDP queries all need real-time access to infrastructure that may be unreachable.
3. **Credentials prove identity, not behavior.** A valid certificate proves identity was verified at issuance time. It says nothing about current behavior. A compromised endpoint with valid credentials passes every certificate check.
4. **Revocation is inherently delayed.** Even in well-connected environments, revocation propagation takes time. In DDIL environments, it may take hours or days.

In connected enterprise environments, certificate management is already painful: 77% of organizations experienced certificate-related outages in a 24-month period, with an average cost of $11.1 million per organization per year [2][3]. High-profile failures (Equifax 2017, Ericsson/O2 2018, Let's Encrypt root expiry 2021) occur with full connectivity to certificate infrastructure [4][5][6].

### Where It Breaks Entirely

**Tactical/DDIL environments.** The DoD CRL can exceed 50 MB; tactical SATCOM links at 9.6-256 kbps cannot reliably download it [7]. Tactical edge systems frequently lose connectivity to OCSP responders and must choose between fail-open (insecure) and fail-closed (mission denial) [8].

**Space and DTN.** One-way light time to Mars ranges from 4 to 24 minutes. A certificate rotation requiring two round-trips takes 1-4 hours minimum. BPSec (RFC 9172) defers key management entirely: "Key management is outside the scope of this document" [9]. Current space missions use manual key rotation via limited ground contact windows, with no in-flight revocation mechanism [10].

**Multi-agency operations.** The Federal PKI involves hundreds of cross-certifications [11]. When cross-certifications lapse, trust paths between agencies break. In disaster response or coalition operations, each participant brings its own PKI; interoperability depends on fragile bridge CAs.

The trend is worsening: the CA/Browser Forum has proposed 47-day certificate lifetimes by 2029 (Ballot SC-081) [12], multiplying the operational burden 4-8x and the frequency of potential failure points proportionally.

---

## 2. The Layered Architecture: ZTA + AT

ZTA and AT are complementary layers, not alternatives. ZTA opens the door; AT decides what happens inside the room.

| | Zero Trust | AutonomousTrust |
|---|---|---|
| **Evaluates** | Credentials, device posture, context | Behavior over time |
| **Trust model** | Binary (allow/deny) | Continuous gradient (0.0-1.0) |
| **Adapts** | When policies are updated by humans | Continuously, autonomously |
| **Fails when** | PDP is unreachable or wrong | Never fully -- degrades gracefully |
| **Scales via** | More policy rules | More peer observations |

A peer needs valid ZTA credentials to reach an AT agent (satisfying the mandate), but once connected, AT takes over. The certificate is no longer the operative trust boundary -- behavioral reputation is. A ZTA-authenticated peer enters the network at neutral reputation (0.5) and must earn higher trust through demonstrated behavior. Authentication is not trust.

### Failure Mode Transformation

| Certificate Failure | ZTA-Only Impact | ZTA + AT Impact |
|---|---|---|
| **Expired cert** | Service outage | Brief re-authentication; AT reputation persists across the renewal |
| **Compromised cert** | Full access until revocation propagates | Attacker has neutral reputation (new identity) or divergent behavior (existing identity) -- AT detects it |
| **CA compromise** | Catastrophic trust collapse across all relying parties | AT trust is independent of CA; network continues on behavioral trust |
| **OCSP/CRL unreachable** | Fail-open (insecure) or fail-closed (outage) | AT trust evaluation continues unimpaired |
| **PDP unavailable** | No new connections approved (SP 800-207 SS7.3) | AT peers continue operating on behavioral trust |
| **Cross-cert lapse** | Inter-agency authentication fails | AT trust between peers persists; re-established when connectivity returns |
| **Stale cached revocation** | False sense of security | AT behavioral scoring detects changed behavior regardless of credential state |

### AT-Informed Certificate Management

AT's reputation signal can inform automated certificate lifecycle decisions:

- **Strong AT reputation + expiring cert**: Auto-renew with confidence (behavior is verified, risk is low)
- **Degrading AT reputation + valid cert**: Flag for scrutiny, shorten cert lifetime, or investigate
- **Post-rotation re-authentication**: AT reputation carries over, minimizing disruption
- **Bandwidth-constrained CRL distribution**: Prioritize CRL delivery to peers with low/declining AT reputation; high-reputation peers can safely operate with stale revocation data

---

## 3. Design Principles

1. **ZTA remains mandatory when available.** AT does not override or bypass ZTA -- it extends it.
2. **AT provides continuity when ZTA fails.** The value proposition is graceful degradation, not ZTA replacement.
3. **Credential state informs reputation, not the reverse.** ZTA revocation penalizes AT reputation. AT reputation can inform cert lifecycle decisions. Neither layer unilaterally controls the other.
4. **Configuration, not hardcoding.** Different deployments (enterprise, tactical, space) have different ZTA availability profiles. The integration must be tunable.
5. **Honest about gaps.** When operating without ZTA verification, the system logs it rather than pretending verification happened.

---

## 4. Architecture Overview

The ZTA subsystem is compiled conditionally via `AT_ZTA=ON` in CMake, which defines `AT_ZTA_ENABLED` globally. When compiled in, it can be enabled or disabled at runtime via `zta_policy.cfg.json`. When disabled at runtime, all ZTA code paths are no-ops.

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

### Key Design Decisions

1. **Master switch**: ZTA can be compiled in but disabled at runtime. This allows a single binary to serve both ZTA-mandated and non-ZTA deployments.
2. **Pluggable backends**: The verifier interface (`zta_verifier_t`) is a vtable with function pointers. New credential types (SAML, JWT, etc.) can be added without modifying core code.
3. **Reputation integration**: ZTA verification results feed into the reputation system as one signal among many -- not a binary kill switch. A revocation applies a configurable reputation penalty; it does not forcibly disconnect the peer.
4. **DDIL fallback**: When verification infrastructure is unreachable, peers can still be admitted with a reputation cap, preserving network formation in disconnected environments.
5. **Audit trail**: Every verification attempt, deferral, and resolution is logged to a JSONL file for compliance review.

---

## 5. Pluggable Verifier Interface

The `zta_verifier_t` struct (`src/c/autonomous_trust/zta/zta_verifier.h`) defines a vtable with five operations:

| Operation | Purpose |
|-----------|---------|
| `verify_credential` | Validate a credential (signature chain, expiry, revocation status) |
| `check_revocation` | Check if a previously verified credential has been revoked |
| `is_available` | Test whether verification infrastructure is currently reachable |
| `credential_hash` | Compute a deterministic SHA-256 hash for identity binding |
| `destroy` | Free verifier resources |

Any function pointer may be NULL; a NULL pointer is treated as returning `ZTA_UNAVAILABLE`.

### Verification Status

| Status | Meaning |
|--------|---------|
| `ZTA_VERIFIED` | Credential is valid and verified |
| `ZTA_REJECTED` | Credential is invalid (bad signature, unknown issuer) |
| `ZTA_DEFERRED` | Verification deferred (infrastructure unreachable, DDIL scenario) |
| `ZTA_EXPIRED` | Credential has expired |
| `ZTA_REVOKED` | Credential has been revoked |
| `ZTA_UNAVAILABLE` | Verifier cannot perform this operation |

### Backend Implementations

**X.509 verifier** (`x509_verifier.h`): OpenSSL-based certificate verification against a CA bundle (PEM). Supports optional OCSP responder and CRL file for revocation checking. Configurable connection timeout (default 2000ms).

**OIDC verifier** (`oidc_verifier.h`): Stub for token-based credentials. Currently returns `ZTA_UNAVAILABLE` for all operations. Validates the interface design and provides a template for future token-based deployments.

**Null verifier**: Always returns `ZTA_VERIFIED`. Used when ZTA is compiled in but disabled at runtime.

---

## 6. Identity Binding

When ZTA is enabled, the `public_identity_t` struct (`identity.h`) carries additional fields:

| Field | Type | Purpose |
|-------|------|---------|
| `zta_credential_hash` | `uint8_t[32]` | SHA-256 of the ZTA credential presented at admission |
| `zta_issuer` | `char[64]` | Credential issuer identifier |
| `zta_credential` | `uint8_t *` | Raw credential bytes (heap-allocated) |
| `zta_credential_len` | `size_t` | Length of the raw credential |

These fields are serialized in the identity protobuf (`identity.proto` fields 6-8) and exchanged during peer discovery. The credential hash provides a stable binding between the AT identity (UUID + Ed25519 key) and the ZTA credential that was valid at admission time.

Credential rotation updates the binding; AT reputation is unaffected by routine rotation. This is by design -- the behavioral trust history persists across credential renewals.

---

## 7. Policy Configuration

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

### Field Reference

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

### Environment-Specific Tuning

**Enterprise** (full connectivity): Short `reverify_interval_sec` (300-900), high `revocation_reputation_penalty` (0.9-1.0), `allow_ddil_fallback` false.

**Tactical/DDIL**: Moderate `reverify_interval_sec` (1800-3600), `allow_ddil_fallback` true, `ddil_fallback_reputation_cap` 0.3-0.5. AT's reputation gossip protocol uses minimal bandwidth compared to CRL distribution (50+ MB DoD CRLs vs. compact reputation scores). Compromised-but-credentialed assets are detected via behavioral divergence even when ZTA credentials are valid. Reputation persists locally and converges via gossip when connectivity resumes.

**Space/DTN**: Long `reverify_interval_sec` (7200+), `allow_ddil_fallback` true, `ddil_fallback_reputation_cap` 0.5. Rely primarily on AT behavioral trust. AT complements BPSec (RFC 9172) by adding the behavioral layer that BPSec explicitly defers: BPSec answers "is this bundle authentic?" AT answers "should we trust this relay?" A relay with valid BPSec credentials but degrading forwarding reliability loses AT reputation and is routed around.

**Multi-agency**: AT's bilateral negotiation protocol handles cross-organizational trust without requiring PKI interoperability or cross-certification. New participants enter at neutral reputation regardless of ZTA authentication status and earn trust through demonstrated behavior. When cross-cert trust paths break, AT trust between peers persists -- authentication can be re-established when connectivity returns without losing behavioral trust history.

---

## 8. Delegated Verification (Distributed PDP)

In prolonged DDIL scenarios, no peer in the group may be able to reach ZTA infrastructure (OCSP, CRL endpoints). Without mitigation, every DDIL-admitted peer stays capped at `ddil_fallback_reputation_cap` indefinitely, preventing the network from reaching full trust depth.

Delegated verification solves this by turning the AT group itself into a distributed Policy Decision Point. When any peer in the group successfully verifies a credential against ZTA infrastructure, it broadcasts the result via `ZTA_PROTO_VERIFICATION`. Peers that could not verify independently accept the delegated result -- but only from peers they trust.

### How It Works

1. Peer A admits Peer B in DDIL mode (reputation capped at 0.5).
2. Peer C has OCSP connectivity and verifies B's credential during periodic re-verification. C broadcasts a `ZTA_VERIFICATION_RESULT` message identifying B as verified, signed with C's identity.
3. Peer A receives C's verification. If the vouch is from an admitted group member (guaranteed by the encrypted channel), A records it.
4. When the number of distinct vouching peers reaches `delegated_verification_quorum`, A lifts B's DDIL reputation cap. B can now earn reputation above 0.5.

### Trust Gating

Delegated verification is not blind trust in relay. The `delegated_verification_min_reputation` threshold (default 0.7) controls the minimum reputation a vouching peer must have for its verification to be accepted. The ZTA process queries the local reputation process via IPC (`local_rep_query`/`local_rep_response`) and caches scores with a 10-minute TTL. Vouches that arrive before the voucher's reputation is cached are held in a pending queue and evaluated when the reputation response arrives. This prevents:

- An attacker joining in DDIL mode and vouching for a confederate (the attacker's own reputation is too low).
- A recently compromised peer whose reputation is degrading from issuing trusted vouches.

The `delegated_verification_quorum` (default 1) can be raised for higher-assurance environments. With quorum 3, three independent peers must each verify the credential before the cap lifts. This provides Byzantine fault tolerance: a single compromised verifier cannot unilaterally lift caps.

### Audit Trail

Every delegated vouch is recorded in the audit log:

- The initial vouch receipt (action: `"delegated_vouch"`)
- The cap-lift event when quorum is met (action: `"delegated_cap_lift"`)
- The resolution of the original deferred audit entry

This provides a complete chain: "Peer B was admitted at T with deferred verification; Peer C vouched at T+N1; Peer D vouched at T+N2; quorum met at T+N2; cap lifted."

### Configuration

| Field | Default | Description |
|-------|---------|-------------|
| `delegated_verification_min_reputation` | `0.7` | Vouching peer must have at least this reputation |
| `delegated_verification_quorum` | `1` | Number of independent vouches needed to lift cap |

**Tactical deployment**: quorum 1 (any trusted peer's verification suffices). Favors rapid cap-lifting over Byzantine resilience.

**High-assurance deployment**: quorum 2-3 with `delegated_verification_min_reputation` 0.8+. Multiple independent verifications required.

**Space/DTN deployment**: quorum 1, `delegated_verification_min_reputation` 0.6. Ground stations that verify during contact windows can vouch for peers that haven't had a contact window yet.

---

## 9. ZTA Process

The `zta_process_run` function (`zta_process.h`) implements a background process that:

1. **Periodically re-verifies** peer credentials against ZTA infrastructure at the configured interval.
2. **Applies reputation penalties** for revoked or expired credentials.
3. **Resolves deferred verifications** when infrastructure becomes available.
4. **Broadcasts revocation alerts** to the group via `ZTA_PROTO_REVOCATION_ALERT` messages.
5. **Enforces reputation caps** on peers admitted without ZTA verification.

When ZTA is disabled at runtime, the process exits immediately.

### Protocol Messages

ZTA peers exchange three message types via the network layer:

| Message | Constant | Purpose |
|---------|----------|---------|
| `zta_revoked` | `ZTA_PROTO_REVOCATION_ALERT` | Alert the group about a detected revocation |
| `zta_verified` | `ZTA_PROTO_VERIFICATION` | Share a verification result with peers |
| `zta_reverify` | `ZTA_PROTO_REVERIFY_REQ` | Request peers to re-verify a specific peer |

These use the existing `net_msg_t` transport with the function field set to the protocol constant.

---

## 10. Audit Logging

The `zta_audit_log_t` (`zta_audit.h`) provides a thread-safe, append-only audit log in JSONL format (one JSON object per line). The default log path is `/var/at/zta_audit.jsonl`.

Each entry records:

- Timestamp
- Peer UUID
- Action type (`"admission_check"`, `"periodic_reverify"`, `"revocation_detected"`, etc.)
- Verification result (status, reason, credential hash, TTL)
- Whether the verification was deferred
- If deferred: when and how it was resolved

The audit log maintains an in-memory list of up to 256 unresolved deferred entries. When the ZTA process resolves a deferral (infrastructure becomes reachable), it writes a resolution entry linking back to the original deferral.

This audit trail supports compliance review: "we could not verify peer X at time T due to OCSP being unreachable; we verified at time T+N; result was VERIFIED."

---

## 11. Integration with Admission Protocol

The ZTA check occurs during Phase 3 (Border Guard Mode) of the [identity protocol](identity-protocol.md). When a new peer announces, the border guard:

1. Validates the AT identity (UUID, keys, package hash) -- unchanged.
2. If `require_at_admission` is true, verifies the peer's ZTA credential via the configured verifier.
3. If verification returns `ZTA_VERIFIED`, the peer is proposed for group voting with no reputation cap (starts at 0.5 neutral, can earn higher).
4. If verification returns `ZTA_DEFERRED` and `allow_ddil_fallback` is true, the peer is admitted with a reputation cap of `ddil_fallback_reputation_cap`. The deferral is recorded in the audit log.
5. If verification returns `ZTA_REJECTED`, `ZTA_EXPIRED`, or `ZTA_REVOKED`, the peer is not proposed.
6. If `require_at_admission` is false, the ZTA check is skipped entirely.

---

## 12. Compliance Alignment

Implementing AT with ZTA does not conflict with ZTA mandates. It extends them.

| Standard/Framework | Requirement | AT Alignment |
|---|---|---|
| NIST SP 800-207 [1] | Minimize implicit trust | AT makes trust explicit, continuous, and behavioral |
| NIST SP 800-160 Vol. 2 [13] | Distributed decision-making as resilience technique | AT's decentralized trust evaluation is precisely this |
| NIST CSF 2.0 [14] | Continuous monitoring | AT's transaction scoring is continuous monitoring at the peer level |
| DoD Zero Trust Strategy [15] | Operate in DDIL environments | AT requires no centralized infrastructure |
| CISA ZT Maturity Model | Progressive trust evaluation | AT's trust gradient (0.0-1.0) is progressive by design |
| OMB M-22-09 | Agency-level ZTA implementation | AT extends ZTA without conflicting with it |

Every ZTA requirement -- identity verification, least privilege, session management, micro-segmentation -- remains in place. AT adds a capability ZTA's architecture cannot provide: continuous, autonomous, behavioral trust evaluation that operates without human policy authoring and without centralized infrastructure.

---

## 13. Building with ZTA

```bash
cd src/c
mkdir build && cd build
cmake .. -DAT_ZTA=ON
make -j$(nproc)
```

`AT_ZTA=ON` adds OpenSSL as a dependency and compiles the `src/c/autonomous_trust/zta/` sources. It also defines `AT_ZTA_ENABLED` globally, which extends `public_identity_t` and `generic_msg_t` with ZTA fields. All translation units must see the same definition to avoid struct size mismatches.

### Running Tests

```bash
# All tests including ZTA
ctest --output-on-failure

# ZTA tests only
ctest -R "zta_" --output-on-failure
```

The ZTA-specific tests are:
- `zta_verifier_test` -- verifier interface and null/X.509 backends
- `zta_policy_test` -- policy serialization and verifier creation
- `zta_audit_test` -- audit log init, record, defer, resolve

### Source Files

Modified:
- `src/protobuf/.../identity/identity.proto` -- ZTA binding fields (6-8)
- `src/c/autonomous_trust/identity/identity.h` / `identity.c` -- extended `public_identity_t`, serialization
- `src/c/autonomous_trust/identity/id_proc.c` -- ZTA check during admission
- `src/c/autonomous_trust/utilities/msg_types.h` / `msg_types.c` -- `ZTA_REVOCATION_ALERT` and `ZTA_VERIFICATION_RESULT` message types
- `src/c/CMakeLists.txt` -- `AT_ZTA` option, conditional compilation, ZTA test targets

New:
- `src/c/autonomous_trust/zta/zta_verifier.h` / `.c` -- pluggable verifier interface and null backend
- `src/c/autonomous_trust/zta/x509_verifier.h` / `.c` -- OpenSSL X.509 backend
- `src/c/autonomous_trust/zta/oidc_verifier.h` / `.c` -- OIDC stub backend
- `src/c/autonomous_trust/zta/zta_policy.h` / `.c` -- policy configuration and JSON serialization
- `src/c/autonomous_trust/zta/zta_process.h` / `.c` -- background re-verification process
- `src/c/autonomous_trust/zta/zta_audit.h` / `.c` -- compliance audit log
- `src/c/autonomous_trust/zta/zta_protocol.h` -- protocol message constants
- `src/c/test/zta_verifier_test.c`, `zta_policy_test.c`, `zta_audit_test.c` -- unit tests
- `config/cfg/zta_policy.cfg.json` -- default policy configuration
- `examples/zta/` -- 4-peer Docker Compose demo with mock OCSP

---

## 14. Demo

See [examples/zta/](../../examples/zta/) for a 4-peer Docker Compose scenario demonstrating ZTA verification, DDIL fallback, and mid-session revocation. Run:

```bash
cd examples/zta_demo
./run-demo.sh
```

The demo creates:
- **mock-ocsp**: Mock OCSP responder with control endpoints for revoking certificates
- **command-post**: Trust anchor with full OCSP connectivity
- **squad-leader**: Peer with valid credential
- **drone-alpha**: Peer whose certificate is revoked mid-demo
- **drone-bravo**: Peer that starts in a DDIL scenario (OCSP unreachable)

---

## 15. Open Questions

1. **Retroactive reputation adjustment.** When a peer operates for an extended period without ZTA verification and then verification fails, how far back should reputation be unwound? The current implementation applies a single penalty at detection time; historical unwinding is not yet implemented.
2. **Multi-operator ZTA.** In coalition/multi-agency scenarios (LunaNet, joint ops), peers may have certs from different CAs. The verifier interface supports this in principle (multiple CA bundles), but cross-certification verification and CA trust negotiation are not yet implemented.
3. **Python implementation.** ~~The current ZTA integration is C-only.~~ **Closed (2026-06-03, commit `f6250c8`).** The Python identity process (`idprocess.py`) now performs ZTA checks at admission time (`_zta_admit`, gated in `welcoming_committee`), with X.509 verification, DDIL reputation capping, and wire-level credential binding at parity with C. See [ZTA Python Parity](zta-python-parity.md) for the implementation and the features that remain C-only (background re-verification process, audit log, delegated verification).

---

## References

[1] NIST. "Zero Trust Architecture." SP 800-207, August 2020. https://doi.org/10.6028/NIST.SP.800-207

[2] KeyFactor/Ponemon Institute. "2023 State of Machine Identity Management."

[3] Ponemon Institute. "The Impact of Digital Certificates on the Enterprise." Commissioned by Venafi, 2019.

[4] U.S. House Committee on Oversight and Government Reform. "The Equifax Data Breach." December 2018.

[5] Ofcom. Investigation into O2/Ericsson network outage, December 6, 2018.

[6] Let's Encrypt. "DST Root CA X3 Expiration (September 2021)." https://letsencrypt.org/docs/dst-root-ca-x3-expiration-september-2021/

[7] DISA. "DoD Public Key Infrastructure (PKI) and Public Key Enabling (PKE)." DoD Instruction 8520.02, May 2011 (updated 2019).

[8] NSA. "Embrace a Zero Trust Security Model." Cybersecurity Information Sheet, February 2021.

[9] IETF. "Bundle Protocol Security (BPSec)." RFC 9172, January 2022. https://datatracker.ietf.org/doc/html/rfc9172

[10] NASA/JPL. "DTN Security Key Management." DTN Working Group presentations, IETF, 2015-2022.

[11] Federal PKI Management Authority. Annual Reports. https://www.idmanagement.gov/fpki/

[12] CA/Browser Forum. Ballot SC-081, "Reduce the Maximum Validity Period of DV and OV Certificates." Proposed 2024.

[13] NIST. "Developing Cyber-Resilient Systems." SP 800-160 Vol. 2, Rev. 1, December 2021. https://doi.org/10.6028/NIST.SP.800-160v2r1

[14] NIST. "Cybersecurity Framework 2.0." February 2024. https://doi.org/10.6028/NIST.CSWP.29

[15] DoD. "Department of Defense Zero Trust Strategy." November 2022. https://dodcio.defense.gov/Portals/0/Documents/Library/DoD-ZTStrategy.pdf

[Identity Protocol >](identity-protocol.md)
