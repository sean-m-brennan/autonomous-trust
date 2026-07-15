*[AutonomousTrust](autonomous_trust.md) > Security*

# AutonomousTrust Security Model

AutonomousTrust assumes a hostile environment with no reachable central authority to vouch for anyone (see the [adversarial assumption](concept.md#adversarial-assumption)). This document states the security properties AT aims to provide, how it contains a malicious or compromised peer, and the risks it raises the cost of without eliminating. For implementation-level hardening (memory safety, deserialization, allowlists, message verification), see [Security Hardening](architecture/security-hardening.md).

## Security Properties

Identity is cryptographic, and there are no logins. The mesh has no user accounts or shared passwords. Every peer is a non-person entity identified by a keypair (Ed25519 for signatures, X25519 for key agreement) and a UUID. A peer proves who it is by signing, not by presenting a secret, and private keys never leave the node (see [Identity and configuration bootstrap](api.md#identity-and-configuration-bootstrap)). A human operator authenticates once at a console and is thereafter represented on the mesh by a machine identity like any other peer (see [Operator Access](architecture/operator-access.md)).

Peers cannot be spoofed. All traffic is encrypted and signed (NaCl/libsodium: X25519 with XSalsa20-Poly1305, and Ed25519 signatures), so one peer cannot impersonate another without its private key. A `Message` carries a `verified` flag that the network layer sets only after cryptographic verification, and the reputation subsystem treats an unverified consensus message as suspect rather than acting on it.

Trust is earned, and it is withdrawn for non-cooperation rather than granted for it. A peer starts every relationship at zero trust and gains reach only by behaving well. It does not receive standing rights for authenticating once. When a peer stops cooperating or begins to misbehave, its rights are withdrawn through a reputation slash that is quorum-co-signed and backed by a Merkle proof any peer can re-verify (see [Reputation vs. Blockchain Analysis](architecture/reputation-vs-blockchain-analysis.md)).

Access is least-privilege and scoped to a task. A peer reaches only what the work at hand requires, gated by its current trust tier (see [Trust Tiers](architecture/trust-tiers.md)). There is no general-purpose, standing grant, so the reach of any one peer stays small.

Decisions are deterministic and auditable. A trust decision follows from signed evidence and yields the same result for every peer that checks it. The ZTA overlay writes a JSONL audit trail of every credential verification, deferral, and resolution for later review (see [ZTA Integration](architecture/zta-integration.md)).

## Malicious Code Containment

AT treats any peer as potentially compromised at any moment, including one that holds valid credentials. Containment limits what such a peer can do.

Authorization is bound to identity and behavior, not to a credential alone. A compromised-but-credentialed peer still has to act within its learned behavioral envelope. Deviation costs it reputation and, past a threshold, gets it slashed and tier-gated out of the capabilities it can no longer justify. This is the case a credential check alone cannot catch, and it is the case AT is built for.

A peer cannot reach beyond its permitted capabilities. Capabilities are explicitly advertised and tier-gated, so a peer cannot invoke one above its tier, and it cannot beacon or exfiltrate through a channel it was never granted. Task-specific scoping keeps the blast radius of a subverted peer to its own task.

A peer cannot control anything outside itself. There is no central controller to subvert and no standing implicit trust to inherit. Trust decisions are local and consensus-checked, so one peer cannot dictate another's trust state: a slash requires a signed quorum, not a single accuser.

Code and configuration cannot be silently changed. The embedded C core is built as a signed binary and verified before it loads. At runtime, configuration is parsed against a closed allowlist of registered types, so a crafted payload cannot instantiate an arbitrary class and gain code execution. Network data is deserialized with msgpack rather than pickle, and peer-supplied class names resolve only against a closed allowlist. See [Security Hardening](architecture/security-hardening.md) for the full set of these measures.

## Known Vulnerabilities

AT raises the cost of the following attack classes. It does not claim to eliminate them, and the honest framing is residual risk, not immunity.

Larger-than-local coordination. Reputation is weighted and consensus is Byzantine-tolerant, and cryptographic identity plus evidence-gated slashing make disposable Sybil identities expensive. An adversary who can field enough colluding, well-behaved identities to hold a majority in a local quorum can still bias trust within that quorum. Identity cost, reputation weighting, hardware attestation, and quorum thresholds raise the price of that majority; they do not make it impossible.

Corruption of the system of knowing. The trust record is itself an attack surface. Bad-mouthing, whitewashing, and on-off behavior all target the reputation history rather than the data path. Hash-linking, Merkle checkpoints, and quorum-signed slashes make tampering detectable and every accusation checkable, but a large or patient colluding set can still move scores within the range the weighting permits.

Drive-by and post-admission compromise. A peer can be subverted after it is admitted. AT's answer is behavioral: constrain what the peer can do through tier and task scope, then detect drift from its envelope. Detection is subject to the base-rate fallacy: when attacks are rare, false positives can swamp true ones, so AT leans on constraint over detection and reports false-exclusion rate against a realistic attack base rate.

Implementation surface. Memory safety in the C core, deserialization of network data, and the web-based inspector tooling are ongoing concerns addressed by the mitigations tracked in [Security Hardening](architecture/security-hardening.md). Those measures are the first line of defense and are validated against attack scenarios in [Adversarial Testing](architecture/adversarial-testing.md).

## See also

- [Concept](concept.md): the adversarial assumption and inverted access model behind these properties.
- [Security Hardening](architecture/security-hardening.md): implementation-level mitigations across the C core, Python services, and tooling.
- [ZTA Integration](architecture/zta-integration.md): credential gating, DDIL fallback, and the audit trail.
- [Adversarial Testing](architecture/adversarial-testing.md): attack scenarios and how the model is validated.
