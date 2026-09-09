# AutonomousTrust Architecture

Technical architecture documentation for the AutonomousTrust cooperative computing framework.

## Contents

- [System Overview](overview.md) (Design principles and cryptographic foundation
- [Process Architecture](process-architecture.md)) Multiprocessing orchestration and IPC
- [Networking](networking.md) (Network layer, channels, and message routing
- [TCP Connection Pooling](network-connection-pooling.md)) Optional persistent connections, reuse, and persistent readers
- [Network Wire Format](network-wire-format.md) (The JSON and protobuf envelopes, the group-carried format choice, and why detection stays unbuilt
- [Native/FFI Dual Implementation](native-ffi-dual-implementation.md) (C runtime, CFFI bridge, Python↔C interoperability, and embedded/microdrone nodes
- [Identity Protocol](identity-protocol.md)) Peer discovery, voting, and group formation
- [First Contact](first-contact.md) (Adding a specific person you already know: the 1:1 introduction, signed invitations, and safety-number verification
- [Task Negotiation](negotiation.md) (Distributed task lifecycle
- [Reputation Consensus](reputation.md)) Paxos-based reputation scoring
- [Gateway Reputation Tree](gateway-reputation-tree.md): Multi-group membership and recursive subtree reputation
- [Reputation vs. Blockchain Analysis](reputation-vs-blockchain-analysis.md) (Hash-linking, Merkle checkpoints, and slashing
- [Trust Tiers](trust-tiers.md)) Tiered capabilities, weighted transactions, bootstrap corpus, tier-gated access
- [Physical Consistency](physical-consistency.md) (Refuting a peer's claim on dimensions, bounds, kinematics and conservation, before any reputation math runs
- [Certificate-Carrying Interfaces](certificate-interfaces.md)) Answers that arrive with a witness: duals, DRAT refutations, potentials and cuts, checked exactly
- [Calibration Audit](calibration-audit.md) (Auditing whether a peer's prediction sets cover as often as it claims: the overconfident peer an averaged reputation cannot see coming
- [Prequential Competence](prequential-competence.md)) How much a peer's evidence weighs, learned from its record of forecasts against outcomes, and the regret bound that comes with it
- [Node Lifecycle](node-lifecycle.md) (Startup phases and state transitions
- [Partition Recovery](partition-recovery.md)) Split-brain detection, probe/response, and group merge
- [Cohort Clock Skew](cohort-clock-skew.md) (Measuring peer clock disagreement, and why peer reference clocks stay unbuilt
- [Persistent Cohort](persistent-cohort.md) (On-disk identity/group/reputation state and warm restarts
- [Integration Testing](integration-testing.md)) Metrics collection and scenario verification
- [Adversarial Testing](adversarial-testing.md) (Security validation via attack scenarios and CALDERA orchestration
- [SG2 Detection Walkthrough](sg2-detection-walkthrough.md)) Compromise detection and visualization in the DoD mission demo
- [Space Communications](space-communications.md) (Interplanetary link physics, delay routing, and orbital scenarios
- [Security Hardening](security-hardening.md)) Memory safety, RCE prevention, and input validation
- [ZTA Integration](zta-integration.md) (Zero Trust credential verification, DDIL fallback, and audit logging
- [ZTA Python Parity](zta-python-parity.md)) Python implementation of the ZTA admission gate and wire binding
- [Operator Access](operator-access.md) (Human operator authentication via PIV/CAC + MFA, session lifecycle, and the request-only operator node
- [Operator-Attended Signal](operator-attended.md)) Which nodes have a human behind them: the durable guardian binding and the consumer-pull attended-now attestation
- [App-Facing Peer Carrier](app-peer-carrier.md), What a hosting application learns about peers: the two carrier messages, the roster pull, and the flat app-facing ABI
