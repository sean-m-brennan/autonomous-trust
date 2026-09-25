# AutonomousTrust architecture

Technical architecture documentation for the AutonomousTrust cooperative computing framework.

## Contents

- [System overview](overview.md): Design principles and cryptographic foundation
- [Process architecture](process-architecture.md): Multiprocessing orchestration and IPC
- [Networking](networking.md): Network layer, channels, and message routing
- [TCP connection pooling](network-connection-pooling.md): Optional persistent connections, reuse, and persistent readers
- [Network wire format](network-wire-format.md): The JSON and protobuf envelopes, the group-carried format choice, and why detection stays unbuilt
- [Native/FFI dual implementation](native-ffi-dual-implementation.md): C runtime, CFFI bridge, Python↔C interoperability, and embedded/microdrone nodes
- [Identity protocol](identity-protocol.md): Peer discovery, voting, and group formation
- [First contact](first-contact.md): Adding a specific person you already know: the 1:1 introduction, signed invitations, and safety-number verification
- [Task negotiation](negotiation.md): Distributed task lifecycle
- [Reputation consensus](reputation.md): Paxos-based reputation scoring
- [Gateway reputation tree](gateway-reputation-tree.md): Multi-group membership and recursive subtree reputation
- [Reputation vs. blockchain analysis](reputation-vs-blockchain-analysis.md): Hash-linking, Merkle checkpoints, and slashing
- [Trust tiers](trust-tiers.md): Tiered capabilities, weighted transactions, bootstrap corpus, tier-gated access
- [Physical consistency](physical-consistency.md): Refuting a peer's claim on dimensions, bounds, kinematics and conservation, before any reputation math runs
- [Certificate-carrying interfaces](certificate-interfaces.md): Answers that arrive with a witness: duals, DRAT refutations, potentials and cuts, checked exactly
- [Calibration audit](calibration-audit.md): Auditing whether a peer's prediction sets cover as often as it claims: the overconfident peer an averaged reputation cannot see coming
- [Prequential competence](prequential-competence.md): How much a peer's evidence weighs, learned from its record of forecasts against outcomes, and the regret bound that comes with it
- [Node lifecycle](node-lifecycle.md): Startup phases and state transitions
- [Partition recovery](partition-recovery.md): Split-brain detection, probe/response, and group merge
- [Cohort clock skew](cohort-clock-skew.md): Measuring peer clock disagreement, and why peer reference clocks stay unbuilt
- [Persistent cohort](persistent-cohort.md): On-disk identity/group/reputation state and warm restarts
- [Integration testing](integration-testing.md): Metrics collection and scenario verification
- [Adversarial testing](adversarial-testing.md): Security validation via attack scenarios and CALDERA orchestration
- [SG2 detection walkthrough](sg2-detection-walkthrough.md): Compromise detection and visualization in the DoD mission demo
- [Space communications](space-communications.md): Interplanetary link physics, delay routing, and orbital scenarios
- [Security hardening](security-hardening.md): Memory safety, RCE prevention, and input validation
- [ZTA integration](zta-integration.md): Zero Trust credential verification, DDIL fallback, and audit logging
- [ZTA Python parity](zta-python-parity.md): Python implementation of the ZTA admission gate and wire binding
- [Operator access](operator-access.md): Human operator authentication via PIV/CAC + MFA, session lifecycle, and the request-only operator node
- [Operator-attended signal](operator-attended.md): Which nodes have a human behind them: the durable guardian binding and the consumer-pull attended-now attestation
- [App-facing peer carrier](app-peer-carrier.md): What a hosting application learns about peers: the two carrier messages, the roster pull, and the flat app-facing ABI
- [Extensions](extensions.md): How a feature adds IPC message types, app verbs and app-event kinds through registries instead of `#ifdef`s; the extension libraries (DTN, the gateway, the five oracle layers) and the scorer's oracle registry; and the static-link anchor rule
