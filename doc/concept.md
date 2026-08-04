*[AutonomousTrust](autonomous_trust.md) > Concept*

# AutonomousTrust Concept

AutonomousTrust (AT) is a framework for cooperative computing among machines that operate in a hostile environment without a reachable central authority. This document explains why AT is built the way it is. For how it is built, see the [architecture documentation](architecture/README.md); for a scenario that shows the ideas in motion, see the [example application](example-application.md).

## Adversarial assumption

AT assumes the environment is hostile at all times. Networked systems live in a continuous arms race, so AT does not treat a secure perimeter, a valid credential, or a peer that behaved well yesterday as evidence that the next message is safe. Every peer is a potential adversary until its behavior earns otherwise, and a peer that has earned trust can lose it the moment its behavior changes.

This is the opposite of the usual model, in which authentication grants standing trust and the system assumes good faith until something breaks. A credentialed but compromised peer is the case that model cannot see, and it is the case AT is designed for.

## Inverted access model

Traditional access control defaults to access. A subject who authenticates is let in, and administrators write policy to carve out what that subject may *not* do. AT inverts this. The default is no access. A peer starts every relationship at zero trust and gains reach only as it demonstrates trustworthy behavior, along a gradient rather than through a single yes-or-no gate.

Because trust is a live value, a node meters access in stages within one application:

1. refuse traffic from badly-trusted peers, to conserve bandwidth;
2. accept traffic but refuse compute to weakly-trusted peers, to protect CPU time;
3. offer compute but withhold data from moderately-trusted peers, to protect data;
4. share data with well-trusted peers.

The evaluation is done by the machine, continuously, not by a human writing policy for each asset, flow, and coalition partner. Human-authored policy does not scale to a large machine-to-machine population; behavioral evaluation at the node does. See [Trust Tiers](architecture/trust-tiers.md) for how the gradient is quantized into capability tiers.

## Machine as active participant

In AT the machine is responsible for its own safety. It is not a passive tool waiting for a person to make each security decision. The primary mode is machine-to-machine (M2M): the peers are non-person entities that discover one another, form groups, negotiate work, and decide whom to trust with no user present.

A human operator is a special, and largely degenerate, case. When a person is involved, they authenticate once through the operator console (PIV/CAC plus MFA), and from then on they are represented on the mesh by a machine identity like any other peer. The user interface is therefore one participant among many, not the seat of control. See [Operator Access](architecture/operator-access.md).

## Task-specific resource access

AT processes are always scoped to a specific task. There is no general-purpose, standing grant of resources. A peer requests the capabilities a piece of work actually needs, those capabilities are gated by the peer's current trust tier, and access is allocated for the task and released when the task ends.

This keeps the blast radius of any single compromised peer small. A captured peer can reach only what its task and its earned trust allow, not the whole system, so containment holds even before any anomaly is detected. Constraint does more work here than detection does.

## Familiar analogies

Two analogies help place AT for newcomers.

- **Service mesh.** Like a service mesh, AT sits between an application and the network and mediates every interaction between peers, following the Unix philosophy of small components that each do one thing and cooperate over a simple interface. The differences are that each component chooses its own level of participation, and the mediation is a live trust decision rather than static routing and fixed policy.
- **Reputation as ranking.** AT's reputation score behaves a little like PageRank. A peer's standing is derived from what other peers attest about it, weighted by their own standing, rather than assigned by a single central rater. That makes the score costly for any one peer, or a small colluding group, to dictate. See [Reputation Consensus](architecture/reputation.md).

## See also

- [Architecture](architecture/README.md): how these principles are implemented.
- [Example application](example-application.md): the concept in a worked scenario.
- [README](../README.md): quick start and project overview.
