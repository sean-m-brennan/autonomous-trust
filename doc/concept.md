*Previous: [The optional stack](../../../doc/the-stack.md)*

# Trust as a live value

Almost every access control system ever built asks one question at the door and
never asks it again. Present a credential, get admitted, and from that moment
the system treats you as the credential says you are. Everything after admission
is a matter of what policy permits the admitted party to do.

That arrangement has a blind spot with a name. It cannot see a peer that holds a
perfectly valid credential and has been taken over. The certificate is genuine,
the signature verifies, the identity is exactly who it claims to be, and the
thing behind it is now working for somebody else. Nothing in the model is
looking at behavior, so nothing in the model notices.

AutonomousTrust is built for that case and for one other: the case where the
authority that issues credentials cannot be reached. On a mesh network under
jamming, in a habitat behind twenty minutes of light-lag, or in a valley whose
gateway just went down, a system that must consult a central policy service has
two options and both are bad. Fail open, and the compromise walks in. Fail
closed, and the network stops working at exactly the moment it was needed.

The alternative is to make trust a value that each node computes for itself,
continuously, from what it has actually observed. A peer starts every
relationship at zero. It earns reach by behaving well in dealings that really
happened. It loses reach when its behavior changes, within seconds, without
anybody filing anything. And every part of that judgement is made locally, so it
keeps working when the node is cut off from everything.

This chapter is why the framework is built that way. The chapters after it are
how.

## The adversarial assumption

AutonomousTrust assumes the environment is hostile at all times, and it assumes
this permanently rather than during an incident.

Networked systems live in a continuous arms race. A secure perimeter is a claim
about yesterday, a valid credential is a claim about the issuer rather than the
holder, and a peer that behaved well an hour ago is evidence about an hour ago.
None of the three is evidence that the next message is safe, so the framework
treats none of them that way. Every peer is a potential adversary until its
behavior earns otherwise, and a peer that has earned trust can lose it the
moment its behavior changes.

This inverts the usual posture, in which authentication grants standing trust
and the system assumes good faith until something visibly breaks. Although that
posture is comfortable, and although it is nearly universal, it is precisely
wrong for the threat that matters most, since the credentialed-but-compromised
peer is the one case it cannot represent at all.

## Access as a gradient, not a gate

Traditional access control defaults to access. A subject who authenticates is
let in, and administrators write policy to carve out what that subject may *not*
do. The default is yes and the exceptions are written by hand.

AutonomousTrust inverts this too. The default is no access. A peer starts every
relationship at zero trust and gains reach only as it demonstrates trustworthy
behavior, along a gradient rather than through a single yes-or-no gate.

Because trust is a live value rather than a one-time check, a node meters access
in stages within one application, and the stages are chosen so that each one
protects a different scarce resource. An agent using this framework can
adaptively: 1) refuse communications from severely untrusted peers, conserving
bandwidth; 2) communicate with but refuse computation services to faintly
trusted peers, protecting CPU time; 3) offer services but refuse data-sharing to
moderately trusted peers, protecting data; and 4) offer data-sharing to well
trusted peers, all with a configurable gradient of access at every level.

The evaluation is done by the machine, continuously, rather than by a person
writing policy for each asset, each flow, and each coalition partner.
Human-authored policy does not scale to a large machine-to-machine population.
Behavioral evaluation at the node does, and it does so without asking anybody's
permission at the moment it matters.

## The machine as an active participant

In AutonomousTrust the machine is responsible for its own safety. It is not a
passive tool waiting for a person to make each security decision.

The primary mode is machine-to-machine. The peers are non-person entities that
discover one another, form groups, negotiate work, and decide whom to trust with
no user present. This is not an efficiency measure. A population of machines
large enough to be useful is a population too large for a person to adjudicate,
and a network that only works while somebody is watching it is a network that
fails overnight.

A human operator is a special and largely degenerate case. When a person is
involved, they authenticate once through the operator console with a hardware
credential and a second factor, and from then on they are represented on the
mesh by a machine identity like any other peer. The user interface is therefore
one participant among many rather than the seat of control.

That framing has a consequence the upper tiers depend on heavily. Because a
human is present on the mesh only through a machine that stands for him, the
question of which machines have a person behind them, and whether that person
was there recently, becomes a first-class thing the network tracks rather than
an assumption it makes. That signal is the subject of a later chapter, and it is
what the polity tier reads when it asks which human answers for which machine.

## Task-specific access

AutonomousTrust processes are always scoped to a specific task. There is no
general-purpose standing grant of resources.

A peer requests the capabilities that a particular piece of work actually needs.
Those capabilities are gated by the current trust tier of that peer. Access is
allocated for the duration of the task and released when the task ends. Nothing
accumulates, and no grant outlives the reason it was made.

This keeps the blast radius of any single compromised peer small. A captured
peer can reach only what its task and its earned trust allow, rather than the
whole system, so containment holds even before any anomaly is detected.
Constraint does more work here than detection does, which is the correct
division of labor: detection is a race against an adversary, and constraint is
not.

## Two familiar analogies

Two comparisons help place the framework for a reader coming from ordinary
distributed systems, and both break in instructive places.

Like a service mesh, AutonomousTrust sits between an application and the network
and mediates every interaction between peers, following the Unix philosophy of
small components that each do one thing and cooperate over a simple interface.
The differences are that each component chooses its own level of participation,
and that the mediation is a live trust decision rather than static routing under
fixed policy.

Like PageRank, the reputation score of a peer is derived from what other peers
attest about it, weighted by the standing those peers themselves hold, rather
than assigned by a single central rater. That recursion is what makes the score
costly for any one peer, or any small colluding group, to dictate. The
difference is that the graph here is a graph of observed conduct rather than of
citations, and that it is recomputed continuously rather than crawled.

## Where this sits in the stack

AutonomousTrust answers exactly one question, which is who may cooperate, and it
answers it among machines inside a single trust boundary. Two things follow, and
both matter for the tiers above.

Participation is anonymous by default and that is deliberate. Inside one
community, an identity is a public key and a history of conduct, and nothing
requires it to name a person. Anonymity here is a protection rather than a
weakness, since it lets a node participate without its operator bearing the
social cost of being seen to do so.

And the framework produces cooperation without producing a community. What
emerges from a working mesh is a cluster of nodes that reliably deal with each
other, which is a topological fact rather than a body that can act. It has no
boundary anyone agreed to, no memory of decisions, no offices, and no way to
persist as its members turn over. Making that cluster into something that can
sign an agreement is the work of the next tier, and it is why the next tier
exists.

## Further reading

- [The security model](security.md): the threat model, the containment
  properties, and the residual risk that the design accepts.
- [Zero Trust integration](architecture/zta-integration.md): how credential
  verification and behavioral reputation compose rather than compete, and what
  happens when the verification infrastructure is unreachable.
- [Reputation against blockchain](architecture/reputation-vs-blockchain-analysis.md):
  why the ledger is hash-linked and checkpointed rather than mined, and what
  slashing buys.
- [Machine-to-machine security](m2m_security.md): the security model stated for
  the case where no person is present at either end.

---

*Next: [How a node is built](architecture/overview.md)*
