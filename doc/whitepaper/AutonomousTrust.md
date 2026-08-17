*Previous: [The integration API](../api.md)*

---
title: AutonomousTrust subtitle: Cooperative computing among machines that don't
trust each other author: Sean M. Brennan date: August 2026
---
A technical introduction: motivations, philosophy, and mechanisms.

---

## Abstract

Zero Trust Architecture is the best answer the industry currently has, and it is
still humans writing rules for machines to enforce, with a central authority on
the hot path of every connection. Both properties fail at the edge. When the
link to the policy engine is jammed, no new connection can be approved. When a
credentialed endpoint is captured, every certificate check still passes. And
each new asset, flow, and partner multiplies the human policy surface
combinatorially.

AutonomousTrust (AT) is a framework for cooperative computing among peers that
do not fully trust each other and cannot count on a central authority to vouch
for anyone. Every peer starts untrusted, earns standing through observed
behavior in an iterated game, and is re-evaluated continuously. Every decision
is made at the node. Authentication opens the door; AT governs what happens
inside the room, and keeps governing it when the network is jammed, degraded, or
partitioned.

This paper covers the motivation, the philosophy, and then the mechanisms:
cryptographic identity over a Merkle DAG ledger, a hash-linked bilateral
reputation chain with evidence-gated slashing, leaderless Byzantine Multi-Paxos,
capability tier-gating, peer-to-peer negotiation, and a network built to survive
disconnection. It also covers how AT layers onto NIST SP 800-207 rather than
replacing it, where humans fit, what is built today, and how we prove any of it.

---

## 1. Motivation: conventional trust breaks at the edge

Zero Trust as normally built (NIST SP 800-207) is policy-driven and therefore
human-driven. It also assumes a reachable central authority (CA, OCSP, CRL) on
the hot path of *every* connection. That premise fails three ways.


| Failure mode                | Why it happens                                                                                                                                                                                                                                                                                                                           |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Dies when comms drop**    | SP 800-207 section 5.2 is explicit: an unreachable policy engine means no new connection can be approved. CRLs commonly run to tens of megabytes, which tactical SATCOM at 9.6 to 256 kbps cannot reliably pull; at Mars light-time, certificate rotation takes hours. The result is fail-open (insecure) or fail-closed (mission kill). |
| **Blind to behavior**       | A compromised endpoint with valid credentials and compliant device posture passes every check. Authentication says nothing about current conduct, and the compromised-but-authenticated asset is the most dangerous case there is.                                                                                                       |
| **Doesn't scale by policy** | Every asset, data flow, and coalition partner multiplies the human policy surface combinatorially, which guarantees gaps or over-restriction. Usually both.                                                                                                                                                                              |

These are not bugs to patch. They follow from the design premise, which is why
tuning the configuration does not help. Worse, a peer adversary will engineer
exactly these conditions on purpose: jam the link, partition the net, capture a
node. Denied, Degraded, Intermittent and Limited (DDIL) operation is the design
center here, not an edge case.

### 1.1 The reframe: authentication versus enforcement

> Authentication opens the door. AutonomousTrust decides what happens inside
> the room, continuously.

Conventional ZTA and ICAM grant implicit trust after login. One proof, then
trusted, for the life of the session. AT augments that with a continuous
behavioral gradient. Authentication proves *who*; AT governs *what*, *for how
long*, and revokes in real time. A valid credential earns a peer the right to be
*heard*, and is never a substitute for trust.

Authentication is not trust. Everything that follows is a consequence of taking
that sentence literally.

---

## 2. Philosophy: trust is earned, emergent, and local

Six commitments shape every mechanism in the system:

1. Zero-trust default-deny, so that every peer starts untrusted and identity
 alone implies nothing.
2. Standing accrues from observed behavior in an iterated game, rather than
 being conferred by fiat.
3. Peers confer standing, weighted by *their* standing, which yields a
 PageRank-like web of opinion instead of a central verdict.
4. Assume any peer may be hostile; least privilege, scoped to the task, bounds
 the blast radius when one turns out to be.
5. Uncertainty degrades access gracefully, and never silently grants it.
6. A human operator is just a privileged peer, running the same machinery with
 PIV/CAC and MFA.

### 2.1 Human trust as the design template

Our founding assumption is that human trust mechanisms, developed over at least
a hundred thousand years of hard selective pressure, are likely to be more
effective than anything we can design from scratch. They already solve the
problems distributed computing keeps rediscovering: cooperating with strangers,
detecting defection, scaling social structure past what any individual can
track, and recovering from betrayal. The academic literature on computational
trust is littered with domain-specific models that never left the lab. We would
rather copy what evolution has already optimized.

Human trust relationships break down into seven structural facets, and each one
has a direct machine implementation:

1. **Scale.** Social groups are cognitively bounded (Dunbar gives a maximum
 around 150, with tighter tiers at 5, 15 and 35), and larger organizations
 use hierarchy to loosely cohere the whole. In AT, peers communicate
 directly within a bounded enclave, and a dynamic hierarchy of peer leaders
 handles traversal between enclaves.
2. **Language.** Shared language is both efficient knowledge transfer and an
 in-group signifier. In AT, the message schemas an agent implements define
 which groups it participates in. Schema is membership.
3. **Shared goals.** Trust is barely needed when people merely work near each
 other, and becomes critical when they work *together*. In AT, goals are
 negotiated explicitly by protocol, and an agent with no business talking to
 you simply will not.
4. **Consistent identity.** Human trust cannot function without it, which is
 why false identity provokes reactions from embarrassment to violence. In
 AT, identity is cryptographic and recorded in a verifiable ledger.
5. **Reputation.** Standing enables indirect reciprocity: you act partly on
 how your action will affect your standing with third parties. In AT,
 bilateral transaction scores are weighted by the scorer's own standing.
6. **Optimization for strangers.** Where reputation information is sparse,
 humans fall back on heuristics such as the two-strikes rule. In AT,
 game-theoretic strategies carry the cold-start case.
7. **Prioritization.** Tracking trust is cognitively expensive, so humans use
 shortcuts, most visibly social roles. In AT, configurable strategy trades
 security against opportunity, and hierarchy makes discovery cheap.

### 2.2 The trust gradient in practice

Because trust is a live value in [0.0, 1.0] rather than a boolean, a single node
can meter access along a gradient. This is the inverted access model, and all
four levels operate in the same application at the same time:

1. Refuse traffic from badly trusted peers, to save bandwidth
2. Accept traffic but refuse compute to weakly trusted peers, to protect CPU
3. Offer compute but withhold data from moderately trusted peers, to protect
 data
4. Share data with well trusted peers

The payoff of treating trust as a number is that the same peer can be good
enough to talk to and not good enough to compute for. Conventional allow/deny
cannot express that.

### 2.3 Five bases of trust

Behavioral reputation is the interesting layer, and it is also the one that
needs history. A real-time system has to work before any history exists, so AT
leads with the bases that do not require it:

1. authentication and provenance (the existing credential stack)
2. hardware attestation, for the captured-asset case (TPM or secure element,
 measured boot)
3. least-privilege containment
4. delegated or transferred trust (a cohort vouches)
5. behavioral reputation

Bases 1 through 4 need no history. Base 5 requires an iterated game, which
raises the obvious objection: how do you assess a never-before-seen, one-shot
actor in real time? Two facts make that limit much less binding than it looks.
First, a real fleet is a small, persistent population of repeat players, so the
iterated game runs at identity-lifetime scale. Second, constraint beats
detection. Bases 1 through 4 do the heavy lifting up front, and behavioral
detection refines rather than gates.

---

## 3. Architecture at a glance

AT is decentralized by construction. Groups form organically, reputation is
maintained by leaderless Byzantine Multi-Paxos, and tasks are negotiated peer to
peer. Four cooperating subsystem processes do the work:

- **Network.** Transport, encryption, discovery
- **Identity.** Who a peer is, and admission
- **Negotiation.** What work gets done, and for whom
- **Reputation.** How much each peer is trusted

Cryptography is NaCl/libsodium throughout, with no novel primitives:


| Operation               | Primitive                               |
| ----------------------- | --------------------------------------- |
| Signing                 | Ed25519 (identity, votes, message auth) |
| Peer-to-peer encryption | X25519 + XSalsa20-Poly1305 (NaCl Box)   |
| Group encryption        | shared symmetric key (NaCl SecretBox)   |

Private keys never touch the wire. Announcements carry public keys only.

An AT node deploys as a small resident agent co-located with the application it
protects, sitting between that application and the network as its own policy
decision and enforcement point. Where a device cannot host code at all, the same
agent runs as a bump-in-the-wire gateway on its data bus. The C core is
bounded-memory and deterministic, and the anomaly layer keeps fixed per-peer
state with no backhaul to a data lake, so the agent can run as a low-priority
co-resident process or offload to the gateway entirely. A compute-starved sensor
carries little or none of the trust-evaluation cost.

---

## 4. Identity

### 4.1 Keys and names

Each identity holds two separate key pairs: an Ed25519 signing pair, for
one-to-many verification, and an X25519 encryption pair, for one-to-one Box.
Private material stays local, and `publish()` yields a public-only copy of the
identity for the wire.

Naming is Zooko-style, which is how we get decentralized, human-meaningful and
secure names at once instead of picking two:

- `nickname` is the online global name (for example
 `squad-warrant@dod-demo`), and it is the only name that appears on the wire.
- `petname` is the local name each receiver mints for itself. It is never
 serialized, so nobody can inject a name into your namespace.

Every identity also carries a stable UUID. Duplicate UUID, signing-key, or
encryption-key collisions are rejected on sight.

The canonical wire form is a flat JSON document that is byte-identical between
the Python and C implementations. That is the interoperability contract, and
section 11 explains how we hold ourselves to it.

### 4.2 A verifiable ledger with permissionless admission

Identity history is a DAG of Merkle roots. The useful analogy is *git*: identity
blobs are diffs, Merkle roots are commits, and divergent branches merge at their
lowest common ancestor. Membership is provable by Merkle inclusion proof, and
backdating is rejected by timestamp monotonicity.

Admission is permissionless but Sybil-resistant, on what amounts to a
border-guard pattern:

`announce` (open broadcast) -> *choose group* (adopt longest history) ->
`request_access` -> peers `vote_on_peer` (Ed25519-signed) -> `peer_accepted` ->
`full_history` (group key and DAG, encrypted)

The agreement algorithm behind the vote is pluggable: Proof of Work, Proof of
Stake, or Proof of Authority, chosen to suit the deployment. Peers with a known
UUID (the amnesia and restart cases) skip the vote, and a membership change
propagates a group-key update to the cohort.

Note what admission does *not* do. It does not confer standing. A peer that has
just been voted in has been granted the right to be heard, and has a reputation
of zero.

---

## 5. Reputation

### 5.1 The transaction ledger

Reputation rests on a hash-linked, bilateral transaction chain. It is not a
global blockchain, which would be the wrong CAP and resource trade for a
small-memory, intermittently connected mesh. It is a bounded, per-node
verifiable commit log.

Every `Transaction` is intrinsically bilateral, with two counterparties and two
scores, so no peer can fill both sides of a record. Hash-linking (blake2b
`prev_hash`) chains committed entries, which makes a tampered segment
*detectable*, so peers sync by verifying rather than by trusting. A Merkle
window root (RFC 6962, domain-separated to defeat CVE-2012-2459) gives O(log n)
inclusion audit. A quorum co-signs that window root as a signed checkpoint,
which acts as a lightweight finality gadget. The window itself is bounded, 200
entries by default, with FIFO eviction and tombstones to prevent zombie
re-insertion of evicted records.

### 5.2 How a score is computed

Scores live in [0, 1], with no negatives. The thresholds come from a single
source and are environment-overridable:


| Value                      | Meaning                                                       |
| -------------------------- | ------------------------------------------------------------- |
| **0.2**                    | cold-start / neutral prior (`PREREP_NEUTRAL`)                 |
| **0.1**                    | communication cut-off; below this, peers stop relaying to you |
| **0.0**                    | slash floor                                                   |
| **0.5 / 0.65 / 0.8 / 0.9** | trust-tier floors (1 through 4)                               |
| **0.21**                   | idle-decay asymptote                                          |

Two modes drive the score, with hysteresis in the band [0.45, 0.55] retaining
whichever mode was already in effect. Cooperation mode is pure reputation: the
trust-weighted average of counterparties' scores, multiplied by their standing
and the task weight. Contrite Tit-for-Tat is the principled response to a
counterparty defecting against *you*, and it is what keeps always-defect from
paying.

Idle decay is deliberately asymmetric. An idle peer relaxes toward 0.21, but
decay never rehabilitates a low or slashed peer. Waiting quietly is not a
recovery strategy.

### 5.3 Consensus and slashing

Agreement on reputation runs as leaderless Byzantine Multi-Paxos, so there is no
coordinator to capture, and none to lose.


| Phase | Messages                                   | Purpose                                                                                      |
| ----- | ------------------------------------------ | -------------------------------------------------------------------------------------------- |
| 1     | `request` -> `grant` / `nack` / `backdate` | ask permission; proposal id is (timestamp, chain-index, peer) with a replay-idempotent guard |
| 2     | `transaction` -> `accepted`                | on majority grant, propose the score; commit on majority accept                              |
| 3     | `committed` (broadcast)                    | every peer writes the*same* bilateral entry                                                  |

A node that has fallen behind catches up by querying its top three most-trusted
peers and majority-voting the result, which is then verifiable against the chain
links rather than taken on faith.

Slashing is the fast path. A quorum-co-signed (Ed25519), evidence-gated
`SlashAttestation` floors a score immediately, instead of waiting roughly twenty
transactions for a weighted average to move. That is what catches the
short-lived rogue, which is precisely the case a moving average handles worst.

Exclusion is sticky. A cut-off peer cannot transact its way back in, and
recovery is an explicit, signed `rehabilitate`.

### 5.4 Two orthogonal axes: rank versus trust tier

AT deliberately separates *where you sit in the network* from *how much you are
trusted*. Existing systems tend to conflate these, and it causes trouble.

Rank is topological. It describes one-hop and gateway reachability, is mostly
static and configuration-derived, and gates routing, partition leadership, and
Proof of Authority votes.

Trust tier is reputation-derived. Its floors are 0.5, 0.65, 0.8 and 0.9, giving
tiers 1 through 4. It moves with behavior (with hysteresis), and it gates
capability access, transaction weighting, and Proof of Trust votes. It is never
serialized, because a tier is *other peers'* opinion of you and not yours to
assert.

A powerful radio at the center of the mesh has high rank and must still earn a
high tier. Capability and trustworthiness are different questions.

---

## 6. Negotiation and agreement

### 6.1 Getting work done, safely

The task lifecycle runs on the encrypted peer-to-peer channel:

`spawn task` -> `invitation` (fan-out to peers advertising the capability) ->
`ack` / `nack` / `haggle` (counter-offer) -> `report results` (with
zero-knowledge proof)

Invitations are tier-gated: a request is refused when the sending tier falls
below the capability's `required_tier`. The *local* capability definition is
authoritative, so a peer cannot talk you into relaxing your own requirement.

Tier loss cancels work in flight. If a peer is demoted mid-task, whatever it is
no longer authorized for is cancelled automatically rather than being allowed to
finish on the strength of a standing it no longer has.

This is where trust composes. The requester verifies the result's zero-knowledge
proof, then submits a transaction score, which feeds Reputation, which adjusts
the tier that gates the next invitation.

### 6.2 One agreement framework, two voter bases

Proofs are Ed25519-signed and tallied by a threshold of the top third of
eligible voters. The framework is shared; the electorate is not:

- Proof of Authority weights votes by rank, meaning topology and capability.
- Proof of Trust weights votes by tier, meaning earned reputation. This is the
 right choice for behavior-dependent decisions such as data sharing.

### 6.3 Bootstrapping from cold

Which leaves the cold-start problem: how does a brand-new mesh earn *any*
reputation, when every mechanism above assumes some? Through a bootstrap
capability corpus, auto-registered on every node. Three capabilities carry it:
`at.handshake` (a signed-nonce challenge), `at.time-attest` (clock agreement
within 200 ms), and `at.echo-challenge` (a signed echo). Paced, deterministic
pairwise interactions seed the first honest scores, at which point the ordinary
machinery has something to work with.

---

## 7. Networking: built to survive disconnection

### 7.1 Three channels, by trust level

1. Open broadcast (UDP, unencrypted) carries *announcements only*
2. Encrypted group (NaCl SecretBox, shared key) carries proposals, votes, and
 Paxos traffic
3. Encrypted peer-to-peer (NaCl Box) carries history, negotiation, and
 reputation

### 7.2 Transports

Transports are a UDP and TCP hybrid, with length-prefixed framing on TCP.
Connection pooling is optional and leaves the wire bytes unchanged, which is
what allows C and Python nodes to interoperate regardless of which one has it
enabled.

Messaging is itself a trust-scored transaction, so unwanted or spurious traffic
costs the sender reputation. Flooding is self-defeating: the attacker's standing
collapses and the network stops relaying for it. Because decryption is streamed,
a connection can also be cut mid-message once the sender is known to be
untrusted.

### 7.3 Partition recovery

Split-brain groups sharing a broadcast domain detect each other by signed probe
and response. The larger group wins under a symmetric adopt test, and members of
the smaller one re-admit and merge. Layer-3 backstops periodically re-sync
per-peer state that was dropped along the way.

Everything degrades to local decisions and reconciles on reconnect. That is the
whole point of the design, and it is why none of the mechanisms above put a
central service on the hot path.

---

## 8. Layering Zero Trust

AT extends NIST SP 800-207 rather than replacing it. A peer still needs valid
credentials to be heard, and behavioral reputation is the operative boundary
*after* connection. Every ZTA requirement stays in place: identity verification,
least privilege, session management, micro-segmentation.

### 8.1 The pluggable verifier

The verifier interface is `verify` / `check_revocation` / `is_available`, and
the whole subsystem is build-gated by `AT_ZTA`:

- An X.509 verifier (OpenSSL and pyca) checks chain and expiry, with optional
 OCSP and CRL. This ships in both implementations.
- An OIDC verifier exists as an interface and is a stub today.

The credential is bound to identity by SHA-256 hash and excluded from identity
equality, which means routine certificate rotation never disturbs accumulated
reputation. This matters more than it sounds: tying standing to a credential
that rotates on a schedule would throw away the history on every rotation.

### 8.2 DDIL fallback and delegated verification

If the CA or OCSP responder is unreachable, AT admits the peer at a capped
reputation and reconciles later. Peers already holding high standing can vouch
for it (delegated verification), which lifts the cap on quorum. An append-only
audit log reconciles when the link returns.

Standard central path validation puts an OCSP round-trip or a large CRL on the
login hot path, and then confers implicit trust for the rest of the session. AT
keeps the high-assurance credential check for proof of human identity but pays
for it once, at console activation, bound to the local cryptographic identity
and off the per-access hot path. Where an edge console cannot reach the PKI at
all, a connected gateway validates (OCSP stapling, or cached short-lived
revocation pre-staged while connected) and vouches through quorum-gated,
reputation-weighted delegation. These are in-spec techniques. What AT adds is
making them autonomous, so the disconnected operator is verified through the
cohort instead of being forced to fail open or fail closed.

An adversary will notice this and try to shrink the reachable quorum by jamming
or partitioning, precisely to force the fallback. AT still does not fail open. A
sub-threshold quorum admits only at a capped reputation ceiling with a reduced
tier gate, gated by the history-independent bases (cryptographic identity and
hardware attestation), and every admission is signed as evidence for
reconciliation later. The access that results is contained and capped, which is
the honest answer for that situation.

### 8.3 Micro-segmentation and compartments

Micro-segmentation falls out of the design: per-group encrypted channels and
keys, capability tier-gating (`required_tier` 0 through 4, running network ->
communication -> services -> data-sharing), task-specific resource access, and
mid-message early cutoff.

The tier ladder is hierarchical, and hierarchy alone cannot express
need-to-know. Compartmented data control adds the missing non-hierarchical axis:
each datum or capability, and each peer grant, carries an access class of
(required_tier, compartment-set). Access requires *both* tier dominance (peer
tier >= required_tier) and containment (the compartment set contains the
object's). This is ordinary lattice semantics, in the Bell-LaPadula sense,
layered on top of the existing tier gate without modifying it.

The two axes are orthogonal and separately sourced, which is the part worth
getting right. A mission-impact and dependency mapping sets the hierarchical
tier floor and the safety-critical flag, and that is a question about
criticality. Compartment and need-to-know tags derive from the authoritative
classification or community-of-interest marking, and that is a question about
confidentiality. A datum can be mission-critical yet uncompartmented, or
low-impact yet tightly compartmented. Labels are configured once at planning
time, and AT enforces the conjunction at runtime.

---

## 9. Humans in the loop, and behavioral sensing

### 9.1 Operator attestation

A human operator is a peer, with two signals marking the fact: `operator_bound`
and `operator_attested_at`, which together say that a human stands behind this
node.

That status is earned, never advertised. A claim arriving on the wire is
neutralized at admission and set true only if a *distinct operator credential*
verifies. Otherwise the flag would be the easiest lie in the system.

Operator access itself is PIV/CAC plus MFA, with TOTP as the default because it
works when the network does not. The private key never leaves the card, and the
path is fail-safe.

### 9.2 The behavioral anomaly layer

The behavioral anomaly layer is a Python prototype today, and it is a *sensor*,
not a decider.

Each node models the behavioral envelope of every peer and role, and emits a
per-peer anomaly score with per-feature attribution. The detectors are online
and explainable (River's Half-Space Trees plus a per-feature streaming histogram
in the HBOS and LODA family), which makes them unsupervised, bounded-memory, and
deterministic under a fixed seed. Determinism is not an aesthetic preference
here: a non-deterministic score cannot be signed evidence, and signed evidence
is the only currency the consensus layer accepts.

ML proposes; consensus disposes. A per-node governor emits a *slash proposal*,
and the signed quorum flow decides. Safety-critical access stays
human-on-the-loop by default, with a fail-safe default and manual override by an
accountable decision-maker. Dwell and quorum guards exist to defeat the
base-rate fallacy, which is the failure mode Axelsson identified for intrusion
detection in 2000: when attacks are rare, a naive detector's false positives
swamp its true ones.

Enterprise UEBA platforms assume continuous backhaul to a data lake and a
passive sensor model. Both assumptions fail under DDIL, which is why the
analytics run on-device and the evidence path is cryptographic rather than
advisory.

---

## 10. Security

### 10.1 Attacks neutralized by the architecture

**Man-in-the-middle and spoofing.** All traffic is encrypted end to end, and
signing keys never leave the node. There is nothing useful to intercept and no
way to impersonate a peer without its private key.

**Compromised but authenticated endpoints.** This is Zero Trust's blind spot and
our reason for existing. Valid credentials are irrelevant to a tier decision;
behavior is what counts.

**Supply-chain compromise of the SunBurst class.** The 2019 to 2020 SunBurst
attack through SolarWinds Orion was undetectable by state-of-the-art tooling
once inside the network, because attacker activity was indistinguishable from
that of valid developers. Under AT, even developers hold no direct access to the
build system, which removes the injection point, and any component running
inside an AT network is confined to the scope of its negotiated schema. When the
Trojan Horse phones home or reaches for systems outside its specification, its
standing collapses and its access goes with it.

**Denial of service and flooding.** Messaging is trust-scored, untrusted senders
are cut off mid-stream, and flooding costs the attacker the reputation it needs
in order to keep flooding.

**Metadata harvesting.** Identity and address pairs appear only in direct
messaging, the system tolerates long-latency near-contact networking that
minimizes even that, and identities can be anonymous in domains that do not
require disclosure.

### 10.2 Attacks requiring active resistance

**Deceit.** A malicious agent may falsify data or results. This does not survive
the presence of competing providers, and cross-source physical consistency
catches it directly where the data are corroborable.

**Insider betrayal.** An agent builds standing patiently, then spends it. The
attack is expensive by construction: reputation is public, betrayal is a
one-time event for a given identity, and evidence-gated slashing means the exit
is fast. Starting over starts at zero.

**Collusion and reputation gaming.** A group drives a target's standing down
through low scores or false gossip. Peer leaders can independently review gossip
claims, and the target's connections outside the enclave act as a check.
Whitewashing and on-off strategies are raised in cost by cryptographic identity
and reputation weighting rather than eliminated. Worth saying plainly: any
adversary in a position to mount this already holds the credentialed foothold at
which conventional ZTA has silently failed, and AT at least leaves signed,
auditable evidence behind.

**Sybil.** Many identities under one entity's control. The textbook defense is
expensive identity generation. AT inverts that: identities are cheap, and
reputation is not. Impatient Sybils are trivial to ignore. Patient Sybils that
invest in standing first are the serious case, and they reduce to insider
betrayal.

**Atomization, or the Eclipse attack.** Malicious peers isolate a target and
feed it false data and false scores. Connections outside the enclave mitigate
it, and the social fences make isolation structurally hard to arrange.

**Rogue authority.** A peer leader abuses its position to censor or deceive its
enclave. Leaders are held to stricter standards than peers, any peer can compete
for leadership, and a leader that stops participating loses standing without
anyone intervening.

**Ledger attacks.** Attempts to corrupt a chain by injecting bad entries or
overwhelming consensus run into two disparate ledgers with different agreement
mechanisms, hash-linked entries, quorum-signed checkpoints, and the reputation
investment such an attack requires up front.

### 10.3 Social fences

A few rules are hard-coded and non-negotiable. Violating one collapses
reputation immediately, with no appeal, because the alternative is a rule that
sufficient standing can buy its way past.

**Freedom of association.** No agent may block another agent's communications
with third parties. Man-in-the-middle blocking is a fence violation. This is the
fence that makes authoritarian attacks expensive.

**Rule of law.** Agents higher in the emergent hierarchy are held to *stricter*
standards, not looser ones. Reputation thresholds for leadership exceed those
for peers.

**Skin in the game.** A hierarchical leader must be a full participant in the
domain it oversees. A leader that does not interact meaningfully with its
enclave loses reputation, which is what keeps out absentee authorities and
holders of empty credentials.

The fences cannot be reconfigured, negotiated away, or overridden by reputation.
They are structural, and closer to a constitutional constraint than to a policy
rule.

### 10.4 Dispute resolution

When peers disagree about scores, data validity, or negotiated terms, resolution
is structured rather than ad hoc. Competing claims are tested against observable
evidence, and corroboration outweighs assertion. The local peer leader can
review disputed transactions and render judgment, always locally, because there
is no global arbiter to appeal to. Discipline is graduated rather than binary:
not every failure ends in exile, and some end in reduced standing, closer
scrutiny, or a temporary restriction.

---

## 11. Two implementations, one contract

There are two implementations of AT, and the division of labor is deliberate.

Python is the reference and development runtime. It exists for rapid iteration,
simulation, and scenario authoring, and it serves as an executable specification
of the semantics.

C is the production and fielded runtime. It runs the embedded and ARM daemon
(`at_demo`), so no Python is needed on-device, and it is under Frama-C/WP
verification with ACSL contracts: 100% of attempted proof goals discharged
(4,262 of 4,262) at roughly 54% function coverage, with documented skips.

The two are wire-interoperable. The backend is chosen at import
(`AUTONOMOUS_TRUST_BACKEND = auto | native | python`) and overlaid per module
through CFFI, so a mixed fleet is normal rather than exceptional.

The corpus is the contract. A cross-language conformance suite (roughly 114
cases at v1, over 150 today) runs *both* harnesses over shared scenarios and
byte-pins signatures, proofs, and envelopes. An asymmetry diff fails CI the
moment the two disagree about anything.

That is the assurance story in one line: the fielded artifact is C, the C is
formally verified, and the conformance corpus proves the C behaves byte-for-byte
like the readable Python reference. Provability without giving up iteration
speed.

---

## 12. Tooling and ecosystem

Namespace packages layer on the core:


| Package        | Role                                                                                                                                               |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| **inspector**  | Live and playback dashboards (Dash and Plotly): trust timeline, per-peer detail, mesh graph, sensor charts, event log                              |
| **simulator**  | Multi-node mesh with mobility paths and radio physics: terrain, delay, routing, and a space link (free-space loss, light delay, occultation)       |
| **evaluation** | Metrics collector, modeling and simulation performance harnesses, and a red-team suite (Byzantine, Sybil, MITM, reputation-gaming; Caldera bridge) |
| **services**   | Application data carried over AT trust: environmental sensors, fusion, video, position                                                             |
| **behaviour**  | The behavioral anomaly layer (prototype; the formally verified C twin is deferred)                                                                 |

---

## 13. See it run

The multi-agency disaster-response demo runs in-process, with no Docker
required:

```
python -m examples.multi_agency      ->  dashboard at http://localhost:8050
```

Ten federal sensors form a trust mesh, and one of them is compromised. The
network excludes it on its own, locally and continuously and with signed
evidence, while the rest keep cooperating. No central authority is consulted at
any point, and nothing fails open. That is the whole idea, and it is worth
watching happen rather than taking on description.

The same shape holds for a tactical thread. Several ISR sensors, a track fusion
and targeting node, and an effects console spread across disadvantaged nodes on
a thin link. In steady state, a sensor's tracks reach the targeting node only
while both endpoints hold standing above the required tier. A sensor that is
authenticated and certificate-valid, but captured or spoofed, and now injecting
an off-track return, drifts outside its learned envelope, loses standing, and is
slashed and gated out of the fires path locally and in real time, with signed
evidence, while a human retains override on anything safety-critical. When the
link to the policy engine and the PKI drops, the cohort keeps working: the
targeting node is vouched for by quorum at a capped tier, each admission is
signed, and the audit reconciles on reconnect. No step in that loop waits on a
reachable central authority.

---

## 14. Where else this applies

The problem AT solves, proving trust when the link back to a central authority
is gone, is not peculiar to defense. Wherever machines outnumber people and the
network cannot be assumed, a PKI round-trip becomes a single point of failure.

Industrial and critical infrastructure operators run thousands of long-lived
controllers on flat networks, where a stolen certificate opens every door. A
behavioral envelope per controller means a valid but hijacked device that starts
issuing off-profile commands is gated out locally, in milliseconds, without
waiting on a security operations center that may itself be cut off. That is a
direct limit on ransomware lateral movement.

Space and delay-tolerant networks live in permanent DDIL, where light-lag makes
a central check impractical. Cohorts vouch for one another, admit peers at
capped tiers under partition, and carry signed evidence back for reconciliation.
Constellations, cislunar relays and deep-space assets need trust that survives a
twenty-minute round trip.

Financial services need machine-to-machine trust that survives a data-center
partition and still yields a tamper-evident record for regulators.
Inter-institution settlement, ATM and point-of-sale fleets, and automated
trading fit the Merkle-checkpointed ledgers, which give immutability and
distributed agreement without the cost and latency of a global blockchain.

Healthcare devices such as infusion pumps, imaging systems and home telemetry
must keep operating and stay verifiable when the hospital uplink drops. AT
protects device and exchange integrity at the edge and leaves an auditable
trail.

Agentic AI is the clearest emerging case. As autonomous software agents
proliferate and act on our behalf, the question stops being whether an identity
is valid and becomes whether an agent is still behaving as it should. That is
exactly what AT evaluates, continuously and without a human in the loop.

The common thread is one capability: keep Zero Trust guarantees when the central
authority is unreachable, at the scale and cost of operational technology. The
addressable market is every fleet of machines that cannot afford to fail open or
fail closed.

---

## 15. Status

AT is a working prototype, not a concept paper, and it is built entirely on
current technology: standard cryptographic libraries, established consensus
algorithms, game-theoretic strategies with decades of literature behind them,
and small messages over any connection. No special hardware, no unproven
primitives, no centralized infrastructure.

### 15.1 What is built

The core process framework, the multiprocessing architecture that orchestrates
the subsystems, is mature. The C library mirrors the Python core in more than
17,000 lines, builds as both a shared and a static library, and carries the
formal-verification status described in section 11. Protobuf protocol
definitions are complete across all subsystems.

Identity handles peer registration with pluggable admission agreement. The
network subsystem provides UDP and TCP messaging with heartbeats and partition
recovery. Negotiation implements the task protocol with tier gating and
tier-loss cancellation. Reputation implements bilateral scoring, hash-linked
chaining, Merkle checkpoints, evidence-gated slashing, and the Paxos consensus
flow. The ZTA overlay ships the X.509 verifier with OCSP and CRL, the DDIL
fallback, delegated verification, and the append-only JSONL audit log.

Around that core sit the inspector dashboards, the simulator with mobility and
radio physics, the evaluation and red-team harnesses, and the services layer. An
earlier demonstration wired an ML ISR pipeline (YOLOv8-OBB) into AT as a
trust-scored capability and exercised cross-source physical-consistency fusion,
which is where the 97.5 m compromised-drone detection came from. Cohorts up to
25 peers form and detect anomalies cleanly; that ceiling is emulation fidelity
rather than anything in the protocol, and a 100-node study is the next step.

The test suite spans unit, integration, conformance and system tests, with
working example deployments.

### 15.2 What remains

The system is in alpha, and several mechanisms exist in structure and need
hardening before anyone points an adversary at them.

Formal-verification coverage stands at roughly 54% of functions, and extending
it across the reputation and consensus modules is queued work. The behavioral
anomaly layer is a Python prototype, and its formally verified C twin is
deferred. Compartment labels are designed but not yet enforced at runtime. The
OIDC verifier is a stub, and the operator console needs full CAC and MFA
integration along with hardware root-of-trust attestation for the captured-asset
case. Protocol-aware enforcement adapters for operational technology (Modbus
TCP, DNP3, OPC-UA, BACnet) are not built. Scaling beyond 100 nodes is unproven.

These gaps are documented and tracked. They are engineering work on an
architecture we consider sound, rather than symptoms of design uncertainty. The
mechanisms that matter, behavioral trust evaluation, game-theoretic
bootstrapping, verifiable identity and reputation ledgers, emergent hierarchy,
and partition recovery, are implemented and demonstrable today.

---

## 16. The through-line

Trust is earned, continuous, and decided locally.

Authentication opens the door. AutonomousTrust governs the room, and keeps
governing it when the network is jammed, degraded, or partitioned. Everything
above (the Merkle chains, the Paxos, the tiers, the ZTA layering, the anomaly
detectors) exists to make those three words hold up against a real adversary in
a real DDIL environment.

---

*Next: [High-trust computing whitepaper](HighTrust.md)*
