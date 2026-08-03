---
marp: true
theme: tekfive
paginate: true
header: 'AutonomousTrust'
---
<!-- _class: lead -->

<!-- _header: ' ' -->

# AutonomousTrust

## Cooperative computing among machines that don't trust each other

A technical introduction: motivations, philosophy, and mechanisms.

<!--
Speaker: This deck assumes you've never seen AutonomousTrust (AT). We'll go
motivation -> philosophy -> the core mechanisms (identity, reputation, tiers,
negotiation, network) -> then touch the security layer (ZTA), the tools, and how
we prove any of it. The through-line: trust is earned continuously and decided
locally, so the system keeps working when the network doesn't.
-->

---

## What is AutonomousTrust?

**A framework for cooperative computing among peers that do not fully trust each other and cannot count on a central authority to vouch for anyone.**

- Peers exchange encrypted data only with peers they trust, and only up to the level that trust allows.
- Trust is never granted once and kept. Every relationship starts at zero, and standing is earned through observed behavior.
- Standing is re-evaluated continuously, so a peer whose behavior changes is reclassified in real time.
- Every decision is made at the node, with no round-trip to a central policy engine or PKI.

<!--
Speaker: Two ideas do all the work here. First, trust is a live value, not a
one-time boolean. Second, the decision is local. Hold onto both; every mechanism
later is in service of them.
-->

---

## Motivation: conventional trust breaks at the edge

Zero Trust as normally built (NIST SP 800-207) is policy-driven, and therefore human-driven. It also assumes a reachable central authority (CA / OCSP / CRL) on the hot path of *every* connection. That premise fails three ways:


| Failure mode                    | Why it happens                                                                                                                                                                 |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Dies when comms drop (DDIL)** | Unreachable policy engine, so no new connection. CRLs are tens of MB over kbps links; Mars light-time makes cert rotation take *hours*. The result is fail-open or fail-closed. |
| **Blind to behavior**           | A compromised endpoint with valid credentials passes every check. Authentication says nothing about current conduct.                                                           |
| **Doesn't scale by policy**     | Every asset, flow, and partner multiplies the human policy surface combinatorially.                                                                                            |

<!--
Speaker: These aren't bugs to patch; they follow from the design premise. A peer
adversary will engineer exactly these conditions: jam the link, partition the
net, capture a node. The fix has to change the premise, not tune the config.
-->

---

## The reframe: authentication vs. enforcement

> **Authentication opens the door. AutonomousTrust decides what happens inside the room, continuously.**

- Conventional ZTA/ICAM grants implicit trust after login: one proof, then trusted.
- AT augments that with a continuous behavioral gradient:
  - Authentication proves *who*. AT governs *what*, *for how long*, and revokes in real time.
  - A valid credential earns a peer the right to be *heard*. It is never a substitute for *trust*.
- "Authentication is not trust."

---

## Philosophy: trust is earned, emergent, and local

- Zero-trust default-deny: every peer starts untrusted, and nothing is implied by identity alone.
- Standing accrues from observed behavior in an iterated game, rather than being conferred by fiat.
- Peers confer standing, weighted by *their* standing: a PageRank-like web of opinion instead of a central verdict.
- Assume any peer may be hostile. Least privilege, scoped to the task, bounds the blast radius.
- Uncertainty degrades access gracefully. It never silently grants it.
- A human operator is just a privileged peer, running the same machinery with PIV/CAC and MFA.

---

## The trust gradient in practice

Because trust is a live value in [0.0, 1.0], one node meters access along a gradient (the inverted access model), all in the same app:

1. Refuse traffic from badly-trusted peers, to save bandwidth
2. Accept traffic but refuse compute to weakly-trusted peers, to protect CPU
3. Offer compute but withhold data from moderately-trusted peers, to protect data
4. Share data with well-trusted peers

<!--
Speaker: This is the payoff of "trust is a number, not a boolean." The same peer
can be good enough to talk to but not good enough to compute for. Conventional
allow/deny can't express that.
-->

---

## Architecture at a glance

Decentralized by construction: groups form organically, reputation is maintained by leaderless Byzantine Multi-Paxos, and tasks are negotiated peer to peer. Four cooperating subsystem processes:

<div class="cols">

**Network** → transport, encryption, discovery
**Identity** → who a peer is; admission
**Negotiation** → what work gets done, for whom
**Reputation** → how much each peer is trusted

</div>


| Operation               | Primitive (NaCl / libsodium)            |
| ----------------------- | --------------------------------------- |
| Signing                 | Ed25519 (identity, votes, message auth) |
| Peer-to-peer encryption | X25519 + XSalsa20-Poly1305 (NaCl Box)   |
| Group encryption        | shared symmetric key (NaCl SecretBox)   |

*Private keys never touch the wire; announcements carry public keys only.*

---

## Identity: keys and names

- Two separate key pairs per identity: an Ed25519 signing pair (one-to-many verify) and an X25519 encryption pair (one-to-one Box). Private material stays local, and `publish()` yields a public-only copy.
- Zooko-style naming, which gets decentralized, human-meaningful, and secure all at once:
  - `nickname` is the online global name (e.g. `squad-warrant@dod-demo`), and the only name on the wire.
  - `petname` is the local name each receiver mints for itself. It is never serialized, so no one can inject a name into yours.
- Stable UUID per identity. Duplicate UUID, signing-key, or encryption-key collisions are rejected on sight.
- The canonical wire form is a flat JSON that is byte-identical between the Python and C implementations. That is the interoperability contract.

---

## Identity: a verifiable ledger, permissionless admission

- Identity history is a DAG of Merkle roots. Think *git*: identity blobs are diffs, Merkle roots are commits, and divergent branches merge at their lowest common ancestor. Membership is provable by Merkle inclusion proof, and backdating is rejected by timestamp monotonicity.
- Admission is permissionless but Sybil-resistant (the border-guard pattern):

`announce` (open broadcast) → *choose group* (adopt longest history) → `request_access` → peers `vote_on_peer` (Ed25519-signed) → `peer_accepted` → `full_history` (group key + DAG, encrypted)

- Admission agreement is pluggable: Proof of Work, Proof of Stake, or Proof of Authority.
- Known-UUID peers (amnesia / restart) skip the vote. The group key rotates on membership change.

---

## Reputation I: the transaction ledger

Reputation rests on a hash-linked, bilateral transaction chain. It is not a global blockchain but a bounded, per-node verifiable commit log.

- Every `Transaction` is intrinsically bilateral (two counterparties, two scores), so one peer can't fill both sides.
- Hash-linking (blake2b `prev_hash`) chains committed entries, so a tampered segment is *detectable* and peers sync by verifying rather than trusting.
- A Merkle window root (RFC 6962, domain-separated to defeat CVE-2012-2459) gives O(log n) inclusion audit.
- Signed checkpoints: a quorum co-signs a window root, which acts as a lightweight finality gadget.
- Bounded window (default 200 entries, FIFO eviction with tombstones against "zombie" re-insertion).

---

## Reputation II: how a score is computed

Scores live in [0, 1], with no negatives. Single-source thresholds (env-overridable):


| Value                      | Meaning                                                       |
| -------------------------- | ------------------------------------------------------------- |
| **0.2**                    | cold-start / neutral prior (`PREREP_NEUTRAL`)                 |
| **0.1**                    | communication cut-off; below this, peers stop relaying to you |
| **0.0**                    | slash floor                                                   |
| **0.5 / 0.65 / 0.8 / 0.9** | trust-tier floors (1 → 4)                                    |
| **0.21**                   | idle-decay asymptote                                          |

- Two modes with hysteresis (the band `[0.45, 0.55]` retains the prior mode):
  - Cooperation is *pure reputation*: the trust-weighted average of counterparties' scores × their standing × task weight.
  - Contrite Tit-for-Tat is the principled response to a counterparty defecting against *you*.
- Idle decay is asymmetric: idle peers relax toward 0.21, but decay never rehabilitates a low or slashed peer.

---

<!-- _class: small -->

## Reputation III: consensus and slashing

Agreement on reputation runs as leaderless Byzantine Multi-Paxos, so there is no coordinator to capture or lose.


| Phase | Messages                                   | Purpose                                                                                   |
| ----- | ------------------------------------------ | ----------------------------------------------------------------------------------------- |
| 1     | `request` → `grant` / `nack` / `backdate` | ask permission; proposal id = (timestamp, chain-index, peer) with replay-idempotent guard |
| 2     | `transaction` → `accepted`                | on majority grant, propose the score; commit on majority accept                           |
| 3     | `committed` (broadcast)                    | every peer writes the *same* bilateral entry                                               |

- Catch-up queries the top-3 most-trusted peers and majority-votes the result, which is verifiable via chain links.
- Slashing is the fast path: a quorum-co-signed (Ed25519), evidence-gated `SlashAttestation` floors a score immediately, instead of waiting roughly 20 transactions for the average to move. That is what catches short-lived rogues.
- Exclusion is sticky: a cut-off peer can't transact its way back, and recovery is an explicit, signed `rehabilitate`.

---

<!-- _class: smaller -->

## Two orthogonal axes: rank vs. trust tier

AT deliberately separates *where you sit in the network* from *how much you're trusted*.

<div class="cols">

**Rank** (topology)

- one-hop / gateway reachability
- mostly static, from config
- gates routing, partition-leader, Proof-of-Authority votes

**Trust tier** (reputation-derived)

- floors at 0.5 / 0.65 / 0.8 / 0.9, giving tiers 1 to 4
- moves with behavior, with hysteresis
- gates capability access, transaction weighting, Proof-of-Trust votes
- never serialized, because trust is *others'* opinion of you

</div>

<!--
Speaker: A powerful radio at the center of the mesh has high rank but must still
EARN a high tier. Capability (rank) and trustworthiness (tier) are different
questions, and conflating them is a classic mistake.
-->

---

## Negotiation: getting work done, safely

- Task lifecycle on the encrypted peer-to-peer channel:

`spawn task` → `invitation` (fan-out to peers advertising the capability) → `ack` / `nack` / `haggle` (counter-offer) → `report results` (with zero-knowledge proof)

- Tier-gated invites: a request is refused if the sender's tier is below the capability's `required_tier`. The *local* capability definition is authoritative.
- Tier-loss cancellation: if a peer is demoted mid-task, work it's no longer authorized for is cancelled automatically.
- This is where trust composes: the requester verifies the result's ZKP, then submits a transaction score, which feeds Reputation.

---

## Agreement & bootstrapping trust

- One agreement framework, two voter bases (proofs are Ed25519-signed, tallied by a threshold of the top third):
  - Proof of Authority weights votes by rank (topology and capability).
  - Proof of Trust weights votes by tier (earned reputation). Use it for behavior-dependent decisions like data sharing.
- The cold-start problem: how does a brand-new mesh earn *any* reputation? Through a bootstrap capability corpus, auto-registered on every node:
  - `at.handshake` (signed-nonce challenge), `at.time-attest` (clock agreement ±200 ms), `at.echo-challenge` (signed echo).
  - Paced, deterministic pairwise interactions seed the first honest scores.

---

## Networking: built to survive disconnection

- Three channels, by trust level:
  1. Open broadcast (UDP, unencrypted) carries *announcements only*
  2. Encrypted group (NaCl SecretBox, shared key) carries proposals, votes, and Paxos
  3. Encrypted peer-to-peer (NaCl Box) carries history, negotiation, and reputation
- UDP / TCP hybrid transports (length-prefixed TCP framing). Optional connection pooling leaves the wire bytes unchanged, so C and Python nodes interoperate.
- Partition recovery: split-brain groups on a shared broadcast domain detect each other (signed probe/response), the larger group wins by a symmetric adopt test, and members re-admit and merge. Layer-3 backstops periodically re-sync dropped per-peer state.

<!--
Speaker: DDIL (Denied, Degraded, Intermittent, Limited) is the design center,
not an edge case. Everything degrades to local decisions and reconciles on
reconnect.
-->

---

## Layering Zero Trust: ZTA integration

**AT extends NIST SP 800-207 rather than replacing it.** A peer still needs valid credentials to be heard; behavioral reputation is the operative boundary *after* connection.

- Pluggable verifier interface (`verify` / `check_revocation` / `is_available`), build-gated by `AT_ZTA`:
  - X.509 verifier (OpenSSL / pyca): chain and expiry, optional OCSP/CRL. *Shipped in both implementations.*
  - OIDC verifier: interface present, *stub* today.
- The credential is bound to identity by SHA-256 hash and excluded from identity equality, so routine cert rotation never disturbs reputation.
- DDIL fallback: if the CA/OCSP is unreachable, admit at a capped reputation and reconcile later. Peers with high standing can vouch (delegated verification), lifting the cap on quorum. An append-only audit log reconciles on reconnect.

---

<!-- _class: smallest -->

## Human-in-the-loop and behavioral sensing

<div class="cols">

**Operator attestation**

- `operator_bound` / `operator_attested_at` signal "a human stands behind this node."
- Earned, never advertised: a claim on the wire is neutralized at admission and set true only if a *distinct operator credential* verifies.
- Operator access is PIV/CAC plus MFA (TOTP by default, DDIL-friendly). The key never leaves the card, and the path is fail-safe.

**Behavioral anomaly layer** *(Python prototype)*

- Online, explainable detectors (River HST + PyOD HBOS) are deterministic, so scores are admissible signed evidence.
- "ML proposes, consensus disposes": a per-node governor emits a *slash proposal*, and the signed quorum flow decides.
- Human-on-the-loop by default. Dwell and quorum guards defeat the base-rate fallacy.

</div>

---

<!-- _class: smaller -->

## Two implementations, one contract

<div class="cols">

**Python** (reference & development)

- rapid iteration, simulation, scenario authoring
- executable specification of the semantics

**C** (production & fielded)

- runs the embedded/ARM daemon (`at_demo`), so no Python is needed on-device
- formally verified (Frama-C / ACSL contracts): 100% of attempted proof goals discharged

</div>

- Wire-interoperable, with the backend chosen at import (`AUTONOMOUS_TRUST_BACKEND = auto | native | python`) and overlaid per-module via CFFI.
- "The corpus is the contract." A cross-language conformance suite (~114 cases at v1, 150+ today) runs *both* harnesses over shared scenarios and byte-pins signatures, proofs, and envelopes. An asymmetry diff fails CI if the two ever disagree.

<!--
Speaker: This is the assurance story in one line: the fielded artifact is C, C is
formally verified, and the conformance corpus proves C behaves byte-for-byte like
the readable Python reference. You get provability without giving up iteration.
-->

---

<!-- _class: small -->

## Tooling & ecosystem

Namespace packages layered on the core:


| Package        | Role                                                                                                                                              |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| **inspector**  | Live/playback dashboards (Dash + Plotly): trust timeline, per-peer detail, mesh graph, sensor charts, event log                                   |
| **simulator**  | Multi-node mesh with mobility paths and radio physics: terrain, delay, routing, and even a space link (free-space loss, light-delay, occultation) |
| **evaluation** | Metrics collector, M&S performance harnesses, and a red-team suite (Byzantine, Sybil, MITM, reputation-gaming; MITRE Caldera bridge)              |
| **services**   | Application data carried over AT trust: environmental sensors, fusion, video, position                                                            |
| **behaviour**  | The behavioral-anomaly layer (prototype; formally-verified C twin deferred)                                                                       |

---

## See it run

The multi-agency disaster-response demo runs in-process, with no Docker required:

```
python -m examples.multi_agency      →  dashboard at http://localhost:8050
```

> Ten federal sensors form a trust mesh. **One is compromised.**
> The network **excludes it on its own** (locally, continuously, and with signed evidence) while the rest keep cooperating.

No central authority is consulted. Nothing "fails open." That is the whole idea.

---

<!-- _class: lead -->

# The through-line

**Trust is earned, continuous, and decided locally.**

Authentication opens the door. AutonomousTrust governs the room, and keeps governing it when the network is jammed, degraded, or partitioned.

<!--
Speaker: If the audience remembers one slide, make it this one. Everything else
(the Merkle chains, the Paxos, the tiers, the ZTA layering) exists to make
"earned, continuous, local" hold up against a real adversary in a real DDIL
environment.
-->
