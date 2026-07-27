---
marp: true
theme: tekfive
paginate: true
header: 'AutonomousTrust'
---
<!-- _class: lead -->
<!-- _header: ' ' -->

# AutonomousTrust

## Behavior-aware Zero Trust for comms-denied combat systems

A technical companion: the ideas behind the proposal.

<!--
Speaker: This is a companion to the written volume. The goal isn't to re-read the
proposal; it's to walk the technical reasoning from the problem, through the trust
model, to each mechanism, and finally to how we'll prove it. Roughly six threads:
(1) why conventional ZTA breaks at the edge, (2) the reframe from authentication to
enforcement, (3) the five-bases trust model, (4) the mechanisms that implement it,
(5) how they survive disconnection, (6) how we validate.
-->

---

## The problem is structural, not incremental

Zero Trust (NIST SP 800-207) as normally built is policy-driven, and therefore human-driven. It also assumes a reachable central authority (CA / OCSP / CRL) on the connection hot path.

That assumption fails in exactly three ways at the tactical edge:

| Failure mode                    | Why it happens                                                                                                                          |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| **Dies when comms drop (DDIL)** | §5.2: an unreachable policy engine means no new connection. CRLs are tens of MB; SATCOM is 9.6 to 256 kbps. The result is fail-open or fail-closed. |
| **Can't see behavior**          | A compromised endpoint with valid credentials passes every check. This is SP 800-207's blind spot.                                       |
| **Doesn't scale by policy**     | Every asset, flow, and partner multiplies the human policy surface combinatorially.                                                     |

<!--
Speaker: The point to land here is that these aren't bugs you patch; they follow
from ZTA's design premises. A peer adversary will *engineer* the exact conditions
(jamming, partition, capture) that trigger all three. So the fix has to change the
premise, not tune the implementation.
-->

---

## The reframe: authentication vs. enforcement

> **ZTA authentication opens the door. AT decides what happens inside the room, continuously.**

Conventional ZTA (and ICAM) grant implicit trust after login: one proof, then trusted. AT replaces that with a continuous behavioral gradient:

- Every authenticated peer starts at zero trust and earns standing through observed behavior.
- Trust is a live value in [0.0, 1.0], evaluated locally and continuously, rather than a one-time boolean.
- Authentication proves *who*. AT enforcement governs *what*, *for how long*, and *revokes in real time.*

<!--
Speaker: This is the conceptual hinge of the whole system. ICAM/PKI answers "is this
identity valid?" That's necessary but not sufficient. AT answers the question SP
800-207 leaves open: "is this validated identity still behaving like it should, right
now?" Everything downstream is machinery to answer that without a central authority.
-->

---

## Where AT sits: an edge-local PDP

AT is a resident agent co-located with each combat-system or OT endpoint, or a bump-in-the-wire gateway where a device can't host code.

```
   mission app  ──►  [ AT agent / gateway = PDP+PEP ]  ──►  network
                         │  crypto identity
                         │  behavioral trust eval
                         │  tier-gate + slashing
                         └► signed audit
```

- It sits between the mission application and the network as that node's policy-decision and enforcement point.
- Bounded-memory deterministic C core, plus a streaming anomaly layer with fixed per-peer state and no data-lake backhaul.
- It runs low-priority co-resident, or offloads entirely to the gateway so a compute-starved sensor carries little cost.
- Phase I characterizes the footprint (CPU, memory, and added latency on embedded ARM) as a first-class result.

<!--
Speaker: Two things matter. First, the decision is made *at the node*, close to the
edge, echoing the human chain of command. Second, we take the resource cost
seriously: a weapons controller can't spare much, so the design lets you push the
work onto a gateway. We measure and report the footprint rather than hand-waving it.
-->

---

## The trust model: five bases

A real-time system must judge assets before behavioral history exists. So AT layers five bases:

| # | Basis                                                                                  | Needs history?     |
| - | -------------------------------------------------------------------------------------- | ------------------ |
| 1 | **Authentication / provenance** (ICAM)                                                 | No                 |
| 2 | **Hardware attestation**: TPM / secure element, measured boot (captured-asset defense) | No                 |
| 3 | **Least-privilege containment**                                                        | No                 |
| 4 | **Delegated / transferred trust**                                                      | No                 |
| 5 | **Behavioral reputation**                                                              | Yes, iterated game |

Two facts shrink the "one-shot stranger" problem: a fleet is a small, persistent population of repeat players, and constraint beats detection.

> AT leads with the history-free bases 1 through 4. Behavioral ML (base 5) is a gap-filling refinement, not the foundation.

<!--
Speaker: This ordering is deliberate and it's the answer to "isn't ML unreliable
against novel one-shot attacks?" Yes, so we don't hang the system on it. Identity,
attestation, and containment do the heavy lifting and need no history. Behavior
refines the picture over the identity-lifetime of a repeat player. Constraint beats
detection: it's better to bound what a suspect node *can* do than to bet on catching
it in the act.
-->

---

## Identity and the ledgers

Machine and NPE identity is cryptographic and self-sovereign:

- Ed25519 (sign) + X25519 (key-agreement) + UUID. Private keys never traverse the wire.
- All traffic encrypted with NaCl/libsodium: X25519 + XSalsa20-Poly1305, Ed25519 signatures.

A purpose-built permissioned DLT, using three tuned structures rather than one global chain:

- Merkle-DAG identity ledger: who is who.
- Reputation ledger: hash-linked, RFC 6962 Merkle-checkpointed, and slashing-capable.
- Audit log: append-only JSONL, intact offline, reconciled on reconnect.

> We decline a global chain, Proof-of-Work, and unbounded history as the wrong CAP and resource trade for a small-memory, intermittently-connected mesh.

<!--
Speaker: "Blockchain" is in the topic, so we give them the properties they actually
want (immutability, tamper-evidence, distributed agreement) without the properties
that kill you at the edge (a single global chain, PoW burn, ever-growing state). The
Merkle checkpointing is what lets an offline node prove history when it reconnects.
-->

---

## Consensus and evidence-gated slashing

Trust changes are agreed, not asserted:

- Leaderless Byzantine Multi-Paxos consensus, with no single point to jam or subvert.
- A reputation penalty ("slash") is quorum-signed and Merkle-proof-gated: you cannot slash a peer without cryptographic evidence others can re-verify.
- Past threshold, slashing triggers autonomous tier-gate exclusion, dropping the peer from the capability level it no longer earns.

Every decision is deterministic, reproducible, and traceable to signed evidence.

<!--
Speaker: The word to stress is *evidence-gated*. Reputation systems are notoriously
gameable: collusion, bad-mouthing, Sybil. Requiring a Merkle proof plus a signed
quorum means an accusation is checkable and an exclusion is auditable. Determinism
matters for accreditation: same evidence, same decision, every time.
-->

---

## Micro-segmentation on two orthogonal axes

Access requires **both** conditions to hold, in a lattice/dominance model (Bell-LaPadula style):

<div class="cols">

**Axis 1: hierarchical tier** *(criticality)*
`required_tier 0-4`
network → comms → services → data-sharing
Peer tier **≥** object tier.
*Set at planning time from mission-impact / dependency mapping (with NAVSEA TPOC).*

**Axis 2: compartment set** *(confidentiality)*
need-to-know containment
Peer set **⊇** object set.
*Derived from the classification guide / community-of-interest marking.*

</div>

Each datum and grant carries an access class of (required_tier, compartment-set). The axes are orthogonal and separately sourced. A datum can be mission-critical yet uncompartmented, or low-impact yet tightly compartmented.

> Tier-gating is implemented today. The compartment axis layers on without modifying it (Phase I design).

<!--
Speaker: The subtlety is that "how important" and "who's allowed to see it" are
different questions with different owners. The tier floor comes from the mission
planner; the compartment tags come from the classification authority. AT just
enforces the conjunction at runtime; it doesn't try to author policy.
-->

---

## The ML anomaly layer: a governed sensor

The topic asks for AI/ML on access patterns. AT's answer: deterministic enforcement is primary, and ML is a subordinate, governed sensor that feeds evidence to the trust algorithm.

- Each node models the behavioral envelope of every peer and role, producing a per-peer anomaly score with per-feature attribution.
- A sustained anomaly feeds reputation. Past threshold it fires the quorum-signed, Merkle-gated slashing path above.
- Engine: streaming Half-Space Trees plus a per-feature streaming-histogram detector (HBOS/LODA, native attribution).
- Unsupervised, online, bounded-memory, and deterministic under fixed seeds. Prototyped in Python (River/PyOD), reimplemented in the verified C core.

Enterprise UEBA assumes data-lake backhaul plus a passive sensor. Both fail under DDIL. On-device analytics also mitigate the intrusion-detection base-rate fallacy (Axelsson, 2000): when attacks are rare, a naive detector's false positives swamp the true ones.

<!--
Speaker: Two design commitments here. First, ML never *acts* on its own; it produces
evidence that flows into the same deterministic, auditable slashing machinery as
everything else. That keeps the system explainable and accreditable. Second, the
detector is streaming and bounded; it runs on the node under DDIL, unlike a cloud
UEBA product. The base-rate point is why we report false-exclusion rate against a
realistic attack base rate, not just raw accuracy.
-->

---

## Surviving disconnection: the hierarchical network

The key result: AT does not fail open or closed when the central authority is unreachable.

- ICAM is kept for human-identity proof but paid once, at console activation, bound to the local AT identity and off the per-access hot path.
- Nested PDPs form a hierarchical, emergent-gateway network. A connected gateway validates via OCSP stapling or cached short-lived revocation (pre-staged while connected), then vouches through quorum-gated, reputation-weighted delegated verification.
- If an adversary shrinks the reachable quorum by jamming or partition, a sub-threshold quorum admits only at a capped reputation ceiling and reduced tier-gate: base-3 containment, gated by the history-free bases 1 and 2.
- Every admission is signed, so the audit reconciles on reconnect.

> The disconnected operator is verified through the cohort, instead of being forced to choose between insecure and mission-kill.

<!--
Speaker: This is where AT does its main work. The failure modes from slide 2 all
collapse here. Note the graceful degradation: full quorum → normal operation;
shrunken quorum → still admit, but capped and contained, leaning on identity and
hardware attestation which need no history; total isolation → signed local decisions
that reconcile later. There is never a moment where the system waits on a reachable CA.
-->

---

## Assurance: formal verification + a byte-for-byte reference

- Production C core, embedded ARM build, under Frama-C/WP + ACSL formal verification.
- 100% proof on attempted goals (4,262 / 4,262) at roughly 54% function coverage, with documented skips, scoped to memory-safety and ACSL conformance.
- A Python implementation is the executable spec, pinned byte-for-byte to the C core by a cross-language conformance corpus.

> Formal verification is machine-checked assurance toward ATO, the accreditation asset that carries into Phase II / III.

<!--
Speaker: The dual-implementation trick is worth explaining: Python is the readable
reference and rapid-prototyping runtime; C is the deployable, formally verified core;
the conformance corpus guarantees they agree bit-for-bit. So we prototype the ML
layer in Python fast, and re-implement into a core we can actually prove. FV coverage
is honest: ~54% of functions, 100% of what we attempted, and expanding it is a
named Phase II task.
-->

---

<!-- _class: small -->

## Putting it together: the MTC-A/X thread

A Maritime Targeting Cell engagement: ISR sensors → track-fusion/targeting node → fires/effects console, spread across ships and disadvantaged nodes on tactical SATCOM.

| Situation                         | What AT does                                                                                                                                                                                                                     |
| --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Steady state**                  | A sensor's tracks reach the targeting node only while both hold reputation above the required tier.                                                                                                                               |
| **Captured / spoofed sensor**     | Authenticated and cert-valid, but it injects an off-track return, drifts outside its learned envelope, loses reputation, and is autonomously slashed and tier-gated out of the fires path, locally and in real time, with signed evidence. Human-on-the-loop keeps override for safety-critical fires. |
| **SATCOM to PDP / DoD PKI drops** | The cohort keeps operating: the targeting node is vouched by quorum at a capped tier, each admission is signed, and the audit reconciles on reconnect.                                                                            |

> No step in this loop waits on a reachable central authority.

<!--
Speaker: This slide shows every mechanism firing in one thread. The captured-sensor
row is the compromised-but-credentialed case that conventional ZTA can't touch. The
last row is DDIL survival. And note the human stays on the loop exactly where it
matters, on safety-critical fires, while routine trust decisions run autonomously.
-->

---

<!-- _class: small -->

## How we prove it: validation methodology

Feasibility is established the right way for each claim, with M&S where simulation is faithful and silicon where it isn't:

- M&S for latency comparison, attack outcomes, and admin overhead, against an externally-anchored ZTA-only baseline and a pre-registered, MITRE ATT&CK-mapped attack corpus, delivered as reproducible Government artifacts.
- The existing subscale C prototype on embedded ARM for real-time authentication latency, because M&S can't substitute for silicon timing.
- Resilience demonstrated under Sybil, Byzantine, compromised-credential, partition, and DDIL conditions with no reachable infrastructure, reporting false-exclusion rate against a realistic base rate.

| Target              | Goal       | How substantiated          |
| ------------------- | ---------- | -------------------------- |
| Authentication time | **≤ 5 s** | measured on subscale build |
| Latency             | **−50%**  | modeled vs. ZTA baseline   |
| Unauthorized access | **−90%**  | attack-corpus outcomes     |
| Admin overhead      | **−25%**  | modeled / analytic         |

<!--
Speaker: The methodological discipline is the message: pre-registered baseline and
attack corpus so we can't move the goalposts, reproducible artifacts so the
Government can re-run them, and honest tagging of measured vs. modeled. Steady-state
auth is the "average authentication time" the topic asks about; one-time behavioral
enrollment is off the hot path and reported separately so we don't conflate the two.
-->

---

<!-- _class: lead -->

# The through-line

**Authentication opens the door; AutonomousTrust governs the room, continuously and locally, with no central authority to jam.**

History-free bases carry the first contact. Behavior refines over the fleet's lifetime. Every decision is signed, deterministic, and reconciles on reconnect.

<!--
Speaker: If the audience remembers one sentence, it's the top line. Everything else
(the ledgers, consensus, the ML sensor, compartmented access, the DDIL fallback) is
in service of governing the room continuously without depending on a link the
adversary gets a vote over.
-->
