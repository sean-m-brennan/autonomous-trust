---
title: "DAF27TZ01-DV002: Cyber Resiliency for Fog and Edge Computing Devices"
subtitle: "Volume 5: Feasibility Documentation (Phase I-Type Effort)"
author: "TekFive, Inc."
---

<!-- DRAFT, 2026-10-23. Volume 5 per the DAF D2P2 instructions (p. DAF-10); not
counted against the 35-page technical volume. Results still to be produced are
marked [TODO: result]; the work that produces each is listed in NOTES.md. -->

This document includes data that must not be disclosed outside the Government
and must not be duplicated, used, or disclosed in whole or in part for any
purpose other than to evaluate this proposal. [TODO: standard restrictive legend
per the DoW FY27 STTR BAA.]

# Feasibility of AutonomousTrust for Fog and Edge Cyber Resiliency

## 1. Basis and performance of the feasibility work

The topic asks for an approach, an architecture and a prior demonstration of a
limited-scope prototype that prevents or mitigates a single class of
cyber-attack on an edge-node or embedded device, with the ability to scale to a
large number of edge nodes and to detect and respond to an attack autonomously.
This document provides each, from TekFive's AutonomousTrust (AT) prototype.

AT was conceived by the PI in 2023 (Brennan, "AutonomousTrust: High-trust
systems for secure cooperation," TekFive whitepaper, May 3, 2023) and has been
designed, implemented and tested since then by TekFive with TekFive internal
funds. The PI is the author of AT and performed the substantial majority of the
feasibility work described here. None of it is based on, or logically extends
from, prior or ongoing federally funded SBIR or STTR work. TekFive has one
pending SBIR proposal on related technology, disclosed in Volume 2 §I; it has
not been funded, and nothing in this document depends on it. [TODO: IP rights
assertions for AT, per the BAA, with a short summary of each restricted item.]

## 2. Approach

Our premise is that security context at the edge is local, situational and
always changing, so detection and response should be local too. An edge node on
a small UAS or a small satellite cannot pull a revocation list over a
constrained link, cannot wait on a cloud analytics service to tell it that a
neighbor has gone bad, and in many cases will never be physically reached again.
What it does have is neighbors, and the neighbors are in the best position to
notice that one of them has stopped behaving as it should. They are also the
only party guaranteed to be present when it happens.

AT therefore puts the trust decision on the device and makes it a collective
one. Each node evaluates its peers continuously, the cohort agrees changes in
standing by consensus, and enforcement follows directly from standing: a node
whose reputation falls loses access to the capabilities its tier allowed, and a
node whose misbehavior is established by signed evidence is excluded. No step on
that path waits on a central authority or a human, which is what makes the
response fast enough for an asset that cannot be reached and cheap enough to
repeat across thousands of nodes. Humans stay on the loop for consequential
recovery decisions, as the topic's Q&A asks.

We chose an approach that needs no special hardware and no special compiler. AT
is portable C11 built with standard toolchains, cryptography comes from
libsodium, and the agent runs as an ordinary process beside the mission
software. Where a device offers a hardware root of trust, AT uses it as one more
source of evidence; where it does not, the remaining bases of trust still hold.
That choice addresses the topic's C-SWaP constraint directly, since the defense
does not ask the platform for an FPGA, a custom processor or an add-on security
module.

## 3. Architecture

![Figure 1. Operational concept (OV-1). AT cohorts of smallsats, sUAS and
ground IoBT sensors each decide on their own. The sUAS cohort detects a
credentialed but compromised node, demotes it and gates it out of the
data-sharing tier with no reach-back on the decision path (§4). The smallsat
cohort refuses an unsigned update (§5). Fog-tier gateways roll reputation up the
hierarchy (§3.4), a late joiner and a sub-threshold admission sit at a capped
tier (§3.5), and the operator stays on the
loop.](./autonomoustrust_ov1_dv002.png){width=100%}

### 3.1 The node

Each device runs a resident AT agent between the mission application and the
network, acting as that node's policy decision and enforcement point. A device
that cannot host the agent is fronted by a bump-in-the-wire gateway on its data
path. The agent is a set of cooperating subsystems (identity, network,
reputation, negotiation and task processing) plus optional extensions, of which
the ones that matter here are the physical-consistency oracle, the fleet-update
service, the Zero Trust verifier, the Bundle Protocol transport and the gateway.

### 3.2 Five bases of trust

Trust in AT rests on five bases, applied in a deliberate order. The first four
need no history, so they carry first contact. (1) Cryptographic identity and
provenance: Ed25519 signing and X25519 encryption keys bound to a UUID and
recorded in a Merkle-DAG identity ledger; private keys never leave the node. (2)
Device integrity: evidence about the software the device is running, from signed
artifacts and, where available, hardware attestation. (3) Least-privilege
containment: five capability tiers that gate everything from basic networking up
to data sharing. (4) Delegated trust: a member vouches for a newcomer, which is
admitted only at a capped level. The fifth, behavioral reputation, refines trust
over the life of the fleet. We lead with the history-independent bases because
constraint beats detection, and a fleet that must be right on first contact
cannot wait for a behavioral model to warm up.

### 3.3 Agreement and enforcement

Reputation changes are agreed by leaderless Multi-Paxos among cohort members and
recorded in a hash-linked, RFC 6962 Merkle-checkpointed ledger, with every
reputation half signed by the party that produced it. When a node's reputation
falls below the bar for its tier, it is demoted, and demotion cancels work it
already had in flight. When the evidence is strong enough, a quorum-signed,
Merkle-proof-gated slash excludes it. Exclusion is sticky and is lifted only by
a signed rehabilitation. Every decision is deterministic and traceable to the
evidence that caused it.

### 3.4 The hierarchy and the fog tier

Nodes form cohorts, and cohorts form a hierarchy through gateway nodes that
aggregate the reputation of the members beneath them and relay it upward. A
node's standing can be resolved through several gateway levels by a deep
reputation query, and the root of the hierarchy is discovered rather than
configured. The gateways are the fog tier of the architecture. Because each
decision involves only a node's cohort and a bounded path up the hierarchy, the
cost of a decision grows with cohort size rather than with fleet size, which is
the property that lets the approach scale to hundreds and thousands of edge
nodes.

### 3.5 Disconnected operation

Under jamming, partition or light-lag, a cohort keeps deciding with whatever
quorum it can reach. A sub-threshold quorum admits newcomers only at a capped
reputation ceiling and a reduced tier, gated by the history-independent bases,
and signs every such admission so it can be reconciled when connectivity
returns. Partition detection and recovery are autonomous. Traffic can be carried
over the Bundle Protocol (ION and µD3TN backends) for delay-tolerant links.

## 4. Demonstration: the compromised-but-credentialed edge node

We demonstrated AT against the attack class that conventional Zero Trust handles
worst: an edge node whose identity and credentials are valid but whose behavior
is no longer under its owner's control. It does not matter to the defense
whether control was lost through a remote exploit, through capture of a downed
device, or through an implant delivered in the supply chain, because the defense
acts on what the node does rather than on how it was compromised. That is why we
chose this class to demonstrate first.

**Scenario.** TekFive's ISR scenario places unmanned sensor platforms in an AT
cohort, each running an ML object detector (YOLOv8-OBB) and reporting target
tracks to a fusion node as a trust-scored capability. One platform is
compromised partway through the run and begins reporting a target position that
disagrees with its peers' observations of the same target.

**Detection.** AT's physical-consistency oracle cross-checks corroborable
observations against each other and against physical bounds. In the recorded run
it flagged the compromised platform's report at a 97.5 m deviation against a 50
m bound. The oracle is implemented identically in both runtimes and pinned by
206 conformance cases with zero asymmetric results.

**Response.** The flag becomes signed evidence, the evidence lowers the
platform's reputation, and the cohort demotes it out of the data-sharing tier.
The fusion node stops receiving the false track and the mission continues on the
remaining platforms. No operator action and no contact with any central service
was required. [TODO: result: time from first false report to exclusion, and
fusion-track error with and without AT.]

**On representative edge hardware.** The C agent runs on an ARM Cortex-A72
(Raspberry Pi 4 class) from a minimal Buildroot/musl image of about fifteen
packages, with no interactive shell and no package manager, and interoperates on
the wire with the Python reference cohort through discovery, admission and
group-key exchange. [TODO: result: on-hardware detection-to-exclusion latency,
CPU and resident memory under load.] The library's static footprint on x86_64 is
456 KiB of text and 318 KiB of BSS; we moved a 4 MiB message buffer to the heap
specifically to bring smaller targets into reach. [TODO: aarch64 figures from
the current build.]

**The anomaly layer.** Physical consistency covers data that other sensors can
corroborate. For behavior that cannot be corroborated, AT carries a lightweight,
unsupervised, streaming anomaly layer (Half-Space Trees and HBOS, per peer and
per role, with per-feature attribution) whose output is a governed input to
reputation and never a direct trigger. On a synthetic compromise corpus covering
gradual drift, abrupt deviation and intermittent misbehavior, it detected every
injected compromise with no false exclusions, where a static-policy baseline had
a false-positive rate of 0.21. At a 1% attack base rate its precision was 1.00
against the baseline's 0.03, and it detected sooner (16.6 against 29.4 [TODO:
units]). The anomaly layer's recommendations are presented to an operator rather
than acted on automatically. [TODO: result: recommendation reaching an operator
in a live cohort.]

## 5. Second class: tampered and unauthorized software

The topic's Q&A confirms that preventing execution of unauthenticated or
tampered firmware, updates or commands counts as a single class, and the
prototype prevents it as well. AT's fleet-update extension accepts an update
only if the proposal is Ed25519-signed, the proposer holds sufficient
reputation, and the cohort approves it by Paxos vote. The artifact is
BLAKE2b-256 hashed and transferred in 960-byte chunks, and after installation a
health check triggers automatic rollback if the new build misbehaves. Release
binaries are signed at build time and verified before they load, and the root
filesystem is protected by dm-verity. Configuration can be pushed through the
same path, but never a node's identity, which the update service refuses
outright.

[TODO: result: on-hardware demonstration that (a) a tampered image is refused at
boot, (b) an unsigned update is refused by the cohort, and (c) a signed but
faulty update is rolled back autonomously, with timings for each.]

## 6. Other attack classes already handled

These are not the subject of the demonstration but bear on the Phase II claim
that the approach extends across classes.

- **Replay.** Every protocol verb carries a per-sender sequence number, and each
  receiver keeps a persisted high-water mark per sender and verb, in both
  runtimes.
- **Man-in-the-middle.** All traffic is authenticated and encrypted
  (X25519 + XSalsa20-Poly1305, Ed25519 signatures).
- **Sybil.** New identities must win an admission vote whose electorate is the
  existing members, first-contact peers count in no quorum, and a returning
  UUID must present the keys on record. Sybils are bounded at admission rather
  than hunted in the transaction graph.
- **On-off and reputation gaming.** Exclusion is sticky; new identities start at
  zero trust, so discarding a damaged identity buys nothing.
- **Partition.** Autonomous detection and recovery, with capped admission and
  signed reconciliation as in §3.5.
- **Revoked credentials.** An X.509 verifier checks OCSP and CRL, defers
  verification under DDIL, and accepts delegated verification by quorum.

[TODO: result: saved output from the Sybil, MITM, replay and compromise red-team
harnesses.]

## 7. Scaling

The cohort-and-hierarchy structure in §3.4 is what scales; a flat cohort is not
meant to. Cohorts of 16 and 25 peers form, admit and detect anomalies cleanly in
emulation. [TODO: result: 100-node run with admission time, detection latency
and per-node message overhead against node count.] [TODO: result: hierarchical
run at [N] nodes across [k] gateway levels.] Phase II carries this to the
1,000-node range on a cluster.

## 8. Assurance of the defense itself

A defense that runs on every device is part of every device's attack surface, so
we hold it to a higher standard than the software it protects. The C core is
under Frama-C/WP formal verification with ACSL contracts, at 100% proof on the
goals attempted (4,262 of 4,262 as of April 2026) and 53.6% function coverage.
[TODO: refreshed figures, including extensions.] A byte-for-byte conformance
corpus of 677 cases pins the C core to the Python reference with zero asymmetric
results, so behavior demonstrated in the reference is the behavior the device
runs. Untrusted input is parsed defensively (msgpack rather than pickle,
allowlisted configuration classes, NULL-guarded parsing), secrets are zeroed in
memory after use, and the agent runs under systemd confinement.

## 9. Conclusion of the feasibility effort

The prototype prevents one attack class (tampered and unauthorized software) and
detects and contains a second (the compromised-but-credentialed node) on an edge
device, autonomously and without central infrastructure. Its architecture scales
by hierarchy, and its core is small, portable and formally verified. Phase II
broadens the classes, takes the defense down into the device's boot chain and
process model, and demonstrates fight-through under independent attack.

## References

[TODO: compile. At minimum the AT whitepaper, NIST SP 800-207 and SP 800-160
Vol. 2, RFC 6962, and Axelsson, "The base-rate fallacy and the difficulty of
intrusion detection," ACM TISSEC 3(3), 2000.]