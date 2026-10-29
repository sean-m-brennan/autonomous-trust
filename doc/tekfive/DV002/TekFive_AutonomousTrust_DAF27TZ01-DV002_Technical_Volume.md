---
title: "DAF27TZ01-DV002: Cyber Resiliency for Fog and Edge Computing Devices"
subtitle: "Volume 2: Technical Volume (STTR Direct to Phase II)"
author: "TekFive, Inc., with the McCrary Institute for Cyber and Critical Infrastructure Security, Auburn University"
---

<!-- DRAFT, 2026-10-23. Section order follows DAF_STTR_27TZ_D2P2_R1.pdf (pp.
DAF-4 to DAF-8): TOC, glossary, milestones, identification and significance,
objectives, work plan (new page, no proprietary data), deliverables, then items
C-I. Limit: 35 pages, 11 pt minimum, one-inch margins, graphics legible in black
and white. Feasibility documentation is in Volume 5
(TekFive_AutonomousTrust_DAF27TZ01-DV002_Feasibility.md) and does not count
against the limit. Open items are marked [TODO]. -->

[TODO: standard restrictive legend per the DoW FY27 STTR BAA, and marking of
proprietary pages. The Work Plan must carry none.]

# AutonomousTrust: Fight-Through Resilience for Fog and Edge Devices

## 1) Table of Contents

[TODO: generate at layout.]

## 2) Glossary

| Term | Meaning |
|---|---|
| ABMS | Advanced Battle Management System |
| ACSL | ANSI/ISO C Specification Language |
| AFRL/RI | Air Force Research Laboratory Information Directorate |
| APT | Advanced persistent threat |
| AT | AutonomousTrust |
| ATT&CK | MITRE Adversarial Tactics, Techniques and Common Knowledge |
| BPSec | Bundle Protocol Security (RFC 9172) |
| C-SWaP | Cost, size, weight and power |
| COA | Course of action |
| DDIL | Denied, disrupted, intermittent and limited (communications) |
| DTN | Delay-tolerant networking |
| FEC | Fog and edge computing |
| IoBT | Internet of Battle Things |
| IoST | Internet of Space Things |
| OCSP / CRL | Online Certificate Status Protocol / Certificate Revocation List |
| PI | Principal Investigator |
| SBOM | Software bill of materials |
| SPARTA | Space Attack Research and Tactic Analysis (Aerospace Corporation) |
| sUAS | Small unmanned aircraft system |
| TEE | Trusted execution environment |
| TPOC | Technical point of contact |
| ZTA | Zero Trust Architecture (NIST SP 800-207) |

[TODO: complete at final edit.]

## 3) Milestone Identification

| Milestone | Month | Event and deliverable |
|---|---|---|
| M1 | 1 | Kickoff with the TPOCs; reference platforms and fight-through scenarios confirmed |
| M2 | 3 | Attack-class taxonomy, threat model and test plan; attack set and thresholds pre-registered |
| M3 | 6 | Device-integrity design review; first McCrary campaign against the baseline fabric |
| M4 | 12 | Device integrity and C anomaly layer complete; mid-term review |
| M5 | 15 | AI-integrity and fog-tier resilience complete; COA selection interface |
| M6 | 18 | Platform integration complete; 1,000-node scaling study |
| M7 | 21 | Pre-exercise campaigns complete; readiness review; prototype installed for the Government exercise at AFRL/RI, Rome, NY |
| M8 | 23 | Government-run red-team exercise, AFRL/RI, Rome, NY: supply-chain and remote-exploit fight-through [TODO: date per Government] |
| M9 | 24 | Final report, assurance evidence package, transition plan |

Status reports are delivered quarterly throughout.

## 4) Identification and Significance of the Problem or Opportunity

The fog and edge devices the Air Force and Space Force are fielding (small UAS,
small satellites, battlefield sensors and the gateways that aggregate them) are
where processing is moving and where the defender has the least help. An edge
node is small, long-lived and frequently out of touch with anything resembling a
security operations center. It cannot pull a fifty-megabyte revocation list over
a constrained link, it cannot wait on a cloud analytics service to tell it a
neighbor has gone bad, and if it is a satellite or a downed aircraft it will not
be physically reached again. The topic names the threats plainly: implants
delivered through the supply chain, remote exploitation over wireless channels,
physical access to captured or downed devices, and attacks on the AI algorithms
the devices run.

Current defenses answer badly at this scale. Perimeter and network-based
defenses do nothing for a node that was compromised before it was fielded.
Conventional Zero Trust depends on a reachable policy engine and certificate
authority; SP 800-207 §5.2 says that no new connection can be approved when they
are unreachable, and every such design then collapses to fail-open or
fail-closed. Hardware-centric defenses (obfuscation, redundancy, FPGAs, custom
processors) cost more than many of these platforms can carry, and approaches
built on special-purpose compilers do not get adopted. Most important, nearly
all of them treat a device holding valid credentials as trustworthy until a
human says otherwise, and the topic is right that remote assets cannot wait for
a human.

The opportunity is to make the devices defend each other. AutonomousTrust (AT)
puts the trust decision on the device and makes it collective: each node
evaluates its peers continuously, the cohort agrees changes in standing by
consensus, and a node's access follows its standing automatically. Nothing on
that path waits on a central authority, so it works under jamming and light-lag,
and because each decision involves only a node's cohort and a short path up a
hierarchy of gateways, it scales by adding cohorts. AT is portable C11 on
standard toolchains, needs no special hardware, and is itself under formal
verification. Volume 5 documents the feasibility prototype, which prevents
tampered and unauthorized software and autonomously detects and contains a
compromised-but-credentialed edge node.

This Phase II effort takes that prototype to the device level and to the attack
classes the topic names, and ends with the fight-through demonstration the topic
calls essential: a fleet that completes its mission while a supply-chain or
remote-exploit compromise is present in it.

## 5) Phase II Technical Objectives

The Phase II work is organized around seven objectives. For each we give the
approach, the method, and the commercial application, since the instructions ask
for the last and because we expect each to stand on its own commercially.

### O1. Attack-class taxonomy, threat model and test plan

**Approach.** The McCrary Institute builds the attack-class taxonomy for air and
space FEC devices from MITRE ATT&CK for ICS and Enterprise, the Aerospace
Corporation's SPARTA matrix, the FEC and IoBT literature and its own operational
experience, and maps each class to the AT mechanism expected to handle it and to
the SP 800-160 Vol. 2 cyber-resiliency techniques. The starting inventory is in
Table 1.

**Method.** The taxonomy, the reference platforms, the fight-through scenario,
the metrics and their thresholds are agreed with the TPOCs and pre-registered
before any measurement, so that results cannot be tuned to the test. McCrary
leads; TekFive contributes the mechanism mapping.

**Commercial application.** A tested mapping from edge attack classes to
defensive mechanisms is directly reusable for industrial-control and
commercial-constellation customers, both of whom have to show regulators and
insurers which threats a control addresses.

*Table 1. Starting inventory of attack classes.*

| Attack class | Example on an FEC device | AT mechanism in the prototype | Phase II work |
|---|---|---|---|
| Supply chain: tampered image or update | Implanted firmware; an update signed with a stolen key | Signed, reputation-gated, cohort-approved updates with hashed chunked transfer and automatic rollback; signed binaries verified at load; dm-verity root filesystem | Measured boot; attestation from the platform's own root of trust; reproducible builds and SBOM; behavioral check after update (O2) |
| Remote exploit leading to APT | Memory-corruption exploit in a radio-facing service, followed by persistence and lateral movement | Tier gating bounds what an exploited node can reach; defensive parsing; systemd confinement | Subsystem process isolation (seccomp, Landlock); attestation refresh; behavioral detection of post-exploit activity; capability migration (O2, O3) |
| Physical capture of a downed device | Key extraction or reflashing of a recovered sUAS | Identity bound to keys on record; sticky exclusion; secrets zeroed in memory | Rekey on exclusion; keys held in the platform's secure storage where present; cohort-wide revocation of a captured identity (O2) |
| AI algorithm exploitation | Adversarial input to an onboard detector; model tampering | Cross-source physical-consistency fusion catches outputs inconsistent with peers and physics (demonstrated) | Model-artifact integrity under O2; single-source plausibility models; robustness of AT's own anomaly layer to evasion and poisoning (O4) |
| Compromised-but-credentialed node | Any of the above, seen from outside: valid keys, wrong behavior | Physical-consistency oracle; reputation; tier demotion; quorum-signed slash (demonstrated) | Anomaly layer in the verified C core; independent test (O3, O7) |
| Sybil | Fabricated identities to swing votes | Member-only admission electorate; first-contact peers count in no quorum; returning identities must present keys on record | Independent campaigns at scale (O7) |
| Byzantine and equivocation | Node tells different peers different things | Signed bilateral evidence; fork detection; operator-declared Byzantine quorum bounds | Byzantine-safe quorum placement; long-partition island operation (O3) |
| Compromised fog gateway | Gateway misreports or isolates its children (eclipse) | Hierarchical reputation with deep queries that bypass a single gateway | Redundant gateway paths; cross-checking of gateway reports (O3) |
| Replay | Re-sent commands or votes | Per-sender, per-verb sequence numbers with persisted high-water marks | Independent test (O7) |
| Man-in-the-middle | Interposed relay on a crosslink | Authenticated encryption and signatures on all traffic | BPSec on the Bundle Protocol path (O5) |
| Reputation gaming | On-off behavior, collusion, whitewashing | Sticky exclusion; new identities start at zero trust | Collusion analysis; adversarial evaluation (O4, O7) |
| Denial of service | Flooding a constrained link or a node's queues | Flood counters; bounded queues; rate-limited probes | Streamed decryption with mid-message cutoff; per-peer budgets (O3) |
| Partition and jamming | Contested crosslink or ground link | Autonomous partition detection and recovery; capped admission under sub-threshold quorum; signed reconciliation | Light-lag and contact-window operation (O5) |

Two rows deserve a note. AT bounds Sybils at admission rather than detecting
them by behavior, which is a design choice: an identity that cannot vote cannot
swing a vote. And a large, patient colluding set can still move reputation
scores, as in any reputation system; what AT guarantees is that the adversary
pays for it with signed, auditable evidence and remains constrained by the
history-independent bases while doing so.

### O2. Device-level integrity

**Approach.** The prototype treats a node as a network participant. Phase II
treats it as a device with a boot chain, a software supply chain, a process
model and stored secrets, and makes each a source of evidence. Measured boot
records what the device actually started. Signed artifacts are verified at boot,
at load and at install, so an implant has to defeat three independent checks.
Builds become reproducible and carry an SBOM, so that the fleet can compare what
a device reports against what was built. AT's own subsystems run as separate,
confined processes, so that a remote exploit in one cannot reach the node's keys
or its reputation state.

The topic warns against defenses that depend on expensive add-on trusted
hardware, and we agree. Attestation in Phase II uses the root of trust the
platform already has: a boot ROM with secure boot, a TEE such as Arm TrustZone
with a firmware TPM, or a discrete TPM or secure element where one is already
fitted. Its absence lowers the ceiling on what a device can be trusted with; it
does not stop the device from participating. That graded design is the
difference between a defense that can be deployed across a fleet of mixed small
platforms and one that cannot.

**Method.** Implement on the reference platforms chosen at M1; pin each
mechanism into the conformance corpus so both runtimes agree; bring new C code
under the same Frama-C regime as the core.

**Commercial application.** Fleet-scale attestation without mandated hardware is
the main obstacle for commercial IoT and drone operators, whose devices vary
widely and cannot be refitted.

### O3. Fog-tier analytics and resilience of the hierarchy

**Approach.** The anomaly layer moves from a Python prototype to the formally
verified C core, pinned to the prototype by the conformance corpus, so that an
edge device can run it. Heavier analytics move to the fog gateways, which can
afford them and which see many devices at once. Because a gateway that lies
about its children is the most valuable foothold in the fabric, the hierarchy
gains redundant gateway paths and cross-checking of gateway reports, and cohorts
gain an island mode for long disconnection, using Byzantine-safe quorum
placement rather than the crash-fault majority the prototype uses by default.
Streamed decryption with mid-message cutoff lets a node stop paying for a
message as soon as it can tell the message is hostile.

**Method.** Implementation and conformance testing at TekFive; adversarial
evaluation of each change by McCrary as it lands rather than only at the end.

**Commercial application.** A verified, small-footprint behavioral detector for
embedded Linux is a product in its own right for OT and medical-device vendors.

### O4. Response, course-of-action selection and AI integrity

**Approach.** The prototype contains a compromised node autonomously. The
topic's Q&A asks for more: autonomous detection, with autonomous responses
presented to a human for course-of-action selection. Phase II therefore adds the
step after containment. The fabric proposes ranked courses of action (isolate
and continue, roll back, re-image, migrate the affected capability to a healthy
peer, revoke the identity, or accept degraded operation), each with its evidence
and its expected mission impact, and an accountable operator chooses.
Containment stays autonomous and immediate, because it is reversible and
time-critical, and recovery waits on a human where the consequences warrant it.
For space assets, where a ground decision may be minutes away, the playbook
specifies which responses the cohort may take on its own while it waits.

AI algorithm exploitation gets its own work here, on two fronts. Onboard models
are artifacts like any other and come under O2's integrity checks. Their outputs
come under AT's consistency checks, which already caught a compromised detector
in the feasibility demonstration and which Phase II extends from corroborable
data to single-source plausibility. AT's own anomaly layer is a model too, and
McCrary attacks it directly with evasion and poisoning.

**Method.** TekFive builds the playbook and operator interface; McCrary leads
the adversarial-ML evaluation; every decision lands in the audit ledger.

**Commercial application.** Human-on-the-loop response with signed evidence is
what regulated operators (utilities, hospitals) need before they let any system
act automatically.

### O5. Air and space platform integration

**Approach.** AT already carries traffic over the Bundle Protocol and its
simulator models light-lag, occultation and laser and RF links. Phase II adds
BPSec to the bundle path, exercises the fabric against contact-window and
light-lag scenarios, and builds one adapter for devices that cannot host the
agent. We propose two reference platforms: an sUAS-class companion computer (ARM
Cortex-A72, the feasibility platform) and a small-satellite onboard computer of
the radiation-tolerant ARMv8 class, represented by a Zynq UltraScale+ MPSoC
(quad Cortex-A53) of the kind commercial smallsat computers are built on. The
two share an instruction set, so the Buildroot image and the footprint
measurements carry from one to the other, and the MPSoC's secure boot and
on-chip device key give the integrity work of O2 a root of trust the platform
already has. Both boards are flight-representative rather than
flight-qualified, which keeps the hardware bill small. The adapter follows from
that choice ([TODO: MAVLink or CAN for the sUAS; SpaceWire for the
spacecraft]).

Not every spacecraft is ARM. To show the C core is not tied to one
architecture, we run it and the conformance corpus on big-endian SPARC under
QEMU's LEON3 model, the processor family behind radiation-hardened parts such
as the GR740. A byte-for-byte corpus is a direct test of wire-format
portability, and emulation costs nothing in hardware. The platforms AT will
eventually have to cover are radiation-hardened LEON, the RISC-V High
Performance Spaceflight Computing processor (Microchip PIC64-HPSC), and the
microcontroller-class computers most CubeSats fly. Phase II reaches the first
by emulation and the last by a feasibility study, since microcontroller-class
devices are the smallest members of an IoBT and currently out of the agent's
reach; HPSC is a Phase III target. We characterize the agent on the
flight-class reference hardware.

**Method.** Integration on the reference hardware, confirmed with the TPOCs at
M1; the LEON3 conformance run under emulation; footprint and latency reported
as first-class results.

**Commercial application.** Commercial constellations and drone fleets operate
under the same link constraints, and the bus adapters open the agent to devices
that cannot be modified.

### O6. Scale

**Approach.** The topic asks for hundreds to thousands of edge nodes. AT scales
by hierarchy, and Phase II demonstrates that at the 1,000-node range on a
cluster, reporting per-node CPU, memory and link overhead and decision latency
against node count, flat and hierarchical.

**Method.** Scale harness on TekFive's AWS GovCloud account, with a subset of
nodes on physical edge hardware to anchor the emulation.

**Commercial application.** Scale evidence is the first question every IoT and
industrial customer asks.

### O7. Pre-exercise evaluation and the Government red-team exercise

**Approach.** The deciding test of Phase II is the Government-run red-team
exercise at the AFRL Information Directorate (AFRL/RI) in Rome, NY, and we plan
the evaluation work around it. McCrary runs the pre-registered attack set
against the integrated fabric as a series of campaigns, each followed by fixes,
so that the fabric meets the Government's red team having already been through
several rounds with another one. TekFive then delivers and installs the
prototype for the exercise, supports it on site, and expects to demonstrate both
fight-through scenarios below there. We define fighting through as completing
the mission task at a stated fraction of the unattacked baseline while the
compromise is present, rather than merely detecting it.

In the **supply-chain** scenario a fraction of the fleet receives an update that
passes signature checks, because the adversary holds a signing key. The defense
must catch it by other means. Measured boot and attestation report a software
state that does not match the reproducible build, which lowers base 2 for those
devices; any that slip past begin to behave differently, which lowers base 5.
The cohort demotes them, the fleet-update service votes a rollback, and while
the rollback runs, their capability migrates to healthy peers. The operator is
offered re-imaging, retirement of the stolen key, or continued containment.

In the **remote-exploit** scenario an adversary gains code execution on a
radio-facing service. Process isolation confines the exploit to one subsystem,
so it cannot reach the node's keys or reputation state. What it can do with the
node's network presence is bounded by the node's tier, and as soon as the node's
behavior departs from its envelope, its tier drops and the reachable surface
shrinks with it. Its mission function moves to a peer, and the operator chooses
between quarantine and re-image.

**Metrics.** Attack-class coverage (classes prevented, contained or detected,
out of the O1 set); detection latency and time to containment; false-exclusion
rate at a realistic attack base rate, since a detector whose false alarms swamp
its true ones is worse than none (Axelsson, 2000); mission-task completion under
attack as a fraction of the unattacked baseline; per-node overhead on reference
hardware; and decision latency against fleet size. We report these for McCrary's
campaigns and adopt the Government's criteria for the exercise. [TODO: proposed
thresholds, stated here and confirmed with the TPOCs at M2.]

**Commercial application.** Results from a Government-run red-team exercise,
preceded by a university institute's campaigns, are evidence a customer can rely
on without having to trust the vendor.

<!-- page break: the Work Plan begins on a new page and is incorporated into the
contract by reference. No proprietary information below this line. -->

## 6) Work Plan

### 1.0 Objective

The objective of this effort is to develop and demonstrate a decentralized
cyber-resiliency capability for fog and edge computing devices that prevents,
detects and responds to cyber-attacks autonomously, scales to fleets of hundreds
to thousands of devices, and enables those devices to continue their mission
through a supply-chain or remote-exploit compromise. The expected outcome is a
prototype integrated on representative air and space edge platforms, an
independently evaluated record of the attack classes it addresses, and a
transition plan.

### 2.0 Scope

The effort covers attack-class analysis and test planning; device-level
integrity (boot, load and install verification, attestation using
platform-native roots of trust, reproducible builds, process isolation);
behavioral analytics at the edge and fog tiers; response and operator
course-of-action selection; integration with air and space links and platform
buses; scaling; and evaluation by the research institution in preparation for a
Government-run red-team exercise, at which supply-chain and remote-exploit
fight-through are demonstrated. Major milestones are listed in Section 3.
Deliverables are the prototype software, the evaluation results and data, the
reports in Section 7, and the transition plan.

### 3.0 Background

Applicable documents include NIST SP 800-207 (Zero Trust Architecture); NIST SP
800-160 Vol. 2 Rev. 1 (Developing Cyber-Resilient Systems); NIST SP 800-193
(Platform Firmware Resiliency); NIST SP 800-218 (Secure Software Development
Framework); the DoD Zero Trust Strategy and Reference Architecture; MITRE ATT&CK
for ICS and Enterprise; the Aerospace Corporation SPARTA framework; CCSDS
734.2-B (Bundle Protocol) and RFC 9172 (BPSec); and RFC 6962 (Merkle audit
structures). [TODO: platform bus standards once selected.] The effort builds on
the contractor's existing AutonomousTrust prototype. Hardware-centric defenses
(obfuscation, redundancy, FPGAs or custom processors) and special-purpose
compilers have been found ill-suited to cost-constrained edge platforms and are
not pursued.

### 4.0 Task/Technical Requirements

**4.1 Task 1: Attack-class taxonomy, threat model and test plan.**

4.1.1 The contractor shall develop an attack-class taxonomy for air and space
FEC devices, including at minimum supply-chain, remote-exploit, physical-capture
and AI-algorithm exploitation classes, and map each class to defensive
mechanisms and to SP 800-160 Vol. 2 techniques.

4.1.2 The contractor shall define, with Government concurrence, the reference
platforms, the fight-through scenarios, the evaluation metrics and their
thresholds, and shall record them before evaluation begins.

4.1.3 The contractor shall deliver a test plan covering every class in the
taxonomy.

**4.2 Task 2: Device-level integrity.**

4.2.1 The contractor shall implement measured boot and attestation using the
roots of trust native to the reference platforms, bound to each device's
cryptographic identity, with graded trust for devices lacking such hardware.

4.2.2 The contractor shall implement verification of signed software artifacts
at boot, load and install.

4.2.3 The contractor shall produce reproducible builds and software bills of
materials for the prototype.

4.2.4 The contractor shall isolate the prototype's subsystems into separately
confined processes.

4.2.5 The contractor shall implement identity re-keying and cohort-wide
revocation of a captured device's identity.

**4.3 Task 3: Edge and fog analytics and hierarchy resilience.**

4.3.1 The contractor shall implement the behavioral anomaly detector in the
embedded runtime, conformance-tested against the reference implementation.

4.3.2 The contractor shall place analytics between edge devices and fog gateways
according to device capacity.

4.3.3 The contractor shall implement redundant gateway paths and cross-checking
of gateway reports.

4.3.4 The contractor shall implement Byzantine-fault-tolerant quorum placement
and extended-partition operation.

4.3.5 The contractor shall implement streamed message processing with early
rejection of hostile messages.

**4.4 Task 4: Response, course-of-action selection and AI integrity.**

4.4.1 The contractor shall implement an autonomous containment playbook.

4.4.2 The contractor shall implement generation and ranking of courses of action
with supporting evidence and estimated mission impact, and an operator interface
for selection and override.

4.4.3 The contractor shall record every containment and operator decision in a
tamper-evident audit log.

4.4.4 The contractor shall implement integrity checking of onboard model
artifacts and plausibility checking of single-source model outputs.

4.4.5 The contractor shall evaluate the anomaly detector against evasion and
poisoning attacks.

**4.5 Task 5: Air and space platform integration.**

4.5.1 The contractor shall implement Bundle Protocol Security on the
delay-tolerant transport.

4.5.2 The contractor shall demonstrate operation under light-lag and
contact-window conditions agreed with the Government.

4.5.3 The contractor shall implement one platform bus or protocol adapter for
the reference platforms.

4.5.4 The contractor shall characterize processor, memory and link overhead on
representative flight-class hardware, and shall report on the feasibility of
microcontroller-class deployment.

4.5.5 The contractor shall execute the conformance corpus against the C core
on an emulated big-endian SPARC (LEON3) target and report the results.

**4.6 Task 6: Scale.** The contractor shall demonstrate operation at a scale of
not less than 1,000 nodes and report overhead and decision latency against node
count.

**4.7 Task 7: Pre-exercise evaluation and Government red-team exercise.**

4.7.1 The research institution shall conduct adversary-emulation campaigns
against the integrated prototype according to the test plan, in preparation for
the Government-run exercise.

4.7.2 The contractor shall deliver, install and configure the prototype for the
Government-run red-team exercise at AFRL/RI, Rome, NY, and shall support the
exercise on site.

4.7.3 The contractor shall demonstrate continued mission-task completion during
a supply-chain compromise and during a remote-exploit compromise.

4.7.4 The contractor shall report campaign results against the recorded metrics
and thresholds, and shall analyze the exercise results as released by the
Government.

**4.8 Task 8: Program management and reporting.** The contractor shall hold a
kickoff and a mid-term review with the Government, deliver quarterly status
reports and a final report, and deliver a transition plan.

## 7) Deliverables

| Item | Description | Due | Qty |
|---|---|---|---|
| Software | AutonomousTrust prototype (C core and reference runtime) with Phase II extensions, build scripts and SBOM | M9 | 1 |
| Test data | Taxonomy, test plan, pre-registration record, red-team and scaling data, reproducible evaluation artifacts | M2, M7, M9 | 1 each |
| Assurance package | Formal-verification results and conformance corpus | M9 | 1 |
| Exercise package | Prototype configured for the Government red-team exercise, with installation and operating instructions | M7 | 1 |
| Documentation | Software documentation and user's manual | M9 | 1 |
| Status reports | Quarterly | Quarterly | 8 |
| Final report | Single-page public summary followed by objectives, work, results and feasibility estimates | M9 | 1 |
| Transition plan | Integration path for the identified transition programs | M9 | 1 |

Reference edge hardware purchased under the effort is used for development and
evaluation and is not a deliverable item. [TODO: decide; if hardware is left in
Rome for the exercise it may become one, and DFARS 252.211-7003 then applies.]
[TODO: data-rights assertions for AT background technology.]

### C) Related Work

**AutonomousTrust (TekFive, 2023 to present, internally funded).** The proposed
work builds on AT, documented in Volume 5. AT provides cryptographic identity in
a Merkle-DAG ledger, reputation-weighted indirect reciprocity, leaderless
Multi-Paxos agreement, evidence-gated slashing, capability tier gating, a Zero
Trust overlay (an X.509 verifier with OCSP and CRL, deferred verification under
DDIL and delegated verification by quorum), a physical-consistency oracle,
peer-to-peer signed fleet updates, a Bundle Protocol transport, partition
detection and recovery, and a hierarchical gateway network. The C core is under
Frama-C/WP formal verification and pinned to the Python reference by a 677-case
conformance corpus. [TODO: client contact and completion date fields do not fit
an internal effort; state that.]

**PI background.** [TODO: prior programs with client, contact and completion
date, e.g. the AMOS 2021 dynamic-coalition work (Vestrand et al.) and other LANL
or TekFive programs on autonomous distributed and flight systems.]

**McCrary Institute.** [TODO: McCrary programs relevant to edge and critical
infrastructure security, with client and contact.]

**State of the art.** Commercial reputation services score infrastructure
centrally and assume connectivity; AT computes reputation among the devices
themselves and keeps doing so disconnected. Hardware-centric FEC defenses
(obfuscation, redundancy, FPGA-based monitoring) and network-perimeter defenses
are discussed in Section 4. Streaming detection of APTs in industrial IoT (Javed
et al., 2022) and the AI-based FEC taxonomy of Iftikhar et al. (2022) inform
Tasks 3 and 4. [TODO: McCrary to add the literature for the taxonomy; subject
matter experts commenting on the state of the art, if any.]

### D) Commercialization Potential

**First planned product.** [TODO: Sean to decide. Candidate: an AT edge agent
and fog gateway for small UAS and IoT fleets, licensed per device with a
supported gateway.]

**Probable customers and market size.** Defense customers are the programs
fielding small UAS, small satellites and IoBT sensors, beginning with the
transition targets below. Commercial customers are operators of industrial
control systems with thousands of long-lived controllers on flat networks,
commercial constellation operators, drone-fleet operators, healthcare device
fleets that must keep working when the hospital uplink drops, and builders of
multi-agent AI systems, where the question is no longer whether an identity is
valid but whether an agent is still behaving as it should. [TODO: market sizing
with sources.]

**Funding to market.** [TODO: amount and sources.]

**Marketing expertise.** [TODO: TekFive business development; McCrary's
relationships with utilities and critical-infrastructure operators, including
through SERC3; TABA (up to $50,000) for market validation.]

**Competitors and advantage.** Centralized reputation and threat-intelligence
services, endpoint detection products and Zero Trust platforms all depend on
reachable infrastructure; hardware-security vendors depend on added parts. AT's
advantage is that it keeps working disconnected, needs no added hardware, and
carries formal-verification evidence. [TODO: named competitors and price
position.]

### E) Relationship with Future R/R&D Efforts

Phase II ends with a prototype on representative platforms that has been through
a Government-run red-team exercise. Phase III integrates it into a transition
program's platforms for operational test and accreditation, with the formally
verified core and the exercise results as the principal accreditation evidence.
The Phase III description names avionics, space systems, IoT, IoBT and IoST, all
of which the same agent serves with a different bus adapter. [TODO: transition
programs and sponsors; letters of support.]

### F) Key Personnel

| Name and title | Employer | Education and experience | Citizenship |
|---|---|---|---|
| Sean M. Brennan, Principal Investigator | TekFive | Software engineer, architect and research scientist with 20+ years building secure, real-time autonomous distributed systems from the resource-constrained edge to the data-fusion core, across unclassified and classified networks, including embedded and flight software and M&S of large distributed networks. Ph.D. in Computer Science (2009). Author of AutonomousTrust. | U.S. |
| [TODO: university PI] | McCrary Institute, Auburn University | [TODO] | [TODO] |
| [TODO: e.g. J. Mark Norris, ZTA and systems engineering] | TekFive | [TODO] | U.S. |

[TODO: PI technical resume with publications; concise resumes for McCrary
staff.] No foreign nationals are proposed for any task, at TekFive or at Auburn.
TekFive holds an active Top Secret Facility Clearance issued by DCSA, with an
approved FSO, an Insider Threat Program and NISPOM compliance, and is 100%
U.S.-owned with no FOCI. [TODO: refresh clearance counts.]

### G) Facilities/Equipment

TekFive supplies development workstations and servers, the AT codebase,
simulator and scale harness, representative ARM edge hardware, and an AWS
GovCloud account (ITAR compliant) for the scaling study. The PI works from a
TekFive-designated office in Duck, WV under TekFive's approved remote-work and
information-security policies (CMMC Level 2); other TekFive work is performed at
850 Ben Graves Dr NW, Suite 324, Huntsville, AL 35816. McCrary work is performed
at Auburn University. [TODO: McCrary facilities and equipment.] [TODO: reference
platform hardware to be purchased, with justification in the cost volume.]

TekFive's facilities comply with all applicable federal, state and local
environmental laws and regulations. [TODO: Auburn to confirm the same for its
facilities.]

### H) Consultants/Subcontractors

**McCrary Institute for Cyber and Critical Infrastructure Security, Auburn
University (research institution).** McCrary is our STTR research partner, and
we chose the division of work deliberately: TekFive builds the defense and
McCrary attacks it, so that every claim of coverage in the final report has been
tested by people who did not write the code. McCrary leads the attack-class
taxonomy and test plan (Task 1), the adversarial-ML evaluation (Task 4.4.5) and
the campaigns that prepare the fabric for the Government exercise (Task 4.7.1),
and contributes to the fight-through scenarios. [TODO: whether McCrary staff may
attend the exercise in Rome.] McCrary performs approximately 40% of the effort
and TekFive approximately 60%, measured by cost. [TODO: McCrary PI and staff,
facilities (Edge Lab, SERC3) and their role, statement of work, signed letter of
intent, and cost proposal. Final split depends on the hardware purchase.]

### I) Prior, Current, or Pending Support of Similar Proposals or Awards

TekFive submitted a related proposal, "AutonomousTrust: Behavior-Aware Zero
Trust for Comms-Denied Combat Systems," to the Department of the Navy under SBIR
topic DON26BZ03-NV059 (Real-time Zero Trust Data and Access Control for Combat
Systems) on July 22, 2026, PI Sean M. Brennan, Senior Software Engineer. It has
not been funded. That effort concerns data-access control for shipboard combat
systems and is not essentially equivalent to the work proposed here, but both
build on AT and we disclose it accordingly. [TODO: solicitation number and date;
check the Cover Sheet box.]