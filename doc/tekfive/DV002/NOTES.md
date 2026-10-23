# DV002 working notes

Draft started 2026-10-23. Files:

- `TekFive_AutonomousTrust_DAF27TZ01-DV002_Technical_Volume.md`: Volume 2, in
  the section order the DAF instructions require.
- `TekFive_AutonomousTrust_DAF27TZ01-DV002_Feasibility.md`: Volume 5
  feasibility documentation, outside the page limit.
- `topic_DAF27TZ01-DV002.md`: the topic, full description and Q&A.

The DAF instructions (`DAF_STTR_27TZ_D2P2_R1.pdf`, 27 pp., downloaded
2026-10-23) are in the session scratchpad, not in the repo, because `/home` was
at 91% when downloaded. Copy them here if wanted (340 KB).

## What the DAF instructions settle

- **Limits.** $2,000,000, 24 months, 35 pages for Volume 2. Excess pages are not
  read. 11 pt minimum, one-inch margins, numbered pages, graphics legible in
  black and white.
- **Volume 2 order.** Table of contents, glossary, milestones, identification
  and significance, Phase II objectives (each with its commercial
  application), work plan (on a new page, no proprietary data, binding
  requirements in "shall" language, sections 1.0 Objective, 2.0 Scope, 3.0
  Background, 4.0 Tasks), deliverables, related work (with client contact and
  completion date), commercialization potential (five named questions),
  relationship with future R&D, key personnel (PI resume with publications;
  citizenship), facilities, consultants and subcontractors (signed letters of
  intent, SOW, cost proposal), prior, current and pending support.
- **Feasibility goes in Volume 5**, outside the page limit. It must have been
  substantially performed by TekFive or the PI, and cannot be based on or
  logically extend from federally funded SBIR/STTR work. Sean confirmed
  2026-10-23 that NV059 is unfunded and that all prep for this proposal is
  TekFive funded. If NV059 is awarded before DV002 is decided, its Phase I
  outputs still must not be cited as DV002 feasibility.
- **Volume 5 also requires** the Regulatory Compliance Initial Safety
  Assessment form (afwerx.com), DD Form 2345 (ITAR topic; certified copy or
  proof of application), and data-rights assertions with a summary per
  restricted item. A TABA request (up to $50,000) also goes here, in detail.
- **Volume 6** FWA training must be complete before DSIP will accept the
  submission. **Volume 7** foreign-affiliation disclosures are a DSIP webform.
- **Work share is unclear.** The instructions say both "a minimum of 50% ...
  by the proposing firm" and "for Phase II, a minimum of one-third ... by the
  Awardee", and say nothing STTR-specific. The DoW STTR BAA rule is at least
  40% by the small business and at least 30% by the research institution.
  Ask the DAF help desk (usaf.team@afsbirsttr.us). The planned 60/40 split
  satisfies every one of these readings. Because the percentage is measured by
  cost, hardware bought by TekFive raises TekFive's share; hardware for the
  evaluation lab bought on McCrary's side of the budget raises theirs, which
  is one way to hold McCrary at 40% if the hardware bill grows.
- **The full topic text says more than DSIP showed.** The attack classes of
  concern are supply chain, remote exploits leading to APTs, and AI algorithm
  exploitation, plus physical access to downed or captured devices. It names
  sUAS, small satellites and IoBT. It warns against expensive add-on trusted
  hardware, FPGAs, custom processors and special-purpose compilers, and asks
  for 100s to 1000s of nodes. The draft now answers each.

## Dates

| When | What |
|---|---|
| 2026-10-28 08:00 ET | Pre-release ends. Last chance to talk to Blasch and Pham directly. |
| 2026-11-11 12:00 ET | Topic Q&A closes (questions through DSIP only after 10-28). |
| 2026-11-25 12:00 ET | Proposals due in DSIP. |

**Blasch conversation (by 2026-10-23).** Sean asked about platforms, the bus
adapter and the fight-through scenario. Blasch's answer, paraphrased: whatever
you have ready to go. Transition programs were not asked. Sean's two readings
are (a) they already have someone in mind, or (b) they are open to anything
likely to pass the Phase II red-team demonstration.

Either way, the draft responds the same way. It picks the reference platforms
and scenarios itself rather than deferring them to kickoff, leans on what is
ready now, and makes the independent red-team result the centerpiece, with an
invitation for the Government to observe or field its own red team (Volume 2
O7). A vague answer during pre-release is also common, because TPOCs avoid
giving any one offeror an advantage, so (a) is not established by it.

**Pham** is still reachable until 10-28 08:00 ET. Worth asking him the
transition question Blasch was not asked, and which small-satellite processor
class he would consider representative, since he is the Space Force TPOC.

## The Phase II red-team exercise

Sean, 2026-10-23: the Phase II red-team demonstration is a Government-run
exercise at AFRL's Information Directorate (AFRL/RI) in Rome, NY (confirmed by
Sean). Volume 2 now treats McCrary's campaigns as preparation for that exercise
rather than as the final evaluation, adds an exercise package delivered at M7,
puts the exercise at M8, and drops the earlier offer for the Government to field
its own red team, since it already does.

Things to find out, from the TPOCs or through DSIP Q&A by 11-11:

- When in the 24 months the exercise falls, and how long it runs.
- Whether the Government furnishes the platforms and network, or we ship ours.
  If ours stay in Rome they may become deliverable hardware (DFARS
  252.211-7003).
- The exercise's success criteria, so our metrics can align with them.
- Whether the exercise network is unclassified, and who may attend (McCrary
  staff in particular).

Cost volume: travel to Rome for integration and the exercise, at least two
trips, plus the kickoff the instructions require.

## Differences from NV059

NV059 was a Navy SBIR **Phase I**. DV002 is an Air Force **STTR Direct to Phase
II**, and most of the structural changes follow from that.

- **Feasibility must already exist.** NV059 proposed to show feasibility by M&S.
  DV002 needs a prior demonstration of one attack class on an edge device,
  with autonomous detection and response, presented as done. Part A of the
  draft carries that.
- **Funding rule on feasibility.** Feasibility cannot derive from federally
  funded SBIR/STTR work. AT and all prep work are TekFive funded; NV059 is
  unfunded and is disclosed as pending support in Volume 2 §I.
- **STTR, not SBIR.** McCrary must do at least 30% of the work and TekFive at
  least 40%. The plan is about 40% McCrary and 60% TekFive, by cost. Sentar has
  no role in Phase II (Sean, 2026-10-23).
- **Fog and edge, not combat-system data access.** NV059 framed AT as a Zero
  Trust overlay for combat-system data. DV002 frames it as device resilience,
  with the gateway hierarchy recast as the fog tier.
- **Devices, not just network participants.** The boot chain, supply chain,
  process model and physical bus become part of AT's evidence (§B.1, Task 2).
  Hardware attestation moves from an Option design spec in NV059 to a Phase II
  build.
- **Air and space, not afloat.** DTN and light-lag replace tactical SATCOM to
  ships; MIL-STD-1553 / SpaceWire replace Modbus / DNP3 / OPC-UA / BACnet;
  SPARTA joins ATT&CK.
- **Hardware.** The topic warns against add-on trusted hardware, so attestation
  is graded and uses whatever root of trust the platform already has, rather
  than requiring a TPM as NV059's Option design assumed.
- **AI algorithm exploitation** is a named class here and had no NV059
  counterpart; the ISR demo's catch of a compromised detector is the hook.
- **No quantitative targets in the topic.** NV059 had four Navy targets (auth
  under 5 s, latency −50%, unauthorized access −90%, admin overhead −25%).
  DV002 has none, so the draft proposes metrics to agree with the TPOCs.
- **Response goes to a human for COA selection.** The DV002 Q&A asks for
  autonomous detection plus autonomous responses offered to an operator.
  NV059's human-on-the-loop was an override; DV002 needs ranked courses of
  action (Task 4).
- **Fight-through is the Phase II demonstration.** Supply-chain or
  remote-exploit, with the mission continuing.
- **Research partner focus.** McCrary's contribution is the attack-class
  taxonomy, adversary emulation and independent T&E (§B.2).

## Pre-submission work

These are the items the draft states as done that the code does not yet support,
plus what is needed to fill each `[TODO: result]`. Ordered roughly by how much
the proposal leans on them.

1. **Pi 4 hardware run (STRETCH_GOAL_3 phases 2, 4, 5).** Everything so far is
   QEMU and Docker. Run `at_demo` on a real Cortex-A72 from the Buildroot image,
   in the ISR scenario, and capture detection-to-exclusion latency, CPU and
   RSS. §A.3 depends on it.
2. **Signature verification at boot and load.** `embedded/sign-binary.sh`
   signs, but nothing verifies at load; the systemd unit just execs `at_demo`.
   `doc/security.md` already claims verification before load. Minimum is a
   verifying launcher, plus the signed boot.img / initramfs that
   `embedded/doc/architecture.md` describes (no initramfs exists under
   `buildroot/` today).
3. **Supply-chain demonstration on hardware.** With `-DAT_FLEET_LIB=ON`, show
   a tampered image refused, an unsigned update refused, and a signed-but-faulty
   update rolled back, with timings. Close ISSUES §2.34 (host check owed).
   This is the second attack class in §A.3 and the Q&A's own example.
4. **100-node run.** `.scale-results/summary.csv` (May 27) shows 100 peers
   "degraded, no-anomaly-in-log". Need it green: admission time, detection
   latency, per-node overhead against node count. Then a hierarchical run at
   larger N across several gateway levels, which is the real scaling argument;
   the topic says 100s to 1000s, so the larger the hierarchical N, the better.
5. **ML layer wired into response.** `PeerBehaviourGovernor` is only
   instantiated inside the behavior package, and its `SlashRecommendation`
   list has no consumer. Wire it into a live cohort with `auto_slash=False`
   and show a recommendation reaching an operator. Even a minimal COA
   prompt would let §A.3 meet the Q&A directly. Also get the units for
   "16.6 against 29.4".
6. **Red-team result artifacts.** The harnesses exist
   (`src/autonomous-trust-evaluation/.../redteam/`) but no results are in the
   tree. A run of the Sybil, MITM, replay and compromise harnesses with saved
   output backs the "AT mechanism today" column of §B.3.
7. **Frama-C refresh.** Figures are from 2026-04-17 and exclude the
   extensions (rendezvous, first_contact, data_source unverified). Rerun and
   update §A.5.
8. **Commit the hostile-join work** (R+D §14.4, 72 modified/untracked files)
   if any of it is to be cited.
9. **arm64 CI green run.** The workflow exists; automatic runs were disabled
   2026-10-23.
10. **Doc corrections**, so a reviewer who reads the repo finds it consistent
    with the proposal: `security.md` (signed binary, hardware attestation);
    `embedded/doc/architecture.md` (boot chain); DTN comments claiming BPSec;
    `adversarial-testing.md` and `security-hardening.md` (unverified Paxos
    proposals are rejected, not merely logged); the NIST matrix M10/M11
    status; the whitepaper's "100-node study is the next step".

11. **aarch64 footprint from the current build.** The only arm64 numbers
    (text 2,570,261 / bss 469,200 for the static `at_demo`) predate the BSS
    fix; Volume 5 §4 wants current ones.

Paperwork, not engineering:

- Regulatory Compliance Initial Safety Assessment form; DD Form 2345; FWA
  training; Volume 7 webform; data-rights assertions.
- Work-share question to the DAF help desk (see above).
- PI technical resume with publications (Volume 2 §F requires it).
- Commercialization answers: first product, market size, funding to market,
  marketing, competitors (Volume 2 §D).
- McCrary: PI, staff, facilities, percentage of effort, budget, letter,
  export-control plan, STTR cooperative agreement.
- Letters of support from Air Force or Space Force programs, and Phase III
  partners. The GDMS letter was Navy-specific.
- NV059 status for §B.14 and the feasibility-funding question.
- OV-1 for an air/space fleet.

## Claims deliberately left out

These are true but either thin or easily misread, so the draft does not lean on
them:

- Cortex-M7 is "currently infeasible" per the embedded plan; the draft offers
  only a microcontroller-class *feasibility study* in Task 5.
- The package-hash admission allowlist is self-reported and would not survive
  a reviewer's question, so the draft does not cite it as supply-chain defense.
- Sybil detection in the behavioral red-team scores 0.0 by design (Sybils are
  bounded at admission); §B.3 explains that instead of quoting the number.
- Revocation applies a reputation penalty rather than disconnecting; not
  mentioned.
