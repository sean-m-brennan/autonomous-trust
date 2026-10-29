# Resource requirements: one C node

These figures are for a single instance of the C implementation (`at_demo`), so
that hardware can be sized from measurement rather than guesswork. We measured
all 28 C nodes of a working 40-node dod-mission cohort on 2026-10-27, sampling
each over 120 s twice: once while the cohort was forming, before the scenario
started, and once while the scenario was running. CPU, memory and network were
read from each container's cgroup v2 and `/proc` counters.

## Measurements

| Resource | Cohort forming | Scenario running | Notes |
|---|---|---|---|
| CPU | 1.1% of one core (median; 0.8 to 1.3%) | 0.6% (0.3 to 0.9%) | One core of an AMD Ryzen 9 9950X |
| Memory | 40 MiB median (28 to 52) | 68 MiB median (57 to 82); peak 83 MiB | Whole container cgroup, page cache included |
| Network | about 45 KB/s each way (about 360 kbit/s) | about 14 KB/s each way (about 110 kbit/s); one node peaked at 49 KB/s transmit | Includes the demo's sensor traffic |
| Disk | 4.3 MB of binaries | about 200 KB of state per node after a full run | Logs excluded |

The binaries are `at_demo` (1.98 MB), `libautonomous_trust.so` (1.18 MB) and
eleven extension libraries (about 1.2 MB together). At runtime they need
libsodium, protobuf-c, jansson and libuuid, which are small. The 144 MB container
image is almost entirely its Debian base, and AT does not require it.

## Recommendations

For each node we suggest budgeting:

- **CPU:** one ARMv8 core of Cortex-A53 class or better, allowing about 10% of
  that core for AT so that bursts during cohort formation have room.
- **RAM:** 128 MiB, or 256 MiB for comfortable headroom.
- **Storage:** 16 MB for binaries and state, plus log space; 64 MB is ample at
  INFO level.
- **Link:** at least 512 kbit/s symmetric while a cohort forms. Steady state in
  a 40-peer cohort is about 128 kbit/s.

## Caveats

- **Network grows with cohort size.** Formation traffic is gossip within the
  cohort, so a larger cohort costs every member more. These figures are for 40
  peers, and the gateway hierarchy is what keeps cohorts small.
- **Memory includes page cache** from the node writing its state files, so it
  overstates what the process needs. We did not separate resident memory from
  cache.
- **CPU was measured on x86 inside Docker.** A Cortex-A53 or A72 core is several
  times slower, so expect a few percent of one core there; a run on real ARM
  hardware should confirm it. [TODO: Pi 4 measurement]
- **The workload is the dod-mission demo,** whose sensor traffic is part of the
  bandwidth figure. A different mission will differ.

## Hierarchical cohorts

We ran the dod-mission scenario as a two-tier hierarchy on 2026-10-29: a command
cohort (coordinator, squad, jet, command node and three RQ-86 gateways) over three
field cohorts, each gateway on both the command subnet and its field subnet. Field
microdrones were C nodes apart from one Python anchor per cohort, and all of it ran
on one host. A field peer has joined when a member sends it `access_granted` or it
adopts its cohort's group; join time runs from its own first announce, and a seeded
drone that takes its cohort's group before asking counts as zero.

| Run | Field cohorts | Joined | Join p90 per cohort | Anomaly detected | Host RAM peak |
|---|---|---|---|---|---|
| 48 peers (3 × 13 field nodes) | 14 nodes each | 36 of 36 | 83 s, 87 s, 70 s | yes, 835 s | 55% |
| 96 peers (3 × 29 field nodes) | 30 nodes each | 84 of 84 | 744 s, 396 s, 175 s | yes, 919 s | 59% |

At both sizes the cohorts stayed apart: the coordinator's group held its eight
command members, no field peer reached the command cohort, and the gateways relayed
field readings, the MQ-800's among them, to the coordinator.

Joins at 96 are slow because the host is saturated, not because the cohorts are
large. The kernel drops a share of UDP sends at the sender while reporting success
(`SndbufErrors` climbed on every node we sampled, a sixth of sends or more on some),
and process start-up for 176 containers spread over twenty minutes, so a cohort's
admitter often came up after its members. A joiner therefore asks again until it is
admitted (`AT_JOIN_PATIENCE_SEC`), and a welcomer sends its welcome twice more a few
seconds later. On hardware with one cohort per host the start-up spread and the send
loss should both fall away. [TODO: rerun at 96 with field cohorts on separate hosts]
