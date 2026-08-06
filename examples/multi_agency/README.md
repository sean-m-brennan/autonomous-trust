# Multi-Agency Federal Data Sharing Demo

A demonstration of [AutonomousTrust](../../src/autonomous-trust/README.md)
in a credible multi-agency disaster-response scenario.

## Scenario

Hurricane Helene is making landfall near **Wilmington, North Carolina**.
Ten sensor nodes from four federal agencies need to share environmental
data in real time, but one sensor has been compromised and is sending
falsified weather readings.

The network forms autonomously, detects the bad data through
cross-source validation, collapses the compromised sensor's reputation,
and excludes it: **all without human intervention**.

> The dashboard is a *window into the network*, not a control surface.
> Every trust decision is made by the autonomous agents.  The narration
> credits decisions to the network, not to a human operator.

### Agencies & peers

| Peer | Agency | Type | Location |
|------|--------|------|----------|
| noaa-sensor-1 | NOAA | Weather station | Wrightsville Beach |
| noaa-sensor-2 | NOAA | Weather station | Carolina Beach |
| noaa-sensor-3 | NOAA | Weather station | Topsail Beach *(compromised)* |
| usgs-monitor-1 | USGS | Seismic monitor | Castle Hayne |
| usgs-monitor-2 | USGS | Seismic monitor | Burgaw |
| fema-field-1 | FEMA | Field station | Wilmington |
| fema-field-2 | FEMA | Field station | Leland |
| fema-fusion | FEMA | Fusion center | Raleigh |
| epa-monitor-1 | EPA | Air quality | Wilmington *(joins late)* |

### Timeline

| Time | Phase | What Happens |
|------|-------|-------------|
| T+0:00 | Formation | NOAA, USGS, FEMA peers discover each other |
| T+1:00 | Bootstrap | Trust graph stabilizes, reputation reaches 0.7+ |
| T+2:00 | Negotiation | Peers negotiate data-sharing agreements |
| T+2:30 | Data Sharing | Weather, seismic, and air quality streams begin |
| T+4:00 | Compromise | noaa-sensor-3 starts sending falsified temperature data |
| T+4:30 | Detection | Network detects anomaly via cross-source validation |
| T+5:00 | Exclusion | noaa-sensor-3 reputation collapses, autonomously excluded |
| T+6:00 | EPA Onboard | EPA monitor joins post-exclusion |
| T+7:00 | Integration | Full data sharing resumes with 9 trusted peers |

### The money shot

At T+4:00 the compromised NOAA sensor begins reporting falsified
temperature readings.  The sensor comparison chart shows its values
diverging from the other two NOAA sensors.  By T+4:30 the trust
dynamics timeline shows its reputation dropping.  By T+5:00 it is
excluded, the trust graph edge turns red, then disappears.

The compromise mode is configurable:
- **Gradual drift**: realistic; readings slowly shift away from truth
- **Abrupt deviation**: dramatic; instant jump to false values

## Quick start

```bash
# From the repository root:
cd examples/multi_agency
./deploy/run-demo.sh

# Open dashboard at http://localhost:8050
```

## Canned playback

A pre-recorded session can be replayed without running the full
simulation.  This is useful for presentations and CI verification.

```bash
# Record a session
python -m examples.multi_agency.run --record session.jsonl

# Replay at 5x speed
python -m examples.multi_agency.run --playback session.jsonl --speed 5
```

## Reputation log-harvest debug lens

A debugging instrument for understanding how reputation actually
propagates, **not** production-realistic on purpose. Instead of the
dashboard learning bilateral trust by relaying `rep_pair` scores over
the mesh (which only shows what survives the network round-trip), each
node reports **its own** view of every peer straight to its logs, and a
host-side harvester reconstructs the full observer→subject matrix
out-of-band.

**1. Run the mesh with the dump enabled.** Set `AT_REP_DUMP_SEC` on the
participants (seconds between dumps; unset/0 = off). Each node's
reputation process then logs one line per interval:

```
AT_REPDUMP {"t":123.4,"self":"<uuid>","view":[
  {"s":"<subj-uuid>","nick":"noaa-sensor-2","con":0.81,"rep":0.79,
   "n":12,"coop":11,"def":1,"tier":2,"exc":false}, ... ]}
```

`con` is the node's own consensus view of the subject; `n`/`coop`/`def`
are the raw CTFT inputs (committed bilateral txs split at the 0.5
cooperate threshold) behind it. *(Python reputation backend only: a
native-C run does not emit these, same as `AT_REP_TRACE`.)*

For Docker Compose, add to `deploy/docker-compose.yml` (e.g. under
`x-common-env`) or export before launch:

```yaml
environment:
  AT_REP_DUMP_SEC: "2"
```

**2. Harvest the logs and serve the dashboard** from a host that has the
container runtime on its PATH:

```bash
# Docker Compose:
python -m examples.multi_agency --log-harvest            # tails docker logs -f
# Kubernetes / minikube:
python -m examples.multi_agency --log-harvest --runtime k8s --namespace <ns>
# Explicit node set (default = the scenario's peer names):
python -m examples.multi_agency --log-harvest --containers noaa-sensor-1,noaa-sensor-2
```

Or drive both steps through the unified launcher: bring the mesh up with
dumps enabled, then attach the lens (launched as a managed background
subprocess, served on 8060 so it doesn't collide with the coordinator's
own 8050 dashboard):

```bash
AT_REP_DUMP_SEC=2 scripts/run-demo.sh --variant=multi-agency --compose   # terminal 1
scripts/run-demo.sh --variant=multi-agency --log-harvest                 # terminal 2
# k8s: add --runtime k8s --namespace <ns> to the --log-harvest call
```

### Exclusion triage (why is a node "excluded"?)

`excluded` on the Trust Network graph is a *display* verdict (dashboard
consensus ≤ 0.5), which is **not** AT's real exclusion (`COMM_CUTOFF` =
0.1 / the reputation process's `_excluded` set). A peer sitting at the
0.2 cold-start baseline (no committed bilateral transactions yet) is
below 0.5 but nowhere near real exclusion, so it gets mislabeled. The
one-shot triage reads the current logs and separates the cases:

```bash
python -m examples.multi_agency --triage          # docker
python -m examples.multi_agency --triage --runtime k8s --namespace <ns>
scripts/run-demo.sh --variant=multi-agency --triage
```

```
SUBJECT  OBS  n>0  MEAN  MIN   MAX   EXC  COOP  DEF  VERDICT
c        2    2    0.04  0.04  0.05  2    0     5    REAL: below COMM_CUTOFF on 2 observer(s)
a        2    0    0.20  0.20  0.20  0    0     0    MISLABELED: cold-start baseline, 0 committed txs
d        2    2    0.29  0.28  0.30  0    2     7    DECLINED: earned drop (check def vs coop)
b        2    2    0.81  0.80  0.82  0    11    0    ok
```

`n>0` (observers with committed bilateral history) and `EXC` (observers
holding the subject in `_excluded`) are the tells: `n>0 == 0` means the
low score is pure baseline (mislabeled); `EXC > 0` means genuine AT
exclusion.

The harvester tails every node's logs, unions each node's self-report
into a global matrix (observer identity = the container/pod the line
came from, so nothing self-claimed is trusted), and feeds the dashboard
the same `rep_pair`/`peer_seen` stream it already renders. Each
observer's own-view score is one directed edge; the demo averages them
per subject for the Trust-Dynamics line and takes `min()` per undirected
pair for the Trust-Network edge. An edge appears only once **both**
endpoints have self-reported, so every name is an authoritative node
name (they resolve within one `AT_REP_DUMP_SEC` interval).

In this mode the graph also colors **exclusion authoritatively**: a peer
is drawn *excluded* only when a majority of observers hold it in their
real `_excluded` set, *forming* (faint) when no peer has committed
bilateral history with it yet, and *active* otherwise, so a cold-start
peer at the 0.2 baseline is no longer mislabeled "excluded" by the 0.5
display threshold. (Coordinator-hosted-live and playback modes, which
emit no per-subject status, still fall back to the score threshold.)

## Architecture

```
examples/
  common/              Shared framework (scenario engine, generators,
                       compromise behaviors, playback, deployment)
  multi_agency/
    scenario.py        10-peer disaster response scenario definition
    generators/        NOAA weather, USGS seismic, EPA air quality
    compromise/        Falsified sensor behaviors (drift, abrupt)
    tasks/             Data-sharing and cross-source validation tasks
    deploy/            Docker Compose config + run script
```

The scenario engine (`autonomous_trust.simulator.scenarios.scenario`) is shared with
other demos (e.g. the DoD squad infiltration demo).  The multi-agency-specific
code defines the peers, geography, data generators, and dashboard
customization.

## Data generators

Each sensor peer runs a data generator that produces realistic readings:

- **Weather** (NOAA): Temperature (sinusoidal diurnal + hurricane warming),
  wind speed (random walk with gusts), barometric pressure (declining trend),
  precipitation (event-based)
- **Seismic** (USGS): Background micro-seismicity with occasional events
- **Air Quality** (EPA): AQI, PM2.5, ozone (affected by storm conditions)

## Docker limitations

The Docker Compose deployment has these limitations compared to a
full Kubernetes deployment:

- **No per-link bandwidth shaping**: all peers share a flat bridge network.
  A K8s deployment with CNI plugins could simulate constrained links.
- **No native node failure injection**: compromised peers are simulated
  via behavior changes, not container restarts.  K8s supports pod eviction
  and network policies for more realistic failure scenarios.
- **Single-host only**: Docker Compose runs on one machine.  K8s
  distributes across a cluster for realistic network latency.
