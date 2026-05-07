# Multi-Agency Federal Data Sharing Demo

A demonstration of [AutonomousTrust](../../src/autonomous-trust/README.md)
in a credible multi-agency disaster-response scenario.

## Scenario

Hurricane Helene is making landfall near **Wilmington, North Carolina**.
Ten sensor nodes from four federal agencies need to share environmental
data in real time — but one sensor has been compromised and is sending
falsified weather readings.

The network forms autonomously, detects the bad data through
cross-source validation, collapses the compromised sensor's reputation,
and excludes it — **all without human intervention**.

> The dashboard is a *window into the network*, not a control surface.
> Every trust decision is made by the autonomous agents.  The narration
> credits decisions to the network, not to a human operator.

### Agencies & Peers

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

### The Money Shot

At T+4:00 the compromised NOAA sensor begins reporting falsified
temperature readings.  The sensor comparison chart shows its values
diverging from the other two NOAA sensors.  By T+4:30 the trust
dynamics timeline shows its reputation dropping.  By T+5:00 it is
excluded — the trust graph edge turns red, then disappears.

The compromise mode is configurable:
- **Gradual drift** — realistic; readings slowly shift away from truth
- **Abrupt deviation** — dramatic; instant jump to false values

## Quick Start

```bash
# From the repository root:
cd examples/multi_agency
./deploy/run-demo.sh

# Open dashboard at http://localhost:8050
```

## Canned Playback

A pre-recorded session can be replayed without running the full
simulation.  This is useful for presentations and CI verification.

```bash
# Record a session
python -m examples.multi_agency.run --record session.jsonl

# Replay at 5x speed
python -m examples.multi_agency.run --playback session.jsonl --speed 5
```

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

## Data Generators

Each sensor peer runs a data generator that produces realistic readings:

- **Weather** (NOAA): Temperature (sinusoidal diurnal + hurricane warming),
  wind speed (random walk with gusts), barometric pressure (declining trend),
  precipitation (event-based)
- **Seismic** (USGS): Background micro-seismicity with occasional events
- **Air Quality** (EPA): AQI, PM2.5, ozone (affected by storm conditions)

## Docker Limitations

The Docker Compose deployment has these limitations compared to a
full Kubernetes deployment:

- **No per-link bandwidth shaping** — all peers share a flat bridge network.
  A K8s deployment with CNI plugins could simulate constrained links.
- **No native node failure injection** — compromised peers are simulated
  via behavior changes, not container restarts.  K8s supports pod eviction
  and network policies for more realistic failure scenarios.
- **Single-host only** — Docker Compose runs on one machine.  K8s
  distributes across a cluster for realistic network latency.
