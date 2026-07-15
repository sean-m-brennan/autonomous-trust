*[AutonomousTrust](autonomous_trust.md) > Example Application*

# Example Application: Multi-Agency Disaster Response

This is AutonomousTrust end to end, in one scenario. If you have read the [concept](concept.md) and skimmed the [architecture](architecture/README.md), this ties them together: a cohort forms, does useful work, catches one of its own members lying, and removes it, with no human in the decision loop.

The demo ships in [`examples/multi_agency/`](../examples/multi_agency/README.md) and runs in-process on your machine, so you can watch it happen.

## The scenario

Hurricane Helene is making landfall near Wilmington, North Carolina. Ten sensor nodes belonging to four federal agencies need to share environmental data in real time. One of them has been compromised and is reporting falsified readings.

| Peer | Agency | Type | Note |
|------|--------|------|------|
| noaa-sensor-1, -2 | NOAA | Weather stations | |
| noaa-sensor-3 | NOAA | Weather station | compromised |
| usgs-monitor-1, -2 | USGS | Seismic monitors | |
| fema-field-1, -2 | FEMA | Field stations | |
| fema-fusion | FEMA | Fusion center | |
| epa-monitor-1 | EPA | Air quality | joins late |

The agencies do not share a central trust authority, and the link to any such authority cannot be assumed during a storm. The peers have to decide among themselves who is trustworthy, and they have to keep deciding as conditions change.

## Running it

```bash
# In-process, no Docker. Joins a live AT mesh and streams real peer
# observations into the dashboard.
python -m examples.multi_agency
# Open http://localhost:8050

# Replay a captured run without an AT runtime (useful for demos and CI):
python -m examples.multi_agency --playback session.json

# Capture a run's scripted timeline to JSON for later replay:
python -m examples.multi_agency --record session.json
```

For the multi-node version orchestrated over Docker, Tilt, and Minikube:

```bash
./at run-demo --variant=multi-agency
```

The dashboard is a window into the network, not a control surface. Every trust decision on screen is made by the agents; nothing in the UI overrides them.

## What to watch

The scenario runs on a scripted timeline. Each phase exercises a different part of the runtime.

| Time | Phase | What happens |
|------|-------|--------------|
| T+0:00 | Formation | NOAA, USGS, and FEMA peers discover each other and form a group. |
| T+1:00 | Bootstrap | The trust graph stabilizes as peers earn reputation past ~0.7. |
| T+2:00 | Negotiation | Peers negotiate data-sharing agreements for the work at hand. |
| T+2:30 | Data sharing | Weather, seismic, and air-quality streams begin flowing. |
| T+4:00 | Compromise | noaa-sensor-3 starts reporting falsified temperature data. |
| T+4:30 | Detection | The network flags the anomaly through cross-source validation. |
| T+5:00 | Exclusion | The sensor's reputation collapses and it is dropped from the cohort. |
| T+6:00 | EPA onboard | An EPA monitor joins after the exclusion. |
| T+7:00 | Integration | Full data sharing resumes among the nine trusted peers. |

The turn to watch is T+4:00 through T+5:00. The compromised sensor's temperature readings diverge from the other two NOAA sensors covering the same area. The sensor-comparison chart shows the divergence, the trust-dynamics timeline shows its reputation falling, and by T+5:00 its edge in the trust graph turns red and then disappears. The compromise mode is configurable between a gradual drift and an abrupt jump.

## How it maps to the architecture

Each phase above is a subsystem doing its job:

- **Formation** is the identity subsystem: peer discovery, admission voting, and group formation over cryptographic identities whose private keys never leave the node. See [Identity Protocol](architecture/identity-protocol.md).
- **Bootstrap** is the trust-tier machinery: a new peer runs a small corpus of low-stakes transactions to earn its way up the reputation gradient before it is trusted with real data. See [Trust Tiers](architecture/trust-tiers.md).
- **Negotiation** is the distributed task lifecycle: peers agree on which capabilities they will provide to whom. See [Task Negotiation](architecture/negotiation.md).
- **Detection and exclusion** are the reputation subsystem. A sustained anomaly drives the peer's score down through the running consensus, and a quorum-co-signed slash floors it, which triggers tier-gated removal. The decision is deterministic and backed by signed evidence any peer can re-verify. See [Reputation Consensus](architecture/reputation.md) and [Reputation vs. Blockchain Analysis](architecture/reputation-vs-blockchain-analysis.md).
- **EPA late join** exercises admission after the cohort is already running, where the ZTA overlay gates entry and DDIL fallback applies if verification infrastructure is unreachable. See [ZTA Integration](architecture/zta-integration.md).

Nothing in this loop waits on a central authority, and the human watching the dashboard is an observer, not the decider.

## Going deeper

- [`examples/multi_agency/README.md`](../examples/multi_agency/README.md): the demo's own walkthrough, agency roster, and playback details.
- [`examples/README.md`](../examples/README.md): the full example suite, the `ScenarioInterface` abstraction, and how to add your own scenario.
- [SG2 Detection Walkthrough](architecture/sg2-detection-walkthrough.md): the same detect-and-exclude story in the DoD mission demo, at the wire level.
