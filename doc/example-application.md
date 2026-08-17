*Previous: [The human behind the machine](architecture/operator-attended.md)*

# A worked scenario

Everything in Part II has been mechanism. This chapter is the mechanism running,
in one scenario that can be started on an ordinary machine and watched from a
browser.

A hurricane is making landfall. Ten sensor nodes belonging to four federal
agencies need to share environmental readings in real time, and one of them has
been compromised and is reporting falsified data. The agencies share no central
trust authority, and even if they did, the link to it cannot be assumed during a
storm. So the sensors have to work out among themselves who is worth believing,
and they have to keep working it out as conditions change.

Over about seven minutes the cohort forms, does useful work, notices that one of
its own members is lying, and removes it. No person is in the decision loop at
any point. The dashboard shows what happened; it does not cause it.

| Peer | Agency | Type | Note |
|------|--------|------|------|
| noaa-sensor-1, -2 | NOAA | Weather stations | |
| noaa-sensor-3 | NOAA | Weather station | compromised |
| usgs-monitor-1, -2 | USGS | Seismic monitors | |
| fema-field-1, -2 | FEMA | Field stations | |
| fema-fusion | FEMA | Fusion center | |
| epa-monitor-1 | EPA | Air quality | joins late |

## Running it

The scenario runs in-process, with no container runtime required.

```bash
# In-process. Joins a live AT mesh and streams real peer
# observations into the dashboard.
python -m examples.multi_agency
# Open http://localhost:8050

# Replay a captured run without an AT runtime (useful for demos and CI):
python -m examples.multi_agency --playback session.json

# Capture a run's scripted timeline to JSON for later replay:
python -m examples.multi_agency --record session.json
```

For the multi-node version orchestrated across containers:

```bash
./at run-demo --variant=multi-agency
```

The dashboard is a window into the network rather than a control surface. Every
trust decision on screen is made by the agents, and nothing in the interface
overrides them.

## The timeline

The scenario runs on a scripted schedule, and each phase exercises a different
part of the runtime.

| Time | Phase | What happens |
|------|-------|--------------|
| T+0:00 | Formation | NOAA, USGS, and FEMA peers discover each other and form a group. |
| T+1:00 | Bootstrap | The trust graph stabilizes as peers earn reputation past roughly 0.7. |
| T+2:00 | Negotiation | Peers negotiate data-sharing agreements for the work at hand. |
| T+2:30 | Data sharing | Weather, seismic, and air-quality streams begin flowing. |
| T+4:00 | Compromise | One NOAA sensor starts reporting falsified temperature data. |
| T+4:30 | Detection | The network flags the anomaly through cross-source validation. |
| T+5:00 | Exclusion | The reputation of that sensor collapses and it is dropped from the cohort. |
| T+6:00 | Late join | An EPA monitor joins after the exclusion. |
| T+7:00 | Integration | Full data sharing resumes among the nine remaining peers. |

The minute to watch is from T+4:00 to T+5:00. The temperature readings from the
compromised sensor diverge from the two other NOAA sensors covering the same
area. The comparison chart shows the divergence, the trust-dynamics timeline
shows its reputation falling, and by T+5:00 its edge in the trust graph turns red
and then disappears. The compromise mode is configurable between a gradual drift
and an abrupt jump, and the gradual case is the more instructive of the two,
since it is the one a threshold alarm would miss.

## Each phase is a subsystem

The timeline above maps onto the chapters that precede this one.

*Formation* is the identity subsystem, being peer discovery, admission voting,
and group formation over cryptographic identities whose private keys never leave
the node.

*Bootstrap* is the trust-tier machinery. A new peer runs a small corpus of
low-stakes transactions to earn its way up the reputation gradient before it is
trusted with real data, which is precisely the separation between building trust
and acting on it that the tier chapter describes.

*Negotiation* is the distributed task lifecycle, where peers agree which
capabilities they will provide to whom, and where the tier gate first bites.

*Detection and exclusion* are the reputation subsystem. A sustained anomaly
drives the score of the peer down through the running consensus, and a
quorum-co-signed slash floors it, which triggers tier-gated removal. The decision
is deterministic and backed by signed evidence any peer can re-verify, which is
the whole point of the attestation machinery: no peer has to take the exclusion
on anybody's word.

*The late join* exercises admission after the cohort is already running, where
the credential overlay gates entry and the degraded-connectivity fallback applies
when verification infrastructure is unreachable.

Although a person is watching the dashboard throughout, nothing in the loop waits
on that person, and nothing waits on a central authority either. That is the
claim Part II has been making, and this is it running.

## Where Part II ends

What the scenario produces, by T+7:00, is nine machines that reliably cooperate
and one that does not, with the difference established from observed conduct and
recorded in a form anybody can check.

What it does not produce is a community. There is no boundary anyone agreed to,
no record of a decision anybody made, no office anyone holds, and no way for this
cohort to persist as its members are replaced. The nine peers cannot sign an
agreement with anybody, because there is no party there to sign it. Nine machines
that trust each other are a fact about a graph.

Turning that fact into a body that can act is the subject of Part III.

## Further reading

- [`examples/multi_agency/README.md`](../examples/multi_agency/README.md): the
  walkthrough for the demo itself, the agency roster, and playback details.
- [`examples/README.md`](../examples/README.md): the full example suite, the
  scenario interface, and how to add a scenario.
- [A compromise, detected](architecture/sg2-detection-walkthrough.md): the same
  detect-and-exclude story in the mission demo, at the wire level.
- [Zero Trust integration](architecture/zta-integration.md): the credential
  overlay and the degraded-connectivity fallback the late join exercises.

---

*Next: [From cooperation to community](../../ethne/doc/concept.md)*
