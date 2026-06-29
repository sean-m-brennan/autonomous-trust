# AutonomousTrust Behaviour

The in-built **behavioral-anomaly layer** for AutonomousTrust (SOW Task 3 /
objective **O3**). It runs on each AT node, learns a behavioral *envelope* per
peer×role from the access stream, and feeds the existing deterministic
reputation / slashing / tier-gating engine as **governed evidence**:

> **ML proposes, deterministic consensus disposes.**

The anomaly score never excludes anyone by itself. A *sustained* anomaly raises
a `SlashAttestation(reason="sustained_anomaly", evidence_ref=…)` that enters the
existing quorum-signed, Merkle-proof-gated slashing fast-path — so every
exclusion is still a deterministic, reproducible, signed consensus decision.
Safety-critical access stays human-on-the-loop (fail-safe default).

## Why these algorithms

Per the SOW (Task 3.2) and `doc/NV059/work/AIML_software_survey.md`, the layer
is built **via River/PyOD** — the mature, permissively-licensed reference
runtimes — using **streaming Half-Space Trees** (multivariate isolation, from
`river.anomaly`) plus **HBOS** (per-feature histogram, native attribution, from
`pyod.models.hbos`, made streaming via a sliding-window refit). Both are:

- **online / streaming** — incremental per-event (HBOS via window refit);
- **unsupervised** — no labeled attack data;
- **bounded-memory** — fixed footprint, safe on embedded ARM;
- **deterministic under a fixed seed** — River's HST is seed-deterministic and
  PyOD's HBOS has no randomness, so the score is reproducible enough to be
  *admissible* signed consensus evidence rather than a black box; and
- **explainable** — HBOS's per-feature density *is* the "why".

The deferred formally-verified **C core** is the "owned" reimplementation that
reproduces this prototype's scores, pinned by the existing cross-language
conformance corpus (Task 3.5).

Two **base-rate-fallacy guards** (the SOW's #1 risk) keep "ML proposes" from
becoming trigger-happy: a *sustained-anomaly* dwell state machine (a single
spike never trips an exclusion) and a calibrator **std floor** (a detector
trained on near-identical normal traffic doesn't hair-trigger on micro-noise).

## Layout

This package is split into a **pure, node-agnostic library** (the future
standalone `.so`) and a thin **host-side adapter** that wires it into a node.

```
autonomous_trust/behaviour/
  # --- pure library (no autonomous_trust.core dependency; the .so candidate) ---
  detectors/
    base.py          # AnomalyDetector interface (evaluate-then-learn)
    river_hst.py     # River Half-Space Trees adapter (multivariate isolation)
    pyod_hbos.py     # PyOD HBOS adapter, streaming via sliding-window refit
    calibrator.py    # online raw-score → [0,1] calibration (Welford+logistic+floor)
  features.py        # per-peer×role access-stream feature extraction (3.1)
  ensemble.py        # detectors + sustained-anomaly state machine + BehaviorMonitor;
                     #   emits the neutral SlashProposal on a rising-edge alarm (3.3)
  # --- host-side adapter (imports core; runtime glue, NOT ported to the .so) ---
  governor.py        # PeerBehaviourGovernor: a component a node embeds (B4)
```

## Governed path — a per-node, pluggable component

This is **not** a central node that polices the mesh. It is functionality **each
node embeds to watch its own peers**: every node runs its own monitor, so slash
proposals come from many independent observers and the existing quorum-signed
slash flow aggregates them — "ML proposes, deterministic consensus disposes".

The split is deliberate, to make the eventual **C `.so`** a clean port:

* **`BehaviorMonitor`** (library) is pure — deterministic, bounded-memory, no
  node/queue/identity/wire dependency, no I/O. A node feeds it its peers' access
  events; it routes each to a per-peer×role detector and, on the rising edge of a
  *sustained* alarm, queues a neutral **`SlashProposal`** (`peer_id`, `reason`,
  `floor`, score, per-feature attribution — the *why*). The host pulls them with
  `poll_proposals()` (pull model, no callbacks). This is the unit the Task 3.5
  conformance corpus pins: same event stream → same proposals, Python and C. The
  pinning plan — the layered determinism analysis, the quantization boundary, and
  the new `behaviour` corpus protocol — is documented in
  `doc/NV059/work/BEHAVIOUR_CONFORMANCE_PLAN.md`.
* **`PeerBehaviourGovernor`** (adapter) is the only piece that touches the trust
  machinery. A node owns one, feeds it observed peer events, and calls
  `enforce(queues)`, which translates each proposal into a real core
  `SlashAttestation(reason="sustained_anomaly")` on the reputation queue. The
  unchanged 3-phase quorum-signed flow (forward_slash → slash_propose →
  slash_sign → slash_final → reputation floor → tier_lost → negotiation
  exclusion) disposes of it. This adapter is runtime-specific glue and is **not**
  part of the `.so` — the C node reimplements an equivalent shim around the same
  library ABI (`create` / `observe` / `poll_proposals` / `reset_alarm`).

A node plugs it in by composition:

```python
class MyNode(AutonomousTrust):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.governor = PeerBehaviourGovernor(self, auto_slash=False)

    def autonomous_tasking(self, queues):
        for message in list(self.unhandled_messages):
            self.governor.ingest_message(message)   # observe this node's peers
        self.governor.enforce(queues)                # propose → slash
        self._report_unhandled()
```

Three independent guards stand between an anomaly and an exclusion: the
**sustained-anomaly dwell** state machine (a lone spike never latches), the
**co-sign quorum** (one node cannot exclude a peer alone), and
**human-on-the-loop** — the default (`auto_slash=False`) records a logged
`SlashRecommendation` for an operator; `auto_slash=True` opts into the
fully-autonomous path.

## Resilience / threat M&S (red-team suite, SOW Task 3.4)

`autonomous_trust/behaviour/redteam/` is a **deterministic, library-level** M&S
harness: a synthetic peer population spanning the threat archetypes
(compromised-credential, Byzantine, Sybil, and benign-but-disrupted **DDIL**) is
driven through the pure `BehaviorMonitor` and a static-policy baseline, scoring
detection latency, exclusion correctness, and the false-exclusion rate projected
to a realistic attack base rate (Axelsson). No node/network/docker (the
docker-based `evaluation/redteam` is the separate live-mesh integration).

```bash
python -m autonomous_trust.behaviour.redteam            # markdown report
python -m autonomous_trust.behaviour.redteam --json out.json
```

The headline result (seed 1234) is the case for a *governed* sensor: the ML
layer detects every credentialed compromise with **zero false exclusions** — so
its precision stays ~1.0 even at a 1% base rate — while a static threshold
detects a touch more but excludes *every* DDIL peer, collapsing to ~0.03
precision at that base rate (the base-rate fallacy, quantified). DDIL is the
crux: a legitimate peer made bursty/refusing by a degraded link must **not** be
excluded, and the learned per-peer envelope + dwell achieves that where a fixed
threshold cannot. Sybil is reported but is primarily an identity-layer concern.
A real finding the suite surfaced: detection *races adaptation* — too small an
HBOS window lets a slow compromise be learned as normal, so the window must be
wide enough to catch sustained abuse.

## Tests

```bash
cd src/autonomous-trust-behaviour
AUTONOMOUS_TRUST_BACKEND=python ./run-tests.sh
```

The detector tests pin the load-bearing property — **determinism** (identical
seed + stream ⇒ identical score) — alongside anomaly separation, HBOS
attribution, and warmup semantics.


### Red-team testing results

 (seed 1234, 56 peers) — the case for a governed sensor:

  
| | ML governed sensor | Static baseline |
|---|---|---|
| Compromised-credential detection | 1.00 | 1.00 |
| False-exclusion rate (FPR) | 0.00 | 0.21 |
| DDIL false-exclusion | 0.00 | 1.00 (all) |
| Precision @ base-rate 0.01 | 1.00 | 0.03 |
| Detection latency | 16.6 | 29.4 |

  The ML layer catches every credentialed compromise with zero false-exclusions, so its precision survives the
  base-rate fallacy; the static baseline detects a touch more but excludes every DDIL peer and collapses to
  3% precision at a realistic base rate. M5 exit criteria satisfied: compromised-but-credentialed asset
  detected + governably excluded, false-exclusion rate reported against realistic base rates, deterministic
  under fixed seed.

  Honest findings reported, not hidden: Sybil detection is 0.0 (it's an identity-layer concern, not
  behavioural); and the suite surfaced that detection races adaptation — too small an HBOS window lets a slow
  compromise be learned as normal, so the window must be wide enough (the harness uses 200, closer to the
  prototype's real default than the unit-test 120).

  Tests: 70 pass (was 51), 98% coverage — a fast pure-math unit test (test_redteam_metrics.py, pins the
  Axelsson formula) plus a harness-driven M5/discipline/base-rate integration test (test_redteam.py). README
  and memory updated. All uncommitted on feature/dod-demo.