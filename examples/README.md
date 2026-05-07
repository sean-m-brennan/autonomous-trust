# AutonomousTrust Examples

Worked scenarios that exercise the AutonomousTrust runtime, each
demonstrating a different deployment shape.

| Directory | Shape | Source |
|---|---|---|
| `mission/` | DoD ISR / strike-team coordination; TCP-simulator-driven physics | `autonomous_trust.simulator` ⟶ `SimulationInterface` |
| `multi_agency/` | Civilian disaster-response (NOAA / USGS / FEMA / EPA) | in-process `PlaybackEngine` + live AT bridge ⟶ `PlaybackInterface` |
| `appalachia/`, `asteroid_belt/` | Compose-only sample topologies | scenario YAML |
| `monitor/`, `requestor/` | Single-node smoke utilities | — |
| `zta/` | Zero-trust enrollment + OCSP demo | docker-compose only |
| `demo/` | Misc one-off demos | — |
| `run_example.py`, `validate_configs.py` | Runners shared by the python examples | — |

The remainder of this document covers **adding a new scenario** that
shares the dashboard infrastructure used by `mission/` and
`multi_agency/`.

---

## Scenario architecture

A scenario is anything that produces state over time and can be ticked
by a Dash UI. The shared abstraction is `ScenarioInterface`
(`autonomous_trust.evaluation.scenarios.scenario_iface`), an ABC that
both built-in sources implement:

```
                   ScenarioInterface (ABC)
                         │
            ┌────────────┴────────────┐
            │                         │
   SimulationInterface          PlaybackInterface
   (TCP simulator;              (in-process engine;
    used by mission/)            used by multi_agency/)
```

The ABC's surface is small:

| Method / property | Purpose |
|---|---|
| `start()`, `stop()` | Lifecycle. Implementations may spawn threads / sockets / no-ops. |
| `tick() -> ScenarioState` | Advance one UI cadence; fires update handlers. Drives the dashboard. |
| `reset()` | Return to T+0; fires reset handlers. |
| `toggle()` | Play/pause. |
| `paused`, `current_time` | State accessors. |
| `register_update_handler(h)` | Subscribe to per-tick `ScenarioState` snapshots. |
| `register_end_handler(h)` | Subscribe to scenario-end notifications. |
| `register_reset_handler(h)` | Subscribe to reset notifications. |

`ScenarioState` is a dataclass: `time_seconds`, `playing`, `phase_idx`,
`phase_name`, `duration_seconds`, `mode`, plus a `source_specific` dict
for fields that don't fit the common shape.

---

## Pattern 1 — In-process scenario (like `multi_agency/`)

Use this when the scenario logic runs **inside** the inspector
process: scripted timeline, optional canned playback, optional live
observations from real AT peers via a bridge queue.

### 1. Define a scenario class

Subclass
`autonomous_trust.evaluation.scenarios.scenario.Scenario`, declare the
peer roster and phase timeline. See
`src/autonomous-trust-evaluation/autonomous_trust/evaluation/scenarios/disaster_response.py`
as a worked example.

```python
# my_scenario.py
from autonomous_trust.evaluation.scenarios.scenario import (
    Scenario, Phase, PeerRole,
)

class MyScenario(Scenario):
    name = "My Scenario"
    peers = {...}     # name -> PeerRole
    phases = [...]    # list[Phase]
```

### 2. Wrap it in a `PlaybackInterface`

`PlaybackInterface` already owns the engine, the optional canned
playback file, the optional live-AT bridge queue, and the optional
event recorder. Construct it from your scenario:

```python
from autonomous_trust.evaluation.scenarios.playback_iface import (
    PlaybackInterface,
)

iface = PlaybackInterface(
    MyScenario(),
    playback_file=None,    # path to canned JSON for replay
    bridge_queue=None,     # multiprocessing queue from a live AT bridge
    record_file=None,      # path to write captured events on shutdown
)
```

### 3. Build a Dash app on top

Subscribe to the interface's event streams and render. The interface
exposes three event streams beyond the ABC's `register_update_handler`:

| Method | Fires for |
|---|---|
| `register_scenario_event_handler(h)` | engine-dispatched scenario events (PEER_JOIN, COMPROMISE_DETECT, …) |
| `register_bridge_event_handler(h)` | raw tuples drained from `bridge_queue` (live AT observations) |
| `register_event_log_handler(h)` | every new entry appended to `scenario._event_log` (scripted + bridge annotations) |
| `on_engine_event(h)` | direct passthrough to the engine's listener (e.g. `KeyStatTracker`) |

`MultiAgencyDemo` (`examples/multi_agency/demo.py`) is the reference
consumer — it owns the layout, the Dash callbacks, and all UI-derived
state (timeline samples, sensor history, streams panel), and registers
handlers on the interface for everything else.

### 4. Wire it into a CLI

A scenario lives entirely under `examples/<name>/`; its `__main__.py`
is the entrypoint. Run with `python -m examples.<name> [args...]`.

The pattern: parse args, construct the bridge (if live mode needs
one), construct the `ScenarioInterface`, hand it to the demo class.
See `examples/multi_agency/__main__.py` as a worked example.

### 5. Generalizing the AT bridge

If your scenario uses a custom set of streaming capabilities,
`InspectorBridge` (in
`src/autonomous-trust-inspector/autonomous_trust/inspector/bridge.py`)
takes a `cap_to_proc: dict[str, str]` map at construction. The
multi-agency demo's specific map lives in `examples/multi_agency/bridge.py`;
copy that pattern with your own capability names.

---

## Pattern 2 — TCP-simulator-driven scenario (like `mission/`)

Use this when scenario state is computed by an external simulator
process (`autonomous_trust.simulator`) and pushed to the dashboard
over a socket. The dashboard side uses `SimulationInterface` directly
— no new code required.

### 1. Define a simulator scenario YAML

The simulator consumes a scenario YAML describing peers, paths,
antennas, and data streams. See
`examples/mission/simulator/scenario.yaml` for a worked example. The
multi-agency demo also has a generator
(`examples/multi_agency/simulator/generate_scenario.py`) that
translates a Python `Scenario` definition into the YAML format —
useful if you want one source of truth for both patterns.

### 2. Run the simulator

```bash
python -m autonomous_trust.simulator --resolve-short-name path/to/scenario.yaml
```

### 3. Construct a coordinator that uses `MapDisplay`

```python
from autonomous_trust.core import AutonomousTrust
from autonomous_trust.inspector.peer.daq import Cohort, CohortTracker
from autonomous_trust.evaluation.dash_components.map_display import MapDisplay

class MyCoordinator(AutonomousTrust):
    def __init__(self, **kwargs):
        super().__init__(silent=True, **kwargs)
        self.cohort = Cohort(self.queue_pool)
        self.add_worker(CohortTracker, self.system_dependencies, cohort=self.cohort)
        # ... register data receivers, video, etc.
```

`MapDisplay.run()` constructs a `SimulationInterface` against
`sim_host:sim_port`, wires up `SimulationControls` + `DynamicMap`, and
serves the Dash app. See `examples/mission/coordinator/coordinator.py`
for the full pattern.

### 4. Compose / k8s manifests

`mission/configure_compose.py` generates the per-peer compose
services. For an analogous flow against in-process scenarios, see
`autonomous_trust.evaluation.scenarios.disaster_response_compose`.

---

## Pattern 3 — Custom source

If neither pattern fits (e.g. WebSocket replay, gRPC stream, file
tailer), implement `ScenarioInterface` directly. Required:

- `start()`, `stop()` — lifecycle
- `tick() -> ScenarioState` — fire `_fire_update(state)` and return the snapshot
- `reset()` — fire `_fire_reset()` after rewinding internal state
- `toggle()` — flip play/pause
- `paused`, `current_time` — state accessors

Call `super().__init__()` so the ABC's handler lists are initialized.
Once your subclass is in place, any Dash app written against
`ScenarioInterface` (rather than a concrete subclass) will accept it.

---

## See also

- `src/autonomous-trust-evaluation/autonomous_trust/evaluation/scenarios/scenario_iface.py` — the ABC and `ScenarioState`
- `src/autonomous-trust-evaluation/autonomous_trust/evaluation/scenarios/playback_iface.py` — in-process implementation
- `src/autonomous-trust-evaluation/autonomous_trust/evaluation/dash_components/sim_iface.py` — TCP-simulator implementation
- `src/autonomous-trust-inspector/autonomous_trust/inspector/bridge.py` — generic AT-mesh bridge (`InspectorBridge`)
- `examples/multi_agency/{demo,bridge,__main__}.py` — full reference of an in-process demo
- `examples/multi_agency/README.md` — multi-agency demo walkthrough
- `examples/mission/conops.md` — the mission scenario's concept of operations
