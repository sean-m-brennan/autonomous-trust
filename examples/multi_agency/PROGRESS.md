# Civilian Demo Implementation Progress

Tracking implementation of the Multi-Agency Federal Data Sharing demo
from `demo-implementation-plan.md`.

## Status: All phases complete + Dockerized

---

## Decisions

- **Shared code**: moved into `autonomous_trust.inspector` (dashboard) and `autonomous_trust.simulator` (scenario, generators, compromise, playback, deployment)
- **Architecture**: Higher-level orchestrator driving simulator + inspector + services (option c)
- **Dashboard**: Extend existing inspector dashboard with demo-specific panels (option a)
- **Playback**: Canned JSON playback included in initial implementation
- **Deployment**: Docker Compose first; document K8s limitations as they arise
- **Geography**: Southeast US hurricane-prone area (coastal NC — Wilmington/Outer Banks region)
- **Compromise mode**: Configurable — both gradual drift and abrupt deviation supported

---

## Phase 0: Design & Clarification
- [x] Read demo-implementation-plan.md
- [x] Read dod-demo-implementation-plan.md (for shared patterns)
- [x] Survey existing infrastructure (simulator, inspector, services, core)
- [x] Identify reusable components across both demos
- [x] Resolve open questions with user
- [x] Finalize directory layout
- [x] Create README.md

## Phase 1: Shared Example Framework (now in inspector/simulator packages)
- [x] `scenario.py` — Base scenario engine (phases, timed events, peer lifecycle)
- [x] `generators.py` — Base data generator classes (sensor readings with noise/drift)
- [x] `compromise.py` — Compromise behavior modules (gradual drift, abrupt deviation)
- [x] `playback.py` — Event recorder and canned playback engine
- [x] `deployment.py` — Docker Compose generation helpers
- [ ] Dashboard extensions to inspector (trust timeline phase markers, event log)

## Phase 2: Civilian Scenario (`examples/multi_agency/`)
- [x] `scenario.py` — 10-peer disaster response scenario definition
- [x] `generators/weather.py` — NOAA weather data (temp, wind, pressure, precip)
- [x] `generators/seismic.py` — USGS seismic data (magnitude, ground velocity)
- [x] `generators/airquality.py` — EPA air quality (AQI, PM2.5, ozone)
- [x] `compromise/falsified_sensor.py` — Compromised NOAA sensor (gradual + abrupt)
- [x] `tasks/data_sharing.py` — Weather/seismic/AQ stream task definitions
- [x] `tasks/fusion.py` — FEMA cross-source fusion task
- [x] `tasks/validation.py` — Cross-source validation with anomaly detection

## Phase 3: Dashboard Customization
- [x] Agency map config (Mapbox satellite, agency color coding, center on Wilmington NC)
- [x] Trust dynamics timeline (per-peer reputation lines, phase markers, threshold line)
- [x] Sensor comparison chart (multi-peer overlay, consensus band, anomaly shading)
- [x] Data streams panel (active feeds table with quality indicators)
- [x] Peer detail drawer (identity, reputation, state, network, streams)
- [x] Event log (color-coded, time-stamped, icon-tagged, scrollable HTML)
- [x] Civilian dashboard config (civilian_app.py ties components to scenario)

## Phase 4: Playback & Deployment
- [x] Play/pause, speed (1x-10x), phase jump controls (`common/dashboard/playback_controls.py`)
- [x] Progress bar with phase markers (overlaid dots + seek bar)
- [x] Canned playback (already in `common/playback.py` — EventRecorder + PlaybackEngine)
- [x] Docker Compose deployment (`deploy/docker-compose.yml` — 12 services)
- [x] `deploy/run-demo.sh` orchestration (build, config gen, playback mode, timeline display)
- [x] Docker limitation documented: EPA delayed join uses env var, not native delayed-start
- [x] `deploy/Dockerfile` layers on `autonomous-trust-full-devel` base
- [x] `participant.py` — AT node inheriting `AutonomousTrust`, registers workers
- [x] `coordinator.py` — AT coordinator with cohort tracking, reputation monitoring
- [x] `simulator/generate_scenario.py` — generates scenario.yaml from Python definition
- [x] docker-compose.yml uses AT entrypoint pattern (AUTONOMOUS_TRUST_EXE + conda env)
- [x] run-demo.sh builds full image chain (base → full → demo) automatically
- [x] GeoPosition fallback: works without AT packages installed (config gen, tests)

## Phase 5: Polish & Presentation Mode
- [x] Full-screen optimized layout (`civilian/dashboard/presentation.py`)
- [x] Narration overlays per phase (`common/dashboard/narration.py` + `narration_script.py`)
- [x] Dark theme, professional aesthetic (CSS grid layout, plotly_dark, #0F172A bg)
- [x] Agency legend in title bar
- [x] Static preview rendering for development

## Phase 6: Testing & Verification
- [x] Scenario definition: 9 peers, 9 phases, correct structure (6 checks)
- [x] Scenario advancement: peer join, compromise, exclusion, EPA onboard (8 checks)
- [x] Weather generators: 4 data types, reasonable ranges, declining pressure (3 checks)
- [x] Seismic generators: magnitude + ground velocity (1 check)
- [x] Air quality generators: AQI + PM2.5 + ozone (1 check)
- [x] Gradual compromise: drift increases over time (3 checks)
- [x] Abrupt compromise: immediate +15C offset (2 checks)
- [x] Cross-source validation: detects anomalous sensor (3 checks)
- [x] Playback: record → replay roundtrip with seek (4 checks)
- [x] Task definitions: 3 tasks serialize correctly (4 checks)
- **Total: 35 checks, 0 failures**

---

## Docker Limitations (to document for K8s migration)
- **No native delayed-start**: EPA peer joins at T+6:00 but Docker Compose
  starts all containers immediately.  Workaround: `AT_JOIN_DELAY_SEC` env var
  makes the peer sleep before connecting.  K8s could use a Job or CronJob.
- **No per-link bandwidth shaping**: All peers on a flat bridge network.
  K8s CNI plugins (e.g. Cilium) can enforce per-link QoS.
- **No native failure injection**: Compromised sensor is behavior-simulated,
  not container-level.  K8s can evict pods or apply NetworkPolicies.
- **Single-host only**: All 12 containers share one machine.  K8s distributes
  across nodes for realistic latency.

---

## Directory Layout

```
examples/
  common/                     # Shared framework for all demos
    __init__.py
    scenario.py               # Base scenario engine (phases, events, peer lifecycle)
    generators.py             # Base data generator classes
    compromise.py             # Compromise behavior modules (drift, abrupt, sybil)
    playback.py               # Event recording and canned playback
    deployment.py             # Docker Compose generation helpers
  civilian/                   # Multi-Agency Federal Data Sharing demo
    README.md
    PROGRESS.md               # This file
    scenario.py               # 10-peer disaster response scenario
    generators/
      __init__.py
      weather.py              # NOAA weather data
      seismic.py              # USGS seismic data
      airquality.py           # EPA air quality data
    compromise/
      __init__.py
      falsified_sensor.py     # Compromised NOAA sensor
    tasks/
      __init__.py
      data_sharing.py         # Stream tasks
      fusion.py               # FEMA fusion task
      validation.py           # Cross-source validation
    deploy/
      docker-compose.yml
      run-demo.sh
  zta/                        # (existing) ZTA DDIL demo
  demo/                       # (existing) Fleet update demo
```
