# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""Entrypoint for the DoD mission demo dashboard.

Live runs use ``coordinator.py`` inside the Docker stack
(``scripts/run-demo.sh --variant=dod-mission``).  This entrypoint is the
counterpart for **canned playback** — replays a recorded scenario
event log without bringing up containers, so a presentation laptop
that has the AT Python packages installed can show the same dashboard
the live demo produces.

Usage::

    python -m examples.dod_mission --playback RECORDING.json [--port 8050]
                                   [--speed 1.0|2.0|5.0|10.0]
                                   [--squad-size 4] [--swarm-size 4]
                                   [--sensor-count 3] [--hacked-sensors 2]

The recording must have been captured by a live coordinator run with
``--record FILE`` (see ``coordinator.py``).  Recordings carry their own
scenario shape under ``payload["scenario"]``; the scaling knobs above
let you reconstruct the matching ``DoDMissionScenario`` for the
dashboard panels.  Use the same knobs that the live run used.

Recordings now carry a sidecar ``snapshots`` stream of reputation
samples (one per coordinator reputation poll, ~30 s apart per peer)
and sensor readings (every reading the coordinator validators see,
modulo ``AT_RECORDING_READING_STRIDE``).  Playback replays both: the
trust timeline and sensor charts populate in time order alongside
the scripted scenario events.
"""

from __future__ import annotations

import argparse
import logging
import sys


_HERE_FOR_LOG = "examples.dod_mission"


def _parse_args(argv):
    p = argparse.ArgumentParser(
        prog="python -m examples.dod_mission",
        description="DoD squad infiltration dashboard — canned playback.",
    )
    p.add_argument("--playback", metavar="FILE", required=True,
                   help="Recorded scenario event-log JSON (produced by "
                        "coordinator.py --record).")
    p.add_argument("--port", type=int, default=8050,
                   help="Port to serve the Dash app on (default: 8050).")
    p.add_argument("--speed", type=float, default=1.0,
                   choices=(1.0, 2.0, 5.0, 10.0),
                   help="Playback speed multiplier (default: 1.0).")
    p.add_argument("--paused", action="store_true",
                   help="Start paused (default: auto-play on launch).")
    p.add_argument("--squad-size", type=int, default=4)
    p.add_argument("--swarm-size", type=int, default=4)
    p.add_argument("--sensor-count", type=int, default=3)
    p.add_argument("--hacked-sensors", type=int, default=2)
    p.add_argument("--no-mq800", action="store_true")
    p.add_argument("--no-jet", action="store_true")
    p.add_argument("--no-command", action="store_true")
    p.add_argument("--log-level", default="info",
                   choices=("debug", "info", "warning", "error"))
    return p.parse_args(argv)


def main(argv=None):
    args = _parse_args(argv if argv is not None else sys.argv[1:])

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logger = logging.getLogger(_HERE_FOR_LOG)

    # Lazy imports: Dash/plotly are heavy and we want --help to be cheap.
    from autonomous_trust.evaluation.scenarios.playback_iface import (
        PlaybackInterface,
    )

    from .scenario import DoDMissionScenario
    from .dashboard.dod_app import build_dashboard
    from .dashboard import live_server
    from .dashboard.narration_script import DOD_NARRATION

    scenario = DoDMissionScenario(
        squad_size=args.squad_size,
        swarm_size=args.swarm_size,
        sensor_count=args.sensor_count,
        hacked_sensors=args.hacked_sensors,
        include_mq800=not args.no_mq800,
        include_jet=not args.no_jet,
        include_command=not args.no_command,
    )

    iface = PlaybackInterface(scenario, playback_file=args.playback)
    iface.set_speed(args.speed)

    panels = build_dashboard(scenario)

    # PlaybackInterface fires both register_scenario_event_handler and
    # register_event_log_handler for every replayed event (Scenario._apply_event
    # calls _emit, which both fires scenario.on_event listeners AND appends to
    # scenario._event_log).  Subscribe only to the dict path — it handles
    # scripted ScenarioEvents and dict-shaped records (anomalies) uniformly
    # without producing duplicate event-log entries.
    def _on_event_record(rec):
        try:
            panels["event_log"].add_from_event_record(rec)
        except Exception:
            logger.exception("Failed to render event record")

    iface.register_event_log_handler(_on_event_record)

    # Snapshot stream — populates the trust timeline + sensor charts
    # from the recording sidecar. The dispatcher is intentionally
    # minimal; unknown snapshot types are silently ignored so old
    # recordings stay compatible.
    from datetime import timedelta as _td
    from autonomous_trust.services.data import Reading

    def _on_snapshot(snap, _t):
        kind = snap.get("type")
        if kind == "REPUTATION_SAMPLE":
            try:
                live_server.feed_timeline_sample(
                    panels,
                    t_seconds=float(snap.get("t", 0.0)),
                    peer_name=str(snap.get("peer", "")),
                    score=float(snap.get("score", 0.0)),
                )
            except Exception:
                logger.exception("Failed to feed reputation snapshot")
        elif kind == "SENSOR_READING":
            try:
                reading = Reading(
                    timestamp=_td(seconds=float(snap.get("t", 0.0))),
                    peer_name=str(snap.get("peer", "")),
                    data_type=str(snap.get("data_type", "")),
                    value=float(snap.get("value", 0.0)),
                    unit=str(snap.get("unit", "")),
                    quality=float(snap.get("quality", 1.0)),
                    metadata=dict(snap.get("metadata") or {}),
                )
            except Exception:
                logger.exception("Failed to reconstruct reading snapshot")
                return
            for chart_key in ("target_x_chart", "noise_chart"):
                try:
                    panels[chart_key].add_reading(reading)
                except Exception:
                    logger.exception(
                        "Failed to feed reading snapshot to %s", chart_key)

    iface.register_snapshot_handler(_on_snapshot)

    state = {"reputations": {}, "tick": 0, "t_seconds": 0.0, "phase": None}

    def state_provider():
        # Drive playback forward on each tick of the Dash 1Hz interval.
        # PlaybackInterface.tick() is a no-op when paused, so this is
        # safe to call unconditionally.
        iface.tick()
        tel = iface.telemetry()
        state["tick"] = int(tel.scenario_time)
        state["t_seconds"] = float(tel.scenario_time)
        state["phase"] = tel.current_phase_name
        # Playback advances the scenario (playback_engine calls
        # scenario.advance_to), so the squad/microdrone positions move
        # too — surface them for the target-position map's asset markers.
        state["platforms"] = {
            name: {"lat": r.position.lat, "lon": r.position.lon,
                   "alt": r.position.alt, "kind": r.kind, "color": r.color}
            for name, r in scenario.peers.items()
            if r.kind in ("soldier", "microdrone")
        }
        return state

    if not args.paused:
        iface.play()
        logger.info("Auto-playing recording at %.1fx", args.speed)
    else:
        logger.info("Recording loaded paused — use the Dash UI to start")

    app = live_server.make_app(
        name=_HERE_FOR_LOG,
        title=f"{scenario.name} — canned playback",
        panels=panels,
        chart_keys=["target_x_chart", "noise_chart"],
        state_provider=state_provider,
        narration_script=DOD_NARRATION,
        # Canned playback is meant for presentations; default to on so
        # the user sees narration immediately.  Live mode keeps it off
        # (operator opts in via the toggle).
        presentation_default=True,
    )
    logger.info("Serving canned playback on http://0.0.0.0:%d", args.port)
    app.run(host="0.0.0.0", port=args.port,
            debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
