# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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
import json
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
                   help="Open frozen; click Resume in the dashboard to start.")
    p.add_argument("--no-auto-pause", action="store_true",
                   help="Disable the automatic freeze right before the first "
                        "narration block (default: auto-pause so the operator "
                        "starts the narrative on cue with Resume).")
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
    from autonomous_trust.inspector.dashboard.narration import (
        resolve_narration,
    )

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

    # Event-anchor the narration to THIS recording: the script's trust/threat
    # beats carry cue anchors (see narration_script) that we re-time to when
    # the events actually fired, so the narrative tracks the emergent timeline
    # rather than an idealised schedule.
    try:
        with open(args.playback) as _f:
            _recording = json.load(_f)
    except Exception:
        logger.exception("Could not re-read recording for narration anchoring")
        _recording = None
    # Cohort for the "reputation has stabilized above 0.7" beat: the ISR
    # producers (microdrones + RQ-86 recon) whose scored data earns them a
    # rising consensus — those are the curves that visibly level off. The
    # squad is consumer-only (seeded/flat, not "rising"), and command is a
    # remote gateway, so neither belongs to the "curves leveling" cohort.
    # The cue falls back to its authored time if any member never crosses.
    _cohort = [
        p.name for p in scenario.peers.values()
        if p.kind in ("microdrone", "recon-drone")
    ]
    # Pace the cards so each stays readable and the screen is never blank
    # mid-narrative: every card holds until the next beat (persist-until-next),
    # with a min_dwell floor so a cascade of cues right after a late detection
    # doesn't flash by. min_dwell is in scenario seconds and the overlay
    # advances on scenario time, so at >1x a scenario-second is less wall-clock
    # time — scale by speed to keep the on-screen time ~constant (~16 s/card at
    # 1x). No max_dwell: during a long wait for an emergent beat (e.g. a late
    # MQ-800 divergence) the preceding context card holds rather than blanking;
    # a clean re-record shrinks those gaps so the holds stay short.
    _wall_dwell = 16.0
    narration = resolve_narration(
        DOD_NARRATION, _recording, cohort=_cohort,
        min_dwell=_wall_dwell * args.speed)

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
        # Re-arm the gated jet strike from the recorded rogue anomaly (the
        # src="validator" COMPROMISE_DETECT — the same reliable signal the
        # live coordinator gates on, and present in every recording), so
        # playback holds the jet off-map until the anomaly replays. First
        # (rogue) hit wins; gate_jet_on_anomaly ignores non-rogue peers and
        # the scripted (sourceless) detect.
        try:
            if (rec.get("type") == "COMPROMISE_DETECT"
                    and (rec.get("data") or {}).get("source") == "validator"):
                scenario.gate_jet_on_anomaly(
                    rec.get("peer"), float(rec.get("t", 0.0)))
        except Exception:
            logger.exception("Failed to gate jet from replayed anomaly")

    iface.register_event_log_handler(_on_event_record)

    # Snapshot stream — populates the trust timeline + sensor charts
    # from the recording sidecar. The dispatcher is intentionally
    # minimal; unknown snapshot types are silently ignored so old
    # recordings stay compatible.
    from datetime import timedelta as _td
    from autonomous_trust.services.data import Reading

    # Derived dashboard state accumulated as snapshots fire. A live run
    # gets these from the coordinator's _push_dashboard_update; in
    # playback there is no AT mesh, so we rebuild them here so the
    # Reputations panel and the peer-detail drawer animate instead of
    # sitting empty. Positions/agencies/kinds are reconstructed from the
    # (deterministic, seeded) scenario in state_provider, not from these.
    _rep_by_peer: dict[str, float] = {}
    _tier_by_peer: dict[str, int] = {}
    _detection_per_target: dict[tuple, dict] = {}
    _detection_log_per_peer: dict[str, list] = {}
    # Mirrors coordinator.DoDMissionCoordinator.DETECTION_* so the drawer
    # shows the same primary detection (the MQ-800 compound-alpha lie wins
    # the per-peer slot) and the log stays bounded.
    _DETECTION_PRIORITY_UIDS = ("compound-alpha", "compound-bravo")
    _DETECTION_LOG_CAP = 10

    def _on_snapshot(snap, _t):
        kind = snap.get("type")
        if kind == "REPUTATION_SAMPLE":
            peer = str(snap.get("peer", ""))
            try:
                _rep_by_peer[peer] = float(snap.get("score", 0.0))
                # Recorded tier (new recordings). Old recordings lack it;
                # derive a coarse tier from the score band so the drawer
                # still reads "active" above the 0.5 trust line rather than
                # being stuck "onboarding". 0.5 is the tier-1 threshold
                # (see live_server _render_peer_drawer's bootstrap band).
                if "tier" in snap:
                    _tier_by_peer[peer] = int(snap.get("tier", 0))
                else:
                    _tier_by_peer[peer] = (
                        1 if _rep_by_peer[peer] > 0.5 else 0)
            except (TypeError, ValueError):
                logger.exception("Failed to accumulate reputation snapshot")
            try:
                live_server.feed_timeline_sample(
                    panels,
                    t_seconds=float(snap.get("t", 0.0)),
                    peer_name=peer,
                    score=float(snap.get("score", 0.0)),
                )
            except Exception:
                logger.exception("Failed to feed reputation snapshot")
        elif kind == "DETECTION":
            # Rebuild the per-(peer, uid) detection cache + per-peer log the
            # drawer reads. Mirrors coordinator._cache_detection_reading.
            try:
                peer = str(snap.get("peer", ""))
                uid = str(snap.get("world_uid", ""))
                entry = {k: v for k, v in snap.items()
                         if k not in ("type", "t")}
                entry.setdefault("peer_name", peer)
                entry["t_seconds"] = float(
                    snap.get("t_seconds", snap.get("t", 0.0)))
                _detection_per_target[(peer, uid)] = entry
                log = _detection_log_per_peer.setdefault(peer, [])
                log.append(entry)
                if len(log) > _DETECTION_LOG_CAP:
                    del log[:-_DETECTION_LOG_CAP]
            except Exception:
                logger.exception("Failed to accumulate detection snapshot")
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

    # Asset kinds surfaced as moving markers on the target-position map —
    # the same set the live coordinator feeds (soldiers, the microdrone
    # swarm, the RQ-86 recon pair, the MQ-800, the fighter jet, and the
    # leave-behind ground sensors). The playback path previously surfaced
    # only soldiers + microdrones, so the air assets never appeared.
    _ASSET_KINDS = ("soldier", "microdrone", "recon-drone",
                    "armed-drone", "fighter-jet", "ground-sensor")

    def _detection_per_peer():
        """Collapse detection_per_target to one entry per peer, preferring
        the storyline-critical UIDs then most-recent. Mirrors
        coordinator._pick_primary_detection_per_peer so the drawer shows
        the MQ-800 compound-alpha lie, not its honest reading."""
        by_peer: dict[str, list] = {}
        for (peer, _uid), entry in _detection_per_target.items():
            by_peer.setdefault(peer, []).append(entry)
        out: dict[str, dict] = {}
        for peer, entries in by_peer.items():
            for uid in _DETECTION_PRIORITY_UIDS:
                hit = next((e for e in entries
                            if e.get("world_uid") == uid), None)
                if hit is not None:
                    out[peer] = dict(hit)
                    break
            else:
                out[peer] = dict(max(
                    entries, key=lambda e: e.get("t_seconds", 0.0)))
        return out

    def _reputations_view():
        """Accumulated scores, completed with pre-established peers as
        ``None`` ("forming…") before their first sample — mirrors the
        live coordinator._reputations_view so the panel shows the full
        roster from the start instead of materialising peers one by one."""
        reps = dict(_rep_by_peer)
        for role in scenario.peers.values():
            if getattr(role, "join_phase", 0) == 0 and role.name not in reps:
                reps[role.name] = None
        return reps

    state = {"reputations": {}, "tick": 0, "t_seconds": 0.0, "phase": None}

    def state_provider():
        # Drive playback forward on each tick of the Dash 1Hz interval.
        # PlaybackInterface.tick() is a no-op when paused, so this is
        # safe to call unconditionally.
        iface.tick()
        tel = iface.telemetry()
        t_seconds = float(tel.scenario_time)
        state["tick"] = int(tel.scenario_time)
        state["t_seconds"] = t_seconds
        state["phase"] = tel.current_phase_name
        # PLAYBACK mode never calls scenario.advance_to (the recording is
        # the event source — see PlaybackEngine.tick), so the movement
        # model never runs and the squad/drones would sit frozen at T+0
        # (no asset markers move, no flight-path trails build). Drive the
        # position-only update here: _update_positions is deterministic in
        # scenario time and seeded, so it reproduces the live infil/exfil
        # path + air-asset orbits exactly without re-firing scripted events.
        try:
            scenario._update_positions(_td(seconds=t_seconds))  # noqa: SLF001
        except Exception:
            logger.exception("Failed to advance playback positions")
        state["platforms"] = {
            name: {"lat": r.position.lat, "lon": r.position.lon,
                   "alt": r.position.alt, "kind": r.kind, "color": r.color}
            for name, r in scenario.peers.items()
            if r.kind in _ASSET_KINDS
            # Hide a late joiner until it arrives, and drop the two ECM
            # microdrone casualties before exfil (DoDMissionScenario.
            # peer_active) — mirrors the live coordinator.
            and scenario.peer_active(name, t_seconds)
        }
        # Static role lookups + accumulated trust/detection state so the
        # peer-detail drawer + Reputations panel render the same
        # header/status/score/detection the live dashboard shows (both read
        # these straight off state; the live coordinator fills them in
        # _push_dashboard_update).
        state["agencies"] = {p.name: p.agency
                             for p in scenario.peers.values()}
        state["kinds"] = {p.name: p.kind
                          for p in scenario.peers.values()}
        state["reputations"] = _reputations_view()
        state["tiers"] = dict(_tier_by_peer)
        state["detection_per_peer"] = {
            peer: entry for peer, entry in _detection_per_peer().items()
            if scenario.peer_active(peer, t_seconds)
        }
        state["detection_log_per_peer"] = {
            k: list(v) for k, v in _detection_log_per_peer.items()
            if scenario.peer_active(k, t_seconds)
        }
        return state

    # The dashboard owns pause/resume: it advances the recording (via
    # state_provider -> iface.tick) only while unpaused, so the engine is left
    # playing and live_server's pause Store gates the clock. This keeps a
    # single source of truth for "is the demo running".
    iface.play()
    if args.paused:
        logger.info("Recording opens frozen — click Resume to start (%.1fx)",
                    args.speed)
    elif not args.no_auto_pause:
        logger.info("Recording will auto-pause before the narrative — click "
                    "Resume to begin (%.1fx)", args.speed)
    else:
        logger.info("Auto-playing recording at %.1fx", args.speed)

    app = live_server.make_app(
        name=_HERE_FOR_LOG,
        title=f"{scenario.name} — canned playback",
        panels=panels,
        chart_keys=["target_x_chart", "noise_chart", "trust_network"],
        state_provider=state_provider,
        narration_script=narration,
        # Canned playback is meant for presentations; default to on so
        # the user sees narration immediately.  Live mode keeps it off
        # (operator opts in via the toggle).
        presentation_default=True,
        peer_names=sorted(scenario.peers.keys()),
        # Match the live coordinator: open the Peer Detail drawer on the
        # rq86-1 gateway by default (falls back to empty if absent).
        default_peer="rq86-1",
        start_paused=args.paused,
        auto_pause_before_narration=not args.no_auto_pause,
    )
    logger.info("Serving canned playback on http://0.0.0.0:%d", args.port)
    app.run(host="0.0.0.0", port=args.port,
            debug=False, use_reloader=False)


if __name__ == "__main__":
    # Default to forkserver: 'fork' (Linux default through 3.13) forks a
    # multi-threaded process and can deadlock the child. Harmless on 3.14+.
    import multiprocessing as _mp
    _mp.set_start_method('forkserver', force=True)
    main()
