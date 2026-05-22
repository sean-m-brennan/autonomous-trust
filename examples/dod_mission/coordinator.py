# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#  Licensed under the Apache License, Version 2.0
# ******************
"""DoD mission demo coordinator / inspector node.

Aggregates ISR data from all participants, runs the dashboard with
DoD-specific panels (tactical map, trust timeline, event log,
active-tasks panel), runs the cross-source validators that catch the
MQ-800's contradictory ISR, and records scenario events for canned
replay.

Modeled on examples/multi_agency/coordinator.py.  Differs in:
  (a) loads `DoDMissionScenario` rather than `DisasterResponseScenario`
  (b) instantiates the DoD position + electronic-noise validators
  (c) selects compromise mode from `AT_COMPROMISE_MODE` env var so the
      same image can run with either gradual or abrupt MQ-800 deviation
      without rebuilding.

Usage:
    python coordinator.py [--setup] [--log-level debug]
                          [--record FILE] [--compromise-mode gradual|abrupt]
"""

from __future__ import annotations

import logging
import os
import queue
import sys
from datetime import timedelta
from pathlib import Path

from autonomous_trust.core import (
    AutonomousTrust, CfgIds, Configuration, LogLevel, to_yaml_string,
)
from autonomous_trust.core.network import Message
from autonomous_trust.core.reputation.protocol import ReputationProtocol
from autonomous_trust.core.reputation.reputation import TransactionScore
from autonomous_trust.services.data import Reading
from autonomous_trust.core.config.generate import (
    generate_identity, generate_worker_config,
)
from autonomous_trust.core.system import now, queue_cadence
from autonomous_trust.evaluation.scenarios.recording import EventRecorder

try:
    from autonomous_trust.inspector.peer.daq import Cohort, CohortTracker
    HAS_INSPECTOR = True
except ImportError as _exc:
    # WHY stderr instead of logger: this runs at module-import time,
    # before the per-module logger below has been configured (and
    # before AT's logging setup runs). A bare ImportError swallow here
    # produces no signal at all — the coordinator silently degrades
    # `_drain_peer_readings` to a no-op, no readings flow, no
    # TransactionScores are submitted, and the coordinator never
    # appears as a paxos proposer. Surfacing the actual exception is
    # the fastest path to diagnosis next time this fires.
    print(
        f"[dod_mission.coordinator] HAS_INSPECTOR=False — "
        f"autonomous_trust.inspector.peer.daq import failed: "
        f"{type(_exc).__name__}: {_exc}",
        file=sys.stderr, flush=True,
    )
    HAS_INSPECTOR = False

try:
    from autonomous_trust.core import Process, ProcMeta
    from autonomous_trust.services.data.client import DataRcvr
    HAS_DATA = True

    from queue import Empty as _DQ_Empty
    from autonomous_trust.core import CfgIds as _DQ_CfgIds, from_yaml_string as _DQ_from_yaml_string
    from autonomous_trust.core.network import Message as _DQ_Message
    from autonomous_trust.services.data.server import (  # noqa
        DataProcess as _DQ_DataProcess, DataProtocol as _DQ_DataProtocol,
    )

    class DiagDataRcvr(DataRcvr, metaclass=ProcMeta,
                       proc_name='data-sink',
                       description='Data sink (with traceback surfacing)'):
        """DataRcvr wrapper that (a) prints tracebacks to stderr and
        (b) overrides ``process()`` to fix an upstream type bug.

        AT's ``DataRcvr.process`` (services/data/client.py:54) builds
        ``Message(..., to_whom=peer)`` where ``peer`` comes from
        ``peer_capabilities[cap_name]``.  But ``PeerCapabilities``
        stores **peer ids** (UUID strings, per ``sync_from_message``),
        not ``Identity`` objects, and ``Message.__init__`` insists on
        Identity.  Result: the worker crashes on the first peer
        discovery and AT's ``_handle_results`` logs
        ``unexpected termination of process data-sink`` every tick
        thereafter.  This override resolves uuid → Identity via
        ``protocol.peers.find_by_uuid`` before constructing the
        subscribe message.

        Also overrides ``handle_data`` to push received payloads onto
        a coordinator-owned drain queue rather than into
        ``self.cohort.peers[uuid].data_stream``.  AT's queue_pool
        assigns mp.Queue slots inside ``Cohort.update_group``, which
        runs per-process; CohortTracker (one worker), DataRcvr (this
        worker), and the coordinator main proc each maintain their
        own forked ``Cohort`` instance.  Worker subprocs assigning
        ``peer.data_stream = queue_pool.next()`` in any local order
        means the queue object the worker writes to is NOT the queue
        object the main proc reads from — payloads vanish.  A single
        shared mp.Queue (created in the main proc, passed via
        ``add_worker(..., reading_drain=...)``) sidesteps the
        per-process cohort indirection entirely.
        """

        def __init__(self, configurations, subsystems, log_queue,
                     dependencies, **kwargs):
            # Pop reading_drain before super().__init__ so DataRcvr's
            # kwargs['cohort'] access still succeeds and we don't leak
            # the extra kwarg into the Protocol base class.
            self.reading_drain = kwargs.pop('reading_drain', None)
            super().__init__(configurations, subsystems, log_queue,
                             dependencies, **kwargs)

        def handle_data(self, _queues, message):
            if message.function != _DQ_DataProtocol.data:
                return False
            uuid_str = None
            try:
                uuid_str = str(message.from_whom.uuid)
                data = _DQ_from_yaml_string(message.obj)
            except Exception:
                self.logger.exception(
                    "DiagDataRcvr.handle_data: failed to decode payload")
                return True
            if self.reading_drain is None:
                # Fallback: keep the legacy per-peer cohort path so
                # we don't silently lose data if reading_drain wasn't
                # wired up.
                return super().handle_data(_queues, message)
            try:
                self.reading_drain.put(
                    (uuid_str, data),
                    block=True, timeout=self.q_cadence)
            except Exception:
                self.logger.warning(
                    "DiagDataRcvr.handle_data: drain put failed for %s",
                    uuid_str, exc_info=True)
            return True

        def process(self, queues, signal):
            import traceback as _tb
            try:
                self._patched_process(queues, signal)
            except BaseException:
                sys.stderr.write(
                    "DiagDataRcvr.process crashed:\n" + _tb.format_exc())
                sys.stderr.flush()
                raise

        def _patched_process(self, queues, signal):
            cap = _DQ_DataProcess.capability_name
            while self.keep_running(signal):
                # Subscribe to any newly-advertised data sources.
                if cap in self.protocol.peer_capabilities:
                    for ref in self.protocol.peer_capabilities[cap]:
                        ident = self._resolve_identity(ref)
                        if ident is None or ident in self.servicers:
                            continue
                        self.servicers.append(ident)
                        msg = _DQ_Message(
                            _DQ_DataProcess.name,
                            _DQ_DataProtocol.request,
                            self.name, ident)
                        queues[_DQ_CfgIds.network].put(
                            msg, block=True, timeout=self.q_cadence)
                        self.logger.info(
                            "DiagDataRcvr: subscribed to %s",
                            getattr(ident, "nickname", ident))

                # Drain inbound messages (the data payloads).
                try:
                    message = queues[self.name].get(
                        block=True, timeout=self.q_cadence)
                except _DQ_Empty:
                    message = None
                if message is None:
                    continue
                if not self.protocol.run_message_handlers(queues, message):
                    if hasattr(message, "function"):
                        self.logger.error(
                            "Unhandled message %s", message.function)
                    else:
                        self.logger.error(
                            "Unhandled message of type %s",
                            type(message).__name__)

        def _resolve_identity(self, ref):
            """Accept Identity, UUID, or uuid-string; return Identity
            or None when the lookup fails (peer hasn't been added to
            the local roster yet).

            ``Peers.find_by_uuid`` does ``uuid in {p.uuid: p ...}`` —
            a strict equality check.  Depending on how the local
            roster was populated, ``p.uuid`` may be a ``uuid.UUID``
            instance or a string, and ``peer_capabilities`` may
            likewise store either type.  We try the ref as-is,
            then ``str(ref)``, then ``UUID(str(ref))``, then a
            last-ditch linear scan over ``protocol.peers.all``
            comparing ``str(p.uuid) == str(ref)``.
            """
            if hasattr(ref, "uuid") and hasattr(ref, "address"):
                return ref  # already an Identity

            import uuid as _uuid_mod
            raw = getattr(ref, "uuid", ref)
            candidates = [raw, str(raw)]
            try:
                candidates.append(_uuid_mod.UUID(str(raw)))
            except (ValueError, AttributeError, TypeError):
                pass

            for cand in candidates:
                try:
                    hit = self.protocol.peers.find_by_uuid(cand)
                except Exception:
                    hit = None
                if hit is not None:
                    return hit

            try:
                target = str(raw)
                for p in self.protocol.peers.all:
                    if str(getattr(p, "uuid", None)) == target:
                        return p
            except Exception:
                pass
            return None
except ImportError as _exc:
    # See HAS_INSPECTOR rationale above — silent degradation here means
    # the coordinator runs without DiagDataRcvr's uuid→Identity fix and
    # AT's data-sink process crashes silently every tick.
    print(
        f"[dod_mission.coordinator] HAS_DATA=False — "
        f"autonomous_trust.services.data.* import failed: "
        f"{type(_exc).__name__}: {_exc}",
        file=sys.stderr, flush=True,
    )
    HAS_DATA = False

# Sibling-module imports.  Entrypoint.sh runs this script by file
# path (`python3 examples/dod_mission/coordinator.py`), so front-load
# _HERE on sys.path to make bare `from scenario import ...` resolve
# regardless of how the script was invoked.
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
from scenario import DoDMissionScenario  # noqa: E402
from dashboard.dod_app import build_dashboard  # noqa: E402
from dashboard import live_server  # noqa: E402
from dashboard.narration_script import DOD_NARRATION  # noqa: E402
sys.path.insert(0, str(_HERE / "tasks"))
from validation import (  # noqa: E402
    POSITION_VALIDATOR_X, POSITION_VALIDATOR_Y, ELECTRONIC_NOISE_VALIDATOR,
    ALL_VALIDATORS,
)

logger = logging.getLogger(__name__)


def _ts_keep(batch_id: str, denom: int) -> bool:
    """Deterministic per-batch decimation for TS submission.

    MUST stay in lockstep with
    examples/dod_mission/participant.py:_ts_keep — both sides call
    it on the same batch_id and AT_TS_DECIMATION, so they agree on
    which batches form bilateral Transactions
    (reputation.py:209 requires both p1 and p2 before a
    Transaction enters the chain).
    """
    if denom <= 1:
        return True
    return int(batch_id.replace('-', '')[:8], 16) % denom == 0


def _reading_from_dict(d: dict) -> Reading:
    """Reconstruct a Reading from the dict shape that
    ``Reading.to_dict()`` emits (and that DoDDataProcess ships over
    the wire)."""
    return Reading(
        timestamp=timedelta(seconds=float(d["t"])),
        peer_name=str(d["peer"]),
        data_type=str(d["type"]),
        value=float(d["value"]),
        unit=str(d.get("unit", "")),
        quality=float(d.get("quality", 1.0)),
        metadata=d.get("metadata") or {},
    )


class DoDMissionCoordinator(AutonomousTrust):
    """Coordinator node for the DoD squad infiltration demo.

    Extends AutonomousTrust with:
      - Peer cohort tracking (for dashboard population)
      - Reputation monitoring (for trust timeline)
      - Cross-source ISR validation (catches MQ-800 contradictory data)
      - Scenario event recording (for canned playback)
    """

    def __init__(self, scenario: DoDMissionScenario,
                 record_path: str | None = None,
                 compromise_mode: str = "abrupt",
                 dashboard_port: int = 8050,
                 **kwargs):
        self.scenario = scenario
        self._record_path = record_path
        self._event_recorder: EventRecorder | None = (
            EventRecorder() if record_path else None)
        self._compromise_mode = compromise_mode
        self._dashboard_port = dashboard_port
        self._reputation_cache: dict[str, float] = {}
        self._anomaly_log: list[dict] = []
        self._tick_count = 0
        self._latest_state: dict = {
            "reputations": {},
            # Parallel to `reputations`: nickname -> peer._tier int. Fed
            # by _push_dashboard_update from self.peers.all. The
            # reputations panel renders these alongside the score; see
            # dashboard/live_server.py:_render_reputations.
            "tiers": {},
            "tick": 0, "phase": None,
        }
        # nickname -> tier int (so _render_reputations can show both)
        self._tier_cache: dict[str, int] = {}
        self.data_queue: queue.Queue = queue.Queue()
        # Per-batch state for sender-scoring.  batch_id (uuid str) →
        # {'submitted': bool, 'anomalous': bool, 'first_tick': int}.
        # We submit a TransactionScore as soon as a few ticks have
        # passed since the batch's first sighting so all readings in
        # the batch have arrived; downgrading after submission isn't
        # supported (paxos rounds are one-shot per task_id).
        self._batch_state: dict[str, dict] = {}
        # Ticks of grace after first-sighting before submitting.  At
        # 500ms cadence, 4 ticks = 2 seconds — well over the
        # generator's 1 Hz emit interval.
        self._batch_settle_ticks = 4
        # Deterministic per-batch decimation for TS submission.
        # MUST match the sender's filter in
        # examples/dod_mission/participant.py:_ts_keep so both
        # sides pick the same batches — otherwise bilateral
        # pairing never forms (reputation.py:209 requires both
        # p1 and p2 before a Transaction enters the chain).
        # Default 30: ~1/30 of batches scored, cutting paxos
        # traffic ~30x from the original per-batch cadence while
        # keeping CTFT fed.
        self._ts_decimation = int(
            os.environ.get("AT_TS_DECIMATION", "30"))

        # Validators run inline on the coordinator; in a full deployment
        # these would also run on dedicated fusion peers (squad-intel,
        # command).  Keeping them here for Phase 3 simplicity.
        self.validators = list(ALL_VALIDATORS)

        # Panel components — built once, fed incrementally below and
        # rendered each tick by the Dash live server.
        self._panels = build_dashboard(scenario)

        # silent=False so logger output goes to stdout (and thus docker
        # logs).  With silent=True, AT only writes to the per-container
        # rotating logfile under /var/at/, which makes the demo
        # essentially un-debuggable from `docker compose logs`.
        super().__init__(silent=False, **kwargs)

        # Register the DoD trust-ladder caps (metadata only — function=None)
        # so the reputation process's _resolve_tx_weight finds the right
        # transaction_weight when scoring batches tagged with
        # capability_name="dod.sensor-report". Must run BEFORE _configure
        # / subprocess fork so the workers inherit the populated
        # Capabilities. See examples/dod_mission/trust_ladder.yaml.
        from .trust_ladder import register_trust_ladder  # local import
        self._trust_ladder = register_trust_ladder(self.capabilities)

        if HAS_INSPECTOR:
            self._cohort = Cohort(self.queue_pool)
            self.add_worker(CohortTracker, cohort=self._cohort)

        # Single mp.Queue that DiagDataRcvr writes into and
        # _drain_peer_readings reads from.  Created here (before
        # add_worker) so the worker subproc gets a forked reference
        # to the same underlying mp.Queue object.  Bypasses the
        # per-process Cohort indirection that silently drops data —
        # see DiagDataRcvr docstring.
        self._reading_drain = self.queue_type()

        # DataRcvr.handle_data is overridden to push to
        # self._reading_drain rather than self.cohort.peers — see
        # DiagDataRcvr docstring for why.  The cohort kwarg is still
        # required by DataRcvr.__init__ (and useful for peer-metadata
        # bookkeeping); pass it alongside.
        if HAS_DATA and HAS_INSPECTOR:
            self.add_worker(DiagDataRcvr, cohort=self._cohort,
                            reading_drain=self._reading_drain)

        # Subscribe to the scenario's event stream so we can record
        # PhaseEvents (PEER_JOIN, COMPROMISE_START, PEER_EXCLUDE) to
        # the canned-playback log alongside our own anomaly events.
        scenario.on_event(self._on_scenario_event)

    # -- AT lifecycle ---------------------------------------------------

    def init_tasking(self, queues):
        logger.info("DoD mission coordinator starting "
                    "(scenario=%s, compromise_mode=%s, %d peers)",
                    self.scenario.name, self._compromise_mode,
                    len(self.scenario.peers))
        if self._record_path:
            logger.info("Recording scenario events to %s", self._record_path)
        # Spin up the Dash server in a daemon thread so AT keeps owning
        # the main loop.  The thread dies with the process; no explicit
        # join in cleanup().
        live_server.start_in_thread(
            name=__name__,
            title=self.scenario.name,
            panels=self._panels,
            chart_keys=["target_x_chart", "noise_chart"],
            state_provider=lambda: self._latest_state,
            port=self._dashboard_port,
            narration_script=DOD_NARRATION,
        )
        logger.info("Dashboard serving on :%d", self._dashboard_port)

    def autonomous_tasking(self, queues):
        self._tick_count += 1
        # Drain every tick — readings arrive at ~1 Hz per peer; if we
        # batch the drain to N>1 ticks we risk filling per-peer
        # data_stream queues (a small, fixed-size multiproc Queue
        # allocated from the QueuePool).
        self._drain_peer_readings(queues)
        # Query reputation every ~30s (60 ticks at the 500ms cadence
        # multi-agency assumes; tune later from real runs).
        if self._tick_count % 60 == 0:
            self._query_reputations(queues)
        if self._tick_count % 10 == 0:
            self._push_dashboard_update()

    _logged_first_drain = False
    _logged_first_reading = False
    _logged_first_peers = False
    _logged_first_batch_submit = False
    _logged_first_rep_drain = False
    _logged_first_batch_seen = False
    _logged_missing_task_id = False

    def _drain_peer_readings(self, queues=None):
        """Drain payloads that DiagDataRcvr has put onto the shared
        ``self._reading_drain`` queue, reconstruct ``Reading``
        objects, and fan them out through the validator + chart
        pipeline.

        The cohort sync below is kept only for the dashboard's
        per-peer metadata view; the data path itself runs through
        the single shared queue so it doesn't depend on cohort
        consistency across worker subprocesses.  See DiagDataRcvr
        docstring for the per-process cohort issue this works
        around.

        ``queues`` is forwarded into submit_reading_for_validation so
        that path can put a ``TransactionScore`` on the reputation
        queue.  Optional because some legacy call sites in tests
        don't pass queues; the score submission is skipped if it's
        None."""
        if not HAS_INSPECTOR:
            return
        # Sync the main proc's cohort view from the protocol-level
        # `self.peers` list — only for dashboard population.  See
        # DiagDataRcvr docstring for why this view of cohort.peers is
        # not authoritative for the data path itself.
        try:
            if self.peers is not None and self.peers.all:
                self._cohort.update_group(
                    {str(p.uuid): p for p in self.peers.all})
        except Exception:
            logger.exception("Cohort sync from self.peers failed")
        if (not DoDMissionCoordinator._logged_first_peers
                and self._cohort.peers):
            logger.info(
                "_drain_peer_readings: cohort first populated with "
                "%d peer(s): %s",
                len(self._cohort.peers),
                sorted(p.nickname for p in self._cohort.peers.values()))
            DoDMissionCoordinator._logged_first_peers = True
        if (not DoDMissionCoordinator._logged_first_drain
                and self._tick_count % 20 == 0):
            logger.info(
                "_drain_peer_readings: tick=%d, cohort_size=%d "
                "(awaiting first reading)",
                self._tick_count, len(self._cohort.peers))

        if getattr(self, '_reading_drain', None) is None:
            return

        # Used only for nicer log lines below.
        peers_by_uuid = {str(p.uuid): p for p in self.peers.all} \
            if self.peers is not None else {}

        while True:
            try:
                item = self._reading_drain.get_nowait()
            except queue.Empty:
                break
            except Exception:
                break
            if not item:
                continue
            try:
                uuid_str, payload = item
            except (TypeError, ValueError):
                logger.warning(
                    "_drain_peer_readings: unexpected drain item shape: %r",
                    item)
                continue
            peer = peers_by_uuid.get(uuid_str)
            peer_name = (getattr(peer, 'nickname', None)
                         or getattr(peer, 'fullname', None)
                         or uuid_str[:8])
            if not DoDMissionCoordinator._logged_first_reading:
                logger.info(
                    "_drain_peer_readings: first reading payload from "
                    "%s: type=%s len=%s",
                    peer_name, type(payload).__name__,
                    len(payload) if hasattr(payload, '__len__') else 'n/a')
                DoDMissionCoordinator._logged_first_reading = True
                DoDMissionCoordinator._logged_first_drain = True
            entries = payload if isinstance(payload, list) else [payload]
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                try:
                    reading = _reading_from_dict(entry)
                except Exception:
                    logger.exception(
                        "Malformed reading from %s: %r",
                        peer_name, entry)
                    continue
                try:
                    self.submit_reading_for_validation(reading, queues)
                except Exception:
                    logger.exception(
                        "Validator/chart dispatch failed for %s",
                        peer_name)

    def cleanup(self):
        """Flush the event log to disk on shutdown."""
        if self._event_recorder is not None and self._record_path:
            try:
                self._event_recorder.save(
                    self._record_path, scenario=self.scenario)
                logger.info("Recorded %d events to %s",
                            len(self._event_recorder.events),
                            self._record_path)
            except Exception:
                logger.exception("Failed to save recording")
        logger.info("DoD mission coordinator shutting down")

    # -- internal -------------------------------------------------------

    def _on_scenario_event(self, event):
        """Forward scenario events to the event log + playback record."""
        try:
            self._panels["event_log"].add_from_scenario_event(event)
        except Exception:
            logger.exception("Failed to forward scenario event to dashboard")
        if self._event_recorder is not None:
            self._event_recorder.record(event)

    def _query_reputations(self, queues):
        """Send consensus_rep_req for every known peer, then drain
        whatever ``self.latest_reputation`` has accumulated since
        last call.

        Uses ``consensus_rep_req`` rather than ``rep_req`` so the
        dashboard reflects a deterministic, history-only score
        derived from the consensus tx chain (see
        ``ReputationProcess._consensus_reputation``) instead of the
        coordinator's local CTFT/pure score.  The coordinator is an
        observer — it never submits TransactionScores — so the
        CTFT branch always returned 0.49 for peers it has no
        bilateral history with, and oscillated between regimes for
        the few it did.  The consensus path produces the same
        number on every node (the same view a participating peer
        would compute), which is what the inspector should display.
        """
        try:
            for peer in self.peers.all:
                query = Message(
                    CfgIds.reputation,
                    ReputationProtocol.consensus_rep_req,
                    to_yaml_string((peer, self.proc_name)),
                    self.identity,
                )
                try:
                    queues[CfgIds.reputation].put(
                        query, block=True, timeout=queue_cadence)
                except Exception:
                    logger.debug("Reputation queue put failed", exc_info=True)
        except Exception:
            logger.exception("Reputation request fanout failed")

        # Drain whatever replies AT has populated for us.
        peers_by_uuid = {str(p.uuid): p for p in self.peers.all}
        if (not DoDMissionCoordinator._logged_first_rep_drain
                or self._tick_count % 120 == 0):
            # Periodic snapshot so we can see whether AT's reputation
            # process is actually delivering scores and what they look
            # like.  Without this, "still 0.49" gives no information
            # about which side of the pipeline is stalled.
            logger.info(
                "_query_reputations: tick=%d peers.all=%d "
                "latest_reputation=%d history items, last5=%r",
                self._tick_count, len(self.peers.all),
                len(self.latest_reputation),
                [(str(k)[:8], round(getattr(v, "score", -1), 3))
                 for k, v in list(self.latest_reputation.items())[-5:]])
            DoDMissionCoordinator._logged_first_rep_drain = True
        for peer_id_str, rep in list(self.latest_reputation.items()):
            score = getattr(rep, "score", None)
            if score is None:
                continue
            peer = peers_by_uuid.get(str(peer_id_str))
            name = getattr(peer, "nickname", None) or str(peer_id_str)
            self._reputation_cache[name] = float(score)
            self._feed_timeline(name, float(score))
            # Stash the peer's trust tier alongside the score so the
            # dashboard reputations panel can show both. tier defaults
            # to 0 if the peer object isn't fully resolved yet.
            self._tier_cache[name] = int(getattr(peer, "_tier", 0))

    def _feed_timeline(self, peer_name: str, score: float) -> None:
        # AutonomousTrust sets ``tasking_start`` once init_tasking runs;
        # before then the t coordinate is unreliable, so fall back to a
        # tick-derived seconds estimate (500ms AT cadence) so the very
        # first observations still land on the timeline at sensible x.
        try:
            t = (now() - self.tasking_start).total_seconds()
        except Exception:
            t = self._tick_count * 0.5
        live_server.feed_timeline_sample(
            self._panels, t_seconds=t, peer_name=peer_name, score=score)

    def _push_dashboard_update(self):
        # Scenario seconds since tasking_start — falls back to tick-derived
        # estimate (AT runs at ~500ms cadence) until tasking_start is set.
        try:
            t_seconds = (now() - self.tasking_start).total_seconds()
        except Exception:
            t_seconds = self._tick_count * 0.5
        self._latest_state = {
            "reputations": dict(self._reputation_cache),
            "tiers": dict(self._tier_cache),
            "tick": self._tick_count,
            "t_seconds": t_seconds,
            "phase": (self.scenario.current_phase.name
                      if self.scenario.current_phase else None),
        }
        try:
            self.data_queue.put_nowait(("state", self._latest_state))
        except queue.Full:
            pass

    def submit_reading_for_validation(self, reading, queues=None) -> None:
        """Push a reading through validators + charts, and accumulate
        per-batch anomaly state so we can submit a TransactionScore
        for the batch as a whole once it has settled (see
        _maybe_submit_batch_scores).
        """
        # Fan the reading to both sensor charts; each ignores mismatched
        # data_types internally, so the dispatch stays simple.
        for chart_key in ("target_x_chart", "noise_chart"):
            try:
                self._panels[chart_key].add_reading(reading)
            except Exception:
                logger.exception("Failed to forward reading to %s", chart_key)

        # Track the batch this reading came from; flip its anomaly flag
        # if any validator fires.  The Reading's task_id is stamped by
        # DoDDataProcess.acquire() — readings emitted by peers running
        # an older participant.py won't carry it, so this block is
        # entirely a no-op there.
        batch_id = (reading.metadata or {}).get("task_id")
        if batch_id is not None:
            state = self._batch_state.get(batch_id)
            if state is None:
                state = {"submitted": False, "anomalous": False,
                         "first_tick": self._tick_count,
                         "peer_name": reading.peer_name}
                self._batch_state[batch_id] = state
                if not DoDMissionCoordinator._logged_first_batch_seen:
                    logger.info(
                        "Coordinator: first reading with task_id "
                        "received: peer=%s batch=%s",
                        reading.peer_name, batch_id)
                    DoDMissionCoordinator._logged_first_batch_seen = True
        elif not DoDMissionCoordinator._logged_missing_task_id:
            logger.warning(
                "Coordinator: reading from %s has NO task_id in "
                "metadata (metadata=%r) — generator-side stamping "
                "didn't reach this side, so batch TransactionScores "
                "will not be submitted",
                reading.peer_name, reading.metadata)
            DoDMissionCoordinator._logged_missing_task_id = True

        anomalous_this_reading = False
        for validator in self.validators:
            if validator.data_type != reading.data_type:
                continue
            result = validator.submit(reading)
            if result is None:
                continue
            if result.is_anomalous:
                anomalous_this_reading = True
                t_sec = result.timestamp.total_seconds()
                # Type is "COMPROMISE_DETECT" (a PhaseEvent enum name) so the
                # record survives PlaybackEngine.load_recorded's PhaseEvent
                # filter and replays in the event log; data.source pins it
                # as a validator hit (vs. a scripted scenario detect) for
                # any tool that wants to split them.
                record = {
                    "t": t_sec,
                    "type": "COMPROMISE_DETECT",
                    "peer": result.peer_name,
                    "data_type": result.data_type,
                    "deviation": result.deviation,
                    "consensus": result.consensus,
                    "threshold": result.threshold,
                    "description": (
                        f"{result.peer_name} {result.data_type} "
                        f"deviation {result.deviation:.1f} > {result.threshold:.1f}"
                    ),
                    "data": {"source": "validator"},
                }
                self._anomaly_log.append(record)
                if self._event_recorder is not None:
                    self._event_recorder.record(record)
                logger.warning(
                    "ANOMALY: %s reported %s=%.2f, consensus=%.2f (dev %.1f > %.1f)",
                    result.peer_name, result.data_type,
                    reading.value, result.consensus,
                    result.deviation, result.threshold,
                )
                # Surface on the event log + mark the chart trace.
                live_server.feed_event(self._panels, record)
                for chart_key in ("target_x_chart", "noise_chart"):
                    try:
                        self._panels[chart_key].mark_anomalous(
                            result.peer_name, t_sec)
                    except Exception:
                        pass

        if batch_id is not None and anomalous_this_reading:
            self._batch_state[batch_id]["anomalous"] = True

        if queues is not None:
            self._maybe_submit_batch_scores(queues)

    def _maybe_submit_batch_scores(self, queues):
        """Submit a TransactionScore for any batch that has settled
        (first sighting >= self._batch_settle_ticks ago) and not yet
        been submitted.  0.8 for a clean batch, 0.3 for one with any
        anomaly — pinned to automate.py:473 (ZKP verify pass/fail).

        Batches are decimated by _ts_keep on batch_id; the sender
        side (participant.py) applies the same filter so both sides
        agree on which batches form bilateral Transactions.
        Anomalies on non-selected batches don't drop reputation
        directly — but since compromise is sustained, the next
        selected batch from the same peer will also fire ANOMALY
        and drive the score down (latency ~AT_TS_DECIMATION batches).
        Filtered-out batches are marked submitted so they get
        reaped on the next pass.
        """
        # Iterate over a snapshot so we can mutate _batch_state.
        for batch_id, state in list(self._batch_state.items()):
            if state["submitted"]:
                # Reap submitted batches that are well past the
                # settle window so the dict doesn't grow unboundedly.
                if (self._tick_count - state["first_tick"]
                        > self._batch_settle_ticks * 8):
                    del self._batch_state[batch_id]
                continue
            if (self._tick_count - state["first_tick"]
                    < self._batch_settle_ticks):
                continue
            if not _ts_keep(batch_id, self._ts_decimation):
                state["submitted"] = True
                continue
            is_anomaly = bool(state["anomalous"])
            score = 0.3 if is_anomaly else 0.8
            # Tag the TS with the DoD ladder cap name so the
            # reputation process's _resolve_tx_weight picks up the
            # configured transaction_weight (4×) — see
            # examples/dod_mission/trust_ladder.yaml and
            # dod-demo-implementation-plan.md §Phase 6 / scope #3.
            ts = TransactionScore(task_id=batch_id, score=score,
                                  capability_name="dod.sensor-report")
            try:
                queues[CfgIds.reputation].put(
                    ts, block=True, timeout=queue_cadence)
                state["submitted"] = True
                if not DoDMissionCoordinator._logged_first_batch_submit:
                    logger.info(
                        "Coordinator: first batch TransactionScore "
                        "submitted: peer=%s batch=%s score=%.2f anomalous=%s",
                        state.get("peer_name"), batch_id, score,
                        state["anomalous"])
                    DoDMissionCoordinator._logged_first_batch_submit = True
                else:
                    logger.debug(
                        "Submitted batch TransactionScore: peer=%s "
                        "batch=%s score=%.2f anomalous=%s",
                        state.get("peer_name"), batch_id, score,
                        state["anomalous"])
            except queue.Full:
                logger.warning(
                    "Reputation queue full; deferring batch %s",
                    batch_id)


def main():
    # AT's Automaton attaches its StreamHandler to a logger named after
    # its own class (`DoDMissionCoordinator`), not to root.  This module's
    # `logger = logging.getLogger(__name__)` therefore has no handler in
    # its chain and `logger.info(...)` falls back to Python's lastResort
    # (WARNING-only, stderr).  Diagnostic markers like `awaiting first
    # reading` get silently swallowed.  basicConfig here installs a root
    # handler before AT init so module-level INFO actually reaches docker
    # logs.
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    setup_mode = "--setup" in sys.argv
    record_path = None
    compromise_mode = os.environ.get("AT_COMPROMISE_MODE", "abrupt")
    log_level = LogLevel.DEBUG

    for i, arg in enumerate(sys.argv):
        if arg == "--log-level" and i + 1 < len(sys.argv):
            log_level = LogLevel[sys.argv[i + 1].upper()]
        elif arg == "--record" and i + 1 < len(sys.argv):
            record_path = sys.argv[i + 1]
        elif arg == "--compromise-mode" and i + 1 < len(sys.argv):
            compromise_mode = sys.argv[i + 1]

    root_dir = os.environ.get(Configuration.ROOT_VARIABLE_NAME,
                              str(Path(__file__).parent / "coordinator"))
    os.environ[Configuration.ROOT_VARIABLE_NAME] = root_dir
    cfg_dir = Configuration.get_cfg_dir()
    dat_dir = Configuration.get_data_dir()
    os.makedirs(cfg_dir, exist_ok=True)
    os.makedirs(dat_dir, exist_ok=True)

    # generate_identity needs cfg_dir as first arg (mission/coordinator.py
    # is the working reference).  `defaults=True` lets AT fill in
    # default values for any subsystem config we haven't pre-populated.
    generate_identity(cfg_dir, preserve=True, defaults=True)

    # Build the scenario from env-var knobs so the same coordinator
    # image works for a 16-peer demo and a 100-peer scale test.
    scenario = DoDMissionScenario(
        squad_size=int(os.environ.get("AT_SQUAD_SIZE", "4")),
        swarm_size=int(os.environ.get("AT_SWARM_SIZE", "4")),
        sensor_count=int(os.environ.get("AT_SENSOR_COUNT", "3")),
        hacked_sensors=int(os.environ.get("AT_HACKED_SENSORS", "2")),
        include_mq800=os.environ.get("AT_INCLUDE_MQ800", "1") != "0",
        include_jet=os.environ.get("AT_INCLUDE_JET", "1") != "0",
        include_command=os.environ.get("AT_INCLUDE_COMMAND", "1") != "0",
    )

    if setup_mode:
        # Signature: generate_worker_config(cfg_dir, proc_name, cfg_class, defaults).
        # Mission demo's reference call is the model.
        if HAS_DATA:
            from autonomous_trust.services.data.client import DataConfig
            generate_worker_config(cfg_dir, DataRcvr.name, DataConfig, True)
        # CohortTracker doesn't expose a separate InitializableConfig — leave
        # it to AT's defaults at runtime.  When the inspector is wired with
        # its own worker config schema, add the call here.
        print(f"Setup complete for DoD coordinator "
              f"({len(scenario.peers)} peers).")
        return

    logger.info("Starting DoD mission coordinator")
    coord = DoDMissionCoordinator(
        scenario=scenario,
        record_path=record_path,
        compromise_mode=compromise_mode,
        log_level=log_level,
    )
    coord.run_forever()


if __name__ == "__main__":
    main()
