"""
Multi-agency demo coordinator / inspector node.

Aggregates data from all participants, runs the dashboard with
demo-specific panels (trust timeline, sensor comparison, event log),
manages scenario playback, and records events for canned replay.

Usage:
    python coordinator.py [--setup] [--log-level debug]
                          [--record FILE] [--compromise-mode gradual|abrupt]
"""

from __future__ import annotations

import os
import sys
import queue
import json
import logging
import threading
from pathlib import Path
from datetime import timedelta

from autonomous_trust.core import AutonomousTrust, Configuration, LogLevel, CfgIds, Process, ProcMeta, to_yaml_string
from autonomous_trust.core.config.generate import generate_identity, generate_worker_config
from autonomous_trust.core.network import Message
from autonomous_trust.core.reputation.protocol import ReputationProtocol
from autonomous_trust.core.reputation.reputation import TransactionScore
from autonomous_trust.core.system import queue_cadence, now
from autonomous_trust.evaluation.scenarios.recording import EventRecorder
from autonomous_trust.services.data import Reading


def _roster_name_of(peer):
    """Bare roster name for a peer == the local-part of its ONLINE nickname.

    The online nickname (e.g. ``noaa-1@tekfive.com``) is the only globally-
    consistent, wire-carried name; the local petname is deliberately arbitrary
    (a random suffix is minted on receipt -- see identity.derive_local_petname)
    and must NOT be used to match a peer to its scenario role. Strip the
    ``@domain`` to recover the deployment-set AT_PEER_NAME (``noaa-1``). Accepts
    a raw ``Identity`` (``.nickname``) or a peer wrapper exposing ``.identity``,
    and tolerates a nickname with no ``@``."""
    ident = getattr(peer, "identity", None) or peer
    nn = (getattr(ident, "nickname", None)
          or getattr(peer, "nickname", None) or "")
    return str(nn).split('@', 1)[0].strip()


try:
    from autonomous_trust.inspector.peer.daq import Cohort, CohortTracker
    HAS_INSPECTOR = True
except ImportError as _exc:
    # Silent degradation here makes `_drain_peer_readings` a no-op and
    # readings never reach the coordinator. Surface the cause at
    # module-import time on stderr (logger isn't configured yet).
    print(
        f"[multi_agency.coordinator] HAS_INSPECTOR=False — "
        f"autonomous_trust.inspector.peer.daq import failed: "
        f"{type(_exc).__name__}: {_exc}",
        file=sys.stderr, flush=True,
    )
    HAS_INSPECTOR = False

try:
    from autonomous_trust.services.data.client import DataRcvr
    HAS_DATA = True

    from queue import Empty as _DQ_Empty
    from autonomous_trust.core import (
        CfgIds as _DQ_CfgIds, from_yaml_string as _DQ_from_yaml_string,
    )
    from autonomous_trust.core.network import Message as _DQ_Message
    from autonomous_trust.services.data.server import (  # noqa
        DataProcess as _DQ_DataProcess, DataProtocol as _DQ_DataProtocol,
    )

    class DiagDataRcvr(DataRcvr, metaclass=ProcMeta,
                       proc_name='data-sink',
                       description='Data sink (with traceback surfacing)'):
        """DataRcvr wrapper carried over from DoD. Pushes received
        payloads onto a coordinator-owned drain queue rather than
        ``self.cohort.peers[uuid].data_stream`` — the latter goes
        through a per-process Cohort instance and the data path
        silently drops payloads when CohortTracker, DataRcvr, and
        the coordinator main proc each maintain their own forked
        copy. A single shared mp.Queue sidesteps the indirection.

        Also fixes a uuid→Identity resolution bug in upstream's
        ``DataRcvr.process``: PeerCapabilities stores peer UUIDs
        (strings) but ``Message.__init__`` insists on Identity, so
        the worker crashes on the first peer discovery. The
        ``_patched_process`` override resolves uuid → Identity via
        ``protocol.peers.find_by_uuid`` before constructing the
        subscribe message.

        See examples/dod_mission/coordinator.py for the full
        DiagDataRcvr origin docstring.
        """

        def __init__(self, configurations, subsystems, log_queue,
                     dependencies, **kwargs):
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
                            _roster_name_of(ident) or ident)
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
            if hasattr(ref, "uuid") and hasattr(ref, "address"):
                return ref
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
    print(
        f"[multi_agency.coordinator] HAS_DATA=False — "
        f"autonomous_trust.services.data.client import failed: "
        f"{type(_exc).__name__}: {_exc}",
        file=sys.stderr, flush=True,
    )
    HAS_DATA = False

# Dashboard imports — PYTHONPATH=/app:... in the demo image (see
# deploy/Dockerfile), so the package-qualified imports work directly.
from examples.multi_agency.scenario import DisasterResponseScenario  # noqa: E402
from examples.multi_agency.dashboard.multi_agency_app import (  # noqa: E402
    build_dashboard,
)
from examples.multi_agency.dashboard import live_server  # noqa: E402
from examples.multi_agency.tasks.validation import (  # noqa: E402
    ALL_VALIDATORS,
)
from examples.multi_agency.trust_ladder import (  # noqa: E402
    register_trust_ladder,
)

logger = logging.getLogger(__name__)


# Phase 6 #2 rank-gate for multi-agency: minimum fraction of admitted
# peers that must have completed AT-core bootstrap (peer._tier >= 1)
# before the scenario consents to leave Formation/Bootstrap and enter
# Negotiation. Mirrors DoD's APPROACH_* constants in
# examples/dod_mission/scenario.py.
NEGOTIATION_TIER_THRESHOLD = 1
NEGOTIATION_FRACTION_REQUIRED = 0.9


def _bootstrap_gate(scenario) -> bool:
    """Phase gate for the Negotiation transition.

    Consults scenario.``_tier_view_provider`` (a callable returning
    ``{peer_name: tier_int}``) which the live coordinator attaches at
    init time. Returns True (gate open) when:
      - no provider is attached (playback mode without a live coord),
        OR
      - ≥ NEGOTIATION_FRACTION_REQUIRED of admitted peers have
        ``tier >= NEGOTIATION_TIER_THRESHOLD``.

    A provider that returns an empty dict is treated as "no peers
    formed yet" → gate stays closed.
    """
    provider = getattr(scenario, "_tier_view_provider", None)
    if provider is None:
        return True
    try:
        tiers = provider() or {}
    except Exception:
        return True
    if not tiers:
        return False
    threshold = getattr(scenario, "_negotiation_gate_threshold",
                        NEGOTIATION_TIER_THRESHOLD)
    fraction = getattr(scenario, "_negotiation_gate_fraction",
                       NEGOTIATION_FRACTION_REQUIRED)
    at_or_above = sum(1 for t in tiers.values() if int(t) >= threshold)
    return at_or_above >= fraction * len(tiers)


def _ts_keep(batch_id: str, denom: int) -> bool:
    """Deterministic per-batch decimation for TS submission.

    Matches the DoD pattern. The sender side will need to keep the
    same filter once the multi-agency participants are wired to
    submit their bilateral TS half; for now the coordinator-side
    half ships alone and the bilateral pair never forms.
    """
    if denom <= 1:
        return True
    return int(batch_id.replace('-', '')[:8], 16) % denom == 0


def _reading_from_dict(d: dict) -> Reading:
    """Reconstruct a Reading from the dict shape that
    ``Reading.to_dict()`` emits over the data service wire.
    """
    return Reading(
        timestamp=timedelta(seconds=float(d["t"])),
        peer_name=str(d["peer"]),
        data_type=str(d["type"]),
        value=float(d["value"]),
        unit=str(d.get("unit", "")),
        quality=float(d.get("quality", 1.0)),
        metadata=d.get("metadata") or {},
    )


class MultiAgencyCoordinator(AutonomousTrust):
    """Coordinator node for the multi-agency disaster response demo.

    Extends AutonomousTrust with:
    - Peer cohort tracking (for dashboard)
    - Reputation monitoring (for trust timeline)
    - Data aggregation (for sensor comparison)
    - Scenario event recording (for canned playback)
    """

    def __init__(self, scenario: DisasterResponseScenario,
                 record_path: str | None = None,
                 compromise_mode: str = "abrupt",
                 dashboard_port: int = 8050,
                 **kwargs):
        self.scenario = scenario
        self.data_queue: queue.Queue = queue.Queue()
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
            "tiers": {},
            "tick": 0, "phase": None,
        }
        # nickname -> tier int (so _render_reputations can show both)
        self._tier_cache: dict[str, int] = {}
        # Prior cycle's tier_cache snapshot — used to detect demotions
        # (Phase 6 #5). See _emit_tier_lost.
        self._prev_tier_cache: dict[str, int] = {}
        # Per-batch state for sender-scoring.  batch_id (uuid str) →
        # {'submitted': bool, 'anomalous': bool, 'first_tick': int}.
        self._batch_state: dict[str, dict] = {}
        # 4 ticks ≈ 2 seconds at 500ms cadence — enough to see all
        # readings in a single 1Hz batch before scoring.
        self._batch_settle_ticks = 4
        # Per-batch TS decimation (matches DoD default). Once the
        # multi-agency participant grows a sender-side TS half, the
        # filter MUST stay in lockstep on both sides to form
        # bilateral Transactions.
        self._ts_decimation = int(
            os.environ.get("AT_TS_DECIMATION", "30"))
        # Per-(peer, data_type) snapshot stride. Decimates the
        # SENSOR_READING records the EventRecorder writes; the chart
        # panels themselves see every reading on the live path.
        self._recording_reading_stride = max(1, int(
            os.environ.get("AT_RECORDING_READING_STRIDE", "1")))
        self._reading_record_counts: dict[tuple[str, str], int] = {}

        # Validators run inline on the coordinator; a future fusion
        # peer could subscribe to the same drain and re-run them.
        self.validators = list(ALL_VALIDATORS)

        self._panels = build_dashboard(scenario)

        super().__init__(silent=True, **kwargs)

        # Phase 6 #1 — register the multi-agency trust-ladder caps
        # (metadata only) so the reputation process's _resolve_tx_weight
        # finds the right transaction_weight when scoring batches
        # tagged with capability_name="multi.sensor-report". Must run
        # BEFORE _configure / subprocess fork so workers inherit the
        # populated Capabilities. See trust_ladder.yaml.
        self._trust_ladder = register_trust_ladder(self.capabilities)

        # Peer tracking
        if HAS_INSPECTOR:
            self._cohort = Cohort(self.queue_pool)
            self.add_worker(CohortTracker, cohort=self._cohort)

        # Single mp.Queue that DiagDataRcvr writes into and
        # _drain_peer_readings reads from. Bypasses the per-process
        # Cohort indirection that silently drops data.
        self._reading_drain = self.queue_type()

        # DiagDataRcvr (Phase 6 backport from DoD) — overrides
        # handle_data to push to self._reading_drain rather than
        # cohort.peers[uuid].data_stream.
        if HAS_DATA and HAS_INSPECTOR:
            self.add_worker(DiagDataRcvr, cohort=self._cohort,
                            reading_drain=self._reading_drain)

        # Subscribe to scenario events so phase transitions and
        # COMPROMISE_* records land in both the event log panel and
        # the recording sidecar.
        scenario.on_event(self._on_scenario_event)

        # Phase 6 #2 — rank-gate the Negotiation phase (T+90s) on
        # ≥90% peers at tier ≥1. Attached as a scenario attribute so
        # the gate predicate (defined inline below) can find the live
        # tier cache without taking a coordinator reference at scenario-
        # construction time. Default-OK when no provider attached
        # (playback mode without a live coord) so existing recordings
        # replay unmodified.
        scenario._tier_view_provider = lambda: dict(self._tier_cache)
        self._install_negotiation_gate(scenario)

    # -- AT lifecycle ---------------------------------------------------

    def init_tasking(self, queues):
        """Called once before the main loop starts."""
        logger.info("Multi-agency coordinator starting (compromise_mode=%s, %d peers)",
                    self._compromise_mode, len(self.scenario.peers))
        if self._record_path:
            logger.info("Recording events to %s", self._record_path)
        live_server.start_in_thread(
            name="examples.multi_agency.coordinator",
            title=self.scenario.name,
            panels=self._panels,
            chart_keys=["temperature_chart", "wind_chart"],
            state_provider=lambda: self._latest_state,
            port=self._dashboard_port,
        )
        logger.info("Dashboard serving on :%d", self._dashboard_port)

    def autonomous_tasking(self, queues):
        """Called each tick — drains readings, fires validators,
        submits TSs, queries reputations, advances scenario clock.
        """
        self._tick_count += 1
        self._drain_peer_readings(queues)
        # Query reputation every ~30s (60 ticks at the 500ms cadence
        # multi-agency assumes).
        if self._tick_count % 60 == 0:
            self._query_reputations(queues)
        # Advance scenario clock + push dashboard update every 10 ticks.
        if self._tick_count % 10 == 0:
            self._advance_scenario_clock()
            self._push_dashboard_update()

    def cleanup(self):
        """Flush the event log on shutdown."""
        if self._event_recorder is not None and self._record_path:
            try:
                self._event_recorder.save(
                    self._record_path, scenario=self.scenario)
                logger.info("Recorded %d events to %s",
                            len(self._event_recorder.events),
                            self._record_path)
            except Exception:
                logger.exception("Failed to save recording")
        logger.info("Multi-agency coordinator shutting down")

    # -- internal -------------------------------------------------------

    _logged_first_drain = False
    _logged_first_reading = False
    _logged_first_peers = False
    _logged_first_batch_submit = False
    _logged_first_rep_drain = False
    _logged_first_batch_seen = False
    _logged_missing_task_id = False

    def _install_negotiation_gate(
            self, scenario: DisasterResponseScenario) -> None:
        """Install _bootstrap_gate on the Negotiation phase.

        Done at coordinator-init time rather than in scenario.define()
        because the gate is a coordinator-side concern (it consults
        the live tier cache the coordinator owns). Playback runs
        without a coordinator default-OK on the gate, so this
        doesn't break existing recordings.
        """
        for phase in scenario.phases:
            if phase.name == "Negotiation":
                phase.gate = _bootstrap_gate
                logger.info(
                    "Installed bootstrap rank-gate on Negotiation phase "
                    "(threshold tier >= %d, fraction >= %.0f%%)",
                    NEGOTIATION_TIER_THRESHOLD,
                    100 * NEGOTIATION_FRACTION_REQUIRED)
                return
        logger.warning(
            "Negotiation phase not found in scenario; rank-gate not installed")

    def _on_scenario_event(self, event):
        """Forward scenario events to the event log + playback record."""
        try:
            self._panels["event_log"].add_from_scenario_event(event)
        except Exception:
            logger.exception("Failed to forward scenario event to dashboard")
        if self._event_recorder is not None:
            self._event_recorder.record(event)

    def _advance_scenario_clock(self) -> None:
        """Tick the scenario forward to (now - tasking_start).

        Mirror of DoD's _advance_scenario_clock — without this the
        scenario never leaves Formation in live mode and the dashboard
        phase indicator + the Negotiation rank-gate are never
        consulted.
        """
        try:
            t = now() - self.tasking_start
        except Exception:
            return
        try:
            self.scenario.advance_to(t)
        except Exception:
            logger.exception("scenario.advance_to(%s) failed", t)

    def _drain_peer_readings(self, queues=None):
        """Drain payloads from the shared reading_drain queue,
        reconstruct Readings, and fan them through validator + chart
        pipeline.
        """
        if not HAS_INSPECTOR:
            return
        try:
            if self.peers is not None and self.peers.all:
                self._cohort.update_group(
                    {str(p.uuid): p for p in self.peers.all})
        except Exception:
            logger.exception("Cohort sync from self.peers failed")
        if (not MultiAgencyCoordinator._logged_first_peers
                and self._cohort.peers):
            logger.info(
                "_drain_peer_readings: cohort first populated with "
                "%d peer(s): %s",
                len(self._cohort.peers),
                sorted(_roster_name_of(p)
                       for p in self._cohort.peers.values()))
            MultiAgencyCoordinator._logged_first_peers = True

        if getattr(self, '_reading_drain', None) is None:
            return
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
                continue
            peer = peers_by_uuid.get(uuid_str)
            peer_name = _roster_name_of(peer) or uuid_str[:8]
            if not MultiAgencyCoordinator._logged_first_reading:
                logger.info(
                    "_drain_peer_readings: first reading payload from "
                    "%s: type=%s len=%s",
                    peer_name, type(payload).__name__,
                    len(payload) if hasattr(payload, '__len__') else 'n/a')
                MultiAgencyCoordinator._logged_first_reading = True
                MultiAgencyCoordinator._logged_first_drain = True
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

    def submit_reading_for_validation(self, reading, queues=None) -> None:
        """Push a reading through validators + charts, and accumulate
        per-batch anomaly state so we can submit a TransactionScore
        for the batch as a whole once it has settled.
        """
        # Fan to both sensor charts; each ignores mismatched data_types.
        for chart_key in ("temperature_chart", "wind_chart"):
            try:
                self._panels[chart_key].add_reading(reading)
            except Exception:
                logger.exception("Failed to forward reading to %s", chart_key)
        # Snapshot the reading for canned playback (decimated per
        # (peer, data_type) by AT_RECORDING_READING_STRIDE).
        if self._event_recorder is not None:
            key = (reading.peer_name, reading.data_type)
            seq = self._reading_record_counts.get(key, 0)
            self._reading_record_counts[key] = seq + 1
            if seq % self._recording_reading_stride == 0:
                self._event_recorder.record_snapshot({
                    "t": reading.timestamp.total_seconds(),
                    "type": "SENSOR_READING",
                    "peer": reading.peer_name,
                    "data_type": reading.data_type,
                    "value": float(reading.value),
                    "unit": reading.unit,
                    "quality": float(reading.quality),
                    "metadata": dict(reading.metadata or {}),
                })

        batch_id = (reading.metadata or {}).get("task_id")
        if batch_id is not None:
            state = self._batch_state.get(batch_id)
            if state is None:
                state = {"submitted": False, "anomalous": False,
                         "first_tick": self._tick_count,
                         "peer_name": reading.peer_name}
                self._batch_state[batch_id] = state
                if not MultiAgencyCoordinator._logged_first_batch_seen:
                    logger.info(
                        "Coordinator: first reading with task_id received: "
                        "peer=%s batch=%s",
                        reading.peer_name, batch_id)
                    MultiAgencyCoordinator._logged_first_batch_seen = True
        elif not MultiAgencyCoordinator._logged_missing_task_id:
            logger.warning(
                "Coordinator: reading from %s has NO task_id in metadata "
                "(metadata=%r) — generator-side stamping didn't reach this "
                "side, so batch TransactionScores will not be submitted",
                reading.peer_name, reading.metadata)
            MultiAgencyCoordinator._logged_missing_task_id = True

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
                live_server.feed_event(self._panels, record)

        if batch_id is not None and anomalous_this_reading:
            self._batch_state[batch_id]["anomalous"] = True

        if queues is not None:
            self._maybe_submit_batch_scores(queues)

    def _maybe_submit_batch_scores(self, queues):
        """Submit a TransactionScore tagged with capability_name=
        ``multi.sensor-report`` for any batch that has settled past
        self._batch_settle_ticks and not yet been submitted.
        0.8 for a clean batch, 0.3 for one with any anomaly.
        """
        for batch_id, state in list(self._batch_state.items()):
            if state["submitted"]:
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
            ts = TransactionScore(task_id=batch_id, score=score,
                                  capability_name="multi.sensor-report")
            try:
                queues[CfgIds.reputation].put(
                    ts, block=True, timeout=queue_cadence)
                state["submitted"] = True
                if not MultiAgencyCoordinator._logged_first_batch_submit:
                    logger.info(
                        "Coordinator: first batch TransactionScore "
                        "submitted: peer=%s batch=%s score=%.2f anomalous=%s",
                        state.get("peer_name"), batch_id, score,
                        state["anomalous"])
                    MultiAgencyCoordinator._logged_first_batch_submit = True
            except queue.Full:
                logger.warning(
                    "Reputation queue full; deferring batch %s",
                    batch_id)

    def _query_reputations(self, queues):
        """Fan out consensus_rep_req for every known peer, then drain
        whatever ``self.latest_reputation`` has accumulated. Same
        pattern as DoD: history-only consensus score so the dashboard
        shows the deterministic view a participating peer would
        compute, not the coordinator's local CTFT.
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

        peers_by_uuid = {str(p.uuid): p for p in self.peers.all}
        if (not MultiAgencyCoordinator._logged_first_rep_drain
                or self._tick_count % 120 == 0):
            logger.info(
                "_query_reputations: tick=%d peers.all=%d "
                "latest_reputation=%d history items, last5=%r",
                self._tick_count, len(self.peers.all),
                len(self.latest_reputation),
                [(str(k)[:8], round(getattr(v, "score", -1), 3))
                 for k, v in list(self.latest_reputation.items())[-5:]])
            MultiAgencyCoordinator._logged_first_rep_drain = True
        for peer_id_str, rep in list(self.latest_reputation.items()):
            score = getattr(rep, "score", None)
            if score is None:
                continue
            peer = peers_by_uuid.get(str(peer_id_str))
            name = _roster_name_of(peer) or str(peer_id_str)
            self._reputation_cache[name] = float(score)
            self._feed_timeline(name, float(score))
            new_tier = int(getattr(peer, "_tier", 0))
            prev_tier = self._prev_tier_cache.get(name)
            self._tier_cache[name] = new_tier
            if prev_tier is not None and new_tier < prev_tier:
                self._emit_tier_lost(name, prev_tier, new_tier)
            self._prev_tier_cache[name] = new_tier

    def _emit_tier_lost(self, peer_name: str, prev_tier: int,
                        new_tier: int) -> None:
        """Surface a peer's tier demotion to dashboard + recording.
        Mirror of DoD's _emit_tier_lost.
        """
        try:
            t_sec = (now() - self.tasking_start).total_seconds()
        except Exception:
            t_sec = self._tick_count * 0.5
        record = {
            "t": t_sec,
            "type": "TIER_LOST",
            "peer": peer_name,
            "prev_tier": prev_tier,
            "new_tier": new_tier,
            "description": (
                f"{peer_name} tier {prev_tier} → {new_tier} "
                f"(access revoked)"
            ),
            "data": {"source": "tier_change"},
        }
        self._anomaly_log.append(record)
        if self._event_recorder is not None:
            self._event_recorder.record(record)
        try:
            live_server.feed_event(self._panels, record)
        except Exception:
            logger.exception("Failed to feed tier_lost to event log")
        logger.warning(
            "TIER_LOST: %s tier %d -> %d", peer_name, prev_tier, new_tier)

    def _feed_timeline(self, peer_name: str, score: float) -> None:
        try:
            t = (now() - self.tasking_start).total_seconds()
        except Exception:
            t = self._tick_count * 0.5
        live_server.feed_timeline_sample(
            self._panels, t_seconds=t, peer_name=peer_name, score=score)
        if self._event_recorder is not None:
            self._event_recorder.record_snapshot({
                "t": t,
                "type": "REPUTATION_SAMPLE",
                "peer": peer_name,
                "score": float(score),
            })

    def _push_dashboard_update(self):
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


def main():
    # AT's Automaton attaches its StreamHandler only to a logger named
    # after its own class, not to root.  Without basicConfig here,
    # `logger = getLogger(__name__)` above has no handler in its chain
    # and `logger.info(...)` falls to Python's lastResort (WARNING/stderr),
    # silently dropping every diagnostic line below WARNING.  See
    # examples/dod_mission/coordinator.py:main() for the long version.
    logging.basicConfig(
        level=logging.INFO,
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    setup_mode = "--setup" in sys.argv
    record_path = None
    compromise_mode = "abrupt"
    log_level = LogLevel.DEBUG

    for i, arg in enumerate(sys.argv):
        if arg == "--log-level" and i + 1 < len(sys.argv):
            log_level = LogLevel[sys.argv[i + 1].upper()]
        elif arg == "--record" and i + 1 < len(sys.argv):
            record_path = sys.argv[i + 1]
        elif arg == "--compromise-mode" and i + 1 < len(sys.argv):
            compromise_mode = sys.argv[i + 1]

    # AT derives etc/at + var/at from AUTONOMOUS_TRUST_ROOT.  generate_identity
    # requires cfg_dir as a positional arg (see mission/coordinator.py).
    root_dir = os.environ.get(Configuration.ROOT_VARIABLE_NAME,
                              str(Path(__file__).parent / "coordinator"))
    os.environ[Configuration.ROOT_VARIABLE_NAME] = root_dir
    cfg_dir = Configuration.get_cfg_dir()
    dat_dir = Configuration.get_data_dir()
    os.makedirs(cfg_dir, exist_ok=True)
    os.makedirs(dat_dir, exist_ok=True)

    generate_identity(cfg_dir, preserve=True, defaults=True)

    if setup_mode:
        # generate_worker_config(cfg_dir, proc_name, cfg_class, defaults)
        if HAS_DATA:
            from autonomous_trust.services.data.client import DataConfig
            generate_worker_config(cfg_dir, DataRcvr.name, DataConfig, True)
        # CohortTracker has no separate InitializableConfig; AT uses defaults.
        print("Setup complete for coordinator")
        return

    logger.info("Starting multi-agency coordinator")
    scenario = DisasterResponseScenario()
    coordinator = MultiAgencyCoordinator(
        scenario=scenario,
        record_path=record_path,
        compromise_mode=compromise_mode,
        log_level=log_level,
    )
    coordinator.run_forever()


if __name__ == "__main__":
    # Default to forkserver: 'fork' (Linux default through 3.13) forks a
    # multi-threaded process and can deadlock the child. Harmless on 3.14+.
    import multiprocessing as _mp
    _mp.set_start_method('forkserver', force=True)
    main()
