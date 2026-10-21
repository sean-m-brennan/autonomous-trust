# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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
from collections import deque
from datetime import timedelta

# Stretch Goal 2 / Phase 3: bound the per-peer detection ring buffer.
# Plan section 6.1 caps the inspector drawer's log strip at 10; we keep
# the same depth in the coordinator cache so the drawer can render the
# full history without further plumbing.
DETECTION_LOG_CAPACITY = 10
from pathlib import Path

from autonomous_trust.core import (
    AutonomousTrust, CfgIds, Configuration, LogLevel, to_yaml_string,
)
from autonomous_trust.core.network import Message
from autonomous_trust.core.reputation.protocol import ReputationProtocol
from autonomous_trust.core.reputation.reputation import (
    TransactionScore, SlashAttestation)
from autonomous_trust.services.data import Reading
from autonomous_trust.core.config.generate import (
    generate_identity, generate_worker_config,
)
from autonomous_trust.core.system import now, queue_cadence
from autonomous_trust.inspector.transitive_trust import (
    TransitiveTrustMixin, PEER_PAIR_QUERY_SEC)
from autonomous_trust.evaluation.scenarios.recording import EventRecorder
from autonomous_trust.core import LOG_FORMAT, LOG_DATEFMT

def _roster_name_of(peer):
    """Bare roster name for a peer == the local-part of its ONLINE nickname.

    The online nickname (e.g. ``mq800@tekfive.com``) is the only globally-
    consistent, wire-carried name; the local petname is deliberately arbitrary
    (a random suffix is minted on receipt -- see
    identity.derive_local_petname) and must NOT be used to match a peer to its
    scenario roster role. We strip the ``@domain`` to recover the deployment-set
    AT_PEER_NAME (``mq800``) the scenario keys on.

    Accepts either a raw ``Identity`` (``.nickname``) or a peer wrapper that
    exposes ``.identity`` (the inspector's ``PeerDataAcq``), and tolerates a
    nickname with no ``@`` (returned as-is)."""
    ident = getattr(peer, "identity", None) or peer
    nn = (getattr(ident, "nickname", None)
          or getattr(peer, "nickname", None) or "")
    return str(nn).split('@', 1)[0].strip()


def _peer_permits_neighbor(name: str, agency: str,
                           other: str, other_agency: str) -> bool:
    """Trust-graph isolation policy for one endpoint of an edge (mirrors the
    real command structure):

    * **microdrones** are ODA-internal assets (flown by the squad), so they
      only trust-link WITHIN the ODA — to soldiers and to each other.
    * the **command** node coordinates only with the RQ-86 gateways and the
      ODA, so it only links to ``rq86-*`` or ODA peers.

    Everyone else is unrestricted (returns True). Pure — keyed on the same
    name prefixes the warm-start cohort uses (see reputation_warmstart)."""
    if name.startswith("microdrone-"):
        return other_agency == "ODA"
    if name == "command":
        return other.startswith("rq86-") or other_agency == "ODA"
    return True


def _trust_edge_allowed(a: str, agency_a: str, b: str, agency_b: str) -> bool:
    """True if a bilateral trust edge between ``a`` and ``b`` may be drawn.

    Admitted iff BOTH endpoints permit the other (intersection of the two
    isolation policies). So e.g. command<->microdrone is DROPPED: command
    permits the ODA, but the microdrone permits only ODA members and the
    command node is not one — command reaches the ODA via the squad, not each
    drone. Pure."""
    return (_peer_permits_neighbor(a, agency_a, b, agency_b)
            and _peer_permits_neighbor(b, agency_b, a, agency_a))


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
            # Nicknames of peers known to produce data — the roster-driven
            # subscribe fallback for late joiners whose data-cap advert was
            # lost (see _patched_process). Empty set => fallback is a no-op.
            self.data_producers = set(kwargs.pop('data_producers', None) or ())
            # uuid strings of peers we have ACTUALLY received a reading from.
            # The roster subscribe is fire-and-forget on the producer side
            # (server.handle_requests registers a client only if the request
            # lands), so a single lost/early request strands a producer at
            # clients=0 forever. We retry the subscribe until a reading shows
            # up here, so a late joiner (mq800) whose first request was dropped
            # — or arrived before its group-join settled — still gets serviced.
            self._received_data_uuids: set = set()
            # Re-subscribe throttle: attempt every Nth process() iteration
            # (the first attempt is on iteration 0, see _patched_process) so a
            # lost/early request is retried within ~N * q_cadence seconds until
            # data flows. Kept small so a late joiner whose advert was lost
            # (mq800) appears within a few seconds, not ~10s; raise to ease
            # network load if a deployment has many silent producers.
            self._resub_period = max(1, int(
                os.environ.get("AT_DATA_RESUBSCRIBE_TICKS", "6")))
            self._resub_tick = 0
            self._resub_logged: set = set()
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
            # Mark this producer as live so the roster-subscribe retry
            # (see _patched_process) stops re-requesting its stream.
            if uuid_str is not None:
                self._received_data_uuids.add(uuid_str)
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
                            _roster_name_of(ident) or ident)

                # Fallback: subscribe to admitted data-PRODUCING roster peers
                # whose data-capability advertisement never reached us. A late
                # joiner (the MQ-800 at T+4:00) can drop that advert under UDP
                # loss; the cap path above then never lists it, so its readings
                # never arrive and it is never detected — which also strands the
                # anomaly-gated jet. The peer's DataProcess runs regardless and
                # answers a direct request, so subscribing by roster recovers
                # the stream.
                #
                # The subscribe is fire-and-forget: the producer registers us
                # as a client only if the request actually lands
                # (server.handle_requests), and there is no ack. A single
                # request lost to UDP — or sent before the late joiner's
                # group-join settled — therefore leaves it at clients=0 forever
                # (observed: mq800 emits "active=True, clients=0", its readings
                # never arrive, no anomaly, jet never launches). So we RETRY on
                # a throttle, keyed on whether a reading has actually arrived
                # (_received_data_uuids, set in handle_data), not on whether we
                # once sent a request — until the stream is live.
                #
                # Fire on the FIRST pass (tick 0 % period == 0) and then every
                # _resub_period passes — incrementing AFTER the check. The
                # increment used to run first, so the first attempt waited a
                # whole period (~10s): mq800, whose advert is lost and which
                # thus depends entirely on this path, appeared ~10s late while
                # cap-advertised producers (rq86) showed immediately. Firing
                # immediately closes that mq800-specific lag.
                if (self.data_producers
                        and self._resub_tick % self._resub_period == 0):
                    for p in self._pending_roster_subscriptions(
                            self.protocol.peers.all,
                            self._received_data_uuids,
                            self.data_producers):
                        msg = _DQ_Message(
                            _DQ_DataProcess.name,
                            _DQ_DataProtocol.request,
                            self.name, p)
                        queues[_DQ_CfgIds.network].put(
                            msg, block=True, timeout=self.q_cadence)
                        # Log the first attempt per peer at INFO; later retries
                        # at DEBUG so a never-reachable producer can't flood.
                        uid = str(getattr(p, "uuid", ""))
                        log = (self.logger.info if uid not in self._resub_logged
                               else self.logger.debug)
                        self._resub_logged.add(uid)
                        log("DiagDataRcvr: roster-subscribed to %s "
                            "(no readings yet — retrying until live)",
                            _roster_name_of(p) or p)
                self._resub_tick += 1

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

        @staticmethod
        def _pending_roster_subscriptions(peers_all, already, data_producers):
            """Roster peers that produce data but aren't satisfied yet.

            Pure decision half of the late-joiner fallback (see
            _patched_process): given the admitted roster, the set of peers
            already satisfied, and the set of data-producer roster names,
            return the peers to (re)subscribe to now. ``already`` may hold
            Identity objects (the cap path's servicers) OR bare uuid strings
            (the retry path's _received_data_uuids) — both reduce to a uuid
            string. Dedups by uuid string so a peer already serviced / already
            delivering data is skipped, and the same peer isn't returned twice
            within one pass.
            """
            subscribed = {str(getattr(s, "uuid", s)) for s in already}
            pending = []
            for p in peers_all:
                # Match on the ONLINE nickname's local-part, NOT the petname:
                # the petname is local-only and arbitrary on the receiver side
                # (random suffix), so it never equals a roster name like
                # "mq800". See _roster_name_of / identity.derive_local_petname.
                if _roster_name_of(p) not in data_producers:
                    continue
                uid = str(getattr(p, "uuid", ""))
                if not uid or uid in subscribed:
                    continue
                subscribed.add(uid)
                pending.append(p)
            return pending

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
from reputation_warmstart import (  # noqa: E402
    is_warm_start_member, is_pre_trusted, reconcile_rep_score,
    reconcile_rep_score_sticky, warm_start_edge_score,
    SEED_REPUTATION, SEED_TIER,
)
sys.path.insert(0, str(_HERE / "tasks"))
from validation import (  # noqa: E402
    POSITION_VALIDATOR_X, POSITION_VALIDATOR_Y, ELECTRONIC_NOISE_VALIDATOR,
    ALL_VALIDATORS,
)

logger = logging.getLogger(__name__)


# The consensus reputation baseline for a peer with no committed bilateral
# history is exactly the neutral 0.5 (see repprocess._consensus_baseline,
# final fallback). A real EMA over the demo's transaction scores (0.3 for an
# anomalous batch, 0.8 for a clean one) never lands exactly on 0.5, and a
# slash floors to 0.1 — so an exact-0.5 reading is the "no information yet"
# cold-start placeholder, not an earned score. The neutral test + the
# warm-start substitution that uses it now live in reputation_warmstart
# (is_neutral_rep / reconcile_rep_score), shared with tools/seed_dod_cohort.py.


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


class DoDMissionCoordinator(TransitiveTrustMixin, AutonomousTrust):
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
        # Dashboard warm-start: replace a pre-trusted peer's cold-start 0.5
        # with its seeded prior when it has no *earned* consensus to show.
        # Two cases qualify:
        #   * join_phase > 0   — joins too late to build history (the
        #                        fighter-jet's ~15 s strike window).
        #   * kind == soldier  — consumer-only (participant.py: squad members
        #                        run no data generator), so they never appear
        #                        as a counterparty in scored bilateral
        #                        transactions and their consensus stays at the
        #                        neutral baseline forever. Their trust is
        #                        pre-established (seeded), exactly as the
        #                        narration states ("pre-established trust with
        #                        their microdrones…"), so the dashboard should
        #                        show that seeded prior, not 0.5.
        #   * kind == microdrone — seeded in the persistent cohort (~0.7); their
        #                        earned build-up does not reliably surface via
        #                        the coordinator's consensus query (data-light /
        #                        group-churn-prone, more so since C-node interop
        #                        widened the field cohort), so they read
        #                        "forming…" indefinitely without warm-start. A
        #                        real rising score still overrides the prior the
        #                        moment one lands (reconcile_rep_score), so the
        #                        trust-dynamics build-up is unaffected when it
        #                        does surface. See reputation_warmstart
        #                        .is_warm_start_member (the authoritative set).
        # Keyed by roster name (== the local-part of the AT identity's online
        # nickname; see _roster_name_of). _reputations_view / _tiers_view apply
        # the same prior for a warm-start asset that never surfaces a score.
        self._warm_start_peers: set[str] = {
            p.name for p in scenario.peers.values()
            if is_warm_start_member(
                p.name, getattr(p, "join_phase", 0), p.kind)
        }
        # The coordinator's OWN AT node (nickname "coordinator") is the
        # observer, not a scenario peer, so the comprehension above never sees
        # it — yet is_warm_start_member treats it as infrastructure that should
        # read trusted from t=0. Add it explicitly so it surfaces its seeded
        # prior (0.70 / T2) instead of the cold-start 0.50 it would otherwise
        # show in its own dashboard. ("command" is a real scenario peer and is
        # already covered by the comprehension.)
        self._warm_start_peers.add("coordinator")
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
        # Stretch Goal 2 / Phase 3+4: per-(peer, world_uid) detection
        # cache so a peer reporting multiple distinct targets keeps
        # them all available to the drawer (the MQ-800 compromise
        # emits both an alpha lie and an honest bravo per tick; a
        # latest-wins per-peer cache would lose the lie). The flat
        # `_detection_per_peer` view that the dashboard reads is
        # derived in `_push_dashboard_update` by picking the
        # storyline-critical UID first, then the most-recent
        # overall. The per-peer log keeps every emission in arrival
        # order so the drawer's thumbnail strip carries history.
        self._detection_per_target: dict[tuple[str, str], dict] = {}
        self._detection_log_per_peer: dict[str, deque] = {}
        # nickname -> tier int (so _render_reputations can show both)
        self._tier_cache: dict[str, int] = {}
        # Mirror of the prior _query_reputations cycle's _tier_cache.
        # We diff the two each cycle so a tier demotion (new < prev)
        # produces a TIER_LOST event on the dashboard event log and in
        # the recording sidecar. Without this, AT's reputation process
        # publishes tier_lost on the negotiation queue (see
        # repprocess.py:_publish_tier_change) but it's invisible to the
        # coordinator's main process. Polling _tier off self.peers.all
        # is the lightest-weight bridge.
        self._prev_tier_cache: dict[str, int] = {}
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

        # --- Slashing (fast-penalty path) -----------------------------
        # The consensus EMA is structurally too slow for a short-lived
        # rogue (mq800 is active ~30s; at decimation 30 it samples ~1
        # bilateral tx, and the half-life-20 EMA barely moves before
        # exclusion freezes it -> "stuck at 0.5"). When we detect
        # SUSTAINED anomalies, or the scenario excludes a peer, emit a
        # signed SlashAttestation that floors the peer's reputation
        # immediately on the reputation chain (bypassing the EMA). See
        # repprocess.SlashAttestation / reputation-vs-blockchain-analysis.md.
        self._anomaly_streak: dict[str, int] = {}
        self._slashed_peers: set = set()
        # Peers the scenario has excluded (PEER_EXCLUDE). A forged-identity
        # sensor is rejected at the ZTA identity layer, so it never forms a
        # consensus chain and the exclusion slash can't resolve its uuid;
        # tracking the exclusion here lets _reputations_view floor its
        # displayed score deterministically (see that method).
        self._excluded_peers: set = set()
        # Live queues handle, set each tick by autonomous_tasking; used by
        # _on_scenario_event (which has no queues param of its own).
        self._task_queues = None
        # Anomalous SELECTED batches from one peer before we slash it.
        self._slash_threshold = int(
            os.environ.get("AT_SLASH_ANOMALY_THRESHOLD", "2"))
        self._slash_floor = float(
            os.environ.get("AT_SLASH_FLOOR", "0.1"))

        # Per-peer-per-datatype reading-snapshot decimation, used only
        # when an event recorder is attached. Default 1 records every
        # reading; raise via AT_RECORDING_READING_STRIDE to trim the
        # recording file for long runs. The chart panels still see
        # every reading on the live path — this only affects what
        # lands in the recording sidecar.
        self._recording_reading_stride = max(1, int(
            os.environ.get("AT_RECORDING_READING_STRIDE", "1")))
        self._reading_record_counts: dict[tuple[str, str], int] = {}

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
        # `coordinator.py` is invoked as a script (not a module), so the
        # sibling imports use bare names after the sys.path.insert(_HERE)
        # near the top of this file — same pattern as `from scenario ...`.
        from trust_ladder import register_trust_ladder  # local import
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
            # Roster of peers that PRODUCE data (have generator bundles in
            # participant._build_generators). The data sink subscribes to
            # these directly as a fallback when their `data` capability
            # advertisement never reaches it — a late joiner like the MQ-800
            # (T+4:00) can drop that advert, and then the cap-driven subscribe
            # path never lists it, so its readings never arrive and it is
            # never detected. See DiagDataRcvr._patched_process.
            _DATA_PRODUCER_KINDS = {
                "microdrone", "recon-drone", "armed-drone", "ground-sensor"}
            data_producers = {
                name for name, role in scenario.peers.items()
                if getattr(role, "kind", None) in _DATA_PRODUCER_KINDS}
            self.add_worker(DiagDataRcvr, cohort=self._cohort,
                            reading_drain=self._reading_drain,
                            data_producers=data_producers)

        # Subscribe to the scenario's event stream so we can record
        # PhaseEvents (PEER_JOIN, COMPROMISE_START, PEER_EXCLUDE) to
        # the canned-playback log alongside our own anomaly events.
        scenario.on_event(self._on_scenario_event)

        # Phase 6 #2 rank-gate: the Approach phase's gate predicate
        # polls this callable for the live tier view; the gate clears
        # only when ≥90% of admitted peers have peer._tier >= 1.
        # Attached as a scenario attribute so DoDMissionScenario
        # doesn't need a coordinator reference at construction time.
        scenario._tier_view_provider = lambda: dict(self._tier_cache)

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
            chart_keys=["target_x_chart", "noise_chart", "trust_network"],
            state_provider=lambda: self._latest_state,
            port=self._dashboard_port,
            narration_script=DOD_NARRATION,
            # Show the guiding narration (top-of-viewport overlay) from
            # the start; it can still be toggled off via Presentation Mode.
            presentation_default=True,
            peer_names=sorted(self.scenario.peers.keys()),
            # Open the Peer Detail drawer on the rq86-1 gateway by default
            # (falls back to empty if that peer isn't in the cohort).
            default_peer="rq86-1",
        )
        logger.info("Dashboard serving on :%d", self._dashboard_port)

    def autonomous_tasking(self, queues):
        self._tick_count += 1
        # Stash the live queues so callbacks without a queues param
        # (e.g. _on_scenario_event, fired from _advance_scenario_clock)
        # can submit slashes onto the reputation queue.
        self._task_queues = queues
        # Drain every tick — readings arrive at ~1 Hz per peer; if we
        # batch the drain to N>1 ticks we risk filling per-peer
        # data_stream queues (a small, fixed-size multiproc Queue
        # allocated from the QueuePool).
        self._drain_peer_readings(queues)
        # Query reputation every ~10s (20 ticks at the 500ms cadence) so an
        # earned consensus score surfaces on the dashboard promptly instead of
        # lagging up to a full ~30s behind the tx that produced it. The cohort
        # is small, so the extra consensus_rep_req fan-out is cheap; pre-trusted
        # assets already read their warm-start prior immediately
        # (_reputations_view), so this mainly accelerates the visible climb of
        # the cold-bootstrap field peers (sensors / rq86 / mq800).
        if self._tick_count % 20 == 0:
            self._query_reputations(queues)
        # Peer-of-peer (transitive) trust: ask each observer for its view of
        # every other subject over the network (TransitiveTrustMixin). Replies
        # land in self.latest_reputation_pairs (automate.py); _build_trust_matrix
        # turns them into the dashboard's Trust Network edges. Cadence ~= 60s
        # (PEER_PAIR_QUERY_SEC) at the 500ms tick, kept off the 20-tick direct
        # cadence since it is O(N^2).
        if self._tick_count % int(PEER_PAIR_QUERY_SEC / 0.5) == 0:
            self.query_peer_pairs(queues, logger=logger)
        # Flush the recording on its own (slower) cadence so a hard kill (or a
        # missed graceful-shutdown window — e.g. k8s teardown wiping the node)
        # can't discard the whole run; it's a durability backstop, not a display
        # path, so it need not track the query cadence. cleanup() still does a
        # final flush. No-op when recording is disabled.
        if self._tick_count % 60 == 0:
            self._flush_recording()
        # Advance the scenario clock so phases progress past Setup in
        # live mode. The Approach-phase gate (Phase 6 #2) consults the
        # live tier view attached above; until ≥90% of peers reach
        # tier ≥1 the scenario holds at Setup even after T+1:00. Pace
        # at 10 ticks (~5 s) so the gate sees fresh tier data without
        # flooding the log.
        if self._tick_count % 10 == 0:
            self._advance_scenario_clock()
            self._push_dashboard_update()

    def _advance_scenario_clock(self) -> None:
        """Tick the scenario forward to (now - tasking_start).

        The DoD coordinator does not use PlaybackInterface in live
        mode, so without this the scenario never leaves Setup and the
        dashboard phase indicator never updates. Idempotent: Scenario
        already guards against re-firing events past `current_phase`.
        """
        try:
            t = now() - self.tasking_start
        except Exception:
            return
        try:
            self.scenario.advance_to(t)
        except Exception:
            logger.exception("scenario.advance_to(%s) failed", t)

    _logged_first_drain = False
    _logged_first_reading = False
    _logged_first_peers = False
    _logged_first_batch_submit = False
    _logged_first_rep_drain = False
    _logged_first_batch_seen = False
    _logged_missing_task_id = False
    _logged_jet_gate = False

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
                # Log the bare roster names (online-nickname local-part), not
                # the arbitrary local petnames -- see _roster_name_of.
                sorted(_roster_name_of(p)
                       for p in self._cohort.peers.values()))
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
            # Bare roster name for log lines (online-nickname local-part); the
            # data path itself keys off the reading payload's peer_name.
            peer_name = _roster_name_of(peer) or uuid_str[:8]
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

    def _flush_recording(self, *, final: bool = False) -> None:
        """Persist the recording captured so far.

        Called periodically from autonomous_tasking (so an ungraceful exit
        can't lose the run) and once more on shutdown. Safe to call when
        recording is disabled (no-op) and to call repeatedly — ``save()``
        rewrites the file each time."""
        if self._event_recorder is None or not self._record_path:
            return
        try:
            self._event_recorder.save(
                self._record_path, scenario=self.scenario)
            n = len(self._event_recorder.events)
            if final:
                logger.info("Recorded %d events to %s",
                            n, self._record_path)
            else:
                logger.debug("Flushed %d events to %s (periodic)",
                             n, self._record_path)
        except Exception:
            logger.exception("Failed to save recording")

    def cleanup(self):
        """Flush the event log to disk on shutdown."""
        self._flush_recording(final=True)
        logger.info("DoD mission coordinator shutting down")

    # -- internal -------------------------------------------------------

    def _on_scenario_event(self, event):
        """Forward scenario events to the event log + playback record.

        On PEER_EXCLUDE, also issue a slash so the excluded peer's
        reputation reflects the exclusion verdict immediately rather than
        waiting for the slow consensus EMA (which, for a short-lived
        rogue, never catches up before exclusion freezes its chain)."""
        try:
            self._panels["event_log"].add_from_scenario_event(event)
        except Exception:
            logger.exception("Failed to forward scenario event to dashboard")
        if self._event_recorder is not None:
            self._event_recorder.record(event)
        # Compare by enum name to avoid importing PhaseEvent here.
        if (getattr(getattr(event, "event_type", None), "name", "")
                == "PEER_EXCLUDE"):
            peer_name = getattr(event, "peer_name", None)
            if peer_name:
                # Track the exclusion unconditionally so the dashboard can
                # floor the score even when the slash below is a no-op (a
                # forged-identity peer never joins, so its uuid won't resolve).
                self._excluded_peers.add(peer_name)
                self._submit_slash(
                    self._task_queues, peer_name,
                    reason=SlashAttestation.REASON_PEER_EXCLUDE,
                    floor=0.0)

    def _peer_uuid(self, peer_name):
        """Resolve a bare roster name to its peer UUID.

        Matches on the ONLINE nickname's local-part (the wire-carried, globally
        consistent name), NOT the local petname -- the petname is arbitrary on
        the receiver (random suffix) and never equals a roster name."""
        try:
            for p in self.peers.all:
                if _roster_name_of(p) == peer_name:
                    return p.uuid
        except Exception:
            logger.debug("peer-uuid lookup failed for %s", peer_name,
                         exc_info=True)
        return None

    def _submit_slash(self, queues, peer_name, reason, floor,
                      evidence_batch=None):
        """Put a SlashAttestation on the reputation queue (once per peer).

        The reputation process (forward_slash) stamps epoch/nonce, signs,
        self-applies the floor (so this coordinator's dashboard reflects
        it at once), and runs the co-sign quorum so peers adopt it too."""
        if peer_name in self._slashed_peers:
            return
        if queues is None:
            return
        uuid = self._peer_uuid(peer_name)
        if uuid is None:
            logger.warning("Slash: cannot resolve uuid for %s yet", peer_name)
            return
        att = SlashAttestation(
            slasher_uuid=self.identity.uuid, target_uuid=uuid,
            reason=reason, floor_score=floor,
            evidence_ref=((evidence_batch, None) if evidence_batch else None))
        try:
            queues[CfgIds.reputation].put(
                att, block=True, timeout=queue_cadence)
            self._slashed_peers.add(peer_name)
            logger.warning(
                "SLASH submitted: peer=%s reason=%s floor=%.2f",
                peer_name, reason, floor)
        except Exception:
            logger.exception("Failed to submit slash for %s", peer_name)

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
            # Diagnostic for the worker->main peer-propagation gap
            # (dod-coordinator-partition-nonconvergence.md, layer 3): the
            # IdentityProcess worker admits the mesh but `self.peers` (main
            # proc) stays tiny. group_addrs tells us whether Group broadcasts
            # reach main even when Peers broadcasts don't — if group_addrs is
            # large while peers.all stays ~1, the gap is specifically the
            # Peers fan-out / run_message_handlers application, not the queue.
            try:
                group_addrs = len(list(self.group.addresses)) \
                    if getattr(self, "group", None) is not None else 0
            except Exception:
                group_addrs = -1
            logger.info(
                "_query_reputations: tick=%d peers.all=%d group_addrs=%d "
                "latest_reputation=%d history items, last5=%r",
                self._tick_count, len(self.peers.all), group_addrs,
                len(self.latest_reputation),
                [(str(k)[:8], round(getattr(v, "score", -1), 3))
                 for k, v in list(self.latest_reputation.items())[-5:]])
            DoDMissionCoordinator._logged_first_rep_drain = True
        # Reconcile entries that resolve to the same display name before
        # touching the cache/timeline. A peer that re-keys or rejoins (see
        # the late-joiner handling) can leave a stale/forming uuid in
        # latest_reputation alongside its live one; the forming uuid scores
        # the neutral consensus baseline (0.5) while the live uuid carries
        # the real EMA. The old code fed BOTH to the timeline each cycle, so
        # a single peer's line drew two points per tick — its real score and
        # 0.5 — i.e. a sawtooth (and the reputations table flipped to
        # whichever uuid was iterated last). Collect candidate (score, tier)
        # per name, then keep ONE representative, preferring a real
        # (non-neutral) score over the 0.5 placeholder so a known reputation
        # never jumps to 0.5.
        candidates: dict[str, list[tuple[float, int]]] = {}
        for peer_id_str, rep in list(self.latest_reputation.items()):
            score = getattr(rep, "score", None)
            if score is None:
                continue
            peer = peers_by_uuid.get(str(peer_id_str))
            if peer is None:
                # A uuid no longer in peers.all — a peer that left, or the
                # stale identity of one that re-keyed (now deduped out by
                # Peers.add). Its entry lingers in latest_reputation with a
                # frozen value; skip it so it doesn't draw an orphan line.
                continue
            # Bare roster name from the ONLINE nickname's local-part (keys the
            # panel + maps to the scenario role). NOT the petname: that is
            # local-only and arbitrary on the receiver (random suffix), so it
            # never equals a roster name like "mq800". See _roster_name_of.
            name = _roster_name_of(peer)
            # Skip a peer that surfaced before its nickname resolved (e.g. a
            # half-admitted identity mid-handshake): an empty name renders as a
            # spurious blank-labelled row (T0 / 0.50) at the top of the panel.
            # It re-appears under its real name once the nickname lands.
            if not name or not str(name).strip():
                continue
            tier = int(getattr(peer, "_tier", 0))
            candidates.setdefault(name, []).append((float(score), tier))

        for name, vals in candidates.items():
            # Prefer a real (non-neutral) score; for a warm-start peer with
            # only the neutral cold-start placeholder (e.g. the fighter-jet,
            # present too briefly to build consensus) substitute its seeded
            # prior so a pre-trusted asset never reads untrusted while up.
            # Otherwise fall back to neutral (a genuinely cold/forming peer).
            # Cross-cycle stickiness (the name-keyed twin of the per-peer
            # running consensus EMA): when NO reading this cycle carries real
            # earned evidence — every candidate is the neutral cold-start
            # baseline — a peer that has already earned a score must NOT regress
            # to that placeholder. This happens when a peer's live identity uuid
            # briefly drops out of peers.all (churn) or a re-keyed/"forming"
            # uuid surfaces alone, leaving only the 0.5 baseline for the name
            # for a cycle or two; feeding it drew a per-peer sawtooth tooth
            # (drop to baseline, then re-climb). A REAL drop — a lower EMA or a
            # slash floor — is non-neutral, so it is NOT masked and still shows.
            score, new_tier = reconcile_rep_score_sticky(
                vals, name in self._warm_start_peers,
                self._reputation_cache.get(name), self._tier_cache.get(name))
            self._reputation_cache[name] = score
            self._feed_timeline(name, score)
            # Stash the peer's trust tier alongside the score so the
            # dashboard reputations panel can show both.
            prev_tier = self._prev_tier_cache.get(name)
            self._tier_cache[name] = new_tier
            if prev_tier is not None and new_tier < prev_tier:
                self._emit_tier_lost(name, prev_tier, new_tier)
            self._prev_tier_cache[name] = new_tier

    def _emit_tier_lost(self, peer_name: str, prev_tier: int,
                        new_tier: int) -> None:
        """Surface a peer's tier demotion to the dashboard + recording.

        Built on the same record shape as COMPROMISE_DETECT so the
        playback engine + event-log panel reuse the existing parser
        path. The `data.source="tier_change"` tag lets a tool split
        validator-driven anomalies from reputation-driven tier drops.
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
        if self._event_recorder is not None:
            self._event_recorder.record_snapshot({
                "t": t,
                "type": "REPUTATION_SAMPLE",
                "peer": peer_name,
                "score": float(score),
                # Carry the access tier alongside the score so canned
                # playback can colour the Reputations ladder + drive the
                # peer-detail status the same way the live dashboard does
                # (it has no _tier_cache to reach into). Defaults to 0
                # when the peer hasn't been tiered yet.
                "tier": int(self._tier_cache.get(peer_name, 0)),
            })

    def _cache_detection_reading(self, reading) -> dict:
        """Stash a detection-typed Reading in per-(peer, uid) caches.

        Stores a flat dict (rather than DetectionSummary) so the entry
        survives the data_queue pickle hop into the live_server callback
        process without needing the inspector import on the wire path.
        Returns the cached entry so callers (the recorder path) can
        persist it into the playback sidecar.
        """
        md = reading.metadata or {}
        world_uid = str(md.get("world_uid", ""))
        entry = {
            "peer_name": reading.peer_name,
            "world_uid": world_uid,
            "label": str(md.get("label", "")),
            "confidence": float(reading.value),
            "crop_b64": md.get("crop_b64") or "",
            "crop_size_px": tuple(md.get("crop_size_px") or (0, 0)),
            "bbox_in_crop_px": tuple(md.get("bbox_in_crop_px")
                                     or (0, 0, 0, 0)),
            "obb_in_crop_px": [list(p) for p in (md.get("obb_in_crop_px")
                                                 or [])],
            "target_latlon": tuple(md.get("target_latlon") or (0.0, 0.0)),
            "t_seconds": reading.timestamp.total_seconds(),
        }
        self._detection_per_target[(reading.peer_name, world_uid)] = entry
        log = self._detection_log_per_peer.get(reading.peer_name)
        if log is None:
            log = deque(maxlen=DETECTION_LOG_CAPACITY)
            self._detection_log_per_peer[reading.peer_name] = log
        log.append(entry)
        return entry

    # Priority list for `_pick_primary_detection_per_peer`. World UIDs
    # that appear earlier "win" the per-peer slot, even if a later
    # detection arrived for a lower-priority UID. This is what keeps
    # MQ-800's compound-alpha lie visible to the operator even when
    # MQ-800 also reports an honest compound-bravo on the same tick.
    DETECTION_PRIORITY_UIDS = ("compound-alpha", "compound-bravo")

    def _pick_primary_detection_per_peer(self) -> dict[str, dict]:
        """Collapse the (peer, uid) cache to one entry per peer.

        Order of preference: storyline-critical UIDs (per
        DETECTION_PRIORITY_UIDS) first, then most-recent t_seconds.
        """
        out: dict[str, dict] = {}
        by_peer: dict[str, list[dict]] = {}
        for (peer, _uid), entry in self._detection_per_target.items():
            by_peer.setdefault(peer, []).append(entry)
        for peer, entries in by_peer.items():
            for priority_uid in self.DETECTION_PRIORITY_UIDS:
                hit = next((e for e in entries
                            if e["world_uid"] == priority_uid), None)
                if hit is not None:
                    out[peer] = dict(hit)
                    break
            else:
                out[peer] = dict(max(entries, key=lambda e: e["t_seconds"]))
        return out

    def _reputations_view(self, t_seconds: float = 0.0) -> dict:
        """Reputations for the dashboard, completed with pre-established peers.

        Every pre-established peer (join_phase 0) should be forming a
        consensus reputation by the Approach beat, so surface all of them
        even before a consensus score has landed: such a peer maps to
        ``None``, which the panel renders as "forming…" rather than the
        peer being silently absent (which read as "only rq86-1 has a
        reputation"). Peers with a consensus score show it; later joiners
        appear once scored.
        """
        reps: dict = dict(self._reputation_cache)
        try:
            for role in self.scenario.peers.values():
                if role.name in reps:
                    continue
                # Only surface a peer's row once it has actually arrived on the
                # map/narrative (peer_reputation_visible) — a pre-established
                # asset is visible from t=0, a late joiner (MQ-800 T+4:00, jet
                # at its dynamic launch) only when it checks in. Showing a late
                # joiner's row before then read as confusing ("why is the rogue
                # already listed?"); showing it only after it earns consensus
                # lagged the map/narrative. This tracks arrival instead.
                if not self.scenario.peer_reputation_visible(
                        role.name, t_seconds):
                    continue
                # A WARM-START asset (microdrone/soldier/jet/command) reads its
                # seeded prior, NOT "forming…": the warm-start in
                # _query_reputations only fires once a peer surfaces in
                # latest_reputation, which is unreliable for these data-light /
                # churn-prone peers (see reputation_warmstart). A real
                # (non-neutral) score still overrides it the moment one lands.
                # A non-warm-start peer (e.g. the rogue MQ-800) reads "forming…"
                # (None) until it earns its real — and soon-slashed — score.
                reps[role.name] = (SEED_REPUTATION
                                   if role.name in self._warm_start_peers
                                   else None)
        except Exception:
            logger.debug("reputations-view roster merge failed",
                         exc_info=True)
        # Deterministic untrusted-floor, mirroring the trust verdict:
        #   ZTA invalid (forged identity) -> 0.0 (untrusted the moment known)
        #   excluded but ZTA-valid        -> slash floor (sub-0.5, untrusted)
        #
        # PRIMARY MECHANISM (2026-06-03): forged-identity sensors are now
        # rejected at the IDENTITY LAYER by the ZTA admission gate
        # (idprocess.welcoming_committee + identity/zta/; provisioned by
        # tools/provision_zta_certs.py). A rejected peer never joins, never
        # gets scored, and so never appears in self._reputation_cache — the
        # `forged_identity` floor below no longer fires in a ZTA-enabled run.
        # It is retained as a DASHBOARD FALLBACK for ZTA-disabled runs (no
        # zta_policy / no mission CA): there the hacked sensor would otherwise
        # sit at the cold-start 0.5 baseline, so we still floor it to 0.0 as
        # soon as it surfaces a reputation or is excluded (independent of the
        # scripted PEER_EXCLUDE, which can lag if the bootstrap gate holds the
        # clock at Setup). Floors only peers already present (or excluded) so
        # we never conjure an absent peer; min() so we never raise a peer
        # already lower. Clean sensors untouched. See zta-python-parity.md.
        # TODO(follow-up): surface the actual ZTA rejection as a dashboard
        # event (cross-process plumbing from the worker idprocess), then this
        # fallback can be dropped entirely.
        for role in self.scenario.peers.values():
            name = role.name
            zta_invalid = bool((getattr(role, "metadata", None) or {})
                               .get("forged_identity"))
            excluded = name in self._excluded_peers
            if zta_invalid and (name in reps or excluded):
                floor = 0.0
            elif excluded:
                floor = self._slash_floor
            else:
                continue
            existing = reps.get(name)
            reps[name] = (min(existing, floor)
                          if isinstance(existing, (int, float)) else floor)
        return reps

    def _tiers_view(self, t_seconds: float = 0.0) -> dict:
        """Trust tiers for the dashboard, completed in lockstep with
        _reputations_view: a pre-established warm-start asset that has no
        earned tier yet reads its seeded tier (SEED_TIER) rather than T0, so
        the reputations panel shows a consistent (score, tier) pair instead of
        "0.70 / T0". A peer with a real cached tier keeps it (set together with
        its real score in _query_reputations), so an earned tier still wins.
        """
        tiers = dict(self._tier_cache)
        for role in self.scenario.peers.values():
            if (role.name not in tiers
                    and role.name in self._warm_start_peers
                    and self.scenario.peer_reputation_visible(
                        role.name, t_seconds)):
                tiers[role.name] = SEED_TIER
        return tiers

    def _build_trust_matrix(self, t_seconds: float = 0.0):
        """Undirected bilateral trust edges for the dashboard Trust Network.

        Built from ``self.latest_reputation_pairs`` (populated by the peer-pair
        query round): each ``(observer_uuid, subject_uuid) -> rep`` is resolved
        to roster names and the two directional views of a pair are min-combined
        (skepticism-wins). Returns ``list[(observer, subject, score)]`` — the
        shape ``build_graph_from_scenario(trust_matrix=...)`` consumes.

        Warm-start applies at two points:

        * *Substitution* — a directional reading whose SUBJECT is a pre-trusted
          asset with no earned bilateral history yet is a cold-start neutral
          (PREREP_NEUTRAL on both the pure and tit-for-tat paths, which the
          reverted signed-scale framing once split into 0.5 and 0.0), the same
          reason its Reputations-panel score is warm-started
          (reconcile_rep_score).
          ``warm_start_edge_score`` surfaces the seeded prior so it draws an edge
          instead of dropping off the graph. A real reading — including earned
          skepticism — is left as-is, so the skepticism-wins min-combine still
          lets genuine low trust override the prior.

        * *Pre-established mesh* — the seeded cohort (``is_pre_trusted``:
          squad-/microdrone-/jet-) mutually trusts at SEED_REPUTATION from t=0
          (tools/seed_dod_cohort writes it into each member's
          reputation.cfg.json). That trust EXISTS before any query, so it must
          show IMMEDIATELY — not wait for the first O(N^2) peer-pair round
          (~tick 120) to route and return, which left the graph edgeless for the
          first ~1–2 min. It is drawn from the scenario ROSTER and gated by
          ``peer_reputation_visible`` (the same arrival gate _reputations_view
          uses, so the Trust Network and Reputations panels agree on when a
          cohort member appears — the jet stays off the graph until its launch).
          ``setdefault`` makes it a FALLBACK: a real earned reading (or a
          cold-start one already substituted above) always wins over the seed.
        """
        warm = self._warm_start_peers
        combined: dict[tuple[str, str], float] = {}
        pairs = getattr(self, "latest_reputation_pairs", None)
        if pairs:
            name_of = {str(p.uuid): (_roster_name_of(p) or str(p.uuid))
                       for p in self.peers.all}
            for (obs_uuid, subj_uuid), rep in list(pairs.items()):
                obs = name_of.get(str(obs_uuid))
                subj = name_of.get(str(subj_uuid))
                if not obs or not subj or obs == subj:
                    continue
                try:
                    score = float(getattr(rep, "score", rep))
                except (TypeError, ValueError):
                    continue
                score = warm_start_edge_score(score, subj in warm)
                key = tuple(sorted((obs, subj)))
                combined[key] = (min(combined[key], score)
                                 if key in combined else score)
        try:
            cohort = sorted(
                r.name for r in self.scenario.peers.values()
                if is_pre_trusted(r.name)
                and self.scenario.peer_reputation_visible(r.name, t_seconds))
        except Exception:
            logger.debug("trust-matrix warm-start mesh failed", exc_info=True)
            cohort = []
        for i, a in enumerate(cohort):
            for b in cohort[i + 1:]:
                combined.setdefault(tuple(sorted((a, b))), SEED_REPUTATION)
        # Isolation policy: some assets are group-restricted (microdrones ->
        # ODA-only; command -> rq86-*/ODA-only), so drop any edge the topology
        # forbids -- whether it came from the seeded mesh or a real peer-pair
        # reading. Applied last so it governs both sources uniformly.
        agency_of = {r.name: getattr(r, "agency", "")
                     for r in self.scenario.peers.values()}
        return [(a, b, s) for (a, b), s in combined.items()
                if _trust_edge_allowed(a, agency_of.get(a, ""),
                                       b, agency_of.get(b, ""))]

    def _push_dashboard_update(self):
        # Scenario seconds since tasking_start — falls back to tick-derived
        # estimate (AT runs at ~500ms cadence) until tasking_start is set.
        try:
            t_seconds = (now() - self.tasking_start).total_seconds()
        except Exception:
            t_seconds = self._tick_count * 0.5
        self._latest_state = {
            "reputations": self._reputations_view(t_seconds),
            "tiers": self._tiers_view(t_seconds),
            # Peer-of-peer trust edges for the Trust Network panel (Stage 5).
            "trust_matrix": self._build_trust_matrix(t_seconds),
            # Live narration gates for beats whose real moment floats. The jet
            # strike is gated on the jet actually reaching the objective (its
            # launch is gated on the MQ-800 collapse, so the strike time floats
            # later than the authored t_start). See narration_script / the
            # NarrationOverlay.advance_to gates arg.
            "narration_gates": {
                "jet_over_target": self.scenario.jet_over_objective(t_seconds),
            },
            # True (drifting) ISR target lat/lon so the map's microdrone FOV
            # wedges point where the target actually IS, not the static squad
            # hold (GROUND_MID) the drones loiter on. See target_position_map.
            "target_latlon": self.scenario.true_target_latlon(t_seconds),
            "tick": self._tick_count,
            "t_seconds": t_seconds,
            "phase": (self.scenario.current_phase.name
                      if self.scenario.current_phase else None),
            # Stretch Goal 2 / Phase 3+4: dashboard-facing flat view.
            # detection_per_peer collapses the (peer, uid) cache to
            # the storyline-critical UID (compound-alpha) when
            # available, so the inspector drawer + AgencyMap marker
            # show the MQ-800 lie instead of the peer's most-recent
            # honest reading. detection_per_target carries the full
            # per-(peer, uid) cache for components that want all of
            # a peer's contacts. Age computed at render time against
            # t_seconds.
            # Static role lookups so the drawer can render the
            # header (agency, kind) without reaching back into the
            # scenario object across the data_queue boundary.
            "agencies": {p.name: p.agency
                         for p in self.scenario.peers.values()},
            "kinds": {p.name: p.kind
                      for p in self.scenario.peers.values()},
            # Live squad + microdrone positions for the target-position
            # map's asset markers. Updated each tick by the scenario's
            # movement model (scenario.advance_to). See
            # TargetPositionMapPanel.set_platforms.
            "platforms": {
                p.name: {"lat": p.position.lat, "lon": p.position.lon,
                         "alt": p.position.alt, "kind": p.kind,
                         "color": p.color}
                for p in self.scenario.peers.values()
                if p.kind in ("soldier", "microdrone",
                              "recon-drone", "armed-drone",
                              "fighter-jet", "ground-sensor")
                # Don't draw a late joiner (MQ-800 @ T+4:00, sensors @ T+2:00)
                # before it actually arrives — else it sits at its roster
                # position from t=0 and reads as "already here". peer_active
                # also drops the two ECM microdrone casualties before exfil.
                and self.scenario.peer_active(p.name, t_seconds)
            },
            # Detection markers follow the same active-peer gate so a lost
            # microdrone's last detection doesn't linger on the map after it
            # has dropped off.
            "detection_per_peer": {
                peer: entry
                for peer, entry in self._pick_primary_detection_per_peer().items()
                if self.scenario.peer_active(peer, t_seconds)
            },
            "detection_per_target": {
                f"{peer}|{uid}": dict(entry)
                for (peer, uid), entry
                in self._detection_per_target.items()
                if self.scenario.peer_active(peer, t_seconds)
            },
            "detection_log_per_peer": {
                k: [dict(entry) for entry in log]
                for k, log in self._detection_log_per_peer.items()
                if self.scenario.peer_active(k, t_seconds)
            },
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
        # Stretch Goal 2 / Phase 3: detection-typed readings hold the
        # full crop + metadata for the inspector. They don't feed the
        # numeric charts; drop them into the per-peer cache and skip
        # the chart fan-out + validator loop (the parallel
        # target_position_x/y readings are what the validators score).
        if reading.data_type == "detection":
            entry = self._cache_detection_reading(reading)
            # Persist the detection (crop + bbox + label + UID) into the
            # playback sidecar so the canned-playback peer-detail drawer
            # can rebuild detection_per_peer / detection_log_per_peer —
            # there is no live AT mesh in playback to re-emit these, and
            # the crop imagery isn't otherwise reconstructable. Detection
            # emissions are sparse (time-floor + per-UID suppression in
            # generators/detection.py), so recording every one is cheap.
            if self._event_recorder is not None and entry is not None:
                snap = dict(entry)
                snap["t"] = reading.timestamp.total_seconds()
                snap["type"] = "DETECTION"
                snap["peer"] = reading.peer_name
                self._event_recorder.record_snapshot(snap)
            return
        if reading.data_type == "detection_heartbeat":
            # No visible state to update — the cache stays as-is so
            # the drawer keeps showing the most-recent real detection.
            return

        # Fan the reading to both sensor charts; each ignores mismatched
        # data_types internally, so the dispatch stays simple.
        for chart_key in ("target_x_chart", "noise_chart"):
            try:
                self._panels[chart_key].add_reading(reading)
            except Exception:
                logger.exception("Failed to forward reading to %s", chart_key)
        # Stash a snapshot of the reading so canned playback can replay
        # what the live charts showed. Decimated per
        # (peer, data_type) by self._recording_reading_stride.
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
                # Anomaly time on the coordinator SCENARIO clock
                # (now - tasking_start) — the same clock that drives the jet
                # position, phase events, and _jet_launch_time. NOT
                # result.timestamp: that is reading.timestamp, stamped on the
                # producer's AT_DEMO_T0_EPOCH (launcher) clock, which precedes
                # tasking_start by the coordinator's boot/bootstrap offset. Using
                # it armed gate_jet_on_anomaly that many seconds late, sliding the
                # jet strike late live AND in playback (the recorded marker's "t"
                # below re-arms the gate). Falls back to the tick-derived estimate
                # until tasking_start is set, mirroring _push_dashboard_update.
                try:
                    t_sec = (now() - self.tasking_start).total_seconds()
                except Exception:
                    t_sec = self._tick_count * 0.5
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
                # Release the gated fighter-jet strike once the rogue is
                # actually exposed. The validator detection is the reliable
                # signal in both live and playback (it fires whenever the
                # rogue's data diverges and is recorded as a src="validator"
                # COMPROMISE_DETECT); a slash may never resolve the rogue's
                # uuid, so it is NOT a dependable gate. First (rogue) hit wins;
                # non-rogue peers are ignored inside gate_jet_on_anomaly.
                try:
                    self.scenario.gate_jet_on_anomaly(result.peer_name, t_sec)
                    if (not DoDMissionCoordinator._logged_jet_gate
                            and getattr(self.scenario,
                                        "_jet_anomaly_sec", None) is not None):
                        logger.warning(
                            "JET GATE armed by %s anomaly at t=%.1fs — "
                            "jet will launch shortly",
                            result.peer_name, self.scenario._jet_anomaly_sec)
                        DoDMissionCoordinator._logged_jet_gate = True
                except Exception:
                    logger.exception("Failed to gate jet on anomaly for %s",
                                     result.peer_name)
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
                # Sustained-anomaly slash: count anomalous SELECTED batches
                # per peer; past the threshold, floor its reputation now
                # via a slash (the 0.3 TS above still records the bilateral
                # defection on-chain, but the slash is what makes the score
                # drop within the rogue's short active window).
                if is_anomaly:
                    pname = state.get("peer_name")
                    if pname:
                        self._anomaly_streak[pname] = (
                            self._anomaly_streak.get(pname, 0) + 1)
                        if (self._anomaly_streak[pname]
                                >= self._slash_threshold):
                            self._submit_slash(
                                queues, pname,
                                reason=(SlashAttestation
                                        .REASON_SUSTAINED_ANOMALY),
                                floor=self._slash_floor,
                                evidence_batch=batch_id)
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
        format=LOG_FORMAT, datefmt=LOG_DATEFMT,
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

    # Give the coordinator's AT node a stable, human-readable identity
    # instead of a random codename (e.g. "SafeKing") so it shows as
    # "coordinator" in the reputations list / trust graph. AT_PEER_NAME is
    # the same hook participants use to carry their scenario role name into
    # the AT identity nickname; honor a deployment-provided value if set.
    os.environ.setdefault("AT_PEER_NAME", "coordinator")

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
    # Default to forkserver: 'fork' (Linux default through 3.13) forks a
    # multi-threaded process and can deadlock the child. Harmless on 3.14+.
    import multiprocessing as _mp
    _mp.set_start_method('forkserver', force=True)
    main()
