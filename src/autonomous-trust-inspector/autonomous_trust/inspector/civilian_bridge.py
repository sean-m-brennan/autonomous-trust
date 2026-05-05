# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ******************

"""Stage-3a civilian live-mode bridge.

The civilian dashboard runs in the main process as a Dash server.
To observe real AT peers, we spawn a parallel Inspector in a daemon
thread that joins the AT network and pushes observations into a
shared multiprocessing queue. The Dash tick callback drains the queue
and annotates the scenario with live events.

Intentional limits (Stage 3a):
    - Peer-id to scenario-name matching is best-effort (nickname),
      pending AT_PEER_NAME -> identity propagation.
    - Observations annotate the event log but do NOT yet replace
      _rep_samples synthesis (timeline keeps synthesized shape).
    - Exclusion / compromise detection is inferred by Stage 3b.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from queue import Empty, Full
from typing import Optional

from autonomous_trust.core import (
    CfgIds, LogLevel, Process, ProcMeta, from_yaml_string,
)
from autonomous_trust.core.capabilities import PeerCapabilities
from autonomous_trust.core.config import to_json_string
from autonomous_trust.core.identity.peers import Peers
from autonomous_trust.core.network import Network, Message
from autonomous_trust.core.reputation.protocol import ReputationProtocol
from autonomous_trust.core.system import queue_cadence
from autonomous_trust.core._python import _probes
from autonomous_trust.services.data.server import DataProtocol

from .inspector import Inspector


logger = logging.getLogger(__name__)

# Bridge event tuple shapes. First element is the tag.
#   ("peer_seen",  name:str)
#   ("reputation", name:str, score:float, wall_t:float)
#   ("ping",       name:str, rtt_ms:float, wall_t:float)
#   ("rep_pair",   observer:str, subject:str, score:float, wall_t:float)
#       — Stage 3b.3(a) bilateral observation: observer's view of subject.
#   ("reading",    peer:str, reading_dict:dict, wall_t:float)
#       — Stage 3b.4 envdata stream: a single Reading.to_dict() emitted by
#         a NOAA / USGS / EPA / FEMA peer's EnvData* worker.
#   ("peer_gone",  name:str)   # Stage 3b future
BRIDGE_QUEUE_MAX = 1024

# Send a peer-to-peer reputation-query round every PEER_PAIR_QUERY_SEC.
# O(N²) round-trips per round, but N is small (~10 peers) and the network
# can absorb 100 messages/min easily.
PEER_PAIR_QUERY_SEC = 60.0

# Capabilities the bridge subscribes to over the network. Each maps to
# the remote process's queue name so Message(proc_target, request, ...)
# lands on the right peer worker.
_RCVR_CAP_TO_PROC = {
    'weather_stream':    'weather-stream',
    'seismic_stream':    'seismic-stream',
    'airquality_stream': 'airquality-stream',
    'situation_report':  'situation-report',
    'data_fusion':       'data-fusion',
}


def _peer_name(identity_obj) -> str:
    """Best-effort identity -> display name.

    AT Identity has .nickname, .fullname, .uuid. For the civilian demo
    we prefer nickname (matches scenario's 'noaa-1' style when AT_PEER_NAME
    propagation is wired; Stage 3b). Falls back to str() if none set.
    """
    for attr in ("nickname", "fullname"):
        v = getattr(identity_obj, attr, None)
        if v:
            return str(v)
    return str(identity_obj)


class BridgeDataRcvr(Process, metaclass=ProcMeta,
                     proc_name='bridge-data-rcvr',
                     description='Civilian inspector envdata receiver',
                     cfg_name='bridge-data-rcvr'):
    """Forkserver-child worker that subscribes to peer envdata streams
    and forwards each Reading dict directly to the inspector bridge
    queue.

    Differs from `services.data.client.DataRcvr` in two ways:

      1. It subscribes to the disaster-response capability surface
         (weather / seismic / airquality / situation_report / data_fusion)
         rather than the generic 'data' capability.
      2. It bypasses Cohort-based routing — there's no Cohort on the
         inspector side, only the Manager-backed `bridge_queue` shared
         with the Dash callback.

    Lives in the inspector container; instantiated via
    `CivilianInspectorBridge.add_worker(BridgeDataRcvr, bridge_queue=...)`.
    """

    def __init__(self, configurations, subsystems, log_queue, dependencies,
                 **kwargs):
        super().__init__(configurations, subsystems, log_queue,
                         dependencies=dependencies)
        self._bridge_queue = kwargs['bridge_queue']
        # (cap_name, peer_uuid_str) tuples we've already sent a request to.
        self._servicers: set = set()
        self.protocol = DataProtocol(self.name, self.logger, configurations)
        self.protocol.register_handler(DataProtocol.data, self._handle_data)

    def _handle_data(self, _queues, message):
        if message.function != DataProtocol.data:
            return False
        _probes.counter('bridge.rcvr', 'handle_data')
        peer_obj = getattr(message, "from_whom", None)
        peer_name = _peer_name(peer_obj) if peer_obj is not None else "?"
        try:
            reading = message.obj
            if isinstance(reading, str):
                reading = from_yaml_string(reading)
            if not isinstance(reading, dict):
                _probes.counter('bridge.rcvr', 'data_bad_shape')
                return True  # accepted but unhandled shape
            self._bridge_queue.put_nowait(
                ("reading", peer_name, reading, time.time()))
            _probes.counter('bridge.rcvr', 'data_forwarded')
        except Full:
            # Dash side isn't draining; not fatal.
            _probes.counter('bridge.rcvr', 'queue_full')
        except Exception:
            _probes.counter('bridge.rcvr', 'data_exc')
            self.logger.debug("dropping malformed reading from %s",
                              peer_name, exc_info=True)
        return True

    def _subscribe_to_new_peers(self, queues):
        """Send a DataProtocol.request to any peer advertising one of
        the disaster envdata capabilities, once per (cap, peer) pair."""
        peer_caps = self.protocol.peer_capabilities
        _probes.counter('bridge.rcvr', 'subscribe_called')
        if not peer_caps:
            _probes.counter('bridge.rcvr', 'subscribe_no_caps')
            return
        try:
            cap_count = len(peer_caps)
        except Exception:
            cap_count = -1
        _probes.counter('bridge.rcvr', 'peer_caps_size', str(cap_count))
        peers_index = self.protocol.peers
        for cap, proc_target in _RCVR_CAP_TO_PROC.items():
            try:
                peer_uuids = peer_caps[cap]
            except KeyError:
                _probes.counter('bridge.rcvr', 'cap_missing', cap)
                continue
            _probes.counter('bridge.rcvr', 'cap_found', cap,
                            n=len(peer_uuids) if peer_uuids else 0)
            for peer_uuid in peer_uuids:
                key = (cap, str(peer_uuid))
                if key in self._servicers:
                    continue
                identity = peers_index.find_by_uuid(peer_uuid) \
                    if peers_index is not None else None
                if identity is None:
                    # Peer's Identity hasn't reached us yet; try again
                    # next iteration.
                    _probes.counter('bridge.rcvr', 'no_identity_yet', cap)
                    continue
                msg = Message(proc_target, DataProtocol.request,
                              self.name, identity)
                try:
                    queues[CfgIds.network].put(msg, block=True,
                                               timeout=self.q_cadence)
                    self._servicers.add(key)
                    _probes.counter('bridge.rcvr', 'subscribe_sent', cap)
                except Full:
                    _probes.counter('bridge.rcvr', 'subscribe_q_full', cap)
                    self.logger.debug(
                        "network queue full; deferring subscribe %s -> %s",
                        cap, peer_uuid)

    def process(self, queues, signal):
        _probes.counter('bridge.rcvr', 'process_started')
        while self.keep_running(signal):
            _probes.counter('bridge.rcvr', 'iter')
            self._subscribe_to_new_peers(queues)
            try:
                message = queues[self.name].get(block=True,
                                                timeout=self.q_cadence)
            except Empty:
                message = None
            if message is None:
                continue
            _probes.counter('bridge.rcvr', 'msg_recv',
                            type(message).__name__)
            # CivilianInspectorBridge.autonomous_tasking forwards the
            # bridge's peer_capabilities + peers roster onto our queue
            # (see civilian_bridge.py:241-248). Without these, our
            # DataProtocol.peer_capabilities stays empty and
            # _subscribe_to_new_peers never finds any cap to subscribe
            # to. Update the protocol's view directly when we recognize
            # the payload; fall through to the generic message handlers
            # for everything else (DataProtocol.data replies, etc.).
            if isinstance(message, PeerCapabilities):
                # Bridge-rcvr receives PeerCapabilities from TWO sources:
                #   - direct fan-put from idproc via _remember_activity
                #     (with the framework fix it includes PeerCapabilities)
                #   - forward from CivilianInspectorBridge.autonomous_tasking,
                #     which reads main proc's view of peer_capabilities.
                # main proc's view lags behind idproc's because main is
                # heavily backlogged (102k rep_resp messages, processed
                # one-per-500ms), so its forwards routinely carry a
                # smaller set of caps than idproc has. Naively replacing
                # `self.protocol.peer_capabilities = message` lets a
                # stale 8-key forward downgrade a freshly arrived 9-key
                # direct fan-put — manifested as EPA's airquality_stream
                # being seen by idproc but never reaching bridge-rcvr.
                # Accept only updates that strictly grow (or replace
                # nothing): if incoming has fewer keys than what we
                # already hold, drop it.
                cur = self.protocol.peer_capabilities
                cur_n = len(cur) if cur is not None else 0
                inc_n = len(message)
                if inc_n >= cur_n:
                    self.protocol.peer_capabilities = message
                    _probes.counter('bridge.rcvr', 'caps_accept',
                                    f'{cur_n}->{inc_n}')
                else:
                    _probes.counter('bridge.rcvr', 'caps_reject_shrink',
                                    f'{cur_n}->{inc_n}')
                continue
            if isinstance(message, Peers):
                self.protocol.peers = message
                continue
            self.protocol.run_message_handlers(queues, message)


class CivilianInspectorBridge(Inspector):
    """Inspector subclass that shadows the stock observer but routes
    reputation / peer-roster events to a bridge queue instead of its
    own VizServer. The CivilianDemo's Dash callback drains the queue."""

    def __init__(self, bridge_queue, **kwargs):
        super().__init__(**kwargs)
        self._bridge_queue = bridge_queue
        self._seen: set[str] = set()
        self._last_rep: dict[str, float] = {}
        # (observer_uuid_str, subject_uuid_str) -> last-pushed score.
        # Used to suppress no-op rep_pair pushes when nothing changed.
        self._last_pair: dict[tuple[str, str], float] = {}
        # Stage 3b.4: stream readings come in via BridgeDataRcvr.
        # The Dash side drains the same `bridge_queue` so no separate
        # plumbing is needed here; we just register the worker.
        self.add_worker(BridgeDataRcvr, self.system_dependencies,
                        bridge_queue=bridge_queue)

    def init_tasking(self, queues):
        # No VizServer — the civilian demo runs its own Dash server in
        # the main process.
        pass

    def cleanup(self):
        pass

    def _resolve_name(self, uuid_str: str) -> str:
        """Look up a peer's display name by uuid string.

        latest_reputation keys are uuid strings (from rep.peer_id), not
        Identity objects, so _peer_name on them falls through to str(uuid).
        Resolve via self.peers so the bridge events carry the scenario
        nickname (e.g. 'noaa-1').
        """
        peer = self.peers.find_by_uuid(uuid_str)
        if peer is not None:
            return _peer_name(peer)
        if self.identity is not None and str(self.identity.uuid) == uuid_str:
            return _peer_name(self.identity)
        return uuid_str

    def autonomous_tasking(self, queues):
        _probes.counter('bridge.task', 'enter')
        _probes.counter('bridge.task', 'peers_all', str(len(self.peers.all)))
        # Forward latest peer_capabilities + peer roster to BridgeDataRcvr.
        # idproc only broadcasts these to `main` and `negotiation`; without
        # this push, the rcvr's protocol.peer_capabilities and .peers stay
        # at the empty defaults from its __init__ and it never subscribes.
        rcvr_q = queues.get(BridgeDataRcvr.name)
        if rcvr_q is None:
            _probes.counter('bridge.task', 'rcvr_q_missing')
        else:
            _probes.counter('bridge.task', 'rcvr_q_present')
            try:
                pc_size = len(self.peer_capabilities) \
                    if self.peer_capabilities is not None else -1
            except Exception:
                pc_size = -1
            _probes.counter('bridge.task', 'fwd_pc_size', str(pc_size))
            for payload in (self.peer_capabilities, self.peers):
                if payload is None:
                    _probes.counter('bridge.task', 'fwd_skip_none')
                    continue
                try:
                    rcvr_q.put(payload, block=True, timeout=queue_cadence)
                    _probes.counter('bridge.task', 'fwd_put',
                                    type(payload).__name__)
                except Exception:
                    _probes.counter('bridge.task', 'fwd_put_exc')
        # Reuse the stock inspector's per-peer query cadence (rep+ping).
        if self.tasking_tick(1):  # ~30s
            _probes.counter('bridge.task', 'tick1_fired')
            for peer in self.peers.all:
                try:
                    query = Message(
                        CfgIds.reputation,
                        ReputationProtocol.rep_req,
                        to_json_string((peer, self.proc_name)),
                        self.identity,
                        from_whom=self.identity,
                    )
                    queues[CfgIds.reputation].put(
                        query, block=True, timeout=queue_cadence)
                    # return_to is a *queue name*, not the class display
                    # name. proc_name resolves to 'main' (the AT
                    # top-level queue) via Protocol.__init__.
                    # netproc dispatches ping() into a thread pool, so
                    # this no longer blocks the main loop.
                    ping = Message(CfgIds.network, Network.ping, 5,
                                   peer, return_to=self.proc_name)
                    queues[CfgIds.network].put(
                        ping, block=True, timeout=queue_cadence)
                except Exception:
                    logger.exception("[bridge] failed to query peer %r",
                                     peer)
                name = _peer_name(peer)
                if name not in self._seen:
                    self._seen.add(name)
                    self._push(("peer_seen", name))

        # Stage 3b.3(a): peer-to-peer reputation queries. Ask each peer
        # (observer) for its view of every OTHER peer (subject). Goes
        # over the network so the remote peer's ReputationProcess is the
        # one that computes. Responses arrive as rep_resp on the AT main
        # loop, captured into latest_reputation_pairs by automate.py.
        # from_whom MUST be set so the responding peer's
        # forward_reputation can route the rep_resp back over the
        # network (else requestor=None and the response stays local).
        if self.tasking_tick(3, PEER_PAIR_QUERY_SEC):
            _probes.counter('bridge.task', 'tick3_fired')
            peers = list(self.peers.all)
            _probes.counter('bridge.task', 'tick3_peers', str(len(peers)))
            for observer in peers:
                for subject in peers:
                    if str(observer.uuid) == str(subject.uuid):
                        continue
                    try:
                        query = Message(
                            CfgIds.reputation,
                            ReputationProtocol.rep_req,
                            to_json_string((subject, self.proc_name)),
                            observer,  # routed over the network
                            from_whom=self.identity,
                        )
                        _probes.counter('bridge.task', 'tick3_msg_built')
                        queues[CfgIds.network].put(
                            query, block=True, timeout=queue_cadence)
                        _probes.counter('bridge.task', 'tick3_msg_queued')
                    except Exception:
                        _probes.counter('bridge.task', 'tick3_exc')
                        logger.exception(
                            "[bridge] failed peer-pair rep_req %r->%r",
                            observer, subject)

        if self.tasking_tick(2, 5.0):  # ~5s
            now = time.time()
            for subject_uuid, rep in self.latest_reputation.items():
                try:
                    score = float(getattr(rep, "score", rep))
                except (TypeError, ValueError):
                    continue
                name = self._resolve_name(subject_uuid)
                prev = self._last_rep.get(name)
                if prev is None or abs(prev - score) >= 0.05:
                    self._last_rep[name] = score
                    self._push(("reputation", name, score, now))

            # Bilateral: emit rep_pair events with observer + subject names.
            pairs = getattr(self, "latest_reputation_pairs", None)
            if pairs:
                for (obs_uuid, sub_uuid), rep in list(pairs.items()):
                    try:
                        score = float(getattr(rep, "score", rep))
                    except (TypeError, ValueError):
                        continue
                    obs_name = self._resolve_name(obs_uuid)
                    sub_name = self._resolve_name(sub_uuid)
                    key = (obs_uuid, sub_uuid)
                    prev = self._last_pair.get(key)
                    if prev is None or abs(prev - score) >= 0.05:
                        self._last_pair[key] = score
                        self._push(("rep_pair", obs_name, sub_name,
                                    score, now))

            for message in list(self.unhandled_messages):
                # unhandled_messages is a mixed bag — skip anything
                # that isn't a Network.ping Message.
                if getattr(message, "function", None) != Network.ping:
                    continue
                self.unhandled_messages.remove(message)
                try:
                    rtt = float(message.obj)
                except (TypeError, ValueError):
                    continue
                target = _peer_name(getattr(message, "to_whom", None)
                                    or getattr(message, "from_whom", None)
                                    or "?")
                self._push(("ping", target, rtt, time.time()))

    def _push(self, event):
        try:
            self._bridge_queue.put_nowait(event)
        except queue.Full:
            # Drop silently; bridge is best-effort. A full queue means
            # the Dash side isn't draining — not fatal.
            pass


def spawn_bridge(bridge_queue, log_level=LogLevel.WARNING):
    """Start a CivilianInspectorBridge in a daemon thread.

    Returns the thread. The bridge calls run_forever() which spawns
    AT worker subprocesses of its own; the thread is the 'parent'
    coordinator, same as a normal Inspector invocation.
    """
    def _target():
        try:
            bridge = CivilianInspectorBridge(
                bridge_queue=bridge_queue, log_level=log_level)
            bridge.run_forever()
        except Exception:
            logger.exception("[bridge] CivilianInspectorBridge crashed")

    t = threading.Thread(target=_target, name="civilian-bridge",
                         daemon=True)
    t.start()
    return t
