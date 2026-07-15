# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ******************

"""Generic live-mode bridge between an AT mesh and an external dashboard.

The dashboard (e.g. a Dash server in the main process) cannot itself
participate in the AT protocol — it would block its own UI loop.
``InspectorBridge`` runs an Inspector in a daemon thread: it joins the
AT network, observes peers, and pushes events to a multiprocessing
queue the dashboard drains on each tick.

Scenario-specific wiring lives in caller modules — pass the capability
→ peer-process-queue map via ``cap_to_proc`` and the bridge subscribes
to those streams. Everything else (peer_seen / reputation / rep_pair /
ping / reading event shapes, the rep_req cadence, the PeerCapabilities
forwarding) is the same regardless of what data is flowing.

Intentional limits:
    - Peer-id to display-name matching is best-effort (nickname),
      pending AT_PEER_NAME -> identity propagation.
    - Observations annotate the event log but do NOT yet replace
      synthesized timeline samples.
    - Exclusion / compromise detection is inferred downstream.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from queue import Empty, Full
from typing import Mapping, Optional, Type

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
from .transitive_trust import PEER_PAIR_QUERY_SEC


logger = logging.getLogger(__name__)

# Bridge event tuple shapes. First element is the tag.
#   ("peer_seen",  name:str, uuid:str, fingerprint:str)
#       — fired once on first observation; uuid is the peer's AT
#         Identity UUID, fingerprint is the leading bytes of the peer's
#         public signing key (hex, 16 chars). Either string may be
#         empty if the peer's Identity object is missing those fields.
#   ("reputation", name:str, score:float, wall_t:float)
#   ("ping",       name:str, rtt_ms:float, wall_t:float)
#   ("rep_pair",   observer:str, subject:str, score:float, wall_t:float)
#       — bilateral observation: observer's view of subject.
#   ("reading",    peer:str, reading_dict:dict, wall_t:float)
#       — single Reading.to_dict() emitted by a peer's data-stream worker.
#   ("peer_gone",  name:str)   # future
BRIDGE_QUEUE_MAX = 1024

# PEER_PAIR_QUERY_SEC (the peer-to-peer query cadence) and the query round
# itself now live in transitive_trust.TransitiveTrustMixin, shared with the
# stock Inspector. O(N²) round-trips per round, but typical N is small
# (~10 peers) and the network can absorb 100 messages/min easily.

# Minimum score delta that triggers a `reputation` / `rep_pair` push to
# the bridge queue. The bridge polls latest_reputation every ~5s; with
# a 0.05 floor, sub-5% drift was being suppressed and the dashboard
# could appear stuck on a seed value (e.g. 0.49). 0.01 lets the UI see
# small movement without flooding — at most one event per peer per 5s
# tick anyway.
REPUTATION_PUSH_DELTA = 0.01


def _peer_name(identity_obj) -> str:
    """Best-effort identity -> display name.

    AT Identity has .nickname (online), .petname (local), .uuid. Prefer
    nickname so bridge events carry the scenario's label (e.g.
    'noaa-1@...') when AT_PEER_NAME propagation is wired. Falls back to
    petname, then str() if none set.
    """
    for attr in ("nickname", "petname"):
        v = getattr(identity_obj, attr, None)
        if v:
            return str(v)
    return str(identity_obj)


def _peer_uuid(identity_obj) -> str:
    """Stringify the peer's UUID (or '' if absent)."""
    u = getattr(identity_obj, "uuid", None)
    return "" if u is None else str(u)


def _peer_fingerprint(identity_obj) -> str:
    """Short hex fingerprint of the peer's public signing key.

    Used as a human-comparable key identity in the dashboard's Peer
    Detail panel. Returns the first 16 hex chars of
    `signature.publish()` (the peer's verify key, hex-encoded). Falls
    back to '' if the Identity carries no signature.
    """
    sig = getattr(identity_obj, "signature", None)
    if sig is None:
        return ""
    try:
        pub = sig.publish()
    except Exception:
        return ""
    if isinstance(pub, bytes):
        pub = pub.decode("ascii", errors="replace")
    return str(pub)[:16]


class BridgeDataRcvr(Process, metaclass=ProcMeta,
                     proc_name='bridge-data-rcvr',
                     description='Inspector bridge envdata receiver',
                     cfg_name='bridge-data-rcvr'):
    """Forkserver-child worker that subscribes to peer data streams and
    forwards each Reading dict directly to the inspector bridge queue.

    Differs from `services.data.client.DataRcvr` in two ways:

      1. It subscribes to a caller-supplied capability surface (passed
         in via the ``cap_to_proc`` kwarg) rather than the generic
         'data' capability.
      2. It bypasses Cohort-based routing — there's no Cohort on the
         inspector side, only the Manager-backed `bridge_queue` shared
         with the Dash callback.

    Lives in the inspector container; instantiated via
    `InspectorBridge.add_worker(BridgeDataRcvr, bridge_queue=...,
                                cap_to_proc=...)`.
    """

    def __init__(self, configurations, subsystems, log_queue, dependencies,
                 **kwargs):
        super().__init__(configurations, subsystems, log_queue,
                         dependencies=dependencies)
        self._bridge_queue = kwargs['bridge_queue']
        # cap_name -> remote process queue name. Snapshot at construction
        # so the worker doesn't share mutable state with the parent.
        self._cap_to_proc: dict[str, str] = dict(kwargs['cap_to_proc'])
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
        the configured capabilities, once per (cap, peer) pair."""
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
        for cap, proc_target in self._cap_to_proc.items():
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
            # InspectorBridge.autonomous_tasking forwards the bridge's
            # peer_capabilities + peers roster onto our queue (see
            # bridge.py InspectorBridge.autonomous_tasking). Without
            # these, our DataProtocol.peer_capabilities stays empty and
            # _subscribe_to_new_peers never finds any cap to subscribe
            # to. Update the protocol's view directly when we recognize
            # the payload; fall through to the generic message handlers
            # for everything else (DataProtocol.data replies, etc.).
            if isinstance(message, PeerCapabilities):
                # Bridge-rcvr receives PeerCapabilities from TWO sources:
                #   - direct fan-put from idproc via _remember_activity
                #     (with the framework fix it includes PeerCapabilities)
                #   - forward from InspectorBridge.autonomous_tasking,
                #     which reads main proc's view of peer_capabilities.
                # main proc's view lags behind idproc's because main is
                # heavily backlogged (102k rep_resp messages, processed
                # one-per-500ms). The two are DIFFERENT PARTIAL VIEWS of
                # the same {cap_name: [peer_ids]} map: each can carry keys
                # the other lacks. An earlier size-monotonic guard
                # (accept only if inc_n >= cur_n) tried to protect EPA's
                # airquality_stream but did the opposite — it rejected the
                # airquality-bearing view whenever that view had fewer
                # *total* keys, so airquality never reached bridge-rcvr.
                # Reconcile by UNION instead: merge incoming per-cap peer
                # sets into what we hold so no key is ever lost to a
                # smaller update. (Trade-off: caps are never removed here;
                # stale peers are harmless because the subscribe loop
                # re-checks the peer roster via find_by_uuid.)
                cur = self.protocol.peer_capabilities
                cur_n = len(cur) if cur is not None else 0
                inc_n = len(message)
                # Diagnostic: which incoming keys are NEW vs what we hold,
                # and whether this update carries airquality_stream. Lets
                # us distinguish "arrived-and-merged" from "never arrives".
                cur_keys = set(cur) if cur is not None else set()
                new_keys = set(message) - cur_keys
                _probes.counter('bridge.rcvr', 'caps_incoming_new',
                                ','.join(sorted(new_keys)) or '(none)')
                _probes.counter('bridge.rcvr', 'caps_has_airq',
                                '1' if 'airquality_stream' in set(message)
                                else '0')
                if cur is None or cur_n == 0:
                    self.protocol.peer_capabilities = message
                    _probes.counter('bridge.rcvr', 'caps_accept',
                                    f'{cur_n}->{inc_n}')
                else:
                    merged = dict(cur._listing)
                    for cap in message:
                        existing = merged.get(cap)
                        if existing is None:
                            merged[cap] = list(message[cap])
                            continue
                        seen = {str(p) for p in existing}
                        combined = list(existing)
                        for pid in message[cap]:
                            if str(pid) not in seen:
                                combined.append(pid)
                                seen.add(str(pid))
                        merged[cap] = combined
                    new_caps = PeerCapabilities(_listing=merged)
                    # Preserve runtime-only descriptors from both views.
                    new_caps.descriptors = {
                        **getattr(cur, 'descriptors', {}),
                        **getattr(message, 'descriptors', {})}
                    self.protocol.peer_capabilities = new_caps
                    _probes.counter('bridge.rcvr', 'caps_merge',
                                    f'{cur_n}->{len(new_caps)}')
                continue
            if isinstance(message, Peers):
                self.protocol.peers = message
                continue
            self.protocol.run_message_handlers(queues, message)


class InspectorBridge(Inspector):
    """Inspector subclass that shadows the stock observer but routes
    reputation / peer-roster events to a bridge queue instead of its
    own VizServer. The dashboard's tick callback drains the queue."""

    def __init__(self, bridge_queue, *, cap_to_proc: Mapping[str, str],
                 **kwargs):
        super().__init__(**kwargs)
        self._bridge_queue = bridge_queue
        self._cap_to_proc: dict[str, str] = dict(cap_to_proc)
        self._seen: set[str] = set()
        self._last_rep: dict[str, float] = {}
        # (observer_uuid_str, subject_uuid_str) -> last-pushed score.
        # Used to suppress no-op rep_pair pushes when nothing changed.
        self._last_pair: dict[tuple[str, str], float] = {}
        # Stream readings come in via BridgeDataRcvr. The dashboard side
        # drains the same `bridge_queue` so no separate plumbing is
        # needed here; we just register the worker.
        self.add_worker(BridgeDataRcvr, self.system_dependencies,
                        bridge_queue=bridge_queue,
                        cap_to_proc=self._cap_to_proc)

    def init_tasking(self, queues):
        # No VizServer — the dashboard owns its own server in the main
        # process.
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
                    self._push(("peer_seen", name,
                                _peer_uuid(peer),
                                _peer_fingerprint(peer)))

        # Peer-to-peer reputation queries. Ask each peer (observer) for
        # its view of every OTHER peer (subject). Goes over the network
        # so the remote peer's ReputationProcess is the one that
        # computes. Responses arrive as rep_resp on the AT main loop,
        # captured into latest_reputation_pairs by automate.py.
        # from_whom MUST be set so the responding peer's
        # forward_reputation can route the rep_resp back over the
        # network (else requestor=None and the response stays local).
        if self.tasking_tick(3, PEER_PAIR_QUERY_SEC):
            # Peer-to-peer reputation queries (shared TransitiveTrustMixin):
            # ask each observer for its view of every other subject, routed
            # over the network; responses are captured into
            # latest_reputation_pairs by automate.py.
            _probes.counter('bridge.task', 'tick3_fired')
            _probes.counter('bridge.task', 'tick3_peers', str(len(self.peers.all)))
            sent = self.query_peer_pairs(queues, logger=logger)
            _probes.counter('bridge.task', 'tick3_msg_queued', str(sent))

        if self.tasking_tick(2, 5.0):  # ~5s
            now = time.time()
            for subject_uuid, rep in self.latest_reputation.items():
                try:
                    score = float(getattr(rep, "score", rep))
                except (TypeError, ValueError):
                    continue
                name = self._resolve_name(subject_uuid)
                prev = self._last_rep.get(name)
                if prev is None or abs(prev - score) >= REPUTATION_PUSH_DELTA:
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
                    if prev is None or abs(prev - score) >= REPUTATION_PUSH_DELTA:
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


def spawn_bridge(bridge_queue, cap_to_proc: Mapping[str, str], *,
                 bridge_class: Type[InspectorBridge] = InspectorBridge,
                 thread_name: str = "inspector-bridge",
                 log_level=LogLevel.WARNING):
    """Start an InspectorBridge in a daemon thread.

    Returns the thread. The bridge calls run_forever() which spawns
    AT worker subprocesses of its own; the thread is the 'parent'
    coordinator, same as a normal Inspector invocation.

    ``bridge_class`` lets callers swap in a subclass with extra
    behavior; ``thread_name`` is purely cosmetic but useful for tracing.
    """
    def _target():
        try:
            bridge = bridge_class(
                bridge_queue=bridge_queue,
                cap_to_proc=cap_to_proc,
                log_level=log_level)
            bridge.run_forever()
        except Exception:
            logger.exception("[bridge] %s crashed", bridge_class.__name__)

    t = threading.Thread(target=_target, name=thread_name, daemon=True)
    t.start()
    return t
