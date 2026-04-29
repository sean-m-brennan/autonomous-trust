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
from typing import Optional

from autonomous_trust.core import CfgIds, LogLevel
from autonomous_trust.core.config import to_json_string
from autonomous_trust.core.network import Network, Message
from autonomous_trust.core.reputation.protocol import ReputationProtocol
from autonomous_trust.core.system import queue_cadence

from .inspector import Inspector


logger = logging.getLogger(__name__)

# Bridge event tuple shapes. First element is the tag.
#   ("peer_seen",  name:str)
#   ("reputation", name:str, score:float, wall_t:float)
#   ("ping",       name:str, rtt_ms:float, wall_t:float)
#   ("rep_pair",   observer:str, subject:str, score:float, wall_t:float)
#       — Stage 3b.3(a) bilateral observation: observer's view of subject.
#   ("peer_gone",  name:str)   # Stage 3b future
BRIDGE_QUEUE_MAX = 1024

# Send a peer-to-peer reputation-query round every PEER_PAIR_QUERY_SEC.
# O(N²) round-trips per round, but N is small (~10 peers) and the network
# can absorb 100 messages/min easily.
PEER_PAIR_QUERY_SEC = 60.0


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
        # Reuse the stock inspector's per-peer query cadence (rep+ping).
        if self.tasking_tick(1):  # ~30s
            for peer in self.peers.all:
                try:
                    query = Message(
                        CfgIds.reputation,
                        ReputationProtocol.rep_req,
                        to_json_string((peer, self.proc_name)),
                        self.identity,
                    )
                    queues[CfgIds.reputation].put(
                        query, block=True, timeout=queue_cadence)
                    # return_to is a *queue name*, not the class display
                    # name. proc_name resolves to 'main' (the AT
                    # top-level queue) via Protocol.__init__.
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
            peers = list(self.peers.all)
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
                        queues[CfgIds.network].put(
                            query, block=True, timeout=queue_cadence)
                    except Exception:
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
