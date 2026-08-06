# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************
"""OperatorNode: an AutonomousTrust subclass that feeds the operator console.

Mirrors the Inspector pattern (`inspector/inspector.py`): the AT node runs in a
background thread and a monitor process + ``autonomous_tasking`` drain live state
into a queue the TUI consumes. The OperatorNode is a **request-only** client
(§6.3): it registers no serving capabilities by default -- it consumes resources,
it doesn't offer them, and earns standing like any peer (warm-start floor, §3.3).

Two layers, separated so the logic is testable:

  * `directory_from_state` -- a **pure adapter** mapping live AT structures
    (PeerCapabilities, Peers, reputation, the operator's own Capabilities
    registry, its tier) into a `ResourceDirectory`. Unit-tested with light
    duck-typed fakes; no node required.
  * `OperatorNode` / `OperatorProcess` -- the integration layer that calls the
    adapter on a cadence, emits snapshots on ``external_feedback``, and triggers
    the TCP-backed ``caps_query`` active refresh. This runs only inside a live
    node (the run loop is the integration seam, like P1's node-start).
"""
from __future__ import annotations

from queue import Empty, Full
from typing import Mapping, Optional

from .resource_directory import (
    build_directory, CapabilityDescriptor, PeerInfo, ResourceDirectory,
    ResourceKind)


def _arg_schema(cap) -> Optional[dict]:
    """Derive an arg schema from a Capability's descriptor or arg_names."""
    schema = getattr(cap, 'arg_schema', None)
    if schema:
        return dict(schema)
    arg_names = getattr(cap, 'arg_names', None)
    if arg_names:
        return {name: 'any' for name in arg_names}
    return None


def directory_from_state(local_capabilities, peer_capabilities, peers,
                         my_tier: int = 0,
                         reputations: Optional[Mapping] = None,
                         online_uuids=None) -> ResourceDirectory:
    """Build a `ResourceDirectory` from live AT state (pure; no I/O).

    Args:
        local_capabilities: the operator's `Capabilities` registry (name ->
            `Capability`). Function-less descriptor entries are fine: a
            request-only operator pre-registers known resources (name +
            required_tier + schema) so the directory is self-describing without
            the wire capability-descriptor (the deferred follow-up).
        peer_capabilities:  `PeerCapabilities` (Mapping cap_name -> [peer ids]).
        peers:              `Peers` (``find_by_uuid`` -> identity w/ .tier/.petname).
        my_tier:            the operator's own current trust tier.
        reputations:        optional {peer_id: obj-with-.score}.
        online_uuids:       optional iterable of online peer ids (default: all
                            providers treated online when peers has a record).
    """
    reputations = reputations or {}
    online = None if online_uuids is None else {str(u) for u in online_uuids}

    descriptors: dict = {}
    for name in local_capabilities:
        cap = local_capabilities[name]
        descriptors[name] = CapabilityDescriptor(
            name=name,
            kind=getattr(cap, 'kind', '') or ResourceKind.UNKNOWN.value,
            description=getattr(cap, 'description', '') or '',
            required_tier=getattr(cap, 'required_tier', None),
            arg_schema=_arg_schema(cap))

    wire_descriptors = getattr(peer_capabilities, 'descriptors', {}) or {}
    providers: dict = {}
    for cap_name in peer_capabilities:
        ids = [str(u) for u in peer_capabilities[cap_name]]
        providers[cap_name] = ids
        if cap_name in descriptors:
            continue
        # Remote-only cap: prefer the descriptor learned from caps_response;
        # else a bare descriptor (required_tier unknown -> reach UNKNOWN).
        wire = wire_descriptors.get(cap_name)
        if wire:
            descriptors[cap_name] = CapabilityDescriptor(
                name=cap_name,
                kind=wire.get('kind') or ResourceKind.UNKNOWN.value,
                description=wire.get('description', '') or '',
                required_tier=wire.get('required_tier'),
                arg_schema=wire.get('arg_schema'))
        else:
            descriptors[cap_name] = CapabilityDescriptor(cap_name)

    peer_info: dict = {}
    all_ids = {pid for ids in providers.values() for pid in ids}
    for pid in all_ids:
        peer = peers.find_by_uuid(pid) if peers is not None else None
        rep = reputations.get(pid)
        score = getattr(rep, 'score', None) if rep is not None else None
        is_online = True if online is None else (pid in online)
        if peer is not None:
            peer_info[pid] = PeerInfo(
                peer=pid,
                name=getattr(peer, 'petname', '') or getattr(peer, 'nickname', ''),
                tier=int(getattr(peer, 'tier', 0) or 0),
                reputation=score, online=is_online)
        else:
            # No standing record -> unknown peer; offline unless told otherwise.
            peer_info[pid] = PeerInfo(peer=pid, reputation=score,
                                      online=(online is not None and is_online))
    return build_directory(descriptors, providers, peer_info, my_tier)


# ---------------------------------------------------------------------------
# Integration layer (runs only inside a live node; see module docstring).
# ---------------------------------------------------------------------------

try:  # keep the pure adapter importable even where the core deps are absent
    from autonomous_trust.core import (AutonomousTrust, Process, ProcMeta,
                                       CfgIds)
    from autonomous_trust.core.capabilities import PeerCapabilities
    from autonomous_trust.core.network import Message
    from autonomous_trust.core.identity.protocol import IdentityProtocol
    from autonomous_trust.core.system import queue_cadence
    _HAVE_CORE = True
except Exception:  # pragma: no cover - exercised only without the core present
    _HAVE_CORE = False


if _HAVE_CORE:

    class OperatorProcess(Process, metaclass=ProcMeta,
                          proc_name='operator',
                          description='Operator resource-directory monitor'):
        """Silent monitor worker (mirrors InspectorProcess)."""

        def __init__(self, configurations, subsystems, log_q, dependencies):
            super().__init__(configurations, subsystems, log_q,
                             dependencies=dependencies)

        def process(self, queues, signal):
            # The directory is assembled on the main loop (which holds peers +
            # reputation); this worker just stays alive for the monitor slot.
            while self.keep_running(signal):
                try:
                    queues[self.name].get(block=True, timeout=self.q_cadence)
                except Empty:
                    pass

    class OperatorNode(AutonomousTrust):
        """Request-only AT node that emits ResourceDirectory snapshots.

        ``run_forever(q_in=control, q_out=feedback)`` exposes the standard
        external queues; directory snapshots are pushed to ``external_feedback``
        for the TUI, and ``Task``s arrive on ``external_control`` (P5).
        """

        #: cadence id for directory emission (every ~5s via tasking_tick(2, 5))
        DIRECTORY_TICK = 7

        def __init__(self, directory_period: float = 5.0, **kwargs):
            super().__init__(**kwargs)
            self.add_worker(OperatorProcess, self.system_dependencies)
            self._directory_period = directory_period
            self._peer_capabilities = PeerCapabilities()
            self.latest_directory: Optional[ResourceDirectory] = None

        # -- request-only: register no serving capabilities by default --
        def init_tasking(self, queues):
            # Intentionally do not register serving abilities (§6.3). Subclasses
            # may opt in later.
            pass

        def _collect_peer_capabilities(self):
            """Drain PeerCapabilities broadcasts from unhandled messages.

            The identity process broadcasts `PeerCapabilities` to the main loop;
            anything the main handlers don't consume lands in
            ``unhandled_messages`` (the Inspector drains pings the same way).
            """
            for message in list(self.unhandled_messages):
                if isinstance(message, PeerCapabilities):
                    self.unhandled_messages.remove(message)
                    for cap_name in message:
                        self._peer_capabilities.register(
                            cap_name, list(message[cap_name]))
                    for nm, desc in getattr(message, 'descriptors', {}).items():
                        self._peer_capabilities.register_descriptor(nm, desc)

        def current_directory(self) -> ResourceDirectory:
            my_tier = int(getattr(self.identity, 'tier', 0) or 0)
            return directory_from_state(
                self.capabilities, self._peer_capabilities, self.peers,
                my_tier=my_tier, reputations=self.latest_reputation)

        def request_caps_refresh(self, queues):
            """Active refresh: directed `caps_query` sweep to repair lost
            announces (reuses the late-joiner machinery)."""
            for peer in self.peers.all:
                try:
                    queues[CfgIds.network].put(
                        Message(self.name, IdentityProtocol.caps_query, '',
                                to_whom=peer),
                        block=True, timeout=queue_cadence)
                except Full:
                    self.logger.error('request_caps_refresh: network queue full')

        def autonomous_tasking(self, queues):
            self._collect_peer_capabilities()
            if self.tasking_tick(self.DIRECTORY_TICK, self._directory_period):
                self.latest_directory = self.current_directory()
                if self.external_feedback in queues:
                    try:
                        queues[self.external_feedback].put(
                            self.latest_directory, block=True,
                            timeout=queue_cadence)
                    except Full:
                        self.logger.error('autonomous_tasking: feedback full')
