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
"""Local soft-absence (doc/architecture/peer-presence.md).

The network process stamps every frame it routes from a known peer and every
frame it sends, and from those two clocks decides, per peer, whether the peer
has gone quiet. Nothing here touches the roster, the group key or any quorum: an
absent peer is still a member. What changes is that the node stops asking it to
do work (task invitations and probes), and the app is told.

Two thresholds, both wall-clock seconds:

* ``AT_PRESENCE_HEARTBEAT_SEC`` (default 30): a node that has sent nothing to
  some peer for this long sends one group presence frame, so an idle cohort
  still hears from everyone. A busy node never sends one.
* ``AT_PRESENCE_ABSENT_SEC`` (default 90): a peer heard from nothing for this
  long is absent. A peer is never absent before it has been on the roster this
  long.

Mirrors C ``network/net_presence.{c,h}``.
"""

import os
import threading
from dataclasses import dataclass
from typing import Iterable, Optional

from ..app_verbs import AppEvent

#: The envelope a presence frame travels under. Labelled for the identity
#: process, not the network one, so a node built before presence existed drops
#: it as an unknown identity verb rather than routing it back into its own
#: outbound loop. A node that knows the verb consumes it in the network process
#: and never routes it.
PRESENCE_PROCESS = 'identity'
PRESENCE_FUNCTION = 'presence'

HEARTBEAT_DEFAULT_SEC = 30.0
ABSENT_DEFAULT_SEC = 90.0


@dataclass
class PeerPresence(AppEvent):
    """Network -> negotiation and the app: one peer went quiet, or came back.

    Advisory only: the peer stays on every roster and in every quorum.
    ``last_heard`` is epoch seconds of the last frame routed from the peer, 0
    for none yet. Mirrors C ``peer_presence_msg_t`` / ``at_app_presence_t``."""
    peer_uuid: str
    present: bool
    last_heard: float = 0.0


def _env_seconds(name: str, fallback: float) -> float:
    raw = os.environ.get(name, '')
    if not raw:
        return fallback
    try:
        value = float(raw)
    except ValueError:
        return fallback
    return value if value > 0.0 else fallback


class _Entry:
    __slots__ = ('since', 'last_heard', 'last_sent', 'absent')

    def __init__(self, since: float):
        self.since = since
        self.last_heard = 0.0
        self.last_sent = 0.0
        self.absent = False


class PresenceTracker:
    """Per-peer heard/sent clocks and the decisions made from them.

    Thread-safe: frames are heard on receiver threads, the tick runs on the
    network process's main loop."""

    def __init__(self, heartbeat_sec: Optional[float] = None,
                 absent_sec: Optional[float] = None):
        if heartbeat_sec is None:
            heartbeat_sec = _env_seconds('AT_PRESENCE_HEARTBEAT_SEC',
                                         HEARTBEAT_DEFAULT_SEC)
        if absent_sec is None:
            absent_sec = _env_seconds('AT_PRESENCE_ABSENT_SEC',
                                      ABSENT_DEFAULT_SEC)
        self.heartbeat_sec = (heartbeat_sec if heartbeat_sec > 0.0
                              else HEARTBEAT_DEFAULT_SEC)
        self.absent_sec = absent_sec if absent_sec > 0.0 else ABSENT_DEFAULT_SEC
        # Absent means "missed the heartbeats it owed us", so a threshold below
        # one heartbeat would mark an idle but healthy peer absent between two
        # presence frames.
        self.absent_sec = max(self.absent_sec, self.heartbeat_sec)
        self._entries: dict[str, _Entry] = {}
        self._lock = threading.Lock()

    def heard(self, peer_uuid, now: float) -> None:
        """A frame from ``peer_uuid`` was routed. A uuid not on the roster at
        the last tick is ignored: a frame from an address we have not admitted
        yet is not evidence about a member."""
        if not peer_uuid:
            return
        with self._lock:
            entry = self._entries.get(str(peer_uuid))
            if entry is not None and now > entry.last_heard:
                entry.last_heard = now

    def sent(self, peer_uuid, now: float) -> None:
        """A frame went out to ``peer_uuid``, or to every peer when it is None
        (a group frame or a broadcast)."""
        with self._lock:
            if peer_uuid is None:
                targets = self._entries.values()
            else:
                entry = self._entries.get(str(peer_uuid))
                targets = [entry] if entry is not None else []
            for entry in targets:
                if now > entry.last_sent:
                    entry.last_sent = now

    def tick(self, roster: Iterable, now: float):
        """Reconcile with ``roster`` (uuids) and evaluate it at ``now``.

        Peers new to the roster start present, with their grace and heartbeat
        clocks at ``now``; peers gone from it are forgotten.

        :return: ``(heartbeat_due, changes)``: whether some roster peer has had
            nothing from us for the heartbeat interval (the caller sends one
            presence frame to the group and reports it with ``sent(None, now)``),
            and a :class:`PeerPresence` for each peer whose state flipped."""
        keys = [str(u) for u in roster if u]
        changes = []
        due = False
        with self._lock:
            for gone in set(self._entries) - set(keys):
                del self._entries[gone]
            for key in keys:
                entry = self._entries.get(key)
                if entry is None:
                    entry = self._entries[key] = _Entry(now)
                # Silence is measured from the later of joining the tracker and
                # the last frame heard, so a new peer gets the full grace.
                absent = (now - max(entry.last_heard, entry.since)) > self.absent_sec
                if absent != entry.absent:
                    entry.absent = absent
                    changes.append(PeerPresence(key, not absent, entry.last_heard))
                if (now - max(entry.last_sent, entry.since)) >= self.heartbeat_sec:
                    due = True
        return due, changes

    def snapshot(self, roster: Iterable) -> list:
        """The current state of each ``roster`` peer, for the app's roster
        pull. A peer not seen yet reads present with ``last_heard`` 0."""
        rows = []
        with self._lock:
            for uuid in roster:
                key = str(uuid)
                entry = self._entries.get(key)
                rows.append(PeerPresence(key, entry is None or not entry.absent,
                                         0.0 if entry is None else entry.last_heard))
        return rows
