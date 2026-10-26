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
"""When each peer was last heard through this node's own transport.

Presence counts every frame from a peer, however it arrived. This counts only
frames the core transport delivered, so an extension that carries traffic some
other way (a relay, a radio) can ask whether the transport path to a peer
works. Frames an extension injects never stamp it. Twin of C net_liveness.
"""
import threading


class TransportLiveness:
    #: Peers tracked at once; past this the one heard longest ago is forgotten.
    MAX = 512

    def __init__(self, start: float):
        self._start = start
        self._last = {}
        self._lock = threading.Lock()

    def heard(self, peer_uuid, now: float) -> None:
        if peer_uuid is None:
            return
        key = str(peer_uuid).lower()
        with self._lock:
            prev = self._last.get(key)
            if prev is None and len(self._last) >= self.MAX:
                del self._last[min(self._last, key=self._last.get)]
            if prev is None or now > prev:
                self._last[key] = now

    def quiet_for(self, peer_uuid, now: float) -> float:
        with self._lock:
            since = self._last.get(str(peer_uuid).lower(), self._start)
        return max(0.0, now - since)
