# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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

from collections.abc import Mapping
import multiprocessing

from .config import Configuration
from autonomous_trust.core.protobuf.processes import capabilities_pb2


class Capability(Configuration):
    """Name and function"""
    _msg_class = capabilities_pb2.Capability

    def __init__(self, name, function=None, arg_names=None, keywords=None,
                 required_tier: int = 0, transaction_weight: int = 1):
        super().__init__(capabilities_pb2.Capability)
        self.name = name
        self.function = function  # this will be None for remote handling
        self.arg_names = arg_names
        self.keywords = keywords
        # Trust-tier metadata. See doc/architecture/trust-tiers.md §4.
        # required_tier is the minimum peer._tier needed to invoke this
        # capability (0 = any admitted peer). transaction_weight is the
        # multiplier applied in _pure_reputation to TSs from tasks using
        # this capability (1 = no boost).
        self.required_tier = required_tier
        self.transaction_weight = transaction_weight

    def execute(self, task, pid_q):
        pid_q.put_nowait(multiprocessing.current_process().pid)
        try:
            return self.function(*task.parameters.args, **task.parameters.kwargs)
        except Exception as e:
            raise RuntimeError('Capability %r execution failed for task %s: %s' % (self.name, task.uuid, e)) from e

    def __eq__(self, other):
        return self.name == other.name

    def to_dict(self):
        # Intentionally minimal — `to_dict` is for log/repr surfaces; the
        # cross-impl wire form is the protobuf `Capability` message
        # (capabilities.proto / sync_to_message). `arg_names` and
        # `keywords` are runtime-only fields cleared by sync_from_message,
        # so they have no meaningful serialized representation. See
        # divergence.md H15 (re-audit) for the unified C-side equivalent
        # via `capability_t.arguments`.
        return dict(name=self.name,
                    required_tier=self.required_tier,
                    transaction_weight=self.transaction_weight)

    def sync_to_message(self):
        self.message.name = self.name
        self.message.category = ''
        self.message.required_tier = self.required_tier
        self.message.transaction_weight = self.transaction_weight

    def sync_from_message(self):
        self.name = self.message.name
        self.function = None
        self.arg_names = None
        self.keywords = None
        self.required_tier = int(self.message.required_tier)
        # proto3 can't distinguish "not set" from 0; treat 0 as the
        # default weight (1) so peers without the field interoperate.
        w = int(self.message.transaction_weight)
        self.transaction_weight = w if w > 0 else 1


class Capabilities(Mapping):
    """Mapping of name to Capability"""
    def __init__(self):
        self._listing = {}

    def __len__(self):
        return len(self._listing)

    def __iter__(self):
        return self._listing.__iter__()

    def __getitem__(self, key):
        return self._listing[key]

    def __contains__(self, item):
        return item in self._listing.values()

    def to_list(self) -> list[str]:
        return [cap.name for cap in self._listing.values()]

    def register_ability(self, name, function, arg_names=None, keywords=None,
                         required_tier: int = 0, transaction_weight: int = 1):
        self._listing[name] = Capability(name, function, arg_names, keywords,
                                         required_tier=required_tier,
                                         transaction_weight=transaction_weight)


class PeerCapabilities(Mapping, Configuration):
    """Mapping of capability names to peer ids"""
    _msg_class = capabilities_pb2.PeerCapabilities

    def __init__(self, _listing=None):
        super().__init__(capabilities_pb2.PeerCapabilities)
        self._listing = _listing
        if _listing is None:
            self._listing = {}

    def __len__(self):
        return len(self._listing)

    def __iter__(self):
        return self._listing.__iter__()

    def __getitem__(self, key):
        return self._listing[key]

    def register(self, peer_id, caps: list[str]):
        for name in caps:
            if name not in self._listing:
                self._listing[name] = []
            self._listing[name].append(peer_id)

    def sync_to_message(self):
        # Invert Python's {cap_name: [peer_ids]} to proto's {peer: [capabilities]}
        peer_caps = {}
        for cap_name, peer_ids in self._listing.items():
            for pid in peer_ids:
                peer_key = str(pid)
                if peer_key not in peer_caps:
                    peer_caps[peer_key] = []
                peer_caps[peer_key].append(cap_name)
        del self.message.listing[:]
        for peer, cap_names in peer_caps.items():
            entry = self.message.listing.add()
            entry.peer = peer
            for cn in cap_names:
                cap = entry.capability.add()
                cap.name = cn
                cap.category = ''

    def sync_from_message(self):
        # Invert proto's {peer: [capabilities]} back to Python's {cap_name: [peer_ids]}
        self._listing = {}
        for entry in self.message.listing:
            for cap in entry.capability:
                if cap.name not in self._listing:
                    self._listing[cap.name] = []
                self._listing[cap.name].append(entry.peer)
