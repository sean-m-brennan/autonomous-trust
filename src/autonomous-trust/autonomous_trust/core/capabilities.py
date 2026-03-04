# ******************
#  Copyright 2024 TekFive, Inc. and contributors
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
from .protobuf.processes import capabilities_pb2


class Capability(Configuration):
    """Name and function"""
    _msg_class = capabilities_pb2.Capability

    def __init__(self, name, function=None, arg_names=None, keywords=None):
        super().__init__(capabilities_pb2.Capability)
        self.name = name
        self.function = function  # this will be None for remote handling
        self.arg_names = arg_names
        self.keywords = keywords

    def execute(self, task, pid_q):
        pid_q.put_nowait(multiprocessing.current_process().pid)
        # FIXME handle errors
        return self.function(*task.parameters.args, **task.parameters.kwargs)

    def __eq__(self, other):
        return self.name == other.name

    def to_dict(self):
        return dict(name=self.name)  # TODO more info

    def sync_to_message(self):
        self.message.name = self.name
        self.message.category = ''

    def sync_from_message(self):
        self.name = self.message.name
        self.function = None
        self.arg_names = None
        self.keywords = None


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

    def register_ability(self, name, function, arg_names=None, keywords=None):
        self._listing[name] = Capability(name, function, arg_names, keywords)


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
        # Invert {cap_name: [peer_ids]} to {peer_id: [cap_names]}
        peer_caps = {}
        for cap_name, peer_ids in self._listing.items():
            for pid in peer_ids:
                if pid not in peer_caps:
                    peer_caps[pid] = []
                peer_caps[pid].append(cap_name)
        del self.message.listing[:]
        for peer_id, cap_names in peer_caps.items():
            entry = self.message.listing.add()
            entry.peer = peer_id
            for cn in cap_names:
                cap = entry.capability.add()
                cap.name = cn
                cap.category = ''

    def sync_from_message(self):
        # Invert {peer_id: [caps]} back to {cap_name: [peer_ids]}
        self._listing = {}
        for entry in self.message.listing:
            peer_id = entry.peer
            for cap in entry.capability:
                if cap.name not in self._listing:
                    self._listing[cap.name] = []
                self._listing[cap.name].append(peer_id)
