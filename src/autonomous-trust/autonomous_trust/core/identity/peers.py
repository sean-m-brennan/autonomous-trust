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

from ..config.configuration import Configuration
from ..protobuf import peers_pb2

class Peers(Configuration):
    """
    Peers are arranged hierarchically by their network reach, which usually corresponds to greater capability.
    The level this node is in is always the middle (all group messages are at this level,
    otherwise messaging is point-to-point). The number of levels is therefore always odd.
    Node valuation is a separate trust hierarchy that implements automatic de-prioritization and eventual disconnection.
    """
    LEVELS = 3
    VALUES = 10

    def __init__(self, hierarchy=None, valuation=None):
        super().__init__(peers_pb2.Peers)
        self.hierarchy = hierarchy
        if hierarchy is None:
            self.hierarchy = [dict({}) for _ in range(self.LEVELS)]
        self.valuation = valuation
        if valuation is None:
            self.valuation = [dict({}) for _ in range(self.VALUES)]
        self.all = []
        self.listing = {}
        for idx in range(len(self.hierarchy)):
            for peer in self.hierarchy[idx].values():
                self.listing[peer.address] = peer
                self.all.append(peer)

    def to_dict(self):
        return dict(hierarchy=self.hierarchy, valuation=self.valuation)

    @property
    def mid_level(self):
        return self.LEVELS // 2

    @property
    def my_level_peers(self):
        return self.hierarchy[self.mid_level]

    @staticmethod
    def _index_by(who):
        return who.nickname

    def _find(self, index):
        for idx in range(len(self.hierarchy)):
            if index in self.hierarchy[idx]:
                return idx
        return

    def _find_v(self, index):
        for idx in range(len(self.valuation)):
            if index in self.valuation[idx]:
                return idx
        return

    def find_by_index(self, index):
        idx = self._find(index)
        if idx is not None:
            return self.hierarchy[idx][index]

    def find_by_uuid(self, uuid):
        ids = {p.uuid: p for p in self.listing.values()}
        if uuid in ids:
            return ids[uuid]
        return None

    def find_by_address(self, address):
        if '/' in address:
            address = address.split('/')[0]
        if address in self.listing:
            return self.listing[address]
        return None

    def find_top_n(self, n):
        if n >= len(self.all):
            return self.all
        p_list = []
        for idx in range(len(self.valuation)):
            for peer in self.valuation[idx].values():
                if len(p_list) >= n:
                    break
                p_list.append(peer)
            if len(p_list) >= n:
                break

    def add(self, who, level=None):
        if level is None:
            level = self.mid_level
        if who.address not in self.listing:
            self.listing[who.address] = who
        if who not in self.all:
            self.all.append(who)
        index = self._index_by(who)
        self.hierarchy[level][index] = who
        self.valuation[-1][index] = who

    def delete(self, who):
        index = self._index_by(who)
        idx = self._find(index)
        v_idx = self._find_v(index)
        if idx is not None:
            del self.hierarchy[idx][index]
            del self.valuation[v_idx][index]

    def move(self, who, level):
        if who in self.all:
            index = self._index_by(who)
            idx = self._find_v(index)
            if idx is not None and idx > 0:
                self.hierarchy[level][index] = who
                del self.hierarchy[idx][index]

    def promote(self, who):
        if who in self.all:
            index = self._index_by(who)
            idx = self._find_v(index)
            if idx is not None:
                if idx > 0:
                    self.valuation[idx - 1][index] = who
                    del self.valuation[idx][index]
            else:
                self.valuation[-1][index] = who

    def demote(self, who):
        index = self._index_by(who)
        idx = self._find_v(index)
        if idx is not None:
            if idx < len(self.hierarchy):
                self.valuation[idx + 1][index] = who
            else:
                del self.listing[who.address]
                self.all.remove(who)
            del self.valuation[idx][index]
