# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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
from .. import _probes


def strip_cidr(address):
    """``address`` without a ``/prefix`` CIDR suffix. A DTN endpoint ID
    (``dtn:``/``ipn:``) is returned whole: its slashes are part of the address,
    and cutting at the first one turned every EID into ``dtn:``. Mirrors C's
    peers_find_by_address."""
    if isinstance(address, str) and '/' in address and not address.startswith(('dtn:', 'ipn:')):
        return address.split('/')[0]
    return address


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
        #super().__init__(peers_pb2.Peers)
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
        # Compared as lower-case strings: a peer's uuid is a str or a UUID
        # depending on where its Identity was built (an envelope, a config, a
        # contact record), and the same peer must be found either way -- a
        # type-strict match lost every contact restored at startup to the
        # relayed-frame lookup, which asks with a UUID.
        if uuid is None:
            return None
        key = str(uuid).lower()
        for p in self.listing.values():
            if str(p.uuid).lower() == key:
                return p
        return None

    def find_by_address(self, address):
        address = strip_cidr(address)
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
        return p_list

    def add(self, who, level=None):
        if level is None:
            level = self.mid_level
        index = self._index_by(who)
        # A peer that rejoins under a new identity keeps its nickname but
        # gets a new uuid (and usually a new address). hierarchy/valuation
        # are keyed by nickname, so `who` replaces the prior holder there;
        # but self.all and self.listing are keyed by object/address and
        # would otherwise retain the stale entry — leaving two peers with
        # the same nickname in self.all. Downstream that doubles per-peer
        # work (e.g. reputation queries) and, because the stale uuid scores
        # the cold-start neutral baseline while the live one carries the
        # real score, drew a sawtooth on the dashboard's trust timeline.
        # Evict the prior holder of this nickname (a genuinely new object)
        # from every structure first, so there is exactly one peer per
        # nickname. Re-adding the SAME object is left to the idempotent
        # guards below.
        prior = self.find_by_index(index)
        if prior is not None and prior is not who:
            try:
                self.all.remove(prior)
            except ValueError:
                pass
            self.listing.pop(getattr(prior, 'address', None), None)
            self.delete(prior)  # clears the nickname slot in hierarchy/valuation
            _probes.emit('peer.set', 'replaced',
                         peer_nick=index,
                         old_uuid=str(getattr(prior, 'uuid', None)),
                         new_uuid=str(getattr(who, 'uuid', None)))
            _probes.counter('peer.set', 'replaced')
        was_new = who.address not in self.listing
        if who.address not in self.listing:
            self.listing[who.address] = who
        if who not in self.all:
            self.all.append(who)
        self.hierarchy[level][index] = who
        self.valuation[-1][index] = who
        if was_new:
            _probes.emit('peer.set', 'added',
                         peer_uuid=str(getattr(who, 'uuid', None)),
                         peer_addr=getattr(who, 'address', None),
                         peer_nick=getattr(who, 'nickname', None))
            _probes.counter('peer.set', 'added')

    def delete(self, who):
        # hierarchy and valuation are independent structures; a peer can be
        # present in one but not the other (e.g. a wire-reconstructed Peers,
        # whose __init__ rebuilds all/listing from `hierarchy` but does not
        # backfill `valuation`). Guard each removal on its own lookup — gating
        # both on `idx is not None` indexed self.valuation[None] and crashed
        # the add()->delete(prior) resync path with a TypeError.
        index = self._index_by(who)
        idx = self._find(index)
        v_idx = self._find_v(index)
        if idx is not None:
            del self.hierarchy[idx][index]
        if v_idx is not None:
            del self.valuation[v_idx][index]

    def remove(self, who):
        """Forget ``who`` entirely: the nickname slots AND the address
        listing and ``all`` list the lookups actually read.

        ``delete`` clears only the slots -- it is the half ``add`` needs when
        it evicts a prior holder, and ``add`` clears the other two itself. A
        caller letting a peer go for good needs all four, or ``find_by_uuid``
        and the network's address attribution keep finding it. The C twin is
        processes_remove_peer. Returns True if anything was removed."""
        found = False
        for peer in [p for p in self.all if p is who or p.uuid == who.uuid]:
            self.all.remove(peer)
            found = True
        for addr in [a for a, p in self.listing.items()
                     if p is who or p.uuid == who.uuid]:
            del self.listing[addr]
            found = True
        index = self._index_by(who)
        slot = self.find_by_index(index)
        if slot is not None and (slot is who or slot.uuid == who.uuid):
            self.delete(slot)
            found = True
        return found

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
            if idx < len(self.valuation) - 1:
                self.valuation[idx + 1][index] = who
            else:
                del self.listing[who.address]
                self.all.remove(who)
            del self.valuation[idx][index]

    def filtered_for_persist(self, keep_uuids):
        """Return a deep-ish copy with only peers whose uuid is in keep_uuids.

        Used by the persistent-cohort save path so untrusted (rep<=0.5) peers
        don't survive a process restart. Hierarchy + valuation are filtered
        in parallel; peer objects themselves are reused (no deep copy).
        """
        keep = {str(u) for u in keep_uuids}
        def _filt(level):
            return {k: v for k, v in level.items()
                    if str(getattr(v, 'uuid', '')) in keep}
        return Peers(hierarchy=[_filt(lvl) for lvl in self.hierarchy],
                     valuation=[_filt(tier) for tier in self.valuation])
