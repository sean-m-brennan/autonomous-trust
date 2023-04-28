from ..config.configuration import Configuration


class Peers(Configuration):
    LEVELS = 3

    def __init__(self, hierarchy=None):
        self.hierarchy = hierarchy
        if hierarchy is None:
            self.hierarchy = [dict({}) for _ in range(self.LEVELS)]
        self.all = []
        self.listing = {}
        for idx in range(len(self.hierarchy)):
            for peer in self.hierarchy[idx].values():
                self.listing[peer.address] = peer
                self.all.append(peer)

    def to_dict(self):
        return dict(hierarchy=self.hierarchy)

    @staticmethod
    def _index_by(who):
        return who.nickname

    def _find(self, index):
        for idx in range(len(self.hierarchy)):
            if index in self.hierarchy[idx].keys():
                return idx
        return

    def find_by_index(self, index):
        idx = self._find(index)
        if idx is not None:
            return self.hierarchy[idx][index]

    def find_by_address(self, address):
        if address in self.listing.keys():
            return self.listing[address]
        return None

    def promote(self, who):
        if who.address not in self.listing.keys():
            self.listing[who.address] = who
        if who not in self.all:
            self.all.append(who)
        index = self._index_by(who)
        idx = self._find(index)
        if idx is not None:
            if idx > 0:
                self.hierarchy[idx - 1][index] = who
                del self.hierarchy[idx][index]
        else:
            self.hierarchy[-1][index] = who

    def demote(self, who):
        index = self._index_by(who)
        idx = self._find(index)
        if idx is not None:
            if idx < len(self.hierarchy):
                self.hierarchy[idx + 1][index] = who
            else:
                del self.listing[who.address]
                self.all.remove(who)
            del self.hierarchy[idx][index]
