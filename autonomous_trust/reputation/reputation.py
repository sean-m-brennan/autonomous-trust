from collections.abc import Mapping
from uuid import UUID

from ..config import Configuration


class TransactionScore(Configuration):
    def __init__(self, task_id, score):
        self.task_id = task_id
        self.score = score


class Transaction(Configuration):
    def __init__(self, task_id: UUID, p1_id: UUID = None, p1_score: float = None,
                 p2_id: UUID = None, p2_score: float = None, index: int = None):
        self.task_id = task_id
        self.p1_id = p1_id
        self.p1_score = p1_score
        self.p2_id = p2_id
        self.p2_score = p2_score
        self.index = index

    def __len__(self):
        if self.p1_id is None and self.p2_id is None:
            return 0
        if self.p1_id is None or self.p2_id is None:
            return 1
        return 2

    def add(self, peer_id: UUID, score: float):
        if self.p1_id is None:
            self.p1_id = peer_id
            self.p1_score = score
        elif self.p2_id is None:
            self.p2_id = peer_id
            self.p2_score = score


class TransactionHistory(Mapping):
    def __init__(self, _chain: list[Transaction] = None):
        self._chain = _chain
        if _chain is None:
            self._chain = []
        self._task_mapping = {}
        for link in self._chain:
            self._task_mapping[link.task_id] = link
        self._peer_mapping = {}
        for link in self._chain:
            self._map_peers(link)

    def _map_peers(self, tx: Transaction):
        if tx.p1_id is not None:
            if tx.p1_id not in self._peer_mapping:
                self._peer_mapping[tx.p1_id] = []
            self._peer_mapping[tx.p1_id].append(tx)
        if tx.p2_id is not None:
            if tx.p2_id not in self._peer_mapping:
                self._peer_mapping[tx.p2_id] = []
            self._peer_mapping[tx.p2_id].append(tx)

    def __getitem__(self, key):
        return self._task_mapping[key]

    def update(self, task_id: UUID, peer_id: UUID, score: float):
        if task_id not in self._task_mapping:
            self._task_mapping[task_id] = Transaction(task_id)
        tx = self._task_mapping[task_id]
        if len(tx) == 2:
            return  # ignore duplicates
        tx.add(peer_id, score)
        self._map_peers(tx)
        if len(tx) > 1:
            tx.index = len(self._chain)
            self._chain.append(tx)

    def __len__(self):
        return len(self._chain)

    def __iter__(self):
        self._chain.__iter__()

    def by_peer(self, peer_id: UUID):
        return self._peer_mapping[peer_id]

    def era(self, idx: int):
        return self._chain[idx:]

    def catchup(self, chain: list[Transaction]):
        for link in chain:
            if link.index > len(self._chain):
                self.update(link.task_id, link.p1_id, link.p1_score)
                self.update(link.task_id, link.p2_id, link.p2_score)


class Reputation(Configuration):
    def __init__(self, peer_id: UUID, score: float):
        self.peer_id = peer_id
        self.score = score


class Reputations(Configuration):
    def __init__(self, current: dict[UUID, float] = None):
        self.current = current
        if current is None:
            self.current = {}

    def __getitem__(self, key):
        return self.current[key]

    def __contains__(self, item):
        return item in self.current

    def update(self, peer_id: UUID, score: float):
        self.current[peer_id] = score
