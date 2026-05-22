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

import os
from collections import OrderedDict
from collections.abc import Mapping
from uuid import UUID

from ..config import Configuration


class TransactionScore(Configuration):
    def __init__(self, task_id, score, capability_name: str = None):
        self.task_id = task_id
        self.score = score
        # Optional: name of the Capability whose execution produced this
        # TS. Used by _pure_reputation to look up transaction_weight at
        # scoring time (Slice 3). None means "unknown / legacy" — weight
        # defaults to 1. See doc/architecture/trust-tiers.md §4.4.
        self.capability_name = capability_name


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
        elif self.p2_id is None and peer_id != self.p1_id:
            # A Transaction is intrinsically bilateral; the same peer cannot
            # occupy both slots. Without this guard a duplicate `committed`
            # broadcast for the same paxos round would set p2 = p1, producing
            # a self-transaction that CTFT's `p1==peer && p2==self` check
            # silently rejects.
            self.p2_id = peer_id
            self.p2_score = score


class TransactionHistory(Mapping):
    """Bounded commit log of bilateral Transactions.

    ``max_chain_len`` caps the resident chain (default
    ``DEFAULT_MAX_CHAIN_LEN``). When the cap is reached, the oldest
    committed tx is evicted from ``_chain`` along with its entries in
    ``_task_mapping`` and ``_peer_mapping``. ``tx.index`` stays
    monotonically increasing across evictions so ``era()`` and
    ``catchup()`` retain absolute-index semantics — only the suffix
    still resident in ``_chain`` is materializable.

    Override the default with ``max_chain_len`` (constructor) or the
    ``AT_TX_HISTORY_CAP`` env var; constructor wins. Loaded chains
    longer than the cap are accepted as-is — trimming starts on the
    first new ``update()``. Mirrors the C twin in
    ``src/c/autonomous_trust/reputation/reputation.c``; keep
    eviction semantics in lockstep so the conformance corpus stays
    valid.

    Behavior change vs. the unbounded predecessor: ``catchup()`` no
    longer back-fills indices below ``_next_index`` (i.e. anything
    already evicted is gone — peers that need the old prefix can
    no longer fetch it from us). Acceptable because reputation
    scoring weights recent txs heavily, and consensus drift past
    the window is unrecoverable anyway.

    Tombstone: evicted ``task_id``s are kept in ``_evicted_task_ids``
    (a bounded FIFO ordered set the same size as the chain) so
    ``update()`` can refuse to re-create entries for tasks we
    already committed and rolled out. Without this, a late
    ``committed`` broadcast — common when handle_accepted's dedup
    window is exceeded and re-broadcasts fire — would call
    ``update(evicted_task, …)``, the ``task_id not in _task_mapping``
    branch would create a fresh ``Transaction``, and the
    counterparty's late ``committed`` would complete it and append
    a zombie to the head of the chain (evicting a legitimate recent
    entry). The tombstone breaks that loop.
    """

    DEFAULT_MAX_CHAIN_LEN = 200

    def __init__(self, _chain: list[Transaction] = None,
                 max_chain_len: int = None):
        if max_chain_len is None:
            env = os.environ.get('AT_TX_HISTORY_CAP')
            try:
                max_chain_len = (int(env) if env
                                 else self.DEFAULT_MAX_CHAIN_LEN)
            except ValueError:
                max_chain_len = self.DEFAULT_MAX_CHAIN_LEN
        if max_chain_len < 1:
            raise ValueError("max_chain_len must be >= 1")
        self.max_chain_len = max_chain_len
        self._chain: list[Transaction] = list(_chain) if _chain else []
        self._task_mapping: dict[UUID, Transaction] = {
            link.task_id: link for link in self._chain}
        self._peer_mapping: dict[UUID, list[Transaction]] = {}
        for link in self._chain:
            self._map_peers(link)
        # Monotonic insertion counter — survives evictions so
        # tx.index keeps growing forever. Seed past the highest
        # index already in the loaded chain (if any) so subsequent
        # appends don't collide.
        max_existing = max(
            (link.index for link in self._chain if link.index is not None),
            default=-1)
        self._next_index = max_existing + 1
        # Absolute index of self._chain[0] — needed to translate an
        # absolute era(idx) request into a deque-relative offset after
        # the head has been rolled forward by eviction.
        if self._chain and self._chain[0].index is not None:
            self._first_index = self._chain[0].index
        else:
            self._first_index = 0
        # Tombstone: FIFO ordered set of evicted task_ids. Sized to
        # match max_chain_len so we remember the most-recent
        # max_chain_len evictions; combined with the resident chain,
        # the dedup horizon covers the last 2 * max_chain_len task_ids.
        # See class docstring for the late-committed reanimation
        # hazard this guards against.
        self._evicted_task_ids: 'OrderedDict[UUID, None]' = OrderedDict()

    def _map_peers(self, tx: Transaction):
        if tx.p1_id is not None:
            if tx.p1_id not in self._peer_mapping:
                self._peer_mapping[tx.p1_id] = []
            self._peer_mapping[tx.p1_id].append(tx)
        if tx.p2_id is not None:
            if tx.p2_id not in self._peer_mapping:
                self._peer_mapping[tx.p2_id] = []
            self._peer_mapping[tx.p2_id].append(tx)

    def _evict_oldest(self):
        """Drop chain[0] and scrub it from the task and peer maps.

        Identity-compares on removal because ``_map_peers`` may have
        appended the same tx twice to the same peer's list (it fires
        on both the p1-only and completed states), so a single
        ``list.remove`` would leave a stale reference behind.
        """
        oldest = self._chain.pop(0)
        self._task_mapping.pop(oldest.task_id, None)
        for peer_id in {oldest.p1_id, oldest.p2_id} - {None}:
            lst = self._peer_mapping.get(peer_id)
            if not lst:
                continue
            lst[:] = [tx for tx in lst if tx is not oldest]
            if not lst:
                del self._peer_mapping[peer_id]
        # Tombstone the evicted task so late `committed` broadcasts
        # for it can't reanimate a zombie entry. Bounded same as
        # the chain — together they cover 2 * max_chain_len task_ids.
        self._evicted_task_ids[oldest.task_id] = None
        while len(self._evicted_task_ids) > self.max_chain_len:
            self._evicted_task_ids.popitem(last=False)
        if self._chain and self._chain[0].index is not None:
            self._first_index = self._chain[0].index
        else:
            self._first_index = self._next_index

    def __getitem__(self, key):
        return self._task_mapping[key]

    def update(self, task_id: UUID, peer_id: UUID, score: float):
        if task_id not in self._task_mapping:
            # Refuse to reanimate a task we already committed and
            # rolled out of the resident chain. handle_committed
            # calls update() unconditionally on inbound broadcasts;
            # without this guard, late `committed` messages would
            # build a half-completed Transaction in _task_mapping
            # that any later counterparty-side late `committed`
            # would complete and re-insert at the head of the
            # chain — silently evicting a legitimate recent entry
            # and corrupting reputation math.
            if task_id in self._evicted_task_ids:
                return
            self._task_mapping[task_id] = Transaction(task_id)
        tx = self._task_mapping[task_id]
        if len(tx) == 2:
            return  # ignore duplicates
        if peer_id == tx.p1_id:
            # Skip before `_map_peers` so we don't re-append the same tx to
            # `_peer_mapping[p1_id]` (which would inflate by_peer() results
            # and skew downstream peer-tx counts).
            return
        tx.add(peer_id, score)
        self._map_peers(tx)
        if len(tx) > 1:
            tx.index = self._next_index
            self._next_index += 1
            if len(self._chain) >= self.max_chain_len:
                self._evict_oldest()
            self._chain.append(tx)
            if len(self._chain) == 1:
                self._first_index = tx.index

    def __len__(self):
        return len(self._chain)

    def __iter__(self):
        return self._chain.__iter__()

    def by_peer(self, peer_id: UUID):
        return self._peer_mapping[peer_id]

    def era(self, idx: int):
        """Return the chain suffix from absolute index ``idx`` onward.

        If ``idx`` predates ``_first_index`` (entries already evicted)
        the available suffix is returned; older entries are gone.
        """
        if not self._chain:
            return []
        offset = max(0, idx - self._first_index)
        return self._chain[offset:]

    def catchup(self, chain: list[Transaction]):
        for link in chain:
            if link.index is None:
                continue
            if link.index >= self._next_index:
                self.update(link.task_id, link.p1_id, link.p1_score)
                self.update(link.task_id, link.p2_id, link.p2_score)


class Reputation(Configuration):
    def __init__(self, peer_id: UUID, score: float):
        self.peer_id = peer_id
        self.score = score


class Reputations(Configuration):
    def __init__(self, current: dict[UUID, float] = None):
        if current is None:
            self.current = {}
        else:
            # Convert string keys back to UUIDs (from JSON deserialization)
            self.current = {UUID(k) if isinstance(k, str) else k: v
                            for k, v in current.items()}

    def __getitem__(self, key):
        return self.current[key]

    def __contains__(self, item):
        return item in self.current

    def to_dict(self):
        return {'current': {str(k): v for k, v in self.current.items()}}

    def update(self, peer_id: UUID, score: float):
        self.current[peer_id] = score
