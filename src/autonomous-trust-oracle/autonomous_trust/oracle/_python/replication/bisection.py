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
"""The bisection dispute game for a replicated task (R+D.md §12.6, slice C).

When two executors disagree about a long computation, :mod:`.adjudication`
returns ``dispute`` and scores nobody: a majority is not an oracle, and one
replica's word must not defame the executor it checked. This resolves that
dispute the way Truebit and optimistic-rollup fraud proofs do -- by localizing
the fault to a single step rather than re-running the whole computation, at a
cost logarithmic in its length.

**Why a hash chain, not a list of states.** Each executor commits to a chained
digest ``h_i = H(h_{i-1} || s_i)`` (``h_0 = H(s_0)``, the shared input). The
chaining is the whole point: because ``h_i`` depends on every state up to ``i``,
"the two chains differ at index ``i``" is MONOTONIC -- once they differ they
differ forever -- which is exactly what lets a binary search find the FIRST
divergent step in ``O(log n)`` challenges without either executor revealing more
than one digest per round. A bare list of states gives no such monotonicity: two
states can differ at ``k`` and agree again at ``k+1``, and no binary search is
sound over it. The primitive is the codebase's Merkle hash --- blake2b, 64-char
lowercase hex --- so a committed root is identical in the C twin
(``src/c/extensions/replication/bisection.c``).

**What the conformance corpus pins, and what it does not.** It pins the game:
the committed root, the divergence index the search finds, and the verdict the
single-step check renders against a reference trace that stands in for
"re-execute step k". It does NOT wire this to live tasks, because the game
requires DETERMINISTIC REPLAY of a peer's work -- a real constraint on how a
capability is written (the doc is explicit), and one AT cannot impose on an
arbitrary capability unilaterally. The live path is gated on that precondition;
see doc/architecture/replication.md.

**States are opaque tokens.** An intermediate state is compared for exact
equality, and hashed as its UTF-8 bytes. Numeric tolerance belongs to a task's
final RESULT (slice B), not to the bit-exact intermediate states a
deterministic replay produces; a step either reproduces or it does not.

The verdicts are :mod:`.adjudication`'s own -- ``corroborated`` / ``outvoted``
-- so :func:`.adjudication.verify` maps a resolved dispute to the same
``replication``-channel scores an outright majority would.
"""

from __future__ import annotations

from typing import Any, Optional

from autonomous_trust.core.structures.merkle import MerkleTree

from .adjudication import CORROBORATED, OUTVOTED


def _state_bytes(state: Any) -> bytes:
    """A state token's canonical bytes for hashing: its UTF-8 text."""
    if isinstance(state, bytes):
        return state
    return str(state).encode('utf-8')


def hash_chain(states: list[Any]) -> list[str]:
    """The committed chain ``h_0 .. h_{n-1}`` as 64-char lowercase-hex strings.

    ``h_0 = H(s_0)`` and ``h_i = H(h_{i-1} || s_i)``, the same
    canonical-content-chained-with-previous form the reputation Merkle entry
    uses, so the digest is identical in both runtimes.
    """
    chain: list[str] = []
    prev = b''
    for state in states:
        digest = MerkleTree.get_hash(prev + _state_bytes(state))  # hex bytes
        chain.append(digest.decode('ascii'))
        prev = digest
    return chain


def commit_root(states: list[Any]) -> Optional[str]:
    """The executor's committed root: the final chain digest, or ``None`` for
    an empty trace (nothing was computed to commit to)."""
    chain = hash_chain(states)
    return chain[-1] if chain else None


def first_divergence(chain_a: list[str], chain_b: list[str]) -> Optional[int]:
    """The first index at which two committed chains differ, by binary search.

    ``None`` when neither chain diverges from the other over their common
    length AND they are the same length; when they agree over the common length
    but one is longer, the divergence is at that common length (one executor
    kept computing past where the other stopped). Relies on the chain's
    monotonic "differ" predicate; a raw state list could not be searched this
    way.
    """
    n = min(len(chain_a), len(chain_b))
    if n == 0 or chain_a[n - 1] == chain_b[n - 1]:
        return n if len(chain_a) != len(chain_b) else None
    # differ(n-1) is true and differ is monotonic: find the smallest true.
    lo, hi = 0, n - 1
    while lo < hi:
        mid = (lo + hi) // 2
        if chain_a[mid] != chain_b[mid]:
            hi = mid
        else:
            lo = mid + 1
    return lo


def bisect_adjudicate(peer_a: str, states_a: list[Any],
                      peer_b: str, states_b: list[Any],
                      reference: list[Any]
                      ) -> tuple[Optional[int], dict[str, str]]:
    """Resolve a two-way dispute by localizing and checking the first divergent
    step.

    Returns ``(divergence_index, {peer: verdict})``. Both executors agree at the
    input, so the search finds the first step where their committed chains part;
    the reference's state at that step is the ground truth a re-execution would
    produce, and whichever executor reproduced it is ``corroborated`` while one
    that did not is ``outvoted``. Both can be outvoted -- two executors wrong in
    different ways at the same step -- which is the honest outcome, not a tie.

    ``divergence_index`` is ``None`` only when the two never diverge, in which
    case there was no dispute to resolve and both are ``corroborated``.
    """
    chain_a = hash_chain(states_a)
    chain_b = hash_chain(states_b)
    k = first_divergence(chain_a, chain_b)
    if k is None:
        return None, {peer_a: CORROBORATED, peer_b: CORROBORATED}

    ref_k = reference[k] if k < len(reference) else None
    a_k = states_a[k] if k < len(states_a) else None
    b_k = states_b[k] if k < len(states_b) else None
    return k, {
        peer_a: CORROBORATED if a_k == ref_k else OUTVOTED,
        peer_b: CORROBORATED if b_k == ref_k else OUTVOTED,
    }


# --- the live game (RD_12.6_LIVE_REPLICATION_PLAN.md §3.5) --------------------
#
# bisect_adjudicate above holds both traces whole. A live verifier holds only
# what each executor committed to, (trace_len, trace_root), and asks for
# digests one index at a time. The session keeps an interval (lo, hi) with
# the two chains differing at hi and agreeing at lo - 1 (or lo = 0), and ends
# when lo == hi = k, the first divergent step. Soundness does not rest on the
# executors answering honestly: a lie about a midpoint only moves k, and at k
# each executor must reveal states that hash to its own claimed digests.

def _digest(prev: Optional[str], state: Any) -> str:
    """``H(prev || state)``, ``prev`` as its hex text (none for h_0)."""
    head = prev.encode('ascii') if prev else b''
    return MerkleTree.get_hash(head + _state_bytes(state)).decode('ascii')


class ChallengeSession:
    """The verifier's side of the bisection game over two commitments.

    Executor ``'a'`` committed ``(len_a, root_a)`` and ``'b'`` ``(len_b,
    root_b)``; a root is ``None`` for an empty trace. :meth:`pending` names
    the index to ask about and which executors still owe a digest there (a
    committed root is never asked for again), :meth:`answer` records the
    replies, and once :attr:`done`, :attr:`divergence` is the first step where
    the chains part. Mirrors C ``at_repl_session_t``."""

    def __init__(self, len_a: int, root_a: Optional[str],
                 len_b: int, root_b: Optional[str]) -> None:
        self.lens = {'a': int(len_a), 'b': int(len_b)}
        self.digests: dict[str, dict[int, str]] = {'a': {}, 'b': {}}
        self.asked: list[int] = []
        for side, n, root in (('a', len_a, root_a), ('b', len_b, root_b)):
            if n > 0 and root is not None:
                self.digests[side][n - 1] = root
        n = min(len_a, len_b)
        if len_a == len_b and root_a == root_b:
            self.lo = self.hi = None           # no dispute to resolve
        elif n == 0:
            self.lo = self.hi = 0
        elif len_a == len_b:
            self.lo, self.hi = 0, n - 1
        else:
            # The shorter has no state at n, so the chains differ there.
            self.lo, self.hi = 0, n

    @property
    def disputed(self) -> bool:
        return self.lo is not None

    @property
    def done(self) -> bool:
        return self.pending() is None

    @property
    def divergence(self) -> Optional[int]:
        return self.lo if self.disputed and self.done else None

    def pending(self) -> Optional[tuple[int, tuple[str, ...]]]:
        """``(index, sides that owe a digest there)``, or None when done.
        Once the search has narrowed to k, a side whose trace reaches k but
        whose digest there is not yet known (the longer of two traces of
        different lengths) is asked for it before the session is done."""
        if self.lo is None:
            return None
        at = (self.lo + self.hi) // 2 if self.lo < self.hi else self.lo
        owe = tuple(s for s in ('a', 'b')
                    if at not in self.digests[s]
                    and (self.lo < self.hi or at < self.lens[s]))
        if self.lo == self.hi and not owe:
            return None
        return at, owe

    def answer(self, index: int, digest_a: Optional[str] = None,
               digest_b: Optional[str] = None) -> None:
        """Record the digests owed at ``index`` and narrow the interval.
        Raises ValueError for an index not asked or a digest still owed."""
        want = self.pending()
        if want is None or want[0] != index:
            raise ValueError('index %r was not asked' % (index,))
        for side, digest in (('a', digest_a), ('b', digest_b)):
            if side in want[1]:
                if not isinstance(digest, str) or len(digest) != 64:
                    raise ValueError('a digest is owed by %s' % side)
                self.digests[side][index] = digest
        self.asked.append(index)
        if self.lo == self.hi:
            return                              # the final fetch at k
        if self.digests['a'][index] != self.digests['b'][index]:
            self.hi = index
        else:
            self.lo = index + 1

    def agreed_prev(self) -> Optional[str]:
        """``h_{k-1}``, which both chains share, or None at ``k == 0``."""
        k = self.divergence
        return None if not k else self.digests['a'][k - 1]

    def claimed(self, side: str) -> Optional[str]:
        """``side``'s digest at ``k``, or None when its trace ends before k."""
        return self.digests[side].get(self.divergence)


def reveal_consistent(session: ChallengeSession, side: str,
                      reveal: dict[str, Any], max_state_bytes: int) -> bool:
    """Do ``side``'s revealed states hash to its own claimed digests?

    ``reveal`` holds ``prev`` (``h_{k-2}``, absent for k < 2), ``pre``
    (``s_{k-1}``, absent at k = 0) and ``state`` (``s_k``, absent when the
    side's trace ends before k). An executor whose reveal contradicts its own
    commitment, or whose state is over ``max_state_bytes``, is inconsistent.
    Mirrors C ``at_repl_reveal_consistent``."""
    k = session.divergence
    pre, state, prev = reveal.get('pre'), reveal.get('state'), reveal.get('prev')
    for s in (pre, state):
        if s is not None and len(_state_bytes(s)) > max_state_bytes:
            return False
    if k > 0:
        if pre is None or (prev is None) != (k == 1):
            return False
        if prev is not None and len(prev) != 64:
            return False
        if _digest(prev, pre) != session.agreed_prev():
            return False
    elif pre is not None:
        return False
    claimed = session.claimed(side)
    if claimed is None:
        return state is None
    return state is not None and _digest(session.agreed_prev(), state) == claimed


def settle(session: ChallengeSession, reveals: dict[str, dict[str, Any]],
           truth, max_state_bytes: int) -> dict[str, str]:
    """The verdict on each executor once the session is done.

    ``truth(pre_state)`` re-executes the divergent step from the verified
    pre-state (``None`` at k = 0, where it returns the agreed ``s_0``) and
    returns the true ``s_k``, or None when the computation ends at ``k - 1``.
    An executor whose reveal is inconsistent is ``outvoted``; a consistent one
    is ``corroborated`` iff its ``s_k`` is the true one. With no consistent
    pre-state at k > 0 there is nothing to re-execute from, and both are
    ``outvoted``: each contradicted its own commitment. Mirrors C
    ``at_repl_settle``."""
    k = session.divergence
    ok = {s: reveal_consistent(session, s, reveals.get(s) or {}, max_state_bytes)
          for s in ('a', 'b')}
    pre = None
    if k > 0:
        good = [s for s in ('a', 'b') if ok[s]]
        if not good:
            return {'a': OUTVOTED, 'b': OUTVOTED}
        pre = reveals[good[0]].get('pre')
    true_k = truth(pre)
    return {s: CORROBORATED if ok[s] and (reveals[s] or {}).get('state') == true_k
            else OUTVOTED for s in ('a', 'b')}
