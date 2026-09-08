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
(``src/c/autonomous_trust/replication/bisection.c``).

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
