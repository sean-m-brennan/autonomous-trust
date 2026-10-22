/********************
 *  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *******************/

#ifndef AT_REPLICATION_BISECTION_H
#define AT_REPLICATION_BISECTION_H

/** @addtogroup internal_replication
 *  @{
 *
 * The bisection dispute game for a replicated task (R+D.md §12.6, slice C), the
 * C twin of `autonomous_trust.oracle._python.replication.bisection`.
 *
 * When two executors disagree, the adjudicator returns `dispute` and scores
 * nobody; this resolves it the Truebit way, localizing the fault to a single
 * step rather than re-running. Each executor commits to a chained digest
 * h_i = H(h_{i-1} || s_i); the chaining makes "the chains differ at i"
 * MONOTONIC, so a binary search finds the FIRST divergent step in O(log n). The
 * hash is the codebase's Merkle primitive (blake2b, 64-hex), so a committed
 * root is identical to the Python twin. States are opaque tokens compared for
 * exact equality; numeric tolerance belongs to a final RESULT (slice B), not to
 * the bit-exact intermediate states a deterministic replay produces.
 */

#include <stdbool.h>
#include <stddef.h>

#include "replication/adjudication.h"   /* at_repl_verdict_t */

/** blake2b hex length, matching the reputation Merkle (TX_HASH_HEX_LEN). */
#define AT_REPL_HASH_HEX_LEN 64

/** Upper bound on trace length the conformance game models. */
#define AT_REPL_MAX_STEPS 256

/** @brief The committed root: the final chain digest as 64-hex + NUL.
 *
 * Returns false (and leaves @p out untouched) for an empty trace -- nothing was
 * computed to commit to. Mirrors Python `commit_root`. */
bool at_replication_commit_root(const char *const *states, size_t n,
                                char out[AT_REPL_HASH_HEX_LEN + 1]);

/** @brief Resolve a two-way dispute by localizing and checking the first
 * divergent step.
 *
 * Writes the divergence index to @p divergence_out and true to @p diverged_out
 * when the chains part; when they never diverge, @p diverged_out is false and
 * both verdicts are CORROBORATED (there was no dispute). Otherwise each verdict
 * is CORROBORATED when that executor's state at the divergent step equals the
 * reference's (the ground truth a re-execution would produce) and OUTVOTED when
 * it does not -- both may be OUTVOTED. Mirrors Python `bisect_adjudicate`.
 * Returns false only on a bad argument or a trace over AT_REPL_MAX_STEPS. */
bool at_replication_bisect_adjudicate(
    const char *const *states_a, size_t na,
    const char *const *states_b, size_t nb,
    const char *const *reference, size_t nref,
    int *divergence_out, bool *diverged_out,
    at_repl_verdict_t *verdict_a, at_repl_verdict_t *verdict_b);

/* ---- The live game (RD_12.6_LIVE_REPLICATION_PLAN.md section 3.5) --------
 *
 * at_replication_bisect_adjudicate holds both traces whole. A live verifier
 * holds only what each executor committed to, (trace_len, trace_root), and
 * asks for digests one index at a time. The session keeps an interval
 * (lo, hi) with the chains differing at hi and agreeing at lo - 1 (or
 * lo = 0), and ends at the first divergent step k. A lie about a midpoint
 * only moves k: at k each executor must reveal states that hash to its own
 * claimed digests. Mirrors Python ChallengeSession / reveal_consistent /
 * settle. Executor 0 is Python's 'a', executor 1 its 'b'. */

typedef struct
{
    int  lens[2];
    bool disputed;
    int  lo, hi;
    bool have[2][AT_REPL_MAX_STEPS + 1];
    char digests[2][AT_REPL_MAX_STEPS + 1][AT_REPL_HASH_HEX_LEN + 1];
} at_repl_session_t;

/** One executor's reveal at k: h_{k-2}, s_{k-1}, s_k, each NULL when absent
 * (k < 2, k = 0, and a trace that ends before k respectively). */
typedef struct
{
    const char *prev;
    const char *pre;
    const char *state;
} at_repl_reveal_t;

/** Re-execute the divergent step: the true s_k from the verified pre-state
 * (@p pre is NULL at k = 0, where it returns the agreed s_0), or NULL when
 * the computation ends at k - 1. */
typedef const char *(*at_repl_truth_fn)(const char *pre, void *ctx);

/** @brief Start a session over two commitments (a root is NULL for an empty
 * trace). Returns false for a length below 0 or over AT_REPL_MAX_STEPS. */
bool at_repl_session_init(at_repl_session_t *s, int len_a, const char *root_a,
                          int len_b, const char *root_b);

/** @brief The index to ask about and which executors owe a digest there;
 * false once the session is done (or there was no dispute). */
bool at_repl_session_pending(const at_repl_session_t *s, int *index, bool owe[2]);

/** @brief Record the digests owed at @p index (NULL for one not owed) and
 * narrow the interval. False for an index not asked or a digest still owed. */
bool at_repl_session_answer(at_repl_session_t *s, int index,
                            const char *digest_a, const char *digest_b);

/** @brief The first divergent step once done, or -1. */
int at_repl_session_divergence(const at_repl_session_t *s);

/** @brief Do @p side's revealed states hash to its own claimed digests, each
 * state within @p max_state_bytes? */
bool at_repl_reveal_consistent(const at_repl_session_t *s, int side,
                               const at_repl_reveal_t *r, size_t max_state_bytes);

/** @brief The verdict on each executor once the session is done: an
 * inconsistent reveal is OUTVOTED, a consistent one CORROBORATED iff its s_k
 * is the true one. With no consistent pre-state at k > 0, both are OUTVOTED. */
bool at_repl_settle(const at_repl_session_t *s, const at_repl_reveal_t reveals[2],
                    at_repl_truth_fn truth, void *ctx, size_t max_state_bytes,
                    at_repl_verdict_t out[2]);

/** @} */

#endif /* AT_REPLICATION_BISECTION_H */
