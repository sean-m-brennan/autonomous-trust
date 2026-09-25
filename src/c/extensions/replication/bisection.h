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
 * C twin of `autonomous_trust.core._python.replication.bisection`.
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

/** @} */

#endif /* AT_REPLICATION_BISECTION_H */
