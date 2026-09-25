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

#ifndef AT_REPLICATION_SAMPLING_H
#define AT_REPLICATION_SAMPLING_H

/** @addtogroup internal_replication
 *  @{
 *
 * The arithmetic of replication sampling: one draw, one decision (R+D.md
 * §12.6), the C twin of `autonomous_trust.core._python.replication.sampling`.
 *
 * Build-order step 6 of doc/verification_oracle.md. Replicating a random
 * fraction p of tasks (rather than all of them) is what makes replication
 * affordable: if detection costs a peer a multiplicative reputation loss L and
 * a completed task gains it g, cheating is unprofitable whenever p * L > g, and
 * in AT L is a tier demotion, so p can be small (the BOINC argument).
 *
 * The draw must be UNPREDICTABLE TO THE PEER and REPRODUCIBLE for the corpus,
 * and both hold when the seed is a parameter, exactly as for the Freivalds
 * challenge in the certificate layer: production draws it from the verifier's
 * own entropy at check time, a replay supplies a fixed one. This file is pure —
 * no state, no clock, no configuration — so it stays identical to the Python
 * twin down to the operation order.
 */

#include <stdbool.h>
#include <stdint.h>

/** @brief A single draw in [0.0, 1.0) from SplitMix64(seed).
 *
 * The high 53 bits of one 64-bit output scaled by 2**-53 — high bits because
 * SplitMix64's low bits carry the least entropy, 53 because that is the double
 * mantissa, so `(u >> 11) * 2**-53` is exact. Identical to the Python
 * `uniform_unit`. */
double at_replication_uniform_unit(uint64_t seed);

/** @brief A probability forced into [0.0, 1.0]. Forgives a per-task override;
 * a declaration is validated on load instead. */
double at_replication_clamp_prob(double prob);

/** @brief Decide whether to replicate one completed task.
 *
 * Returns the boolean the caller acts on; when @p draw_out is non-NULL the draw
 * it came from is copied there, so a scenario can pin the draw and not only the
 * decision. `draw < p` (not `<=`): p == 0 replicates nothing even on a zero
 * draw, p == 1 replicates everything since draw is strictly below 1. */
bool at_replication_should_replicate(double prob, uint64_t seed,
                                     double *draw_out);

/** @} */

#endif /* AT_REPLICATION_SAMPLING_H */
