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

#ifndef AT_CERT_RNG_H
#define AT_CERT_RNG_H

/** @addtogroup internal_certificates
 *  @{
 *
 * SplitMix64, the one PRNG both runtimes draw a verifier challenge from.
 *
 * Freivalds' check multiplies by a random vector, and its soundness rests on
 * the prover not knowing that vector in advance. Two requirements pull in
 * opposite directions:
 *
 *   - The vector must be UNPREDICTABLE TO THE PEER. Deriving it from the
 *     matrices — a hash of the inputs, say — destroys the guarantee outright:
 *     the prover chooses C, so it can grind candidate answers until one passes
 *     a challenge it can compute itself.
 *   - The check must be REPRODUCIBLE, or the conformance corpus cannot pin it
 *     and the two runtimes cannot be shown to agree.
 *
 * Both hold when the SEED is a parameter: production draws it from the
 * requestor's own entropy at check time (the peer never sees it until the
 * check is over), and a replay supplies a fixed one. Same shape as the
 * observation clock in the physics layer, and as the probe challenge in
 * R+D.md §12.7 — the requestor's own record, never anything read off the reply.
 *
 * SplitMix64 (Steele, Lea and Flood, 2014) because it is eight lines of
 * integer arithmetic with no state beyond a counter, so this and the Python
 * twin emit identical streams for identical seeds. It is not cryptographic and
 * does not need to be: the requirement is that the peer cannot predict the
 * draw before answering, which the secrecy of the seed supplies.
 */

#include <stdint.h>

typedef struct
{
    uint64_t state;
} at_splitmix64_t;

/** @brief Seed the stream. */
void at_splitmix64_init(at_splitmix64_t *rng, uint64_t seed);

/** @brief The next 64 bits. */
uint64_t at_splitmix64_next(at_splitmix64_t *rng);

/**
 * @brief A challenge entry: -1.0 or +1.0, from the stream's low bit.
 *
 * Freivalds is usually stated over {0,1}. {-1,+1} has the same one-sided error
 * bound and is better conditioned: a zero entry silently drops a column from
 * the product, so a wrong answer differing only in dropped columns would
 * survive a round it should have failed.
 */
double at_splitmix64_pm1(at_splitmix64_t *rng);

/** @} */
#endif /* AT_CERT_RNG_H */
