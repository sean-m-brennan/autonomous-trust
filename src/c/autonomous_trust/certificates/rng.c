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

#include <stddef.h>

#include "certificates/rng.h"

void at_splitmix64_init(at_splitmix64_t *rng, uint64_t seed)
{
    if (rng != NULL)
        rng->state = seed;
}

uint64_t at_splitmix64_next(at_splitmix64_t *rng)
{
    /* The reference SplitMix64. uint64_t wraps, which is what the Python twin
     * spells as an explicit mask on every step; the two streams agree bit for
     * bit only because both wrap at the same places. */
    rng->state += 0x9E3779B97F4A7C15ULL;
    uint64_t z = rng->state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

double at_splitmix64_pm1(at_splitmix64_t *rng)
{
    return (at_splitmix64_next(rng) & 1u) ? 1.0 : -1.0;
}
