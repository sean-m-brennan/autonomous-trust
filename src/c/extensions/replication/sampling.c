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

#include "replication/sampling.h"

#include <stddef.h>

#include "certificates/rng.h"

/* 2**53: the draw keeps 53 bits because that is the IEEE-754 double mantissa,
 * so the multiply below is exact. Written as 2**-53 once, the same constant the
 * Python twin multiplies by. */
static const double AT_REPL_INV_TWO53 = 1.0 / 9007199254740992.0;

double at_replication_uniform_unit(uint64_t seed)
{
    at_splitmix64_t rng;
    at_splitmix64_init(&rng, seed);
    uint64_t u = at_splitmix64_next(&rng);
    return (double)(u >> 11) * AT_REPL_INV_TWO53;
}

double at_replication_clamp_prob(double prob)
{
    if (prob < 0.0)
        return 0.0;
    if (prob > 1.0)
        return 1.0;
    return prob;
}

bool at_replication_should_replicate(double prob, uint64_t seed,
                                     double *draw_out)
{
    double p = at_replication_clamp_prob(prob);
    double draw = at_replication_uniform_unit(seed);
    if (draw_out != NULL)
        *draw_out = draw;
    return draw < p;
}
