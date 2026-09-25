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

#include "replication/adjudication.h"

#include <math.h>
#include <string.h>

#include "reputation/tx_channel.h"   /* TX_CHANNEL_REPLICATION */

static bool _agree(const at_repl_result_t *a, const at_repl_result_t *b,
                   double tolerance)
{
    /* A numeric result never agrees with a non-numeric one, matching Python,
     * where `42 == "42"` is false: the is_number divide is checked first. */
    if (a->is_number != b->is_number)
        return false;
    if (a->is_number)
        return fabs(a->num - b->num) <= tolerance;
    return strcmp(a->text, b->text) == 0;
}

void at_replication_adjudicate(const at_repl_result_t *results, size_t n,
                               double tolerance,
                               at_repl_verdict_t *verdicts_out)
{
    if (results == NULL || verdicts_out == NULL)
        return;
    if (n < 2)
    {
        for (size_t i = 0; i < n; i++)
            verdicts_out[i] = AT_REPL_SINGLE;
        return;
    }

    size_t best_index = 0;
    size_t best_count = 0;
    for (size_t i = 0; i < n; i++)
    {
        size_t count = 0;
        for (size_t j = 0; j < n; j++)
            if (_agree(&results[i], &results[j], tolerance))
                count++;
        if (count > best_count)
        {
            best_count = count;
            best_index = i;
        }
    }

    if (best_count * 2 > n)
    {
        for (size_t i = 0; i < n; i++)
            verdicts_out[i] = _agree(&results[i], &results[best_index],
                                     tolerance)
                                  ? AT_REPL_CORROBORATED
                                  : AT_REPL_OUTVOTED;
    }
    else
    {
        for (size_t i = 0; i < n; i++)
            verdicts_out[i] = AT_REPL_DISPUTE;
    }
}

bool at_replication_verify(at_repl_verdict_t verdict, double *score_out,
                           const char **channel_out)
{
    double score = 0.0;
    switch (verdict)
    {
    case AT_REPL_CORROBORATED:
        score = AT_REPL_CORROBORATED_SCORE;
        break;
    case AT_REPL_OUTVOTED:
        score = AT_REPL_OUTVOTED_SCORE;
        break;
    case AT_REPL_DISPUTE:
    case AT_REPL_SINGLE:
        return false;   /* no score: a dispute goes to bisection, a single
                         * result was never replicated */
    }
    if (score_out != NULL)
        *score_out = score;
    if (channel_out != NULL)
        *channel_out = TX_CHANNEL_REPLICATION;
    return true;
}

const char *at_replication_verdict_str(at_repl_verdict_t verdict)
{
    switch (verdict)
    {
    case AT_REPL_CORROBORATED: return "corroborated";
    case AT_REPL_OUTVOTED:     return "outvoted";
    case AT_REPL_DISPUTE:      return "dispute";
    case AT_REPL_SINGLE:       return "single";
    default:                   return "unknown";
    }
}
