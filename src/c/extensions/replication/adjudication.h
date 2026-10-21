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

#ifndef AT_REPLICATION_ADJUDICATION_H
#define AT_REPLICATION_ADJUDICATION_H

/** @addtogroup internal_replication
 *  @{
 *
 * Adjudicating a replicated task by agreement (R+D.md §12.6, slice B), the C
 * twin of `autonomous_trust.core._python.replication.adjudication`.
 *
 * Several executors return a result for the same task; this decides what that
 * says about each. Same shape as the certificate layer's verifier:
 * `at_replication_adjudicate` produces the FINDING (a per-executor verdict, so
 * the corpus can pin the finding itself) and `at_replication_verify` maps a
 * verdict to the (score, channel) the reputation process folds in, or to
 * nothing.
 *
 *   - CORROBORATED: agrees with a strict majority -> a good replication score.
 *   - OUTVOTED: in the minority against a strict majority -> a bad score.
 *   - DISPUTE: no strict majority -> nobody scored; the bisection game (slice
 *     C) resolves it. A majority is not an oracle, so one replica's word must
 *     never defame the executor it checked.
 *   - SINGLE: fewer than two results -> nothing was replicated.
 *
 * Agreement is deterministic: two numeric results agree within the capability's
 * tolerance (default exact), anything else only on exact equality, and a
 * numeric result never agrees with a non-numeric one (Python's `42 == "42"` is
 * false). The majority is the value the most executors agree with, in input
 * order on a tie, held by strictly more than half.
 */

#include <stdbool.h>
#include <stddef.h>

#include "replication/replication.h"   /* AT_REPL_NAME_LEN */

/** Canonical-string buffer for a non-numeric result. */
#define AT_REPL_VALUE_LEN 127

typedef enum
{
    AT_REPL_CORROBORATED = 0,
    AT_REPL_OUTVOTED,
    AT_REPL_DISPUTE,
    AT_REPL_SINGLE
} at_repl_verdict_t;

/** One executor's result, as the adjudicator compares it. Numeric results
 * carry @c num; everything else carries a canonical @c text, and the two are
 * never equal across the divide. */
typedef struct
{
    char   peer[AT_REPL_NAME_LEN + 1];
    bool   is_number;
    double num;
    char   text[AT_REPL_VALUE_LEN + 1];
} at_repl_result_t;

/** The channel a replication finding lands on and its two scores, matching the
 * Python twin (and the certificate layer's proved-right / proved-wrong pair). */
#define AT_REPL_CORROBORATED_SCORE 0.9
#define AT_REPL_OUTVOTED_SCORE     0.1

/** @brief Verdict per executor for one replicated task.
 *
 * Writes @p verdicts_out[i] for each of the @p n results in @p results.
 * Fewer than two results is SINGLE for each. @p tolerance is the numeric
 * agreement tolerance. Mirrors Python `adjudicate`. */
void at_replication_adjudicate(const at_repl_result_t *results, size_t n,
                               double tolerance,
                               at_repl_verdict_t *verdicts_out);

/** @brief Map a verdict to (score, channel), or report there is none.
 *
 * Returns true and fills @p score_out / @p channel_out for CORROBORATED and
 * OUTVOTED; returns false for DISPUTE and SINGLE. @p channel_out is set to the
 * static channel string. Mirrors Python `verify`. */
bool at_replication_verify(at_repl_verdict_t verdict, double *score_out,
                           const char **channel_out);

/** @brief The verdict's stable lowercase name (for diagnostics and the
 * conformance corpus): "corroborated" / "outvoted" / "dispute" / "single". */
const char *at_replication_verdict_str(at_repl_verdict_t verdict);

/** @} */

#endif /* AT_REPLICATION_ADJUDICATION_H */
