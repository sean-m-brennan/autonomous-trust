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

#ifndef AT_CERT_DRAT_H
#define AT_CERT_DRAT_H

/** @addtogroup internal_certificates
 *  @{
 *
 * A DRAT refutation checker: the UNSAT half of the `sat` certificate.
 *
 * A peer claiming a formula is satisfiable proves it in one line — hand over
 * the assignment. A peer claiming it is UNsatisfiable can exhibit nothing so
 * simple, and "I searched and found nothing" is precisely the claim a lying
 * peer makes for free. DRAT makes it checkable: the peer emits the lemmas its
 * solver derived, and this replays them, confirming each is implied by what
 * came before and that the sequence ends at the empty clause.
 *
 * The check is the standard one (Heule, Hunt and Wetzler, FMCAD 2013). A lemma
 * is accepted when it is RUP — assume every literal false, unit-propagate, and
 * reach a conflict — or RAT on its first literal, meaning every resolvent
 * against a clause containing the negated pivot is itself RUP. RAT is the
 * weaker condition that admits the clause-ADDITION steps implication alone
 * would reject.
 *
 * Counters rather than watched literals: watched literals are how a solver
 * does this fast, but they carry occurrence lists to maintain identically on
 * both sides of a two-runtime port, and this is verifying a bounded proof from
 * a peer rather than running a search.
 *
 * The Python twin is
 * src/autonomous-trust/autonomous_trust/core/_python/certificates/drat.py.
 */

#include <stdbool.h>
#include <stddef.h>

#include <jansson.h>

/** Ceiling on the live clause set, independent of the declaration's proof
 *  cap. The input is a peer-supplied blob, and unbounded work on peer input is
 *  a denial of service with extra steps. */
#define AT_DRAT_MAX_CLAUSES 200000

/** Outcome of a replay. MALFORMED is the blob being unreadable, which is a
 *  different finding from the proof being wrong — though both are the peer's
 *  doing, so both end as INVALID upstream. */
typedef enum
{
    AT_DRAT_VALID = 0,
    AT_DRAT_INVALID,
    AT_DRAT_MALFORMED,
} at_drat_result_t;

/**
 * @brief Replay @p proof against @p formula.
 *
 * @param formula       JSON array of clauses, each an array of non-zero ints.
 * @param proof         JSON array of steps: a clause to add, or {"d": [...]}
 *                      to delete one.
 * @param max_proof_len Step cap from the declaration.
 * @param reason        Optional buffer for the finding.
 */
at_drat_result_t at_drat_check(json_t *formula, json_t *proof,
                               int max_proof_len,
                               char *reason, size_t reason_len);

/** @} */
#endif /* AT_CERT_DRAT_H */
