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

#ifndef AT_CERT_CHECKERS_H
#define AT_CERT_CHECKERS_H

/** @addtogroup internal_certificates
 *  @{
 *
 * One checker per row of the oracle doc's certifying-algorithms table
 * (McConnell, Mehlhorn, Naeher and Schweitzer, 2011). Each takes the problem
 * INPUTS (from the requestor's own retained task, never from the reply), the
 * peer's ANSWER, and the peer's CERTIFICATE, and returns an exact verdict.
 *
 * A note on floating point that applies to every numeric checker: sums run in
 * index order and comparisons are against the declaration's tolerance. Both
 * are load-bearing for the two-runtime port, since addition is not associative
 * and a checker summing in a different order could land on the other side of a
 * bound.
 *
 * The Python twin is
 * src/autonomous-trust/autonomous_trust/core/_python/certificates/checkers.py.
 */

#include <stddef.h>
#include <stdint.h>

#include <jansson.h>

#include "certificates/certificates.h"

/** A checker. Returns VALID / INVALID / INDETERMINATE; never ABSENT or NONE,
 *  which are the caller's findings about the declaration rather than about the
 *  witness. */
typedef at_cert_verdict_t (*at_cert_checker_fn)(json_t *inputs, json_t *answer,
                                                json_t *certificate,
                                                const at_cert_capability_t *decl,
                                                uint64_t seed,
                                                char *reason, size_t reason_len);

/** @brief The checker for @p kind, or NULL if this runtime has none. */
at_cert_checker_fn at_cert_checker_for(const char *kind);

/**
 * @brief True for checkers whose witness is not the peer's to supply.
 *
 * `matrix_product` is verified against the requestor's OWN randomness and
 * `linear_solve` against a residual computed from the answer itself, so "no
 * certificate attached" is the normal case for both and must not be read as a
 * peer withholding one. `state_estimation` reads its sequence out of the
 * answer for the same reason.
 */
bool at_cert_self_certifying(const char *kind);

/** @} */
#endif /* AT_CERT_CHECKERS_H */
