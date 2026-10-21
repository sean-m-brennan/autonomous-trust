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

#ifndef AT_CONFORMAL_H
#define AT_CONFORMAL_H

/** @addtogroup internal_calibration
 *  @{
 */

#include <stdbool.h>
#include <stddef.h>

/**
 * The arithmetic of the coverage audit (R+D.md §12.4). The C twin of Python
 * `calibration/conformal.py`, and deliberately a separate translation unit
 * from the auditor for the same reason the Python module is separate: this is
 * the half that has to be IDENTICAL across the runtimes, down to the order of
 * operations, and keeping it pure makes that testable on its own.
 *
 * The test: a peer emits prediction sets at a claimed coverage `c` and we
 * observe `k` hits in `n` resolved predictions. Under the null that the peer's
 * true coverage is at least `c`, the hit count is stochastically at least
 * Binomial(n, c), so P(X <= k) is a valid p-value against "true coverage is
 * below what was claimed". Reject when it falls under `audit_alpha`.
 *
 * Exact and finite-sample: no asymptotics, and no distributional assumption
 * beyond independence of the resolutions. It is the hypothesis-test dual of
 * the Clopper-Pearson interval, chosen over the interval because the tail sum
 * needs nothing but `lgamma` — which both runtimes have and agree on — where
 * an interval would need an inverse incomplete beta that C has no library for.
 *
 * See doc/architecture/calibration-audit.md.
 */

/**
 * @brief Is @p actual inside the prediction box, component-wise?
 *
 * A miss on ANY component is a miss. @p tolerance widens each side.
 * Mismatched lengths are a miss rather than an error: a set of the wrong arity
 * does not contain anything.
 */
bool at_conformal_covers(const double *lo, const double *hi, size_t n_bounds,
                         const double *actual, size_t n_actual,
                         double tolerance);

/**
 * @brief `log P(X <= k)` for `X ~ Binomial(n, p)`.
 *
 * Returns `-INFINITY` for a tail of exactly zero, and `0.0` (log 1) when the
 * tail is the whole mass.
 *
 * Summed in log space with a max-shift because `(1 - p)^n` underflows to zero
 * for the coverages that matter — 0.1^512 is not representable — and a naive
 * recurrence from that term returns a tail of exactly 0.0, i.e. "reject", for
 * every peer.
 */
double at_binomial_tail_log(int k, int n, double p);

/**
 * @brief Does the record reject the peer's claimed coverage?
 *
 * True means the shortfall is larger than sampling noise explains at the
 * @p audit_alpha level. Callers are responsible for not asking before they
 * have enough resolutions to matter: the minimum-sample policy belongs with
 * the configuration, not here.
 */
bool at_conformal_overconfident(int hits, int n, double claimed,
                                double audit_alpha);

/** @} */ /* end of internal_calibration */

#endif /* AT_CONFORMAL_H */
