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
 ********************/

#include "calibration/conformal.h"

#include <math.h>

bool at_conformal_covers(const double *lo, const double *hi, size_t n_bounds,
                         const double *actual, size_t n_actual,
                         double tolerance)
{
    if (lo == NULL || hi == NULL || actual == NULL)
        return false;
    if (n_bounds == 0 || n_bounds != n_actual)
        return false;
    for (size_t i = 0; i < n_bounds; i++)
    {
        if (actual[i] < lo[i] - tolerance || actual[i] > hi[i] + tolerance)
            return false;
    }
    return true;
}

double at_binomial_tail_log(int k, int n, double p)
{
    if (n <= 0)
        return 0.0;     /* no trials: the tail is everything */
    if (k >= n)
        return 0.0;
    if (k < 0)
        return -INFINITY;
    /* p at the boundaries makes log(p) or log1p(-p) infinite, and the term for
     * i = 0 (or i = n) would then evaluate 0 * -inf = NaN. Both cases have an
     * exact answer, so take it rather than letting a NaN through. */
    if (p <= 0.0)
        return 0.0;         /* X is 0 almost surely, and k >= 0 */
    if (p >= 1.0)
        return -INFINITY;   /* X is n almost surely, and k < n */

    const double log_p = log(p);
    const double log_q = log1p(-p);

    /* log C(n, i) by the recurrence rather than via lgamma. That is not a
     * micro-optimisation: CPython's `math.lgamma` is its OWN implementation
     * rather than a call into libm, so a tail computed with lgamma disagrees
     * with the Python twin in the last few ulp and the identical-arithmetic
     * claim in the header would be false. `log` and `log1p` DO go straight to
     * libm on both sides, and the recurrence uses nothing else -- every
     * argument is an exact small integer.
     *
     * Two passes rather than an array of terms: the summation order is the
     * same either way (i ascending, exactly as the Python twin iterates), and
     * re-running the recurrence is cheaper than a stack buffer sized for the
     * largest outcome ring. */
    double biggest = -INFINITY;
    double log_choose = 0.0;               /* log C(n, 0) = 0 */
    for (int i = 0; i <= k; i++)
    {
        if (i > 0)
            log_choose += log((double)(n - i + 1)) - log((double)i);
        double term = log_choose + (double)i * log_p + (double)(n - i) * log_q;
        if (term > biggest)
            biggest = term;
    }
    /* No finite term: every one underflowed to -inf, so the tail is zero.
     * `isinf` rather than `== -INFINITY` because the host build is
     * -Werror=float-equal, and `biggest` can only ever be -inf here (it starts
     * there and every finite term replaces it). */
    if (isinf(biggest))
        return -INFINITY;

    double total = 0.0;
    log_choose = 0.0;
    for (int i = 0; i <= k; i++)
    {
        if (i > 0)
            log_choose += log((double)(n - i + 1)) - log((double)i);
        double term = log_choose + (double)i * log_p + (double)(n - i) * log_q;
        total += exp(term - biggest);
    }
    return biggest + log(total);
}

bool at_conformal_overconfident(int hits, int n, double claimed,
                                double audit_alpha)
{
    if (n <= 0 || audit_alpha <= 0.0)
        return false;
    if (audit_alpha >= 1.0)
        return true;
    return at_binomial_tail_log(hits, n, claimed) < log(audit_alpha);
}
