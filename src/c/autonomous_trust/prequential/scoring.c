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

#include "prequential/scoring.h"

#include <math.h>

double at_preq_interval_score(const double *lo, const double *hi, size_t n_box,
                              const double *actual, size_t n_actual,
                              double alpha, double tolerance)
{
    if (lo == NULL || hi == NULL || actual == NULL || n_box == 0
        || n_actual != n_box)
        return AT_PREQ_SHAPE_MISMATCH;
    double penalty = 2.0 / alpha;
    double total = 0.0;
    /* Operation order is load-bearing: the Python twin's interval_score()
     * writes the same expression in the same sequence, and the corpus pins
     * the resulting loss. */
    for (size_t i = 0; i < n_box; i++)
    {
        /* Sharpness from the DECLARED interval, misses judged against the
         * widened one: the tolerance models what is unknown about `actual`,
         * which can only bear on whether the value fell outside. Charging the
         * widened width would bill every peer for OUR instrument and would
         * put a floor of 2*tolerance/scale under a perfect forecaster's loss.
         * See scoring.h and the Python twin. */
        double low = lo[i] - tolerance;
        double high = hi[i] + tolerance;
        double y = actual[i];
        double term = hi[i] - lo[i];
        if (y < low)
            term += penalty * (low - y);
        else if (y > high)
            term += penalty * (y - high);
        total += term;
    }
    return total / (double)n_box;
}

double at_preq_normalized_loss(double score, double scale)
{
    if (!(scale > 0.0))
        return AT_PREQ_MAX_LOSS;
    double value = score / scale;
    if (value < 0.0)
        return 0.0;
    if (value > AT_PREQ_MAX_LOSS)
        return AT_PREQ_MAX_LOSS;
    return value;
}

double at_preq_band_multiplier(double mean_loss, double band_min,
                               double band_max)
{
    if (mean_loss < 0.0)
        mean_loss = 0.0;
    else if (mean_loss > AT_PREQ_MAX_LOSS)
        mean_loss = AT_PREQ_MAX_LOSS;
    return band_max - (band_max - band_min) * mean_loss;
}

int at_preq_weight_round(double value)
{
    if (!isfinite(value))
        return 1;
    /* floor(x + 0.5), NOT lround: lround is half-away-from-zero and Python's
     * round is banker's, and they disagree at exactly 0.5 — which is where a
     * band-mapped multiplier lands most often. */
    double rounded = floor(value + 0.5);
    if (rounded < 1.0)
        return 1;
    return (int)rounded;
}

void at_preq_hedge_weights(const double *cum, size_t n, double eta,
                           double *out)
{
    if (out == NULL || n == 0)
        return;
    if (cum == NULL || !(eta > 0.0))
    {
        for (size_t i = 0; i < n; i++)
            out[i] = 1.0 / (double)n;
        return;
    }
    double biggest = -INFINITY;
    for (size_t i = 0; i < n; i++)
    {
        out[i] = -eta * cum[i];
        if (out[i] > biggest)
            biggest = out[i];
    }
    double total = 0.0;
    for (size_t i = 0; i < n; i++)
    {
        out[i] = exp(out[i] - biggest);
        total += out[i];
    }
    if (!(total > 0.0))
    {
        /* Cannot happen after the max-shift (one term is exp(0) = 1), but a
         * uniform answer is the right fallback and costs nothing. */
        for (size_t i = 0; i < n; i++)
            out[i] = 1.0 / (double)n;
        return;
    }
    for (size_t i = 0; i < n; i++)
        out[i] /= total;
}

double at_preq_hedge_bound(int n_experts, int rounds, double eta)
{
    if (n_experts < 1 || !(eta > 0.0))
        return 0.0;
    if (rounds < 0)
        rounds = 0;
    return log((double)n_experts) / eta + eta * (double)rounds / 8.0;
}
