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

#ifndef AT_PREQUENTIAL_SCORING_H
#define AT_PREQUENTIAL_SCORING_H

/** @defgroup internal_prequential_scoring Prequential arithmetic
 *  @{
 */

/**
 * The arithmetic of prequential competence (R+D.md §12.5), the C twin of
 * Python `core/_python/prequential/scoring.py`. Pure: no state, no clock, no
 * configuration.
 *
 * THE LOSS is the Winkler interval score (Winkler 1972; Gneiting and Raftery
 * 2007 §6.2), a proper scoring rule for a central prediction interval at
 * level 1 - alpha:
 *
 *     IS = (u - l) + (2/alpha) max(0, l - y) + (2/alpha) max(0, y - u)
 *
 * The first term is SHARPNESS and the other two the MISS PENALTY, so a peer
 * cannot score well by being vague or by being confidently wrong. The
 * degenerate "cover everything" interval that the coverage audit (R+D.md
 * §12.4) is required to forgive is penalised here, and that division of
 * labour is why this layer exists.
 *
 * `alpha` is the OPERATOR's declared level, never the coverage the peer
 * claimed: the miss penalty is 2/alpha, so a peer that picked its own would
 * lower it to make misses cheap, and competence measured at two different
 * levels is not a comparison.
 *
 * CROSS-RUNTIME IDENTITY. Three things here are about the Python twin rather
 * than about statistics:
 *
 *   - the operation order of the interval score is fixed, and both runtimes
 *     write it the same way;
 *   - the ring mean sums in SLOT order (see prequential.h), because a
 *     floating-point sum depends on its order;
 *   - at_preq_weight_round is floor(x + 0.5), not lround (half-away-from-zero)
 *     and not Python's banker's `round`; they disagree at exactly 0.5, which
 *     is where a band-mapped multiplier lands most often.
 *
 * Unlike the coverage audit's binomial tail, nothing here needs lgamma: the
 * only transcendentals are exp and log, and both go straight to libm on both
 * sides.
 *
 * See doc/architecture/prequential-competence.md.
 */

#include <stdbool.h>
#include <stddef.h>

/** The loss ceiling. Bounded losses are what Hedge's regret bound needs, and
 *  a forecast that misses by ten scales is not usefully worse than one that
 *  misses by five — "impossible" is the physics layer's verdict to render. */
#define AT_PREQ_MAX_LOSS 1.0

/** What ::at_preq_interval_score returns when the shapes do not line up.
 *  A real score is never negative for a non-inverted interval, so a single
 *  sentinel suffices; callers map it to ::AT_PREQ_MAX_LOSS, because a forecast
 *  that committed to a shape the world contradicts is the worst case rather
 *  than an absent one. */
#define AT_PREQ_SHAPE_MISMATCH (-1.0)

/**
 * @brief The Winkler interval score of the box [lo, hi] against @p actual.
 *
 * The MEAN over components, so a 3-vector forecast is not three times worse
 * than a scalar one. @p tolerance forgives a MISS within measurement error
 * and does NOT enlarge the sharpness term -- it models what is unknown about
 * @p actual, and the width is the peer's own exactly known declaration. Same
 * reason the coverage audit has a tolerance, applied to the same term.
 *
 * @return the score, or ::AT_PREQ_SHAPE_MISMATCH on an arity mismatch.
 */
double at_preq_interval_score(const double *lo, const double *hi, size_t n_box,
                              const double *actual, size_t n_actual,
                              double alpha, double tolerance);

/** @brief `min(1, score / scale)`, the bounded loss the weights are built on. */
double at_preq_normalized_loss(double score, double scale);

/**
 * @brief Map a mean loss in [0, 1] onto the declared weight band.
 *
 * 0 (a perfectly sharp forecaster) maps to @p band_max and 1 (saturated) to
 * @p band_min. Linear deliberately: a nonlinear map would be a tuning surface
 * with nothing to tune it against. What the number must be is monotone in the
 * record and inside the range the operator authorised.
 */
double at_preq_band_multiplier(double mean_loss, double band_min,
                               double band_max);

/**
 * @brief `floor(value + 0.5)`, floored at 1.
 *
 * The EMA applies a weight by folding a score in that many times, so the
 * composed weight is a positive integer and 1 is the floor — which is why a
 * capability authored at transaction_weight 1 cannot be demoted by
 * competence. Recorded as a limitation in the design doc rather than worked
 * around, since a fractional fold would change every existing weighted EMA.
 */
int at_preq_weight_round(double value);

/**
 * @brief Normalized exponential weights `exp(-eta L_i) / sum_j exp(-eta L_j)`.
 *
 * In log space with a max-shift, because exp(-eta L) underflows to zero for
 * the cumulative losses a long run produces — and a table of zeros normalizes
 * to a division by zero, i.e. no aggregate at all, at exactly the run lengths
 * where the bound starts to be worth having.
 *
 * The caller passes only the AWAKE peers' cumulative losses (the sleeping-
 * experts restriction, Freund, Schapire, Singer and Warmuth 1997), so a peer
 * that did not forecast this round is neither rewarded nor punished for it.
 *
 * @param cum  @p n cumulative losses.
 * @param out  @p n weights, summing to 1.
 */
void at_preq_hedge_weights(const double *cum, size_t n, double eta,
                           double *out);

/**
 * @brief `ln N / eta + eta T / 8`: Hedge's regret bound for bounded losses.
 *
 * Reported alongside the realized regret so the guarantee is measurable
 * rather than asserted. @p n_experts is the number of peers that have ever
 * forecast the quantity; @p rounds the rounds the peer in question was awake.
 */
double at_preq_hedge_bound(int n_experts, int rounds, double eta);

/** @} */ /* end of internal_prequential_scoring */

#endif /* AT_PREQUENTIAL_SCORING_H */
