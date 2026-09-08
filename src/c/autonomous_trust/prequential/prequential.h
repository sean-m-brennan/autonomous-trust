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

#ifndef AT_PREQUENTIAL_H
#define AT_PREQUENTIAL_H

/** @defgroup internal_prequential Prequential competence
 *  @{
 */

/**
 * Prequential competence with per-region weighting (R+D.md §12.5), the C twin
 * of Python `core/_python/prequential/`.
 *
 * Build-order step 4 of doc/verification_oracle.md. Dawid's prequential
 * principle (1984): a forecaster is assessed only by its record of
 * predictions against outcomes, never by anything about its internals.
 *
 * THIS LAYER RETURNS NO SCORE. Every other oracle layer produces a score and
 * an evidence channel; this one produces a per-(peer, capability) COMPETENCE
 * MULTIPLIER on the EMA weight and adds no evidence of its own, because poor
 * competence is not a defection: a peer whose forecasts are wide or wrong has
 * told no lie, and scoring it like a physically impossible claim would undo
 * the distinction R+D.md §12.4 exists to draw. R+D.md §12.8's channel set is
 * closed and pre-declared, and deliberately has no `prequential` in it.
 *
 * The multiplier composes with the two weights already in the EMA:
 *
 *     EMA weight = transaction_weight   (authored, trust_ladder.json)
 *                x competence           (learned, this layer)
 *                x channel weight       (authored, §12.8, local evidence only)
 *
 * and is confined to a declared band around 1.0, so the operator's authored
 * number stays the anchor and a learned weight can never leave the range the
 * operator allowed.
 *
 * SLEEPING EXPERTS. A peer is scored only on the rounds it spoke (Freund,
 * Schapire, Singer and Warmuth, 1997), which is what makes the competence
 * REGIONAL — trusted on thermal, distrusted on attitude — with nobody
 * declaring the regions in advance. The same restriction drives the Hedge
 * weights behind ::at_prequential_combine, whose aggregate forecast is the
 * claimant for the regret bound against arbitrary adversarial peers.
 *
 * Opt-in: with $AT_PREQUENTIAL unset the model is empty and every multiplier
 * is exactly 1.0, so nothing that has not opted in changes behaviour.
 *
 * See doc/architecture/prequential-competence.md.
 */

#include <stdbool.h>
#include <stddef.h>

#include <jansson.h>

/** Longest capability, quantity or peer name held here. */
#define AT_PREQ_NAME_LEN 63

/** Forecasting capabilities in one declaration. */
#define AT_PREQ_MAX_CAPS 16

/** Distinct quantities across those capabilities. */
#define AT_PREQ_MAX_QUANTITIES 16

/** Components in a forecast box; matches AT_PHYS_MAX_COMPONENTS. */
#define AT_PREQ_MAX_COMPONENTS 8

/** Unresolved forecasts held per quantity, across all peers. */
#define AT_PREQ_MAX_OUTSTANDING 32

/** Resolved losses remembered per (peer, capability). A ring, so a peer that
 *  forecast badly a year ago and has since improved ages out of the weight. */
#define AT_PREQ_MAX_OUTCOMES 64

/** Peers tracked. Smaller than the coverage audit's table because each cell
 *  here holds doubles rather than a bitset. */
#define AT_PREQ_MAX_PEERS 16

/** Rejection-reason buffer. */
#define AT_PREQ_ERR_LEN 256

/** The multiplier for anything this layer has nothing to say about: the layer
 *  off, an undeclared capability, an unknown peer, or a record shorter than
 *  min_samples. Exactly 1.0 — the authored transaction_weight, verbatim. */
#define AT_PREQ_NEUTRAL_COMPETENCE 1.0

/* Declaration defaults; the Python twin's model.py carries the same numbers
 * and the same reasons. */
#define AT_PREQ_DEFAULT_MIN_SAMPLES 8
#define AT_PREQ_DEFAULT_HORIZON_SEC 60.0
#define AT_PREQ_DEFAULT_ETA 1.0
#define AT_PREQ_DEFAULT_ALPHA 0.1
#define AT_PREQ_DEFAULT_BAND_MIN 0.5
#define AT_PREQ_DEFAULT_BAND_MAX 2.0

/** One capability whose replies carry a scored forecast. */
typedef struct
{
    char   capability[AT_PREQ_NAME_LEN + 1];
    char   quantity[AT_PREQ_NAME_LEN + 1];
    int    quantity_index;   /**< into at_prequential_model_t::quantities */
    double scale;            /**< one unit of loss, in the quantity's units */
    double alpha;            /**< the level the interval score is taken at */
    double horizon_sec;
    double tolerance;
} at_preq_forecasting_t;

/** A parsed prequential.json. Empty (n_capabilities == 0) unless configured. */
typedef struct
{
    int    n_capabilities;
    int    n_quantities;
    at_preq_forecasting_t capabilities[AT_PREQ_MAX_CAPS];
    char   quantities[AT_PREQ_MAX_QUANTITIES][AT_PREQ_NAME_LEN + 1];
    int    min_samples;
    int    max_outcomes;
    int    max_outstanding;
    double eta;
    double band_min;
    double band_max;
} at_prequential_model_t;

/** One outstanding forecast, awaiting its outcome. */
typedef struct
{
    char   subject[AT_PREQ_NAME_LEN + 1];
    int    capability;   /**< index into the model */
    int    n_components;
    double lo[AT_PREQ_MAX_COMPONENTS];
    double hi[AT_PREQ_MAX_COMPONENTS];
    double alpha;
    double scale;
    double tolerance;
    double made_at;
    double deadline;
} at_preq_forecast_entry_t;

/** Per-quantity queue of unresolved forecasts, oldest first. */
typedef struct
{
    int count;
    at_preq_forecast_entry_t items[AT_PREQ_MAX_OUTSTANDING];
} at_preq_pending_t;

/** Per-(peer, capability) ring of resolved losses, in SLOT order.
 *
 * A fixed array plus a head index, and the Python twin mirrors this layout
 * rather than using a deque: the mean is a floating-point sum, so the ORDER
 * the entries are summed in is part of the answer, and the two runtimes have
 * to agree to the last bit or the same peer draws different weights depending
 * on which runtime scored it. */
typedef struct
{
    int    count;   /**< live entries, saturating at model.max_outcomes */
    int    head;    /**< next write index */
    double losses[AT_PREQ_MAX_OUTCOMES];
} at_preq_ring_t;

/** Per-(quantity, peer) Hedge state.
 *
 * `mixture_on_awake` is the accumulated MIXTURE loss over the rounds this peer
 * was awake, which is what makes the sleeping-experts regret measurable: the
 * guarantee is against each specialist on its OWN rounds, so comparing a
 * peer's cumulative loss against the mixture over all rounds would be
 * comparing two different sequences. */
typedef struct
{
    bool   seen;
    double cumulative_loss;
    int    rounds;
    double mixture_on_awake;
} at_preq_peer_record_t;

/** Per-quantity Hedge accumulators.
 *
 * `mixture_loss` is what Hedge bounds — the loss of following one peer drawn
 * according to the weights — and needs no convexity assumption.
 * `aggregate_loss` is the loss of the vincentized forecast, i.e. what an
 * application consuming ::at_prequential_combine would have suffered. On the
 * RAW interval score, which is convex in the endpoints, Jensen puts it at or
 * below the mixture; on the NORMALIZED loss it can exceed it, because
 * min(1, .) is not convex. That is the honest reading of a bounded loss rather
 * than a defect, so `saturated_rounds` counts the rounds where any awake
 * forecast hit the ceiling and the comparison can be read with the caveat. */
typedef struct
{
    at_preq_peer_record_t peers[AT_PREQ_MAX_PEERS];
    int    rounds;
    double mixture_loss;
    double aggregate_loss;
    int    saturated_rounds;
} at_preq_quantity_record_t;

/** The estimator: a model, the forecasts in flight, and the resolved record.
 *
 * Process-local and unsynchronised, for the same reason the physics window and
 * the coverage audit's rings are: every loss it holds was resolved by this
 * node, and what leaves the node is an ordinary weighted score that every peer
 * judges on its own terms. */
typedef struct
{
    at_prequential_model_t model;
    at_preq_pending_t pending[AT_PREQ_MAX_QUANTITIES];
    char peers[AT_PREQ_MAX_PEERS][AT_PREQ_NAME_LEN + 1];
    int  n_peers;
    at_preq_ring_t losses[AT_PREQ_MAX_PEERS][AT_PREQ_MAX_CAPS];
    at_preq_quantity_record_t hedge[AT_PREQ_MAX_QUANTITIES];
} at_prequential_estimator_t;

/** One contributor to an aggregate forecast. */
typedef struct
{
    char   peer[AT_PREQ_NAME_LEN + 1];
    char   capability[AT_PREQ_NAME_LEN + 1];
    double weight;
} at_preq_contributor_t;

/** The aggregate forecast ::at_prequential_combine produces. */
typedef struct
{
    char   quantity[AT_PREQ_NAME_LEN + 1];
    int    n_components;
    double lo[AT_PREQ_MAX_COMPONENTS];
    double hi[AT_PREQ_MAX_COMPONENTS];
    double alpha;
    int    n_contributors;
    at_preq_contributor_t contributors[AT_PREQ_MAX_OUTSTANDING];
} at_preq_aggregate_t;

/** One peer's realized regret and the bound on it. */
typedef struct
{
    char   peer[AT_PREQ_NAME_LEN + 1];
    double cumulative_loss;
    int    rounds;
    double realized;   /**< mixture over this peer's awake rounds - its loss */
    double bound;      /**< ln N / eta + eta T / 8 */
} at_preq_peer_regret_t;

/** What ::at_prequential_regret reports for one quantity. */
typedef struct
{
    char   quantity[AT_PREQ_NAME_LEN + 1];
    int    rounds;
    int    experts;
    double mixture_loss;
    double aggregate_loss;
    int    saturated_rounds;
    int    n_peers;
    at_preq_peer_regret_t peers[AT_PREQ_MAX_PEERS];
} at_preq_regret_t;

/**
 * @brief Parse a prequential declaration from JSON text.
 * @param json_text The declaration; NULL or empty yields the empty model.
 * @param out       Zeroed and filled on success.
 * @param err       Optional buffer (AT_PREQ_ERR_LEN) for the rejection reason.
 * @param err_len   Size of @p err.
 * @return true on success; false leaves @p out empty and fills @p err.
 */
bool at_prequential_model_parse(const char *json_text,
                                at_prequential_model_t *out,
                                char *err, size_t err_len);

/**
 * @brief Load the declaration named by @p path, or by $AT_PREQUENTIAL.
 *
 * With neither set, @p out is the empty model and this returns true: the layer
 * is opt-in. A configured path that cannot be read or does not parse returns
 * false — a learned weighting an operator believes is running and is not is
 * worse than one never switched on, because the EMA it silently fails to move
 * is the one the operator was counting on.
 */
bool at_prequential_model_load(const char *path, at_prequential_model_t *out,
                               char *err, size_t err_len);

/** @brief Install @p model and empty the store. */
void at_prequential_estimator_init(at_prequential_estimator_t *est,
                                   const at_prequential_model_t *model);

/** @brief Drop all forecasts and losses. Tests and scenario replays. */
void at_prequential_estimator_reset(at_prequential_estimator_t *est);

/** @brief Is any capability declared to forecast? */
bool at_prequential_enabled(const at_prequential_estimator_t *est);

/**
 * @brief Record an attached forecast.
 *
 * Silent about an unusable one: "declared predictive and attached nothing" is
 * a fact about the CLAIM, and the coverage audit already scores it (0.3 on
 * `calibration`). Scoring it again here would double-count one omission, and
 * this layer has no channel to score it on in any case.
 *
 * @param prediction The `prediction` member of the reply, or NULL — the SAME
 *                   artifact R+D.md §12.4 reads. `coverage` is deliberately
 *                   not read; see scoring.h.
 * @return whether the forecast was usable and recorded.
 */
bool at_prequential_observe(at_prequential_estimator_t *est,
                            const char *capability, const json_t *prediction,
                            const char *subject, double now);

/**
 * @brief Settle outstanding forecasts about @p quantity with a known truth.
 *
 * The explicit path, for a ground truth this runtime never sees as a task
 * result. @p reporter is the peer that supplied the value, or NULL for a local
 * observation; a peer's own report NEVER settles its own forecast, because
 * that is the peer supplying the truth it is scored against.
 *
 * @return how many forecasts this settled.
 */
int at_prequential_settle(at_prequential_estimator_t *est,
                          const char *quantity,
                          const double *actual, size_t n_actual,
                          double now, const char *reporter);

/**
 * @brief Settle from a task result, via the physics quantity it reports.
 *
 * The default path: @p quantity is what physics.json says the reporting
 * capability reports, so an ordinary result closes the loop with no
 * application involvement. The caller resolves the name (neg_proc asks the
 * physics model), so this module stays independent of the physics one.
 *
 * @param result_str The peer's answer as text: a bare number, a JSON array, or
 *                   an object with a `value`/`values` member.
 * @return how many forecasts this settled.
 */
int at_prequential_settle_result(at_prequential_estimator_t *est,
                                 const char *quantity, const char *result_str,
                                 const char *subject, double now);

/**
 * @brief The EMA weight multiplier for @p subject on @p capability.
 *
 * ::AT_PREQ_NEUTRAL_COMPETENCE for an undeclared capability, an unknown peer,
 * or a record shorter than min_samples. Silence rather than a guess: the
 * weight does not move until there is something to move it with.
 */
double at_prequential_competence(const at_prequential_estimator_t *est,
                                 const char *subject, const char *capability);

/**
 * @brief The mesh's aggregate forecast for @p quantity.
 *
 * The Hedge-weighted combination of the forecasts currently outstanding,
 * endpoint-wise (vincentized). Nothing in AT core consumes it: it is the API
 * for an application that wants the mesh's best estimate, and the claimant for
 * the regret bound ::at_prequential_regret reports.
 *
 * @return false when the layer is off or nothing is outstanding.
 */
bool at_prequential_combine(const at_prequential_estimator_t *est,
                            const char *quantity, double now,
                            at_preq_aggregate_t *out);

/**
 * @brief Realized regret against every peer, and Hedge's bound on it.
 * @return false when the quantity has seen no rounds.
 */
bool at_prequential_regret(const at_prequential_estimator_t *est,
                           const char *quantity, at_preq_regret_t *out);

/** @} */ /* end of internal_prequential */

#endif /* AT_PREQUENTIAL_H */
