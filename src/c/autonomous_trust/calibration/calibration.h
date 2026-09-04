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

#ifndef AT_CALIBRATION_H
#define AT_CALIBRATION_H

/** @defgroup internal_calibration Conformal coverage audit
 *  @{
 */

/**
 * Conformal coverage audit (R+D.md §12.4), the C twin of Python
 * `core/_python/calibration/`.
 *
 * Build-order step 3 of doc/verification_oracle.md. The layer separates two
 * things a scalar reputation conflates:
 *
 *   - competence, i.e. the prediction sets are tight; and
 *   - honesty about one's own limits, i.e. the sets cover as advertised.
 *
 * A peer that is frequently wrong but properly humble is safe to work with. A
 * peer that is usually right and systematically overconfident scores well
 * right up until the first time being wrong matters, and an averaged
 * reputation cannot see it coming.
 *
 * FALSIFICATION ONLY, like the physics layer and unlike the certificate layer:
 * a passing audit earns nothing. The verdicts are
 *
 *   - AT_CAL_OVERCONFIDENT — the record rejects the coverage the peer claimed;
 *   - AT_CAL_ABSENT        — declared predictive and produced no usable set;
 *   - AT_CAL_NONE          — nothing to say. The common case.
 *
 * The gradualism doc/verification_oracle.md asks for (a physical refutation
 * should demote faster than a drifting calibration score) is the CHANNEL
 * WEIGHT, not a softened number: `physical` weighs 3 against `calibration` at
 * the baseline 1 (R+D.md §12.8). A rejected coverage claim is a proven-false
 * statement the peer made about itself, so it scores like one.
 *
 * Opt-in: with $AT_CALIBRATION unset the model is empty and every call yields
 * AT_CAL_NONE. An audit that guessed at which capabilities were meant to be
 * predictive would be manufacturing evidence.
 *
 * See doc/architecture/calibration-audit.md.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <jansson.h>

/** Longest capability, quantity or peer name held here. */
#define AT_CAL_NAME_LEN 63

/** Predictive capabilities in one declaration. */
#define AT_CAL_MAX_CAPS 16

/** Distinct quantities across those capabilities. */
#define AT_CAL_MAX_QUANTITIES 16

/** Components in a prediction set; matches AT_PHYS_MAX_COMPONENTS. */
#define AT_CAL_MAX_COMPONENTS 8

/** Unresolved predictions held per quantity, across all peers. */
#define AT_CAL_MAX_OUTSTANDING 32

/** Resolutions remembered per (peer, capability). A ring, so a peer that was
 *  badly calibrated and has since been corrected ages out of the verdict. */
#define AT_CAL_MAX_OUTCOMES 256

/** Peers tracked; matches AT_PHYS_MAX_PEERS. */
#define AT_CAL_MAX_PEERS 32

/** Rejection-reason buffer. */
#define AT_CAL_ERR_LEN 256

/** Verdict of one assessment. */
typedef enum
{
    AT_CAL_NONE = 0,      /**< no declaration, too little evidence, or fine */
    AT_CAL_ABSENT,        /**< declared predictive, no usable set attached */
    AT_CAL_OVERCONFIDENT, /**< the record rejects the claimed coverage */
} at_cal_verdict_t;

/** A coverage claim the exact test rejects. Defection-grade. */
#define AT_CAL_OVERCONFIDENT_SCORE 0.1

/** Declared predictive and produced nothing usable. A fact about the claim,
 *  not about the answer, and not evidence of dishonesty — the mirror of the
 *  certificate layer's "declared to certify and did not". */
#define AT_CAL_ABSENT_SCORE 0.3

/* Declaration defaults; the Python twin's model.py carries the same numbers
 * and the same reasons. */
#define AT_CAL_DEFAULT_MIN_SAMPLES 30
#define AT_CAL_DEFAULT_AUDIT_ALPHA 0.05
#define AT_CAL_DEFAULT_HORIZON_SEC 60.0
#define AT_CAL_DEFAULT_MIN_COVERAGE 0.5
#define AT_CAL_DEFAULT_MAX_COVERAGE 0.999

/** One capability declared to emit prediction sets. */
typedef struct
{
    char   capability[AT_CAL_NAME_LEN + 1];
    char   quantity[AT_CAL_NAME_LEN + 1];
    int    quantity_index;   /**< into at_calibration_model_t::quantities */
    double horizon_sec;
    double min_coverage;
    double max_coverage;
    double tolerance;
} at_cal_predictive_t;

/** A parsed calibration.json. Empty (n_capabilities == 0) unless configured. */
typedef struct
{
    int    n_capabilities;
    int    n_quantities;
    at_cal_predictive_t capabilities[AT_CAL_MAX_CAPS];
    char   quantities[AT_CAL_MAX_QUANTITIES][AT_CAL_NAME_LEN + 1];
    int    min_samples;
    double audit_alpha;
    int    max_outcomes;
    int    max_outstanding;
} at_calibration_model_t;

/** One outstanding prediction set, awaiting its outcome. */
typedef struct
{
    char   subject[AT_CAL_NAME_LEN + 1];
    int    capability;   /**< index into the model */
    double coverage;
    int    n_components;
    double lo[AT_CAL_MAX_COMPONENTS];
    double hi[AT_CAL_MAX_COMPONENTS];
    double tolerance;
    double made_at;
    double deadline;
} at_cal_pred_t;

/** Per-quantity queue of unresolved predictions, oldest first. */
typedef struct
{
    int count;
    at_cal_pred_t items[AT_CAL_MAX_OUTSTANDING];
} at_cal_pending_t;

/** Per-(peer, capability) ring of hit/miss outcomes, as a bitset. */
typedef struct
{
    int     count;  /**< live entries, saturating at model.max_outcomes */
    int     head;   /**< next write index */
    uint8_t hits[AT_CAL_MAX_OUTCOMES / 8];
} at_cal_ring_t;

/** The auditor: a model, the predictions in flight, and the resolved record.
 *
 * Process-local and unsynchronised, for the same reason the physics store is:
 * every outcome it counts was resolved by this node, and the verdict enters
 * consensus as an ordinary transaction score that every peer judges on its own
 * terms. */
typedef struct
{
    at_calibration_model_t model;
    at_cal_pending_t pending[AT_CAL_MAX_QUANTITIES];
    char peers[AT_CAL_MAX_PEERS][AT_CAL_NAME_LEN + 1];
    int  n_peers;
    at_cal_ring_t outcomes[AT_CAL_MAX_PEERS][AT_CAL_MAX_CAPS];
} at_calibration_auditor_t;

/**
 * @brief Parse a calibration declaration from JSON text.
 * @param json_text The declaration; NULL or empty yields the empty model.
 * @param out       Zeroed and filled on success.
 * @param err       Optional buffer (AT_CAL_ERR_LEN) for the rejection reason.
 * @param err_len   Size of @p err.
 * @return true on success; false leaves @p out empty and fills @p err.
 */
bool at_calibration_model_parse(const char *json_text,
                                at_calibration_model_t *out,
                                char *err, size_t err_len);

/**
 * @brief Load the declaration named by @p path, or by $AT_CALIBRATION.
 *
 * With neither set, @p out is the empty model and this returns true: the layer
 * is opt-in. A configured path that cannot be read or does not parse returns
 * false — an audit an operator believes is running and is not is worse than
 * one never switched on.
 */
bool at_calibration_model_load(const char *path, at_calibration_model_t *out,
                               char *err, size_t err_len);

/** @brief Install @p model and empty the store. */
void at_calibration_auditor_init(at_calibration_auditor_t *auditor,
                                 const at_calibration_model_t *model);

/** @brief Drop all predictions and outcomes. Tests and scenario replays. */
void at_calibration_auditor_reset(at_calibration_auditor_t *auditor);

/** @brief Is any capability declared predictive? */
bool at_calibration_enabled(const at_calibration_auditor_t *auditor);

/**
 * @brief Settle outstanding predictions about @p quantity with a known truth.
 *
 * The explicit path, for a ground truth this runtime never sees as a task
 * result. @p reporter is the peer that supplied the value, or NULL for a
 * local observation; a peer's own report NEVER settles its own prediction,
 * because that is the peer supplying the truth it is audited against.
 *
 * @return how many predictions this settled.
 */
int at_calibration_settle(at_calibration_auditor_t *auditor,
                          const char *quantity,
                          const double *actual, size_t n_actual,
                          double now, const char *reporter);

/**
 * @brief Settle from a task result, via the physics quantity it reports.
 *
 * The default path: @p quantity is what physics.json says @p capability
 * reports, so an ordinary result closes the loop with no application
 * involvement. Pass the quantity name resolved by the caller (neg_proc asks
 * the physics model) — this module deliberately does not depend on the physics
 * one, so that a node running calibration without physics still works through
 * ::at_calibration_settle.
 *
 * @param result_str The peer's answer as text: a bare number, a JSON array, or
 *                   an object with a `value`/`values` member.
 * @return how many predictions this settled.
 */
int at_calibration_settle_result(at_calibration_auditor_t *auditor,
                                 const char *quantity,
                                 const char *result_str,
                                 const char *subject, double now);

/**
 * @brief Record an attached prediction and report this peer's standing.
 *
 * @param capability    The capability that answered.
 * @param prediction    The `prediction` member of the reply, or NULL.
 * @param subject       The peer that answered; NULL yields AT_CAL_NONE.
 * @param now           Seconds; a parameter so a replay reproduces the live
 *                      verdicts.
 * @param score_out     Optional; receives the score for a non-NONE verdict.
 * @param reason_out    Optional buffer (AT_CAL_ERR_LEN) receiving the reason.
 * @param reason_len    Size of @p reason_out.
 */
at_cal_verdict_t at_calibration_assess(at_calibration_auditor_t *auditor,
                                       const char *capability,
                                       const json_t *prediction,
                                       const char *subject, double now,
                                       double *score_out,
                                       char *reason_out, size_t reason_len);

/** @} */ /* end of internal_calibration */

#endif /* AT_CALIBRATION_H */
