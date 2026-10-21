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

/* Prequential competence (R+D.md §12.5): an observe arm that keeps the record,
 * and the competence multiplier the negotiation process submits with each
 * score (negotiation/neg_oracle.h). Until FEATURE_SPLIT_PLAN Phase 3 this lived
 * in neg_proc.c. */

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <jansson.h>

#include "at_prequential.h"
#include "negotiation/neg_oracle.h"
#include "reputation/tx_channel.h"   /* evidence channels */
#include "utilities/logger.h"
#include "prequential/prequential.h"

/* The multiplier IS the accumulated record of resolved forecasts, so an
 * estimator built per result would weight every peer at exactly 1.0 forever
 * -- indistinguishable from the layer being switched off. */
static at_prequential_estimator_t est;
static bool loaded = false;

/* Same load policy as the other layers (mirrors Python
 * prequential_estimator): a rejected declaration is logged and the layer
 * stays OFF, because a node that cannot learn a weighting must still be able
 * to score a task. */
static at_prequential_estimator_t *prequential_estimator(void)
{
    if (!loaded)
    {
        at_prequential_model_t model;
        char err[AT_PREQ_ERR_LEN] = {0};
        if (!at_prequential_model_load(NULL, &model, err, sizeof(err)))
        {
            log_error(NULL, "prequential: declaration rejected, layer stays "
                            "OFF: %s\n", err);
            at_prequential_model_parse(NULL, &model, NULL, 0);
        }
        at_prequential_estimator_init(&est, &model);
        loaded = true;
    }
    return &est;
}

/* Both halves, as an OBSERVE arm: this layer renders no verdict, so its record
 * must not depend on which verdict arm happened to speak first -- a forecast
 * attached to a reply whose certificate arm is about to score it still has to
 * be recorded. After physics (order 100) for the reason the coverage audit's
 * settle is: a refuted result neither resolves forecasts nor records one.
 * Settle before observe, so a peer forecasting the quantity it just reported
 * is weighted against a record including everything this result settled. */
static void prequential_observe(const neg_score_input_t *in)
{
    at_prequential_estimator_t *e = prequential_estimator();
    if (!at_prequential_enabled(e))
        return;
    const char *quantity = neg_oracle_reported_quantity(in->cap);
    if (quantity != NULL)
    {
        int resolved = at_prequential_settle_result(e, quantity, in->result_str,
                                                    in->subject, in->now);
        if (resolved > 0)
            log_debug(NULL, "prequential: resolved %d outstanding "
                            "forecast(s) about %s\n", resolved, quantity);
    }
    json_t *pred = NULL;
    if (in->prediction_json != NULL && in->prediction_json[0] != '\0')
    {
        json_error_t perr;
        pred = json_loads(in->prediction_json, 0, &perr);
    }
    at_prequential_observe(e, in->cap, pred, in->subject, in->now);
    if (pred != NULL)
        json_decref(pred);
}

static double prequential_competence(const char *cap, const char *subject)
{
    at_prequential_estimator_t *e = prequential_estimator();
    if (!at_prequential_enabled(e))
        return AT_PREQ_NEUTRAL_COMPETENCE;
    return at_prequential_competence(e, subject, cap);
}

static void prequential_reset(void)
{
    loaded = false;
}

static const neg_oracle_t prequential_oracle = {
    .name = "prequential", .reset = prequential_reset,
};
static const neg_oracle_arm_t observe_arm = {
    .name = "prequential.observe", .order = 210, .observe = prequential_observe,
};

static void __attribute__((constructor)) prequential_oracle_register(void)
{
    (void)neg_oracle_register(&prequential_oracle);
    (void)neg_oracle_arm_register(&observe_arm);
    (void)neg_oracle_provide_competence(prequential_competence);
}

void at_prequential_link(void) {}
