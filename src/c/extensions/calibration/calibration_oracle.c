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

/* The coverage audit (R+D.md §12.4) as two scorer arms (negotiation/neg_oracle.h).
 * Until FEATURE_SPLIT_PLAN Phase 3 this lived in neg_proc.c. */

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <jansson.h>

#include "at_calibration.h"
#include "negotiation/neg_oracle.h"
#include "reputation/tx_channel.h"   /* evidence channels */
#include "utilities/logger.h"
#include "calibration/calibration.h"

/* The verdict IS the accumulated record of resolved predictions, so an auditor
 * built per result would have nothing to audit and would be permanently
 * silent: one per process, built from $AT_CALIBRATION on first use. */
static at_calibration_auditor_t auditor;
static bool loaded = false;

/* Mirrors Python calibration_auditor(): a malformed declaration is fatal at
 * load but must not take down the scoring path on every subsequent result, so
 * the failure is logged once and the layer stays off. */
static at_calibration_auditor_t *calibration_auditor(void)
{
    if (!loaded)
    {
        at_calibration_model_t model;
        char err[AT_CAL_ERR_LEN] = {0};
        if (!at_calibration_model_load(NULL, &model, err, sizeof(err)))
        {
            log_error(NULL, "calibration: declaration rejected, layer stays "
                            "OFF: %s\n", err);
            at_calibration_model_parse(NULL, &model, NULL, 0);
        }
        at_calibration_auditor_init(&auditor, &model);
        loaded = true;
    }
    return &auditor;
}

/* Half one: let this result RESOLVE predictions other peers made about the
 * quantity it reports. After physics (order 100), because a refuted result is
 * not evidence about the world -- settling an honest forecaster's prediction
 * against a refuted observation would let a lying reporter convict it.
 * Everything past physics is usable, including a result whose own certificate
 * arm is about to score it: a wrong answer to THIS task is still a
 * measurement. */
static void calibration_settle(const neg_score_input_t *in)
{
    at_calibration_auditor_t *aud = calibration_auditor();
    if (!at_calibration_enabled(aud))
        return;
    const char *quantity = neg_oracle_reported_quantity(in->cap);
    if (quantity == NULL)
        return;
    int settled = at_calibration_settle_result(aud, quantity, in->result_str,
                                               in->subject, in->now);
    if (settled > 0)
        log_debug(NULL, "calibration: resolved %d outstanding "
                        "prediction(s) about %s\n", settled, quantity);
}

/* Half two: judge the peer's CLAIM about how often answers of this kind land
 * inside the set it quotes. After the certificate arm (order 300), because an
 * exact check of THIS answer outranks a statistical claim about a hundred of
 * them. Falsification only: a peer not caught over-claiming earns nothing. */
static bool calibration_assess(const neg_score_input_t *in, double *score, const char **channel)
{
    at_calibration_auditor_t *aud = calibration_auditor();
    if (!at_calibration_enabled(aud))
        return false;
    json_t *pred = NULL;
    if (in->prediction_json != NULL && in->prediction_json[0] != '\0')
    {
        json_error_t perr;
        pred = json_loads(in->prediction_json, 0, &perr);
    }
    char why[AT_CAL_ERR_LEN] = {0};
    at_cal_verdict_t verdict = at_calibration_assess(
        aud, in->cap, pred, in->subject, in->now, score, why, sizeof(why));
    if (pred != NULL)
        json_decref(pred);
    if (verdict == AT_CAL_NONE)
        return false;
    log_warn(NULL, "calibration: %s\n", why);
    *channel = TX_CHANNEL_CALIBRATION;
    return true;
}

static void calibration_reset(void)
{
    loaded = false;
}

static const neg_oracle_t calibration_oracle = {
    .name = "calibration", .reset = calibration_reset,
};
static const neg_oracle_arm_t settle_arm = {
    .name = "calibration.settle", .order = 200, .observe = calibration_settle,
};
static const neg_oracle_arm_t assess_arm = {
    .name = "calibration.assess", .order = 400, .score = calibration_assess,
};

static void __attribute__((constructor)) calibration_oracle_register(void)
{
    (void)neg_oracle_register(&calibration_oracle);
    (void)neg_oracle_arm_register(&settle_arm);
    (void)neg_oracle_arm_register(&assess_arm);
}

void at_calibration_link(void) {}
