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

/* Certificate-carrying interfaces (R+D.md §12.3) as a scorer arm
 * (negotiation/neg_oracle.h). Until FEATURE_SPLIT_PLAN Phase 3 this lived in
 * neg_proc.c. */

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <jansson.h>

#include "at_certificates.h"
#include "negotiation/neg_oracle.h"
#include "reputation/tx_channel.h"   /* evidence channels */
#include "utilities/logger.h"
#include "certificates/certificates.h"

/* The declaration, built from $AT_CERTIFICATES on first call and empty when
 * that is unset. Stateless apart from the model -- a witness is self-contained
 * -- but held so the file is read and the inventory reported ONCE. */
static at_cert_model_t model;
static bool loaded = false;

/* A malformed declaration is fatal at load (certificates.c says why) but must
 * not take down the scoring path on every subsequent result: the failure is
 * recorded once and the layer stays OFF.
 *
 * Emits the inventory once, here. That report is the other half of what
 * R+D.md §12.3 asks for: a node that silently falls through to completion
 * scoring for everything it cannot check looks, from outside, exactly like a
 * node checking everything. Mirrors Python certificate_verifier(). */
static const at_cert_model_t *certificate_model(void)
{
    if (!loaded)
    {
        char err[AT_CERT_ERR_LEN] = {0};
        if (!at_cert_model_load(NULL, &model, err, sizeof(err)))
        {
            log_error(NULL,
                      "certificates: declaration rejected, layer stays OFF: %s\n",
                      err);
            at_cert_model_parse(NULL, &model, NULL, 0);
        }
        loaded = true;
        if (at_cert_model_enabled(&model))
        {
            at_cert_inv_row_t rows[AT_CERT_MAX_CAPABILITIES];
            int n = at_cert_inventory(&model, NULL, 0, rows, AT_CERT_MAX_CAPABILITIES);
            if (n > 0)
            {
                char report[4096];
                at_cert_inventory_format(rows, n, report, sizeof(report));
                log_info(NULL, "%s\n", report);
            }
        }
    }
    return &model;
}

/* After physics, because a witness proves the answer satisfies the problem AS
 * STATED, which says nothing about whether the statement was physically
 * coherent. The one layer that can return a GOOD score: "proved right" is the
 * strongest positive evidence this node can obtain. INDETERMINATE is OUR
 * record failing, never the peer's fault, so it falls through unscored. */
static bool certificates_score(const neg_score_input_t *in, double *score, const char **channel)
{
    const at_cert_model_t *certs = certificate_model();
    if (!at_cert_model_enabled(certs))
        return false;
    char why[AT_CERT_ERR_LEN] = {0};
    at_cert_verdict_t verdict = at_cert_evaluate(
        certs, in->cap, in->result_str, in->certificate_json, in->kwargs_json,
        in->seed, why, sizeof(why));
    if (verdict != AT_CERT_VALID && verdict != AT_CERT_INVALID &&
        verdict != AT_CERT_ABSENT)
        return false;
    if (verdict == AT_CERT_VALID)
        log_info(NULL, "certificates: %s verified (%s)\n",
                 in->cap ? in->cap : "-", at_cert_verdict_name(verdict));
    else
        log_warn(NULL, "certificates: %s %s: %s\n",
                 in->cap ? in->cap : "-", at_cert_verdict_name(verdict), why);
    *channel = TX_CHANNEL_CERTIFICATE;
    *score = at_cert_score(verdict);
    return true;
}

static void certificates_reset(void)
{
    loaded = false;
}

static const neg_oracle_t certificates_oracle = {
    .name = "certificates", .reset = certificates_reset,
};
static const neg_oracle_arm_t certificates_arm = {
    .name = "certificates.check", .order = 300, .score = certificates_score,
};

static void __attribute__((constructor)) certificates_oracle_register(void)
{
    (void)neg_oracle_register(&certificates_oracle);
    (void)neg_oracle_arm_register(&certificates_arm);
}

void at_certificates_link(void) {}
