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

/* Physical consistency (R+D.md §12.2) as a scorer arm (negotiation/neg_oracle.h),
 * and the provider of the capability -> reported-quantity lookup the coverage
 * audit and the prequential layer settle through. Until FEATURE_SPLIT_PLAN
 * Phase 3 this lived in neg_proc.c. */

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <jansson.h>

#include "at_physics.h"
#include "negotiation/neg_oracle.h"
#include "reputation/tx_channel.h"   /* evidence channels */
#include "utilities/logger.h"
#include "physics/physics.h"

/* The process-wide checker and its observation window, built from
 * $AT_PHYSICS on first call and empty when that is unset. The window is what
 * the multi-peer intersection and the parity residuals are computed over -- a
 * checker rebuilt per result would see no history and could only ever perform
 * the single-claim checks. `loaded` is separate from "the model is empty": an
 * unconfigured $AT_PHYSICS is a legitimate empty model, and re-reading the
 * file on every result to rediscover that would be a syscall per task. */
static at_physics_checker_t checker;
static bool loaded = false;

static at_physics_checker_t *physics_checker(void)
{
    if (!loaded)
    {
        /* A malformed declaration is fatal at load (physics.c says why) but
         * must not take down the scoring path on every subsequent result: the
         * failure is recorded once and the layer stays OFF, which is the same
         * end state as never having configured it. Mirrors Python
         * physics_checker(). */
        at_physics_model_t model;
        char err[AT_PHYS_ERR_LEN] = {0};
        if (!at_physics_model_load(NULL, &model, err, sizeof(err)))
        {
            log_error(NULL, "physics: declaration rejected, layer stays OFF: %s\n",
                      err);
            at_physics_model_parse(NULL, &model, NULL, 0);
        }
        at_physics_checker_init(&checker, &model);
        loaded = true;
    }
    return &checker;
}

/* After the known-answer probe and before every other arm: a probe holds the
 * exact right answer, which strictly subsumes asking whether the answer is
 * possible; everything after this is a judgment about completion. It speaks
 * only to refute -- a claim that merely survives earns nothing -- so a NONE
 * verdict falls through. */
static bool physics_score(const neg_score_input_t *in, double *score, const char **channel)
{
    at_physics_checker_t *physics = physics_checker();
    if (!at_physics_checker_enabled(physics))
        return false;
    char reason[AT_PHYS_ERR_LEN] = {0};
    at_physics_verdict_t verdict = at_physics_check(
        physics, in->cap, in->result_str, in->subject, in->now, score,
        reason, sizeof(reason));
    if (verdict == AT_PHYSICS_REFUTED)
    {
        log_warn(NULL, "physics: REFUTED (%s)\n", reason);
        *channel = TX_CHANNEL_PHYSICAL;
        return true;
    }
    if (verdict == AT_PHYSICS_IMPLICATED)
    {
        log_info(NULL, "physics: %s\n", reason);
        *channel = TX_CHANNEL_SWARM_DISAGREEMENT;
        return true;
    }
    return false;
}

/* The declared quantity a capability REPORTS, or NULL. The link lives in
 * physics.json (each quantity names its reporting capability); providing it
 * from here is what lets the calibration and prequential layers stay
 * independent of this one -- a node can run the audit with no physics
 * declaration at all and resolve predictions through at_calibration_settle. */
static const char *physics_quantity(const char *capability)
{
    const at_physics_checker_t *physics = physics_checker();
    for (int i = 0; i < physics->model.n_quantities; i++)
        if (strcmp(physics->model.quantities[i].capability, capability) == 0)
            return physics->model.quantities[i].name;
    return NULL;
}

static void physics_reset(void)
{
    loaded = false;   /* rebuilt (window emptied) from $AT_PHYSICS on next use */
}

static const neg_oracle_t physics_oracle = { .name = "physics", .reset = physics_reset };
static const neg_oracle_arm_t physics_arm = {
    .name = "physics.check", .order = 100, .score = physics_score,
};

static void __attribute__((constructor)) physics_oracle_register(void)
{
    (void)neg_oracle_register(&physics_oracle);
    (void)neg_oracle_arm_register(&physics_arm);
    (void)neg_oracle_provide_quantity(physics_quantity);
}

void at_physics_link(void) {}
