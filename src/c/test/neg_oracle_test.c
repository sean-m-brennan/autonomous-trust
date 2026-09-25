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

/* The oracle registry (negotiation/neg_oracle.h, FEATURE_SPLIT_PLAN Phase 3):
 * the arms run in order and the first verdict ends scoring, observe arms only
 * record, refusals, the providers and their neutral defaults, reset, and the
 * start-time refusal of a declared layer this binary lacks. The core links no
 * layer here, so the registry starts empty. */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "negotiation/neg_oracle.h"
#include "negotiation/neg_proc_priv.h"
#include "reputation/tx_channel.h"

static char arm_log[16];
static size_t arm_log_len;
static int resets;

static bool feq(double a, double b) { return fabs(a - b) < 1e-12; }
static void mark(char c) { arm_log[arm_log_len++] = c; }

static bool arm_a(const neg_score_input_t *in, double *s, const char **ch) { mark('a'); return false; }
static void arm_o(const neg_score_input_t *in) { mark('o'); }
static bool arm_b(const neg_score_input_t *in, double *s, const char **ch) { mark('b'); return false; }
static bool arm_c(const neg_score_input_t *in, double *s, const char **ch)
{
    mark('c');
    if (in->cap == NULL || strcmp(in->cap, "decide") != 0)
        return false;
    *s = 0.42;
    *ch = TX_CHANNEL_CERTIFICATE;
    return true;
}
static bool arm_d(const neg_score_input_t *in, double *s, const char **ch) { mark('d'); return true; }

/* Registered out of order on purpose. */
static const neg_oracle_arm_t A = { .name = "t.a", .order = 100, .score = arm_a };
static const neg_oracle_arm_t O = { .name = "t.o", .order = 250, .observe = arm_o };
static const neg_oracle_arm_t B = { .name = "t.b", .order = 300, .score = arm_b };
static const neg_oracle_arm_t C = { .name = "t.c", .order = 400, .score = arm_c };
static const neg_oracle_arm_t D = { .name = "t.d", .order = 500, .score = arm_d };

static void count_reset(void) { resets++; }
static const neg_oracle_t PHYS = { .name = "physics", .reset = count_reset };

static const char *quantity(const char *cap) { return strcmp(cap, "thermo") == 0 ? "temperature" : NULL; }
static double competence(const char *cap, const char *subject) { return 1.25; }

DEFINE_TEST(test_empty_registry_is_neutral)
{
    unsetenv("AT_PHYSICS");
    unsetenv("AT_CALIBRATION");
    unsetenv("AT_PREQUENTIAL");
    unsetenv("AT_CERTIFICATES");
    neg_score_input_t in = { .cap = "decide" };
    double score = -1.0;
    const char *channel = NULL;
    ck_assert(!neg_oracles_score(&in, &score, &channel));
    ck_assert(neg_oracle_reported_quantity("thermo") == NULL);
    ck_assert(feq(neg_oracle_competence("thermo", "peer"), NEG_NEUTRAL_COMPETENCE));
    ck_assert(feq(negotiation_competence_weight("thermo", "peer"), NEG_NEUTRAL_COMPETENCE));
    ck_assert(!neg_oracle_present("physics"));
    ck_assert_int_eq(neg_oracles_check_env(NULL), 0);

    /* With no layer, the scorer is the probe + completion arms alone. */
    const char *ch = NULL;
    ck_assert(feq(negotiation_score_task_result("decide", NULL, "x", 1, NULL, NULL,
                                                NULL, 0.0, 0, &ch), 0.8));
    ck_assert_str_eq(ch, TX_CHANNEL_TASK_OUTCOME);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_declared_layer_missing_is_refused)
{
    setenv("AT_CALIBRATION", "/nonexistent/calibration.json", 1);
    ck_assert_int_eq(neg_oracles_check_env(NULL), -1);
    setenv("AT_CALIBRATION", "", 1);   /* empty is undeclared */
    ck_assert_int_eq(neg_oracles_check_env(NULL), 0);
    unsetenv("AT_CALIBRATION");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_refusals)
{
    neg_oracle_arm_t unnamed = { .name = "", .order = 1, .score = arm_a };
    neg_oracle_arm_t neither = { .name = "t.x", .order = 1 };
    neg_oracle_arm_t both = { .name = "t.y", .order = 1, .score = arm_a, .observe = arm_o };
    ck_assert_int_eq(neg_oracle_arm_register(NULL), -1);
    ck_assert_int_eq(neg_oracle_arm_register(&unnamed), -1);
    ck_assert_int_eq(neg_oracle_arm_register(&neither), -1);
    ck_assert_int_eq(neg_oracle_arm_register(&both), -1);
    neg_oracle_t noname = { .name = NULL };
    ck_assert_int_eq(neg_oracle_register(NULL), -1);
    ck_assert_int_eq(neg_oracle_register(&noname), -1);
    ck_assert_int_eq(neg_oracle_provide_quantity(NULL), -1);
    ck_assert_int_eq(neg_oracle_provide_competence(NULL), -1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_arms_run_in_order_and_first_verdict_ends)
{
    ck_assert_int_eq(neg_oracle_arm_register(&C), 0);
    ck_assert_int_eq(neg_oracle_arm_register(&A), 0);
    ck_assert_int_eq(neg_oracle_arm_register(&D), 0);
    ck_assert_int_eq(neg_oracle_arm_register(&O), 0);
    ck_assert_int_eq(neg_oracle_arm_register(&B), 0);

    /* C decides: D never runs; the observe arm ran between A and B. */
    arm_log_len = 0;
    neg_score_input_t in = { .cap = "decide" };
    double score = 0.0;
    const char *channel = NULL;
    ck_assert(neg_oracles_score(&in, &score, &channel));
    ck_assert_int_eq((int)arm_log_len, 4);
    ck_assert_mem_eq(arm_log, "aobc", 4);
    ck_assert(feq(score, 0.42));
    ck_assert_str_eq(channel, TX_CHANNEL_CERTIFICATE);

    /* Through the scorer: the arms' verdict, not the completion arm. */
    arm_log_len = 0;
    const char *ch = NULL;
    ck_assert(feq(negotiation_score_task_result("decide", NULL, "x", 1, NULL, NULL,
                                                NULL, 0.0, 0, &ch), 0.42));
    ck_assert_str_eq(ch, TX_CHANNEL_CERTIFICATE);

    /* C declines: D (last) decides. */
    arm_log_len = 0;
    in.cap = "other";
    ck_assert(neg_oracles_score(&in, &score, &channel));
    ck_assert_mem_eq(arm_log, "aobcd", 5);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_providers)
{
    ck_assert_int_eq(neg_oracle_provide_quantity(quantity), 0);
    ck_assert_int_eq(neg_oracle_provide_quantity(quantity), -1);   /* one provider */
    ck_assert_str_eq(neg_oracle_reported_quantity("thermo"), "temperature");
    ck_assert(neg_oracle_reported_quantity("other") == NULL);
    ck_assert(neg_oracle_reported_quantity("") == NULL);
    ck_assert(neg_oracle_reported_quantity(NULL) == NULL);

    ck_assert_int_eq(neg_oracle_provide_competence(competence), 0);
    ck_assert_int_eq(neg_oracle_provide_competence(competence), -1);
    ck_assert(feq(neg_oracle_competence("thermo", "peer"), 1.25));
    ck_assert(feq(negotiation_competence_weight("thermo", "peer"), 1.25));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_declared_layer_passes_check_and_resets)
{
    ck_assert_int_eq(neg_oracle_register(&PHYS), 0);
    ck_assert_int_eq(neg_oracle_register(&PHYS), -1);   /* duplicate */
    ck_assert(neg_oracle_present("physics"));

    setenv("AT_PHYSICS", "/nonexistent/physics.json", 1);
    ck_assert_int_eq(neg_oracles_check_env(NULL), 0);
    unsetenv("AT_PHYSICS");

    resets = 0;
    neg_oracles_reset();
    ck_assert_int_eq(resets, 1);
    negotiation_reset_state();   /* the negotiation reset reaches the layers */
    ck_assert_int_eq(resets, 2);
}
END_TEST_DEFINITION()

RUN_TESTS(NegOracle, test_empty_registry_is_neutral,
          test_declared_layer_missing_is_refused, test_refusals,
          test_arms_run_in_order_and_first_verdict_ends, test_providers,
          test_declared_layer_passes_check_and_resets)
