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

/* libat_prequential present after link (FEATURE_SPLIT_PLAN Phase 3): the
 * "prequential" layer is declared and provides the competence multiplier, and
 * its observe arm records a forecast without deciding the score.
 * neg_oracle_test asserts the converse, that a core-only binary has no layer
 * and refuses a node that declares one. */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "prequential/at_prequential.h"
#include "negotiation/neg_oracle.h"
#include "negotiation/neg_proc_priv.h"
#include "reputation/tx_channel.h"

static bool feq(double a, double b) { return fabs(a - b) < 1e-12; }

/* Write @p json to a fresh temp file and declare it through @p env, the way
 * a node's operator does; the layer re-reads it after the reset. */
static void declare(const char *env, const char *json)
{
    static char path[] = "/tmp/at-prequential-link-XXXXXX";
    int fd = mkstemp(path);
    ck_assert(fd >= 0);
    ck_assert(write(fd, json, strlen(json)) == (ssize_t)strlen(json));
    close(fd);
    setenv(env, path, 1);
    neg_oracles_reset();
}

static double score(const char *cap, const char *kwargs, const char *result,
                    const char *cert, const char *pred, const char **channel)
{
    return negotiation_score_task_result(cap, kwargs, result,
                                         result ? strlen(result) : 0, cert, pred,
                                         "B", 0.0, 7, channel);
}

#define MODEL "{\"version\": 1, \"min_samples\": 2, \"max_outcomes\": 8," \
              " \"max_outstanding\": 8, \"horizon_sec\": 10.0, \"eta\": 1.0," \
              " \"weight_band\": {\"min\": 0.5, \"max\": 2.0}," \
              " \"capabilities\": {" \
              "   \"F\": {\"quantity\": \"q\", \"scale\": 10.0, \"alpha\": 0.1}}}"

DEFINE_TEST(test_linked_but_undeclared_is_neutral)
{
    unsetenv("AT_PREQUENTIAL");
    neg_oracles_reset();
    ck_assert(neg_oracle_present("prequential"));
    ck_assert(feq(negotiation_competence_weight("F", "B"), NEG_NEUTRAL_COMPETENCE));
    at_prequential_link();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_declared_model_observes_without_deciding)
{
    declare("AT_PREQUENTIAL", MODEL);
    ck_assert_int_eq(neg_oracles_check_env(NULL), 0);
    /* The competence provider is this layer's, not the core default: an
     * unknown record sits at neutral until min_samples. */
    ck_assert(feq(negotiation_competence_weight("F", "B"), NEG_NEUTRAL_COMPETENCE));
    /* A forecast rides the reply; the observe arm records it and the score is
     * still the completion arm's. */
    const char *ch = NULL;
    ck_assert(feq(score("F", NULL, "1.0", NULL,
                        "{\"lower\":0.0,\"upper\":2.0,\"coverage\":0.9}", &ch), 0.8));
    ck_assert_str_eq(ch, TX_CHANNEL_TASK_OUTCOME);
    unsetenv("AT_PREQUENTIAL");
    neg_oracles_reset();
}
END_TEST_DEFINITION()

RUN_TESTS(PrequentialLink, test_linked_but_undeclared_is_neutral,
          test_declared_model_observes_without_deciding)
