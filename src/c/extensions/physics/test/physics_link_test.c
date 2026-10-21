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

/* libat_physics present after link (FEATURE_SPLIT_PLAN Phase 3): the "physics"
 * layer is declared, its arm refutes an impossible claim once $AT_PHYSICS
 * names a model, and it provides the reported-quantity lookup.
 * neg_oracle_test asserts the converse, that a core-only binary has no layer
 * and refuses a node that declares one. */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "physics/at_physics.h"
#include "negotiation/neg_oracle.h"
#include "negotiation/neg_proc_priv.h"
#include "physics/physics.h"
#include "reputation/tx_channel.h"

static bool feq(double a, double b) { return fabs(a - b) < 1e-12; }

/* Write @p json to a fresh temp file and declare it through @p env, the way
 * a node's operator does; the layer re-reads it after the reset. */
static void declare(const char *env, const char *json)
{
    static char path[] = "/tmp/at-physics-link-XXXXXX";
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

#define MODEL "{\"version\":1,\"quantities\":{\"sat.solar-power\":" \
              "{\"capability\":\"sat.solar\",\"unit\":\"W\",\"min\":0.0,\"max\":2000.0}}}"

DEFINE_TEST(test_linked_but_undeclared_is_silent)
{
    unsetenv("AT_PHYSICS");
    neg_oracles_reset();
    ck_assert(neg_oracle_present("physics"));
    const char *ch = NULL;
    ck_assert(feq(score("sat.solar", NULL, "-5.0", NULL, NULL, &ch), 0.8));
    ck_assert_str_eq(ch, TX_CHANNEL_TASK_OUTCOME);
    ck_assert(neg_oracle_reported_quantity("sat.solar") == NULL);
    at_physics_link();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_declared_model_refutes_through_the_scorer)
{
    declare("AT_PHYSICS", MODEL);
    ck_assert_int_eq(neg_oracles_check_env(NULL), 0);   /* present: no refusal */
    ck_assert_str_eq(neg_oracle_reported_quantity("sat.solar"), "sat.solar-power");

    const char *ch = NULL;
    ck_assert(feq(score("sat.solar", NULL, "-5.0", NULL, NULL, &ch),
                  AT_PHYSICS_REFUTED_SCORE));
    ck_assert_str_eq(ch, TX_CHANNEL_PHYSICAL);
    ck_assert(feq(score("sat.solar", NULL, "100.0", NULL, NULL, &ch), 0.8));
    ck_assert_str_eq(ch, TX_CHANNEL_TASK_OUTCOME);

    unsetenv("AT_PHYSICS");
    neg_oracles_reset();
}
END_TEST_DEFINITION()

RUN_TESTS(PhysicsLink, test_linked_but_undeclared_is_silent,
          test_declared_model_refutes_through_the_scorer)
