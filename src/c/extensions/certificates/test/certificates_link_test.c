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

/* libat_certificates present after link (FEATURE_SPLIT_PLAN Phase 3): the
 * "certificates" layer is declared, and once $AT_CERTIFICATES names a model
 * its arm proves a witnessed answer right and scores a missing witness.
 * neg_oracle_test asserts the converse, that a core-only binary has no layer
 * and refuses a node that declares one. */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "certificates/at_certificates.h"
#include "negotiation/neg_oracle.h"
#include "negotiation/neg_proc_priv.h"
#include "certificates/certificates.h"
#include "reputation/tx_channel.h"

static bool feq(double a, double b) { return fabs(a - b) < 1e-12; }

/* Write @p json to a fresh temp file and declare it through @p env, the way
 * a node's operator does; the layer re-reads it after the reset. */
static void declare(const char *env, const char *json)
{
    static char path[] = "/tmp/at-certificates-link-XXXXXX";
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

#define MODEL "{\"version\":1,\"capabilities\":{\"d.sat\":{\"checker\":\"sat\"}}}"
#define CNF   "{\"cnf\":[[1],[-1]]}"

DEFINE_TEST(test_linked_but_undeclared_is_silent)
{
    unsetenv("AT_CERTIFICATES");
    neg_oracles_reset();
    ck_assert(neg_oracle_present("certificates"));
    const char *ch = NULL;
    ck_assert(feq(score("d.sat", CNF, "{\"sat\":false}", NULL, NULL, &ch), 0.8));
    ck_assert_str_eq(ch, TX_CHANNEL_TASK_OUTCOME);
    at_certificates_link();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_declared_model_checks_the_witness)
{
    declare("AT_CERTIFICATES", MODEL);
    ck_assert_int_eq(neg_oracles_check_env(NULL), 0);
    const char *ch = NULL;
    ck_assert(feq(score("d.sat", CNF, "{\"sat\":false}", NULL, NULL, &ch),
                  AT_CERT_ABSENT_SCORE));
    ck_assert_str_eq(ch, TX_CHANNEL_CERTIFICATE);
    ck_assert(feq(score("d.sat", CNF, "{\"sat\":false}", "{\"proof\":[[]]}", NULL, &ch),
                  AT_CERT_VALID_SCORE));
    ck_assert_str_eq(ch, TX_CHANNEL_CERTIFICATE);
    unsetenv("AT_CERTIFICATES");
    neg_oracles_reset();
}
END_TEST_DEFINITION()

RUN_TESTS(CertificatesLink, test_linked_but_undeclared_is_silent,
          test_declared_model_checks_the_witness)
