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

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "bootstrap/bootstrap_capabilities.h"

/* Mirrors the scoring contract of bootstrap_capabilities.py so the C and
 * Python verifiers agree value-for-value. The scores are discrete constants
 * (0.9 / 0.5 / 0.1); compare with a tight tolerance since this Check build
 * lacks ck_assert_double_eq. */
#define ck_assert_score(a, b) ck_assert(fabs((double)(a) - (double)(b)) < 1e-9)

DEFINE_TEST(test_handshake_increment)
{
    ck_assert_int_eq(at_handshake(0), 1);
    ck_assert_int_eq(at_handshake(41), 42);
    ck_assert_int_eq(at_handshake(999999), 1000000);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_verify_handshake_scores)
{
    /* correct increment -> 0.9 */
    ck_assert_score(verify_handshake(at_handshake(7), 7), 0.9);
    /* wrong (replayed nonce) -> 0.1 */
    ck_assert_score(verify_handshake(7, 7), 0.1);
    /* wrong (off by one too far) -> 0.1 */
    ck_assert_score(verify_handshake(9, 7), 0.1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_verify_time_attest_bands)
{
    double tol = AT_DEFAULT_TIME_ATTEST_TOLERANCE_SEC;
    /* within tolerance -> 0.9 */
    ck_assert_score(verify_time_attest(1000.05, 1000.0, tol), 0.9);
    /* outside tolerance but finite -> 0.5 (forgivable drift) */
    ck_assert_score(verify_time_attest(1005.0, 1000.0, tol), 0.5);
    /* non-finite (unparseable analog) -> 0.1 */
    ck_assert_score(verify_time_attest(NAN, 1000.0, tol), 0.1);
    ck_assert_score(verify_time_attest(1000.0, INFINITY, tol), 0.1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_echo_roundtrip_and_verify)
{
    char *echoed = at_echo_challenge("echo:deadbeef");
    ck_assert_ptr_nonnull(echoed);
    ck_assert_str_eq(echoed, "echo:deadbeef");
    ck_assert_score(verify_echo(echoed, "echo:deadbeef"), 0.9);
    free(echoed);

    /* NULL payload echoes as empty string */
    char *empty = at_echo_challenge(NULL);
    ck_assert_ptr_nonnull(empty);
    ck_assert_str_eq(empty, "");
    free(empty);

    /* tamper / mismatch -> 0.1; NULL result -> 0.1 */
    ck_assert_score(verify_echo("tampered", "original"), 0.1);
    ck_assert_score(verify_echo(NULL, "original"), 0.1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_registration_metadata)
{
    bootstrap_capability_t caps[BOOTSTRAP_CAPABILITY_COUNT];
    int n = register_bootstrap_capabilities(caps);
    ck_assert_int_eq(n, BOOTSTRAP_CAPABILITY_COUNT);
    for (int i = 0; i < n; i++) {
        ck_assert_str_eq(caps[i].name, BOOTSTRAP_CAPABILITY_NAMES[i]);
        ck_assert_int_eq(caps[i].required_tier, 0);
        ck_assert_int_eq(caps[i].transaction_weight, 1);
    }
    ck_assert_str_eq(BOOTSTRAP_CAPABILITY_NAMES[0], "at.handshake");
    ck_assert_str_eq(BOOTSTRAP_CAPABILITY_NAMES[1], "at.time-attest");
    ck_assert_str_eq(BOOTSTRAP_CAPABILITY_NAMES[2], "at.echo-challenge");
    ck_assert_int_eq(register_bootstrap_capabilities(NULL), -1);
}
END_TEST_DEFINITION()

RUN_TESTS(BootstrapCapabilities,
          test_handshake_increment,
          test_verify_handshake_scores,
          test_verify_time_attest_bands,
          test_echo_roundtrip_and_verify,
          test_registration_metadata)
