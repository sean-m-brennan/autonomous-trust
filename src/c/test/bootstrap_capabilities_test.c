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

#include <stdint.h>

#include "bootstrap/bootstrap_capabilities.h"
#include "processes/capabilities.h"

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

DEFINE_TEST(test_is_probe_capability)
{
    ck_assert(is_probe_capability("at.handshake"));
    ck_assert(is_probe_capability("at.time-attest"));
    ck_assert(is_probe_capability("at.echo-challenge"));
    ck_assert(is_probe_capability("dod.sensor-report") == false);
    ck_assert(is_probe_capability("") == false);
    ck_assert(is_probe_capability(NULL) == false);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_verify_bootstrap_result_dispatch)
{
    /* The dispatcher the BOOTSTRAP_VERIFIERS comment always described and
     * which nothing implemented, in either twin (R+D.md §12.7). */
    double score = -1.0;
    probe_challenge_t ch = {.nonce = 7, .payload = NULL};

    ck_assert(verify_bootstrap_result("at.handshake", (double)at_handshake(7),
                                      NULL, &ch, 0.0, &score));
    ck_assert_score(score, 0.9);

    /* A stale nonce: the peer replied promptly with a well-formed integer, so
     * completion-based scoring cannot tell it from a correct answer. */
    ck_assert(verify_bootstrap_result("at.handshake", 7.0, NULL, &ch, 0.0,
                                      &score));
    ck_assert_score(score, 0.1);

    ch.payload = "abc";
    ck_assert(verify_bootstrap_result("at.echo-challenge", 0.0, "abc", &ch,
                                      0.0, &score));
    ck_assert_score(score, 0.9);
    ck_assert(verify_bootstrap_result("at.echo-challenge", 0.0, "abd", &ch,
                                      0.0, &score));
    ck_assert_score(score, 0.1);

    /* Truthful clock passes; a lying one lands on forgivable-drift rather than
     * defection, because the requestor's comparison includes the round trip. */
    double now = at_time_attest();
    ck_assert(verify_bootstrap_result("at.time-attest", now, NULL, NULL, now,
                                      &score));
    ck_assert_score(score, 0.9);
    ck_assert(verify_bootstrap_result("at.time-attest", now - 3600.0, NULL,
                                      NULL, now, &score));
    ck_assert_score(score, 0.5);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_verify_bootstrap_result_non_probe_is_false)
{
    /* False, not a score -- so the caller falls through to ordinary task
     * scoring rather than grading a domain task against an expected value it
     * does not have. The C form of Python's "return None". */
    double score = 42.0;
    ck_assert(verify_bootstrap_result("dod.sensor-report", 1.0, NULL, NULL,
                                      0.0, &score) == false);
    ck_assert_score(score, 42.0);   /* untouched */
    ck_assert(verify_bootstrap_result(NULL, 1.0, NULL, NULL, 0.0, &score)
              == false);
    ck_assert(verify_bootstrap_result("at.handshake", 1.0, NULL, NULL, 0.0,
                                      NULL) == false);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_verify_bootstrap_result_absent_challenge_defaults)
{
    /* No challenge → nonce 0, matching at_handshake's own default, so an
     * unstamped probe still expects 1 rather than accepting anything. */
    double score = -1.0;
    ck_assert(verify_bootstrap_result("at.handshake", 1.0, NULL, NULL, 0.0,
                                      &score));
    ck_assert_score(score, 0.9);
    ck_assert(verify_bootstrap_result("at.handshake", 55.0, NULL, NULL, 0.0,
                                      &score));
    ck_assert_score(score, 0.1);
    /* Absent expected payload reads as "", which is what at_echo_challenge
     * echoes for NULL -- an empty probe stays verifiable. */
    ck_assert(verify_bootstrap_result("at.echo-challenge", 0.0, "", NULL, 0.0,
                                      &score));
    ck_assert_score(score, 0.9);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_verify_bootstrap_result_nonfinite_handshake)
{
    double score = -1.0;
    probe_challenge_t ch = {.nonce = 7, .payload = NULL};
    ck_assert(verify_bootstrap_result("at.handshake", NAN, NULL, &ch, 0.0,
                                      &score));
    ck_assert_score(score, 0.1);
    ck_assert(verify_bootstrap_result("at.handshake", INFINITY, NULL, &ch,
                                      0.0, &score));
    ck_assert_score(score, 0.1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_time_attest_tolerance_env)
{
    /* Documented in both twins from the start, read by neither. */
    unsetenv("AT_TIME_ATTEST_TOLERANCE_SEC");
    ck_assert_score(time_attest_tolerance(),
                    AT_DEFAULT_TIME_ATTEST_TOLERANCE_SEC);
    setenv("AT_TIME_ATTEST_TOLERANCE_SEC", "5.0", 1);
    ck_assert_score(time_attest_tolerance(), 5.0);
    /* Garbage, zero and negative all fall back: a tolerance of 0 would score
     * every peer 0.5 forever, a quieter failure than using the default. */
    setenv("AT_TIME_ATTEST_TOLERANCE_SEC", "abc", 1);
    ck_assert_score(time_attest_tolerance(),
                    AT_DEFAULT_TIME_ATTEST_TOLERANCE_SEC);
    setenv("AT_TIME_ATTEST_TOLERANCE_SEC", "0", 1);
    ck_assert_score(time_attest_tolerance(),
                    AT_DEFAULT_TIME_ATTEST_TOLERANCE_SEC);
    setenv("AT_TIME_ATTEST_TOLERANCE_SEC", "-1", 1);
    ck_assert_score(time_attest_tolerance(),
                    AT_DEFAULT_TIME_ATTEST_TOLERANCE_SEC);
    unsetenv("AT_TIME_ATTEST_TOLERANCE_SEC");
}
END_TEST_DEFINITION()

/* ------------------------------------------------------------------
 * Responder-side executors (R+D.md §12.7): the shape the negotiation
 * worker can actually call -- keyword arguments in as compact JSON, the
 * answer out as text. Before these existed a C node could accept an
 * invitation but never answer it, because capability_function_t returns
 * void and no result could be collected.
 * ------------------------------------------------------------------ */

DEFINE_TEST(test_handshake_exec_answers_the_challenge)
{
    char out[CAP_RESULT_LEN + 1] = {0};
    ck_assert_ret_ok(at_handshake_exec("{\"nonce\":41}", out, sizeof(out)));
    ck_assert_str_eq(out, "42");

    /* An absent nonce reads as 0 -- documented default, and the requestor
     * scores the answer against the challenge IT sent, so a responder that
     * cannot see the challenge is scored wrong rather than trusted. */
    ck_assert_ret_ok(at_handshake_exec("{}", out, sizeof(out)));
    ck_assert_str_eq(out, "1");
    ck_assert_ret_ok(at_handshake_exec("", out, sizeof(out)));
    ck_assert_str_eq(out, "1");
    /* Unparseable is the same case, not a crash. */
    ck_assert_ret_ok(at_handshake_exec("{not json", out, sizeof(out)));
    ck_assert_str_eq(out, "1");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_echo_exec_echoes_and_refuses_truncation)
{
    char out[CAP_RESULT_LEN + 1] = {0};
    ck_assert_ret_ok(at_echo_challenge_exec("{\"payload\":\"echo:deadbeef\"}",
                                            out, sizeof(out)));
    ck_assert_str_eq(out, "echo:deadbeef");

    /* No payload echoes as "" (what at_echo_challenge(NULL) returns), which
     * verify_echo scores 0.9 against an absent challenge. */
    ck_assert_ret_ok(at_echo_challenge_exec("{}", out, sizeof(out)));
    ck_assert_str_eq(out, "");

    /* A token that does not fit is REFUSED, not truncated: a truncated echo
     * is a wrong answer, and the requestor would read it as tampering when
     * the fault is on this side. */
    char tiny[4] = {0};
    ck_assert(at_echo_challenge_exec("{\"payload\":\"echo:deadbeef\"}",
                                     tiny, sizeof(tiny)) != 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_time_attest_exec_reports_this_clock)
{
    char out[CAP_RESULT_LEN + 1] = {0};
    ck_assert_ret_ok(at_time_attest_exec("", out, sizeof(out)));
    double reported = strtod(out, NULL);
    /* Within a second of our own clock: this is the responder half, so it is
     * the truth being reported, not a comparison. */
    ck_assert_double_eq_tol(reported, at_time_attest(), 1.0);

    /* And the round trip the probe actually makes: this answer, verified
     * against the requestor's clock, scores as an honest one. */
    double score = 0.0;
    ck_assert(verify_bootstrap_result("at.time-attest", reported, out, NULL,
                                      reported, &score));
    ck_assert_score(score, 0.9);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_executors_round_trip_through_their_verifiers)
{
    /* The point of the corpus: an honest responder scores 0.9 and a tampered
     * answer scores 0.1, with the expected value taken from the challenge the
     * requestor sent rather than anything in the reply. */
    char out[CAP_RESULT_LEN + 1] = {0};
    probe_challenge_t ch = { .nonce = 41, .payload = NULL };
    ck_assert_ret_ok(at_handshake_exec("{\"nonce\":41}", out, sizeof(out)));
    double score = 0.0;
    ck_assert(verify_bootstrap_result("at.handshake", strtod(out, NULL), out,
                                      &ch, 0.0, &score));
    ck_assert_score(score, 0.9);

    /* Same reply, but the requestor's record says it asked something else --
     * which is exactly how a replayed or fabricated answer looks. */
    probe_challenge_t other = { .nonce = 77, .payload = NULL };
    ck_assert(verify_bootstrap_result("at.handshake", strtod(out, NULL), out,
                                      &other, 0.0, &score));
    ck_assert_score(score, 0.1);

    probe_challenge_t echo_ch = { .nonce = 0, .payload = "echo:cafe" };
    ck_assert_ret_ok(at_echo_challenge_exec("{\"payload\":\"echo:cafe\"}",
                                            out, sizeof(out)));
    ck_assert(verify_bootstrap_result("at.echo-challenge", 0.0, out, &echo_ch,
                                      0.0, &score));
    ck_assert_score(score, 0.9);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_bootstrap_capabilities_enabled_env)
{
    unsetenv("AT_BOOTSTRAP_DISABLED");
    ck_assert(bootstrap_capabilities_enabled());
    setenv("AT_BOOTSTRAP_DISABLED", "1", 1);
    ck_assert(!bootstrap_capabilities_enabled());
    /* "0" is off-by-request, not disabled -- same reading as the worker's
     * own gate, so a node cannot end up advertising a probe it will not
     * answer (or the reverse). */
    setenv("AT_BOOTSTRAP_DISABLED", "0", 1);
    ck_assert(bootstrap_capabilities_enabled());
    unsetenv("AT_BOOTSTRAP_DISABLED");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_probe_capabilities_are_in_the_capability_table)
{
    /* The advertisement half: an invitation names a capability, and
     * find_capability is what decides whether this node can run it. Python
     * registers these at runtime; C generates the table from
     * DECLARE_CAPABILITY call sites, so this pins that the call sites exist
     * and carry a result-producing entry point. */
    for (int i = 0; i < BOOTSTRAP_CAPABILITY_COUNT; i++) {
        capability_t *cap = find_capability(BOOTSTRAP_CAPABILITY_NAMES[i]);
        ck_assert_ptr_nonnull(cap);
        ck_assert_ptr_nonnull((void *)(uintptr_t)cap->result_function);
        char out[CAP_RESULT_LEN + 1] = {0};
        /* Called with no arguments, so each answers its documented default.
         * Only that the call SUCCEEDS is asserted: at.echo-challenge's
         * default answer is the empty echo, which is a real answer. */
        ck_assert_ret_ok(capability_execute_result(cap, "{}", out,
                                                   sizeof(out)));
    }
}
END_TEST_DEFINITION()

RUN_TESTS(BootstrapCapabilities,
          test_handshake_increment,
          test_verify_handshake_scores,
          test_verify_time_attest_bands,
          test_echo_roundtrip_and_verify,
          test_registration_metadata,
          test_is_probe_capability,
          test_verify_bootstrap_result_dispatch,
          test_verify_bootstrap_result_non_probe_is_false,
          test_verify_bootstrap_result_absent_challenge_defaults,
          test_verify_bootstrap_result_nonfinite_handshake,
          test_time_attest_tolerance_env,
          test_handshake_exec_answers_the_challenge,
          test_echo_exec_echoes_and_refuses_truncation,
          test_time_attest_exec_reports_this_clock,
          test_executors_round_trip_through_their_verifiers,
          test_bootstrap_capabilities_enabled_env,
          test_probe_capabilities_are_in_the_capability_table)
