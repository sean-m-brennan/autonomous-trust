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

/**
 * @file dm_test.c
 * @brief Direct-message payload round-trip + body bounding (Increment 6).
 *
 * A DM is a single directed, ENCRYPTED peer→peer text message carrying
 * {text, seq, ts}. crypto_box authenticates the sender, so — UNLIKE the
 * connection accept — there is NO signature and NO canonical byte form to pin
 * here; the wire payload is plain JSON. So this pins what the handler stands on:
 * the {text,seq,ts} framing round-trips, the body is bound-truncated to
 * AT_DM_TEXT_MAX, and a malformed/unstamped payload is refused. The freshness/
 * replay gate and the emit-to-app path are exercised end-to-end by the
 * conformance scenarios (dm-*.yaml, both runtimes); the plaintext-refusal of the
 * peer_dm verb is pinned in unencrypted_verbs_test.c (peer_dm in the REFUSED
 * list).
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>

#include "identity/dm.h"

DEFINE_TEST(test_text_bound_truncation)
{
    /* A body at the bound is kept whole; one over the bound is truncated to
     * exactly AT_DM_TEXT_MAX bytes (the app-boundary buffer size). */
    char out[AT_DM_TEXT_MAX + 1];
    ck_assert_int_eq((int)at_dm_bound_text("hi", out, sizeof(out)), 2);
    ck_assert_str_eq(out, "hi");

    char big[AT_DM_TEXT_MAX + 64];
    memset(big, 'x', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    size_t n = at_dm_bound_text(big, out, sizeof(out));
    ck_assert_int_eq((int)n, AT_DM_TEXT_MAX);
    ck_assert_int_eq((int)strlen(out), AT_DM_TEXT_MAX);

    /* NULL / tiny buffers stay safe and NUL-terminated. */
    ck_assert_int_eq((int)at_dm_bound_text(NULL, out, sizeof(out)), 0);
    ck_assert_str_eq(out, "");
    char tiny[4];
    ck_assert_int_eq((int)at_dm_bound_text("abcdef", tiny, sizeof(tiny)), 3);
    ck_assert_str_eq(tiny, "abc");
}

DEFINE_TEST(test_payload_round_trips)
{
    /* Build {text,seq,ts} and parse it back: text, seq and ts are all carried. */
    json_t *env = at_dm_to_json("hello there", 7, 1234.5);
    ck_assert_ptr_nonnull(env);

    char text[AT_DM_TEXT_MAX + 1];
    int64_t seq = 0;
    double ts = 0.0;
    ck_assert_int_eq(at_dm_from_json(env, text, sizeof(text), &seq, &ts), 0);
    ck_assert_str_eq(text, "hello there");
    ck_assert_int_eq((int)seq, 7);
    ck_assert_double_eq_tol(ts, 1234.5, 1e-9);
    json_decref(env);
}

DEFINE_TEST(test_over_bound_body_truncated_on_parse)
{
    /* An over-long body in the payload is bound-truncated by the parse (the
     * receive path clamps rather than rejecting the whole DM). */
    char big[AT_DM_TEXT_MAX + 64];
    memset(big, 'y', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    json_t *env = at_dm_to_json(big, 3, 9.0);  /* to_json also bounds it */
    ck_assert_ptr_nonnull(env);

    char text[AT_DM_TEXT_MAX + 1];
    int64_t seq = 0;
    double ts = 0.0;
    ck_assert_int_eq(at_dm_from_json(env, text, sizeof(text), &seq, &ts), 0);
    ck_assert_int_eq((int)strlen(text), AT_DM_TEXT_MAX);
    ck_assert_int_eq((int)seq, 3);
    json_decref(env);
}

DEFINE_TEST(test_malformed_payload_refused)
{
    char text[AT_DM_TEXT_MAX + 1];
    int64_t seq = 0;
    double ts = 0.0;

    /* An unstamped DM (no seq) is refused — the replay guard needs the seq. */
    json_t *no_seq = json_object();
    json_object_set_new(no_seq, "text", json_string("hi"));
    json_object_set_new(no_seq, "ts", json_real(1.0));
    ck_assert_ret_nonzero(at_dm_from_json(no_seq, text, sizeof(text), &seq, &ts));
    ck_assert_str_eq(text, "");  /* cleared on failure */
    json_decref(no_seq);

    /* A non-integer seq is refused. */
    json_t *bad_seq = json_object();
    json_object_set_new(bad_seq, "text", json_string("hi"));
    json_object_set_new(bad_seq, "seq", json_string("7"));
    json_object_set_new(bad_seq, "ts", json_real(1.0));
    ck_assert_ret_nonzero(at_dm_from_json(bad_seq, text, sizeof(text), &seq, &ts));
    json_decref(bad_seq);

    /* A missing text field is refused. */
    json_t *no_text = json_object();
    json_object_set_new(no_text, "seq", json_integer(1));
    json_object_set_new(no_text, "ts", json_real(1.0));
    ck_assert_ret_nonzero(at_dm_from_json(no_text, text, sizeof(text), &seq, &ts));
    json_decref(no_text);

    /* NULL is refused. */
    ck_assert_ret_nonzero(at_dm_from_json(NULL, text, sizeof(text), &seq, &ts));
}

RUN_TESTS(DirectMessage,
          test_text_bound_truncation,
          test_payload_round_trips,
          test_over_bound_body_truncated_on_parse,
          test_malformed_payload_refused)
