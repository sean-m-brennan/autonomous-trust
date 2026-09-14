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
 * @file social_tx_test.c
 * @brief Social-interaction reputation accrual primitives (Increment 8):
 *        the bilateral task_uuid derivation and the diminishing-returns score.
 *
 * The two task_uuid vectors below are PINNED and MUST match the Python twin
 * (social_task_uuid() in capabilities.py). Both peers of an interaction derive
 * the task_uuid independently and must agree byte-for-byte, or their two scores
 * never pair into one bilateral transaction — so this cross-language literal is
 * the guard the whole accrual mechanism depends on. The per-edge counter/cap and
 * bilateral-recency gating are stateful (id_state) and are exercised behaviorally
 * by the accrual-* conformance scenarios on both runtimes.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>
#include <math.h>
#include <sodium.h>

#include "identity/social_tx.h"

/* Fixed reference participants shared with the Python twin:
 *   a = bytes 0x00..0x0f, b = bytes 0x10..0x1f. */
static void ref_uuids(uuid_t a, uuid_t b)
{
    for (int i = 0; i < 16; i++) { a[i] = (uint8_t)i; b[i] = (uint8_t)(0x10 + i); }
}

/* domain "agora-conn", tail = u64le(7). */
static const char *const REF_CONN_TASK = "e906a640-64b6-e889-78b0-e7d8d21b50fd";
/* domain "agora-post", tail = 16 bytes of 0xAB. */
static const char *const REF_POST_TASK = "b4466275-cc76-93a7-2a4f-f0302ded25cb";

DEFINE_TEST(test_task_uuid_matches_pinned_vectors)
{
    uuid_t a, b, t; char s[40];
    ref_uuids(a, b);
    uint8_t seq7[8] = {7, 0, 0, 0, 0, 0, 0, 0};
    ck_assert_int_eq(at_social_task_uuid(AT_SOCIAL_DOMAIN_CONN, a, b, seq7, 8, t), 0);
    uuid_unparse_lower(t, s);
    ck_assert_str_eq(s, REF_CONN_TASK);

    uint8_t pid[16]; memset(pid, 0xAB, sizeof(pid));
    ck_assert_int_eq(at_social_task_uuid(AT_SOCIAL_DOMAIN_POST, a, b, pid, 16, t), 0);
    uuid_unparse_lower(t, s);
    ck_assert_str_eq(s, REF_POST_TASK);
}

DEFINE_TEST(test_task_uuid_is_participant_order_independent)
{
    uuid_t a, b, tab, tba; char sab[40], sba[40];
    ref_uuids(a, b);
    uint8_t tail[8] = {42, 0, 0, 0, 0, 0, 0, 0};
    ck_assert_int_eq(at_social_task_uuid(AT_SOCIAL_DOMAIN_DM, a, b, tail, 8, tab), 0);
    ck_assert_int_eq(at_social_task_uuid(AT_SOCIAL_DOMAIN_DM, b, a, tail, 8, tba), 0);
    uuid_unparse_lower(tab, sab); uuid_unparse_lower(tba, sba);
    ck_assert_str_eq(sab, sba);            /* both peers converge on one task */
}

DEFINE_TEST(test_task_uuid_domain_and_tail_bind)
{
    uuid_t a, b, tc, td, t1, t2; char s[5][40];
    ref_uuids(a, b);
    uint8_t tail[8] = {1, 0, 0, 0, 0, 0, 0, 0};
    uint8_t tail2[8] = {2, 0, 0, 0, 0, 0, 0, 0};
    /* Different domains never collide for the same peers+tail. */
    at_social_task_uuid(AT_SOCIAL_DOMAIN_CONN, a, b, tail, 8, tc);
    at_social_task_uuid(AT_SOCIAL_DOMAIN_DM, a, b, tail, 8, td);
    uuid_unparse_lower(tc, s[0]); uuid_unparse_lower(td, s[1]);
    ck_assert(strcmp(s[0], s[1]) != 0);
    /* Different tail (seq/bucket) => different task. */
    at_social_task_uuid(AT_SOCIAL_DOMAIN_DM, a, b, tail, 8, t1);
    at_social_task_uuid(AT_SOCIAL_DOMAIN_DM, a, b, tail2, 8, t2);
    uuid_unparse_lower(t1, s[2]); uuid_unparse_lower(t2, s[3]);
    ck_assert(strcmp(s[2], s[3]) != 0);
}

DEFINE_TEST(test_task_uuid_rejects_bad_args)
{
    uuid_t a, b, t; ref_uuids(a, b);
    ck_assert_ret_nonzero(at_social_task_uuid(NULL, a, b, NULL, 0, t));
    /* tail_len without tail is refused. */
    ck_assert_ret_nonzero(at_social_task_uuid(AT_SOCIAL_DOMAIN_DM, a, b, NULL, 8, t));
}

DEFINE_TEST(test_pos_score_diminishes)
{
    /* S_pos(count) = 0.65 + 0.25/count: peaks at the tier-4 floor for a first
     * mutual interaction, then decays toward the tier-2 "established" floor. */
    ck_assert(fabs(at_social_pos_score(1) - 0.90) < 1e-9);
    ck_assert(fabs(at_social_pos_score(2) - 0.775) < 1e-9);
    ck_assert(fabs(at_social_pos_score(4) - 0.7125) < 1e-9);
    /* Monotone decreasing and bounded below by the baseline. */
    ck_assert(at_social_pos_score(2) < at_social_pos_score(1));
    ck_assert(at_social_pos_score(1000) > AT_SOCIAL_POS_BASELINE);
    ck_assert(at_social_pos_score(1000) < 0.66);
    /* count <= 0 is treated as 1, and every score stays on the [0,1] TX scale. */
    ck_assert(fabs(at_social_pos_score(0) - 0.90) < 1e-9);
    ck_assert(at_social_pos_score(1) <= 1.0);
}

RUN_TESTS(SocialTx,
          test_task_uuid_matches_pinned_vectors,
          test_task_uuid_is_participant_order_independent,
          test_task_uuid_domain_and_tail_bind,
          test_task_uuid_rejects_bad_args,
          test_pos_score_diminishes)
