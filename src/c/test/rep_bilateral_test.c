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

/** @file Signed halves (R+D.md §14.2; RD_14.2_BILATERAL_EVIDENCE_PLAN.md
 *  Phase 1).
 *
 *  Every ordinary half carries its scorer's signature over half_designation,
 *  which names its counterparty; two halves pair only when each names the
 *  other. The designation's bytes are pinned against the same literal as
 *  Python's, and the pool's pairing rule case by case. The process paths
 *  (commit, placement, catch-up) are pinned by the conformance corpus
 *  (scenarios/reputation/half-*). Mirrors
 *  tests/a_unit/test_bilateral_halves.py.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>

#include <jansson.h>
#include <uuid/uuid.h>

#include "reputation/reputation.h"
#include "reputation/rep_proc_priv.h"

static const char T1[] = "00000000-0000-4000-8000-000000000001";
static const char A[] = "aaaaaaaa-0000-4000-8000-000000000001";
static const char B[] = "bbbbbbbb-0000-4000-8000-000000000002";
static const char C[] = "cccccccc-0000-4000-8000-000000000003";

static void _u(const char *s, uuid_t out)
{
    ck_assert_int_eq(uuid_parse(s, out), 0);
}

DEFINE_TEST(test_the_bytes_are_pinned)
{
    /* The same literal as Python's TestDesignation. */
    static const char want[] =
        "AT-HALF\0"
        "00000000-0000-4000-8000-000000000001"
        "|aaaaaaaa-0000-4000-8000-000000000001"
        "|bbbbbbbb-0000-4000-8000-000000000002|750|task_outcome";
    uuid_t t, a, b;
    _u(T1, t); _u(A, a); _u(B, b);
    uint8_t got[HALF_DESIG_MAX];
    size_t n = half_designation(t, a, b, 750, NULL, got, sizeof(got));
    ck_assert_uint_eq(n, sizeof(want) - 1);
    ck_assert(memcmp(got, want, n) == 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_it_binds_the_counterparty_and_the_score)
{
    uuid_t t, a, b, c;
    _u(T1, t); _u(A, a); _u(B, b); _u(C, c);
    uint8_t base[HALF_DESIG_MAX], other[HALF_DESIG_MAX];
    size_t n = half_designation(t, a, b, 500, NULL, base, sizeof(base));
    size_t m = half_designation(t, a, c, 500, NULL, other, sizeof(other));
    ck_assert(n != m || memcmp(base, other, n) != 0);
    m = half_designation(t, a, b, 250, NULL, other, sizeof(other));
    ck_assert(n != m || memcmp(base, other, n) != 0);
    m = half_designation(t, a, b, 500, TX_CHANNEL_DEFAULT, other, sizeof(other));
    ck_assert(n == m && memcmp(base, other, n) == 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_halves_that_name_each_other_pair)
{
    tx_history_t h;
    ck_assert_ret_ok(tx_history_init(&h));
    uuid_t t, a, b;
    _u(T1, t); _u(A, a); _u(B, b);
    ck_assert_int_eq(tx_history_record_signed_half(&h, t, a, 900, NULL, NULL, b, "s1"),
                     TX_HALF_PENDING);
    ck_assert_int_eq(tx_history_record_signed_half(&h, t, b, 700, NULL, NULL, a, "s2"),
                     TX_HALF_READY);
    ck_assert_str_eq(tx_history_pool_half_sig(&h, t, a), "s1");
    ck_assert_str_eq(tx_history_pool_half_sig(&h, t, b), "s2");
    tx_history_free(&h);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_half_the_held_one_does_not_name_is_refused)
{
    /* A names B; C, seeing the task id on the wire, races B to it. */
    tx_history_t h;
    ck_assert_ret_ok(tx_history_init(&h));
    uuid_t t, a, b, c;
    _u(T1, t); _u(A, a); _u(B, b); _u(C, c);
    tx_history_record_signed_half(&h, t, a, 900, NULL, NULL, b, "s1");
    ck_assert_int_eq(tx_history_record_signed_half(&h, t, c, 0, NULL, NULL, a, "s3"),
                     TX_HALF_MISMATCH);
    ck_assert_int_eq(tx_history_record_signed_half(&h, t, b, 700, NULL, NULL, a, "s2"),
                     TX_HALF_READY);
    tx_history_free(&h);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_squatted_half_gives_way_to_the_half_it_names)
{
    /* C got there first naming A; A's own signed half names B, which proves
     * C's can never pair. A's takes its place and B's completes it. */
    tx_history_t h;
    ck_assert_ret_ok(tx_history_init(&h));
    uuid_t t, a, b, c;
    _u(T1, t); _u(A, a); _u(B, b); _u(C, c);
    tx_history_record_signed_half(&h, t, c, 0, NULL, NULL, a, "s3");
    ck_assert_int_eq(tx_history_record_signed_half(&h, t, a, 900, NULL, NULL, b, "s1"),
                     TX_HALF_PENDING);
    ck_assert_int_eq(tx_history_record_signed_half(&h, t, b, 700, NULL, NULL, a, "s2"),
                     TX_HALF_READY);
    ck_assert_ptr_null(tx_history_pool_half_sig(&h, t, c));
    tx_history_free(&h);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_unnamed_halves_pair_as_they_always_did)
{
    tx_history_t h;
    ck_assert_ret_ok(tx_history_init(&h));
    uuid_t t, a, b;
    _u(T1, t); _u(A, a); _u(B, b);
    tx_history_record_half(&h, t, a, 900, NULL, NULL);
    ck_assert_int_eq(tx_history_record_half(&h, t, b, 700, NULL, NULL), TX_HALF_READY);
    tx_history_free(&h);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_placed_entry_keeps_its_signatures_outside_the_hash)
{
    tx_history_t h;
    ck_assert_ret_ok(tx_history_init(&h));
    uuid_t t, a, b;
    _u(T1, t); _u(A, a); _u(B, b);
    tx_history_record_signed_half(&h, t, a, 900, NULL, NULL, b, "aa");
    tx_history_record_signed_half(&h, t, b, 700, NULL, NULL, a, "bb");
    transaction_t ready[2];
    ck_assert_int_eq(tx_history_ready_items(&h, ready, 2), 1);
    ck_assert_int_eq(tx_history_apply_placed(&h, 0, ready, 1, NULL), TX_PLACE_APPLIED);
    ck_assert_str_eq(tx_history_half_sig(&h, t, a), "aa");
    ck_assert_str_eq(tx_history_half_sig(&h, t, b), "bb");
    /* The same entry unsigned hashes the same. */
    tx_history_t plain;
    ck_assert_ret_ok(tx_history_init(&plain));
    tx_history_record_half(&plain, t, a, 900, NULL, NULL);
    tx_history_record_half(&plain, t, b, 700, NULL, NULL);
    ck_assert_int_eq(tx_history_ready_items(&plain, ready, 2), 1);
    ck_assert_int_eq(tx_history_apply_placed(&plain, 0, ready, 1, NULL),
                     TX_PLACE_APPLIED);
    ck_assert_str_eq(h.head_hash, plain.head_hash);
    /* And the catch-up wire carries them. */
    json_t *arr = NULL;
    ck_assert_ret_ok(tx_history_era_to_json(&h, 0, tx_history_len(&h), &arr));
    json_t *hs = json_object_get(json_array_get(arr, 0), "half_sigs");
    ck_assert_str_eq(json_string_value(json_object_get(hs, A)), "aa");
    ck_assert_str_eq(json_string_value(json_object_get(hs, B)), "bb");
    json_decref(arr);
    tx_history_free(&plain);
    tx_history_free(&h);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_lone_half_keeps_its_name)
{
    tx_history_t h;
    ck_assert_ret_ok(tx_history_init(&h));
    uuid_t t, a, b, got;
    _u(T1, t); _u(A, a); _u(B, b);
    tx_history_record_signed_half(&h, t, a, 900, NULL, NULL, b, "ef01");
    ck_assert(tx_history_pool_names(&h, t, a, got));
    ck_assert_int_eq(uuid_compare(got, b), 0);
    ck_assert_str_eq(tx_history_pool_half_sig(&h, t, a), "ef01");
    tx_history_free(&h);
}
END_TEST_DEFINITION()

RUN_TESTS(RepBilateral,
          test_the_bytes_are_pinned,
          test_it_binds_the_counterparty_and_the_score,
          test_halves_that_name_each_other_pair,
          test_a_half_the_held_one_does_not_name_is_refused,
          test_a_squatted_half_gives_way_to_the_half_it_names,
          test_unnamed_halves_pair_as_they_always_did,
          test_a_placed_entry_keeps_its_signatures_outside_the_hash,
          test_a_lone_half_keeps_its_name)
