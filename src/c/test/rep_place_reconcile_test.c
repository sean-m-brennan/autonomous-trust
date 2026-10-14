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

/** @file Catch-up, reconcile and warm start under ordered placement
 *  (doc/architecture/reputation.md, "Agreeing on an order").
 *
 *  A placed chain carries its placement certificates (on each placement's
 *  last entry, with the index the placement began at), so a node catching up
 *  can check every placement it is handed. Then a placement decides, not a
 *  length: nothing below our own placed end is rewritten, a certified segment
 *  past it wins whatever the lengths, two certified values at one index are
 *  equivocation, and a certified placement may carry a node across a gap.
 *  Mirrors the history half of tests/a_unit/test_placement_reconcile.py.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>
#include <stdlib.h>
#include <uuid/uuid.h>
#include <jansson.h>

#include "autonomous_trust/reputation/reputation.h"

#define SIGS "{\"voter\":\"sig\"}"
#define CERT "{\"x\":\"y\"}"

static uuid_t A, B;
static const int NO_CERTS[1] = { 0 };

static void _task(int n, uuid_t out)
{
    char s[UUID_STRING_LEN + 1];
    snprintf(s, sizeof(s), "00000000-0000-4000-8000-%012d", n);
    uuid_parse(s, out);
}

static tx_history_t *_hist(void)
{
    uuid_parse("aaaaaaaa-0000-4000-8000-000000000001", A);
    uuid_parse("bbbbbbbb-0000-4000-8000-000000000002", B);
    tx_history_t *h = NULL;
    ck_assert_ret_ok(tx_history_create(&h));
    return h;
}

/* Place the tasks ns[0..n) as one placement at the chain's next index. */
static void _place(tx_history_t *h, const int *ns, int n)
{
    tx_history_t *pool = _hist();
    for (int i = 0; i < n; i++)
    {
        uuid_t t;
        _task(ns[i], t);
        tx_history_record_half(pool, t, A, 0.6, NULL, NULL);
        tx_history_record_half(pool, t, B, 0.8, NULL, NULL);
    }
    transaction_t items[PLACE_BATCH_MAX];
    int m = tx_history_ready_items(pool, items, PLACE_BATCH_MAX);
    ck_assert_int_eq(m, n);
    ck_assert_int_eq(tx_history_apply_placed(h, h->next_index, items, m, SIGS),
                     TX_PLACE_APPLIED);
    tx_history_destroy(pool);
}

/* Write task n the legacy way, each half certified. */
static void _legacy(tx_history_t *h, int n)
{
    uuid_t t;
    _task(n, t);
    tx_history_update(h, t, A, 0.6, NULL);
    tx_history_attach_commit_cert(h, t, A, CERT);
    tx_history_update(h, t, B, 0.8, NULL);
    tx_history_attach_commit_cert(h, t, B, CERT);
}

static json_t *_seg(const tx_history_t *h, int from)
{
    json_t *arr = NULL;
    ck_assert_ret_ok(tx_history_era_to_json(h, from, tx_history_len(h), &arr));
    return arr;
}

static int _reconcile(tx_history_t *h, json_t *arr, const int *cert, int n,
                      tx_reconcile_result_t *res)
{
    ck_assert_ret_ok(tx_history_reconcile_placed(h, arr, -1, NULL, cert, n, res));
    return res->status;
}

DEFINE_TEST(test_the_last_entry_of_a_placement_carries_its_certificate)
{
    tx_history_t *h = _hist();
    _place(h, (int[]){ 1, 2 }, 2);
    _place(h, (int[]){ 3 }, 1);
    json_t *arr = _seg(h, 0);
    ck_assert(json_object_get(json_array_get(arr, 0), "place_sigs") == NULL);
    ck_assert_int_eq(json_integer_value(json_object_get(json_array_get(arr, 1),
                                                        "place_from")), 0);
    ck_assert(json_is_object(json_object_get(json_array_get(arr, 1), "place_sigs")));
    ck_assert_int_eq(json_integer_value(json_object_get(json_array_get(arr, 2),
                                                        "place_from")), 2);
    ck_assert_int_eq(tx_history_placed_end(h), 3);
    json_decref(arr);
    tx_history_destroy(h);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_it_survives_a_restart)
{
    tx_history_t *h = _hist();
    _place(h, (int[]){ 1, 2 }, 2);
    _place(h, (int[]){ 3 }, 1);
    json_t *doc = NULL;
    ck_assert_ret_ok(reputation_evidence_to_json(h, NULL, &doc));
    tx_history_t *back = _hist();
    ck_assert_ret_ok(reputation_evidence_from_json(doc, back, NULL));
    ck_assert_int_eq(tx_history_placed_end(back), 3);
    json_t *arr = _seg(back, 0);
    ck_assert_int_eq(json_integer_value(json_object_get(json_array_get(arr, 2),
                                                        "place_from")), 2);
    json_decref(arr);
    json_decref(doc);
    tx_history_destroy(back);
    tx_history_destroy(h);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_placement_begun_before_the_segment_borrows_ours)
{
    tx_history_t *theirs = _hist(), *ours = _hist(), *empty = _hist();
    _place(theirs, (int[]){ 1, 2, 3 }, 3);
    _place(ours, (int[]){ 1, 2, 3 }, 3);
    json_t *tail = _seg(theirs, 2);
    tx_place_batch_t *b = NULL;
    int nb = 0;
    ck_assert_ret_ok(tx_history_place_batches(ours, tail, &b, &nb));
    ck_assert_int_eq(nb, 1);
    ck_assert_int_eq(b[0].k, 0);
    ck_assert_int_eq(b[0].n, 3);
    ck_assert(!b[0].whole);
    free(b);
    ck_assert_ret_ok(tx_history_place_batches(empty, tail, &b, &nb));
    ck_assert_int_eq(nb, 1);
    ck_assert_int_eq(b[0].n, 0);
    free(b);
    json_decref(tail);
    tx_history_destroy(empty);
    tx_history_destroy(ours);
    tx_history_destroy(theirs);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_certified_extension_is_taken)
{
    tx_history_t *ours = _hist(), *theirs = _hist();
    _place(ours, (int[]){ 1 }, 1);
    _place(theirs, (int[]){ 1 }, 1);
    _place(theirs, (int[]){ 2, 3 }, 2);
    json_t *arr = _seg(theirs, 0);
    tx_reconcile_result_t res;
    ck_assert_int_eq(_reconcile(ours, arr, (int[]){ 0, 1, 2 }, 3, &res),
                     TX_RECONCILE_EXTENDED);
    tx_reconcile_result_free(&res);
    ck_assert_int_eq(tx_history_len(ours), 3);
    ck_assert_int_eq(tx_history_placed_end(ours), 3);
    ck_assert_str_eq(ours->head_hash, theirs->head_hash);
    json_decref(arr);
    tx_history_destroy(theirs);
    tx_history_destroy(ours);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_certified_segment_beats_a_longer_uncertified_one)
{
    tx_history_t *ours = _hist(), *theirs = _hist(), *legacy = _hist();
    _legacy(ours, 7);
    _legacy(ours, 8);
    _legacy(ours, 9);
    _legacy(legacy, 7);
    _legacy(legacy, 8);
    _legacy(legacy, 9);
    _place(theirs, (int[]){ 1 }, 1);
    json_t *arr = _seg(theirs, 0);
    tx_reconcile_result_t res;
    /* Without placement, the longer chain still wins. */
    ck_assert_ret_ok(tx_history_reconcile(legacy, arr, -1, &res));
    ck_assert_int_eq(res.status, TX_RECONCILE_KEPT);
    tx_reconcile_result_free(&res);
    ck_assert_int_eq(_reconcile(ours, arr, (int[]){ 0 }, 1, &res),
                     TX_RECONCILE_ADOPTED);
    ck_assert_int_eq(res.dropped, 3);
    /* What it dropped goes back to the pool, certificates and all. */
    ck_assert_int_eq(res.pooled, 3);
    tx_reconcile_result_free(&res);
    ck_assert_int_eq(tx_history_len(ours), 1);
    uuid_t t7;
    _task(7, t7);
    const transaction_t *back = tx_history_pooled(ours, t7);
    ck_assert(back != NULL && back->p1_set && back->p2_set);
    ck_assert(tx_history_pool_cert(ours, t7, A) != NULL);
    json_decref(arr);
    tx_history_destroy(legacy);
    tx_history_destroy(theirs);
    tx_history_destroy(ours);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_nothing_below_our_placed_end_is_rewritten)
{
    tx_history_t *ours = _hist(), *theirs = _hist();
    _place(ours, (int[]){ 1, 2 }, 2);
    for (int n = 5; n <= 8; n++)
        _legacy(theirs, n);
    json_t *arr = _seg(theirs, 0);
    tx_reconcile_result_t res;
    ck_assert_int_eq(_reconcile(ours, arr, NO_CERTS, 0, &res), TX_RECONCILE_KEPT);
    tx_reconcile_result_free(&res);
    ck_assert_int_eq(tx_history_len(ours), 2);
    json_decref(arr);
    tx_history_destroy(theirs);
    tx_history_destroy(ours);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_two_certified_values_at_one_index_are_equivocation)
{
    tx_history_t *ours = _hist(), *theirs = _hist();
    _place(ours, (int[]){ 1, 2 }, 2);
    _place(theirs, (int[]){ 3, 4 }, 2);
    _place(theirs, (int[]){ 5 }, 1);
    json_t *arr = _seg(theirs, 0);
    tx_reconcile_result_t res;
    ck_assert_int_eq(_reconcile(ours, arr, (int[]){ 0, 1, 2 }, 3, &res),
                     TX_RECONCILE_EQUIVOCATION);
    ck_assert_int_eq(res.fork, 0);
    tx_reconcile_result_free(&res);
    ck_assert_int_eq(tx_history_len(ours), 2);
    json_decref(arr);
    tx_history_destroy(theirs);
    tx_history_destroy(ours);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_uncertified_tail_is_cut_off)
{
    tx_history_t *ours = _hist(), *theirs = _hist();
    _place(ours, (int[]){ 1 }, 1);
    _place(theirs, (int[]){ 1 }, 1);
    _place(theirs, (int[]){ 2 }, 1);
    _legacy(theirs, 9);                   /* written outside any placement */
    json_t *arr = _seg(theirs, 0);
    tx_reconcile_result_t res;
    ck_assert_int_eq(_reconcile(ours, arr, (int[]){ 0, 1 }, 2, &res),
                     TX_RECONCILE_EXTENDED);
    tx_reconcile_result_free(&res);
    ck_assert_int_eq(tx_history_len(ours), 2);
    json_decref(arr);
    tx_history_destroy(theirs);
    tx_history_destroy(ours);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_certified_placement_carries_us_across_a_gap)
{
    tx_history_t *ours = _hist(), *theirs = _hist();
    _place(theirs, (int[]){ 1 }, 1);
    _place(theirs, (int[]){ 2 }, 1);
    _place(theirs, (int[]){ 3, 4 }, 2);
    _place(ours, (int[]){ 1 }, 1);
    json_t *far = _seg(theirs, 2);        /* indices 2..3: the (3, 4) placement */
    tx_reconcile_result_t res;
    ck_assert_int_eq(_reconcile(ours, far, (int[]){ 2, 3 }, 2, &res),
                     TX_RECONCILE_ADOPTED);
    tx_reconcile_result_free(&res);
    ck_assert_int_eq(tx_history_len(ours), 2);
    ck_assert_int_eq(ours->next_index, 4);
    ck_assert_str_eq(ours->head_hash, theirs->head_hash);
    uuid_t t1;
    _task(1, t1);
    ck_assert_int_eq(tx_history_record_half(ours, t1, A, 0.6, NULL, NULL),
                     TX_HALF_TOMBSTONED);
    json_decref(far);
    tx_history_destroy(theirs);
    tx_history_destroy(ours);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_gap_without_a_certified_start_is_rejected)
{
    tx_history_t *ours = _hist(), *theirs = _hist();
    _place(theirs, (int[]){ 1 }, 1);
    _place(theirs, (int[]){ 2 }, 1);
    _place(theirs, (int[]){ 3, 4 }, 2);
    _legacy(ours, 1);
    json_t *far = _seg(theirs, 3);        /* closes a placement begun at 2 */
    tx_reconcile_result_t res;
    ck_assert_int_eq(_reconcile(ours, far, NO_CERTS, 0, &res), TX_RECONCILE_REJECTED);
    tx_reconcile_result_free(&res);
    json_decref(far);
    tx_history_destroy(theirs);
    tx_history_destroy(ours);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_what_is_taken_leaves_the_pool)
{
    tx_history_t *ours = _hist(), *theirs = _hist();
    uuid_t t1;
    _task(1, t1);
    tx_history_record_half(ours, t1, A, 0.6, NULL, NULL);
    tx_history_record_half(ours, t1, B, 0.8, NULL, NULL);
    _place(theirs, (int[]){ 1 }, 1);
    json_t *arr = _seg(theirs, 0);
    tx_reconcile_result_t res;
    ck_assert_int_eq(_reconcile(ours, arr, (int[]){ 0 }, 1, &res),
                     TX_RECONCILE_EXTENDED);
    tx_reconcile_result_free(&res);
    ck_assert(tx_history_pooled(ours, t1) == NULL);
    json_decref(arr);
    tx_history_destroy(theirs);
    tx_history_destroy(ours);
}
END_TEST_DEFINITION()

RUN_TESTS(RepPlaceReconcile,
          test_the_last_entry_of_a_placement_carries_its_certificate,
          test_it_survives_a_restart,
          test_a_placement_begun_before_the_segment_borrows_ours,
          test_a_certified_extension_is_taken,
          test_a_certified_segment_beats_a_longer_uncertified_one,
          test_nothing_below_our_placed_end_is_rewritten,
          test_two_certified_values_at_one_index_are_equivocation,
          test_an_uncertified_tail_is_cut_off,
          test_a_certified_placement_carries_us_across_a_gap,
          test_a_gap_without_a_certified_start_is_rejected,
          test_what_is_taken_leaves_the_pool)
