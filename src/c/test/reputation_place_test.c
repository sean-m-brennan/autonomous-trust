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

/** @file The placement pool and the in-order write of decided placements
 *  (doc/architecture/reputation.md, "Agreeing on an order").
 *
 *  Committed halves wait in a pool, by task, and reach the chain only through
 *  a decided placement, which writes its entries at the next index exactly as
 *  given. So every node that applies the same placements in the same order
 *  holds the same chain, whatever order the halves reached it in. Mirrors
 *  tests/a_unit/test_placement_pool.py, and pins the placement bytes to the
 *  Python twin's.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>
#include <stdlib.h>
#include <uuid/uuid.h>

#include "autonomous_trust/reputation/reputation.h"

static uuid_t A, B, C;

static void _uuids(void)
{
    uuid_parse("aaaaaaaa-0000-4000-8000-000000000001", A);
    uuid_parse("bbbbbbbb-0000-4000-8000-000000000002", B);
    uuid_parse("cccccccc-0000-4000-8000-000000000003", C);
}

static void _task(int n, uuid_t out)
{
    char s[UUID_STRING_LEN + 1];
    snprintf(s, sizeof(s), "00000000-0000-4000-8000-%012d", n);
    uuid_parse(s, out);
}

static tx_history_t *_hist(void)
{
    _uuids();
    tx_history_t *h = NULL;
    ck_assert_ret_ok(tx_history_create(&h));
    return h;
}

/* Both halves of task n, B's first. */
static void _ready(tx_history_t *h, int n)
{
    uuid_t t;
    _task(n, t);
    ck_assert_int_eq(tx_history_record_half(h, t, B, 0.8, NULL, NULL),
                     TX_HALF_PENDING);
    ck_assert_int_eq(tx_history_record_half(h, t, A, 0.6, NULL, NULL),
                     TX_HALF_READY);
}

DEFINE_TEST(test_halves_wait_in_the_pool)
{
    tx_history_t *h = _hist();
    uuid_t t;
    _task(1, t);
    ck_assert_int_eq(tx_history_record_half(h, t, A, 0.6, NULL, NULL), TX_HALF_PENDING);
    ck_assert_int_eq(tx_history_record_half(h, t, A, 0.6, NULL, NULL), TX_HALF_DUP);
    ck_assert_int_eq(tx_history_record_half(h, t, B, 0.8, NULL, NULL), TX_HALF_READY);
    ck_assert_int_eq(tx_history_record_half(h, t, C, 0.5, NULL, NULL), TX_HALF_DUP);
    ck_assert_int_eq(tx_history_len(h), 0);
    ck_assert(tx_history_pooled(h, t) != NULL);
    ck_assert_int_eq(tx_history_record_half(h, t, C, 0.5, "no-such-channel", NULL), -1);
    tx_history_destroy(h);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_placed_and_evicted_tasks_are_not_pooled_again)
{
    tx_history_t *h = _hist();
    transaction_t items[PLACE_BATCH_MAX];
    _ready(h, 1);
    ck_assert_int_eq(tx_history_ready_items(h, items, PLACE_BATCH_MAX), 1);
    ck_assert_int_eq(tx_history_apply_placed(h, 0, items, 1, NULL), TX_PLACE_APPLIED);
    uuid_t t;
    _task(1, t);
    ck_assert_int_eq(tx_history_record_half(h, t, C, 0.5, NULL, NULL), TX_HALF_PLACED);
    /* Fill the window past it, so it is evicted and tombstoned. */
    for (int n = 2; n <= MAX_CHAIN_LEN + 1; n++)
    {
        _ready(h, n);
        ck_assert_int_eq(tx_history_ready_items(h, items, 1), 1);
        ck_assert_int_eq(tx_history_apply_placed(h, n - 1, items, 1, NULL),
                         TX_PLACE_APPLIED);
    }
    ck_assert_int_eq(tx_history_record_half(h, t, C, 0.5, NULL, NULL), TX_HALF_TOMBSTONED);
    tx_history_destroy(h);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_ready_items_are_by_task_with_halves_by_scorer)
{
    tx_history_t *h = _hist();
    _ready(h, 3);
    uuid_t t2;
    _task(2, t2);
    tx_history_record_half(h, t2, A, 0.6, NULL, NULL);   /* pending */
    _ready(h, 1);
    transaction_t items[PLACE_BATCH_MAX];
    ck_assert_int_eq(tx_history_ready_items(h, items, PLACE_BATCH_MAX), 2);
    uuid_t t1, t3;
    _task(1, t1);
    _task(3, t3);
    ck_assert(uuid_compare(items[0].task_uuid, t1) == 0);
    ck_assert(uuid_compare(items[1].task_uuid, t3) == 0);
    /* B's half arrived first; A sorts first. */
    ck_assert(uuid_compare(items[0].p1_uuid, A) == 0);
    ck_assert_double_eq_tol(items[0].p1_score, 0.6, 1e-12);
    ck_assert_int_eq(tx_history_ready_items(h, items, 1), 1);
    tx_history_destroy(h);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_placements_apply_in_order)
{
    tx_history_t *h = _hist();
    _ready(h, 1);
    _ready(h, 2);
    transaction_t items[PLACE_BATCH_MAX];
    ck_assert_int_eq(tx_history_ready_items(h, items, PLACE_BATCH_MAX), 2);
    ck_assert_int_eq(tx_history_apply_placed(h, 1, &items[1], 1, NULL), TX_PLACE_BUFFERED);
    ck_assert_int_eq(tx_history_len(h), 0);
    ck_assert_int_eq(tx_history_apply_placed(h, 0, &items[0], 1, "{\"v\":\"s\"}"),
                     TX_PLACE_APPLIED);
    ck_assert_int_eq(tx_history_len(h), 2);
    ck_assert_int_eq(h->chain[0].index, 0);
    ck_assert_int_eq(h->chain[1].index, 1);
    char link[TX_HASH_HEX_LEN + 1];
    transaction_entry_hash(&h->chain[0], link);
    ck_assert_str_eq(h->chain[1].prev_hash, link);
    ck_assert_int_eq(tx_history_ready_items(h, items, PLACE_BATCH_MAX), 0);
    ck_assert_int_eq(tx_history_apply_placed(h, 0, &items[0], 1, NULL), TX_PLACE_OLD);
    ck_assert_int_eq(tx_history_apply_placed(h, 2, items, 0, NULL), TX_PLACE_EMPTY);
    /* The certificate sits on its placement's last entry. */
    uuid_t t1;
    _task(1, t1);
    ck_assert(tx_history_place_cert(h, t1) != NULL);
    ck_assert_int_eq(tx_history_placed_end(h), 1);
    tx_history_destroy(h);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_pooled_certificates_follow_the_entry)
{
    tx_history_t *h = _hist();
    uuid_t t;
    _task(1, t);
    tx_history_record_half(h, t, A, 0.6, NULL, "{\"v\":\"a\"}");
    tx_history_record_half(h, t, B, 0.8, NULL, "{\"v\":\"b\"}");
    ck_assert(tx_history_commit_cert(h, t, A) == NULL);
    transaction_t items[PLACE_BATCH_MAX];
    ck_assert_int_eq(tx_history_ready_items(h, items, PLACE_BATCH_MAX), 1);
    tx_history_apply_placed(h, 0, items, 1, NULL);
    ck_assert_str_eq(tx_history_commit_cert(h, t, A), "{\"v\":\"a\"}");
    ck_assert_str_eq(tx_history_commit_cert(h, t, B), "{\"v\":\"b\"}");
    tx_history_destroy(h);
}
END_TEST_DEFINITION()

/* The same placement, built from halves that arrived in opposite orders, on
 * two nodes, gives the same chain. */
DEFINE_TEST(test_two_nodes_hold_the_same_chain)
{
    tx_history_t *one = _hist();
    tx_history_t *two = _hist();
    uuid_t t;
    for (int n = 1; n <= 3; n++)
    {
        _task(n, t);
        tx_history_record_half(one, t, A, 0.6, NULL, NULL);
        tx_history_record_half(one, t, B, 0.8, NULL, NULL);
    }
    for (int n = 3; n >= 1; n--)
        _ready(two, n);
    transaction_t items[PLACE_BATCH_MAX];
    int m = tx_history_ready_items(one, items, PLACE_BATCH_MAX);
    ck_assert_int_eq(m, 3);
    tx_history_apply_placed(one, 0, items, m, NULL);
    tx_history_apply_placed(two, 0, items, m, NULL);
    ck_assert_str_eq(one->head_hash, two->head_hash);
    tx_history_destroy(one);
    tx_history_destroy(two);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_attestation_is_pooled_once_and_placed)
{
    tx_history_t *h = _hist();
    transaction_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.attested = true;
    uuid_copy(tx.p1_uuid, A);
    tx.p1_set = true;
    tx.p1_score = 0.3;
    snprintf(tx.p1_channel, sizeof(tx.p1_channel), "probe");
    uuid_copy(tx.subject_uuid, B);
    memset(tx.evidence_digest, 'a', TX_ATTEST_DIGEST_HEX_LEN);
    tx_attest_task_uuid(A, B, tx.evidence_digest, tx.task_uuid);
    tx.index = -1;
    ck_assert_ret_ok(tx_history_pool_attested(h, &tx, "{\"v\":\"s\"}"));
    ck_assert(tx_history_pool_attested(h, &tx, NULL) != 0);
    transaction_t items[PLACE_BATCH_MAX];
    ck_assert_int_eq(tx_history_ready_items(h, items, PLACE_BATCH_MAX), 1);
    ck_assert_int_eq(tx_history_apply_placed(h, 0, items, 1, NULL), TX_PLACE_APPLIED);
    ck_assert_str_eq(tx_history_attest_cert(h, tx.task_uuid), "{\"v\":\"s\"}");
    tx.subject_uuid[0] ^= 1;   /* the task id no longer derives from it */
    ck_assert(tx_history_pool_attested(h, &tx, NULL) != 0);
    tx_history_destroy(h);
}
END_TEST_DEFINITION()

/* Byte-for-byte with the Python twin (tests/a_unit/test_placement_pool.py and
 * the place-value-canonical-bytes scenario). */
DEFINE_TEST(test_placement_bytes_match_python)
{
    tx_history_t *h = _hist();
    uuid_t t1, t2;
    _task(1, t1);
    _task(2, t2);
    tx_history_record_half(h, t2, C, 0.5, "probe", NULL);
    tx_history_record_half(h, t2, A, 0.25, NULL, NULL);
    tx_history_record_half(h, t1, B, 0.8, NULL, NULL);
    tx_history_record_half(h, t1, A, 0.6, NULL, NULL);
    transaction_t items[PLACE_BATCH_MAX];
    ck_assert_int_eq(tx_history_ready_items(h, items, PLACE_BATCH_MAX), 2);

    uint8_t raw[PLACE_VALUE_MAX];
    size_t len = place_value_bytes(items, 2, 3, raw, sizeof(raw));
    static const char want_tail[] =
        "00000000-0000-4000-8000-000000000001|aaaaaaaa-0000-4000-8000-000000000001"
        "|0.59999999999999998|bbbbbbbb-0000-4000-8000-000000000002"
        "|0.80000000000000004|3\n"
        "00000000-0000-4000-8000-000000000002|aaaaaaaa-0000-4000-8000-000000000001"
        "|0.25|cccccccc-0000-4000-8000-000000000003|0.5|4|task_outcome|probe";
    ck_assert_int_eq((int)len, (int)(sizeof("AT-PLACE-VALUE") + strlen(want_tail)));
    ck_assert(memcmp(raw, "AT-PLACE-VALUE\0", sizeof("AT-PLACE-VALUE")) == 0);
    ck_assert(memcmp(raw + sizeof("AT-PLACE-VALUE"), want_tail, strlen(want_tail)) == 0);

    char digest[TX_HASH_HEX_LEN + 1];
    place_value_digest(items, 2, 3, digest);
    ck_assert_str_eq(digest,
        "7c61046d768b39b2f1c38ecf1ca40b91114ee713c0469130ba0a174a7a90a1d4");

    char prev[TX_HASH_HEX_LEN + 1];
    memset(prev, 'f', TX_HASH_HEX_LEN);
    prev[TX_HASH_HEX_LEN] = '\0';
    uint8_t desig[PLACE_DESIG_MAX];
    size_t dlen = place_designation(3, prev, digest, desig, sizeof(desig));
    ck_assert_int_eq((int)dlen, (int)(sizeof("AT-PLACE") + 2 + 2 * TX_HASH_HEX_LEN + 1));
    ck_assert(memcmp(desig, "AT-PLACE\0" "3|", sizeof("AT-PLACE") + 2) == 0);

    ck_assert_int_eq(tx_history_apply_placed(h, 0, items, 2, "{\"v\":\"s\"}"),
                     TX_PLACE_APPLIED);
    ck_assert_str_eq(h->head_hash,
        "19ba4e2ca83541b1c851e1c42b0c56c50aec51becf2422722558e55a10028377");
    ck_assert_int_eq(tx_history_placed_end(h), 2);
    tx_history_destroy(h);
}
END_TEST_DEFINITION()

RUN_TESTS(ReputationPlace,
          test_halves_wait_in_the_pool,
          test_placed_and_evicted_tasks_are_not_pooled_again,
          test_ready_items_are_by_task_with_halves_by_scorer,
          test_placements_apply_in_order,
          test_pooled_certificates_follow_the_entry,
          test_two_nodes_hold_the_same_chain,
          test_an_attestation_is_pooled_once_and_placed,
          test_placement_bytes_match_python)
