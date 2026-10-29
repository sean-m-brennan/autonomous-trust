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

/** @file Roster entries: who the group is, recorded in the chain
 *  (doc/architecture/reputation.md, "Who is in the group").
 *
 *  A roster entry has no scorer and no score. Its op, the member an add adds
 *  and the digest of its member list are in its hash; the member list travels
 *  beside it and must reproduce the digest. Pinned against Python's bytes:
 *  tests/a_unit/test_placement_roster.py.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>
#include <stdlib.h>

#include <jansson.h>
#include <uuid/uuid.h>

#include "reputation/reputation.h"

static const char A[] = "aaaaaaaa-0000-4000-8000-000000000001";
static const char B[] = "bbbbbbbb-0000-4000-8000-000000000002";
static const char C[] = "cccccccc-0000-4000-8000-000000000003";
static const char D2[] = "c02c382b7ab59e73d577c48f3bf8b6bd8f4e010f2fd2787498004e95516fd86a";
static const char T0[] = "65c0a743-5641-5b6b-b79d-d5c8a4646039";
static const char G_HASH[] = "02a57fe42cfda395872b38d4420e7d6857dd8dccb31d39e6c4f112cd7d7ce279";
static const char D3[] = "021d352cc8ff94765e2db73afe2d7b5e6e0a6ab9800a728482a031cc266e23bd";
static const char T1[] = "f4076c8e-4a9d-50bd-9575-990b0a9ad5f1";
static const char A_HASH[] = "fd4ebd9e23c3c0299abb0b46eebaf08b2c7ab8805021d7d166cbcfdde908da90";

static json_t *_members(int n)
{
    char k1[65], k2[65], k3[65];
    memset(k1, '1', 64); k1[64] = '\0';
    memset(k2, '2', 64); k2[64] = '\0';
    memset(k3, '3', 64); k3[64] = '\0';
    json_t *m = json_pack("[[s, s], [s, s]]", B, k2, A, k1);
    if (n == 3)
        json_array_append_new(m, json_pack("[s, s]", C, k3));
    return m;
}

static void _entry(transaction_t *tx, const char *task, const char *op,
                   const char *who, const char *digest, int index,
                   const char *prev)
{
    memset(tx, 0, sizeof(*tx));
    uuid_parse(task, tx->task_uuid);
    tx->roster = true;
    strcpy(tx->roster_op, op);
    if (who != NULL)
        uuid_parse(who, tx->roster_uuid);
    strcpy(tx->roster_digest, digest);
    tx->index = index;
    strcpy(tx->prev_hash, prev);
}

DEFINE_TEST(test_the_digest_and_task_are_pinned_against_python)
{
    char d[TX_HASH_HEX_LEN + 1];
    json_t *m2 = _members(2), *m3 = _members(3);
    ck_assert_int_eq(roster_digest(m2, d, NULL), 0);
    ck_assert_str_eq(d, D2);
    ck_assert_int_eq(roster_digest(m3, d, NULL), 0);
    ck_assert_str_eq(d, D3);
    uuid_t t0, t1, c, want;
    char s[UUID_STRING_LEN + 1];
    tx_roster_task_uuid(NULL, "genesis", NULL, D2, t0);
    uuid_unparse_lower(t0, s);
    ck_assert_str_eq(s, T0);
    uuid_parse(C, c);
    tx_roster_task_uuid(t0, "add", c, D3, t1);
    uuid_unparse_lower(t1, s);
    ck_assert_str_eq(s, T1);
    uuid_parse(T1, want);
    ck_assert(uuid_compare(t1, want) == 0);
    json_decref(m2);
    json_decref(m3);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_bad_list_is_refused)
{
    char d[TX_HASH_HEX_LEN + 1], z[65];
    memset(z, 'z', 64); z[64] = '\0';
    json_t *empty = json_array();
    json_t *twice = json_pack("[[s, s], [s, s]]", A, G_HASH, A, D2);
    json_t *bad = json_pack("[[s, s]]", A, z);
    ck_assert_int_eq(roster_digest(empty, d, NULL), -1);
    ck_assert_int_eq(roster_digest(twice, d, NULL), -1);
    ck_assert_int_eq(roster_digest(bad, d, NULL), -1);
    ck_assert(!tx_roster_op_valid("remove"));
    json_decref(empty);
    json_decref(twice);
    json_decref(bad);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_entry_bytes_are_pinned_against_python)
{
    transaction_t g, a;
    _entry(&g, T0, "genesis", NULL, D2, 0, "");
    _entry(&a, T1, "add", C, D3, 1, G_HASH);
    char canon[TX_CANON_MAX], want[TX_CANON_MAX], h[TX_HASH_HEX_LEN + 1];
    ck_assert(transaction_canonical_bytes(&g, canon, sizeof(canon)) > 0);
    snprintf(want, sizeof(want), "%s|null|null|null|null|0|roster|genesis|null|%s", T0, D2);
    ck_assert_str_eq(canon, want);
    transaction_entry_hash(&g, h);
    ck_assert_str_eq(h, G_HASH);
    ck_assert(transaction_canonical_bytes(&a, canon, sizeof(canon)) > 0);
    snprintf(want, sizeof(want), "%s|null|null|null|null|1|roster|add|%s|%s", T1, C, D3);
    ck_assert_str_eq(canon, want);
    transaction_entry_hash(&a, h);
    ck_assert_str_eq(h, A_HASH);
    ck_assert(tx_is_committed(&g));
    uuid_t au;
    uuid_parse(A, au);
    ck_assert(!transaction_score_about(&g, au, NULL, NULL));
}
END_TEST_DEFINITION()

/* A restatement of the genesis declaring N_min 4 (RD_13.2 plan section 0.4):
 * the declaration follows the roster block in the bytes and the task name,
 * and nothing changes without one. Pinned against test_placement_n_min.py. */
static const char T_R4[] = "05b28db3-fb50-5ba5-8a24-a2f053a182fd";
static const char T_R0[] = "2cbb8fdf-80d6-56f4-8038-e4547d1e00ee";
static const char R4_HASH[] = "ca90ab36ec77a141a1c4b7882d760e39fe01806ee27e585eb74ee3924c04fa7e";

DEFINE_TEST(test_a_declared_n_min_is_pinned_against_python)
{
    uuid_t t0, t;
    char ts[UUID_STRING_LEN + 1];
    uuid_parse(T0, t0);
    tx_roster_task_uuid_n(t0, "restate", NULL, D2, 4, t);
    uuid_unparse_lower(t, ts);
    ck_assert_str_eq(ts, T_R4);
    tx_roster_task_uuid_n(t0, "restate", NULL, D2, 0, t);
    uuid_unparse_lower(t, ts);
    ck_assert_str_eq(ts, T_R0);
    tx_roster_task_uuid(t0, "restate", NULL, D2, t);
    uuid_unparse_lower(t, ts);
    ck_assert_str_eq(ts, T_R0);

    transaction_t r;
    _entry(&r, T_R4, "restate", NULL, D2, 1, G_HASH);
    r.roster_n_min = 4;
    char canon[TX_CANON_MAX], want[TX_CANON_MAX], h[TX_HASH_HEX_LEN + 1];
    ck_assert(transaction_canonical_bytes(&r, canon, sizeof(canon)) > 0);
    snprintf(want, sizeof(want), "%s|null|null|null|null|1|roster|restate|null|%s|4",
             T_R4, D2);
    ck_assert_str_eq(canon, want);
    transaction_entry_hash(&r, h);
    ck_assert_str_eq(h, R4_HASH);

    _entry(&r, T_R0, "restate", NULL, D2, 1, G_HASH);
    ck_assert(transaction_canonical_bytes(&r, canon, sizeof(canon)) > 0);
    snprintf(want, sizeof(want), "%s|null|null|null|null|1|roster|restate|null|%s",
             T_R0, D2);
    ck_assert_str_eq(canon, want);

    ck_assert_int_eq(tx_byzantine_f(0), 0);
    ck_assert_int_eq(tx_byzantine_f(3), 0);
    ck_assert_int_eq(tx_byzantine_f(4), 1);
    ck_assert_int_eq(tx_byzantine_f(7), 2);
    ck_assert_int_eq(tx_byzantine_f(10), 3);
}
END_TEST_DEFINITION()

/* The two entries on the catch-up wire, members beside them. */
static json_t *_wire(void)
{
    json_t *m2 = _members(2), *m3 = _members(3);
    json_t *arr = json_pack("[{s:s, s:s, s:b, s:s, s:b, s:i, s:s, s:s, s:n, s:s, s:o},"
                            " {s:s, s:s, s:b, s:s, s:b, s:i, s:s, s:s, s:s, s:s, s:o}]",
        "task", T0, "p1", "00000000-0000-0000-0000-000000000000", "p1_set", 0,
        "p2", "00000000-0000-0000-0000-000000000000", "p2_set", 0, "index", 0,
        "prev_hash", "", "roster_op", "genesis", "roster_uuid", "roster_digest", D2,
        "roster_members", m2,
        "task", T1, "p1", "00000000-0000-0000-0000-000000000000", "p1_set", 0,
        "p2", "00000000-0000-0000-0000-000000000000", "p2_set", 0, "index", 1,
        "prev_hash", G_HASH, "roster_op", "add", "roster_uuid", C, "roster_digest", D3,
        "roster_members", m3);
    ck_assert_ptr_nonnull(arr);
    return arr;
}

DEFINE_TEST(test_the_catchup_wire_and_evidence_round_trip)
{
    tx_history_t h, e;
    ck_assert_ret_ok(tx_history_init(&h));
    ck_assert_ret_ok(tx_history_init(&e));
    json_t *arr = _wire();
    tx_reconcile_result_t res = { TX_RECONCILE_NONE, -1, 0, 0, NULL };
    ck_assert_ret_ok(tx_history_reconcile(&h, arr, -1, &res));
    ck_assert_int_eq(res.status, TX_RECONCILE_EXTENDED);
    tx_reconcile_result_free(&res);
    json_decref(arr);
    ck_assert_int_eq(h.next_index, 2);
    ck_assert_str_eq(h.head_hash, A_HASH);
    ck_assert_ptr_nonnull(tx_history_roster_members(&h, D3));

    json_t *back = NULL;
    ck_assert_ret_ok(tx_history_era_to_json(&h, 0, tx_history_len(&h), &back));
    ck_assert_int_eq((int)json_array_size(back), 2);
    ck_assert_str_eq(json_string_value(json_object_get(json_array_get(back, 1),
                                                       "roster_op")), "add");
    json_decref(back);

    json_t *doc = NULL;
    ck_assert_ret_ok(reputation_evidence_to_json(&h, NULL, &doc));
    ck_assert(json_is_null(json_object_get(json_array_get(json_object_get(doc, "chain"), 0),
                                           "p1_id")));
    ck_assert_ret_ok(reputation_evidence_from_json(doc, &e, NULL));
    ck_assert_str_eq(e.head_hash, A_HASH);
    ck_assert_ptr_nonnull(tx_history_roster_members(&e, D2));
    /* A list that does not reproduce its digest refuses the document. */
    json_t *m2 = _members(2);
    json_object_set_new(json_array_get(json_object_get(doc, "chain"), 1),
                        "roster_members", m2);
    tx_history_t bad;
    ck_assert_ret_ok(tx_history_init(&bad));
    ck_assert(reputation_evidence_from_json(doc, &bad, NULL) != 0);
    json_decref(doc);
    tx_history_free(&bad);
    tx_history_free(&h);
    tx_history_free(&e);
}
END_TEST_DEFINITION()

/* The declaration travels on the catch-up wire and in evidence, and the
 * entry it is on keeps its hash (R4_HASH) through both. */
DEFINE_TEST(test_a_declared_n_min_round_trips)
{
    json_t *m2 = _members(2), *m2b = _members(2);
    json_t *arr = json_pack("[{s:s, s:s, s:b, s:s, s:b, s:i, s:s, s:s, s:n, s:s, s:o},"
                            " {s:s, s:s, s:b, s:s, s:b, s:i, s:s, s:s, s:n, s:s, s:o, s:i}]",
        "task", T0, "p1", "00000000-0000-0000-0000-000000000000", "p1_set", 0,
        "p2", "00000000-0000-0000-0000-000000000000", "p2_set", 0, "index", 0,
        "prev_hash", "", "roster_op", "genesis", "roster_uuid", "roster_digest", D2,
        "roster_members", m2,
        "task", T_R4, "p1", "00000000-0000-0000-0000-000000000000", "p1_set", 0,
        "p2", "00000000-0000-0000-0000-000000000000", "p2_set", 0, "index", 1,
        "prev_hash", G_HASH, "roster_op", "restate", "roster_uuid", "roster_digest", D2,
        "roster_members", m2b, "roster_n_min", 4);
    ck_assert_ptr_nonnull(arr);
    tx_history_t h, e;
    ck_assert_ret_ok(tx_history_init(&h));
    ck_assert_ret_ok(tx_history_init(&e));
    tx_reconcile_result_t res = { TX_RECONCILE_NONE, -1, 0, 0, NULL };
    ck_assert_ret_ok(tx_history_reconcile(&h, arr, -1, &res));
    ck_assert_int_eq(res.status, TX_RECONCILE_EXTENDED);
    tx_reconcile_result_free(&res);
    json_decref(arr);
    ck_assert_str_eq(h.head_hash, R4_HASH);
    transaction_t r;
    ck_assert_int_eq(tx_history_roster_at(&h, h.next_index, &r), 0);
    ck_assert_int_eq(r.roster_n_min, 4);

    json_t *back = NULL;
    ck_assert_ret_ok(tx_history_era_to_json(&h, 0, tx_history_len(&h), &back));
    ck_assert_int_eq((int)json_integer_value(json_object_get(json_array_get(back, 1),
                                                             "roster_n_min")), 4);
    ck_assert_ptr_null(json_object_get(json_array_get(back, 0), "roster_n_min"));
    json_decref(back);

    json_t *doc = NULL;
    ck_assert_ret_ok(reputation_evidence_to_json(&h, NULL, &doc));
    ck_assert_ret_ok(reputation_evidence_from_json(doc, &e, NULL));
    ck_assert_str_eq(e.head_hash, R4_HASH);
    json_decref(doc);
    tx_history_free(&h);
    tx_history_free(&e);
}
END_TEST_DEFINITION()

/* genesis at 0, an ordinary task at 1, the add at 2, as decided placements. */
static void _placed(tx_history_t *h)
{
    ck_assert_ret_ok(tx_history_init(h));
    transaction_t g, a, t;
    _entry(&g, T0, "genesis", NULL, D2, -1, "");
    _entry(&a, T1, "add", C, D3, -1, "");
    memset(&t, 0, sizeof(t));
    t.index = -1;
    uuid_generate(t.task_uuid);
    uuid_parse(A, t.p1_uuid);
    uuid_parse(B, t.p2_uuid);
    t.p1_set = t.p2_set = true;
    t.p1_score_milli = 500;
    t.p2_score_milli = 600;
    json_t *m2 = _members(2), *m3 = _members(3);
    ck_assert_ret_ok(tx_history_roster_put(h, m2, NULL));
    ck_assert_ret_ok(tx_history_roster_put(h, m3, NULL));
    json_decref(m2);
    json_decref(m3);
    ck_assert_int_eq(tx_history_apply_placed(h, 0, &g, 1, NULL), TX_PLACE_APPLIED);
    ck_assert_int_eq(tx_history_apply_placed(h, 1, &t, 1, NULL), TX_PLACE_APPLIED);
    ck_assert_int_eq(tx_history_apply_placed(h, 2, &a, 1, NULL), TX_PLACE_APPLIED);
}

DEFINE_TEST(test_the_roster_in_force_is_the_last_below)
{
    tx_history_t h;
    _placed(&h);
    transaction_t r;
    char s[UUID_STRING_LEN + 1];
    ck_assert_int_eq(tx_history_roster_at(&h, 0, &r), -1);
    ck_assert_int_eq(tx_history_roster_at(&h, 2, &r), 0);
    uuid_unparse_lower(r.task_uuid, s);
    ck_assert_str_eq(s, T0);
    ck_assert_int_eq(tx_history_roster_at(&h, 3, &r), 0);
    uuid_unparse_lower(r.task_uuid, s);
    ck_assert_str_eq(s, T1);
    ck_assert_ptr_nonnull(tx_history_roster_members(&h, r.roster_digest));

    /* It travels with a reconciled chain, member lists included. */
    json_t *arr = NULL;
    ck_assert_ret_ok(tx_history_era_to_json(&h, 0, tx_history_len(&h), &arr));
    tx_history_t o;
    ck_assert_ret_ok(tx_history_init(&o));
    tx_reconcile_result_t res = { TX_RECONCILE_NONE, -1, 0, 0, NULL };
    ck_assert_ret_ok(tx_history_reconcile(&o, arr, -1, &res));
    tx_reconcile_result_free(&res);
    json_decref(arr);
    ck_assert_int_eq(tx_history_roster_at(&o, o.next_index, &r), 0);
    ck_assert_str_eq(r.roster_digest, D3);
    ck_assert_ptr_nonnull(tx_history_roster_members(&o, D3));
    ck_assert_str_eq(o.head_hash, h.head_hash);
    tx_history_free(&o);
    tx_history_free(&h);
}
END_TEST_DEFINITION()

RUN_TESTS(RepPlaceRoster,
          test_the_roster_in_force_is_the_last_below,
          test_the_digest_and_task_are_pinned_against_python,
          test_a_bad_list_is_refused,
          test_the_entry_bytes_are_pinned_against_python,
          test_the_catchup_wire_and_evidence_round_trip,
          test_a_declared_n_min_is_pinned_against_python,
          test_a_declared_n_min_round_trips)
