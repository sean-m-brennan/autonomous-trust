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

#include <string.h>
#include <stdlib.h>
#include <uuid/uuid.h>

#include "autonomous_trust/reputation/reputation.h"
#include "autonomous_trust/structures/map.h"
#include "autonomous_trust/structures/data.h"

/* ---- LONGEST VERIFIED CHAIN (ISSUES.md §2.15) ----
 *
 * Tasks are named by letter and share uuids and peers across histories, so
 * two histories built from the same prefix hold hash-identical entries up to
 * the point where their letters differ: that is where they fork. */
static uuid_t g_tasks[26];
static uuid_t g_fp1, g_fp2;

static void _fork_setup(void)
{
    for (int i = 0; i < 26; i++)
        uuid_generate(g_tasks[i]);
    uuid_generate(g_fp1);
    uuid_generate(g_fp2);
}

static void _fork_chain(tx_history_t *h, const char *letters)
{
    ck_assert_ret_ok(tx_history_init(h));
    for (const char *c = letters; *c; c++)
    {
        int t = *c - 'a';
        ck_assert_ret_ok(tx_history_update(h, g_tasks[t], g_fp1, 0.3 + 0.02 * t, NULL));
        ck_assert_ret_ok(tx_history_update(h, g_tasks[t], g_fp2, 0.9 - 0.02 * t, NULL));
    }
}

static tx_reconcile_result_t _reconcile_from(tx_history_t *dst, const tx_history_t *src,
                                             int final_end)
{
    json_t *wire = NULL;
    ck_assert_ret_ok(tx_history_era_to_json(src, 0, tx_history_len(src), &wire));
    tx_reconcile_result_t res;
    ck_assert_ret_ok(tx_history_reconcile(dst, wire, final_end, &res));
    json_decref(wire);
    return res;
}

static bool _same_root(const tx_history_t *a, const tx_history_t *b)
{
    char ra[TX_HASH_HEX_LEN + 1], rb[TX_HASH_HEX_LEN + 1];
    transaction_window_root(a, ra);
    transaction_window_root(b, rb);
    return strcmp(ra, rb) == 0;
}

DEFINE_TEST(test_tx_fork_adopts_the_longer_chain)
{
    /* Moderation cohort run 12: chains of 9/10/11 with no shared prefix, so
     * Paxos, which needs equal lengths, stalled for good. */
    _fork_setup();
    tx_history_t ours, theirs;
    _fork_chain(&ours, "abx");
    _fork_chain(&theirs, "abcd");

    tx_reconcile_result_t res = _reconcile_from(&ours, &theirs, -1);
    ck_assert_int_eq(res.status, TX_RECONCILE_ADOPTED);
    ck_assert_int_eq(res.fork, 2);
    ck_assert_int_eq(res.dropped, 1);
    ck_assert_int_eq(res.added, 2);
    ck_assert_int_eq(tx_history_len(&ours), 4);
    ck_assert_int_eq(ours.next_index, 4);
    ck_assert(tx_history_verify_links(&ours));
    ck_assert(_same_root(&ours, &theirs));   /* verbatim: byte-identical */

    /* The maps follow: x is gone, c and d are found by task and by peer. */
    transaction_t out;
    ck_assert(tx_history_by_task(&ours, g_tasks['x' - 'a'], &out) != 0);
    ck_assert_ret_ok(tx_history_by_task(&ours, g_tasks['d' - 'a'], &out));
    ck_assert_int_eq(out.index, 3);
    transaction_t by_peer[8];
    int n = 0;
    ck_assert_ret_ok(tx_history_by_peer(&ours, g_fp2, by_peer, &n, 8));
    ck_assert_int_eq(n, 4);

    /* Agreeing now, the same report again changes nothing. */
    res = _reconcile_from(&ours, &theirs, -1);
    ck_assert_int_eq(res.status, TX_RECONCILE_NONE);

    tx_history_free(&ours);
    tx_history_free(&theirs);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tx_fork_keeps_our_chain_when_the_peer_is_shorter)
{
    _fork_setup();
    tx_history_t ours, theirs;
    _fork_chain(&ours, "abxy");
    _fork_chain(&theirs, "abc");
    char before[TX_HASH_HEX_LEN + 1], after[TX_HASH_HEX_LEN + 1];
    transaction_window_root(&ours, before);

    tx_reconcile_result_t res = _reconcile_from(&ours, &theirs, -1);
    ck_assert_int_eq(res.status, TX_RECONCILE_KEPT);
    ck_assert_int_eq(res.fork, 2);
    ck_assert_int_eq(tx_history_len(&ours), 4);
    transaction_window_root(&ours, after);
    ck_assert_str_eq(before, after);

    tx_history_free(&ours);
    tx_history_free(&theirs);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tx_fork_tiebreak_is_symmetric)
{
    /* Equal tips: the LOWER head hash wins, whichever side reconciles. If
     * both sides adopted (or both kept) they would flap or stay forked. */
    _fork_setup();
    tx_history_t a, b;
    _fork_chain(&a, "abx");
    _fork_chain(&b, "abc");
    bool a_lower = strcmp(a.head_hash, b.head_hash) < 0;

    tx_history_t a2, b2;   /* independent copies, so each direction sees the original */
    _fork_chain(&a2, "abx");
    _fork_chain(&b2, "abc");
    tx_reconcile_result_t ra = _reconcile_from(&a2, &b, -1);   /* a hears b */
    tx_reconcile_result_t rb = _reconcile_from(&b2, &a, -1);   /* b hears a */
    ck_assert_int_eq(ra.status, a_lower ? TX_RECONCILE_KEPT : TX_RECONCILE_ADOPTED);
    ck_assert_int_eq(rb.status, a_lower ? TX_RECONCILE_ADOPTED : TX_RECONCILE_KEPT);
    ck_assert(_same_root(&a2, &b2));   /* converged on one chain */

    tx_history_free(&a);
    tx_history_free(&b);
    tx_history_free(&a2);
    tx_history_free(&b2);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tx_fork_refused_inside_the_finalized_checkpoint)
{
    _fork_setup();
    tx_history_t ours, theirs;
    _fork_chain(&ours, "abx");
    _fork_chain(&theirs, "abcd");
    char before[TX_HASH_HEX_LEN + 1], after[TX_HASH_HEX_LEN + 1];
    transaction_window_root(&ours, before);

    /* Checkpoint covers 0..2, the fork is at 2: refused. */
    tx_reconcile_result_t res = _reconcile_from(&ours, &theirs, 3);
    ck_assert_int_eq(res.status, TX_RECONCILE_REFUSED_FINAL);
    ck_assert_int_eq(res.fork, 2);
    transaction_window_root(&ours, after);
    ck_assert_str_eq(before, after);

    /* Checkpoint covers 0..1 only: the fork is past it, so adopt. */
    res = _reconcile_from(&ours, &theirs, 2);
    ck_assert_int_eq(res.status, TX_RECONCILE_ADOPTED);
    ck_assert(_same_root(&ours, &theirs));

    tx_history_free(&ours);
    tx_history_free(&theirs);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tx_fork_adoption_keeps_pending_work)
{
    /* Adoption drops COMMITTED entries only. A half we hold pending for a task
     * the peer lacks survives and commits on top of the adopted chain; a half
     * we hold for a task the peer committed is completed in place, once. */
    _fork_setup();
    tx_history_t ours, theirs;
    _fork_chain(&ours, "abx");
    _fork_chain(&theirs, "abcd");
    uuid_t *z = &g_tasks['z' - 'a'], *d = &g_tasks['d' - 'a'];
    ck_assert_ret_ok(tx_history_update(&ours, *z, g_fp1, 0.4, NULL));
    ck_assert_ret_ok(tx_history_update(&ours, *d, g_fp1, 0.3 + 0.02 * 3, NULL));

    tx_reconcile_result_t res = _reconcile_from(&ours, &theirs, -1);
    ck_assert_int_eq(res.status, TX_RECONCILE_ADOPTED);
    ck_assert_int_eq(tx_history_len(&ours), 4);
    ck_assert_int_eq(ours.chain_len, 5);     /* four committed, z pending, d once */
    ck_assert(_same_root(&ours, &theirs));

    ck_assert_ret_ok(tx_history_update(&ours, *z, g_fp2, 0.6, NULL));
    ck_assert_int_eq(tx_history_len(&ours), 5);
    transaction_t out;
    ck_assert_ret_ok(tx_history_by_task(&ours, *z, &out));
    ck_assert_int_eq(out.index, 4);
    ck_assert(tx_history_verify_links(&ours));

    tx_history_free(&ours);
    tx_history_free(&theirs);
}
END_TEST_DEFINITION()


DEFINE_TEST(test_tx_fork_the_quorum_chain_wins_an_equal_length_tiebreak)
{
    /* Moderation cohort mod-2538837: carol's order fork at equal length never
     * reconciled, and on a tie the lower head hash wins, which can be the
     * side the quorum outvoted. Give the node that WOULD win the tiebreak an
     * attested window its peer's chain reproduces: it must adopt. */
    _fork_setup();
    tx_history_t a, b;
    _fork_chain(&a, "abx");
    _fork_chain(&b, "abc");
    bool a_lower = strcmp(a.head_hash, b.head_hash) < 0;
    tx_history_t *keeper = a_lower ? &a : &b;   /* wins a plain tiebreak */
    tx_history_t *other  = a_lower ? &b : &a;

    tx_attested_t att;
    transaction_window_root(other, att.root);
    att.first_index = 0;
    att.count = 3;

    json_t *wire = NULL;
    ck_assert_ret_ok(tx_history_era_to_json(other, 0, tx_history_len(other), &wire));
    tx_reconcile_result_t res;
    /* Control: without the attestation the keeper keeps. */
    tx_history_t probe;
    _fork_chain(&probe, a_lower ? "abx" : "abc");
    ck_assert_ret_ok(tx_history_reconcile(&probe, wire, -1, &res));
    ck_assert_int_eq(res.status, TX_RECONCILE_KEPT);
    tx_history_free(&probe);

    ck_assert_ret_ok(tx_history_reconcile_attested(keeper, wire, -1, &att, &res));
    ck_assert_int_eq(res.status, TX_RECONCILE_ADOPTED);
    ck_assert_int_eq(res.fork, 2);
    ck_assert(_same_root(keeper, other));

    /* An attestation the segment does NOT reproduce changes nothing. */
    tx_history_t c2;
    _fork_chain(&c2, a_lower ? "abx" : "abc");
    memset(att.root, '0', TX_HASH_HEX_LEN);
    att.root[TX_HASH_HEX_LEN] = '\0';
    ck_assert_ret_ok(tx_history_reconcile_attested(&c2, wire, -1, &att, &res));
    ck_assert_int_eq(res.status, TX_RECONCILE_KEPT);

    json_decref(wire);
    tx_history_free(&c2);
    tx_history_free(&a);
    tx_history_free(&b);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tx_fork_hands_back_what_it_dropped)
{
    /* Agora Phase 4 DDIL: the caller re-proposes its own half of each dropped
     * entry, so the result must carry them, whole and in chain order, and own
     * nothing when nothing was dropped. */
    _fork_setup();
    tx_history_t ours, theirs;
    _fork_chain(&ours, "abxy");
    _fork_chain(&theirs, "abcde");

    tx_reconcile_result_t res = _reconcile_from(&ours, &theirs, -1);
    ck_assert_int_eq(res.status, TX_RECONCILE_ADOPTED);
    ck_assert_int_eq(res.dropped, 2);
    ck_assert(res.dropped_entries != NULL);
    ck_assert(uuid_compare(res.dropped_entries[0].task_uuid, g_tasks['x' - 'a']) == 0);
    ck_assert(uuid_compare(res.dropped_entries[1].task_uuid, g_tasks['y' - 'a']) == 0);
    ck_assert(res.dropped_entries[0].p1_set && res.dropped_entries[0].p2_set);
    ck_assert(uuid_compare(res.dropped_entries[0].p1_uuid, g_fp1) == 0);
    ck_assert_double_eq_tol(res.dropped_entries[0].p1_score, 0.3 + 0.02 * ('x' - 'a'), 1e-12);
    ck_assert_int_eq(res.dropped_entries[0].index, 2);
    tx_reconcile_result_free(&res);
    ck_assert(res.dropped_entries == NULL);
    tx_reconcile_result_free(&res);   /* idempotent */

    /* Agreeing now: nothing dropped, nothing owned. */
    res = _reconcile_from(&ours, &theirs, -1);
    ck_assert_int_eq(res.status, TX_RECONCILE_NONE);
    ck_assert(res.dropped_entries == NULL);

    /* A pure extension drops nothing either. */
    tx_history_t short_h;
    _fork_chain(&short_h, "ab");
    res = _reconcile_from(&short_h, &theirs, -1);
    ck_assert_int_eq(res.status, TX_RECONCILE_EXTENDED);
    ck_assert(res.dropped_entries == NULL);

    tx_history_free(&short_h);
    tx_history_free(&ours);
    tx_history_free(&theirs);
}
END_TEST_DEFINITION()

RUN_TESTS(ReputationFork, test_tx_fork_adopts_the_longer_chain,
          test_tx_fork_keeps_our_chain_when_the_peer_is_shorter,
          test_tx_fork_tiebreak_is_symmetric,
          test_tx_fork_refused_inside_the_finalized_checkpoint,
          test_tx_fork_adoption_keeps_pending_work,
          test_tx_fork_the_quorum_chain_wins_an_equal_length_tiebreak,
          test_tx_fork_hands_back_what_it_dropped)
