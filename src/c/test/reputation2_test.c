/********************
 *  Copyright 2025 Sean M. Brennan and contributors
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

DEFINE_TEST(test_tx_history_by_task)
{
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));

    uuid_t task1, task2, peer1;
    uuid_generate(task1);
    uuid_generate(task2);
    uuid_generate(peer1);

    ck_assert_ret_ok(tx_history_update(&hist, task1, peer1, 0.9));
    ck_assert_ret_ok(tx_history_update(&hist, task2, peer1, 0.5));
    ck_assert_int_eq(tx_history_len(&hist), 2);

    transaction_t out;
    memset(&out, 0, sizeof(out));
    ck_assert_ret_ok(tx_history_by_task(&hist, task1, &out));
    ck_assert_double_eq_tol(out.p1_score, 0.9, 0.001);

    tx_history_free(&hist);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tx_history_by_peer)
{
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));

    uuid_t task1, task2, task3, peer1, peer2;
    uuid_generate(task1);
    uuid_generate(task2);
    uuid_generate(task3);
    uuid_generate(peer1);
    uuid_generate(peer2);

    ck_assert_ret_ok(tx_history_update(&hist, task1, peer1, 0.8));
    ck_assert_ret_ok(tx_history_update(&hist, task2, peer1, 0.6));
    ck_assert_ret_ok(tx_history_update(&hist, task3, peer2, 0.9));

    transaction_t results[10];
    int count = 0;
    ck_assert_ret_ok(tx_history_by_peer(&hist, peer1, results, &count, 10));
    ck_assert_int_eq(count, 2);

    tx_history_free(&hist);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tx_history_era)
{
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));

    uuid_t tasks[5], peer;
    uuid_generate(peer);
    for (int i = 0; i < 5; i++) {
        uuid_generate(tasks[i]);
        ck_assert_ret_ok(tx_history_update(&hist, tasks[i], peer, 0.1 * (i + 1)));
    }

    transaction_t results[10];
    int count = 0;
    ck_assert_ret_ok(tx_history_era(&hist, 1, 3, results, &count));
    ck_assert(count > 0);
    ck_assert(count <= 3);

    tx_history_free(&hist);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_reputation_pure)
{
    tx_history_t hist;
    reputations_t reps;
    ck_assert_ret_ok(tx_history_init(&hist));
    ck_assert_ret_ok(reputations_init(&reps));

    uuid_t peer1, task1;
    uuid_generate(peer1);
    uuid_generate(task1);

    /* Set up some history and reputation */
    ck_assert_ret_ok(tx_history_update(&hist, task1, peer1, 0.9));
    ck_assert_ret_ok(reputations_update(&reps, peer1, 0.85));

    double score = reputation_pure(&hist, &reps, peer1, NULL);
    /* Score should be between 0 and 1 */
    ck_assert(score >= 0.0);
    ck_assert(score <= 1.0);

    tx_history_free(&hist);
    reputations_free(&reps);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_reputation_compute)
{
    tx_history_t hist;
    reputations_t reps;
    ck_assert_ret_ok(tx_history_init(&hist));
    ck_assert_ret_ok(reputations_init(&reps));

    uuid_t self_uuid, peer_uuid, task;
    uuid_generate(self_uuid);
    uuid_generate(peer_uuid);
    uuid_generate(task);

    ck_assert_ret_ok(tx_history_update(&hist, task, peer_uuid, 0.7));
    ck_assert_ret_ok(reputations_update(&reps, peer_uuid, 0.8));

    double score = reputation_compute(&hist, &reps, self_uuid, peer_uuid, NULL);
    ck_assert(score >= 0.0);
    ck_assert(score <= 1.0);

    tx_history_free(&hist);
    reputations_free(&reps);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_reputations_create_destroy)
{
    reputations_t *reps = NULL;
    ck_assert_ret_ok(reputations_create(&reps));
    ck_assert_ptr_nonnull(reps);

    uuid_t peer;
    uuid_generate(peer);
    ck_assert(reputations_contains(reps, peer) == false);

    ck_assert_ret_ok(reputations_update(reps, peer, 0.75));
    ck_assert(reputations_contains(reps, peer) == true);

    double score = 0.0;
    ck_assert_ret_ok(reputations_get(reps, peer, &score));
    ck_assert_double_eq_tol(score, 0.75, 0.001);

    reputations_free(reps);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tx_history_eviction)
{
    /* Pin the bounded-chain behavior: after MAX_CHAIN_LEN bilateral
     * inserts the oldest tx is evicted FIFO, by_task no longer finds
     * the evicted task_uuid, and by_peer drops the oldest reference
     * so the count caps at the chain length (not the number of
     * inserts ever seen). Mirrors the Python pin in
     * tests/a_unit/test_reputation.py — keep this lockstep with
     * TransactionHistory's eviction semantics. */
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));

    const int extra = 5;  /* inserts past the cap */
    const int total = MAX_CHAIN_LEN + extra;
    uuid_t *tasks = malloc(sizeof(uuid_t) * total);
    uuid_t shared_peer;
    uuid_generate(shared_peer);

    for (int i = 0; i < total; i++)
    {
        uuid_generate(tasks[i]);
        uuid_t cp_peer;
        uuid_generate(cp_peer);
        ck_assert_ret_ok(tx_history_update(&hist, tasks[i], shared_peer, 0.7));
        ck_assert_ret_ok(tx_history_update(&hist, tasks[i], cp_peer, 0.3));
    }
    ck_assert_int_eq(tx_history_len(&hist), MAX_CHAIN_LEN);

    /* The first `extra` task_uuids are evicted; by_task returns
     * EREP_NOTX. */
    transaction_t out;
    for (int i = 0; i < extra; i++)
        ck_assert(tx_history_by_task(&hist, tasks[i], &out) != 0);
    /* The most recent inserts are still present. */
    for (int i = total - 1; i >= total - 3; i--)
        ck_assert_ret_ok(tx_history_by_task(&hist, tasks[i], &out));

    /* by_peer is bounded by the residency window: shared_peer is in
     * every retained tx, so we get exactly MAX_CHAIN_LEN back (not
     * `total`). */
    transaction_t *results = malloc(sizeof(transaction_t) * total);
    int count = 0;
    ck_assert_ret_ok(tx_history_by_peer(&hist, shared_peer, results, &count, total));
    ck_assert_int_eq(count, MAX_CHAIN_LEN);

    free(results);
    free(tasks);
    tx_history_free(&hist);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tx_history_evicted_task_does_not_reanimate)
{
    /* Late `committed` broadcasts arrive at handle_committed and
     * call tx_history_update without knowing whether the task was
     * already rolled out. Once a task_uuid has been evicted,
     * tx_history_update must refuse to re-add it. Mirrors Python's
     * test_evicted_task_does_not_reanimate; keep in lockstep. */
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));

    /* Fill past the cap so the first task is evicted. */
    uuid_t first_task;
    uuid_generate(first_task);
    {
        uuid_t cp;
        uuid_generate(cp);
        ck_assert_ret_ok(tx_history_update(&hist, first_task, cp, 0.7));
        uuid_t cp2;
        uuid_generate(cp2);
        ck_assert_ret_ok(tx_history_update(&hist, first_task, cp2, 0.3));
    }
    for (int i = 0; i < MAX_CHAIN_LEN + 1; i++)
    {
        uuid_t tid, p1, p2;
        uuid_generate(tid);
        uuid_generate(p1);
        uuid_generate(p2);
        ck_assert_ret_ok(tx_history_update(&hist, tid, p1, 0.7));
        ck_assert_ret_ok(tx_history_update(&hist, tid, p2, 0.3));
    }
    ck_assert_int_eq(tx_history_len(&hist), MAX_CHAIN_LEN);
    /* first_task should be gone from task_map. */
    transaction_t probe;
    ck_assert(tx_history_by_task(&hist, first_task, &probe) != 0);

    /* Late `committed` for the evicted task — both sides. The
     * update must be a no-op: no orphan in task_map, no chain
     * regrowth, no displacement of legitimate recent entries. */
    int len_before = tx_history_len(&hist);
    uuid_t late_p1, late_p2;
    uuid_generate(late_p1);
    uuid_generate(late_p2);
    ck_assert_ret_ok(tx_history_update(&hist, first_task, late_p1, 0.7));
    ck_assert_ret_ok(tx_history_update(&hist, first_task, late_p2, 0.3));
    ck_assert_int_eq(tx_history_len(&hist), len_before);
    ck_assert(tx_history_by_task(&hist, first_task, &probe) != 0);

    tx_history_free(&hist);
}
END_TEST_DEFINITION()

RUN_TESTS(Reputation2, test_tx_history_by_task, test_tx_history_by_peer,
          test_tx_history_era, test_reputation_pure,
          test_reputation_compute, test_reputations_create_destroy,
          test_tx_history_eviction,
          test_tx_history_evicted_task_does_not_reanimate)
