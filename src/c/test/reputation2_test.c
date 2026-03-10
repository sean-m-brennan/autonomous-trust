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

    double score = reputation_pure(&hist, &reps, peer1);
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

    double score = reputation_compute(&hist, &reps, self_uuid, peer_uuid);
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

RUN_TESTS(Reputation2, test_tx_history_by_task, test_tx_history_by_peer,
          test_tx_history_era, test_reputation_pure,
          test_reputation_compute, test_reputations_create_destroy)
