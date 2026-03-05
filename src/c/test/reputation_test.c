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
#include <math.h>
#include <uuid/uuid.h>

#include "reputation/reputation.h"
#include "utilities/exception.h"
#include "utilities/logger.h"

/****************************
 * Transaction history tests
 ****************************/

DEFINE_TEST(test_tx_history_init)
{
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));
    ck_assert_int_eq(tx_history_len(&hist), 0);
    tx_history_free(&hist);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tx_history_update_retrieve)
{
    tx_history_t hist;
    tx_history_init(&hist);

    uuid_t task_uuid, peer1, peer2;
    uuid_generate(task_uuid);
    uuid_generate(peer1);
    uuid_generate(peer2);

    /* First party scores */
    ck_assert_ret_ok(tx_history_update(&hist, task_uuid, peer1, 0.8));
    ck_assert_int_eq(tx_history_len(&hist), 1);

    /* Second party scores */
    ck_assert_ret_ok(tx_history_update(&hist, task_uuid, peer2, 0.9));

    /* Retrieve by task */
    transaction_t tx;
    ck_assert_ret_ok(tx_history_by_task(&hist, task_uuid, &tx));
    ck_assert(tx.p1_set);
    ck_assert(tx.p2_set);

    /* Check scores - p1 was peer1 (0.8), p2 was peer2 (0.9) */
    ck_assert(fabs(tx.p1_score - 0.8) < 0.001);
    ck_assert(fabs(tx.p2_score - 0.9) < 0.001);

    /* Retrieve by peer */
    transaction_t peer_txns[10];
    int count = 0;
    ck_assert_ret_ok(tx_history_by_peer(&hist, peer1, peer_txns, &count, 10));
    ck_assert_int_eq(count, 1);

    tx_history_free(&hist);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tx_history_era)
{
    tx_history_t hist;
    tx_history_init(&hist);

    /* Add multiple transactions */
    for (int i = 0; i < 5; i++)
    {
        uuid_t task_uuid, peer;
        uuid_generate(task_uuid);
        uuid_generate(peer);
        tx_history_update(&hist, task_uuid, peer, 0.5 + i * 0.1);
    }
    ck_assert_int_eq(tx_history_len(&hist), 5);

    /* Get era slice */
    transaction_t era[10];
    int count = 0;
    ck_assert_ret_ok(tx_history_era(&hist, 1, 3, era, &count));
    ck_assert_int_eq(count, 2);

    tx_history_free(&hist);
}
END_TEST_DEFINITION()

/****************************
 * Reputations tests
 ****************************/

DEFINE_TEST(test_reputations_crud)
{
    reputations_t reps;
    ck_assert_ret_ok(reputations_init(&reps));

    uuid_t peer1, peer2;
    uuid_generate(peer1);
    uuid_generate(peer2);

    /* Initially empty */
    ck_assert(!reputations_contains(&reps, peer1));

    /* Update */
    ck_assert_ret_ok(reputations_update(&reps, peer1, 0.75));
    ck_assert(reputations_contains(&reps, peer1));

    /* Get */
    double score = 0.0;
    ck_assert_ret_ok(reputations_get(&reps, peer1, &score));
    ck_assert(fabs(score - 0.75) < 0.001);

    /* Non-existent peer */
    ck_assert(!reputations_contains(&reps, peer2));

    /* Update overwrites */
    ck_assert_ret_ok(reputations_update(&reps, peer1, 0.9));
    ck_assert_ret_ok(reputations_get(&reps, peer1, &score));
    ck_assert(fabs(score - 0.9) < 0.001);

    reputations_free(&reps);
}
END_TEST_DEFINITION()

/****************************
 * Contrite TFT tests
 ****************************/

DEFINE_TEST(test_contrite_tft_no_history)
{
    tx_history_t hist;
    tx_history_init(&hist);
    reputations_t reps;
    reputations_init(&reps);

    uuid_t self_uuid, peer_uuid;
    uuid_generate(self_uuid);
    uuid_generate(peer_uuid);

    /* No history should return ~0.49 */
    double result = reputation_contrite_tft(&hist, &reps, self_uuid, peer_uuid);
    ck_assert(fabs(result - 0.49) < 0.01);

    tx_history_free(&hist);
    reputations_free(&reps);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_reputation_compute_trusted)
{
    tx_history_t hist;
    tx_history_init(&hist);
    reputations_t reps;
    reputations_init(&reps);

    uuid_t self_uuid, peer_uuid, other_uuid;
    uuid_generate(self_uuid);
    uuid_generate(peer_uuid);
    uuid_generate(other_uuid);

    /* Set up: peer has good reputation */
    reputations_update(&reps, peer_uuid, 0.8);
    reputations_update(&reps, other_uuid, 0.7);

    /* Add a transaction where peer and other interacted */
    uuid_t task_uuid;
    uuid_generate(task_uuid);
    tx_history_update(&hist, task_uuid, peer_uuid, 0.9);
    tx_history_update(&hist, task_uuid, other_uuid, 0.85);

    /* Compute reputation - should use pure algorithm (score > 0.5) */
    double result = reputation_compute(&hist, &reps, self_uuid, peer_uuid);
    /* With one transaction: counterparty_score(0.85) * counterparty_rep(0.7) / 1 = 0.595 */
    ck_assert(result > 0.0);
    ck_assert(result <= 1.0);

    tx_history_free(&hist);
    reputations_free(&reps);
}
END_TEST_DEFINITION()

/****************************
 * Paxos ID tests
 ****************************/

DEFINE_TEST(test_paxos_id_deterministic)
{
    double id1 = paxos_id_index(5.0, 3.0);
    double id2 = paxos_id_index(5.0, 3.0);
    ck_assert(fabs(id1 - id2) < 0.0001);

    /* id1 + id2/10^digits(id2) = 5 + 3/10 = 5.3 */
    ck_assert(fabs(id1 - 5.3) < 0.0001);

    /* Different inputs give different results */
    double id3 = paxos_id_index(5.0, 7.0);
    /* 5 + 7/10 = 5.7 */
    ck_assert(fabs(id3 - 5.7) < 0.0001);

    /* Multi-digit id2 */
    double id4 = paxos_id_index(3.0, 42.0);
    /* 3 + 42/100 = 3.42 */
    ck_assert(fabs(id4 - 3.42) < 0.0001);

    /* Zero id2 */
    double id5 = paxos_id_index(7.0, 0.0);
    ck_assert(fabs(id5 - 7.0) < 0.0001);
}
END_TEST_DEFINITION()

/****************************
 * JSON serialization tests
 ****************************/

DEFINE_TEST(test_tx_history_json_roundtrip)
{
    tx_history_t hist;
    tx_history_init(&hist);

    /* Add transactions */
    uuid_t task1, task2, peer1, peer2;
    uuid_generate(task1);
    uuid_generate(task2);
    uuid_generate(peer1);
    uuid_generate(peer2);

    tx_history_update(&hist, task1, peer1, 0.8);
    tx_history_update(&hist, task1, peer2, 0.7);
    tx_history_update(&hist, task2, peer1, 0.9);

    /* Serialize */
    json_t *json = NULL;
    ck_assert_ret_ok(tx_history_era_to_json(&hist, 0, tx_history_len(&hist), &json));
    ck_assert_ptr_nonnull(json);
    ck_assert(json_is_array(json));

    /* Deserialize into new history */
    tx_history_t hist2;
    tx_history_init(&hist2);
    ck_assert_ret_ok(tx_history_era_from_json(&hist2, json));
    ck_assert_int_eq(tx_history_len(&hist2), tx_history_len(&hist));

    json_decref(json);
    tx_history_free(&hist);
    tx_history_free(&hist2);
}
END_TEST_DEFINITION()

RUN_TESTS(Reputation,
    test_tx_history_init,
    test_tx_history_update_retrieve,
    test_tx_history_era,
    test_reputations_crud,
    test_contrite_tft_no_history,
    test_reputation_compute_trusted,
    test_paxos_id_deterministic,
    test_tx_history_json_roundtrip)
