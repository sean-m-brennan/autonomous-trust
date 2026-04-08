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

DEFINE_TEST(test_tx_history_json_roundtrip)
{
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));

    uuid_t task1, task2, peer1, peer2;
    uuid_generate(task1);
    uuid_generate(task2);
    uuid_generate(peer1);
    uuid_generate(peer2);

    /* Create two-peer transactions */
    ck_assert_ret_ok(tx_history_update(&hist, task1, peer1, 0.8));
    ck_assert_ret_ok(tx_history_update(&hist, task1, peer2, 0.6));
    ck_assert_ret_ok(tx_history_update(&hist, task2, peer1, 0.9));

    /* Serialize to JSON */
    json_t *json_out = NULL;
    ck_assert_ret_ok(tx_history_era_to_json(&hist, 0, tx_history_len(&hist), &json_out));
    ck_assert_ptr_nonnull(json_out);
    ck_assert(json_is_array(json_out));
    ck_assert_int_eq((int)json_array_size(json_out), 2);

    /* Deserialize into fresh history */
    tx_history_t hist2;
    ck_assert_ret_ok(tx_history_init(&hist2));
    ck_assert_ret_ok(tx_history_era_from_json(&hist2, json_out));
    ck_assert_int_eq(tx_history_len(&hist2), 2);

    /* Verify task lookup works on deserialized history */
    transaction_t out;
    ck_assert_ret_ok(tx_history_by_task(&hist2, task1, &out));
    ck_assert(out.p1_set);
    ck_assert_double_eq_tol(out.p1_score, 0.8, 0.001);

    json_decref(json_out);
    tx_history_free(&hist);
    tx_history_free(&hist2);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tx_two_peer_transaction)
{
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));

    uuid_t task, peer1, peer2;
    uuid_generate(task);
    uuid_generate(peer1);
    uuid_generate(peer2);

    /* First update: fills p1 slot */
    ck_assert_ret_ok(tx_history_update(&hist, task, peer1, 0.7));
    ck_assert_int_eq(tx_history_len(&hist), 1);

    /* Second update same task: fills p2 slot */
    ck_assert_ret_ok(tx_history_update(&hist, task, peer2, 0.3));
    ck_assert_int_eq(tx_history_len(&hist), 1);  /* still 1 tx */

    transaction_t out;
    ck_assert_ret_ok(tx_history_by_task(&hist, task, &out));
    ck_assert(out.p1_set);
    ck_assert(out.p2_set);
    ck_assert_double_eq_tol(out.p1_score, 0.7, 0.001);
    ck_assert_double_eq_tol(out.p2_score, 0.3, 0.001);

    tx_history_free(&hist);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_reputation_contrite_tft)
{
    tx_history_t hist;
    reputations_t reps;
    ck_assert_ret_ok(tx_history_init(&hist));
    ck_assert_ret_ok(reputations_init(&reps));

    uuid_t self_id, peer_id, task;
    uuid_generate(self_id);
    uuid_generate(peer_id);
    uuid_generate(task);

    /* No history: should return 0.49 */
    double score = reputation_contrite_tft(&hist, &reps, self_id, peer_id);
    ck_assert_double_eq_tol(score, 0.49, 0.001);

    /* Add a cooperative transaction (both peers, high scores) */
    ck_assert_ret_ok(tx_history_update(&hist, task, self_id, 0.9));
    ck_assert_ret_ok(tx_history_update(&hist, task, peer_id, 0.8));

    score = reputation_contrite_tft(&hist, &reps, self_id, peer_id);
    /* Peer cooperated (0.8 > 0.5), should cooperate back = 1.0 */
    ck_assert_double_eq_tol(score, 1.0, 0.001);

    tx_history_free(&hist);
    reputations_free(&reps);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_reputation_pure_with_counterparty)
{
    tx_history_t hist;
    reputations_t reps;
    ck_assert_ret_ok(tx_history_init(&hist));
    ck_assert_ret_ok(reputations_init(&reps));

    uuid_t peer1, peer2, task;
    uuid_generate(peer1);
    uuid_generate(peer2);
    uuid_generate(task);

    /* Set up a complete transaction between peer1 and peer2 */
    ck_assert_ret_ok(tx_history_update(&hist, task, peer1, 0.9));
    ck_assert_ret_ok(tx_history_update(&hist, task, peer2, 0.7));

    /* Set reputations */
    ck_assert_ret_ok(reputations_update(&reps, peer1, 0.8));
    ck_assert_ret_ok(reputations_update(&reps, peer2, 0.6));

    /* Pure reputation for peer1: counterparty is peer2, score = 0.7 * 0.6 = 0.42 */
    double score = reputation_pure(&hist, &reps, peer1);
    ck_assert(score >= 0.0);
    ck_assert(score <= 1.0);

    /* No transactions: default to 0.5 */
    uuid_t unknown;
    uuid_generate(unknown);
    double def_score = reputation_pure(&hist, &reps, unknown);
    ck_assert_double_eq_tol(def_score, 0.5, 0.001);

    tx_history_free(&hist);
    reputations_free(&reps);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_paxos_id_index)
{
    char buf[PAXOS_KEY_LEN];

    /* Basic string key */
    paxos_id_index(buf, sizeof(buf), 5, 3);
    ck_assert_str_eq(buf, "5:3");

    /* id2 = 0 */
    paxos_id_index(buf, sizeof(buf), 7, 0);
    ck_assert_str_eq(buf, "7:0");

    /* Multi-digit id2 */
    paxos_id_index(buf, sizeof(buf), 1, 42);
    ck_assert_str_eq(buf, "1:42");

    /* Large id1 (timestamp-like) */
    paxos_id_index(buf, sizeof(buf), 1712345678000LL, 5);
    ck_assert_str_eq(buf, "1712345678000:5");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_reputations_get_missing)
{
    reputations_t reps;
    ck_assert_ret_ok(reputations_init(&reps));

    uuid_t peer;
    uuid_generate(peer);

    /* Getting a non-existent peer should fail */
    double score = 0.0;
    ck_assert_ret_nonzero(reputations_get(&reps, peer, &score));
    ck_assert(reputations_contains(&reps, peer) == false);

    /* After adding, should succeed */
    ck_assert_ret_ok(reputations_update(&reps, peer, 0.65));
    ck_assert_ret_ok(reputations_get(&reps, peer, &score));
    ck_assert_double_eq_tol(score, 0.65, 0.01);
    ck_assert(reputations_contains(&reps, peer) == true);

    reputations_free(&reps);
}
END_TEST_DEFINITION()

RUN_TESTS(Reputation3, test_tx_history_json_roundtrip, test_tx_two_peer_transaction,
          test_reputation_contrite_tft, test_reputation_pure_with_counterparty,
          test_paxos_id_index, test_reputations_get_missing)
