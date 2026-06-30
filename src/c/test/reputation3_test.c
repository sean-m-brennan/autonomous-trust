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
#include "autonomous_trust/structures/map.h"
#include "autonomous_trust/structures/data.h"

DEFINE_TEST(test_tx_history_json_roundtrip)
{
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));

    uuid_t task1, task2, peer1, peer2;
    uuid_generate(task1);
    uuid_generate(task2);
    uuid_generate(peer1);
    uuid_generate(peer2);

    /* Two bilateral transactions. After Bug 6 fix only bilateral
     * commits enter the chain and are serialized — the third
     * update below would have left task2 unilateral, and
     * era_to_json now correctly filters that out. To keep the
     * "2 entries on the wire" assertion meaningful, finish task2
     * bilaterally too. */
    ck_assert_ret_ok(tx_history_update(&hist, task1, peer1, 0.8));
    ck_assert_ret_ok(tx_history_update(&hist, task1, peer2, 0.6));
    ck_assert_ret_ok(tx_history_update(&hist, task2, peer1, 0.9));
    ck_assert_ret_ok(tx_history_update(&hist, task2, peer2, 0.5));

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

    /* First update: fills p1 slot — tx is pending, not yet
     * committed (mirrors Python `_chain.append` gated on
     * `len(tx) > 1`). */
    ck_assert_ret_ok(tx_history_update(&hist, task, peer1, 0.7));
    ck_assert_int_eq(tx_history_len(&hist), 0);

    /* Second update same task: fills p2 slot — bilateral commit
     * promotes the tx and bumps len to 1. */
    ck_assert_ret_ok(tx_history_update(&hist, task, peer2, 0.3));
    ck_assert_int_eq(tx_history_len(&hist), 1);

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
    /* One cooperative direct interaction: peer_standing = 0.8,
     * my_standing = 0.9, peer_last = 0.8 (not < 0.5). Falls into the
     * cooperate/cooperate branch which returns max(0.51, peer_standing).
     * Mirrors Python repprocess.py:384-385. */
    ck_assert_double_eq_tol(score, 0.8, 0.001);

    tx_history_free(&hist);
    reputations_free(&reps);
}
END_TEST_DEFINITION()

/* Branch-coverage pins for reputation_contrite_tft.  These mirror the
 * Python tests in src/autonomous-trust/tests/a_unit/test_reputation.py
 * (TestContriteTitForTat) using identical inputs and expected
 * outputs.  A drift on either side fails its own test. */
DEFINE_TEST(test_reputation_contrite_tft_cooperative_self_p2)
{
    /* Same as cooperative-p1 above, but peer fills p1 first.  Result
     * must be order-symmetric in which side filled p1 — the earlier
     * Python revision had p1/p2 score indices swapped and silently
     * produced different answers depending on insertion order. */
    tx_history_t hist;
    reputations_t reps;
    ck_assert_ret_ok(tx_history_init(&hist));
    ck_assert_ret_ok(reputations_init(&reps));

    uuid_t self_id, peer_id, task;
    uuid_generate(self_id);
    uuid_generate(peer_id);
    uuid_generate(task);

    ck_assert_ret_ok(tx_history_update(&hist, task, peer_id, 0.8));  /* peer → p1 */
    ck_assert_ret_ok(tx_history_update(&hist, task, self_id, 0.9));  /* self → p2 */

    double score = reputation_contrite_tft(&hist, &reps, self_id, peer_id);
    ck_assert_double_eq_tol(score, 0.8, 0.001);

    tx_history_free(&hist);
    reputations_free(&reps);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_reputation_contrite_tft_retaliation)
{
    /* Peer defected on last tx (peer_last < 0.5) and self's standing
     * is good → retaliation branch → min(0.49, peer_standing). */
    tx_history_t hist;
    reputations_t reps;
    ck_assert_ret_ok(tx_history_init(&hist));
    ck_assert_ret_ok(reputations_init(&reps));

    uuid_t self_id, peer_id, t1, t2;
    uuid_generate(self_id);
    uuid_generate(peer_id);
    uuid_generate(t1);
    uuid_generate(t2);

    /* tx1: cooperate/cooperate. */
    ck_assert_ret_ok(tx_history_update(&hist, t1, self_id, 0.9));
    ck_assert_ret_ok(tx_history_update(&hist, t1, peer_id, 0.8));
    /* tx2: self cooperates, peer defects. peer_last = 0.2. */
    ck_assert_ret_ok(tx_history_update(&hist, t2, self_id, 0.9));
    ck_assert_ret_ok(tx_history_update(&hist, t2, peer_id, 0.2));

    double score = reputation_contrite_tft(&hist, &reps, self_id, peer_id);
    /* peer_standing = (0.8 + 0.2)/2 = 0.5; my_standing = 0.9.
     * peer_last < 0.5, my_standing >= 0.5 → min(0.49, 0.5) = 0.49. */
    ck_assert_double_eq_tol(score, 0.49, 0.001);

    tx_history_free(&hist);
    reputations_free(&reps);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_reputation_contrite_tft_contrition)
{
    /* Peer defected on last tx but my own standing is also poor →
     * contrition branch → max(0.51, peer_standing). */
    tx_history_t hist;
    reputations_t reps;
    ck_assert_ret_ok(tx_history_init(&hist));
    ck_assert_ret_ok(reputations_init(&reps));

    uuid_t self_id, peer_id, t1, t2;
    uuid_generate(self_id);
    uuid_generate(peer_id);
    uuid_generate(t1);
    uuid_generate(t2);

    /* Both defect, both times. */
    ck_assert_ret_ok(tx_history_update(&hist, t1, self_id, 0.2));
    ck_assert_ret_ok(tx_history_update(&hist, t1, peer_id, 0.3));
    ck_assert_ret_ok(tx_history_update(&hist, t2, self_id, 0.2));
    ck_assert_ret_ok(tx_history_update(&hist, t2, peer_id, 0.4));

    double score = reputation_contrite_tft(&hist, &reps, self_id, peer_id);
    /* peer_standing = (0.3 + 0.4)/2 = 0.35; my_standing = 0.2.
     * peer_last < 0.5, my_standing < 0.5 → max(0.51, 0.35) = 0.51. */
    ck_assert_double_eq_tol(score, 0.51, 0.001);

    tx_history_free(&hist);
    reputations_free(&reps);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_reputation_contrite_tft_third_party_informs_prior)
{
    /* Transactions involving the queried peer but not self do not enter the
     * *bilateral* CTFT computation, but with no bilateral history WITH us
     * they now feed the cold-start prior (reputation_prereputation_prior)
     * instead of a flat 0.49. Mirrors Python
     * test_third_party_transactions_inform_prior (deferred.md §2.4). */
    tx_history_t hist;
    reputations_t reps;
    ck_assert_ret_ok(tx_history_init(&hist));
    ck_assert_ret_ok(reputations_init(&reps));

    uuid_t self_id, peer_id, other, task;
    uuid_generate(self_id);
    uuid_generate(peer_id);
    uuid_generate(other);
    uuid_generate(task);

    /* peer ↔ other tx, no self involvement; other scores the peer 0.1. */
    ck_assert_ret_ok(tx_history_update(&hist, task, peer_id, 0.1));
    ck_assert_ret_ok(tx_history_update(&hist, task, other,   0.1));

    double score = reputation_contrite_tft(&hist, &reps, self_id, peer_id);
    /* observed=0.1, cp_rep(other)=0.5 default, n=1:
     * (1*0.1 + 3*0.49) / (1+3) = 0.3925. */
    ck_assert_double_eq_tol(score, 0.3925, 0.001);

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
    double score = reputation_pure(&hist, &reps, peer1, NULL);
    ck_assert_double_eq_tol(score, 0.42, 0.001);

    /* No transactions: default to 0.5 */
    uuid_t unknown;
    uuid_generate(unknown);
    double def_score = reputation_pure(&hist, &reps, unknown, NULL);
    ck_assert_double_eq_tol(def_score, 0.5, 0.001);

    tx_history_free(&hist);
    reputations_free(&reps);
}
END_TEST_DEFINITION()

/* Pure-reputation branch pin: counterparty missing from reputations
 * uses 0.5 fallback rather than silently skipping.  Mirrors Python
 * TestPureReputation::test_unknown_counterparty_uses_default_0_5. */
DEFINE_TEST(test_reputation_pure_unknown_counterparty_default_0_5)
{
    tx_history_t hist;
    reputations_t reps;
    ck_assert_ret_ok(tx_history_init(&hist));
    ck_assert_ret_ok(reputations_init(&reps));

    uuid_t self_id, peer_id, task;
    uuid_generate(self_id);
    uuid_generate(peer_id);
    uuid_generate(task);

    ck_assert_ret_ok(tx_history_update(&hist, task, peer_id, 0.9));
    ck_assert_ret_ok(tx_history_update(&hist, task, self_id, 0.6));
    /* No reputations set — counterparty fallback should be 0.5. */

    double score = reputation_pure(&hist, &reps, peer_id, NULL);
    /* counterparty_score = 0.6, cp_rep = 0.5 → 0.3. */
    ck_assert_double_eq_tol(score, 0.3, 0.001);

    tx_history_free(&hist);
    reputations_free(&reps);
}
END_TEST_DEFINITION()

/* Weighted-pure pin: a task with transaction_weight=4 contributes
 * exactly 4x to the aggregator's denominator and numerator, so the
 * resulting reputation matches what an unweighted 4-tx-of-the-same
 * pair would yield. Mirrors the C side of doc/architecture/
 * trust-tiers.md §5 Slice 3b. */
DEFINE_TEST(test_reputation_pure_weighted_by_task)
{
    tx_history_t hist;
    reputations_t reps;
    map_t weights;
    ck_assert_ret_ok(tx_history_init(&hist));
    ck_assert_ret_ok(reputations_init(&reps));
    map_init(&weights);

    uuid_t peer, counterparty, task_w1, task_w4;
    uuid_generate(peer);
    uuid_generate(counterparty);
    uuid_generate(task_w1);
    uuid_generate(task_w4);

    /* Two transactions involving `peer` and `counterparty`. Both score
     * the counterparty at 0.9; counterparty's reputation is 1.0 so
     * cp_score * cp_rep = 0.9 for each tx. */
    ck_assert_ret_ok(tx_history_update(&hist, task_w1, peer, 0.0));
    ck_assert_ret_ok(tx_history_update(&hist, task_w1, counterparty, 0.9));
    ck_assert_ret_ok(tx_history_update(&hist, task_w4, peer, 0.0));
    ck_assert_ret_ok(tx_history_update(&hist, task_w4, counterparty, 0.9));
    ck_assert_ret_ok(reputations_update(&reps, counterparty, 1.0));

    char k1[UUID_STRING_LEN + 1], k4[UUID_STRING_LEN + 1];
    uuid_unparse_lower(task_w1, k1);
    uuid_unparse_lower(task_w4, k4);
    map_set(&weights, k1, integer_data(1));
    map_set(&weights, k4, integer_data(4));

    /* Unweighted aggregator: (0.9 + 0.9) / 2 = 0.9. */
    double unweighted = reputation_pure(&hist, &reps, peer, NULL);
    ck_assert_double_eq_tol(unweighted, 0.9, 0.001);

    /* Weighted aggregator: (0.9*1 + 0.9*4) / (1+4) = 0.9 — same in
     * this symmetric setup (both txs have the same contribution
     * direction), so weighting changes the *denominator* but the
     * ratio is invariant. Use asymmetric counterparty scores to
     * actually exercise the weighting. */
    ck_assert_double_eq_tol(reputation_pure(&hist, &reps, peer, &weights),
                            0.9, 0.001);

    /* Asymmetric: bump the w=4 tx's counterparty score so the two
     * contributions differ. cp_score*(cp_rep)*w:
     *   tx_w1: 0.4 * 1.0 * 1 = 0.4
     *   tx_w4: 0.9 * 1.0 * 4 = 3.6
     * total / total_weight = 4.0 / 5 = 0.8. */
    tx_history_free(&hist);
    tx_history_init(&hist);
    ck_assert_ret_ok(tx_history_update(&hist, task_w1, peer, 0.0));
    ck_assert_ret_ok(tx_history_update(&hist, task_w1, counterparty, 0.4));
    ck_assert_ret_ok(tx_history_update(&hist, task_w4, peer, 0.0));
    ck_assert_ret_ok(tx_history_update(&hist, task_w4, counterparty, 0.9));
    double weighted_asym = reputation_pure(&hist, &reps, peer, &weights);
    ck_assert_double_eq_tol(weighted_asym, 0.8, 0.001);

    /* Without weights this would be (0.4 + 0.9) / 2 = 0.65. */
    double unweighted_asym = reputation_pure(&hist, &reps, peer, NULL);
    ck_assert_double_eq_tol(unweighted_asym, 0.65, 0.001);

    map_free(&weights);
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
          test_reputation_contrite_tft,
          test_reputation_contrite_tft_cooperative_self_p2,
          test_reputation_contrite_tft_retaliation,
          test_reputation_contrite_tft_contrition,
          test_reputation_contrite_tft_third_party_informs_prior,
          test_reputation_pure_with_counterparty,
          test_reputation_pure_unknown_counterparty_default_0_5,
          test_reputation_pure_weighted_by_task,
          test_paxos_id_index, test_reputations_get_missing)
