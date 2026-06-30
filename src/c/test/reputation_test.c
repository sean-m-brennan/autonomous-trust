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

#include <uuid/uuid.h>

#include "reputation/reputation.h"
#include "structures/map.h"
#include "structures/data.h"

DEFINE_TEST(test_tx_history_basic)
{
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));
    ck_assert_int_eq(tx_history_len(&hist), 0);

    uuid_t task_uuid, peer1_uuid, peer2_uuid;
    uuid_generate(task_uuid);
    uuid_generate(peer1_uuid);
    uuid_generate(peer2_uuid);

    /* First slot fill keeps the tx pending — mirrors Python's
     * TransactionHistory.__len__ returning len(_chain), which
     * only counts bilateral entries. */
    ck_assert_ret_ok(tx_history_update(&hist, task_uuid, peer1_uuid, 0.75));
    ck_assert_int_eq(tx_history_len(&hist), 0);

    /* Second slot fill promotes to committed and bumps len. */
    ck_assert_ret_ok(tx_history_update(&hist, task_uuid, peer2_uuid, 0.85));
    ck_assert_int_eq(tx_history_len(&hist), 1);

    tx_history_free(&hist);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_reputations_basic)
{
    reputations_t reps;
    ck_assert_ret_ok(reputations_init(&reps));

    uuid_t peer_uuid;
    uuid_generate(peer_uuid);

    ck_assert(reputations_contains(&reps, peer_uuid) == false);

    ck_assert_ret_ok(reputations_update(&reps, peer_uuid, 0.85));
    ck_assert(reputations_contains(&reps, peer_uuid) == true);

    double score = 0.0;
    ck_assert_ret_ok(reputations_get(&reps, peer_uuid, &score));
    ck_assert_double_eq_tol(score, 0.85, 1e-6);

    reputations_free(&reps);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_paxos_id)
{
    /* paxos_id_index produces string keys "id1:id2" */
    char buf[PAXOS_KEY_LEN];
    paxos_id_index(buf, sizeof(buf), 1, 5);
    ck_assert_str_eq(buf, "1:5");
    paxos_id_index(buf, sizeof(buf), 3, 42);
    ck_assert_str_eq(buf, "3:42");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_consensus_by_tier)
{
    /* Per-tier consensus aggregation (trust-tiers §12 / deferred.md §2.3).
     * Mirror of Python TestConsensusByTier. "trusted at tier 1, untrusted
     * at tier 3." */
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));

    uuid_t peer, o1, o3, t1, t3;
    uuid_generate(peer);
    uuid_generate(o1);
    uuid_generate(o3);
    uuid_generate(t1);
    uuid_generate(t3);

    /* tier-1 interaction: counterparty o1 scores the peer 0.9 */
    ck_assert_ret_ok(tx_history_update(&hist, t1, peer, 0.5));
    ck_assert_ret_ok(tx_history_update(&hist, t1, o1, 0.9));
    /* tier-3 interaction: counterparty o3 scores the peer 0.4 */
    ck_assert_ret_ok(tx_history_update(&hist, t3, peer, 0.5));
    ck_assert_ret_ok(tx_history_update(&hist, t3, o3, 0.4));

    map_t task_tiers, task_weights;
    map_init(&task_tiers);
    map_init(&task_weights);
    char tk1[UUID_STRING_LEN + 1], tk3[UUID_STRING_LEN + 1];
    uuid_unparse_lower(t1, tk1);
    uuid_unparse_lower(t3, tk3);
    map_set(&task_tiers, tk1, integer_data(1));
    map_set(&task_tiers, tk3, integer_data(3));

    tier_score_t out[8];
    int n = reputation_consensus_by_tier(&hist, peer, &task_tiers,
                                         &task_weights, out, 8);
    ck_assert_int_eq(n, 2);
    bool saw1 = false, saw3 = false;
    for (int i = 0; i < n; i++)
    {
        if (out[i].tier == 1)
        {
            saw1 = true;
            ck_assert_double_eq_tol(out[i].score, 0.9, 0.001);
        }
        if (out[i].tier == 3)
        {
            saw3 = true;
            ck_assert_double_eq_tol(out[i].score, 0.4, 0.001);
        }
    }
    ck_assert(saw1);
    ck_assert(saw3);

    map_free(&task_tiers);
    map_free(&task_weights);
    tx_history_free(&hist);
}
END_TEST_DEFINITION()

RUN_TESTS(Reputation, test_tx_history_basic, test_reputations_basic, test_paxos_id,
          test_consensus_by_tier)
