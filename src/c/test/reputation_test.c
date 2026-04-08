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

DEFINE_TEST(test_tx_history_basic)
{
    tx_history_t hist;
    ck_assert_ret_ok(tx_history_init(&hist));
    ck_assert_int_eq(tx_history_len(&hist), 0);

    uuid_t task_uuid, peer_uuid;
    uuid_generate(task_uuid);
    uuid_generate(peer_uuid);

    ck_assert_ret_ok(tx_history_update(&hist, task_uuid, peer_uuid, 0.75));
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

RUN_TESTS(Reputation, test_tx_history_basic, test_reputations_basic, test_paxos_id)
