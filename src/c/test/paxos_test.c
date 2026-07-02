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
#include <stdint.h>
#include "autonomous_trust/algorithms/paxos.h"
#include "autonomous_trust/utilities/logger.h"

static logger_t test_logger;

static void __attribute__((constructor)) init_test_logger(void)
{
    logger_init(&test_logger, WARNING, NULL);
}

DEFINE_TEST(test_paxos_init)
{
    paxos_instance_t inst;
    ck_assert_ret_ok(paxos_init(&inst, 5, &test_logger));
    ck_assert_int_eq(inst.num_peers, 5);
    ck_assert_int_eq(inst.chain_len, 0);
    ck_assert(inst.last_id == 0);
    ck_assert(inst.initialized);
    paxos_destroy(&inst);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_paxos_id_index)
{
    char buf[PAXOS_KEY_LEN];
    paxos_id_index(buf, sizeof(buf), 1, 5);
    ck_assert_str_eq(buf, "1:5");
    paxos_id_index(buf, sizeof(buf), 3, 42);
    ck_assert_str_eq(buf, "3:42");
    paxos_id_index(buf, sizeof(buf), 1, 0);
    ck_assert_str_eq(buf, "1:0");
    paxos_id_index(buf, sizeof(buf), 7, 1);
    ck_assert_str_eq(buf, "7:1");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_paxos_handle_request_grant)
{
    paxos_instance_t inst;
    ck_assert_ret_ok(paxos_init(&inst, 3, &test_logger));

    int64_t out_last_id = -1;
    int out_chain_len = -1;

    paxos_response_t r = paxos_handle_request(&inst, 1, 1,
                                               &out_last_id, &out_chain_len);
    ck_assert_int_eq(r, PAXOS_GRANT);
    ck_assert_int_eq(out_chain_len, 0);

    paxos_destroy(&inst);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_paxos_handle_request_nack)
{
    paxos_instance_t inst;
    ck_assert_ret_ok(paxos_init(&inst, 3, &test_logger));

    int64_t out_last_id;
    int out_chain_len;

    paxos_handle_request(&inst, 2, 1, &out_last_id, &out_chain_len);

    paxos_response_t r = paxos_handle_request(&inst, 1, 1,
                                               &out_last_id, &out_chain_len);
    ck_assert_int_eq(r, PAXOS_NACK);

    paxos_destroy(&inst);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_paxos_handle_request_backdate)
{
    paxos_instance_t inst;
    ck_assert_ret_ok(paxos_init(&inst, 3, &test_logger));

    paxos_advance_chain(&inst);

    int64_t out_last_id;
    int out_chain_len;

    paxos_response_t r = paxos_handle_request(&inst, 1, 1,
                                               &out_last_id, &out_chain_len);
    ck_assert_int_eq(r, PAXOS_BACKDATE);

    paxos_destroy(&inst);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_paxos_quorum_3_peers)
{
    paxos_instance_t inst;
    ck_assert_ret_ok(paxos_init(&inst, 3, &test_logger));

    int count1 = paxos_record_grant(&inst, 1, 1, 0.75);
    ck_assert_int_eq(count1, 1);

    int count2 = paxos_record_grant(&inst, 1, 1, 0.75);
    ck_assert_int_eq(count2, 2);
    ck_assert(count2 >= PAXOS_MAJORITY(3));

    paxos_destroy(&inst);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_paxos_quorum_5_peers)
{
    paxos_instance_t inst;
    ck_assert_ret_ok(paxos_init(&inst, 5, &test_logger));

    paxos_record_grant(&inst, 1, 1, 0.5);
    paxos_record_grant(&inst, 1, 1, 0.5);
    int count3 = paxos_record_grant(&inst, 1, 1, 0.5);
    ck_assert_int_eq(count3, 3);
    ck_assert(count3 >= PAXOS_MAJORITY(5));

    paxos_destroy(&inst);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_paxos_acceptance_quorum)
{
    paxos_instance_t inst;
    ck_assert_ret_ok(paxos_init(&inst, 3, &test_logger));

    int a1 = paxos_record_acceptance(&inst, 1, 1);
    ck_assert_int_eq(a1, 1);

    int a2 = paxos_record_acceptance(&inst, 1, 1);
    ck_assert_int_eq(a2, 2);
    ck_assert(a2 >= PAXOS_MAJORITY(3));

    paxos_destroy(&inst);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_paxos_next_ids)
{
    paxos_instance_t inst;
    ck_assert_ret_ok(paxos_init(&inst, 3, &test_logger));

    int64_t id1, id2;
    paxos_next_ids(&inst, &id1, &id2);
    ck_assert(id2 == 1);
    ck_assert(id1 > 0);

    /* Regression for paxos.c:214-223 — id1 must be strictly monotonic, even
     * for back-to-back calls within the same millisecond.  Original code
     * derived id1 from clock_gettime(ms), so a tight loop of calls all
     * produced the same id1, violating Paxos safety.  Fix folds a per-
     * instance counter (and the node_id) into id1. */
    int64_t prev = id1;
    for (int i = 0; i < 32; i++)
    {
        int64_t next_id1 = 0, next_id2 = 0;
        paxos_next_ids(&inst, &next_id1, &next_id2);
        ck_assert(next_id1 > prev);
        prev = next_id1;
    }

    paxos_destroy(&inst);
}
END_TEST_DEFINITION()

RUN_TESTS(Paxos,
    test_paxos_init,
    test_paxos_id_index,
    test_paxos_handle_request_grant,
    test_paxos_handle_request_nack,
    test_paxos_handle_request_backdate,
    test_paxos_quorum_3_peers,
    test_paxos_quorum_5_peers,
    test_paxos_acceptance_quorum,
    test_paxos_next_ids
)
