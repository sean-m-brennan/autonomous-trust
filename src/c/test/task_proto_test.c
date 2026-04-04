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
#include <sodium.h>

#include "negotiation/task_priv.h"
#include "utilities/msg_types_priv.h"

/**
 * Test task_to_proto / proto_to_task roundtrip with realistic data.
 */
DEFINE_TEST(test_task_proto_roundtrip)
{
    ck_assert(sodium_init() >= 0);

    task_t original;
    memset(&original, 0, sizeof(original));

    uuid_generate(original.uuid);
    uuid_generate(original.requestor_uuid);
    strncpy(original.capability.name, "data_service", CAP_NAMELEN);
    original.when.tm_sec = 1700000000;
    original.when.tm_nsec = 500000000;
    original.duration.days = 1;
    original.duration.seconds = 3600;
    original.duration.nsecs = 0;
    original.timeout = 30;
    original.flexible = true;
    original.argc = 2;

    void *data = NULL;
    size_t data_len = 0;
    ck_assert_ret_ok(task_to_proto(&original, sizeof(task_t), &data, &data_len));
    ck_assert_ptr_nonnull(data);
    ck_assert(data_len > 0);

    task_t restored;
    memset(&restored, 0, sizeof(restored));
    ck_assert_ret_ok(proto_to_task(data, data_len, &restored));

    ck_assert(uuid_compare(original.uuid, restored.uuid) == 0);
    ck_assert(uuid_compare(original.requestor_uuid, restored.requestor_uuid) == 0);
    ck_assert_str_eq(restored.capability.name, "data_service");
    ck_assert_int_eq(restored.when.tm_sec, 1700000000);
    ck_assert_int_eq((int)restored.when.tm_nsec, 500000000);
    ck_assert_int_eq((int)restored.duration.days, 1);
    ck_assert_int_eq((int)restored.duration.seconds, 3600);
    ck_assert_int_eq(restored.timeout, 30);
    ck_assert(restored.flexible == true);
    ck_assert_int_eq((int)restored.argc, 2);

    smrt_deref(data);
}
END_TEST_DEFINITION()

/**
 * Test task proto roundtrip with zero/minimal values.
 */
DEFINE_TEST(test_task_proto_minimal)
{
    ck_assert(sodium_init() >= 0);

    task_t original;
    memset(&original, 0, sizeof(original));
    strncpy(original.capability.name, "ping", CAP_NAMELEN);

    void *data = NULL;
    size_t data_len = 0;
    ck_assert_ret_ok(task_to_proto(&original, sizeof(task_t), &data, &data_len));
    ck_assert_ptr_nonnull(data);

    task_t restored;
    memset(&restored, 0, sizeof(restored));
    ck_assert_ret_ok(proto_to_task(data, data_len, &restored));

    ck_assert_str_eq(restored.capability.name, "ping");
    ck_assert_int_eq(restored.timeout, 0);
    ck_assert(restored.flexible == false);
    ck_assert_int_eq((int)restored.argc, 0);

    smrt_deref(data);
}
END_TEST_DEFINITION()

/**
 * Test Paxos-style JSON payload pattern:
 * Pack (id1, id2, peer_uuid) into net_msg, roundtrip via proto, unpack JSON.
 * This exercises the exact serialization path used by reputation handlers.
 */
DEFINE_TEST(test_paxos_payload_roundtrip)
{
    ck_assert(sodium_init() >= 0);

    /* Build a Paxos Phase 1a request payload (as handle_request/grant use) */
    json_t *payload = json_object();
    json_object_set_new(payload, "id1", json_real(3.14159));
    json_object_set_new(payload, "id2", json_integer(42));
    json_object_set_new(payload, "peer_uuid", json_string("550e8400-e29b-41d4-a716-446655440000"));

    /* Pack into a net_msg_t */
    net_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    strncpy(msg.process, "reputation", PROC_NAME_LEN);
    msg.function = (char *)"grant";
    msg.encrypt = true;
    strncpy(msg.return_to, "reputation", PROC_NAME_LEN);

    ck_assert_ret_ok(net_msg_pack_json(&msg, payload));
    json_decref(payload);
    ck_assert_ptr_nonnull(msg.obj);
    ck_assert(msg.len > 0);

    /* Serialize net_msg to proto and back */
    void *wire = NULL;
    size_t wire_len = 0;
    ck_assert_ret_ok(net_msg_to_proto(&msg, &wire, &wire_len));
    ck_assert_ptr_nonnull(wire);

    net_msg_t restored;
    memset(&restored, 0, sizeof(restored));
    ck_assert_ret_ok(proto_to_net_msg(wire, wire_len, &restored));

    ck_assert_str_eq(restored.process, "reputation");
    ck_assert(restored.encrypt == true);

    /* Unpack JSON from restored net_msg */
    json_t *result = NULL;
    ck_assert_ret_ok(net_msg_unpack_json(&restored, &result));
    ck_assert_ptr_nonnull(result);

    /* Verify payload survived the full roundtrip */
    ck_assert_double_eq_tol(json_real_value(json_object_get(result, "id1")), 3.14159, 0.00001);
    ck_assert_int_eq((int)json_integer_value(json_object_get(result, "id2")), 42);
    ck_assert_str_eq(json_string_value(json_object_get(result, "peer_uuid")),
                     "550e8400-e29b-41d4-a716-446655440000");

    json_decref(result);
    smrt_deref(msg.obj);
    smrt_deref(wire);
    smrt_deref(restored.obj);
}
END_TEST_DEFINITION()

/**
 * Test reputation score payload pattern:
 * Pack (peer_uuid, score, requesting_process) as used by handle_rep_request/response.
 */
DEFINE_TEST(test_reputation_score_payload)
{
    ck_assert(sodium_init() >= 0);

    json_t *resp = json_object();
    json_object_set_new(resp, "peer_uuid", json_string("test-peer-uuid-1234"));
    json_object_set_new(resp, "score", json_real(0.85));
    json_object_set_new(resp, "requesting_process", json_string("negotiation"));

    net_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    ck_assert_ret_ok(net_msg_pack_json(&msg, resp));
    json_decref(resp);

    /* Unpack and verify */
    json_t *result = NULL;
    ck_assert_ret_ok(net_msg_unpack_json(&msg, &result));
    ck_assert_double_eq_tol(json_real_value(json_object_get(result, "score")), 0.85, 0.001);
    ck_assert_str_eq(json_string_value(json_object_get(result, "requesting_process")),
                     "negotiation");

    json_decref(result);
    smrt_deref(msg.obj);
}
END_TEST_DEFINITION()

RUN_TESTS(TaskProto, test_task_proto_roundtrip, test_task_proto_minimal,
          test_paxos_payload_roundtrip, test_reputation_score_payload)
