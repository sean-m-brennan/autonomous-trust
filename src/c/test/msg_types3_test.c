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

#include "autonomous_trust/utilities/msg_types.h"
#include "autonomous_trust/utilities/msg_types_priv.h"

DEFINE_TEST(test_net_msg_pack_unpack_json)
{
    ck_assert(sodium_init() >= 0);

    net_msg_t msg = {0};
    json_t *obj = json_object();
    json_object_set_new(obj, "key", json_string("value"));
    json_object_set_new(obj, "score", json_real(0.95));

    ck_assert_ret_ok(net_msg_pack_json(&msg, obj));
    ck_assert_ptr_nonnull(msg.obj);
    ck_assert(msg.len > 0);

    json_t *result = NULL;
    ck_assert_ret_ok(net_msg_unpack_json(&msg, &result));
    ck_assert_ptr_nonnull(result);
    ck_assert_str_eq(json_string_value(json_object_get(result, "key")), "value");
    ck_assert_double_eq_tol(json_real_value(json_object_get(result, "score")), 0.95, 0.001);

    json_decref(obj);
    json_decref(result);
    smrt_deref(msg.obj);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_net_msg_pack_null_json)
{
    net_msg_t msg = {0};
    /* Unpacking empty msg should fail gracefully */
    json_t *result = NULL;
    ck_assert(net_msg_unpack_json(&msg, &result) != 0);
    ck_assert_ptr_null(result);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_net_msg_proto_roundtrip)
{
    ck_assert(sodium_init() >= 0);

    net_msg_t original = {0};
    strncpy(original.process, "reputation", PROC_NAME_LEN);
    original.function = (char *)"grant";
    original.encrypt = true;
    strncpy(original.return_to, "reputation", PROC_NAME_LEN);

    /* Set up from_whom identity */
    uuid_generate(original.from_whom.uuid);
    strncpy(original.from_whom.nickname, "Alice", NAME_LEN);

    /* Pack a small JSON payload */
    json_t *payload = json_object();
    json_object_set_new(payload, "id", json_integer(42));
    ck_assert_ret_ok(net_msg_pack_json(&original, payload));
    json_decref(payload);

    void *data = NULL;
    size_t data_len = 0;
    ck_assert_ret_ok(net_msg_to_proto(&original, &data, &data_len));
    ck_assert_ptr_nonnull(data);
    ck_assert(data_len > 0);

    net_msg_t restored = {0};
    ck_assert_ret_ok(proto_to_net_msg(data, data_len, &restored));
    ck_assert_str_eq(restored.process, "reputation");
    ck_assert(restored.encrypt == true);
    ck_assert_str_eq(restored.return_to, "reputation");
    ck_assert_str_eq(restored.from_whom.nickname, "Alice");

    /* Verify payload roundtripped */
    json_t *restored_payload = NULL;
    ck_assert_ret_ok(net_msg_unpack_json(&restored, &restored_payload));
    ck_assert_int_eq((int)json_integer_value(json_object_get(restored_payload, "id")), 42);
    json_decref(restored_payload);

    smrt_deref(data);
    smrt_deref(original.obj);
    if (restored.function)
        smrt_deref(restored.function);
    smrt_deref(restored.obj);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_net_msg_proto_no_payload)
{
    ck_assert(sodium_init() >= 0);

    net_msg_t original = {0};
    strncpy(original.process, "identity", PROC_NAME_LEN);
    original.encrypt = false;

    void *data = NULL;
    size_t data_len = 0;
    ck_assert_ret_ok(net_msg_to_proto(&original, &data, &data_len));

    net_msg_t restored = {0};
    ck_assert_ret_ok(proto_to_net_msg(data, data_len, &restored));
    ck_assert_str_eq(restored.process, "identity");
    ck_assert(restored.encrypt == false);
    ck_assert_ptr_null(restored.obj);

    smrt_deref(data);
}
END_TEST_DEFINITION()

RUN_TESTS(MsgTypes3, test_net_msg_pack_unpack_json, test_net_msg_pack_null_json,
          test_net_msg_proto_roundtrip, test_net_msg_proto_no_payload)
