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

#include <string.h>
#include <sodium.h>

#include "google/protobuf/any.pb-c.h"
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

/* --- ISSUES §2.1.4: the fixed-size payload arms of proto_to_generic_msg took a
 * peer-supplied `Any.value` and memcpy'd sizeof(struct) out of it without ever
 * checking its length, and leaked the unpacked Any on every path. Both were
 * measured under valgrind (invalid read of 8 bytes; 74 bytes lost per message)
 * before the fix, and both are gone after it. --- */

/** Pack an Any with `type_url` and a payload of `value_len` bytes. */
static uint8_t *_any_with_payload(const char *type_url, size_t value_len,
                                  size_t *out_len)
{
    static uint8_t payload[512];
    memset(payload, 0xAB, sizeof(payload));
    Google__Protobuf__Any any = GOOGLE__PROTOBUF__ANY__INIT;
    any.type_url = (char *)type_url;
    any.value.data = payload;
    any.value.len = value_len;
    *out_len = google__protobuf__any__get_packed_size(&any);
    uint8_t *buf = malloc(*out_len);
    google__protobuf__any__pack(&any, buf);
    return buf;
}

DEFINE_TEST(test_short_fixed_payload_is_rejected)
{
    /* 8 of the 112 bytes tx_score_msg_t wants. This used to return 0 and copy
     * 104 bytes of whatever followed the allocation into the struct, from where
     * it flowed on as a score. */
    size_t len = 0;
    uint8_t *buf = _any_with_payload("TRANSACTION_SCORE", 8, &len);
    generic_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    ck_assert_int_eq(proto_to_generic_msg(buf, len, &msg), -1);
    free(buf);
}

DEFINE_TEST(test_empty_fixed_payload_is_rejected)
{
    size_t len = 0;
    uint8_t *buf = _any_with_payload("PEER_REPUTATION", 0, &len);
    generic_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    ck_assert_int_eq(proto_to_generic_msg(buf, len, &msg), -1);
    free(buf);
}

DEFINE_TEST(test_full_length_fixed_payload_is_accepted)
{
    /* The negative control: the length check must not reject honest traffic. */
    size_t len = 0;
    uint8_t *buf = _any_with_payload("TRANSACTION_SCORE",
                                     sizeof(tx_score_msg_t), &len);
    generic_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    ck_assert_int_eq(proto_to_generic_msg(buf, len, &msg), 0);
    ck_assert_int_eq((int)msg.type, (int)TRANSACTION_SCORE);
    free(buf);
}

DEFINE_TEST(test_repeated_unpack_does_not_grow_without_bound)
{
    /* A leak check cannot be asserted from inside the process, so this is the
     * shape a leak would take rather than the leak detector itself: the same
     * message parsed many times, which is what a daemon does. Run under
     * valgrind (see §2.1.4) for the authoritative result -- it reported 74 bytes
     * lost per call before the free was added, and 0 after. */
    size_t len = 0;
    uint8_t *buf = _any_with_payload("TRANSACTION_SCORE",
                                     sizeof(tx_score_msg_t), &len);
    for (int i = 0; i < 200; i++)
    {
        generic_msg_t msg;
        memset(&msg, 0, sizeof(msg));
        ck_assert_int_eq(proto_to_generic_msg(buf, len, &msg), 0);
    }
    free(buf);
}

RUN_TESTS(MsgTypes3, test_net_msg_pack_unpack_json, test_net_msg_pack_null_json,
          test_net_msg_proto_roundtrip, test_net_msg_proto_no_payload,
          test_short_fixed_payload_is_rejected,
          test_empty_fixed_payload_is_rejected,
          test_full_length_fixed_payload_is_accepted,
          test_repeated_unpack_does_not_grow_without_bound)
