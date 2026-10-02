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
#include "autonomous_trust/utilities/message.h"
#include "autonomous_trust/utilities/msg_types_priv.h"
#include "autonomous_trust/identity/group.h"
#include "autonomous_trust/network/net_message.h"
#ifdef AT_ZTA_ENABLED
#include "zta/zta_msg_types.h"
#endif

extern message_type_t string_to_message_type(const char *str);

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
    net_msg_free_obj(&msg);
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
    net_msg_free_obj(&original);
    if (restored.function)
        free(restored.function);
    net_msg_free_obj(&restored);
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

/* --- The fixed-size payload arms of proto_to_generic_msg took a
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
     * valgrind (see) for the authoritative result -- it reported 74 bytes
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

/* THE SIGNATURE VERDICT MUST SURVIVE THE IPC HOP.
 *
 * net_proc verifies a frame's Ed25519 signature and writes the answer into
 * net_msg_t; every handler that ACTS on it — the group-key rotation gate, the
 * hierarchy gate — runs in another process, on the far side of this
 * serializer. It did not carry `verified` or `has_signature`, so those
 * handlers read false for every message ever sent, and the gates could never
 * open. Measured cost before this test existed: 107 group-key rotations minted
 * across 25 live-cohort runs, zero adopted, and cohorts that forked
 * permanently the moment two members rotated at once.
 *
 * Asserted in BOTH states. Only checking `true` would pass against a
 * serializer that hardcoded it, which would be a worse bug than the one this
 * replaces — an unsigned frame would arrive looking verified. */
DEFINE_TEST(test_net_msg_proto_carries_the_signature_verdict)
{
    ck_assert(sodium_init() >= 0);

    for (int verdict = 0; verdict <= 1; verdict++) {
        net_msg_t original = {0};
        strncpy(original.process, "identity", PROC_NAME_LEN);
        original.function = (char *)"group_key_update";
        original.encrypt = true;
        original.verified = (verdict == 1);
        original.has_signature = (verdict == 1);
        uuid_generate(original.from_whom.uuid);
        strncpy(original.from_whom.nickname, "Alice", NAME_LEN);

        json_t *payload = json_object();
        json_object_set_new(payload, "key_epoch", json_integer(2));
        ck_assert_ret_ok(net_msg_pack_json(&original, payload));
        json_decref(payload);

        void *data = NULL;
        size_t data_len = 0;
        ck_assert_ret_ok(net_msg_to_proto(&original, &data, &data_len));

        net_msg_t restored = {0};
        ck_assert_ret_ok(proto_to_net_msg(data, data_len, &restored));
        ck_assert_int_eq((int)restored.verified, verdict);
        ck_assert_int_eq((int)restored.has_signature, verdict);

        smrt_deref(data);
        net_msg_free_obj(&original);
        if (restored.function)
            free(restored.function);
        net_msg_free_obj(&restored);
    }
}

/* THE GROUP-MULTICAST FLAG IS CORE, AND ABSENT FROM THE IPC JSON WHEN FALSE.
 *
 * `group_multicast` was AT_SOCIAL-only until FEATURE_SPLIT_PLAN Phase 5, when
 * social moved to libat_social: the library sets the flag, and the core's
 * network process must honour it, so the field and RECIPIENT_GROUP are in
 * every build. The key is still written only when true, so a message that
 * does not multicast serializes byte-for-byte as it did before. */
DEFINE_TEST(test_group_multicast_is_core_and_omitted_when_false)
{
    for (int multicast = 0; multicast <= 1; multicast++) {
        net_msg_t original = {0};
        strncpy(original.process, "identity", PROC_NAME_LEN);
        original.function = (char *)"peer_post";
        original.group_multicast = (multicast == 1);
        uuid_generate(original.from_whom.uuid);

        json_t *payload = json_object();
        ck_assert_ret_ok(net_msg_pack_json(&original, payload));
        json_decref(payload);

        /* The IPC encoding is a NUL-terminated JSON text. */
        void *data = NULL;
        size_t data_len = 0;
        ck_assert_ret_ok(net_msg_to_proto(&original, &data, &data_len));
        ck_assert_int_eq(strstr((const char *)data, "group_multicast") != NULL,
                         multicast);

        net_msg_t restored = {0};
        ck_assert_ret_ok(proto_to_net_msg(data, data_len, &restored));
        ck_assert_int_eq((int)restored.group_multicast, multicast);

        smrt_deref(data);
        net_msg_free_obj(&original);
        if (restored.function)
            free(restored.function);
        net_msg_free_obj(&restored);
    }
    ck_assert_int_eq(RECIPIENT_GROUP, 2);
}

/* EVERY TYPE'S NAME MUST DECODE BACK TO THE TYPE.
 *
 * The IPC wire carries the type as `Any.type_url` -- the string from
 * message_type_to_string -- and the receiver maps it back with
 * string_to_message_type. Those were two hand-kept lists, and three types
 * (CHILD_GROUP, ZTA_REVOCATION_ALERT, ZTA_VERIFICATION_RESULT) were encoded
 * but never decoded, so they were dropped at every real IPC hop. The
 * conformance harness's messaging hook bypasses serialization and could not
 * see it. Walks the whole enum, so a type added to one list only fails here. */
static bool _retired(long t)
{
    return t == MSG_TYPE_RETIRED_10 || t == MSG_TYPE_RETIRED_11 || t == MSG_TYPE_RETIRED_12;
}

DEFINE_TEST(test_every_type_name_round_trips)
{
    ck_assert(sodium_init() >= 0);
    for (long t = SIGNAL; t <= PEER_STANDING; t++)
    {
        const char *name = message_type_to_string((message_type_t)t);
        if (_retired(t)) {
            /* Fleet's old slots (FEATURE_SPLIT_PLAN Phase 8): never sent, so
             * nameless, and no name maps back to them. */
            ck_assert(string_to_message_type(name) != (message_type_t)t);
            continue;
        }
        ck_assert(name[0] != '\0');
        ck_assert_int_eq((long)string_to_message_type(name), t);
    }
    for (size_t i = 0; i < at_msg_type_count(); i++)
    {
        long t = at_msg_type_id_at(i);
        const char *name = message_type_to_string((message_type_t)t);
        ck_assert(name[0] != '\0');
        ck_assert_int_eq((long)string_to_message_type(name), t);
        ck_assert(message_size((message_type_t)t) <= AT_MSG_PAYLOAD_MAX);
    }
}
END_TEST_DEFINITION()

/* message_size is how many bytes processes.c copies OUT of a generic_msg_t's
 * payload for an unhandled message, so it must never exceed the payload. It
 * used to return 3.4 MB for PEER_CAPABILITIES. */
DEFINE_TEST(test_every_type_size_fits_the_message)
{
    generic_msg_t msg;
    for (long t = SIGNAL; t <= PEER_STANDING; t++)
        ck_assert(message_size((message_type_t)t) <= sizeof(msg.info));
}
END_TEST_DEFINITION()

/* The end-to-end shape of the CHILD_GROUP drop: through the real serializer,
 * not the hook. */
DEFINE_TEST(test_child_group_survives_the_ipc_serializer)
{
    ck_assert(sodium_init() >= 0);

    uuid_t uuid;
    uuid_generate(uuid);
    group_t *grp = NULL;
    ck_assert_ret_ok(group_create(&uuid, (char *)"172.16.0.9", &grp));
    grp->created = 1700000000.5;

    generic_msg_t out;
    memset(&out, 0, sizeof(out));
    out.type = CHILD_GROUP;
    out.size = message_size(CHILD_GROUP);
    out.info.group = *grp;

    void *data = NULL;
    size_t data_len = 0;
    ck_assert_ret_ok(generic_msg_to_proto(&out, &data, &data_len));

    generic_msg_t in;
    memset(&in, 0, sizeof(in));
    ck_assert_ret_ok(proto_to_generic_msg(data, data_len, &in));
    ck_assert_int_eq((int)in.type, (int)CHILD_GROUP);
    ck_assert_mem_eq(in.info.group.uuid, uuid, sizeof(uuid_t));
    ck_assert_double_eq_tol(in.info.group.created, 1700000000.5, 1e-6);

    smrt_deref(data);
    group_free(grp);
}
END_TEST_DEFINITION()

/* --- The registry (msg_registry.h): a feature's type crosses the same
 * serializer as a core type, through the opaque payload arm. The test type
 * sits in the fleet range, which nothing registers yet. --- */

typedef struct {
    uuid_t who;
    int32_t n;
    char note[40];
} test_ext_msg_t;
AT_MSG_ASSERT_FITS(test_ext_msg_t);

#define TEST_EXT_TYPE (AT_MSG_TYPE_FLEET_MIN + 7)
static const at_msg_vtable_t test_ext_vt = {
    .name = "TEST_EXT_OBSERVED",
    .size = sizeof(test_ext_msg_t),
};

DEFINE_TEST(test_registry_refuses_bad_registrations)
{
    static const at_msg_vtable_t core_name = { .name = "PEER_STANDING", .size = 8 };
    static const at_msg_vtable_t too_big = { .name = "TEST_TOO_BIG", .size = AT_MSG_PAYLOAD_MAX + 1 };
    static const at_msg_vtable_t unnamed = { .name = "", .size = 8 };
    static const at_msg_vtable_t fine = { .name = "TEST_OK", .size = 8 };

    /* A core id is never registrable: it would shadow a named arm. */
    ck_assert_int_eq(at_msg_type_register(PEER_STANDING, &fine), -1);
    ck_assert_int_eq(at_msg_type_register(AT_MSG_TYPE_EXT_MAX + 1, &fine), -1);
    ck_assert_int_eq(at_msg_type_register(AT_MSG_TYPE_FLEET_MIN + 1, &core_name), -1);
    ck_assert_int_eq(at_msg_type_register(AT_MSG_TYPE_FLEET_MIN + 2, &too_big), -1);
    ck_assert_int_eq(at_msg_type_register(AT_MSG_TYPE_FLEET_MIN + 3, &unnamed), -1);
    ck_assert_int_eq(at_msg_type_register(AT_MSG_TYPE_FLEET_MIN + 4, NULL), -1);
    ck_assert_ptr_null(at_msg_type_lookup(AT_MSG_TYPE_FLEET_MIN + 1));

    ck_assert_int_eq(at_msg_type_register(AT_MSG_TYPE_FLEET_MIN + 5, &fine), 0);
    /* Neither the id nor the name may be taken twice. */
    ck_assert_int_eq(at_msg_type_register(AT_MSG_TYPE_FLEET_MIN + 5, &test_ext_vt), -1);
    ck_assert_int_eq(at_msg_type_register(AT_MSG_TYPE_FLEET_MIN + 6, &fine), -1);
    ck_assert_int_eq(at_msg_type_by_name("TEST_OK"), AT_MSG_TYPE_FLEET_MIN + 5);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_registered_type_survives_the_ipc_serializer)
{
    ck_assert(sodium_init() >= 0);
    if (at_msg_type_lookup(TEST_EXT_TYPE) == NULL)
        ck_assert_ret_ok(at_msg_type_register(TEST_EXT_TYPE, &test_ext_vt));

    ck_assert_int_eq((long)message_size((message_type_t)TEST_EXT_TYPE),
                     (long)sizeof(test_ext_msg_t));
    ck_assert_str_eq(message_type_to_string((message_type_t)TEST_EXT_TYPE),
                     "TEST_EXT_OBSERVED");

    generic_msg_t out;
    memset(&out, 0, sizeof(out));
    out.type = TEST_EXT_TYPE;
    out.size = message_size((message_type_t)TEST_EXT_TYPE);
    test_ext_msg_t *p = AT_MSG_EXT(&out, test_ext_msg_t);
    uuid_generate(p->who);
    p->n = 42;
    strncpy(p->note, "through the registry", sizeof(p->note) - 1);

    void *data = NULL;
    size_t data_len = 0;
    ck_assert_ret_ok(generic_msg_to_proto(&out, &data, &data_len));

    generic_msg_t in;
    memset(&in, 0, sizeof(in));
    ck_assert_ret_ok(proto_to_generic_msg(data, data_len, &in));
    ck_assert_int_eq(in.type, TEST_EXT_TYPE);
    const test_ext_msg_t *q = AT_MSG_EXT_CONST(&in, test_ext_msg_t);
    ck_assert_mem_eq(q->who, p->who, sizeof(uuid_t));
    ck_assert_int_eq(q->n, 42);
    ck_assert_str_eq(q->note, "through the registry");
    smrt_deref(data);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_short_registered_payload_is_rejected)
{
    if (at_msg_type_lookup(TEST_EXT_TYPE) == NULL)
        ck_assert_ret_ok(at_msg_type_register(TEST_EXT_TYPE, &test_ext_vt));
    size_t len = 0;
    uint8_t *buf = _any_with_payload("TEST_EXT_OBSERVED", 4, &len);
    generic_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    ck_assert_int_eq(proto_to_generic_msg(buf, len, &msg), -1);
    free(buf);
}
END_TEST_DEFINITION()

/* A FEATURE'S TYPES MUST ACTUALLY BE REGISTERED IN ITS BUILD.
 *
 * Registration is a constructor, and a static link keeps a constructor only
 * if its object is pulled in -- this test links the static archive and
 * references nothing social but the link anchor, which is exactly the case
 * that would drop them. A dropped registration is silent at run time: the
 * types just fail to serialize. So pin the names, the ranges and app_bound. */
DEFINE_TEST(test_feature_types_are_registered)
{
#ifdef AT_ZTA_ENABLED
    at_zta_msg_types_link();
    ck_assert_ptr_nonnull(at_msg_type_lookup(ZTA_REVOCATION_ALERT));
    ck_assert_ptr_nonnull(at_msg_type_lookup(ZTA_VERIFICATION_RESULT));
    ck_assert_str_eq(message_type_to_string((message_type_t)ZTA_REVOCATION_ALERT), "ZTA_REVOCATION_ALERT");
    ck_assert_str_eq(message_type_to_string((message_type_t)ZTA_VERIFICATION_RESULT), "ZTA_VERIFICATION_RESULT");
    ck_assert(!at_msg_type_lookup(ZTA_VERIFICATION_RESULT)->app_bound);
#endif
    /* An app verb nobody registered stays refused. */
    ck_assert_ptr_null(at_app_verb_target("app_not_a_verb"));
}
END_TEST_DEFINITION()

/* A received NET_MESSAGE owns plain malloc buffers for function and obj, and
 * messaging_recv_release is what gives them back. Before it existed the obj
 * came from smrt_create and had its smrt header overwritten by the payload,
 * so nothing could release it and every message leaked (run under valgrind to
 * see the difference). */
DEFINE_TEST(test_recv_release_frees_a_received_net_message)
{
    generic_msg_t sent = {0};
    sent.type = NET_MESSAGE;
    strncpy(sent.info.net_msg.process, "identity", PROC_NAME_LEN);
    sent.info.net_msg.function = (char *)"device_cert";
    json_t *payload = json_pack("{s:s}", "body", "the payload sits at offset 0");
    ck_assert_ret_ok(net_msg_pack_json(&sent.info.net_msg, payload));
    json_decref(payload);
    /* The bytes at the start of the buffer are the payload, not a header. */
    ck_assert_int_eq(sent.info.net_msg.obj[0], '{');

    void *wire = NULL;
    size_t wire_len = 0;
    ck_assert_ret_ok(generic_msg_to_proto(&sent, &wire, &wire_len));
    net_msg_free_obj(&sent.info.net_msg);
    ck_assert_ptr_null(sent.info.net_msg.obj);
    ck_assert_uint_eq(sent.info.net_msg.len, 0);

    generic_msg_t got = {0};
    ck_assert_ret_ok(proto_to_generic_msg(wire, wire_len, &got));
    smrt_deref(wire);
    ck_assert_int_eq(got.type, NET_MESSAGE);
    ck_assert_str_eq(got.info.net_msg.function, "device_cert");
    ck_assert_ptr_nonnull(got.info.net_msg.obj);
    json_t *back = NULL;
    ck_assert_ret_ok(net_msg_unpack_json(&got.info.net_msg, &back));
    ck_assert_str_eq(json_string_value(json_object_get(back, "body")),
                     "the payload sits at offset 0");
    json_decref(back);

    messaging_recv_release(&got);
    ck_assert_int_eq(got.type, 0);
    ck_assert_ptr_null(got.info.net_msg.function);
    ck_assert_ptr_null(got.info.net_msg.obj);
    /* Safe again on the zeroed struct, and on NULL: loops release blindly. */
    messaging_recv_release(&got);
    messaging_recv_release(NULL);
    net_msg_free_obj(NULL);
}
END_TEST_DEFINITION()

RUN_TESTS(MsgTypes3, test_net_msg_pack_unpack_json, test_net_msg_pack_null_json,
          test_recv_release_frees_a_received_net_message,
          test_net_msg_proto_carries_the_signature_verdict,
          test_net_msg_proto_roundtrip, test_net_msg_proto_no_payload,
          test_short_fixed_payload_is_rejected,
          test_empty_fixed_payload_is_rejected,
          test_full_length_fixed_payload_is_accepted,
          test_repeated_unpack_does_not_grow_without_bound,
          test_every_type_name_round_trips,
          test_every_type_size_fits_the_message,
          test_child_group_survives_the_ipc_serializer,
          test_registry_refuses_bad_registrations,
          test_registered_type_survives_the_ipc_serializer,
          test_short_registered_payload_is_rejected,
          test_feature_types_are_registered,
          test_group_multicast_is_core_and_omitted_when_false)
