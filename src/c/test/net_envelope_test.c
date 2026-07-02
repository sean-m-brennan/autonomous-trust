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

/**
 * @file net_envelope_test.c
 * @brief Unit tests for the plaintext forwarding envelope codec
 *        (at-over-dtn.md §4.3). Pure byte-level tests — no transports,
 *        no sockets, no threads.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>

#include "network/net_envelope.h"

/* Fill a UUID with a recognizable byte pattern so mis-copies show up. */
static void fill_uuid(uuid_t u, uint8_t seed)
{
    for (size_t i = 0; i < 16; i++)
        u[i] = (uint8_t)(seed + i);
}

DEFINE_TEST(test_pack_unpack_peer_roundtrip)
{
    net_envelope_t in = {
        .version   = NET_ENV_VERSION,
        .type      = NET_ENV_TYPE_PEER,
        .flags     = 0,
        .hop_count = 0,
    };
    fill_uuid(in.dst_uuid, 0x10);
    fill_uuid(in.src_uuid, 0x40);

    const uint8_t payload[] = {0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed};
    uint8_t frame[64];
    size_t  frame_len = 0;

    ck_assert_ret_ok(net_envelope_pack(&in, payload, sizeof(payload),
                                       frame, sizeof(frame), &frame_len));
    ck_assert_int_eq((int)frame_len, NET_ENV_HEADER_LEN + (int)sizeof(payload));

    net_envelope_t out = {0};
    const uint8_t *pay_out = NULL;
    size_t         pay_out_len = 0;
    ck_assert_ret_ok(net_envelope_unpack(frame, frame_len, &out,
                                         &pay_out, &pay_out_len));

    ck_assert_int_eq(out.version,   NET_ENV_VERSION);
    ck_assert_int_eq((int)out.type, (int)NET_ENV_TYPE_PEER);
    ck_assert_int_eq(out.flags,     0);
    ck_assert_int_eq(out.hop_count, 0);
    ck_assert_mem_eq(out.dst_uuid, in.dst_uuid, 16);
    ck_assert_mem_eq(out.src_uuid, in.src_uuid, 16);
    ck_assert_int_eq((int)pay_out_len, (int)sizeof(payload));
    ck_assert_mem_eq(pay_out, payload, sizeof(payload));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_pack_unpack_broadcast_nil_dst)
{
    /* Broadcast envelopes carry dst_uuid = NIL. */
    net_envelope_t in = {
        .version   = NET_ENV_VERSION,
        .type      = NET_ENV_TYPE_BROADCAST,
        .flags     = 0,
        .hop_count = 0,
    };
    memset(in.dst_uuid, 0, 16);
    fill_uuid(in.src_uuid, 0x77);

    uint8_t frame[NET_ENV_HEADER_LEN];
    size_t  frame_len = 0;
    ck_assert_ret_ok(net_envelope_pack(&in, NULL, 0,
                                       frame, sizeof(frame), &frame_len));
    ck_assert_int_eq((int)frame_len, NET_ENV_HEADER_LEN);

    net_envelope_t out = {0};
    const uint8_t *pay = NULL;
    size_t         pay_len = 0;
    ck_assert_ret_ok(net_envelope_unpack(frame, frame_len, &out, &pay, &pay_len));
    ck_assert_int_eq((int)out.type,    (int)NET_ENV_TYPE_BROADCAST);
    ck_assert_int_eq((int)pay_len,     0);
    ck_assert(net_envelope_is_nil_uuid(out.dst_uuid));
    ck_assert(!net_envelope_is_nil_uuid(out.src_uuid));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_pack_unpack_group_carries_group_uuid)
{
    net_envelope_t in = {
        .version   = NET_ENV_VERSION,
        .type      = NET_ENV_TYPE_GROUP,
        .flags     = NET_ENV_FLAG_FORWARDED,
        .hop_count = 2,
    };
    fill_uuid(in.dst_uuid, 0xA0); /* group id */
    fill_uuid(in.src_uuid, 0xB0);

    uint8_t pay_in[4] = {1, 2, 3, 4};
    uint8_t frame[NET_ENV_HEADER_LEN + sizeof(pay_in)];
    size_t  frame_len = 0;
    ck_assert_ret_ok(net_envelope_pack(&in, pay_in, sizeof(pay_in),
                                       frame, sizeof(frame), &frame_len));

    net_envelope_t out = {0};
    const uint8_t *pay_out = NULL;
    size_t         pay_out_len = 0;
    ck_assert_ret_ok(net_envelope_unpack(frame, frame_len, &out,
                                         &pay_out, &pay_out_len));
    ck_assert_int_eq((int)out.type,  (int)NET_ENV_TYPE_GROUP);
    ck_assert_int_eq(out.flags,      NET_ENV_FLAG_FORWARDED);
    ck_assert_int_eq(out.hop_count,  2);
    ck_assert_mem_eq(out.dst_uuid, in.dst_uuid, 16);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_unpack_rejects_wrong_version)
{
    /* Hand-craft a header with a bogus version byte. */
    uint8_t frame[NET_ENV_HEADER_LEN] = {0};
    frame[0] = 0xFF; /* not NET_ENV_VERSION */
    frame[1] = NET_ENV_TYPE_PEER;

    net_envelope_t out;
    const uint8_t *pay = NULL;
    size_t         pay_len = 0;
    ck_assert_int_eq(
        net_envelope_unpack(frame, sizeof(frame), &out, &pay, &pay_len),
        -1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_unpack_rejects_undersized_frame)
{
    uint8_t frame[NET_ENV_HEADER_LEN - 1] = {0};
    frame[0] = NET_ENV_VERSION;

    net_envelope_t out;
    const uint8_t *pay = NULL;
    size_t         pay_len = 0;
    ck_assert_int_eq(
        net_envelope_unpack(frame, sizeof(frame), &out, &pay, &pay_len),
        -1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_rewrite_header_preserves_payload)
{
    /* Pack, then rewrite with a forwarding update; payload bytes must be
     * untouched — this is the gateway hot-path optimization. */
    net_envelope_t first = {
        .version   = NET_ENV_VERSION,
        .type      = NET_ENV_TYPE_PEER,
        .flags     = 0,
        .hop_count = 0,
    };
    fill_uuid(first.dst_uuid, 0x10);
    fill_uuid(first.src_uuid, 0x40);

    uint8_t pay_in[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    uint8_t frame[NET_ENV_HEADER_LEN + sizeof(pay_in)];
    size_t  frame_len = 0;
    ck_assert_ret_ok(net_envelope_pack(&first, pay_in, sizeof(pay_in),
                                       frame, sizeof(frame), &frame_len));

    /* Gateway updates hop_count and sets the FORWARDED flag. */
    net_envelope_t next = first;
    next.hop_count++;
    next.flags |= NET_ENV_FLAG_FORWARDED;
    ck_assert_ret_ok(net_envelope_rewrite_header(&next, frame, frame_len));

    /* Header fields reflect the rewrite. */
    ck_assert_int_eq(frame[2], NET_ENV_FLAG_FORWARDED);
    ck_assert_int_eq(frame[3], 1);

    /* Payload bytes MUST be byte-identical. */
    ck_assert_mem_eq(frame + NET_ENV_HEADER_LEN, pay_in, sizeof(pay_in));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_nil_uuid_detection)
{
    uuid_t nil_uuid;
    memset(nil_uuid, 0, sizeof(nil_uuid));
    ck_assert(net_envelope_is_nil_uuid(nil_uuid));

    uuid_t non_nil;
    fill_uuid(non_nil, 0x01);
    ck_assert(!net_envelope_is_nil_uuid(non_nil));

    /* Tricky edge case: only one non-zero byte — still non-nil. */
    uuid_t almost;
    memset(almost, 0, sizeof(almost));
    almost[7] = 0x01;
    ck_assert(!net_envelope_is_nil_uuid(almost));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_pack_null_safety)
{
    uint8_t frame[NET_ENV_HEADER_LEN];
    size_t  frame_len = 0;
    net_envelope_t env = { .version = NET_ENV_VERSION, .type = NET_ENV_TYPE_PEER };
    memset(env.dst_uuid, 0, 16);
    memset(env.src_uuid, 0, 16);

    /* NULL env rejected. */
    ck_assert_int_eq(net_envelope_pack(NULL, NULL, 0,
                                       frame, sizeof(frame), &frame_len), -1);
    /* NULL out_frame rejected. */
    ck_assert_int_eq(net_envelope_pack(&env, NULL, 0,
                                       NULL, 0, &frame_len), -1);
    /* Non-zero payload with NULL payload pointer rejected. */
    ck_assert_int_eq(net_envelope_pack(&env, NULL, 4,
                                       frame, sizeof(frame), &frame_len), -1);
    /* Undersized out buffer rejected. */
    uint8_t tiny[NET_ENV_HEADER_LEN - 1];
    ck_assert_int_eq(net_envelope_pack(&env, NULL, 0,
                                       tiny, sizeof(tiny), &frame_len), -1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_unpack_null_safety)
{
    uint8_t frame[NET_ENV_HEADER_LEN] = {0};
    frame[0] = NET_ENV_VERSION;

    net_envelope_t out;
    const uint8_t *pay = NULL;
    size_t         pay_len = 0;

    ck_assert_int_eq(net_envelope_unpack(NULL, NET_ENV_HEADER_LEN,
                                         &out, &pay, &pay_len), -1);
    ck_assert_int_eq(net_envelope_unpack(frame, NET_ENV_HEADER_LEN,
                                         NULL, &pay, &pay_len), -1);
    ck_assert_int_eq(net_envelope_unpack(frame, NET_ENV_HEADER_LEN,
                                         &out, NULL, &pay_len), -1);
    ck_assert_int_eq(net_envelope_unpack(frame, NET_ENV_HEADER_LEN,
                                         &out, &pay, NULL), -1);

    /* rewrite_header NULL checks. */
    net_envelope_t env = { .version = NET_ENV_VERSION };
    ck_assert_int_eq(net_envelope_rewrite_header(NULL, frame, sizeof(frame)), -1);
    ck_assert_int_eq(net_envelope_rewrite_header(&env,  NULL,  sizeof(frame)), -1);
    ck_assert_int_eq(net_envelope_rewrite_header(&env,  frame, 4),              -1);
}
END_TEST_DEFINITION()

RUN_TESTS(Net_Envelope,
          test_pack_unpack_peer_roundtrip,
          test_pack_unpack_broadcast_nil_dst,
          test_pack_unpack_group_carries_group_uuid,
          test_unpack_rejects_wrong_version,
          test_unpack_rejects_undersized_frame,
          test_rewrite_header_preserves_payload,
          test_nil_uuid_detection,
          test_pack_null_safety,
          test_unpack_null_safety)
