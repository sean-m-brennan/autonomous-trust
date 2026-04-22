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

/**
 * @file envelope_relay_test.c
 * @brief End-to-end simulation of the gateway-forwarding relay
 *        (at-over-dtn.md §4.3, slice 2b).
 *
 * Exercises the envelope wire contract across multi-hop paths:
 *   pack at origin → unpack at gateway → rewrite header → unpack at
 *   destination. Asserts payload preservation, hop-count accounting,
 *   FORWARDED flag, and the disposition decision at each hop.
 *
 * This is a protocol-level test — it does not bring up real transports
 * or threads. That keeps the test deterministic and independent of socket
 * availability, while still validating the contract net_proc.c depends on.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdio.h>
#include <string.h>

#include "network/net_envelope.h"

/* ---- Helpers ---- */

static void uuid_fill(uuid_t u, uint8_t seed)
{
    for (size_t i = 0; i < 16; i++)
        u[i] = (uint8_t)(seed + i);
}

/* Simulate a single gateway hop: unpack frame, assert forwardable,
 * bump hop_count, set FORWARDED flag, rewrite header in place. Returns
 * the disposition that classify would have returned. */
static net_env_disposition_t relay_hop(uint8_t *frame, size_t frame_len,
                                       const uuid_t gw_uuid, bool gw_mode)
{
    net_envelope_t env;
    const uint8_t *payload = NULL;
    size_t         payload_len = 0;
    if (net_envelope_unpack(frame, frame_len, &env, &payload, &payload_len) != 0)
        return NET_ENV_DISPOSITION_DROP;

    static const uuid_t NIL = {0};
    net_env_disposition_t d =
        net_envelope_disposition(&env, gw_uuid, NIL, gw_mode);
    if (d != NET_ENV_DISPOSITION_FORWARD)
        return d;

    /* Gateway mutation: bump hop, set FORWARDED flag, rewrite only the
     * header bytes — payload must be byte-identical after the call. */
    env.hop_count = (uint8_t)(env.hop_count + 1);
    env.flags     = (uint8_t)(env.flags | NET_ENV_FLAG_FORWARDED);
    if (net_envelope_rewrite_header(&env, frame, frame_len) != 0)
        return NET_ENV_DISPOSITION_DROP;

    return NET_ENV_DISPOSITION_FORWARD;
}

/* ---- Tests ---- */

DEFINE_TEST(test_relay_peer_one_gateway_hop)
{
    /* Topology: A --[frame]--> G --[frame]--> B.
     * A is sender, B is recipient, G is gateway. */
    uuid_t A, B, G;
    uuid_fill(A, 0x10);
    uuid_fill(B, 0x20);
    uuid_fill(G, 0x30);
    static const uuid_t NIL = {0};

    /* A builds a PEER envelope addressed to B. */
    net_envelope_t sent = {
        .version = NET_ENV_VERSION,
        .type    = NET_ENV_TYPE_PEER,
        .flags   = 0,
        .hop_count = 0,
    };
    memcpy(sent.src_uuid, A, 16);
    memcpy(sent.dst_uuid, B, 16);

    const uint8_t payload[] = "ciphertext-standing-in-for-crypto_box-output";
    const size_t  payload_len = sizeof(payload) - 1;

    uint8_t frame[NET_ENV_HEADER_LEN + sizeof(payload)];
    size_t  frame_len = 0;
    ck_assert_ret_ok(net_envelope_pack(&sent, payload, payload_len,
                                       frame, sizeof(frame), &frame_len));

    /* Gateway G receives: envelope's dst is B, not G → FORWARD. */
    net_env_disposition_t d = relay_hop(frame, frame_len, G, true);
    ck_assert_int_eq((int)d, (int)NET_ENV_DISPOSITION_FORWARD);

    /* B receives forwarded frame. */
    net_envelope_t got;
    const uint8_t *got_payload = NULL;
    size_t         got_payload_len = 0;
    ck_assert_ret_ok(net_envelope_unpack(frame, frame_len, &got,
                                         &got_payload, &got_payload_len));

    /* Disposition at B: dst=B matches → LOCAL. */
    ck_assert_int_eq(
        (int)net_envelope_disposition(&got, B, NIL, false),
        (int)NET_ENV_DISPOSITION_LOCAL);

    /* Invariants: src/dst unchanged, hop_count bumped, FORWARDED set,
     * payload byte-for-byte equal to what A sent. */
    ck_assert_mem_eq(got.src_uuid, A, 16);
    ck_assert_mem_eq(got.dst_uuid, B, 16);
    ck_assert_int_eq(got.hop_count, 1);
    ck_assert_int_eq(got.flags & NET_ENV_FLAG_FORWARDED, NET_ENV_FLAG_FORWARDED);
    ck_assert_int_eq((int)got_payload_len, (int)payload_len);
    ck_assert_mem_eq(got_payload, payload, payload_len);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_relay_peer_two_gateway_hops)
{
    /* Topology: A -> G1 -> G2 -> B. Two chained gateways. */
    uuid_t A, B, G1, G2;
    uuid_fill(A, 0x10);
    uuid_fill(B, 0x20);
    uuid_fill(G1, 0x30);
    uuid_fill(G2, 0x40);

    net_envelope_t sent = {
        .version = NET_ENV_VERSION,
        .type    = NET_ENV_TYPE_PEER,
    };
    memcpy(sent.src_uuid, A, 16);
    memcpy(sent.dst_uuid, B, 16);

    uint8_t payload[32];
    for (size_t i = 0; i < sizeof(payload); i++) payload[i] = (uint8_t)(i * 7 + 3);
    uint8_t frame[NET_ENV_HEADER_LEN + sizeof(payload)];
    size_t  frame_len = 0;
    ck_assert_ret_ok(net_envelope_pack(&sent, payload, sizeof(payload),
                                       frame, sizeof(frame), &frame_len));

    ck_assert_int_eq((int)relay_hop(frame, frame_len, G1, true),
                     (int)NET_ENV_DISPOSITION_FORWARD);
    ck_assert_int_eq((int)relay_hop(frame, frame_len, G2, true),
                     (int)NET_ENV_DISPOSITION_FORWARD);

    net_envelope_t got;
    const uint8_t *pay_out = NULL;
    size_t         pay_len = 0;
    ck_assert_ret_ok(net_envelope_unpack(frame, frame_len, &got, &pay_out, &pay_len));

    ck_assert_int_eq(got.hop_count, 2);
    ck_assert_int_eq(got.flags & NET_ENV_FLAG_FORWARDED, NET_ENV_FLAG_FORWARDED);
    ck_assert_mem_eq(pay_out, payload, sizeof(payload));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_relay_drops_at_hop_exhaustion)
{
    /* A frame that's already at MAX_HOPS must NOT be forwarded — even by
     * a willing gateway. The disposition helper caps forwarding strictly
     * below NET_ENV_MAX_HOPS, so the gateway drops at the boundary. */
    uuid_t A, B, G;
    uuid_fill(A, 0x10);
    uuid_fill(B, 0x20);
    uuid_fill(G, 0x30);

    net_envelope_t sent = {
        .version   = NET_ENV_VERSION,
        .type      = NET_ENV_TYPE_PEER,
        .hop_count = NET_ENV_MAX_HOPS,  /* already at cap */
    };
    memcpy(sent.src_uuid, A, 16);
    memcpy(sent.dst_uuid, B, 16);

    uint8_t dummy[4] = {1, 2, 3, 4};
    uint8_t frame[NET_ENV_HEADER_LEN + sizeof(dummy)];
    size_t  frame_len = 0;
    ck_assert_ret_ok(net_envelope_pack(&sent, dummy, sizeof(dummy),
                                       frame, sizeof(frame), &frame_len));

    ck_assert_int_eq((int)relay_hop(frame, frame_len, G, true),
                     (int)NET_ENV_DISPOSITION_DROP);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_non_gateway_drops_others_peer_traffic)
{
    /* An intermediate node that is NOT a gateway must drop PEER frames
     * not addressed to it — regardless of hop_count remaining. */
    uuid_t A, B, M;
    uuid_fill(A, 0x10);
    uuid_fill(B, 0x20);
    uuid_fill(M, 0xA0);  /* non-gateway middle */

    net_envelope_t sent = {
        .version = NET_ENV_VERSION,
        .type    = NET_ENV_TYPE_PEER,
    };
    memcpy(sent.src_uuid, A, 16);
    memcpy(sent.dst_uuid, B, 16);

    uint8_t pay[8] = {0};
    uint8_t frame[NET_ENV_HEADER_LEN + sizeof(pay)];
    size_t  frame_len = 0;
    ck_assert_ret_ok(net_envelope_pack(&sent, pay, sizeof(pay),
                                       frame, sizeof(frame), &frame_len));

    ck_assert_int_eq((int)relay_hop(frame, frame_len, M, /* gw_mode */ false),
                     (int)NET_ENV_DISPOSITION_DROP);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_broadcast_always_local)
{
    /* Broadcast envelopes classify as LOCAL for every node — gateway
     * or not. Cross-leg broadcast bridging is intentionally NOT part of
     * this header and must be handled explicitly by operators. */
    static const uuid_t NIL = {0};
    uuid_t me;
    uuid_fill(me, 0x55);

    net_envelope_t env = {
        .version = NET_ENV_VERSION,
        .type    = NET_ENV_TYPE_BROADCAST,
    };
    memset(env.dst_uuid, 0, 16);  /* NIL */
    memcpy(env.src_uuid, me, 16);

    ck_assert_int_eq((int)net_envelope_disposition(&env, me, NIL, false),
                     (int)NET_ENV_DISPOSITION_LOCAL);
    ck_assert_int_eq((int)net_envelope_disposition(&env, me, NIL, true),
                     (int)NET_ENV_DISPOSITION_LOCAL);

    /* Also local on a node that is NOT the original sender — broadcast
     * doesn't self-filter at the envelope layer. */
    uuid_t other;
    uuid_fill(other, 0x66);
    ck_assert_int_eq((int)net_envelope_disposition(&env, other, NIL, false),
                     (int)NET_ENV_DISPOSITION_LOCAL);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_group_local_iff_group_matches)
{
    static const uuid_t NIL = {0};
    uuid_t me, my_group, other_group;
    uuid_fill(me, 0x10);
    uuid_fill(my_group,    0xC0);
    uuid_fill(other_group, 0xD0);

    net_envelope_t env = {
        .version = NET_ENV_VERSION,
        .type    = NET_ENV_TYPE_GROUP,
    };
    memcpy(env.src_uuid, me, 16);

    /* GROUP for my group → LOCAL. */
    memcpy(env.dst_uuid, my_group, 16);
    ck_assert_int_eq((int)net_envelope_disposition(&env, me, my_group, false),
                     (int)NET_ENV_DISPOSITION_LOCAL);

    /* GROUP for a different group → DROP (no cross-group bridging). */
    memcpy(env.dst_uuid, other_group, 16);
    ck_assert_int_eq((int)net_envelope_disposition(&env, me, my_group, true),
                     (int)NET_ENV_DISPOSITION_DROP);

    /* Not joined (NIL group) → DROP even if dst is some group. */
    memcpy(env.dst_uuid, my_group, 16);
    ck_assert_int_eq((int)net_envelope_disposition(&env, me, NIL, false),
                     (int)NET_ENV_DISPOSITION_DROP);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_gateway_receives_for_self)
{
    /* Even a gateway should deliver locally when it is the final
     * destination — gateway mode does not force forwarding. */
    static const uuid_t NIL = {0};
    uuid_t G_and_target;
    uuid_fill(G_and_target, 0x30);

    net_envelope_t env = {
        .version = NET_ENV_VERSION,
        .type    = NET_ENV_TYPE_PEER,
    };
    uuid_t src;
    uuid_fill(src, 0x11);
    memcpy(env.src_uuid, src, 16);
    memcpy(env.dst_uuid, G_and_target, 16);

    ck_assert_int_eq(
        (int)net_envelope_disposition(&env, G_and_target, NIL, /* gw */ true),
        (int)NET_ENV_DISPOSITION_LOCAL);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_relay_payload_immutable_across_hops)
{
    /* Targeted invariant: the payload bytes following the header must be
     * bitwise unchanged through an arbitrary number of relay hops. This is
     * the E2E-encryption guarantee — the gateway never touches the crypto
     * frame. */
    uuid_t A, B, G;
    uuid_fill(A, 0x10);
    uuid_fill(B, 0x20);
    uuid_fill(G, 0x30);

    net_envelope_t sent = {
        .version = NET_ENV_VERSION,
        .type    = NET_ENV_TYPE_PEER,
    };
    memcpy(sent.src_uuid, A, 16);
    memcpy(sent.dst_uuid, B, 16);

    /* 128 bytes of high-entropy-looking payload. */
    uint8_t payload[128];
    for (size_t i = 0; i < sizeof(payload); i++)
        payload[i] = (uint8_t)((i * 131 + 41) & 0xFF);

    uint8_t frame[NET_ENV_HEADER_LEN + sizeof(payload)];
    size_t  frame_len = 0;
    ck_assert_ret_ok(net_envelope_pack(&sent, payload, sizeof(payload),
                                       frame, sizeof(frame), &frame_len));

    /* Snapshot the payload region as it entered the wire. */
    uint8_t snapshot[sizeof(payload)];
    memcpy(snapshot, frame + NET_ENV_HEADER_LEN, sizeof(payload));

    /* 5 consecutive gateway hops (well under MAX_HOPS). */
    for (int i = 0; i < 5; i++) {
        ck_assert_int_eq((int)relay_hop(frame, frame_len, G, true),
                         (int)NET_ENV_DISPOSITION_FORWARD);
        ck_assert_mem_eq(frame + NET_ENV_HEADER_LEN, snapshot, sizeof(payload));
    }
}
END_TEST_DEFINITION()

RUN_TESTS(Envelope_Relay,
          test_relay_peer_one_gateway_hop,
          test_relay_peer_two_gateway_hops,
          test_relay_drops_at_hop_exhaustion,
          test_non_gateway_drops_others_peer_traffic,
          test_broadcast_always_local,
          test_group_local_iff_group_matches,
          test_gateway_receives_for_self,
          test_relay_payload_immutable_across_hops)
