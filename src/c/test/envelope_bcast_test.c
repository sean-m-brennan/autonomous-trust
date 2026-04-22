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
 * @file envelope_bcast_test.c
 * @brief Pure-protocol tests for the cross-leg broadcast-forwarding gate
 *        and dedup fingerprint (at-over-dtn.md §4.3 item D).
 *
 * Split from envelope_relay_test.c because the RUN_TESTS macro caps at
 * nine tests per suite. These cover the protocol helpers; the handler
 * integration (dedup + rate-limit + send_broadcast) is exercised in
 * net_proc_relay_test.c.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdint.h>
#include <string.h>

#include "network/net_envelope.h"

static void uuid_fill(uuid_t u, uint8_t seed)
{
    for (size_t i = 0; i < 16; i++)
        u[i] = (uint8_t)(seed + i);
}

DEFINE_TEST(test_should_forward_broadcast_predicate)
{
    /* Gate for cross-leg broadcast forwarding: true iff BROADCAST +
     * gateway + hop_count strictly below NET_ENV_MAX_HOPS. */
    uuid_t src;
    uuid_fill(src, 0x77);

    net_envelope_t env = {
        .version   = NET_ENV_VERSION,
        .type      = NET_ENV_TYPE_BROADCAST,
        .hop_count = 0,
    };
    memcpy(env.src_uuid, src, 16);

    ck_assert_int_eq((int)net_envelope_should_forward_broadcast(&env, /*gw*/ true), 1);
    ck_assert_int_eq((int)net_envelope_should_forward_broadcast(&env, /*gw*/ false), 0);

    /* At the hop cap — even a gateway cannot re-forward. */
    env.hop_count = NET_ENV_MAX_HOPS;
    ck_assert_int_eq((int)net_envelope_should_forward_broadcast(&env, /*gw*/ true), 0);

    /* Non-broadcast types are never forwarded via this gate — they use the
     * regular disposition path. */
    env.hop_count = 0;
    env.type = NET_ENV_TYPE_PEER;
    ck_assert_int_eq((int)net_envelope_should_forward_broadcast(&env, /*gw*/ true), 0);
    env.type = NET_ENV_TYPE_GROUP;
    ck_assert_int_eq((int)net_envelope_should_forward_broadcast(&env, /*gw*/ true), 0);

    /* NULL env → false. */
    ck_assert_int_eq((int)net_envelope_should_forward_broadcast(NULL, /*gw*/ true), 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_broadcast_fingerprint_stable_across_hops)
{
    /* The fingerprint a gateway uses for dedup must be invariant under the
     * header rewrite a previous gateway performs — otherwise two gateways
     * in a ring could re-forward the same frame indefinitely. */
    uuid_t src;
    uuid_fill(src, 0x11);

    net_envelope_t sent = {
        .version   = NET_ENV_VERSION,
        .type      = NET_ENV_TYPE_BROADCAST,
        .hop_count = 0,
        .flags     = 0,
    };
    memcpy(sent.src_uuid, src, 16);
    memset(sent.dst_uuid, 0, 16);

    const uint8_t payload[] = "discovery-hello";
    const size_t  payload_len = sizeof(payload) - 1;

    uint8_t frame[NET_ENV_HEADER_LEN + sizeof(payload)];
    size_t  frame_len = 0;
    ck_assert_ret_ok(net_envelope_pack(&sent, payload, payload_len,
                                       frame, sizeof(frame), &frame_len));

    net_envelope_t before;
    const uint8_t *pay_before = NULL;
    size_t pay_before_len = 0;
    ck_assert_ret_ok(net_envelope_unpack(frame, frame_len, &before,
                                         &pay_before, &pay_before_len));
    uint64_t fp_before =
        net_envelope_broadcast_fingerprint(&before, pay_before, pay_before_len);
    ck_assert_int_eq((int)(fp_before != 0ULL), 1);  /* non-zero */

    /* Simulate a gateway hop: bump hop_count, set FORWARDED flag, rewrite. */
    net_envelope_t next = before;
    next.hop_count = (uint8_t)(next.hop_count + 1);
    next.flags     = (uint8_t)(next.flags | NET_ENV_FLAG_FORWARDED);
    ck_assert_ret_ok(net_envelope_rewrite_header(&next, frame, frame_len));

    net_envelope_t after;
    const uint8_t *pay_after = NULL;
    size_t pay_after_len = 0;
    ck_assert_ret_ok(net_envelope_unpack(frame, frame_len, &after,
                                         &pay_after, &pay_after_len));
    uint64_t fp_after =
        net_envelope_broadcast_fingerprint(&after, pay_after, pay_after_len);

    /* Same fingerprint before and after the hop — loop-prevention invariant. */
    ck_assert_int_eq((int)(fp_before == fp_after), 1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_broadcast_fingerprint_distinguishes_src_and_payload)
{
    /* Dedup must NOT collapse distinct broadcasts. Two envelopes differing
     * only in src_uuid, or only in payload, must fingerprint differently. */
    uuid_t a, b;
    uuid_fill(a, 0x10);
    uuid_fill(b, 0x20);

    net_envelope_t env_a = {
        .version = NET_ENV_VERSION,
        .type    = NET_ENV_TYPE_BROADCAST,
    };
    memcpy(env_a.src_uuid, a, 16);
    net_envelope_t env_b = env_a;
    memcpy(env_b.src_uuid, b, 16);

    const uint8_t payload1[] = "hello";
    const uint8_t payload2[] = "world";

    uint64_t f_a1 = net_envelope_broadcast_fingerprint(&env_a, payload1, sizeof(payload1) - 1);
    uint64_t f_a2 = net_envelope_broadcast_fingerprint(&env_a, payload2, sizeof(payload2) - 1);
    uint64_t f_b1 = net_envelope_broadcast_fingerprint(&env_b, payload1, sizeof(payload1) - 1);

    /* All three must be distinct. */
    ck_assert_int_eq((int)(f_a1 != f_a2), 1);
    ck_assert_int_eq((int)(f_a1 != f_b1), 1);
    ck_assert_int_eq((int)(f_a2 != f_b1), 1);

    /* NULL env → sentinel 0 (real fingerprints are always non-zero since
     * the FNV-1a offset basis seeds from 0xcbf29ce484222325). */
    ck_assert_int_eq((int)net_envelope_broadcast_fingerprint(NULL, payload1, sizeof(payload1) - 1),
                     0);
}
END_TEST_DEFINITION()

RUN_TESTS(Envelope_Bcast,
          test_should_forward_broadcast_predicate,
          test_broadcast_fingerprint_stable_across_hops,
          test_broadcast_fingerprint_distinguishes_src_and_payload)
