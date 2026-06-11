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
 * @file discovery_cross_cluster_test.c
 * @brief Cross-cluster peer discovery (at-over-dtn.md §4.3 stage E),
 *        gated by AT_DISCOVERY_CROSS_CLUSTER.
 *
 * Verifies that when handle_inbound_broadcast sees a NET_ENV_FLAG_FORWARDED
 * envelope, route_to_process receives the INNER wire payload's self-reported
 * from_whom.address rather than the transport-layer from_addr (which would
 * be the gateway's address for a forwarded frame). Without the preservation
 * the receiving cluster would register the remote peer at the gateway's
 * address and reply routing would collapse.
 *
 * Covered:
 *   (a) forwarded envelope → self-reported address preserved;
 *   (b) non-forwarded envelope → transport from_addr is used (existing
 *       behavior unchanged when the FORWARDED flag is clear).
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "network/net_envelope.h"
#include "network/net_message.h"
#include "network/net_proc_priv.h"
#include "network/net_transport.h"
#include "network/network.h"
#include "identity/identity.h"
#include "identity/identity_priv.h"

/* ---------- Minimal mock transport (non-gateway — we only probe
 *            delivery-path behavior, not forwarding). ---------- */

typedef struct { bool is_gateway_flag; } mock_ctx_t;

static int mock_send_unicast(net_transport_ctx_t *c, const uint8_t *w, size_t wl,
                             const char *t, int p)
{ (void)c; (void)w; (void)wl; (void)t; (void)p; return 0; }

static int mock_send_broadcast(net_transport_ctx_t *c, net_channel_t ch,
                               const uint8_t *w, size_t wl, int p)
{ (void)c; (void)ch; (void)w; (void)wl; (void)p; return 0; }

static int mock_recv(net_transport_ctx_t *c, net_channel_t ch,
                     uint8_t **b, size_t *l, char *pa, size_t pal, int t)
{ (void)c; (void)ch; (void)b; (void)l; (void)pa; (void)pal; (void)t; return ENOMSG; }

static void mock_close(net_transport_ctx_t *c) { (void)c; }

static bool mock_is_gateway(const net_transport_ctx_t *c)
{ return ((const mock_ctx_t *)c)->is_gateway_flag; }

static const net_transport_t mock_transport = {
    .name           = "mock_disc",
    .send_unicast   = mock_send_unicast,
    .send_broadcast = mock_send_broadcast,
    .recv           = mock_recv,
    .close          = mock_close,
    .is_gateway     = mock_is_gateway,
};

/* ---------- Helpers ---------- */

static void uuid_fill(uuid_t u, uint8_t seed)
{
    for (size_t i = 0; i < 16; i++) u[i] = (uint8_t)(seed + i);
}

static void init_proc_min(process_t *proc)
{
    memset(proc, 0, sizeof(*proc));
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
}

/* Build a wire-format net_message carrying an ID_ANNOUNCE-like payload
 * whose from_whom.address is @p self_reported_addr. Returns a heap buffer;
 * caller frees via free(). */
static uint8_t *build_inner_wire(const uuid_t announcer_uuid,
                                 const char *self_reported_addr,
                                 size_t *out_len)
{
    net_wire_msg_t wmsg;
    memset(&wmsg, 0, sizeof(wmsg));
    snprintf(wmsg.process, sizeof(wmsg.process), "identity");
    wmsg.function = strdup("ID_ANNOUNCE");
    wmsg.data = NULL;
    wmsg.data_len = 0;
    wmsg.to_whom.type = RECIPIENT_BROADCAST;
    memcpy(wmsg.from_whom.uuid, announcer_uuid, 16);
    snprintf(wmsg.from_whom.nickname, sizeof(wmsg.from_whom.nickname), "remote-peer");
    snprintf(wmsg.from_whom.address, sizeof(wmsg.from_whom.address),
             "%s", self_reported_addr);
    wmsg.encrypt = false;
    wmsg.has_signature = false;

    uint8_t *wire = NULL;
    size_t   wire_len = 0;
    int rc = net_message_to_wire(&wmsg, NULL, &wire, &wire_len);
    free(wmsg.function);
    if (rc != 0) {
        free(wire);
        return NULL;
    }
    *out_len = wire_len;
    return wire;
}

/* Wrap @p inner (inner wire length @p inner_len) in a BROADCAST envelope
 * with @p flags. Result written into @p out_frame; length into @p *out_len. */
static void wrap_broadcast(const uuid_t src_uuid, uint8_t flags,
                           const uint8_t *inner, size_t inner_len,
                           uint8_t *out_frame, size_t out_cap,
                           size_t *out_len)
{
    static const uuid_t NIL = {0};
    net_envelope_t env = {
        .version   = NET_ENV_VERSION,
        .type      = NET_ENV_TYPE_BROADCAST,
        .flags     = flags,
        .hop_count = 0,
    };
    memcpy(env.src_uuid, src_uuid, 16);
    memcpy(env.dst_uuid, NIL, 16);
    int rc = net_envelope_pack(&env, inner, inner_len,
                               out_frame, out_cap, out_len);
    (void)rc;
}

/* ---------- Tests ---------- */

DEFINE_TEST(test_forwarded_broadcast_preserves_self_reported_address)
{
    const char *self_reported = "10.42.7.11";   /* remote-cluster address */
    const char *gateway_addr  = "10.1.0.50";    /* what from_addr would be */

    uuid_t ANN;
    uuid_fill(ANN, 0xC1);

    size_t   inner_len = 0;
    uint8_t *inner = build_inner_wire(ANN, self_reported, &inner_len);
    ck_assert_int_eq((int)(inner != NULL), 1);

    uint8_t frame[1024];
    size_t  frame_len = 0;
    wrap_broadcast(ANN, /*flags*/ NET_ENV_FLAG_FORWARDED,
                   inner, inner_len, frame, sizeof(frame), &frame_len);

    process_t proc;
    init_proc_min(&proc);
    identity_t myself = {0};
    uuid_t ME; uuid_fill(ME, 0x02); memcpy(myself.uuid, ME, 16);

    mock_ctx_t mctx = { .is_gateway_flag = false };
    network_config_t net_cfg = { .port = 27787 };
    bool stop = false;
    logger_t logger = {0};
    net_thread_ctx_t tctx = {
        .transport = &mock_transport,
        .ctx       = (net_transport_ctx_t *)&mctx,
        .proc      = &proc,
        .logger    = &logger,
        .net_cfg   = &net_cfg,
        .myself    = &myself,
        .stop      = &stop,
    };

    net_proc_test_reset_last_routed_from_addr();
    handle_inbound_broadcast(&tctx, frame, frame_len, gateway_addr);

    char observed[64] = {0};
    net_proc_test_get_last_routed_from_addr(observed, sizeof(observed));

    /* The announcer's self-reported address — not the gateway — reaches
     * the identity handler. Replies route via hybrid CIDR matching. */
    ck_assert_str_eq(observed, self_reported);

    free(inner);
    pthread_rwlock_destroy(&proc.protocol.peers_rwlock);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_unforwarded_broadcast_overwrites_with_transport_addr)
{
    /* Control: when the envelope flag is clear, the transport from_addr
     * wins (existing pre-stage-E behavior). Ensures we didn't break
     * direct-LAN discovery — the ONLY difference from test (a) is the
     * absence of NET_ENV_FLAG_FORWARDED. */
    const char *self_reported = "10.42.7.12";
    const char *sender_addr   = "10.1.0.51";

    uuid_t ANN;
    uuid_fill(ANN, 0xC2);

    size_t   inner_len = 0;
    uint8_t *inner = build_inner_wire(ANN, self_reported, &inner_len);
    ck_assert_int_eq((int)(inner != NULL), 1);

    uint8_t frame[1024];
    size_t  frame_len = 0;
    wrap_broadcast(ANN, /*flags*/ 0,
                   inner, inner_len, frame, sizeof(frame), &frame_len);

    process_t proc;
    init_proc_min(&proc);
    identity_t myself = {0};
    uuid_t ME; uuid_fill(ME, 0x03); memcpy(myself.uuid, ME, 16);

    mock_ctx_t mctx = { .is_gateway_flag = false };
    network_config_t net_cfg = { .port = 27787 };
    bool stop = false;
    logger_t logger = {0};
    net_thread_ctx_t tctx = {
        .transport = &mock_transport,
        .ctx       = (net_transport_ctx_t *)&mctx,
        .proc      = &proc,
        .logger    = &logger,
        .net_cfg   = &net_cfg,
        .myself    = &myself,
        .stop      = &stop,
    };

    net_proc_test_reset_last_routed_from_addr();
    handle_inbound_broadcast(&tctx, frame, frame_len, sender_addr);

    char observed[64] = {0};
    net_proc_test_get_last_routed_from_addr(observed, sizeof(observed));

    ck_assert_str_eq(observed, sender_addr);

    free(inner);
    pthread_rwlock_destroy(&proc.protocol.peers_rwlock);
}
END_TEST_DEFINITION()

RUN_TESTS(Discovery_Cross_Cluster,
          test_forwarded_broadcast_preserves_self_reported_address,
          test_unforwarded_broadcast_overwrites_with_transport_addr)
