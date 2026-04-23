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
 * @file envelope_group_forward_test.c
 * @brief Integration test for handle_inbound_group's cross-group forward
 *        path (at-over-dtn.md §4.3 stage F), gated by AT_NET_GROUP_FORWARD.
 *
 * Drives handle_inbound_group with crafted GROUP envelopes through a mock
 * transport whose send_on_leg captures the re-emitted frame. Asserts:
 *   (a) gateway + configured route + fresh fingerprint → forwarded;
 *   (b) gateway + no matching route → dropped (no send);
 *   (c) non-gateway + configured route → dropped;
 *   (d) replay within dedup window → suppressed;
 *   (e) hop_count at NET_ENV_MAX_HOPS → dropped.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "network/net_envelope.h"
#include "network/net_proc_priv.h"
#include "network/net_transport.h"
#include "network/net_transport_hybrid.h"
#include "network/network.h"
#include "identity/identity.h"
#include "identity/identity_priv.h"

/* ---------- Mock transport ---------- */

#define MOCK_SEND_CAP 8

typedef struct {
    uint8_t *buf;
    size_t   len;
    size_t   leg_index;
    net_channel_t channel;
    int      port;
} mock_leg_send_t;

typedef struct mock_ctx_s {
    bool            is_gateway_flag;
    mock_leg_send_t legs[MOCK_SEND_CAP];
    size_t          n_legs;
} mock_ctx_t;

static int mock_send_unicast(net_transport_ctx_t *c, const uint8_t *w, size_t wl,
                             const char *t, int p)
{ (void)c; (void)w; (void)wl; (void)t; (void)p; return -1; }

static int mock_send_broadcast(net_transport_ctx_t *c, net_channel_t ch,
                               const uint8_t *w, size_t wl, int p)
{ (void)c; (void)ch; (void)w; (void)wl; (void)p; return -1; }

static int mock_send_on_leg(net_transport_ctx_t *ctx_opaque, size_t leg_index,
                            net_channel_t channel,
                            const uint8_t *wire, size_t wire_len, int port)
{
    mock_ctx_t *ctx = (mock_ctx_t *)ctx_opaque;
    if (ctx->n_legs >= MOCK_SEND_CAP) return -1;
    mock_leg_send_t *s = &ctx->legs[ctx->n_legs++];
    s->buf = malloc(wire_len);
    if (s->buf == NULL) return -1;
    memcpy(s->buf, wire, wire_len);
    s->len       = wire_len;
    s->leg_index = leg_index;
    s->channel   = channel;
    s->port      = port;
    return 0;
}

static int mock_recv(net_transport_ctx_t *c, net_channel_t ch,
                     uint8_t **b, size_t *l, char *pa, size_t pal, int t)
{ (void)c; (void)ch; (void)b; (void)l; (void)pa; (void)pal; (void)t; return ENOMSG; }

static void mock_close(net_transport_ctx_t *c) { (void)c; }

static bool mock_is_gateway(const net_transport_ctx_t *ctx_opaque)
{
    const mock_ctx_t *ctx = (const mock_ctx_t *)ctx_opaque;
    return ctx->is_gateway_flag;
}

static const net_transport_t mock_transport = {
    .name           = "mock_group_fwd",
    .open           = NULL,
    .send_unicast   = mock_send_unicast,
    .send_broadcast = mock_send_broadcast,
    .recv           = mock_recv,
    .close          = mock_close,
    .is_gateway     = mock_is_gateway,
    .send_on_leg    = mock_send_on_leg,
};

static void mock_ctx_reset(mock_ctx_t *m)
{
    for (size_t i = 0; i < m->n_legs; i++) free(m->legs[i].buf);
    m->n_legs = 0;
}

/* ---------- Helpers ---------- */

static void uuid_fill(uuid_t u, uint8_t seed)
{
    for (size_t i = 0; i < 16; i++) u[i] = (uint8_t)(seed + i);
}

static void build_group_envelope(const uuid_t src, const uuid_t dst_group,
                                 uint8_t hop_count,
                                 const uint8_t *payload, size_t payload_len,
                                 uint8_t *out_frame, size_t out_cap,
                                 size_t *out_len)
{
    net_envelope_t env = {
        .version   = NET_ENV_VERSION,
        .type      = NET_ENV_TYPE_GROUP,
        .flags     = 0,
        .hop_count = hop_count,
    };
    memcpy(env.src_uuid, src, 16);
    memcpy(env.dst_uuid, dst_group, 16);
    int rc = net_envelope_pack(&env, payload, payload_len,
                               out_frame, out_cap, out_len);
    (void)rc;
}

/* Build a process stub with peers_rwlock + empty group membership. Unlike
 * net_proc_relay_test, the gateway here is NOT in the destination group. */
static void init_proc_min(process_t *proc)
{
    memset(proc, 0, sizeof(*proc));
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    /* group.address left empty so local-delivery branch would bail if
     * reached — forward path runs before that check. */
}

/* Build a hybrid_config_t mapping group_uuid -> leg_index. */
static void init_hcfg_with_route(hybrid_config_t *hcfg,
                                 const uuid_t group_uuid, size_t leg_index)
{
    memset(hcfg, 0, sizeof(*hcfg));
    hcfg->n_inners     = leg_index + 1;     /* satisfies lookup bounds check */
    hcfg->is_gateway   = true;
    memcpy(hcfg->group_routes[0].group_uuid, group_uuid, 16);
    hcfg->group_routes[0].leg_index = leg_index;
    hcfg->n_group_routes = 1;
}

/* ---------- Tests ---------- */

DEFINE_TEST(test_gateway_forwards_group_with_matching_route)
{
    uuid_t SRC, GROUP_REMOTE;
    uuid_fill(SRC, 0xA1);
    uuid_fill(GROUP_REMOTE, 0xB1);

    process_t proc;
    init_proc_min(&proc);
    identity_t myself = {0};
    uuid_t ME; uuid_fill(ME, 0x01);
    memcpy(myself.uuid, ME, 16);

    hybrid_config_t hcfg;
    init_hcfg_with_route(&hcfg, GROUP_REMOTE, /*leg*/ 1);

    mock_ctx_t mctx = { .is_gateway_flag = true };
    network_config_t net_cfg = { .port = 27787 };
    bool stop = false;
    logger_t logger = {0};
    net_thread_ctx_t tctx = {
        .transport     = &mock_transport,
        .ctx           = (net_transport_ctx_t *)&mctx,
        .proc          = &proc,
        .logger        = &logger,
        .net_cfg       = &net_cfg,
        .myself        = &myself,
        .stop          = &stop,
        .transport_cfg = &hcfg,
    };

    const uint8_t payload[] = "FWD-payload-A";
    uint8_t frame[128];
    size_t  frame_len = 0;
    build_group_envelope(SRC, GROUP_REMOTE, /*hop*/ 0,
                         payload, sizeof(payload) - 1,
                         frame, sizeof(frame), &frame_len);

    handle_inbound_group(&tctx, frame, frame_len, "10.1.0.2");

    /* Exactly one forward on the configured leg. */
    ck_assert_int_eq((int)mctx.n_legs, 1);
    ck_assert_int_eq((int)mctx.legs[0].leg_index, 1);
    ck_assert_int_eq((int)mctx.legs[0].channel, (int)NET_CHAN_GROUP);

    /* Forwarded frame: hop_count++, FORWARDED flag set; src/dst preserved. */
    net_envelope_t out_env;
    const uint8_t *out_pay = NULL; size_t out_plen = 0;
    ck_assert_ret_ok(net_envelope_unpack(mctx.legs[0].buf, mctx.legs[0].len,
                                         &out_env, &out_pay, &out_plen));
    ck_assert_int_eq((int)out_env.hop_count, 1);
    ck_assert_int_eq((int)(out_env.flags & NET_ENV_FLAG_FORWARDED), NET_ENV_FLAG_FORWARDED);
    ck_assert_int_eq((int)memcmp(out_env.src_uuid, SRC, 16), 0);
    ck_assert_int_eq((int)memcmp(out_env.dst_uuid, GROUP_REMOTE, 16), 0);

    mock_ctx_reset(&mctx);
    pthread_rwlock_destroy(&proc.protocol.peers_rwlock);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_gateway_without_route_drops_group)
{
    uuid_t SRC, GROUP_UNKNOWN, GROUP_CONFIGURED;
    uuid_fill(SRC, 0xA2);
    uuid_fill(GROUP_UNKNOWN,    0xB2);
    uuid_fill(GROUP_CONFIGURED, 0xB3);

    process_t proc;
    init_proc_min(&proc);
    identity_t myself = {0};
    uuid_t ME; uuid_fill(ME, 0x02); memcpy(myself.uuid, ME, 16);

    /* Route table has ONE entry — for a DIFFERENT group. */
    hybrid_config_t hcfg;
    init_hcfg_with_route(&hcfg, GROUP_CONFIGURED, /*leg*/ 1);

    mock_ctx_t mctx = { .is_gateway_flag = true };
    network_config_t net_cfg = { .port = 27787 };
    bool stop = false;
    logger_t logger = {0};
    net_thread_ctx_t tctx = {
        .transport     = &mock_transport,
        .ctx           = (net_transport_ctx_t *)&mctx,
        .proc          = &proc,
        .logger        = &logger,
        .net_cfg       = &net_cfg,
        .myself        = &myself,
        .stop          = &stop,
        .transport_cfg = &hcfg,
    };

    const uint8_t payload[] = "FWD-payload-unk";
    uint8_t frame[128];
    size_t  frame_len = 0;
    build_group_envelope(SRC, GROUP_UNKNOWN, 0,
                         payload, sizeof(payload) - 1,
                         frame, sizeof(frame), &frame_len);

    handle_inbound_group(&tctx, frame, frame_len, "10.1.0.2");

    ck_assert_int_eq((int)mctx.n_legs, 0);

    mock_ctx_reset(&mctx);
    pthread_rwlock_destroy(&proc.protocol.peers_rwlock);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_non_gateway_does_not_forward_group)
{
    uuid_t SRC, GROUP_REMOTE;
    uuid_fill(SRC, 0xA3);
    uuid_fill(GROUP_REMOTE, 0xB4);

    process_t proc;
    init_proc_min(&proc);
    identity_t myself = {0};
    uuid_t ME; uuid_fill(ME, 0x03); memcpy(myself.uuid, ME, 16);

    hybrid_config_t hcfg;
    init_hcfg_with_route(&hcfg, GROUP_REMOTE, 1);
    hcfg.is_gateway = false;  /* ignored — the runtime check goes through
                               * transport->is_gateway below. */

    mock_ctx_t mctx = { .is_gateway_flag = false };  /* NOT a gateway */
    network_config_t net_cfg = { .port = 27787 };
    bool stop = false;
    logger_t logger = {0};
    net_thread_ctx_t tctx = {
        .transport     = &mock_transport,
        .ctx           = (net_transport_ctx_t *)&mctx,
        .proc          = &proc,
        .logger        = &logger,
        .net_cfg       = &net_cfg,
        .myself        = &myself,
        .stop          = &stop,
        .transport_cfg = &hcfg,
    };

    const uint8_t payload[] = "FWD-payload-nongw";
    uint8_t frame[128];
    size_t  frame_len = 0;
    build_group_envelope(SRC, GROUP_REMOTE, 0,
                         payload, sizeof(payload) - 1,
                         frame, sizeof(frame), &frame_len);

    handle_inbound_group(&tctx, frame, frame_len, "10.1.0.2");

    ck_assert_int_eq((int)mctx.n_legs, 0);

    mock_ctx_reset(&mctx);
    pthread_rwlock_destroy(&proc.protocol.peers_rwlock);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_gateway_dedups_duplicate_group_forward)
{
    uuid_t SRC, GROUP_REMOTE;
    uuid_fill(SRC, 0xA4);
    uuid_fill(GROUP_REMOTE, 0xB5);

    process_t proc;
    init_proc_min(&proc);
    identity_t myself = {0};
    uuid_t ME; uuid_fill(ME, 0x04); memcpy(myself.uuid, ME, 16);

    hybrid_config_t hcfg;
    init_hcfg_with_route(&hcfg, GROUP_REMOTE, 1);

    mock_ctx_t mctx = { .is_gateway_flag = true };
    network_config_t net_cfg = { .port = 27787 };
    bool stop = false;
    logger_t logger = {0};
    net_thread_ctx_t tctx = {
        .transport     = &mock_transport,
        .ctx           = (net_transport_ctx_t *)&mctx,
        .proc          = &proc,
        .logger        = &logger,
        .net_cfg       = &net_cfg,
        .myself        = &myself,
        .stop          = &stop,
        .transport_cfg = &hcfg,
    };

    const uint8_t payload[] = "DEDUP-SAME";
    const size_t  pl        = sizeof(payload) - 1;

    uint8_t frame1[128]; size_t f1_len = 0;
    build_group_envelope(SRC, GROUP_REMOTE, 0, payload, pl,
                         frame1, sizeof(frame1), &f1_len);
    handle_inbound_group(&tctx, frame1, f1_len, "10.1.0.2");

    uint8_t frame2[128]; size_t f2_len = 0;
    build_group_envelope(SRC, GROUP_REMOTE, 0, payload, pl,
                         frame2, sizeof(frame2), &f2_len);
    handle_inbound_group(&tctx, frame2, f2_len, "10.1.0.2");

    /* Dedup ring suppresses the second forward. */
    ck_assert_int_eq((int)mctx.n_legs, 1);

    mock_ctx_reset(&mctx);
    pthread_rwlock_destroy(&proc.protocol.peers_rwlock);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_gateway_drops_group_at_hop_exhaustion)
{
    uuid_t SRC, GROUP_REMOTE;
    uuid_fill(SRC, 0xA5);
    uuid_fill(GROUP_REMOTE, 0xB6);

    process_t proc;
    init_proc_min(&proc);
    identity_t myself = {0};
    uuid_t ME; uuid_fill(ME, 0x05); memcpy(myself.uuid, ME, 16);

    hybrid_config_t hcfg;
    init_hcfg_with_route(&hcfg, GROUP_REMOTE, 1);

    mock_ctx_t mctx = { .is_gateway_flag = true };
    network_config_t net_cfg = { .port = 27787 };
    bool stop = false;
    logger_t logger = {0};
    net_thread_ctx_t tctx = {
        .transport     = &mock_transport,
        .ctx           = (net_transport_ctx_t *)&mctx,
        .proc          = &proc,
        .logger        = &logger,
        .net_cfg       = &net_cfg,
        .myself        = &myself,
        .stop          = &stop,
        .transport_cfg = &hcfg,
    };

    const uint8_t payload[] = "HOP-CAPPED";
    uint8_t frame[128]; size_t frame_len = 0;
    /* hop_count already at the protocol ceiling — should_forward_group → false. */
    build_group_envelope(SRC, GROUP_REMOTE, NET_ENV_MAX_HOPS,
                         payload, sizeof(payload) - 1,
                         frame, sizeof(frame), &frame_len);
    handle_inbound_group(&tctx, frame, frame_len, "10.1.0.2");

    ck_assert_int_eq((int)mctx.n_legs, 0);

    mock_ctx_reset(&mctx);
    pthread_rwlock_destroy(&proc.protocol.peers_rwlock);
}
END_TEST_DEFINITION()

RUN_TESTS(Envelope_Group_Forward,
          test_gateway_forwards_group_with_matching_route,
          test_gateway_without_route_drops_group,
          test_non_gateway_does_not_forward_group,
          test_gateway_dedups_duplicate_group_forward,
          test_gateway_drops_group_at_hop_exhaustion)
