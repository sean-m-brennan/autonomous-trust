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
 * @file broadcast_except_leg_test.c
 * @brief Per-leg broadcast exclusion (at-over-dtn D-followup).
 *
 * Verifies that handle_inbound_broadcast, when the transport reports a
 * valid last_recv_leg and provides send_broadcast_except_leg, uses the
 * except-leg path rather than fanning out to every leg. Covers the
 * fallback path too: a transport without the new vtable slots still
 * gets send_broadcast (unchanged Stage D behavior).
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
#include "network/network.h"
#include "identity/identity.h"
#include "identity/identity_priv.h"

/* ---------- Mock transport with the new vtable slots ---------- */

typedef struct {
    uint8_t *buf;
    size_t   len;
    size_t   except_leg;
    bool     had_except_leg;  /* true iff captured via send_broadcast_except_leg */
} mock_send_t;

typedef struct mock_ctx_s {
    bool         is_gateway_flag;
    int          next_leg;       /* what last_recv_leg returns */
    bool         has_except_api; /* toggle the except_leg vtable slot on/off */
    mock_send_t  bcasts[8];
    size_t       n_bcasts;
} mock_ctx_t;

static int mock_send_unicast(net_transport_ctx_t *c, const uint8_t *w, size_t wl,
                             const char *t, int p)
{ (void)c; (void)w; (void)wl; (void)t; (void)p; return -1; }

static int mock_send_broadcast(net_transport_ctx_t *ctx_opaque, net_channel_t ch,
                               const uint8_t *wire, size_t wire_len, int port)
{
    (void)ch; (void)port;
    mock_ctx_t *ctx = (mock_ctx_t *)ctx_opaque;
    if (ctx->n_bcasts >= 8) return -1;
    mock_send_t *s = &ctx->bcasts[ctx->n_bcasts++];
    s->buf = malloc(wire_len);
    if (s->buf == NULL) return -1;
    memcpy(s->buf, wire, wire_len);
    s->len = wire_len;
    s->had_except_leg = false;
    return 0;
}

static int mock_send_broadcast_except_leg(net_transport_ctx_t *ctx_opaque,
                                          net_channel_t ch,
                                          const uint8_t *wire, size_t wire_len,
                                          int port, size_t except_leg)
{
    (void)ch; (void)port;
    mock_ctx_t *ctx = (mock_ctx_t *)ctx_opaque;
    if (ctx->n_bcasts >= 8) return -1;
    mock_send_t *s = &ctx->bcasts[ctx->n_bcasts++];
    s->buf = malloc(wire_len);
    if (s->buf == NULL) return -1;
    memcpy(s->buf, wire, wire_len);
    s->len            = wire_len;
    s->except_leg     = except_leg;
    s->had_except_leg = true;
    return 0;
}

static int mock_recv(net_transport_ctx_t *c, net_channel_t ch,
                     uint8_t **b, size_t *l, char *pa, size_t pal, int t)
{ (void)c; (void)ch; (void)b; (void)l; (void)pa; (void)pal; (void)t; return ENOMSG; }

static void mock_close(net_transport_ctx_t *c) { (void)c; }

static bool mock_is_gateway(const net_transport_ctx_t *c)
{ return ((const mock_ctx_t *)c)->is_gateway_flag; }

static int mock_last_recv_leg(const net_transport_ctx_t *c, net_channel_t ch)
{ (void)ch; return ((const mock_ctx_t *)c)->next_leg; }

/* Two flavors: one that implements the new vtable slots, one that doesn't.
 * Selecting via the mock_ctx->has_except_api flag lets a single test
 * binary cover both paths. */
static const net_transport_t mock_with_except = {
    .name                      = "mock_except",
    .send_unicast              = mock_send_unicast,
    .send_broadcast            = mock_send_broadcast,
    .recv                      = mock_recv,
    .close                     = mock_close,
    .is_gateway                = mock_is_gateway,
    .last_recv_leg             = mock_last_recv_leg,
    .send_broadcast_except_leg = mock_send_broadcast_except_leg,
};

static const net_transport_t mock_without_except = {
    .name           = "mock_no_except",
    .send_unicast   = mock_send_unicast,
    .send_broadcast = mock_send_broadcast,
    .recv           = mock_recv,
    .close          = mock_close,
    .is_gateway     = mock_is_gateway,
    /* .last_recv_leg / .send_broadcast_except_leg left NULL */
};

static void mock_reset(mock_ctx_t *m)
{
    for (size_t i = 0; i < m->n_bcasts; i++) free(m->bcasts[i].buf);
    m->n_bcasts = 0;
}

/* ---------- Helpers ---------- */

static void uuid_fill(uuid_t u, uint8_t seed)
{
    for (size_t i = 0; i < 16; i++) u[i] = (uint8_t)(seed + i);
}

static void build_bcast_envelope(const uuid_t src, uint8_t hop_count,
                                 const uint8_t *payload, size_t payload_len,
                                 uint8_t *out_frame, size_t out_cap,
                                 size_t *out_len)
{
    static const uuid_t NIL = {0};
    net_envelope_t env = {
        .version   = NET_ENV_VERSION,
        .type      = NET_ENV_TYPE_BROADCAST,
        .flags     = 0,
        .hop_count = hop_count,
    };
    memcpy(env.src_uuid, src, 16);
    memcpy(env.dst_uuid, NIL, 16);
    int rc = net_envelope_pack(&env, payload, payload_len,
                               out_frame, out_cap, out_len);
    (void)rc;
}

static void init_proc_min(process_t *proc)
{
    memset(proc, 0, sizeof(*proc));
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
}

/* ---------- Tests ---------- */

DEFINE_TEST(test_gateway_forward_uses_except_leg_path)
{
    uuid_t SRC;
    uuid_fill(SRC, 0xD1);

    process_t proc;
    init_proc_min(&proc);
    identity_t myself = {0};
    uuid_t ME; uuid_fill(ME, 0x01);
    memcpy(myself.uuid, ME, 16);

    mock_ctx_t mctx = {
        .is_gateway_flag = true,
        .next_leg        = 1,        /* say this frame came in on leg 1 */
        .has_except_api  = true,
    };
    network_config_t net_cfg = { .port = 27787 };
    bool stop = false;
    logger_t logger = {0};
    net_thread_ctx_t tctx = {
        .transport = &mock_with_except,
        .ctx       = (net_transport_ctx_t *)&mctx,
        .proc      = &proc,
        .logger    = &logger,
        .net_cfg   = &net_cfg,
        .myself    = &myself,
        .stop      = &stop,
    };

    const uint8_t payload[] = "D-FOLLOWUP-except-leg-1";
    uint8_t frame[256]; size_t frame_len = 0;
    build_bcast_envelope(SRC, /*hop*/ 0, payload, sizeof(payload) - 1,
                         frame, sizeof(frame), &frame_len);

    handle_inbound_broadcast(&tctx, frame, frame_len, "10.1.0.2");

    /* Exactly one send — and it went through the except-leg vtable slot
     * with except_leg = the reported origin leg. */
    ck_assert_int_eq((int)mctx.n_bcasts, 1);
    ck_assert_int_eq((int)mctx.bcasts[0].had_except_leg, 1);
    ck_assert_int_eq((int)mctx.bcasts[0].except_leg, 1);

    mock_reset(&mctx);
    pthread_rwlock_destroy(&proc.protocol.peers_rwlock);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_gateway_forward_falls_back_when_except_api_absent)
{
    /* Transport without last_recv_leg / send_broadcast_except_leg: the
     * handler must still forward via the legacy send_broadcast path. */
    uuid_t SRC;
    uuid_fill(SRC, 0xD2);

    process_t proc;
    init_proc_min(&proc);
    identity_t myself = {0};
    uuid_t ME; uuid_fill(ME, 0x02);
    memcpy(myself.uuid, ME, 16);

    mock_ctx_t mctx = {
        .is_gateway_flag = true,
        .next_leg        = 1,
        .has_except_api  = false,
    };
    network_config_t net_cfg = { .port = 27787 };
    bool stop = false;
    logger_t logger = {0};
    net_thread_ctx_t tctx = {
        .transport = &mock_without_except,
        .ctx       = (net_transport_ctx_t *)&mctx,
        .proc      = &proc,
        .logger    = &logger,
        .net_cfg   = &net_cfg,
        .myself    = &myself,
        .stop      = &stop,
    };

    const uint8_t payload[] = "D-FOLLOWUP-fallback";
    uint8_t frame[256]; size_t frame_len = 0;
    build_bcast_envelope(SRC, 0, payload, sizeof(payload) - 1,
                         frame, sizeof(frame), &frame_len);

    handle_inbound_broadcast(&tctx, frame, frame_len, "10.1.0.2");

    /* Legacy send_broadcast path — had_except_leg must be false. */
    ck_assert_int_eq((int)mctx.n_bcasts, 1);
    ck_assert_int_eq((int)mctx.bcasts[0].had_except_leg, 0);

    mock_reset(&mctx);
    pthread_rwlock_destroy(&proc.protocol.peers_rwlock);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_gateway_forward_falls_back_when_leg_unknown)
{
    /* Transport advertises last_recv_leg but returns -1 (no prior recv).
     * Must still forward — via send_broadcast, not except_leg. */
    uuid_t SRC;
    uuid_fill(SRC, 0xD3);

    process_t proc;
    init_proc_min(&proc);
    identity_t myself = {0};
    uuid_t ME; uuid_fill(ME, 0x03);
    memcpy(myself.uuid, ME, 16);

    mock_ctx_t mctx = {
        .is_gateway_flag = true,
        .next_leg        = -1,   /* unknown */
        .has_except_api  = true,
    };
    network_config_t net_cfg = { .port = 27787 };
    bool stop = false;
    logger_t logger = {0};
    net_thread_ctx_t tctx = {
        .transport = &mock_with_except,
        .ctx       = (net_transport_ctx_t *)&mctx,
        .proc      = &proc,
        .logger    = &logger,
        .net_cfg   = &net_cfg,
        .myself    = &myself,
        .stop      = &stop,
    };

    const uint8_t payload[] = "D-FOLLOWUP-leg-unknown";
    uint8_t frame[256]; size_t frame_len = 0;
    build_bcast_envelope(SRC, 0, payload, sizeof(payload) - 1,
                         frame, sizeof(frame), &frame_len);

    handle_inbound_broadcast(&tctx, frame, frame_len, "10.1.0.2");

    ck_assert_int_eq((int)mctx.n_bcasts, 1);
    /* leg_index < 0 → fallback path, no except_leg. */
    ck_assert_int_eq((int)mctx.bcasts[0].had_except_leg, 0);

    mock_reset(&mctx);
    pthread_rwlock_destroy(&proc.protocol.peers_rwlock);
}
END_TEST_DEFINITION()

RUN_TESTS(Broadcast_Except_Leg,
          test_gateway_forward_uses_except_leg_path,
          test_gateway_forward_falls_back_when_except_api_absent,
          test_gateway_forward_falls_back_when_leg_unknown)
