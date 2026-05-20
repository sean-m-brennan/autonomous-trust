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
 * @file net_proc_relay_test.c
 * @brief Integration test for net_proc.c's envelope-forwarding plumbing.
 *
 * Drives the real handle_inbound_peer() (extracted from
 * peer_receiver_thread) with crafted wire bytes through a mock
 * transport, asserting the gateway FORWARD path produces the expected
 * send_unicast call on the opposite leg — without bringing up
 * daemonize()'d processes or real sockets.
 *
 * Covered:
 *   - Gateway receives a PEER envelope for someone else → forwards with
 *     bumped hop_count + FORWARDED flag, address resolved from peer UUID.
 *   - Non-gateway drops an envelope for someone else (no send).
 *   - Envelope addressed to the local node is delivered (no send).
 *
 * Full crypto round-tripping (A → G → B with real libsodium encrypt /
 * decrypt) is out of scope for this slice; envelope_relay_test already
 * covers the wire contract, and this test pins down that net_proc.c
 * calls the forward/classify helpers correctly.
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

/* ---------- Mock transport ---------- */

#define MOCK_SEND_CAP 8

typedef struct {
    uint8_t *buf;
    size_t   len;
    char     target[ADDR_LEN + 1];
    int      port;
} mock_send_t;

typedef struct mock_ctx_s {
    bool        is_gateway_flag;
    mock_send_t sends[MOCK_SEND_CAP];
    size_t      n_sends;
    mock_send_t bcasts[MOCK_SEND_CAP];  /* captured send_broadcast calls */
    size_t      n_bcasts;
} mock_ctx_t;

static int mock_send_unicast(net_transport_ctx_t *ctx_opaque,
                             const uint8_t *wire, size_t wire_len,
                             const char *target, int port)
{
    mock_ctx_t *ctx = (mock_ctx_t *)ctx_opaque;
    if (ctx->n_sends >= MOCK_SEND_CAP) return -1;
    mock_send_t *s = &ctx->sends[ctx->n_sends++];
    s->buf = malloc(wire_len);
    if (s->buf == NULL) return -1;
    memcpy(s->buf, wire, wire_len);
    s->len  = wire_len;
    s->port = port;
    snprintf(s->target, sizeof(s->target), "%s", target);
    return 0;
}

static int mock_send_broadcast(net_transport_ctx_t *ctx_opaque, net_channel_t ch,
                               const uint8_t *wire, size_t wire_len, int port)
{
    (void)ch;
    mock_ctx_t *ctx = (mock_ctx_t *)ctx_opaque;
    if (ctx->n_bcasts >= MOCK_SEND_CAP) return -1;
    mock_send_t *s = &ctx->bcasts[ctx->n_bcasts++];
    s->buf = malloc(wire_len);
    if (s->buf == NULL) return -1;
    memcpy(s->buf, wire, wire_len);
    s->len    = wire_len;
    s->port   = port;
    s->target[0] = '\0';
    return 0;
}

static int mock_recv(net_transport_ctx_t *ctx, net_channel_t ch,
                     uint8_t **out_buf, size_t *out_len,
                     char *peer_addr, size_t peer_addr_len, int timeout_ms)
{
    (void)ctx; (void)ch; (void)out_buf; (void)out_len;
    (void)peer_addr; (void)peer_addr_len; (void)timeout_ms;
    return ENOMSG;
}

static void mock_close(net_transport_ctx_t *ctx) { (void)ctx; }

static bool mock_is_gateway(const net_transport_ctx_t *ctx_opaque)
{
    const mock_ctx_t *ctx = (const mock_ctx_t *)ctx_opaque;
    return ctx->is_gateway_flag;
}

static const net_transport_t mock_transport = {
    .name           = "mock_net",
    .open           = NULL,  /* we hand-build the ctx */
    .send_unicast   = mock_send_unicast,
    .send_broadcast = mock_send_broadcast,
    .recv           = mock_recv,
    .close          = mock_close,
    .is_gateway     = mock_is_gateway,
};

static void mock_ctx_reset(mock_ctx_t *mctx)
{
    for (size_t i = 0; i < mctx->n_sends; i++)
        free(mctx->sends[i].buf);
    mctx->n_sends = 0;
    for (size_t i = 0; i < mctx->n_bcasts; i++)
        free(mctx->bcasts[i].buf);
    mctx->n_bcasts = 0;
}

/* ---------- Test harness plumbing ---------- */

/* Hand-assemble the minimum state handle_inbound_peer() reads. process_init
 * would pull from JSON configs + spawn a daemon; we only need peers_rwlock
 * initialized and peers[] populated. */
static void init_proc_min(process_t *proc, const uuid_t my_uuid,
                          const uuid_t peer_b_uuid, const char *peer_b_addr)
{
    memset(proc, 0, sizeof(*proc));
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);

    public_identity_t *b = &proc->protocol.peers[0];
    memcpy(b->uuid, peer_b_uuid, 16);
    snprintf(b->address, sizeof(b->address), "%s", peer_b_addr);
    snprintf(b->fullname, sizeof(b->fullname), "peer-B");
    proc->protocol.num_peers = 1;
    proc->protocol.peer_rtt_ms[0] = 50;
    (void)my_uuid;  /* identity carries my_uuid; the proc's own uuid isn't read */
}

static void uuid_fill(uuid_t u, uint8_t seed)
{
    for (size_t i = 0; i < 16; i++) u[i] = (uint8_t)(seed + i);
}

static void build_peer_envelope(net_env_type_t type,
                                const uuid_t src, const uuid_t dst,
                                uint8_t hop_count,
                                const uint8_t *payload, size_t payload_len,
                                uint8_t *out_frame, size_t out_cap,
                                size_t *out_len)
{
    net_envelope_t env = {
        .version   = NET_ENV_VERSION,
        .type      = type,
        .flags     = 0,
        .hop_count = hop_count,
    };
    memcpy(env.src_uuid, src, 16);
    memcpy(env.dst_uuid, dst, 16);
    int rc = net_envelope_pack(&env, payload, payload_len,
                               out_frame, out_cap, out_len);
    (void)rc;  /* tests check the out state; pack is covered elsewhere */
}

/* ---------- Tests ---------- */

DEFINE_TEST(test_gateway_forwards_peer_for_other)
{
    uuid_t G, A, B;
    uuid_fill(G, 0x30);
    uuid_fill(A, 0x10);
    uuid_fill(B, 0x20);

    process_t proc;
    init_proc_min(&proc, G, B, "10.99.0.2");  /* B registered at 10.99.0.2 */
    identity_t myself = {0};
    memcpy(myself.uuid, G, 16);

    mock_ctx_t mctx = { .is_gateway_flag = true };
    network_config_t net_cfg = { .port = 27787 };
    bool stop = false;
    logger_t logger = {0};
    net_thread_ctx_t tctx = {
        .transport = &mock_transport,
        .ctx       = (net_transport_ctx_t *)&mctx,
        .proc      = &proc,
        .queues    = NULL,
        .logger    = &logger,
        .net_cfg   = &net_cfg,
        .myself    = &myself,
        .stop      = &stop,
    };

    const uint8_t payload[] = "some-encrypted-bytes-opaque-to-the-gateway";
    uint8_t frame[256];
    size_t  frame_len = 0;
    build_peer_envelope(NET_ENV_TYPE_PEER, A, B, /*hop*/0,
                        payload, sizeof(payload) - 1,
                        frame, sizeof(frame), &frame_len);

    handle_inbound_peer(&tctx, frame, frame_len, "10.1.0.1");

    /* Gateway must have fired exactly one send_unicast to B's address. */
    ck_assert_int_eq((int)mctx.n_sends, 1);
    ck_assert_str_eq(mctx.sends[0].target, "10.99.0.2");
    ck_assert_int_eq(mctx.sends[0].port, 27787);

    /* The forwarded frame must still be parseable as an envelope with
     * src=A, dst=B, hop_count=1, FORWARDED set, payload unchanged. */
    net_envelope_t got;
    const uint8_t *pay_out = NULL;
    size_t         pay_out_len = 0;
    ck_assert_ret_ok(net_envelope_unpack(mctx.sends[0].buf,
                                         mctx.sends[0].len,
                                         &got, &pay_out, &pay_out_len));
    ck_assert_mem_eq(got.src_uuid, A, 16);
    ck_assert_mem_eq(got.dst_uuid, B, 16);
    ck_assert_int_eq(got.hop_count, 1);
    ck_assert_int_eq(got.flags & NET_ENV_FLAG_FORWARDED, NET_ENV_FLAG_FORWARDED);
    ck_assert_int_eq((int)pay_out_len, (int)sizeof(payload) - 1);
    ck_assert_mem_eq(pay_out, payload, sizeof(payload) - 1);

    mock_ctx_reset(&mctx);
    pthread_rwlock_destroy(&proc.protocol.peers_rwlock);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_non_gateway_drops_peer_for_other)
{
    uuid_t ME, A, B;
    uuid_fill(ME, 0xA0);
    uuid_fill(A,  0x10);
    uuid_fill(B,  0x20);

    process_t proc;
    init_proc_min(&proc, ME, B, "10.99.0.2");
    identity_t myself = {0};
    memcpy(myself.uuid, ME, 16);

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

    uint8_t pay[4] = {9, 9, 9, 9};
    uint8_t frame[128];
    size_t  frame_len = 0;
    build_peer_envelope(NET_ENV_TYPE_PEER, A, B, 0, pay, sizeof(pay),
                        frame, sizeof(frame), &frame_len);

    handle_inbound_peer(&tctx, frame, frame_len, "10.1.0.1");

    /* No send — the frame is not for me, and I'm not a gateway. */
    ck_assert_int_eq((int)mctx.n_sends, 0);

    mock_ctx_reset(&mctx);
    pthread_rwlock_destroy(&proc.protocol.peers_rwlock);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_gateway_does_not_forward_frame_for_self)
{
    /* A gateway should deliver locally when IT is the destination —
     * gateway mode does not force forwarding. */
    uuid_t G, A;
    uuid_fill(G, 0x30);
    uuid_fill(A, 0x10);

    process_t proc;
    init_proc_min(&proc, G, A, "10.1.0.1");  /* A registered */
    identity_t myself = {0};
    memcpy(myself.uuid, G, 16);

    mock_ctx_t mctx = { .is_gateway_flag = true };
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

    /* Craft a PEER envelope addressed to G itself.
     * The payload is intentionally a short blob that (a) isn't a valid
     * crypto_box ciphertext (decrypt_message will fail) and (b) isn't a
     * valid wire-msg (net_message_from_wire will fail), so the handler
     * returns without calling route_to_process — no AF_UNIX traffic. */
    uint8_t pay[4] = {1, 2, 3, 4};
    uint8_t frame[128];
    size_t  frame_len = 0;
    build_peer_envelope(NET_ENV_TYPE_PEER, A, G, 0, pay, sizeof(pay),
                        frame, sizeof(frame), &frame_len);

    handle_inbound_peer(&tctx, frame, frame_len, "10.1.0.1");

    /* Crucially: gateway did NOT forward to itself or anywhere else. */
    ck_assert_int_eq((int)mctx.n_sends, 0);

    mock_ctx_reset(&mctx);
    pthread_rwlock_destroy(&proc.protocol.peers_rwlock);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_gateway_drops_at_hop_exhaustion)
{
    /* Frame arrives at the gateway already at MAX_HOPS — must be dropped,
     * not forwarded. Mirrors envelope_relay_test's disposition assertion
     * but here through net_proc's actual handler code path. */
    uuid_t G, A, B;
    uuid_fill(G, 0x30);
    uuid_fill(A, 0x10);
    uuid_fill(B, 0x20);

    process_t proc;
    init_proc_min(&proc, G, B, "10.99.0.2");
    identity_t myself = {0};
    memcpy(myself.uuid, G, 16);

    mock_ctx_t mctx = { .is_gateway_flag = true };
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

    uint8_t pay[4] = {7, 7, 7, 7};
    uint8_t frame[128];
    size_t  frame_len = 0;
    build_peer_envelope(NET_ENV_TYPE_PEER, A, B,
                        /* hop */ NET_ENV_MAX_HOPS,
                        pay, sizeof(pay),
                        frame, sizeof(frame), &frame_len);

    handle_inbound_peer(&tctx, frame, frame_len, "10.1.0.1");

    ck_assert_int_eq((int)mctx.n_sends, 0);

    mock_ctx_reset(&mctx);
    pthread_rwlock_destroy(&proc.protocol.peers_rwlock);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_gateway_forwards_preserve_payload_through_multiple_gateways)
{
    /* Feed the OUTPUT of one gateway hop as the INPUT to a second
     * gateway, proving the pipeline composes: after two relays the
     * payload is unchanged and hop_count is 2. */
    uuid_t G1, G2, A, B;
    uuid_fill(G1, 0x30);
    uuid_fill(G2, 0x40);
    uuid_fill(A,  0x10);
    uuid_fill(B,  0x20);

    const char *B_ADDR = "10.99.0.2";

    process_t proc_g1; init_proc_min(&proc_g1, G1, B, B_ADDR);
    process_t proc_g2; init_proc_min(&proc_g2, G2, B, B_ADDR);
    identity_t id_g1 = {0}; memcpy(id_g1.uuid, G1, 16);
    identity_t id_g2 = {0}; memcpy(id_g2.uuid, G2, 16);
    network_config_t net_cfg = { .port = 27787 };
    bool stop = false;
    logger_t logger = {0};

    mock_ctx_t mctx1 = { .is_gateway_flag = true };
    net_thread_ctx_t tctx1 = {
        .transport = &mock_transport,
        .ctx = (net_transport_ctx_t *)&mctx1,
        .proc = &proc_g1, .logger = &logger,
        .net_cfg = &net_cfg, .myself = &id_g1, .stop = &stop,
    };

    const uint8_t payload[] = "payload-that-must-survive-two-gateway-hops";
    const size_t  payload_len = sizeof(payload) - 1;
    uint8_t frame[256];
    size_t  frame_len = 0;
    build_peer_envelope(NET_ENV_TYPE_PEER, A, B, 0,
                        payload, payload_len, frame, sizeof(frame), &frame_len);

    handle_inbound_peer(&tctx1, frame, frame_len, "10.1.0.1");
    ck_assert_int_eq((int)mctx1.n_sends, 1);

    /* Feed G1's output into G2 unchanged. */
    mock_ctx_t mctx2 = { .is_gateway_flag = true };
    net_thread_ctx_t tctx2 = {
        .transport = &mock_transport,
        .ctx = (net_transport_ctx_t *)&mctx2,
        .proc = &proc_g2, .logger = &logger,
        .net_cfg = &net_cfg, .myself = &id_g2, .stop = &stop,
    };

    handle_inbound_peer(&tctx2, mctx1.sends[0].buf, mctx1.sends[0].len,
                        "10.50.0.1");
    ck_assert_int_eq((int)mctx2.n_sends, 1);

    net_envelope_t got;
    const uint8_t *pay_out = NULL;
    size_t         pay_out_len = 0;
    ck_assert_ret_ok(net_envelope_unpack(mctx2.sends[0].buf,
                                         mctx2.sends[0].len,
                                         &got, &pay_out, &pay_out_len));
    ck_assert_int_eq(got.hop_count, 2);
    ck_assert_int_eq(got.flags & NET_ENV_FLAG_FORWARDED, NET_ENV_FLAG_FORWARDED);
    ck_assert_int_eq((int)pay_out_len, (int)payload_len);
    ck_assert_mem_eq(pay_out, payload, payload_len);

    mock_ctx_reset(&mctx1);
    mock_ctx_reset(&mctx2);
    pthread_rwlock_destroy(&proc_g1.protocol.peers_rwlock);
    pthread_rwlock_destroy(&proc_g2.protocol.peers_rwlock);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_gateway_drops_when_peer_not_in_registry)
{
    /* Envelope's dst_uuid has no matching peer in the gateway's registry
     * → envelope_forward() returns -1 without calling send_unicast. */
    uuid_t G, A, UNKNOWN, REGISTERED;
    uuid_fill(G, 0x30);
    uuid_fill(A, 0x10);
    uuid_fill(UNKNOWN,    0xFE);
    uuid_fill(REGISTERED, 0x20);

    process_t proc;
    init_proc_min(&proc, G, REGISTERED, "10.99.0.2");  /* only REGISTERED is known */
    identity_t myself = {0};
    memcpy(myself.uuid, G, 16);

    mock_ctx_t mctx = { .is_gateway_flag = true };
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

    uint8_t pay[4] = {0};
    uint8_t frame[128];
    size_t  frame_len = 0;
    build_peer_envelope(NET_ENV_TYPE_PEER, A, UNKNOWN, 0,
                        pay, sizeof(pay), frame, sizeof(frame), &frame_len);

    handle_inbound_peer(&tctx, frame, frame_len, "10.1.0.1");

    ck_assert_int_eq((int)mctx.n_sends, 0);

    mock_ctx_reset(&mctx);
    pthread_rwlock_destroy(&proc.protocol.peers_rwlock);
}
END_TEST_DEFINITION()

/* ---------- Broadcast-forwarding tests (stage D) ----------
 *
 * Each test exercises handle_inbound_broadcast() with envelope bytes and
 * asserts that the mock transport's send_broadcast was (or wasn't) invoked
 * with a properly mutated frame.
 *
 * NOTE: the dedup ring in net_proc.c is PROCESS-GLOBAL, not per-test. Tests
 * that rely on "new" fingerprints use a unique src_uuid to avoid collisions
 * with entries left by sibling tests. */

/* Build a BROADCAST envelope for a test. dst_uuid is always NIL. */
static void build_bcast_envelope(const uuid_t src, uint8_t hop_count,
                                 const uint8_t *payload, size_t payload_len,
                                 uint8_t *out_frame, size_t out_cap,
                                 size_t *out_len)
{
    static const uuid_t NIL_DST = {0};
    build_peer_envelope(NET_ENV_TYPE_BROADCAST, src, NIL_DST, hop_count,
                        payload, payload_len, out_frame, out_cap, out_len);
}

DEFINE_TEST(test_gateway_forwards_broadcast_once)
{
    /* Gateway receives a BROADCAST → delivers locally (no assertion here;
     * route_to_process would fail harmlessly without a real queue) AND
     * re-emits on the same transport with hop_count bumped + FORWARDED. */
    uuid_t SRC;
    uuid_fill(SRC, 0xB0);  /* unique seed — won't collide with sibling tests */

    process_t proc;
    uuid_t dummy_peer;
    uuid_fill(dummy_peer, 0xEE);
    init_proc_min(&proc, SRC, dummy_peer, "10.99.0.9");  /* peer irrelevant for bcast */
    identity_t myself = {0};
    uuid_t G;
    uuid_fill(G, 0x31);
    memcpy(myself.uuid, G, 16);

    mock_ctx_t mctx = { .is_gateway_flag = true };
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

    const uint8_t payload[] = "DISCOVERY-BCAST-PAYLOAD-D1";
    const size_t  payload_len = sizeof(payload) - 1;
    uint8_t frame[256];
    size_t  frame_len = 0;
    build_bcast_envelope(SRC, /*hop*/ 0, payload, payload_len,
                         frame, sizeof(frame), &frame_len);

    handle_inbound_broadcast(&tctx, frame, frame_len, "10.1.0.2");

    /* Gateway must have re-emitted exactly once via send_broadcast. */
    ck_assert_int_eq((int)mctx.n_bcasts, 1);
    ck_assert_int_eq((int)mctx.n_sends,  0);  /* unicast path untouched */
    ck_assert_int_eq(mctx.bcasts[0].port, 27787);

    /* Forwarded frame: src preserved, hop bumped, FORWARDED set, payload intact. */
    net_envelope_t got;
    const uint8_t *pay_out = NULL;
    size_t         pay_out_len = 0;
    ck_assert_ret_ok(net_envelope_unpack(mctx.bcasts[0].buf, mctx.bcasts[0].len,
                                         &got, &pay_out, &pay_out_len));
    ck_assert_int_eq((int)got.type, (int)NET_ENV_TYPE_BROADCAST);
    ck_assert_mem_eq(got.src_uuid, SRC, 16);
    ck_assert_int_eq(got.hop_count, 1);
    ck_assert_int_eq(got.flags & NET_ENV_FLAG_FORWARDED, NET_ENV_FLAG_FORWARDED);
    ck_assert_int_eq((int)pay_out_len, (int)payload_len);
    ck_assert_mem_eq(pay_out, payload, payload_len);

    mock_ctx_reset(&mctx);
    pthread_rwlock_destroy(&proc.protocol.peers_rwlock);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_gateway_dedups_duplicate_broadcast)
{
    /* Feed the SAME broadcast frame twice. First hit: forwarded. Second
     * hit: the dedup ring suppresses re-forward — exactly one send_broadcast
     * call on the mock transport across both invocations. */
    uuid_t SRC;
    uuid_fill(SRC, 0xB1);

    process_t proc;
    uuid_t dummy_peer;
    uuid_fill(dummy_peer, 0xEE);
    init_proc_min(&proc, SRC, dummy_peer, "10.99.0.9");
    identity_t myself = {0};
    uuid_t G;
    uuid_fill(G, 0x32);
    memcpy(myself.uuid, G, 16);

    mock_ctx_t mctx = { .is_gateway_flag = true };
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

    const uint8_t payload[] = "DEDUP-SAME-PAYLOAD";
    const size_t  payload_len = sizeof(payload) - 1;

    /* Re-pack per invocation because the handler mutates the frame buffer. */
    uint8_t frame1[128];
    size_t  f1_len = 0;
    build_bcast_envelope(SRC, 0, payload, payload_len, frame1, sizeof(frame1), &f1_len);
    handle_inbound_broadcast(&tctx, frame1, f1_len, "10.1.0.2");

    uint8_t frame2[128];
    size_t  f2_len = 0;
    build_bcast_envelope(SRC, 0, payload, payload_len, frame2, sizeof(frame2), &f2_len);
    handle_inbound_broadcast(&tctx, frame2, f2_len, "10.1.0.2");

    /* Only the first broadcast was forwarded. */
    ck_assert_int_eq((int)mctx.n_bcasts, 1);

    mock_ctx_reset(&mctx);
    pthread_rwlock_destroy(&proc.protocol.peers_rwlock);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_non_gateway_does_not_forward_broadcast)
{
    /* A non-gateway node must NOT re-emit broadcasts — even if the hop
     * count leaves room. It still delivers locally (unobservable here). */
    uuid_t SRC;
    uuid_fill(SRC, 0xB2);

    process_t proc;
    uuid_t dummy_peer;
    uuid_fill(dummy_peer, 0xEE);
    init_proc_min(&proc, SRC, dummy_peer, "10.99.0.9");
    identity_t myself = {0};
    uuid_t ME;
    uuid_fill(ME, 0xA1);
    memcpy(myself.uuid, ME, 16);

    mock_ctx_t mctx = { .is_gateway_flag = false };  /* NOT a gateway */
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

    const uint8_t payload[] = "non-gateway-passthrough";
    uint8_t frame[128];
    size_t  frame_len = 0;
    build_bcast_envelope(SRC, 0, payload, sizeof(payload) - 1,
                         frame, sizeof(frame), &frame_len);

    handle_inbound_broadcast(&tctx, frame, frame_len, "10.1.0.2");

    ck_assert_int_eq((int)mctx.n_bcasts, 0);
    ck_assert_int_eq((int)mctx.n_sends,  0);

    mock_ctx_reset(&mctx);
    pthread_rwlock_destroy(&proc.protocol.peers_rwlock);
}
END_TEST_DEFINITION()

RUN_TESTS(Net_Proc_Relay,
          test_gateway_forwards_peer_for_other,
          test_non_gateway_drops_peer_for_other,
          test_gateway_does_not_forward_frame_for_self,
          test_gateway_drops_at_hop_exhaustion,
          test_gateway_forwards_preserve_payload_through_multiple_gateways,
          test_gateway_drops_when_peer_not_in_registry,
          test_gateway_forwards_broadcast_once,
          test_gateway_dedups_duplicate_broadcast,
          test_non_gateway_does_not_forward_broadcast)
