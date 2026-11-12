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
 * @file net_proc_defer_test.c
 * @brief Tests for envelope-mode deferred-message keying (at-over-dtn
 *        stage G — gateway-forwarded traffic).
 *
 * Bug fixed: under the routing envelope, a PEER frame received via a gateway
 * from an unknown sender used to be deferred keyed by from_addr (the
 * gateway's transport address). When the original sender was later
 * admitted to peers[] — at their OWN address, not the gateway's — the
 * retry loop's `strcmp(dm->from_addr, new_peer->address)` always missed
 * and the deferred message was stranded.
 *
 * The fix carries the envelope's src_uuid through defer_message and
 * matches by UUID when present. This suite drives handle_inbound_peer()
 * with the same mock transport pattern as net_proc_relay_test, then
 * inspects deferred state via net_proc_test_* hooks.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "net_envelope.h"
#include "gateway_test.h"
#include "network/net_proc_priv.h"
#include "network/net_transport.h"
#include "network/network.h"
#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "network/net_message.h"
#include "utilities/message.h"

/* ---- Mock transport (mirrors the pattern in net_proc_relay_test) ---- */

typedef struct {
    bool is_gateway_flag;
} mock_ctx_t;

static int mock_send_unicast(net_transport_ctx_t *ctx, const uint8_t *w,
                             size_t wl, const char *t, int p)
{ (void)ctx; (void)w; (void)wl; (void)t; (void)p; return 0; }
static int mock_send_broadcast(net_transport_ctx_t *ctx, net_channel_t ch,
                               const uint8_t *w, size_t wl, int p)
{ (void)ctx; (void)ch; (void)w; (void)wl; (void)p; return 0; }
static int mock_recv(net_transport_ctx_t *ctx, net_channel_t ch,
                     uint8_t **o, size_t *ol, char *pa, size_t pl, int t)
{ (void)ctx; (void)ch; (void)o; (void)ol; (void)pa; (void)pl; (void)t; return ENOMSG; }
static void mock_close(net_transport_ctx_t *ctx) { (void)ctx; }
static bool mock_is_gateway(const net_transport_ctx_t *ctx_opaque)
{ return ((const mock_ctx_t *)ctx_opaque)->is_gateway_flag; }

static const net_transport_t mock_transport = {
    .name           = "mock_defer",
    .send_unicast   = mock_send_unicast,
    .send_broadcast = mock_send_broadcast,
    .recv           = mock_recv,
    .close          = mock_close,
    .is_gateway     = mock_is_gateway,
};

/* ---- Harness helpers ---- */

static void uuid_fill(uuid_t u, uint8_t seed)
{
    for (size_t i = 0; i < 16; i++) u[i] = (uint8_t)(seed + i);
}

static void init_proc_empty_peers(process_t *proc)
{
    memset(proc, 0, sizeof(*proc));
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    proc->protocol.num_peers = 0;
}

/* Build a PEER envelope (dst=ME, src=SRC) with a payload that (a) won't
 * decrypt because we have no crypto and (b) won't parse as a plaintext
 * wire message — so handle_inbound_peer is forced down the defer path. */
static void build_undecryptable_peer_envelope(const uuid_t src, const uuid_t dst,
                                              uint8_t *out_frame, size_t out_cap,
                                              size_t *out_len)
{
    net_envelope_t env = {
        .version   = NET_ENV_VERSION,
        .type      = NET_ENV_TYPE_PEER,
        .flags     = 0,
        .hop_count = 0,
    };
    memcpy(env.src_uuid, src, 16);
    memcpy(env.dst_uuid, dst, 16);
    /* Four arbitrary bytes — guaranteed not to round-trip as a wire msg. */
    uint8_t pay[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    (void)net_envelope_pack(&env, pay, sizeof(pay), out_frame, out_cap, out_len);
}

/* ---- Tests ---- */

DEFINE_TEST(test_envelope_defer_keys_by_src_uuid_not_gateway_addr)
{
    /* The gateway forwards a frame from A (unknown) to ME. handle_inbound_peer
     * takes the LOCAL path (dst==me), looks up A in peers[] → not found,
     * tries unencrypted parse → fails, defers. Under the fix, the deferred
     * entry's key is A's UUID, NOT the gateway address from_addr carried. */
    net_proc_test_reset_deferred();

    uuid_t A, ME;
    uuid_fill(A,  0x10);
    uuid_fill(ME, 0x20);

    process_t proc;
    init_proc_empty_peers(&proc);

    identity_t myself = {0};
    memcpy(myself.uuid, ME, 16);

    mock_ctx_t mctx = { .is_gateway_flag = false };  /* LOCAL delivery, not forwarding */
    network_config_t net_cfg = { .port = 27787 };
    gateway_test_enable(&proc, &net_cfg);
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

    uint8_t frame[128];
    size_t  frame_len = 0;
    build_undecryptable_peer_envelope(A, ME, frame, sizeof(frame), &frame_len);

    /* Transport-reported "sender" is a gateway address — NOT A's address. */
    const char *gateway_addr = "10.99.0.42";
    handle_inbound_peer(&tctx, frame, frame_len, gateway_addr);

    ck_assert_int_eq((int)net_proc_test_deferred_count(), 1);

    /* A peer record built with A's UUID but a TOTALLY DIFFERENT address
     * from the gateway must still match the deferred entry — the fix
     * indexes by UUID, not address. */
    public_identity_t arrived_peer_A = {0};
    memcpy(arrived_peer_A.uuid, A, 16);
    snprintf(arrived_peer_A.address, sizeof(arrived_peer_A.address),
             "%s", "10.1.0.7");  /* A's real address, unrelated to gateway_addr */
    ck_assert_int_eq((int)net_proc_test_deferred_matches_peer(0, &arrived_peer_A), 1);

    /* And a different UUID at the gateway's address must NOT match —
     * confirms we're not falling back to from_addr when has_src_uuid. */
    uuid_t B;
    uuid_fill(B, 0xBB);
    public_identity_t peer_B_at_gw = {0};
    memcpy(peer_B_at_gw.uuid, B, 16);
    snprintf(peer_B_at_gw.address, sizeof(peer_B_at_gw.address),
             "%s", gateway_addr);
    ck_assert_int_eq((int)net_proc_test_deferred_matches_peer(0, &peer_B_at_gw), 0);

    net_proc_test_reset_deferred();
    pthread_rwlock_destroy(&proc.protocol.peers_rwlock);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_out_of_range_index_returns_false)
{
    /* Defensive: the exposed predicate must not read past the ring. */
    net_proc_test_reset_deferred();

    uuid_t X;
    uuid_fill(X, 0x55);
    public_identity_t dummy = {0};
    memcpy(dummy.uuid, X, 16);
    snprintf(dummy.address, sizeof(dummy.address), "%s", "1.2.3.4");

    ck_assert_int_eq((int)net_proc_test_deferred_matches_peer(0, &dummy), 0);
    ck_assert_int_eq((int)net_proc_test_deferred_matches_peer(99, &dummy), 0);
    ck_assert_int_eq((int)net_proc_test_deferred_count(), 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_multiple_defers_distinct_uuids_each_match_own_peer)
{
    /* Two distinct unknown senders → two deferred entries. Each peer
     * arrival matches exactly its own entry (not the other one). */
    net_proc_test_reset_deferred();

    uuid_t A, B, ME;
    uuid_fill(A,  0x10);
    uuid_fill(B,  0x30);
    uuid_fill(ME, 0x20);

    process_t proc;
    init_proc_empty_peers(&proc);

    identity_t myself = {0};
    memcpy(myself.uuid, ME, 16);

    mock_ctx_t mctx = { .is_gateway_flag = false };
    network_config_t net_cfg = { .port = 27787 };
    gateway_test_enable(&proc, &net_cfg);
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

    uint8_t frame_a[128], frame_b[128];
    size_t  la = 0, lb = 0;
    build_undecryptable_peer_envelope(A, ME, frame_a, sizeof(frame_a), &la);
    build_undecryptable_peer_envelope(B, ME, frame_b, sizeof(frame_b), &lb);

    handle_inbound_peer(&tctx, frame_a, la, "10.99.0.1");
    handle_inbound_peer(&tctx, frame_b, lb, "10.99.0.2");

    ck_assert_int_eq((int)net_proc_test_deferred_count(), 2);

    public_identity_t peer_A = {0};
    memcpy(peer_A.uuid, A, 16);
    snprintf(peer_A.address, sizeof(peer_A.address), "%s", "10.1.0.1");
    public_identity_t peer_B = {0};
    memcpy(peer_B.uuid, B, 16);
    snprintf(peer_B.address, sizeof(peer_B.address), "%s", "10.1.0.2");

    /* Entry 0 matches A, not B. Entry 1 matches B, not A. */
    ck_assert_int_eq((int)net_proc_test_deferred_matches_peer(0, &peer_A), 1);
    ck_assert_int_eq((int)net_proc_test_deferred_matches_peer(0, &peer_B), 0);
    ck_assert_int_eq((int)net_proc_test_deferred_matches_peer(1, &peer_A), 0);
    ck_assert_int_eq((int)net_proc_test_deferred_matches_peer(1, &peer_B), 1);

    net_proc_test_reset_deferred();
    pthread_rwlock_destroy(&proc.protocol.peers_rwlock);
}
END_TEST_DEFINITION()

/* ---- Known-peer plaintext is verified against the STORED key ---- */

static int  g_routed;
static bool g_routed_verified;

static int _route_hook(const char *key, const message_type_t type,
                       generic_msg_t *msg, bool blocking)
{
    (void)key; (void)blocking;
    if (type == NET_MESSAGE) {
        g_routed++;
        g_routed_verified = msg->info.net_msg.verified;
    }
    return 0;
}

/* A plaintext access_granted from a known peer's uuid, arriving in a PEER
 * envelope (src = peer, dst = ME), signed by the stored peer itself (@p genuine)
 * or by an impostor holding the same uuid under fresh keys. Returns whether it
 * was delivered verified: it must be iff the signature checks against the key
 * we HOLD for that peer. */
static bool _plaintext_from_known_peer_verified(bool genuine)
{
    uuid_t P, ME;
    uuid_fill(P, 0x40);
    uuid_fill(ME, 0x20);
    identity_t *stored = NULL, *impostor = NULL;
    ck_assert_ret_ok(identity_create(&P, "10.1.0.5", "peer", "peer", &stored));
    ck_assert_ret_ok(identity_create(&P, "10.1.0.5", "peer", "peer", &impostor));
    const identity_t *signer = genuine ? stored : impostor;
    public_identity_t *stored_pub = NULL, *signer_pub = NULL;
    ck_assert_ret_ok(identity_publish(stored, &stored_pub));
    ck_assert_ret_ok(identity_publish(signer, &signer_pub));

    process_t proc;
    init_proc_empty_peers(&proc);
    memcpy(&proc.protocol.peers[0], stored_pub, sizeof(public_identity_t));
    proc.protocol.num_peers = 1;
    identity_t myself = {0};
    memcpy(myself.uuid, ME, 16);
    mock_ctx_t mctx = { .is_gateway_flag = false };
    network_config_t net_cfg = { .port = 27787 };
    gateway_test_enable(&proc, &net_cfg);
    bool stop = false;
    logger_t logger = {0};
    net_thread_ctx_t tctx = {
        .transport = &mock_transport, .ctx = (net_transport_ctx_t *)&mctx,
        .proc = &proc, .logger = &logger, .net_cfg = &net_cfg,
        .myself = &myself, .stop = &stop,
    };

    net_wire_msg_t msg = {0};
    snprintf(msg.process, sizeof(msg.process), "%s", "identity");
    msg.function = (char *)"access_granted";
    msg.data = (uint8_t *)"[]";
    msg.data_len = 2;
    msg.encrypt = false;
    memcpy(&msg.from_whom, signer_pub, sizeof(public_identity_t));
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    ck_assert_ret_ok(net_message_to_wire_fmt(&msg, signer, NET_WIRE_JSON,
                                             &wire, &wire_len));
    net_envelope_t env = { .version = NET_ENV_VERSION, .type = NET_ENV_TYPE_PEER };
    memcpy(env.src_uuid, P, 16);
    memcpy(env.dst_uuid, ME, 16);
    uint8_t frame[4096];
    size_t frame_len = 0;
    ck_assert_ret_ok(net_envelope_pack(&env, wire, wire_len, frame, sizeof(frame),
                                       &frame_len));

    g_routed = 0;
    g_routed_verified = false;
    messaging_set_test_hook(_route_hook);
    handle_inbound_peer(&tctx, frame, frame_len, "10.1.0.5");
    messaging_set_test_hook(NULL);
    ck_assert_int_eq(g_routed, 1);

    free(wire);
    smrt_deref(signer_pub);
    smrt_deref(stored_pub);
    identity_free(stored);
    identity_free(impostor);
    pthread_rwlock_destroy(&proc.protocol.peers_rwlock);
    return g_routed_verified;
}

/* The control: signed by the key we hold, it verifies. */
DEFINE_TEST(test_known_peer_plaintext_signed_by_its_key_verifies)
{
    ck_assert(_plaintext_from_known_peer_verified(true));
}
END_TEST_DEFINITION()

/* RD_2.6 plan §2.7: a plaintext frame from a known peer is checked against the
 * key we hold for it, not the key the envelope names. Before, C parsed it with
 * no peer, so a frame signed by ANY key verified under the known uuid. */
DEFINE_TEST(test_known_peer_plaintext_under_another_key_is_unverified)
{
    ck_assert(!_plaintext_from_known_peer_verified(false));
}
END_TEST_DEFINITION()

RUN_TESTS(Net_Proc_Defer,
          test_envelope_defer_keys_by_src_uuid_not_gateway_addr,
          test_out_of_range_index_returns_false,
          test_multiple_defers_distinct_uuids_each_match_own_peer,
          test_known_peer_plaintext_signed_by_its_key_verifies,
          test_known_peer_plaintext_under_another_key_is_unverified)
