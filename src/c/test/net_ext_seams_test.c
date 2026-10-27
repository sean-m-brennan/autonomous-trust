/********************
 *  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *******************/

/* The also-unicast and fan-out hooks: an extension sees each frame the
 * transport sends, with its verb, and the transport still sends it. */
#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdlib.h>
#include <string.h>

#include <sodium.h>
#include <pthread.h>
#include <uuid/uuid.h>

#include "identity/group.h"
#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "network/net_ext.h"
#include "network/net_liveness.h"
#include "processes/processes.h"
#include "utilities/message.h"
#include "network/net_message.h"
#include "network/net_proc_priv.h"
#include "network/net_transport.h"
#include "utilities/allocation.h"

static int t_unicasts, t_broadcasts;
static int x_also, x_fan, x_carry;
static net_channel_t x_ch;
static char x_proc[32], x_fn[64];
static size_t x_len, t_len;
static bool carry_next;
static uint8_t t_wire[4096];   /* the last unicast the fake transport sent */

static int t_send_unicast(net_transport_ctx_t *ctx, const uint8_t *wire, size_t len,
                          const char *target, int port)
{
    (void)ctx; (void)target; (void)port;
    t_unicasts++;
    t_len = len;
    if (len <= sizeof(t_wire))
        memcpy(t_wire, wire, len);
    return 0;
}
static int t_send_broadcast(net_transport_ctx_t *ctx, net_channel_t ch,
                            const uint8_t *wire, size_t len, int port)
{
    (void)ctx; (void)ch; (void)wire; (void)port;
    t_broadcasts++;
    t_len = len;
    return 0;
}
static const net_transport_t T_TRANSPORT = {
    .name = "t_fake",
    .send_unicast = t_send_unicast,
    .send_broadcast = t_send_broadcast,
};

static void x_also_unicast(const uuid_t peer, const char *process, const char *function,
                           const uint8_t *buf, size_t len)
{
    (void)peer; (void)buf;
    x_also++;
    snprintf(x_proc, sizeof(x_proc), "%s", process);
    snprintf(x_fn, sizeof(x_fn), "%s", function);
    x_len = len;
}
static void x_fanout(net_channel_t ch, const char *process, const char *function,
                     const group_t *grp, const uint8_t *buf, size_t len)
{
    (void)grp; (void)buf;
    x_fan++;
    x_ch = ch;
    snprintf(x_proc, sizeof(x_proc), "%s", process);
    snprintf(x_fn, sizeof(x_fn), "%s", function);
    x_len = len;
}
static int x_unicast(const uuid_t peer, const uint8_t *buf, size_t len)
{
    (void)peer; (void)buf; (void)len;
    if (!carry_next)
        return 1;
    x_carry++;
    return 0;
}
static const net_ext_t X_EXT = {
    .name = "x.seams",
    .unicast = x_unicast,
    .also_unicast = x_also_unicast,
    .fanout = x_fanout,
};

static identity_t *_mk(const char *name, const char *addr)
{
    uuid_t u;
    uuid_generate(u);
    identity_t *id = NULL;
    ck_assert_ret_ok(identity_create(&u, addr, name, name, &id));
    return id;
}

static void _msg(net_wire_msg_t *w, recipient_type_t type, const char *fn)
{
    memset(w, 0, sizeof(*w));
    snprintf(w->process, sizeof(w->process), "%s", "identity");
    w->function = strdup(fn);
    w->data = (uint8_t *)strdup("{}");
    w->data_len = 2;
    w->to_whom.type = type;
    w->encrypt = true;
}

static void _reset(void)
{
    t_unicasts = t_broadcasts = x_also = x_fan = x_carry = 0;
    carry_next = false;
    x_proc[0] = x_fn[0] = '\0';
}

DEFINE_TEST(test_also_unicast_sees_the_sealed_frame_and_the_transport_sends)
{
    ck_assert(sodium_init() >= 0);
    ck_assert_int_eq(net_ext_register(&X_EXT), 0);
    _reset();
    identity_t *me = _mk("me", "10.0.0.1"), *peer = _mk("peer", "10.0.0.2");
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(peer, &pub));
    net_wire_msg_t w;
    _msg(&w, RECIPIENT_PEER, "group_key_update");
    memcpy(&w.to_whom.target.peer, pub, sizeof(*pub));
    ck_assert_int_eq(net_proc_test_encrypt_and_send(me, NULL, &w, &T_TRANSPORT, NULL,
                                                    27787, NET_WIRE_JSON, NULL), 0);
    ck_assert_int_eq(x_also, 1);
    ck_assert_int_eq(t_unicasts, 1);
    ck_assert_str_eq(x_proc, "identity");
    ck_assert_str_eq(x_fn, "group_key_update");
    ck_assert_int_eq((int)x_len, (int)t_len);
    free(w.function);
    free(w.data);
    smrt_deref(pub);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_carried_unicast_does_not_call_also_unicast)
{
    _reset();
    carry_next = true;
    identity_t *me = _mk("me", "10.0.0.1"), *peer = _mk("peer", "10.0.0.2");
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(peer, &pub));
    net_wire_msg_t w;
    _msg(&w, RECIPIENT_PEER, "peer_dm");
    memcpy(&w.to_whom.target.peer, pub, sizeof(*pub));
    ck_assert_int_eq(net_proc_test_encrypt_and_send(me, NULL, &w, &T_TRANSPORT, NULL,
                                                    27787, NET_WIRE_JSON, NULL), 0);
    ck_assert_int_eq(x_carry, 1);
    ck_assert_int_eq(x_also, 0);
    ck_assert_int_eq(t_unicasts, 0);
    free(w.function);
    free(w.data);
    smrt_deref(pub);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_fanout_sees_group_and_broadcast_sends)
{
    _reset();
    identity_t *me = _mk("me", "10.0.0.1");
    group_t grp = {0};
    char gaddr[] = "group-addr";
    ck_assert_int_eq(group_init(NULL, gaddr, &grp), 0);

    net_wire_msg_t w;
    _msg(&w, RECIPIENT_GROUP, "presence");
    ck_assert_int_eq(net_proc_test_encrypt_and_send(me, &grp, &w, &T_TRANSPORT, NULL,
                                                    27787, NET_WIRE_JSON, NULL), 0);
    ck_assert_int_eq(x_fan, 1);
    ck_assert_int_eq(x_ch, NET_CHAN_GROUP);
    ck_assert_str_eq(x_fn, "presence");
    ck_assert_int_eq(t_broadcasts, 1);
    free(w.function);
    free(w.data);

    _msg(&w, RECIPIENT_BROADCAST, "group_partition_probe");
    w.encrypt = false;
    ck_assert_int_eq(net_proc_test_encrypt_and_send(me, &grp, &w, &T_TRANSPORT, NULL,
                                                    27787, NET_WIRE_JSON, NULL), 0);
    ck_assert_int_eq(x_fan, 2);
    ck_assert_int_eq(x_ch, NET_CHAN_BROADCAST);
    ck_assert_str_eq(x_fn, "group_partition_probe");
    ck_assert_int_eq(t_broadcasts, 2);
    free(w.function);
    free(w.data);
    /* A group on the stack: its address map is all group_init allocated. */
    map_free(&grp.address_map);
}
END_TEST_DEFINITION()

static int g_routed, g_partition;
static int _route_hook(const char *key, const message_type_t type,
                       generic_msg_t *msg, bool blocking)
{
    (void)key; (void)blocking;
    if (type == NET_MESSAGE && msg->info.net_msg.function != NULL) {
        if (strcmp(msg->info.net_msg.function, "partition_signal") == 0)
            g_partition++;
        else
            g_routed++;
    }
    return 0;
}

static process_t *_proc_holding(identity_t *peer)
{
    process_t *proc = smrt_create(sizeof(process_t));
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    strncpy(proc->name, "network", PROC_NAME_LEN);
    char gaddr[] = "group-addr";
    ck_assert_int_eq(group_init(NULL, gaddr, &proc->protocol.group), 0);
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(peer, &pub));
    memcpy(&proc->protocol.peers[0], pub, sizeof(*pub));
    smrt_deref(pub);
    proc->protocol.num_peers = 1;
    return proc;
}

static void _proc_release(process_t *proc)
{
    map_free(&proc->protocol.group.address_map);
    pthread_rwlock_destroy(&proc->protocol.peers_rwlock);
    smrt_deref(proc);
}

/* A plaintext JSON broadcast envelope from @p from. */
static uint8_t *_bcast_frame(identity_t *from, size_t *len)
{
    net_wire_msg_t w = {0};
    snprintf(w.process, sizeof(w.process), "%s", "identity");
    w.function = strdup("group_partition_probe");
    w.data = (uint8_t *)strdup("{}");
    w.data_len = 2;
    w.to_whom.type = RECIPIENT_BROADCAST;
    uint8_t *wire = NULL;
    ck_assert_ret_ok(net_message_to_wire(&w, from, &wire, len));
    free(w.function);
    free(w.data);
    return wire;
}

DEFINE_TEST(test_injected_broadcast_is_routed_and_does_not_stamp_liveness)
{
    messaging_set_test_hook(_route_hook);
    g_routed = g_partition = 0;
    identity_t *me = _mk("me", "10.0.0.1"), *peer = _mk("peer", "10.0.0.2");
    process_t *proc = _proc_holding(peer);
    net_thread_ctx_t ctx = { .proc = proc, .myself = me };
    net_liveness_reset(net_liveness_now() - 100.0);
    size_t len = 0;
    uint8_t *frame = _bcast_frame(peer, &len);
    char uuid_str[UUID_STR_LEN + 1];
    uuid_unparse_lower(peer->uuid, uuid_str);
    handle_inbound_ext(&ctx, NET_CHAN_BROADCAST, frame, len, uuid_str);
    ck_assert_int_eq(g_routed, 1);
    ck_assert(net_liveness_quiet_for(peer->uuid, net_liveness_now()) >= 100.0);
    free(frame);
    _proc_release(proc);
    messaging_set_test_hook(NULL);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_injected_group_frame_that_fails_raises_no_partition_signal)
{
    messaging_set_test_hook(_route_hook);
    g_routed = g_partition = 0;
    net_held_group_frames_reset();
    identity_t *me = _mk("me", "10.0.0.1"), *peer = _mk("peer", "10.0.0.2");
    process_t *proc = _proc_holding(peer);
    net_thread_ctx_t ctx = { .proc = proc, .myself = me };
    uint8_t junk[96];
    randombytes_buf(junk, sizeof(junk));
    char uuid_str[UUID_STR_LEN + 1];
    uuid_unparse_lower(peer->uuid, uuid_str);
    handle_inbound_ext(&ctx, NET_CHAN_GROUP, junk, sizeof(junk), uuid_str);
    ck_assert_int_eq(g_partition, 0);
    ck_assert_int_eq(g_routed, 0);
    /* The same junk on the transport path does raise one. */
    handle_inbound_group(&ctx, junk, sizeof(junk), peer->address);
    ck_assert_int_eq(g_partition, 1);
    net_held_group_frames_reset();
    _proc_release(proc);
    messaging_set_test_hook(NULL);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_injection_from_an_unknown_uuid_is_dropped)
{
    messaging_set_test_hook(_route_hook);
    g_routed = 0;
    identity_t *me = _mk("me", "10.0.0.1"), *peer = _mk("peer", "10.0.0.2");
    process_t *proc = _proc_holding(peer);
    net_thread_ctx_t ctx = { .proc = proc, .myself = me };
    size_t len = 0;
    uint8_t *frame = _bcast_frame(peer, &len);
    handle_inbound_ext(&ctx, NET_CHAN_BROADCAST, frame, len,
                       "00000000-0000-4000-8000-0000000000ff");
    ck_assert_int_eq(g_routed, 0);
    free(frame);
    _proc_release(proc);
    messaging_set_test_hook(NULL);
}
END_TEST_DEFINITION()


DEFINE_TEST(test_injection_from_an_excluded_peer_is_dropped)
{
    messaging_set_test_hook(_route_hook);
    g_routed = 0;
    identity_t *me = _mk("me", "10.0.0.1"), *peer = _mk("peer", "10.0.0.2");
    process_t *proc = _proc_holding(peer);
    net_thread_ctx_t ctx = { .proc = proc, .myself = me };
    size_t len = 0;
    uint8_t *frame = _bcast_frame(peer, &len);
    char uuid_str[UUID_STR_LEN + 1];
    uuid_unparse_lower(peer->uuid, uuid_str);
    /* Excluded by the gate the receiver threads read (reject_message). */
    for (int i = 0; i < 1000 && !net_proc_test_is_rejected(peer->address); i++)
        net_proc_test_track_annoy(peer->address);
    ck_assert(net_proc_test_is_rejected(peer->address));
    handle_inbound_ext(&ctx, NET_CHAN_BROADCAST, frame, len, uuid_str);
    handle_inbound_ext(&ctx, NET_CHAN_PEER, frame, len, uuid_str);
    ck_assert_int_eq(g_routed, 0);
    net_proc_test_reset_pests();
    /* And by uuid, through reputation's exclusion record. */
    net_note_exclusion(uuid_str, NULL, true);
    handle_inbound_ext(&ctx, NET_CHAN_BROADCAST, frame, len, uuid_str);
    ck_assert_int_eq(g_routed, 0);
    net_note_exclusion(uuid_str, NULL, false);
    handle_inbound_ext(&ctx, NET_CHAN_BROADCAST, frame, len, uuid_str);
    ck_assert_int_eq(g_routed, 1);
    free(frame);
    _proc_release(proc);
    messaging_set_test_hook(NULL);
}
END_TEST_DEFINITION()

/* A frame sealed for us by a peer we hold, injected on the peer channel, takes
 * the peer path (peer_dm is admitted nowhere else) and does not stamp
 * transport liveness; the caller's buffer is left as it was. */
DEFINE_TEST(test_injected_peer_frame_takes_the_peer_path_unstamped)
{
    _reset();
    identity_t *me = _mk("me", "10.0.0.1"), *peer = _mk("peer", "10.0.0.2");
    public_identity_t *me_pub = NULL;
    ck_assert_ret_ok(identity_publish(me, &me_pub));
    net_wire_msg_t w;
    _msg(&w, RECIPIENT_PEER, "peer_dm");
    memcpy(&w.to_whom.target.peer, me_pub, sizeof(*me_pub));
    ck_assert_int_eq(net_proc_test_encrypt_and_send(peer, NULL, &w, &T_TRANSPORT, NULL,
                                                    27787, NET_WIRE_JSON, NULL), 0);
    ck_assert_int_eq(t_unicasts, 1);
    ck_assert(t_len <= sizeof(t_wire));
    free(w.function);
    free(w.data);
    smrt_deref(me_pub);
    uint8_t sealed[sizeof(t_wire)];
    size_t len = t_len;
    memcpy(sealed, t_wire, len);

    messaging_set_test_hook(_route_hook);
    g_routed = g_partition = 0;
    process_t *proc = _proc_holding(peer);
    net_thread_ctx_t ctx = { .proc = proc, .myself = me };
    char uuid_str[UUID_STR_LEN + 1];
    uuid_unparse_lower(peer->uuid, uuid_str);
    net_liveness_reset(net_liveness_now() - 100.0);
    handle_inbound_ext(&ctx, NET_CHAN_PEER, sealed, len, uuid_str);
    ck_assert_int_eq(g_routed, 1);
    ck_assert(net_liveness_quiet_for(peer->uuid, net_liveness_now()) >= 100.0);
    ck_assert(memcmp(sealed, t_wire, len) == 0);

    /* Excluded by uuid, the same frame is refused on the peer channel. */
    net_note_exclusion(uuid_str, NULL, true);
    handle_inbound_ext(&ctx, NET_CHAN_PEER, sealed, len, uuid_str);
    ck_assert_int_eq(g_routed, 1);
    net_note_exclusion(uuid_str, NULL, false);
    _proc_release(proc);
    messaging_set_test_hook(NULL);
}
END_TEST_DEFINITION()

RUN_TESTS(NET_EXT_SEAMS,
          test_also_unicast_sees_the_sealed_frame_and_the_transport_sends,
          test_a_carried_unicast_does_not_call_also_unicast,
          test_fanout_sees_group_and_broadcast_sends,
          test_injected_broadcast_is_routed_and_does_not_stamp_liveness,
          test_injected_group_frame_that_fails_raises_no_partition_signal,
          test_injection_from_an_unknown_uuid_is_dropped,
          test_injection_from_an_excluded_peer_is_dropped,
          test_injected_peer_frame_takes_the_peer_path_unstamped)
