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

/** @file What an inbound wire frame may carry, by the path it came in on
 *  (ISSUES §2.17).
 *
 *  A handler's local-origin check reads from_whom, and on the stranger,
 *  broadcast and group paths from_whom was whatever the envelope said: a
 *  stranger could leave out from_uuid, or claim ours, and pass it. So the
 *  refusal is made on the frame's NAMES before routing: never an `app_*` verb,
 *  never a command to the network process but a remote stats_req, and from a
 *  sender we do not hold only the plaintext (or, on the broadcast channel, the
 *  broadcast) verbs. And a group frame is read as from the peer we hold at its
 *  address, or not at all. The Python twin is
 *  tests/a_unit/test_wire_verb_policy.py.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#include <sodium.h>
#include <uuid/uuid.h>

#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "identity/group.h"
#include "network/net_message.h"
#include "network/net_proc_priv.h"
#include "reputation/reputation.h"
#include "reputation/rep_proc_priv.h"
#include "config/configuration.h"
#include "structures/data.h"
#include "structures/map.h"
#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/allocation.h"

static int  g_routed;
static int  g_sent;          /* every message handed to messaging, any type */
static char g_fn[64];
static uuid_t g_from;

static int _hook(const char *key, const message_type_t type,
                 generic_msg_t *msg, bool blocking)
{
    (void)key; (void)blocking;
    g_sent++;
    if (type == NET_MESSAGE) {
        g_routed++;
        snprintf(g_fn, sizeof(g_fn), "%s",
                 msg->info.net_msg.function != NULL ? msg->info.net_msg.function : "");
        uuid_copy(g_from, msg->info.net_msg.from_whom.uuid);
    }
    return 0;
}

static void _begin(void)
{
    g_routed = 0;
    g_sent = 0;
    g_fn[0] = '\0';
    uuid_clear(g_from);
    messaging_set_test_hook(_hook);
}

static identity_t *_mk(const char *name, const char *addr)
{
    uuid_t u;
    uuid_generate(u);
    identity_t *id = NULL;
    ck_assert_ret_ok(identity_create(&u, addr, name, name, &id));
    return id;
}

static net_route_path_t ALL_PATHS[] = {
    NET_PATH_PEER, NET_PATH_PLAIN_KNOWN, NET_PATH_STRANGER,
    NET_PATH_RELAY_STRANGER, NET_PATH_BROADCAST, NET_PATH_GROUP,
};
#define N_PATHS (sizeof(ALL_PATHS) / sizeof(ALL_PATHS[0]))

DEFINE_TEST(test_an_app_verb_is_never_routed_from_the_wire)
{
    for (size_t i = 0; i < N_PATHS; i++) {
        ck_assert(!net_wire_verb_admitted("identity", "app_send_dm", ALL_PATHS[i], NULL));
        ck_assert(!net_wire_verb_admitted("identity", "app_block", ALL_PATHS[i], NULL));
        ck_assert(!net_wire_verb_admitted("reputation", "app_roster_request",
                                          ALL_PATHS[i], NULL));
    }
    /* The peer verbs the app verbs become are ordinary traffic. */
    ck_assert(net_wire_verb_admitted("identity", "peer_dm", NET_PATH_PEER, NULL));
    ck_assert(net_wire_verb_admitted("identity", "peer_dm", NET_PATH_GROUP, NULL));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_network_process_takes_only_stats_req)
{
    const char *why = NULL;
    ck_assert(net_wire_verb_admitted("network", "stats_req", NET_PATH_PEER, NULL));
    ck_assert(!net_wire_verb_admitted("network", "exclude", NET_PATH_PEER, &why));
    ck_assert_ptr_nonnull(why);
    ck_assert(!net_wire_verb_admitted("network", "readmit", NET_PATH_GROUP, NULL));
    ck_assert(!net_wire_verb_admitted("network", "relay_route", NET_PATH_PEER, NULL));
    ck_assert(!net_wire_verb_admitted("network", "stats_resp", NET_PATH_PEER, NULL));
    ck_assert(!net_wire_verb_admitted("network", "peer_dm", NET_PATH_PEER, NULL));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_stranger_sends_only_plaintext_verbs)
{
    net_route_path_t stranger[] = { NET_PATH_STRANGER, NET_PATH_RELAY_STRANGER };
    for (size_t i = 0; i < 2; i++) {
        ck_assert(net_wire_verb_admitted("identity", "access_granted", stranger[i], NULL));
        ck_assert(net_wire_verb_admitted("identity", "subtree_roster_response",
                                         stranger[i], NULL));
        ck_assert(!net_wire_verb_admitted("identity", "peer_dm", stranger[i], NULL));
        ck_assert(!net_wire_verb_admitted("identity", "full_history", stranger[i], NULL));
        ck_assert(!net_wire_verb_admitted("reputation", "transaction", stranger[i], NULL));
        /* Broadcast-only verbs are not plaintext unicast. */
        ck_assert(!net_wire_verb_admitted("identity", "group_key_update",
                                          stranger[i], NULL));
    }
    /* A peer we hold sends anything that is not refused for every path. */
    ck_assert(net_wire_verb_admitted("reputation", "transaction", NET_PATH_PEER, NULL));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_broadcast_channel_carries_discovery_only)
{
    const char *ok[] = { "request_access", "peer_identity_query",
                         "peer_identity_response", "group_partition_probe",
                         "group_partition_response", "group_key_update",
                         "peer_accepted", "propose_peer" };
    for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++)
        ck_assert(net_wire_verb_admitted("identity", ok[i], NET_PATH_BROADCAST, NULL));
    ck_assert(!net_wire_verb_admitted("identity", "peer_dm", NET_PATH_BROADCAST, NULL));
    ck_assert(!net_wire_verb_admitted("reputation", "transaction",
                                      NET_PATH_BROADCAST, NULL));
}
END_TEST_DEFINITION()

/* route_to_process itself: a refused frame is never handed to a process. */
DEFINE_TEST(test_a_refused_frame_is_not_routed)
{
    _begin();
    identity_t *bob = _mk("bob", "10.0.0.2");
    process_t *proc = smrt_create(sizeof(process_t));
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    strncpy(proc->name, "network", PROC_NAME_LEN);
    net_wire_msg_t w;
    memset(&w, 0, sizeof(w));
    snprintf(w.process, sizeof(w.process), "identity");
    w.data = (uint8_t *)strdup("{}");
    w.data_len = 2;
    uuid_copy(w.from_whom.uuid, bob->uuid);

    w.function = strdup("app_publish_post");
    ck_assert_int_eq(net_proc_test_route_on_path(&w, proc, NULL, NET_PATH_PEER),
                     NET_ROUTE_REFUSED);
    ck_assert_int_eq(g_routed, 0);
    free(w.function);

    w.function = strdup("peer_dm");
    ck_assert_int_eq(net_proc_test_route_on_path(&w, proc, NULL, NET_PATH_STRANGER),
                     NET_ROUTE_REFUSED);
    ck_assert_int_eq(g_routed, 0);
    ck_assert_int_eq(net_proc_test_route_on_path(&w, proc, NULL, NET_PATH_PEER), 0);
    ck_assert_int_eq(g_routed, 1);
    ck_assert_str_eq(g_fn, "peer_dm");
    free(w.function);
    free(w.data);
    messaging_set_test_hook(NULL);
}
END_TEST_DEFINITION()

/* A plaintext JSON envelope for @p fn, signed by @p signer and claiming to be
 * from @p claimed (NULL: no from_uuid at all). */
static uint8_t *_wire(const identity_t *signer, const identity_t *claimed,
                      const char *fn, recipient_type_t to, size_t *len)
{
    net_wire_msg_t w;
    memset(&w, 0, sizeof(w));
    snprintf(w.process, sizeof(w.process), "identity");
    w.function = strdup(fn);
    w.data = (uint8_t *)strdup("{}");
    w.data_len = 2;
    w.to_whom.type = to;
    if (claimed != NULL) {
        public_identity_t *pub = NULL;
        ck_assert_ret_ok(identity_publish((identity_t *)claimed, &pub));
        memcpy(&w.from_whom, pub, sizeof(*pub));
        smrt_deref(pub);
    }
    uint8_t *out = NULL;
    ck_assert_ret_ok(net_message_to_wire(&w, signer, &out, len));
    free(w.function);
    free(w.data);
    return out;
}

DEFINE_TEST(test_the_broadcast_handler_refuses_what_the_channel_does_not_carry)
{
    _begin();
    identity_t *me = _mk("me", "10.0.0.1"), *mallory = _mk("mallory", "10.0.0.9");
    process_t *proc = smrt_create(sizeof(process_t));
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    strncpy(proc->name, "network", PROC_NAME_LEN);
    net_thread_ctx_t ctx = { .proc = proc, .myself = me };
    size_t len = 0;
    /* Claiming to be us, with no key of ours: it must not matter. */
    uint8_t *f = _wire(mallory, me, "app_block", RECIPIENT_BROADCAST, &len);
    handle_inbound_broadcast(&ctx, f, len, "10.0.0.9");
    free(f);
    f = _wire(mallory, NULL, "peer_dm", RECIPIENT_BROADCAST, &len);
    handle_inbound_broadcast(&ctx, f, len, "10.0.0.9");
    free(f);
    ck_assert_int_eq(g_routed, 0);
    f = _wire(mallory, mallory, "request_access", RECIPIENT_BROADCAST, &len);
    handle_inbound_broadcast(&ctx, f, len, "10.0.0.9");
    free(f);
    ck_assert_int_eq(g_routed, 1);
    ck_assert_str_eq(g_fn, "request_access");
    messaging_set_test_hook(NULL);
}
END_TEST_DEFINITION()

/* @p wire sealed under @p grp, as net_encrypt_and_send's group branch frames
 * it: nonce | group_encrypt(wire). */
static uint8_t *_seal(const group_t *grp, const uint8_t *wire, size_t wire_len,
                      size_t *out_len)
{
    unsigned char nonce[crypto_box_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));
    msg_str_t plain = { .msg = (unsigned char *)wire, .len = wire_len };
    size_t cipher_len = wire_len + crypto_box_MACBYTES;
    uint8_t *frame = malloc(sizeof(nonce) + cipher_len);
    ck_assert_ptr_nonnull(frame);
    memcpy(frame, nonce, sizeof(nonce));
    ck_assert_int_eq(group_encrypt(grp, &plain, grp, nonce, frame + sizeof(nonce)), 0);
    *out_len = sizeof(nonce) + cipher_len;
    return frame;
}

DEFINE_TEST(test_a_group_frame_is_read_as_from_the_peer_we_hold)
{
    ck_assert(sodium_init() >= 0);
    _begin();
    identity_t *me = _mk("me", "10.0.0.1"), *bob = _mk("bob", "10.0.0.2");
    identity_t *mallory = _mk("mallory", "10.0.0.9");
    process_t *proc = smrt_create(sizeof(process_t));
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    strncpy(proc->name, "network", PROC_NAME_LEN);
    char gaddr[] = "group-addr";
    ck_assert_int_eq(group_init(NULL, gaddr, &proc->protocol.group), 0);
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(bob, &pub));
    memcpy(&proc->protocol.peers[0], pub, sizeof(*pub));
    smrt_deref(pub);
    proc->protocol.num_peers = 1;
    net_thread_ctx_t ctx = { .proc = proc, .myself = me };

    /* Mallory holds the group key but is not a peer here: claiming our uuid,
     * or none, she is dropped before anything reads the frame. */
    size_t wl = 0, fl = 0;
    uint8_t *w = _wire(mallory, me, "app_block", RECIPIENT_GROUP, &wl);
    uint8_t *f = _seal(&proc->protocol.group, w, wl, &fl);
    handle_inbound_group(&ctx, f, fl, "10.0.0.9");
    free(w); free(f);
    w = _wire(mallory, NULL, "peer_dm", RECIPIENT_GROUP, &wl);
    f = _seal(&proc->protocol.group, w, wl, &fl);
    handle_inbound_group(&ctx, f, fl, "10.0.0.9");
    free(w); free(f);
    ck_assert_int_eq(g_routed, 0);

    /* Bob is a peer. His frame claims to be from us; it is read as his. */
    w = _wire(bob, me, "peer_dm", RECIPIENT_GROUP, &wl);
    f = _seal(&proc->protocol.group, w, wl, &fl);
    handle_inbound_group(&ctx, f, fl, "10.0.0.2");
    free(w); free(f);
    ck_assert_int_eq(g_routed, 1);
    ck_assert_str_eq(g_fn, "peer_dm");
    ck_assert(uuid_compare(g_from, bob->uuid) == 0);
    messaging_set_test_hook(NULL);
}
END_TEST_DEFINITION()

/* The app's roster pull, reputation half: the local app's verb only (ISSUES
 * §2.17). From the app (no sender) it replays one reputation per peer; from a
 * peer it replays nothing. */
DEFINE_TEST(test_a_peers_roster_pull_replays_nothing)
{
    _begin();
    reputation_reset_state(2);
    identity_t *me = _mk("me", "10.0.0.1"), *bob = _mk("bob", "10.0.0.2");
    process_t *proc = smrt_create(sizeof(process_t));
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    strncpy(proc->name, "reputation", PROC_NAME_LEN);
    config_t *id_cfg = calloc(1, sizeof(config_t));
    ck_assert_ptr_nonnull(id_cfg);
    id_cfg->name = "identity";
    id_cfg->data_struct = me;
    ck_assert_ret_ok(map_create(&proc->configs));
    map_set(proc->configs, (map_key_t)"identity",
            object_ptr_data((ptr_t)id_cfg, sizeof(config_t)));
    ck_assert_ret_ok(map_create(&proc->protocol.handlers));
    ck_assert_ret_ok(reputation_register_handlers(proc));
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(bob, &pub));
    memcpy(&proc->protocol.peers[0], pub, sizeof(*pub));
    proc->protocol.num_peers = 1;

    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "reputation", PROC_NAME_LEN);
    msg.info.net_msg.function = REP_PROTO_APP_ROSTER;
    msg.info.net_msg.verified = true;
    memcpy(&msg.info.net_msg.from_whom, pub, sizeof(*pub));     /* a peer's */
    smrt_deref(pub);
    run_message_handlers(proc, NULL, NET_MESSAGE, &msg);
    ck_assert_int_eq(g_sent, 0);
    memset(&msg.info.net_msg.from_whom, 0, sizeof(msg.info.net_msg.from_whom));
    run_message_handlers(proc, NULL, NET_MESSAGE, &msg);         /* the app's */
    ck_assert(g_sent >= 1);
    messaging_set_test_hook(NULL);
}
END_TEST_DEFINITION()

RUN_TESTS(NetRoutePolicy,
          test_an_app_verb_is_never_routed_from_the_wire,
          test_the_network_process_takes_only_stats_req,
          test_a_stranger_sends_only_plaintext_verbs,
          test_the_broadcast_channel_carries_discovery_only,
          test_a_refused_frame_is_not_routed,
          test_the_broadcast_handler_refuses_what_the_channel_does_not_carry,
          test_a_group_frame_is_read_as_from_the_peer_we_hold,
          test_a_peers_roster_pull_replays_nothing)
