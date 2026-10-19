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
/* A group frame sent under a key the network process has not installed yet.
 *
 * Identity adopts a rotated key before the network process installs it, and a
 * one-shot group send in that gap failed to decrypt and was lost (Stele
 * tm-3882043, the team roster). The frame is now held and tried again once a
 * different key is installed. */
#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#include <jansson.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "identity/group.h"
#include "network/net_message.h"
#include "network/net_proc_priv.h"
#include "structures/data.h"
#include "structures/map.h"
#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/allocation.h"

static int g_delivered;      /* peer_dm frames routed to a process */

static int _hook(const char *key, const message_type_t type,
                 generic_msg_t *msg, bool blocking)
{
    (void)key; (void)blocking;
    if (type == NET_MESSAGE && msg->info.net_msg.function != NULL
        && strcmp(msg->info.net_msg.function, "peer_dm") == 0)
        g_delivered++;
    return 0;
}

static identity_t *_mk(const char *name, const char *addr)
{
    uuid_t u;
    uuid_generate(u);
    identity_t *id = NULL;
    ck_assert_ret_ok(identity_create(&u, addr, name, name, &id));
    return id;
}

/* A network process in a keyed group, holding @p peer. */
static process_t *_mk_proc(identity_t *peer)
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

/* The same group, rotated to a new key: what identity adopted. */
static void _rotated(const group_t *g, group_t *out)
{
    json_t *obj = NULL;
    ck_assert_ret_ok(group_to_json(g, &obj));
    memset(out, 0, sizeof(*out));
    ck_assert_ret_ok(group_from_json(obj, out));
    json_decref(obj);
    ck_assert(group_rotate_key(out) > g->key_epoch);
}

/* A peer_dm from @p from, framed and sealed under @p grp as
 * net_encrypt_and_send's group branch does: nonce | group_encrypt(wire). */
static uint8_t *_frame(identity_t *from, const group_t *grp, size_t *out_len)
{
    net_wire_msg_t w = {0};
    snprintf(w.process, sizeof(w.process), "%s", "identity");
    w.function = strdup("peer_dm");
    w.data = (uint8_t *)strdup("{}");
    w.data_len = 2;
    w.to_whom.type = RECIPIENT_GROUP;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    ck_assert_ret_ok(net_message_to_wire(&w, from, &wire, &wire_len));
    free(w.function);
    free(w.data);

    unsigned char nonce[crypto_box_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));
    msg_str_t plain = { .msg = wire, .len = wire_len };
    size_t cipher_len = wire_len + crypto_box_MACBYTES;
    uint8_t *frame = malloc(sizeof(nonce) + cipher_len);
    ck_assert_ptr_nonnull(frame);
    memcpy(frame, nonce, sizeof(nonce));
    ck_assert_int_eq(group_encrypt(grp, &plain, grp, nonce, frame + sizeof(nonce)), 0);
    free(wire);
    *out_len = sizeof(nonce) + cipher_len;
    return frame;
}

static void _begin(void)
{
    ck_assert(sodium_init() >= 0);
    g_delivered = 0;
    net_held_group_frames_reset();
    messaging_set_test_hook(_hook);
}

static void _end(void)
{
    net_held_group_frames_reset();
    messaging_set_test_hook(NULL);
}

/* The live shape: sent under the key identity adopted, before ours caught up. */
DEFINE_TEST(test_a_frame_under_a_key_not_yet_installed_opens_once_it_is)
{
    _begin();
    identity_t *me = _mk("mate", "10.0.0.1"), *off = _mk("officer", "10.0.0.2");
    process_t *proc = _mk_proc(off);
    net_thread_ctx_t ctx = { .proc = proc, .myself = me };
    group_t next;
    _rotated(&proc->protocol.group, &next);

    size_t fl = 0;
    uint8_t *f = _frame(off, &next, &fl);
    handle_inbound_group(&ctx, f, fl, "10.0.0.2");
    free(f);
    ck_assert_int_eq(g_delivered, 0);
    ck_assert_int_eq((int)net_held_group_frame_count(), 1);

    /* No key change yet: nothing to try, and the frame stays. */
    ck_assert_int_eq((int)net_retry_held_group_frames(&ctx), 0);
    ck_assert_int_eq((int)net_held_group_frame_count(), 1);

    /* The network process installs identity's key. */
    proc->protocol.group = next;
    ck_assert_int_eq((int)net_retry_held_group_frames(&ctx), 1);
    ck_assert_int_eq(g_delivered, 1);
    ck_assert_int_eq((int)net_held_group_frame_count(), 0);
    _end();
}

/* A frame that does not open under the new key either is dropped, not held
 * again: it was under some other group's key all along. */
DEFINE_TEST(test_a_frame_that_still_does_not_open_is_dropped)
{
    _begin();
    identity_t *me = _mk("mate", "10.0.0.1"), *off = _mk("officer", "10.0.0.2");
    process_t *proc = _mk_proc(off);
    net_thread_ctx_t ctx = { .proc = proc, .myself = me };
    group_t next, other;
    _rotated(&proc->protocol.group, &next);
    _rotated(&proc->protocol.group, &other);

    size_t fl = 0;
    uint8_t *f = _frame(off, &other, &fl);
    handle_inbound_group(&ctx, f, fl, "10.0.0.2");
    free(f);
    ck_assert_int_eq((int)net_held_group_frame_count(), 1);
    proc->protocol.group = next;
    ck_assert_int_eq((int)net_retry_held_group_frames(&ctx), 1);
    ck_assert_int_eq(g_delivered, 0);
    ck_assert_int_eq((int)net_held_group_frame_count(), 0);
    _end();
}

/* A frame that opens is delivered at once and never held. */
DEFINE_TEST(test_a_frame_under_our_key_is_not_held)
{
    _begin();
    identity_t *me = _mk("mate", "10.0.0.1"), *off = _mk("officer", "10.0.0.2");
    process_t *proc = _mk_proc(off);
    net_thread_ctx_t ctx = { .proc = proc, .myself = me };
    size_t fl = 0;
    uint8_t *f = _frame(off, &proc->protocol.group, &fl);
    handle_inbound_group(&ctx, f, fl, "10.0.0.2");
    free(f);
    ck_assert_int_eq(g_delivered, 1);
    ck_assert_int_eq((int)net_held_group_frame_count(), 0);
    _end();
}

/* The hold is bounded: past NET_HELD_GROUP_FRAMES the oldest goes, so a flood
 * of frames under some other key cannot crowd out the newest. */
DEFINE_TEST(test_the_hold_is_bounded_and_keeps_the_newest)
{
    _begin();
    identity_t *me = _mk("mate", "10.0.0.1"), *off = _mk("officer", "10.0.0.2");
    process_t *proc = _mk_proc(off);
    net_thread_ctx_t ctx = { .proc = proc, .myself = me };
    group_t next, other;
    _rotated(&proc->protocol.group, &next);
    _rotated(&proc->protocol.group, &other);
    for (int i = 0; i < NET_HELD_GROUP_FRAMES + 4; i++) {
        size_t fl = 0;
        uint8_t *f = _frame(off, i < NET_HELD_GROUP_FRAMES ? &other : &next, &fl);
        handle_inbound_group(&ctx, f, fl, "10.0.0.2");
        free(f);
    }
    ck_assert_int_eq((int)net_held_group_frame_count(), NET_HELD_GROUP_FRAMES);
    proc->protocol.group = next;
    ck_assert_int_eq((int)net_retry_held_group_frames(&ctx), NET_HELD_GROUP_FRAMES);
    ck_assert_int_eq(g_delivered, 4);
    _end();
}

RUN_TESTS(NetHeldGroup,
          test_a_frame_under_a_key_not_yet_installed_opens_once_it_is,
          test_a_frame_that_still_does_not_open_is_dropped,
          test_a_frame_under_our_key_is_not_held,
          test_the_hold_is_bounded_and_keeps_the_newest)
