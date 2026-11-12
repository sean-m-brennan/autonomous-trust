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
/* When a peer was last heard through the node's own transport, kept apart from
 * frames an extension delivered some other way. */
#define DEBUG_TESTS 1
#include "test_setup.h"

#include <math.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <uuid/uuid.h>

#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "network/net_liveness.h"
#include "network/net_message.h"
#include "network/net_proc_priv.h"
#include "processes/processes.h"
#include "utilities/allocation.h"
#include "utilities/message.h"

static int _hook(const char *key, const message_type_t type,
                 generic_msg_t *msg, bool blocking)
{
    (void)key; (void)type; (void)msg; (void)blocking;
    return 0;
}

DEFINE_TEST(test_never_heard_counts_from_start)
{
    uuid_t a;
    uuid_generate(a);
    net_liveness_reset(100.0);
    ck_assert(fabs(net_liveness_quiet_for(a, 130.0) - 30.0) < 1e-9);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_heard_resets_quiet_and_older_is_ignored)
{
    uuid_t a;
    uuid_generate(a);
    net_liveness_reset(100.0);
    net_liveness_heard(a, 140.0);
    ck_assert(fabs(net_liveness_quiet_for(a, 150.0) - 10.0) < 1e-9);
    net_liveness_heard(a, 120.0);
    ck_assert(fabs(net_liveness_quiet_for(a, 150.0) - 10.0) < 1e-9);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_quiet_is_never_negative)
{
    uuid_t a;
    uuid_generate(a);
    net_liveness_reset(100.0);
    net_liveness_heard(a, 200.0);
    ck_assert(fabs(net_liveness_quiet_for(a, 150.0) - 0.0) < 1e-9);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_full_table_forgets_the_longest_quiet)
{
    net_liveness_reset(0.0);
    uuid_t first;
    uuid_generate(first);
    net_liveness_heard(first, 1.0);
    for (int i = 0; i < NET_LIVENESS_MAX - 1; i++) {
        uuid_t u;
        uuid_generate(u);
        net_liveness_heard(u, 10.0 + i);
    }
    uuid_t extra;
    uuid_generate(extra);
    net_liveness_heard(extra, 5000.0);
    ck_assert(fabs(net_liveness_quiet_for(extra, 5000.0) - 0.0) < 1e-9);
    /* `first` was replaced, so it counts from start again. */
    ck_assert(fabs(net_liveness_quiet_for(first, 5000.0) - 5000.0) < 1e-9);
}
END_TEST_DEFINITION()

static process_t *_mk_proc(void)
{
    process_t *proc = smrt_create(sizeof(process_t));
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    strncpy(proc->name, "network", PROC_NAME_LEN);
    return proc;
}

static void _route_from(process_t *proc, const uuid_t from)
{
    net_wire_msg_t w = {0};
    snprintf(w.process, sizeof(w.process), "%s", "identity");
    w.function = strdup("peer_dm");
    w.data = (uint8_t *)strdup("{}");
    w.data_len = 2;
    uuid_copy(w.from_whom.uuid, from);
    ck_assert_int_eq(net_proc_test_route_on_path(&w, proc, NULL, NET_PATH_PEER), 0);
    free(w.function);
    free(w.data);
}

DEFINE_TEST(test_transport_frames_stamp_and_extension_frames_do_not)
{
    messaging_set_test_hook(_hook);
    process_t *proc = _mk_proc();
    uuid_t a, b;
    uuid_generate(a);
    uuid_generate(b);
    double start = net_liveness_now();
    net_liveness_reset(start - 100.0);

    _route_from(proc, a);
    ck_assert(net_liveness_quiet_for(a, net_liveness_now()) < 5.0);

    net_proc_test_set_ext_inbound(true);
    _route_from(proc, b);
    net_proc_test_set_ext_inbound(false);
    ck_assert(net_liveness_quiet_for(b, net_liveness_now()) >= 100.0);

    messaging_set_test_hook(NULL);
    smrt_deref(proc);
}
END_TEST_DEFINITION()

/* A stranger, a relayed stranger or the broadcast channel can claim a
 * member's uuid in its envelope; only the member paths, where the sender is a
 * peer we hold, say the transport reaches that peer. */
static void _route_claiming(process_t *proc, const uuid_t from, net_route_path_t path)
{
    net_wire_msg_t w = {0};
    snprintf(w.process, sizeof(w.process), "%s", "identity");
    w.function = strdup("request_access");
    w.data = (uint8_t *)strdup("{}");
    w.data_len = 2;
    uuid_copy(w.from_whom.uuid, from);
    (void)net_proc_test_route_on_path(&w, proc, NULL, path);
    free(w.function);
    free(w.data);
}

DEFINE_TEST(test_only_member_paths_stamp_a_claimed_uuid)
{
    messaging_set_test_hook(_hook);
    process_t *proc = _mk_proc();
    const net_route_path_t strangers[] = {NET_PATH_STRANGER, NET_PATH_RELAY_STRANGER,
                                          NET_PATH_BROADCAST};
    for (size_t i = 0; i < sizeof(strangers) / sizeof(strangers[0]); i++) {
        uuid_t a;
        uuid_generate(a);
        net_liveness_reset(net_liveness_now() - 100.0);
        _route_claiming(proc, a, strangers[i]);
        ck_assert(net_liveness_quiet_for(a, net_liveness_now()) >= 100.0);
    }
    const net_route_path_t members[] = {NET_PATH_PEER, NET_PATH_GROUP, NET_PATH_PLAIN_KNOWN};
    for (size_t i = 0; i < sizeof(members) / sizeof(members[0]); i++) {
        uuid_t a;
        uuid_generate(a);
        net_liveness_reset(net_liveness_now() - 100.0);
        _route_claiming(proc, a, members[i]);
        ck_assert(net_liveness_quiet_for(a, net_liveness_now()) < 5.0);
    }
    messaging_set_test_hook(NULL);
    smrt_deref(proc);
}
END_TEST_DEFINITION()

static identity_t *_mk_id(const char *name, const char *addr)
{
    uuid_t u;
    uuid_generate(u);
    identity_t *id = NULL;
    ck_assert_ret_ok(identity_create(&u, addr, name, name, &id));
    return id;
}

/* A plaintext access_granted from @p sender, as a relay would carry it. */
static uint8_t *_plain_wire(identity_t *sender, size_t *len)
{
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(sender, &pub));
    net_wire_msg_t w = {0};
    snprintf(w.process, sizeof(w.process), "%s", "identity");
    w.function = strdup("access_granted");
    w.data = (uint8_t *)strdup("{}");
    w.data_len = 2;
    w.to_whom.type = RECIPIENT_BROADCAST;
    memcpy(&w.from_whom, pub, sizeof(*pub));
    uint8_t *out = NULL;
    ck_assert_ret_ok(net_message_to_wire(&w, sender, &out, len));
    free(w.function);
    free(w.data);
    smrt_deref(pub);
    return out;
}

/* A relayed frame from a sender we do not hold leaves by one of three ways:
 * unreadable, an envelope naming someone other than the sender the relay
 * stamped, or a stranger's plaintext routed as such. None stamps, and each
 * puts the thread's mark back, so the next transport frame stamps as ever. */
DEFINE_TEST(test_every_relayed_way_out_restores_the_transport_stamp)
{
    messaging_set_test_hook(_hook);
    process_t *proc = _mk_proc();
    identity_t *me = _mk_id("me", "10.0.0.1");
    identity_t *bob = _mk_id("bob", "10.0.0.2"), *mallory = _mk_id("mallory", "10.0.0.3");
    net_thread_ctx_t ctx = { .proc = proc, .myself = me };
    char bu[UUID_STR_LEN + 1], mu[UUID_STR_LEN + 1];
    uuid_unparse_lower(bob->uuid, bu);
    uuid_unparse_lower(mallory->uuid, mu);
    size_t len = 0;
    uint8_t *frame = _plain_wire(bob, &len);
    uint8_t junk[] = "not a frame";
    struct { const uint8_t *buf; size_t len; const char *from; } ways[] = {
        { junk, sizeof(junk) - 1, bu },   /* unreadable */
        { frame, len, mu },               /* claims bob, stamped as mallory */
        { frame, len, bu },               /* a stranger's hello */
    };
    for (size_t i = 0; i < sizeof(ways) / sizeof(ways[0]); i++) {
        net_liveness_reset(net_liveness_now() - 100.0);
        handle_inbound_relayed(&ctx, ways[i].buf, ways[i].len, ways[i].from);
        ck_assert(net_liveness_quiet_for(bob->uuid, net_liveness_now()) >= 100.0);
        ck_assert(net_liveness_quiet_for(mallory->uuid, net_liveness_now()) >= 100.0);
        uuid_t c;
        uuid_generate(c);
        _route_from(proc, c);
        ck_assert(net_liveness_quiet_for(c, net_liveness_now()) < 5.0);
    }
    free(frame);
    identity_free(mallory);
    identity_free(bob);
    identity_free(me);
    messaging_set_test_hook(NULL);
    smrt_deref(proc);
}
END_TEST_DEFINITION()

RUN_TESTS(NET_LIVENESS,
          test_never_heard_counts_from_start,
          test_heard_resets_quiet_and_older_is_ignored,
          test_quiet_is_never_negative,
          test_full_table_forgets_the_longest_quiet,
          test_transport_frames_stamp_and_extension_frames_do_not,
          test_only_member_paths_stamp_a_claimed_uuid,
          test_every_relayed_way_out_restores_the_transport_stamp)
