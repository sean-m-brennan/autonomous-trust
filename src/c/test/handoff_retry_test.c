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

/** @file A sibling hand-off a full queue refused must be retried, not lost.
 *
 *  Partition cohort part-3473787 (2026-09-29): during a five-founder admission
 *  burst ada's identity process could not hand its network process the PEER for
 *  ben ("queue still full" after the 200 ms inline retry), and nothing ever
 *  tried again, so every frame ben sent ada was deferred as an unknown peer for
 *  the rest of the run. ISSUES §2.27.
 *
 *  The messaging test hook stands in for the network queue: it refuses with
 *  EAGAIN while g_refuse is set and records what it accepts.
 */

#define DEBUG_TESTS 1

#include "test_setup.h"

#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#include <jansson.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "identity/id_proc_priv.h"
#include "identity/group.h"
#include "config/configuration.h"
#include "structures/data.h"
#include "structures/map.h"
#include "structures/array.h"
#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
#include "utilities/msg_types_priv.h"
#include "utilities/allocation.h"
#include "utilities/util.h"

static char ID_CONFIRM_FN[] = "peer_accepted";
static char NET_NAME[]      = "network";
static char ID_NAME[]       = "identity";

static bool   g_refuse;
static size_t g_peer_to_network;
static size_t g_group_to_network;
static size_t g_removed_to_network;
static uuid_t g_last_peer;

static int _hook(const char *key, const message_type_t type,
                 generic_msg_t *msg, bool blocking)
{
    (void)blocking;
    if (key == NULL || strcmp(key, NET_NAME) != 0)
        return 0;
    if (type != PEER && type != GROUP && type != PEER_REMOVED)
        return 0;
    if (g_refuse)
        return EAGAIN;
    if (type == PEER) {
        g_peer_to_network++;
        memcpy(g_last_peer, msg->info.peer.uuid, sizeof(uuid_t));
    } else if (type == GROUP) {
        g_group_to_network++;
    } else {
        g_removed_to_network++;
    }
    return 0;
}

static void _begin(void)
{
    ck_assert(sodium_init() >= 0);
    identity_reset_state();
    g_refuse = false;
    g_peer_to_network = g_group_to_network = g_removed_to_network = 0;
    memset(g_last_peer, 0, sizeof(g_last_peer));
    messaging_set_test_hook(_hook);
}

static void _end(void)
{
    messaging_set_test_hook(NULL);
    identity_reset_state();
}

static identity_t *_mk_identity(const char *name, const char *addr)
{
    uuid_t uuid;
    uuid_generate(uuid);
    identity_t *ident = NULL;
    ck_assert_ret_ok(identity_create(&uuid, addr, name, name, &ident));
    ck_assert_ptr_nonnull(ident);
    return ident;
}

static process_t *_mk_process(identity_t *self)
{
    process_t *proc = smrt_create(sizeof(process_t));
    ck_assert_ptr_nonnull(proc);
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    strncpy(proc->name, "identity", PROC_NAME_LEN);
    proc->protocol.phase = 3;
    proc->protocol.num_peers = 0;

    uuid_t guuid;
    uuid_generate(guuid);
    group_init(&guuid, (char *)self->address, &proc->protocol.group);
    char self_uuid[UUID_STRING_LEN + 1];
    uuid_unparse_lower(self->uuid, self_uuid);
    group_add_address(&proc->protocol.group, self_uuid, self->address);

    config_t *id_cfg = calloc(1, sizeof(config_t));
    ck_assert_ptr_nonnull(id_cfg);
    id_cfg->name = "identity";
    id_cfg->data_struct = self;
    data_t *id_dat = object_ptr_data((ptr_t)id_cfg, sizeof(config_t));
    ck_assert_ret_ok(map_create(&proc->configs));
    map_set(proc->configs, (map_key_t)"identity", id_dat);

    ck_assert_ret_ok(map_create(&proc->protocol.handlers));
    ck_assert_ret_ok(identity_register_handlers(proc));
    return proc;
}

/* A peer_accepted naming @p who, through a directory that names the network
 * process, so the admission's sibling hand-offs actually go out. */
static void _dispatch_confirm(process_t *proc, identity_t *who)
{
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(who, &pub));
    json_t *ident_json = NULL;
    ck_assert_ret_ok(public_identity_to_json(pub, &ident_json));
    smrt_deref(pub);

    json_t *payload = json_object();
    json_object_set_new(payload, "peer", ident_json);
    /* Every confirm here comes from the same (zero) sender, so each needs a
     * fresh sequence number or the replay guard refuses it. */
    static int seq = 0;
    json_object_set_new(payload, "seq", json_integer(++seq));

    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = ID_CONFIRM_FN;
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, payload));
    json_decref(payload);

    directory_t *queues = NULL;
    ck_assert_ret_ok(array_create(&queues));
    ck_assert_ret_ok(array_append(queues, string_data(ID_NAME, strlen(ID_NAME))));
    ck_assert_ret_ok(array_append(queues, string_data(NET_NAME, strlen(NET_NAME))));
    run_message_handlers(proc, queues, NET_MESSAGE, &msg);
    array_free(queues);
}

/* THE REGRESSION: a refused PEER is retried on the tick until it lands, and
 * lands as the right peer. */
DEFINE_TEST(test_a_refused_peer_is_retried_until_it_lands)
{
    _begin();
    identity_t *me = _mk_identity("ada", "10.0.0.1");
    identity_t *ben = _mk_identity("ben", "10.0.0.5");
    process_t *proc = _mk_process(me);

    g_refuse = true;
    _dispatch_confirm(proc, ben);
    ck_assert_int_eq((int)g_peer_to_network, 0);
    ck_assert(identity_pending_sibling_handoffs() >= 1);

    /* Still full on the next tick: kept, not dropped. */
    identity_retry_sibling_handoffs(proc);
    ck_assert(identity_pending_sibling_handoffs() >= 1);
    ck_assert_int_eq((int)g_peer_to_network, 0);

    /* The queue drains: the next tick delivers it, once. */
    g_refuse = false;
    identity_retry_sibling_handoffs(proc);
    ck_assert_int_eq((int)g_peer_to_network, 1);
    ck_assert_int_eq(uuid_compare(g_last_peer, ben->uuid), 0);
    ck_assert_int_eq((int)identity_pending_sibling_handoffs(), 0);

    /* Nothing left: a further tick sends nothing more. */
    identity_retry_sibling_handoffs(proc);
    ck_assert_int_eq((int)g_peer_to_network, 1);
    _end();
}

/* GROUP is state: several refusals coalesce to one retry, of the group as it
 * stands when the retry runs. */
DEFINE_TEST(test_refused_group_updates_coalesce)
{
    _begin();
    identity_t *me = _mk_identity("ada", "10.0.0.1");
    identity_t *amy = _mk_identity("amy", "10.0.0.2");
    identity_t *bob = _mk_identity("bob", "10.0.0.3");
    process_t *proc = _mk_process(me);

    g_refuse = true;
    _dispatch_confirm(proc, amy);
    _dispatch_confirm(proc, bob);
    g_refuse = false;
    identity_retry_sibling_handoffs(proc);

    ck_assert(g_group_to_network <= 1);
    ck_assert_int_eq((int)g_peer_to_network, 2);
    ck_assert_int_eq((int)identity_pending_sibling_handoffs(), 0);
    _end();
}

/* A PEER that could not be told, for a peer removed before the retry, is not
 * resurrected: the retry reads identity's current view. */
DEFINE_TEST(test_a_peer_removed_meanwhile_is_not_re_added)
{
    _begin();
    identity_t *me = _mk_identity("ada", "10.0.0.1");
    identity_t *ben = _mk_identity("ben", "10.0.0.5");
    process_t *proc = _mk_process(me);

    g_refuse = true;
    _dispatch_confirm(proc, ben);
    ck_assert(processes_remove_peer(proc, ben->uuid));
    g_refuse = false;
    identity_retry_sibling_handoffs(proc);

    ck_assert_int_eq((int)g_peer_to_network, 0);
    _end();
}

RUN_TESTS(HandoffRetry,
          test_a_refused_peer_is_retried_until_it_lands,
          test_refused_group_updates_coalesce,
          test_a_peer_removed_meanwhile_is_not_re_added)
