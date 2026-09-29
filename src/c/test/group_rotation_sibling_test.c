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

/** @file An adopted group key must reach the NETWORK process, not only identity.
 *
 *  Partition cohort part-3310971 (2026-09-28): four nodes each logged the
 *  adoption of the same rotated key, then multicast under three different
 *  keys and could open none of each other's frames. A rotation changes no
 *  membership, so the group_key_update carrying it is equal-or-smaller than
 *  ours, and handle_group_update's quiet no-op return was its only exit: the
 *  key changed in identity and never went out to the sibling processes, whose
 *  protocol.group (processes.c GROUP handler) is what net_proc encrypts with.
 *
 *  Mirrors tests/a_unit/test_group_key_convergence.py
 *  TestAdoptedKeyReachesSiblings. Dispatch follows identity_resync_test.c.
 */

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

static char ID_UPDATE_FN[] = "group_key_update";
static char NET_NAME[]     = "network";
static char ID_NAME[]      = "identity";

/* GROUP messages handed to the network process, and the key the last carried. */
static size_t g_group_to_network;
static unsigned char g_last_key[crypto_box_PUBLICKEYBYTES];

static int _capture_hook(const char *key, const message_type_t type,
                         generic_msg_t *msg, bool blocking)
{
    (void)blocking;
    if (type == GROUP && key != NULL && strcmp(key, NET_NAME) == 0) {
        g_group_to_network++;
        memcpy(g_last_key, msg->info.group.encryptor.public, sizeof(g_last_key));
    }
    return 0;
}

static void _begin(void)
{
    ck_assert(sodium_init() >= 0);
    identity_reset_state();
    g_group_to_network = 0;
    memset(g_last_key, 0, sizeof(g_last_key));
    messaging_set_test_hook(_capture_hook);
}

static void _end(void)
{
    messaging_set_test_hook(NULL);
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

/* An identity process holding a keyed group with self as its only member. */
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

/* A second member's copy of @p proc's group: same uuid, key and membership. */
static void _copy_group(const process_t *proc, group_t *out)
{
    json_t *obj = NULL;
    ck_assert_ret_ok(group_to_json(&proc->protocol.group, &obj));
    memset(out, 0, sizeof(*out));
    ck_assert_ret_ok(group_from_json(obj, out));
    json_decref(obj);
}

static void _drop_copy(group_t *g)
{
    if (g->address_map.items != NULL)
        map_free(&g->address_map);
}

/* Dispatch @p theirs as a VERIFIED group_key_update from @p member, through a
 * queue directory naming both identity and network (so _remember_activity has
 * a sibling to tell). */
static void _dispatch_update(process_t *proc, identity_t *member, group_t *theirs)
{
    json_t *payload = NULL;
    ck_assert_ret_ok(group_to_json(theirs, &payload));

    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = ID_UPDATE_FN;
    msg.info.net_msg.verified = true;
    msg.info.net_msg.has_signature = true;
    uuid_copy(msg.info.net_msg.from_whom.uuid, member->uuid);
    at_strlcpy(msg.info.net_msg.from_whom.nickname, member->nickname,
               sizeof(msg.info.net_msg.from_whom.nickname));
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, payload));
    json_decref(payload);

    directory_t *queues = NULL;
    ck_assert_ret_ok(array_create(&queues));
    ck_assert_ret_ok(array_append(queues, string_data(ID_NAME, strlen(ID_NAME))));
    ck_assert_ret_ok(array_append(queues, string_data(NET_NAME, strlen(NET_NAME))));
    run_message_handlers(proc, queues, NET_MESSAGE, &msg);
    array_free(queues);
}

/* The live shape: a peer rotated (higher epoch), membership unchanged. */
DEFINE_TEST(test_an_equal_size_rotation_reaches_the_network_process)
{
    _begin();
    identity_t *me = _mk_identity("ada", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    process_t *proc = _mk_process(me);

    group_t theirs;
    _copy_group(proc, &theirs);
    ck_assert(group_rotate_key(&theirs) > proc->protocol.group.key_epoch);

    _dispatch_update(proc, bob, &theirs);

    /* Precondition: identity adopted it. */
    ck_assert_int_eq(memcmp(proc->protocol.group.encryptor.public,
                            theirs.encryptor.public,
                            crypto_box_PUBLICKEYBYTES), 0);
    /* The property: the network process was handed THAT key. */
    ck_assert_int_eq((int)g_group_to_network, 1);
    ck_assert_int_eq(memcmp(g_last_key, theirs.encryptor.public,
                            crypto_box_PUBLICKEYBYTES), 0);

    _drop_copy(&theirs);
    _end();
}

/* Control: a stale rotation is declined, and nothing is sent — the network
 * process already holds the key that stands. */
DEFINE_TEST(test_a_declined_rotation_sends_nothing)
{
    _begin();
    identity_t *me = _mk_identity("ada", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    process_t *proc = _mk_process(me);

    group_t theirs;
    _copy_group(proc, &theirs);
    ck_assert(group_rotate_key(&proc->protocol.group) > theirs.key_epoch);
    unsigned char ours[crypto_box_PUBLICKEYBYTES];
    memcpy(ours, proc->protocol.group.encryptor.public, sizeof(ours));

    _dispatch_update(proc, bob, &theirs);

    ck_assert_int_eq(memcmp(proc->protocol.group.encryptor.public, ours,
                            sizeof(ours)), 0);
    ck_assert_int_eq((int)g_group_to_network, 0);

    _drop_copy(&theirs);
    _end();
}

RUN_TESTS(GroupRotationSibling,
          test_an_equal_size_rotation_reaches_the_network_process,
          test_a_declined_rotation_sends_nothing)
