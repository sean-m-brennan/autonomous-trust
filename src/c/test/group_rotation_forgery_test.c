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

/** @file A stranger on the broadcast channel must not be able to rotate our key.
 *
 *  handle_inbound_broadcast parses with no transport peer, so the sender is
 *  rebuilt from the envelope's own from_* fields and the signature is checked
 *  against the key the envelope names. Any keypair signs its own frame
 *  validly, so such a frame always comes out verified. group_key_update is a
 *  broadcast-only verb, and handle_group_update raises the epoch on any
 *  verified update for our group uuid. Together, anyone who knows the group
 *  uuid can hand a member a key of their own choosing.
 *
 *  These tests drive a forged rotation through handle_inbound_broadcast and
 *  route_to_process into the identity handlers and assert the member keeps
 *  its key. The Python twin is
 *  tests/a_unit/test_broadcast_rotation_forgery.py.
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
#include "network/net_message.h"
#include "network/net_proc_priv.h"
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

static char NET_NAME[] = "network";
static char ID_NAME[]  = "identity";

/* The identity process the network hands its routed frames to. */
static process_t *g_id_proc;
static int g_delivered;

static directory_t *_queues(void)
{
    directory_t *queues = NULL;
    ck_assert_ret_ok(array_create(&queues));
    ck_assert_ret_ok(array_append(queues, string_data(ID_NAME, strlen(ID_NAME))));
    ck_assert_ret_ok(array_append(queues, string_data(NET_NAME, strlen(NET_NAME))));
    return queues;
}

/* Deliver what route_to_process sends to identity straight to its handlers. */
static int _deliver_hook(const char *key, const message_type_t type,
                         generic_msg_t *msg, bool blocking)
{
    (void)blocking;
    if (type == NET_MESSAGE && key != NULL && strcmp(key, ID_NAME) == 0
        && g_id_proc != NULL) {
        g_delivered++;
        directory_t *queues = _queues();
        run_message_handlers(g_id_proc, queues, NET_MESSAGE, msg);
        array_free(queues);
    }
    return 0;
}

static void _begin(void)
{
    ck_assert(sodium_init() >= 0);
    identity_reset_state();
    g_delivered = 0;
    messaging_set_test_hook(_deliver_hook);
}

static void _end(void)
{
    messaging_set_test_hook(NULL);
    g_id_proc = NULL;
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

/* An identity process in phase 3 holding a keyed group of @p self and
 * @p other, with @p other held as a peer. */
static process_t *_mk_member(identity_t *self, identity_t *other)
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
    char ustr[UUID_STRING_LEN + 1];
    uuid_unparse_lower(self->uuid, ustr);
    group_add_address(&proc->protocol.group, ustr, self->address);
    uuid_unparse_lower(other->uuid, ustr);
    group_add_address(&proc->protocol.group, ustr, other->address);

    public_identity_t *pub = &proc->protocol.peers[proc->protocol.num_peers++];
    memcpy(pub, other, sizeof(public_identity_t));
    memset(pub->signature.private, 0, sizeof(pub->signature.private));

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

/* What a stranger mints: our group's uuid, epoch 2, a fresh private key,
 * signed by @p forger, as a plaintext broadcast envelope. @p claimed, when
 * not NULL, is the uuid the envelope names in place of the forger's own; the
 * keys on the envelope stay the forger's. */
static uint8_t *_forged_rotation(const process_t *member, identity_t *forger,
                                 const identity_t *claimed, group_t *rogue,
                                 size_t *len)
{
    json_t *obj = NULL;
    ck_assert_ret_ok(group_to_json(&member->protocol.group, &obj));
    memset(rogue, 0, sizeof(*rogue));
    ck_assert_ret_ok(group_from_json(obj, rogue));
    json_decref(obj);
    group_rotate_key(rogue);
    ck_assert(group_rotate_key(rogue) == 2);

    json_t *payload = NULL;
    ck_assert_ret_ok(group_to_json(rogue, &payload));
    char *data = json_dumps(payload, JSON_COMPACT);
    json_decref(payload);

    net_wire_msg_t w;
    memset(&w, 0, sizeof(w));
    snprintf(w.process, sizeof(w.process), "identity");
    w.function = strdup("group_key_update");
    w.data = (uint8_t *)data;
    w.data_len = strlen(data);
    w.to_whom.type = RECIPIENT_BROADCAST;
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(forger, &pub));
    memcpy(&w.from_whom, pub, sizeof(*pub));
    smrt_deref(pub);
    if (claimed != NULL)
        uuid_copy(w.from_whom.uuid, claimed->uuid);

    uint8_t *out = NULL;
    ck_assert_ret_ok(net_message_to_wire(&w, forger, &out, len));
    free(w.function);
    free(w.data);
    return out;
}

static void _broadcast(identity_t *me, const uint8_t *frame, size_t len)
{
    process_t *net = smrt_create(sizeof(process_t));
    ck_assert_ptr_nonnull(net);
    pthread_rwlock_init(&net->protocol.peers_rwlock, NULL);
    strncpy(net->name, "network", PROC_NAME_LEN);
    net_thread_ctx_t ctx = { .proc = net, .myself = me };
    uint8_t *copy = malloc(len);
    memcpy(copy, frame, len);
    handle_inbound_broadcast(&ctx, copy, len, "10.0.0.9");
    free(copy);
}

static void _drop(group_t *g)
{
    if (g->address_map.items != NULL)
        map_free(&g->address_map);
}

DEFINE_TEST(test_a_strangers_rotation_is_not_adopted)
{
    _begin();
    identity_t *me = _mk_identity("member", "10.0.0.1");
    identity_t *other = _mk_identity("other", "10.0.0.2");
    identity_t *mallory = _mk_identity("mallory", "10.0.0.9");
    g_id_proc = _mk_member(me, other);
    unsigned char before[crypto_box_PUBLICKEYBYTES];
    memcpy(before, g_id_proc->protocol.group.encryptor.public, sizeof(before));

    group_t rogue;
    size_t len = 0;
    uint8_t *frame = _forged_rotation(g_id_proc, mallory, NULL, &rogue, &len);
    _broadcast(me, frame, len);
    free(frame);

    ck_assert_int_eq(g_delivered, 1);
    ck_assert_int_eq((int)g_id_proc->protocol.group.key_epoch, 0);
    ck_assert_mem_eq(g_id_proc->protocol.group.encryptor.public, before,
                     sizeof(before));
    _drop(&rogue);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_rotation_claiming_a_members_uuid_is_not_adopted)
{
    _begin();
    identity_t *me = _mk_identity("member", "10.0.0.1");
    identity_t *other = _mk_identity("other", "10.0.0.2");
    identity_t *mallory = _mk_identity("mallory", "10.0.0.9");
    g_id_proc = _mk_member(me, other);
    unsigned char before[crypto_box_PUBLICKEYBYTES];
    memcpy(before, g_id_proc->protocol.group.encryptor.public, sizeof(before));

    group_t rogue;
    size_t len = 0;
    uint8_t *frame = _forged_rotation(g_id_proc, mallory, other, &rogue, &len);
    _broadcast(me, frame, len);
    free(frame);

    ck_assert_int_eq((int)g_id_proc->protocol.group.key_epoch, 0);
    ck_assert_mem_eq(g_id_proc->protocol.group.encryptor.public, before,
                     sizeof(before));
    _drop(&rogue);
    _end();
}
END_TEST_DEFINITION()

/* A peer we hold is attributed by the transport, so its frame verifies
 * against its real key. Holding it says nothing about whether it belongs to
 * this group. */
DEFINE_TEST(test_a_held_peer_outside_the_group_cannot_rotate_it)
{
    _begin();
    identity_t *me = _mk_identity("member", "10.0.0.1");
    identity_t *other = _mk_identity("other", "10.0.0.2");
    identity_t *outsider = _mk_identity("outsider", "10.0.0.8");
    g_id_proc = _mk_member(me, other);
    public_identity_t *held = &g_id_proc->protocol.peers[g_id_proc->protocol.num_peers++];
    memcpy(held, outsider, sizeof(public_identity_t));
    memset(held->signature.private, 0, sizeof(held->signature.private));
    unsigned char before[crypto_box_PUBLICKEYBYTES];
    memcpy(before, g_id_proc->protocol.group.encryptor.public, sizeof(before));

    group_t rogue;
    size_t len = 0;
    uint8_t *frame = _forged_rotation(g_id_proc, outsider, NULL, &rogue, &len);
    net_wire_msg_t w;
    ck_assert_ret_ok(net_message_from_wire_fmt(frame, len, held, NET_WIRE_JSON, &w));
    free(frame);
    ck_assert(w.verified); /* precondition: verified against the held key */

    process_t *net = smrt_create(sizeof(process_t));
    pthread_rwlock_init(&net->protocol.peers_rwlock, NULL);
    strncpy(net->name, "network", PROC_NAME_LEN);
    ck_assert_int_eq(net_proc_test_route_on_path(&w, net, NULL, NET_PATH_PEER), 0);
    net_wire_msg_free(&w);

    ck_assert_int_eq(g_delivered, 1);
    ck_assert_int_eq((int)g_id_proc->protocol.group.key_epoch, 0);
    ck_assert_mem_eq(g_id_proc->protocol.group.encryptor.public, before,
                     sizeof(before));
    _drop(&rogue);
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(GroupRotationForgery,
          test_a_strangers_rotation_is_not_adopted,
          test_a_rotation_claiming_a_members_uuid_is_not_adopted,
          test_a_held_peer_outside_the_group_cannot_rotate_it)
