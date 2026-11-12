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

/* A queue directory naming both identity and network (so _remember_activity
 * has a sibling to tell). */
static directory_t *_queues(void)
{
    directory_t *queues = NULL;
    ck_assert_ret_ok(array_create(&queues));
    ck_assert_ret_ok(array_append(queues, string_data(ID_NAME, strlen(ID_NAME))));
    ck_assert_ret_ok(array_append(queues, string_data(NET_NAME, strlen(NET_NAME))));
    return queues;
}

/* Sign @p nmsg's pre-image (`process|function|base64(data)`) with
 * @p signer's key, as the sender's network process does. */
static void _sign_update(net_msg_t *nmsg, const identity_t *signer)
{
    size_t b64_len = sodium_base64_encoded_len(nmsg->len,
                                               sodium_base64_VARIANT_ORIGINAL);
    char *b64 = malloc(b64_len);
    sodium_bin2base64(b64, b64_len, nmsg->obj, nmsg->len,
                      sodium_base64_VARIANT_ORIGINAL);
    size_t pre_len = strlen("identity|group_key_update|") + strlen(b64);
    char *pre = malloc(pre_len + 1);
    snprintf(pre, pre_len + 1, "identity|group_key_update|%s", b64);
    crypto_sign_detached(nmsg->signature, NULL, (unsigned char *)pre,
                         pre_len, signer->signature.private);
    free(pre);
    free(b64);
    nmsg->has_signature = true;
}

/* Name @p member in @p proc's group. */
static void _add_member(process_t *proc, identity_t *member)
{
    char ustr[UUID_STRING_LEN + 1];
    uuid_unparse_lower(member->uuid, ustr);
    ck_assert_ret_ok(group_add_address(&proc->protocol.group, ustr, member->address));
}

/* Hold @p member as an admitted peer, as the history's roster does. */
static void _hold_peer(process_t *proc, identity_t *member)
{
    public_identity_t *pub = &proc->protocol.peers[proc->protocol.num_peers++];
    memcpy(pub, member, sizeof(public_identity_t));
    memset(pub->signature.private, 0, sizeof(pub->signature.private));
}

/* A member of @p proc's group that @p proc holds: whose rotations it takes. */
static void _hold_member(process_t *proc, identity_t *member)
{
    _add_member(proc, member);
    _hold_peer(proc, member);
}

/* Dispatch @p theirs as a VERIFIED group_key_update signed by @p member,
 * through a queue directory naming both identity and network (so
 * _remember_activity has a sibling to tell). */
static void _dispatch_update(process_t *proc, identity_t *member, group_t *theirs)
{
    json_t *payload = NULL;
    ck_assert_ret_ok(group_to_json(theirs, &payload));

    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = ID_UPDATE_FN;
    msg.info.net_msg.verified = true;
    uuid_copy(msg.info.net_msg.from_whom.uuid, member->uuid);
    at_strlcpy(msg.info.net_msg.from_whom.nickname, member->nickname,
               sizeof(msg.info.net_msg.from_whom.nickname));
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, payload));
    json_decref(payload);
    _sign_update(&msg.info.net_msg, member);

    directory_t *queues = _queues();
    run_message_handlers(proc, queues, NET_MESSAGE, &msg);
    array_free(queues);
    /* A held update keeps its own copy; this one is ours to free. */
    net_msg_free_obj(&msg.info.net_msg);
}

/* The live shape: a peer rotated (higher epoch), membership unchanged. */
DEFINE_TEST(test_an_equal_size_rotation_reaches_the_network_process)
{
    _begin();
    identity_t *me = _mk_identity("ada", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    process_t *proc = _mk_process(me);
    _hold_member(proc, bob);

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
    _hold_member(proc, bob);

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

/* Partition cohort part-3615656 (2026-10-14), ISSUES §2.61: three members
 * rotated at once to the same epoch. cal was still in phase 2 when amy's and
 * dee's update with the winning (lower) key arrived, so it dropped them, then
 * took the losing key from the merge history. Nobody resends to a member, so
 * cal held the losing key for good. The update is now held and replayed at
 * phase 3, where the same-epoch tiebreak hands cal the winner. */
DEFINE_TEST(test_an_update_before_phase_3_is_replayed_and_settles_the_tiebreak)
{
    _begin();
    identity_t *me = _mk_identity("cal", "10.0.0.3");
    identity_t *amy = _mk_identity("amy", "10.0.0.2");
    process_t *proc = _mk_process(me);
    _hold_member(proc, amy);

    /* Two members' simultaneous rotations of one group: the same epoch. */
    group_t a, b;
    _copy_group(proc, &a);
    _copy_group(proc, &b);
    int64_t epoch = group_rotate_key(&a);
    ck_assert(group_rotate_key(&b) == epoch);
    int order = memcmp(a.encryptor.public, b.encryptor.public,
                       crypto_box_PUBLICKEYBYTES);
    ck_assert(order != 0);
    group_t *winner = order < 0 ? &a : &b;
    group_t *loser = order < 0 ? &b : &a;

    proc->protocol.phase = 2;
    _dispatch_update(proc, amy, winner);
    ck_assert_int_eq((int)g_group_to_network, 0);       /* nothing applied yet */

    /* Joining the group takes the losing key, as cal's merge did. */
    ck_assert(group_accept_rotation(&proc->protocol.group, loser));
    proc->protocol.phase = 3;

    directory_t *queues = _queues();
    ck_assert_int_eq((int)identity_replay_held_group_updates(proc, queues), 1);
    ck_assert_int_eq(memcmp(proc->protocol.group.encryptor.public,
                            winner->encryptor.public,
                            crypto_box_PUBLICKEYBYTES), 0);
    ck_assert_int_eq((int)g_group_to_network, 1);
    ck_assert_int_eq(memcmp(g_last_key, winner->encryptor.public,
                            crypto_box_PUBLICKEYBYTES), 0);
    /* Replayed once, then forgotten. */
    ck_assert_int_eq((int)identity_replay_held_group_updates(proc, queues), 0);
    array_free(queues);

    _drop_copy(&a);
    _drop_copy(&b);
    _end();
}

/* Reputation cohort rep-4070096-11 (2026-10-16), ISSUES §2.61: carol held
 * epoch 2 and adopted a DIFFERENT, larger group from a stale membership
 * update carrying that group's epoch-1 key. She kept her own epoch, so she
 * announced an epoch-1 key as epoch 2; it sorted lowest, and the members who
 * had retired it refused it for good. The key now comes with its own epoch
 * (and no retired keys from the group we left), so the node is simply behind
 * and the next rotation lifts it. */
DEFINE_TEST(test_an_adopted_groups_key_keeps_its_own_epoch)
{
    _begin();
    identity_t *me = _mk_identity("carol", "10.0.0.3");
    identity_t *alice = _mk_identity("alice", "10.0.0.1");
    process_t *proc = _mk_process(me);
    ck_assert(group_rotate_key(&proc->protocol.group) == 1);
    ck_assert(group_rotate_key(&proc->protocol.group) == 2);
    ck_assert_int_eq((int)proc->protocol.group.num_previous_keys, 2);

    /* Alice's group: another uuid, three members, its key at epoch 1. */
    group_t *theirs = NULL;
    uuid_t huuid;
    uuid_generate(huuid);
    ck_assert_ret_ok(group_create(&huuid, (char *)"10.0.0.1", &theirs));
    char alice_uuid[UUID_STRING_LEN + 1];
    uuid_unparse_lower(alice->uuid, alice_uuid);
    ck_assert_ret_ok(group_add_address(theirs, alice_uuid, "10.0.0.1"));
    _hold_peer(proc, alice);
    ck_assert_ret_ok(group_add_address(theirs, "uuid-bob", "10.0.0.2"));
    ck_assert_ret_ok(group_add_address(theirs, "uuid-dee", "10.0.0.4"));
    ck_assert(group_rotate_key(theirs) == 1);

    _dispatch_update(proc, alice, theirs);

    group_t *mine = &proc->protocol.group;
    ck_assert_mem_eq(mine->uuid, huuid, sizeof(uuid_t));
    ck_assert_mem_eq(mine->encryptor.public, theirs->encryptor.public,
                     crypto_box_PUBLICKEYBYTES);
    ck_assert_int_eq((int)mine->key_epoch, 1);
    ck_assert_int_eq((int)mine->num_previous_keys, 0);
    ck_assert_int_eq((int)g_group_to_network, 1);

    /* Behind, not forked: the group's real epoch-2 key is taken. */
    group_t next;
    _copy_group(proc, &next);
    ck_assert(group_rotate_key(theirs) == 2);
    next.encryptor = theirs->encryptor;
    next.key_epoch = 2;
    _dispatch_update(proc, alice, &next);
    ck_assert_int_eq((int)mine->key_epoch, 2);
    ck_assert_mem_eq(mine->encryptor.public, theirs->encryptor.public,
                     crypto_box_PUBLICKEYBYTES);

    _drop_copy(&next);
    group_free(theirs);
    _end();
}

/* The hold is bounded: past ID_HELD_GROUP_UPDATES the oldest goes. */
DEFINE_TEST(test_held_updates_are_bounded)
{
    _begin();
    identity_t *me = _mk_identity("cal", "10.0.0.3");
    identity_t *amy = _mk_identity("amy", "10.0.0.2");
    process_t *proc = _mk_process(me);
    group_t theirs;
    _copy_group(proc, &theirs);

    proc->protocol.phase = 2;
    for (int i = 0; i < ID_HELD_GROUP_UPDATES + 3; i++)
        _dispatch_update(proc, amy, &theirs);
    proc->protocol.phase = 3;

    directory_t *queues = _queues();
    ck_assert_int_eq((int)identity_replay_held_group_updates(proc, queues),
                     ID_HELD_GROUP_UPDATES);
    array_free(queues);
    _drop_copy(&theirs);
    _end();
}

/* Hostile-join run, 2026-11-03: a joiner still in phase 2 held the cohort's
 * rotations to epochs 10 and 11 from members it did not yet hold, so no
 * signature had been checked, and after phase 3 the gate refused every one;
 * the cohort never resent, and the joiner kept a forked key. A held update's
 * signature is now checked again against the peer this node holds for its
 * sender. Only a verified update raises the epoch, as before. Mirrors
 * tests/a_unit/test_group_key_convergence.py TestHeldRotationReverified. */

/* Hold @p theirs at phase 2 as an update signed by @p signer and attributed to
 * @p claimed, unverified (the network did not hold the sender), then reach
 * phase 3 and replay it. */
static void _hold_signed_then_replay(process_t *proc, identity_t *signer,
                                     identity_t *claimed, group_t *theirs)
{
    json_t *payload = NULL;
    ck_assert_ret_ok(group_to_json(theirs, &payload));
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = ID_UPDATE_FN;
    uuid_copy(msg.info.net_msg.from_whom.uuid, claimed->uuid);
    at_strlcpy(msg.info.net_msg.from_whom.nickname, claimed->nickname,
               sizeof(msg.info.net_msg.from_whom.nickname));
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, payload));
    json_decref(payload);

    _sign_update(&msg.info.net_msg, signer);
    msg.info.net_msg.verified = false;

    proc->protocol.phase = 2;
    directory_t *queues = _queues();
    run_message_handlers(proc, queues, NET_MESSAGE, &msg);
    net_msg_free_obj(&msg.info.net_msg);
    proc->protocol.phase = 3;
    ck_assert_int_eq((int)identity_replay_held_group_updates(proc, queues), 1);
    array_free(queues);
}

DEFINE_TEST(test_a_held_rotation_signed_by_a_held_member_is_adopted)
{
    _begin();
    identity_t *me = _mk_identity("joiner", "10.0.0.3");
    identity_t *member = _mk_identity("member", "10.0.0.2");
    process_t *proc = _mk_process(me);
    _add_member(proc, member);
    group_t theirs;
    _copy_group(proc, &theirs);
    group_rotate_key(&theirs);
    ck_assert(group_rotate_key(&theirs) == 2);
    _hold_peer(proc, member);

    _hold_signed_then_replay(proc, member, member, &theirs);

    ck_assert_int_eq((int)proc->protocol.group.key_epoch, 2);
    ck_assert_mem_eq(proc->protocol.group.encryptor.public,
                     theirs.encryptor.public, crypto_box_PUBLICKEYBYTES);
    _drop_copy(&theirs);
    _end();
}

DEFINE_TEST(test_a_held_rotation_signed_by_anyone_else_is_refused)
{
    _begin();
    identity_t *me = _mk_identity("joiner", "10.0.0.3");
    identity_t *member = _mk_identity("member", "10.0.0.2");
    identity_t *mallory = _mk_identity("mallory", "10.0.0.9");
    process_t *proc = _mk_process(me);
    _add_member(proc, member);
    group_t theirs;
    _copy_group(proc, &theirs);
    ck_assert(group_rotate_key(&theirs) == 1);
    _hold_peer(proc, member);

    _hold_signed_then_replay(proc, mallory, member, &theirs);

    ck_assert_int_eq((int)proc->protocol.group.key_epoch, 0);
    _drop_copy(&theirs);
    _end();
}

DEFINE_TEST(test_a_held_rotation_from_a_sender_not_yet_held_is_refused)
{
    _begin();
    identity_t *me = _mk_identity("joiner", "10.0.0.3");
    identity_t *member = _mk_identity("member", "10.0.0.2");
    process_t *proc = _mk_process(me);
    _add_member(proc, member);
    group_t theirs;
    _copy_group(proc, &theirs);
    ck_assert(group_rotate_key(&theirs) == 1);

    _hold_signed_then_replay(proc, member, member, &theirs);

    ck_assert_int_eq((int)proc->protocol.group.key_epoch, 0);
    _drop_copy(&theirs);
    _end();
}

RUN_TESTS(GroupRotationSibling,
          test_an_equal_size_rotation_reaches_the_network_process,
          test_a_declined_rotation_sends_nothing,
          test_an_update_before_phase_3_is_replayed_and_settles_the_tiebreak,
          test_held_updates_are_bounded,
          test_an_adopted_groups_key_keeps_its_own_epoch,
          test_a_held_rotation_signed_by_a_held_member_is_adopted,
          test_a_held_rotation_signed_by_anyone_else_is_refused,
          test_a_held_rotation_from_a_sender_not_yet_held_is_refused)
