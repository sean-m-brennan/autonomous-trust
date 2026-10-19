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
/* Two founders bridged by a common joiner (Stele st-284840, 2026-10-02).
 *
 * The verifier's request_access reached the owner while the owner was still
 * choosing its group, was dropped, and both founded a group. The observer was
 * admitted by both, adopted one, and told nobody, so the founders never met.
 * Now an early request_access is held and replayed at phase 3, and a node that
 * holds one group but was admitted into another sends the other's members its
 * history, which a self-bootstrapped founder merges on. */
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

static char ID_ANNOUNCE_FN[] = "request_access";
static char ID_HISTORY_FN[]  = "full_history";
static char NET_NAME[]       = "network";
static char ID_NAME[]        = "identity";

/* Every full_history handed to the network process, by recipient. */
#define MAX_SENT 8
static size_t g_histories_sent;
static char g_sent_to[MAX_SENT][64];

static int _capture_hook(const char *key, const message_type_t type,
                         generic_msg_t *msg, bool blocking)
{
    (void)blocking;
    if (type == NET_MESSAGE && key != NULL && strcmp(key, NET_NAME) == 0
        && msg->info.net_msg.function != NULL
        && strcmp(msg->info.net_msg.function, ID_HISTORY_FN) == 0)
    {
        if (g_histories_sent < MAX_SENT)
            at_strlcpy(g_sent_to[g_histories_sent],
                       msg->info.net_msg.to_whom.nickname, sizeof(g_sent_to[0]));
        g_histories_sent++;
    }
    return 0;
}

static void _begin(void)
{
    ck_assert(sodium_init() >= 0);
    identity_reset_state();
    g_histories_sent = 0;
    memset(g_sent_to, 0, sizeof(g_sent_to));
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

/* Hold @p who as a peer, as admission or a history's bundle would. */
static void _add_peer(process_t *proc, const identity_t *who)
{
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(who, &pub));
    memcpy(&proc->protocol.peers[proc->protocol.num_peers++], pub,
           sizeof(public_identity_t));
    smrt_deref(pub);
}

/* Another founder's group: a fresh uuid and key, its members as given. */
static json_t *_other_group(identity_t *const *members, size_t n)
{
    group_t g = {0};
    uuid_t guuid;
    uuid_generate(guuid);
    group_init(&guuid, (char *)members[0]->address, &g);
    for (size_t i = 0; i < n; i++)
    {
        char u[UUID_STRING_LEN + 1];
        uuid_unparse_lower(members[i]->uuid, u);
        group_add_address(&g, u, members[i]->address);
    }
    json_t *obj = NULL;
    ck_assert_ret_ok(group_to_json(&g, &obj));
    map_free(&g.address_map);
    return obj;
}

static directory_t *_queues(void)
{
    directory_t *queues = NULL;
    ck_assert_ret_ok(array_create(&queues));
    ck_assert_ret_ok(array_append(queues, string_data(ID_NAME, strlen(ID_NAME))));
    ck_assert_ret_ok(array_append(queues, string_data(NET_NAME, strlen(NET_NAME))));
    return queues;
}

/* Dispatch a request_access whose sender has @p uuid and no nickname, so a
 * replay stops at the handler's empty-identity check. */
static void _dispatch_request(process_t *proc, const uuid_t uuid)
{
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = ID_ANNOUNCE_FN;
    uuid_copy(msg.info.net_msg.from_whom.uuid, uuid);
    directory_t *queues = _queues();
    run_message_handlers(proc, queues, NET_MESSAGE, &msg);
    array_free(queues);
}

/* Dispatch a full_history [group, [], []] from @p sender. */
static void _dispatch_history(process_t *proc, const identity_t *sender,
                              json_t *group_json)
{
    json_t *payload = json_pack("[O[][]]", group_json);
    ck_assert_ptr_nonnull(payload);
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = ID_HISTORY_FN;
    msg.info.net_msg.verified = true;
    uuid_copy(msg.info.net_msg.from_whom.uuid, sender->uuid);
    at_strlcpy(msg.info.net_msg.from_whom.nickname, sender->nickname,
               sizeof(msg.info.net_msg.from_whom.nickname));
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, payload));
    json_decref(payload);
    directory_t *queues = _queues();
    run_message_handlers(proc, queues, NET_MESSAGE, &msg);
    array_free(queues);
    net_msg_free_obj(&msg.info.net_msg);
}

/* The owner was choosing its group when the verifier's request arrived. */
DEFINE_TEST(test_an_access_request_before_phase_3_is_replayed_once)
{
    _begin();
    identity_t *me = _mk_identity("owner", "10.0.0.1");
    process_t *proc = _mk_process(me);
    uuid_t ver;
    uuid_generate(ver);

    proc->protocol.phase = 2;
    _dispatch_request(proc, ver);
    proc->protocol.phase = 3;

    directory_t *queues = _queues();
    ck_assert_int_eq((int)identity_replay_held_access_requests(proc, queues), 1);
    ck_assert_int_eq((int)identity_replay_held_access_requests(proc, queues), 0);
    array_free(queues);
    _end();
}

/* A lone founder re-announces every ~5 s: one held request per requester. */
DEFINE_TEST(test_a_requester_is_held_once_and_the_hold_is_bounded)
{
    _begin();
    identity_t *me = _mk_identity("owner", "10.0.0.1");
    process_t *proc = _mk_process(me);
    uuid_t ver;
    uuid_generate(ver);

    uuid_t cal;
    uuid_generate(cal);
    proc->protocol.phase = 2;
    for (int i = 0; i < 3; i++)
        _dispatch_request(proc, ver);
    _dispatch_request(proc, cal);
    proc->protocol.phase = 3;
    directory_t *queues = _queues();
    ck_assert_int_eq((int)identity_replay_held_access_requests(proc, queues), 2);

    proc->protocol.phase = 2;
    for (int i = 0; i < ID_HELD_ACCESS_REQUESTS + 2; i++)
    {
        uuid_t other;
        uuid_generate(other);
        _dispatch_request(proc, other);
    }
    proc->protocol.phase = 3;
    ck_assert_int_eq((int)identity_replay_held_access_requests(proc, queues),
                     ID_HELD_ACCESS_REQUESTS);
    array_free(queues);
    _end();
}

/* The observer holds the owner's group and was admitted by the verifier's
 * too: it tells the verifier, once. */
DEFINE_TEST(test_a_node_admitted_by_two_groups_tells_the_other_one_once)
{
    _begin();
    identity_t *me = _mk_identity("observer", "10.0.0.3");
    identity_t *ver = _mk_identity("verifier", "10.0.0.2");
    process_t *proc = _mk_process(me);
    _add_peer(proc, ver);

    identity_t *theirs[] = {ver, me};
    json_t *other = _other_group(theirs, 2);
    ck_assert_int_eq((int)identity_tell_bridged_group(proc, other), 1);
    ck_assert_int_eq((int)g_histories_sent, 1);
    ck_assert_str_eq(g_sent_to[0], "verifier");

    ck_assert_int_eq((int)identity_tell_bridged_group(proc, other), 0);
    ck_assert_int_eq((int)g_histories_sent, 1);
    json_decref(other);
    _end();
}

/* Our own group, and a member we share with the other group, hear nothing. */
DEFINE_TEST(test_our_own_group_and_shared_members_are_not_told)
{
    _begin();
    identity_t *me = _mk_identity("observer", "10.0.0.3");
    identity_t *own = _mk_identity("owner", "10.0.0.1");
    process_t *proc = _mk_process(me);
    _add_peer(proc, own);
    char u[UUID_STRING_LEN + 1];
    uuid_unparse_lower(own->uuid, u);
    group_add_address(&proc->protocol.group, u, own->address);

    json_t *ours = NULL;
    ck_assert_ret_ok(group_to_json(&proc->protocol.group, &ours));
    ck_assert_int_eq((int)identity_tell_bridged_group(proc, ours), 0);
    json_decref(ours);

    identity_t *theirs[] = {own, me};
    json_t *other = _other_group(theirs, 2);
    ck_assert_int_eq((int)identity_tell_bridged_group(proc, other), 0);
    ck_assert_int_eq((int)g_histories_sent, 0);
    json_decref(other);
    _end();
}

/* The late shape: our group is settled when the other group's history
 * arrives. The handler tells the other group's member. */
DEFINE_TEST(test_a_foreign_history_in_phase_3_tells_its_group)
{
    _begin();
    identity_t *me = _mk_identity("observer", "10.0.0.3");
    identity_t *ver = _mk_identity("verifier", "10.0.0.2");
    process_t *proc = _mk_process(me);
    _add_peer(proc, ver);

    identity_t *theirs[] = {ver, me};
    json_t *other = _other_group(theirs, 2);
    _dispatch_history(proc, ver, other);
    ck_assert_int_eq((int)g_histories_sent, 1);
    ck_assert_str_eq(g_sent_to[0], "verifier");

    /* Control: a history of our own group tells nobody. */
    json_t *ours = NULL;
    ck_assert_ret_ok(group_to_json(&proc->protocol.group, &ours));
    _dispatch_history(proc, ver, ours);
    ck_assert_int_eq((int)g_histories_sent, 1);
    json_decref(ours);
    json_decref(other);
    _end();
}

/* The shape st-284840 had: both founders' histories arrive while the observer
 * chooses. It adopts the first group and tells the second group's member. */
DEFINE_TEST(test_choosing_between_two_groups_tells_the_one_not_adopted)
{
    _begin();
    identity_t *me = _mk_identity("observer", "10.0.0.3");
    identity_t *own = _mk_identity("owner", "10.0.0.1");
    identity_t *ver = _mk_identity("verifier", "10.0.0.2");
    process_t *proc = _mk_process(me);
    _add_peer(proc, own);
    _add_peer(proc, ver);

    identity_t *first[] = {own, me};
    identity_t *second[] = {ver, me};
    json_t *g1 = _other_group(first, 2);
    json_t *g2 = _other_group(second, 2);
    const char *u1 = json_string_value(json_object_get(g1, "uuid"));
    identity_stash_history(json_pack("[O[][]]", g1));
    identity_stash_history(json_pack("[O[][]]", g2));

    directory_t *queues = _queues();
    ck_assert(identity_adopt_group_from_histories(proc, queues));
    array_free(queues);
    char adopted[UUID_STRING_LEN + 1];
    uuid_unparse_lower(proc->protocol.group.uuid, adopted);
    ck_assert_str_eq(adopted, u1);
    ck_assert_int_eq((int)g_histories_sent, 1);
    ck_assert_str_eq(g_sent_to[0], "verifier");
    json_decref(g1);
    json_decref(g2);
    _end();
}

/* biz-3930802: a held message's copy kept only len bytes of its payload, and
 * the parse read on past them, so a replayed group update (ada's winning key)
 * was discarded as malformed. Here the byte after len is not a NUL, as it was
 * not in the copy: the payload must parse from its length alone, held or not. */
DEFINE_TEST(test_a_payload_parses_by_its_length_held_or_not)
{
    const char text[] = "{\"k\":\"v\"}";
    size_t len = sizeof(text) - 1;
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    msg.info.net_msg.function = ID_HISTORY_FN;
    msg.info.net_msg.obj = malloc(len + 1);
    ck_assert_ptr_nonnull(msg.info.net_msg.obj);
    memcpy(msg.info.net_msg.obj, text, len);
    msg.info.net_msg.obj[len] = 'x';
    msg.info.net_msg.len = len;

    json_t *back = NULL;
    ck_assert_int_eq(net_msg_unpack_json(&msg.info.net_msg, &back), 0);
    ck_assert_str_eq(json_string_value(json_object_get(back, "k")), "v");
    json_decref(back);

    generic_msg_t copy;
    ck_assert(identity_copy_held_message(&msg, &copy));
    back = NULL;
    ck_assert_int_eq(net_msg_unpack_json(&copy.info.net_msg, &back), 0);
    ck_assert_str_eq(json_string_value(json_object_get(back, "k")), "v");
    json_decref(back);
    messaging_recv_release(&copy);
    free(msg.info.net_msg.obj);
}

RUN_TESTS(BridgedGroup,
          test_an_access_request_before_phase_3_is_replayed_once,
          test_a_requester_is_held_once_and_the_hold_is_bounded,
          test_a_node_admitted_by_two_groups_tells_the_other_one_once,
          test_our_own_group_and_shared_members_are_not_told,
          test_a_foreign_history_in_phase_3_tells_its_group,
          test_choosing_between_two_groups_tells_the_one_not_adopted,
          test_a_payload_parses_by_its_length_held_or_not)
