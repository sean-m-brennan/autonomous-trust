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

/** @file A node behind on the group key asks a member for the current group.
 *
 *  Hostile-join run, 2026-11-03: two joiners admitted during the cohort's
 *  burst of rotations ended on a forked key, two epochs behind, and the cohort
 *  never resent, because it saw them as members already. Re-verifying held
 *  updates recovers what the node held; group_key_query recovers what it never
 *  received. The answer is an ordinary group_key_update (signed, as every C
 *  frame is), so the asker takes it through the same verified gate as any
 *  other: a query can make a member resend the group, never make anyone accept
 *  a key it would otherwise refuse.
 *
 *  Mirrors tests/a_unit/test_group_key_query.py.
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

static char ID_NAME[]  = "identity";
static char NET_NAME[] = "network";
static char FN_QUERY[] = "group_key_query";
static char FN_STALE[] = "group_key_stale";

/* What identity handed the network process. */
static int g_updates, g_queries;
static uuid_t g_last_to;
static json_t *g_last_body;

static int _capture_hook(const char *key, const message_type_t type,
                         generic_msg_t *msg, bool blocking)
{
    (void)blocking;
    if (type != NET_MESSAGE || key == NULL || strcmp(key, NET_NAME) != 0
        || msg->info.net_msg.function == NULL)
        return 0;
    bool update = strcmp(msg->info.net_msg.function, "group_key_update") == 0;
    bool query = strcmp(msg->info.net_msg.function, FN_QUERY) == 0;
    if (!update && !query)
        return 0;
    if (update) g_updates++;
    if (query) g_queries++;
    uuid_copy(g_last_to, msg->info.net_msg.to_whom.uuid);
    json_decref(g_last_body);
    g_last_body = NULL;
    net_msg_unpack_json(&msg->info.net_msg, &g_last_body);   /* owned */
    return 0;
}

static void _begin(void)
{
    ck_assert(sodium_init() >= 0);
    identity_reset_state();
    g_updates = g_queries = 0;
    uuid_clear(g_last_to);
    json_decref(g_last_body);
    g_last_body = NULL;
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
    return ident;
}

/* An identity process in phase 3 holding a keyed group of self and @p others. */
static process_t *_mk_process(identity_t *self, identity_t **others, size_t n)
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
    char u[UUID_STRING_LEN + 1];
    uuid_unparse_lower(self->uuid, u);
    group_add_address(&proc->protocol.group, u, self->address);
    for (size_t i = 0; i < n; i++) {
        uuid_unparse_lower(others[i]->uuid, u);
        group_add_address(&proc->protocol.group, u, others[i]->address);
    }

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

/* Hold @p member as an admitted peer. */
static void _hold_peer(process_t *proc, identity_t *member)
{
    public_identity_t *pub = &proc->protocol.peers[proc->protocol.num_peers++];
    memcpy(pub, member, sizeof(public_identity_t));
    memset(pub->signature.private, 0, sizeof(pub->signature.private));
}

static void _dispatch(process_t *proc, generic_msg_t *msg)
{
    directory_t *queues = NULL;
    ck_assert_ret_ok(array_create(&queues));
    ck_assert_ret_ok(array_append(queues, string_data(ID_NAME, strlen(ID_NAME))));
    ck_assert_ret_ok(array_append(queues, string_data(NET_NAME, strlen(NET_NAME))));
    run_message_handlers(proc, queues, NET_MESSAGE, msg);
    array_free(queues);
    net_msg_free_obj(&msg->info.net_msg);
}

/* @p asker's group_key_query for @p group_uuid, as it arrives from the wire. */
static void _query(process_t *proc, identity_t *asker, const uuid_t group_uuid)
{
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = FN_QUERY;
    msg.info.net_msg.verified = true;
    msg.info.net_msg.has_signature = true;
    memcpy(&msg.info.net_msg.from_whom, asker, sizeof(public_identity_t));
    char gu[UUID_STRING_LEN + 1];
    uuid_unparse_lower(group_uuid, gu);
    json_t *body = json_pack("{s:s, s:I}", "group_uuid", gu, "epoch", (json_int_t)0);
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, body));
    json_decref(body);
    _dispatch(proc, &msg);
}

/* The network's local signal: a group frame from @p address would not open.
 * @p from, when not NULL, makes it look as if it came from the wire. */
static void _stale(process_t *proc, const char *address, identity_t *from)
{
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = FN_STALE;
    if (from != NULL)
        memcpy(&msg.info.net_msg.from_whom, from, sizeof(public_identity_t));
    json_t *body = json_string(address);
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, body));
    json_decref(body);
    _dispatch(proc, &msg);
}

/* --- the responder --------------------------------------------------------- */

DEFINE_TEST(test_a_member_gets_the_group)
{
    _begin();
    identity_t *me = _mk_identity("member", "10.0.0.2");
    identity_t *asker = _mk_identity("asker", "10.0.0.3");
    process_t *proc = _mk_process(me, &asker, 1);
    _hold_peer(proc, asker);
    ck_assert(group_rotate_key(&proc->protocol.group) == 1);

    _query(proc, asker, proc->protocol.group.uuid);

    ck_assert_int_eq(g_updates, 1);
    ck_assert_int_eq(uuid_compare(g_last_to, asker->uuid), 0);
    ck_assert_ptr_nonnull(g_last_body);
    group_t sent;
    memset(&sent, 0, sizeof(sent));
    ck_assert_ret_ok(group_from_json(g_last_body, &sent));
    ck_assert_int_eq((int)sent.key_epoch, 1);
    ck_assert(!sodium_is_zero(sent.encryptor.private, crypto_box_SECRETKEYBYTES));
    map_free(&sent.address_map);
    _end();
}

DEFINE_TEST(test_a_non_member_gets_nothing)
{
    _begin();
    identity_t *me = _mk_identity("member", "10.0.0.2");
    identity_t *asker = _mk_identity("asker", "10.0.0.3");
    identity_t *stranger = _mk_identity("stranger", "10.0.0.7");
    process_t *proc = _mk_process(me, &asker, 1);
    _hold_peer(proc, stranger);
    _query(proc, stranger, proc->protocol.group.uuid);
    ck_assert_int_eq(g_updates, 0);
    _end();
}

DEFINE_TEST(test_a_member_we_do_not_hold_gets_nothing)
{
    _begin();
    identity_t *me = _mk_identity("member", "10.0.0.2");
    identity_t *asker = _mk_identity("asker", "10.0.0.3");
    process_t *proc = _mk_process(me, &asker, 1);
    _query(proc, asker, proc->protocol.group.uuid);
    ck_assert_int_eq(g_updates, 0);
    _end();
}

DEFINE_TEST(test_another_group_gets_nothing)
{
    _begin();
    identity_t *me = _mk_identity("member", "10.0.0.2");
    identity_t *asker = _mk_identity("asker", "10.0.0.3");
    process_t *proc = _mk_process(me, &asker, 1);
    _hold_peer(proc, asker);
    uuid_t other;
    uuid_generate(other);
    _query(proc, asker, other);
    ck_assert_int_eq(g_updates, 0);
    _end();
}

DEFINE_TEST(test_before_phase_3_nothing_is_answered)
{
    _begin();
    identity_t *me = _mk_identity("member", "10.0.0.2");
    identity_t *asker = _mk_identity("asker", "10.0.0.3");
    process_t *proc = _mk_process(me, &asker, 1);
    _hold_peer(proc, asker);
    proc->protocol.phase = 2;
    _query(proc, asker, proc->protocol.group.uuid);
    ck_assert_int_eq(g_updates, 0);
    _end();
}

DEFINE_TEST(test_one_answer_per_asker_per_interval)
{
    _begin();
    identity_t *me = _mk_identity("member", "10.0.0.2");
    identity_t *asker = _mk_identity("asker", "10.0.0.3");
    process_t *proc = _mk_process(me, &asker, 1);
    _hold_peer(proc, asker);
    _query(proc, asker, proc->protocol.group.uuid);
    _query(proc, asker, proc->protocol.group.uuid);
    ck_assert_int_eq(g_updates, 1);
    _end();
}

/* --- the asker -------------------------------------------------------------- */

DEFINE_TEST(test_a_stale_signal_queries_the_member_at_that_address)
{
    _begin();
    identity_t *me = _mk_identity("asker", "10.0.0.3");
    identity_t *member = _mk_identity("member", "10.0.0.2");
    process_t *proc = _mk_process(me, &member, 1);
    _hold_peer(proc, member);

    _stale(proc, "10.0.0.2", NULL);

    ck_assert_int_eq(g_queries, 1);
    ck_assert_int_eq(uuid_compare(g_last_to, member->uuid), 0);
    char gu[UUID_STRING_LEN + 1];
    uuid_unparse_lower(proc->protocol.group.uuid, gu);
    ck_assert_str_eq(json_string_value(json_object_get(g_last_body, "group_uuid")), gu);
    ck_assert_int_eq((int)json_integer_value(json_object_get(g_last_body, "epoch")), 0);
    _end();
}

DEFINE_TEST(test_one_query_per_member_per_interval)
{
    _begin();
    identity_t *me = _mk_identity("asker", "10.0.0.3");
    identity_t *member = _mk_identity("member", "10.0.0.2");
    process_t *proc = _mk_process(me, &member, 1);
    _hold_peer(proc, member);
    _stale(proc, "10.0.0.2", NULL);
    _stale(proc, "10.0.0.2", NULL);
    ck_assert_int_eq(g_queries, 1);
    _end();
}

/* group_key_stale is the network process's, never a peer's. */
DEFINE_TEST(test_a_signal_from_the_wire_is_refused)
{
    _begin();
    identity_t *me = _mk_identity("asker", "10.0.0.3");
    identity_t *member = _mk_identity("member", "10.0.0.2");
    process_t *proc = _mk_process(me, &member, 1);
    _hold_peer(proc, member);
    _stale(proc, "10.0.0.2", member);
    ck_assert_int_eq(g_queries, 0);
    _end();
}

DEFINE_TEST(test_an_address_that_is_no_member_is_not_queried)
{
    _begin();
    identity_t *me = _mk_identity("asker", "10.0.0.3");
    identity_t *member = _mk_identity("member", "10.0.0.2");
    process_t *proc = _mk_process(me, &member, 1);
    _hold_peer(proc, member);
    _stale(proc, "10.0.0.8", NULL);
    ck_assert_int_eq(g_queries, 0);
    _end();
}

DEFINE_TEST(test_reaching_phase_3_queries_a_few_members)
{
    _begin();
    identity_t *me = _mk_identity("asker", "10.0.0.3");
    identity_t *members[5];
    char addr[16];
    for (int i = 0; i < 5; i++) {
        snprintf(addr, sizeof(addr), "10.0.1.%d", i + 1);
        members[i] = _mk_identity("m", addr);
    }
    process_t *proc = _mk_process(me, members, 5);
    for (int i = 0; i < 5; i++)
        _hold_peer(proc, members[i]);

    identity_schedule_key_pull(0.0);   /* phase 3 reached, settle elapsed */
    ck_assert_int_eq((int)identity_maybe_pull_key(proc), 3);
    ck_assert_int_eq(g_queries, 3);
    ck_assert_int_eq((int)identity_maybe_pull_key(proc), 0);   /* once per entry */
    ck_assert_int_eq(g_queries, 3);
    _end();
}

RUN_TESTS(GroupKeyQuery,
          test_a_member_gets_the_group,
          test_a_non_member_gets_nothing,
          test_a_member_we_do_not_hold_gets_nothing,
          test_another_group_gets_nothing,
          test_before_phase_3_nothing_is_answered,
          test_one_answer_per_asker_per_interval,
          test_a_stale_signal_queries_the_member_at_that_address,
          test_one_query_per_member_per_interval,
          test_a_signal_from_the_wire_is_refused,
          test_an_address_that_is_no_member_is_not_queried,
          test_reaching_phase_3_queries_a_few_members)
