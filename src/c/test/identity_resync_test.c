/********************
 *  Copyright 2026 Sean M. Brennan and contributors
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

/** @file Unit tests for the C identity-resync parity — the mirror of
 *  Python's IdentityProcess._periodic_identity_resync / handle_identity_query
 *  / handle_identity_response (tests/a_unit/test_partition_recovery.py
 *  TestIdentityResync). Covers the cold/late-joiner identity-loss backstop:
 *  a node that holds a group member's address (group.address_map) but not
 *  its full Identity (peers[] sparse) queries the group and backfills.
 *
 *  Two surfaces:
 *   - identity_periodic_identity_resync (exposed via id_proc_priv.h): query
 *     emission, captured through the messaging test hook. Mirrors the
 *     late_joiner_caps_resync_test harness.
 *   - handle_identity_query / handle_identity_response (static): dispatched
 *     through run_message_handlers with a crafted NET_MESSAGE, following the
 *     peer_rtt_update_test precedent.
 *
 *  Same cases as test_partition_recovery.py::TestIdentityResync:
 *  query-when-sparse, no-query-when-complete, responder-replies,
 *  responder-silent-for-other-group, responder-silent-when-asker-has-us,
 *  response-backfills-member, response-rejects-non-member.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#include <jansson.h>
#include <uuid/uuid.h>

#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "identity/id_proc_priv.h"
#include "identity/group.h"
#include "config/configuration.h"
#include "structures/data.h"
#include "structures/map.h"
#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
#include "utilities/msg_types_priv.h"
#include "utilities/allocation.h"

/* Mutable storage: net_msg_t.function is `char *`, so a const string literal
 * can't be assigned directly. */
static char ID_QUERY_FN[]    = "peer_identity_query";
static char ID_RESPONSE_FN[] = "peer_identity_response";

/* ------------------------------------------------------------------ */
/* Capture of resync emissions via the messaging test hook.            */
/* ------------------------------------------------------------------ */

static size_t g_query_count;
static size_t g_response_count;
static char   g_last_query_group[UUID_STRING_LEN + 1];
static json_t *g_last_query_have;   /* owned; freed in _end */

static int _capture_hook(const char *key, const message_type_t type,
                         generic_msg_t *msg, bool blocking)
{
    (void)key; (void)blocking;
    if (type != NET_MESSAGE || msg->info.net_msg.function == NULL)
        return 0;
    const char *fn = msg->info.net_msg.function;
    if (strcmp(fn, ID_QUERY_FN) == 0) {
        g_query_count++;
        /* Stash the payload for assertion (group_uuid + have-list). */
        if (msg->info.net_msg.obj != NULL) {
            json_error_t err;
            json_t *p = json_loads((const char *)msg->info.net_msg.obj, 0, &err);
            if (p != NULL && json_is_object(p)) {
                const char *g = json_string_value(json_object_get(p, "group_uuid"));
                if (g != NULL) {
                    strncpy(g_last_query_group, g, UUID_STRING_LEN);
                    g_last_query_group[UUID_STRING_LEN] = '\0';
                }
                if (g_last_query_have != NULL)
                    json_decref(g_last_query_have);
                g_last_query_have = json_incref(json_object_get(p, "have"));
            }
            if (p != NULL) json_decref(p);
        }
    } else if (strcmp(fn, ID_RESPONSE_FN) == 0) {
        g_response_count++;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Minimal process_t construction.                                     */
/* ------------------------------------------------------------------ */

static identity_t *_mk_identity(const char *name, const char *addr)
{
    uuid_t uuid;
    uuid_generate(uuid);
    identity_t *ident = NULL;
    ck_assert_ret_ok(identity_create(&uuid, addr, name, name, "me", &ident));
    ck_assert_ptr_nonnull(ident);
    return ident;
}

/* Build a process whose configs carry @p self, with a group seeded with
 * self's address (so the "no group yet" guard fails) and a registered
 * handler table (so run_message_handlers can dispatch NET_MESSAGEs). */
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

/* Register @p member as a group member by address (so it would pass the
 * handle_identity_response membership gate) WITHOUT adding it to peers[]. */
static void _add_group_member_addr(process_t *proc, identity_t *member)
{
    char u[UUID_STRING_LEN + 1];
    uuid_unparse_lower(member->uuid, u);
    group_add_address(&proc->protocol.group, u, member->address);
}

static void _add_peer(process_t *proc, identity_t *peer)
{
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(peer, &pub));
    ck_assert_ptr_nonnull(pub);
    memcpy(&proc->protocol.peers[proc->protocol.num_peers], pub,
           sizeof(public_identity_t));
    proc->protocol.num_peers++;
    smrt_deref(pub);
}

static void _group_uuid_str(const process_t *proc, char out[UUID_STRING_LEN + 1])
{
    uuid_unparse_lower(proc->protocol.group.uuid, out);
}

/* Craft + dispatch a peer_identity_query. @p have_uuids may be NULL. */
static void _dispatch_query(process_t *proc, const char *group_uuid,
                            const char **have_uuids, size_t n_have)
{
    json_t *payload = json_object();
    json_object_set_new(payload, "group_uuid", json_string(group_uuid));
    json_t *have = json_array();
    for (size_t i = 0; i < n_have; i++)
        json_array_append_new(have, json_string(have_uuids[i]));
    json_object_set_new(payload, "have", have);

    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = ID_QUERY_FN;
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, payload));
    json_decref(payload);

    run_message_handlers(proc, NULL, NET_MESSAGE, &msg);
}

/* Craft + dispatch a peer_identity_response carrying @p member's identity. */
static void _dispatch_response(process_t *proc, identity_t *member)
{
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(member, &pub));
    json_t *ident_json = NULL;
    ck_assert_ret_ok(public_identity_to_json(pub, &ident_json));
    smrt_deref(pub);

    json_t *payload = json_object();
    json_object_set_new(payload, "from_identity", ident_json);
    json_object_set_new(payload, "from_address", json_string(member->address));

    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = ID_RESPONSE_FN;
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, payload));
    json_decref(payload);

    run_message_handlers(proc, NULL, NET_MESSAGE, &msg);
}

static bool _peers_contain(const process_t *proc, const uuid_t uuid)
{
    bool found = false;
    peers_read_lock(proc);
    for (size_t i = 0; i < proc->protocol.num_peers; i++)
        if (uuid_compare(proc->protocol.peers[i].uuid, uuid) == 0)
            found = true;
    peers_read_unlock(proc);
    return found;
}

static bool _have_contains(const char *uuid_str)
{
    if (g_last_query_have == NULL || !json_is_array(g_last_query_have))
        return false;
    size_t n = json_array_size(g_last_query_have);
    for (size_t i = 0; i < n; i++) {
        const char *h = json_string_value(json_array_get(g_last_query_have, i));
        if (h != NULL && strcmp(h, uuid_str) == 0)
            return true;
    }
    return false;
}

static void _begin(void)
{
    identity_reset_state();
    g_query_count = 0;
    g_response_count = 0;
    g_last_query_group[0] = '\0';
    g_last_query_have = NULL;
    messaging_set_test_hook(_capture_hook);
}

static void _end(void)
{
    messaging_set_test_hook(NULL);
    if (g_last_query_have != NULL) {
        json_decref(g_last_query_have);
        g_last_query_have = NULL;
    }
}

/* ------------------------------------------------------------------ */
/* Periodic query emission.                                            */
/* ------------------------------------------------------------------ */

DEFINE_TEST(test_query_when_sparse)
{
    _begin();
    identity_t *me = _mk_identity("coord", "10.0.0.1");
    identity_t *m1 = _mk_identity("alice", "10.0.0.2");
    identity_t *m2 = _mk_identity("bob", "10.0.0.3");
    process_t *proc = _mk_process(me);
    /* Group of 3 (self + 2), but peers[] empty -> we hold only our own
     * identity, so a query for the 2 missing members must go out. */
    _add_group_member_addr(proc, m1);
    _add_group_member_addr(proc, m2);

    identity_periodic_identity_resync(proc);

    ck_assert_int_eq(g_query_count, 1);
    char gu[UUID_STRING_LEN + 1];
    _group_uuid_str(proc, gu);
    ck_assert_str_eq(g_last_query_group, gu);
    /* have-list advertises (at least) our own identity. */
    char self_u[UUID_STRING_LEN + 1];
    uuid_unparse_lower(me->uuid, self_u);
    ck_assert(_have_contains(self_u));
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_no_query_when_complete)
{
    _begin();
    identity_t *me = _mk_identity("coord", "10.0.0.1");
    identity_t *m1 = _mk_identity("alice", "10.0.0.2");
    identity_t *m2 = _mk_identity("bob", "10.0.0.3");
    process_t *proc = _mk_process(me);
    _add_group_member_addr(proc, m1);
    _add_group_member_addr(proc, m2);
    /* We hold both members' identities -> have_count(3) >= group_size(3). */
    _add_peer(proc, m1);
    _add_peer(proc, m2);

    identity_periodic_identity_resync(proc);

    ck_assert_int_eq(g_query_count, 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_query_suppressed_when_not_phase3)
{
    _begin();
    identity_t *me = _mk_identity("coord", "10.0.0.1");
    identity_t *m1 = _mk_identity("alice", "10.0.0.2");
    process_t *proc = _mk_process(me);
    _add_group_member_addr(proc, m1);
    proc->protocol.phase = 1;   /* not operational */

    identity_periodic_identity_resync(proc);

    ck_assert_int_eq(g_query_count, 0);
    _end();
}
END_TEST_DEFINITION()

/* ------------------------------------------------------------------ */
/* Responder (handle_identity_query).                                  */
/* ------------------------------------------------------------------ */

DEFINE_TEST(test_responder_replies)
{
    _begin();
    identity_t *me = _mk_identity("alice", "10.0.0.2");
    process_t *proc = _mk_process(me);
    char gu[UUID_STRING_LEN + 1];
    _group_uuid_str(proc, gu);

    /* Asker is in our group and does NOT yet have us (have-list names some
     * other uuid only) -> we must reply. */
    char other[UUID_STRING_LEN + 1] = "00000000-0000-0000-0000-000000000001";
    const char *have[1] = {other};
    _dispatch_query(proc, gu, have, 1);

    ck_assert_int_eq(g_response_count, 1);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_responder_silent_when_asker_has_us)
{
    _begin();
    identity_t *me = _mk_identity("alice", "10.0.0.2");
    process_t *proc = _mk_process(me);
    char gu[UUID_STRING_LEN + 1];
    _group_uuid_str(proc, gu);

    char self_u[UUID_STRING_LEN + 1];
    uuid_unparse_lower(me->uuid, self_u);
    const char *have[1] = {self_u};   /* asker already holds us */
    _dispatch_query(proc, gu, have, 1);

    ck_assert_int_eq(g_response_count, 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_responder_silent_for_other_group)
{
    _begin();
    identity_t *me = _mk_identity("alice", "10.0.0.2");
    process_t *proc = _mk_process(me);

    /* Query names a different group uuid -> not our concern. */
    char foreign[] = "a169fd78-b0f8-4f1d-acfe-2d74b59cf2c7";
    _dispatch_query(proc, foreign, NULL, 0);

    ck_assert_int_eq(g_response_count, 0);
    _end();
}
END_TEST_DEFINITION()

/* ------------------------------------------------------------------ */
/* Recipient (handle_identity_response).                               */
/* ------------------------------------------------------------------ */

DEFINE_TEST(test_response_backfills_member)
{
    _begin();
    identity_t *me = _mk_identity("coord", "10.0.0.1");
    identity_t *m1 = _mk_identity("alice", "10.0.0.2");
    process_t *proc = _mk_process(me);
    _add_group_member_addr(proc, m1);   /* m1 is a known group member */

    ck_assert_int_eq(proc->protocol.num_peers, 0);
    _dispatch_response(proc, m1);

    ck_assert_int_eq(proc->protocol.num_peers, 1);
    ck_assert(_peers_contain(proc, m1->uuid));
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_response_rejects_non_member)
{
    _begin();
    identity_t *me = _mk_identity("coord", "10.0.0.1");
    identity_t *stranger = _mk_identity("mallory", "10.9.9.9");
    process_t *proc = _mk_process(me);
    /* stranger's address is NOT in our group address_map. */

    _dispatch_response(proc, stranger);

    ck_assert_int_eq(proc->protocol.num_peers, 0);
    ck_assert(!_peers_contain(proc, stranger->uuid));
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(IdentityResync,
          test_query_when_sparse,
          test_no_query_when_complete,
          test_query_suppressed_when_not_phase3,
          test_responder_replies,
          test_responder_silent_when_asker_has_us,
          test_responder_silent_for_other_group,
          test_response_backfills_member,
          test_response_rejects_non_member)
