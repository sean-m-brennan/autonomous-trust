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

/**
 * @file gateway_update_scope_test.c
 * @brief A gateway sends its primary group's update only to that group.
 *
 * _update_group fans the group out to every peer, and a gateway's peers include
 * the cohort below it. The command group, key and all, reached field nodes; one
 * that had not yet joined took it, and the two cohorts merged across the
 * gateway. Mirrors TestUpdateScope in test_child_group_routing.py.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#include <uuid/uuid.h>

#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "identity/id_proc_priv.h"
#include "utilities/send_retry.h"
#include <time.h>
#include "identity/group.h"
#include "config/configuration.h"
#include "structures/data.h"
#include "structures/map.h"
#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/allocation.h"
#include "utilities/msg_types_priv.h"
#include <jansson.h>


static uuid_t g_member_uuid, g_field_uuid;
static size_t g_to_member, g_to_field;

static int _capture_hook(const char *key, const message_type_t type,
                         generic_msg_t *msg, bool blocking)
{
    (void)key; (void)blocking;
    if (type != NET_MESSAGE || msg->info.net_msg.function == NULL
        || strcmp(msg->info.net_msg.function, "group_key_update") != 0)
        return 0;
    if (uuid_compare(msg->info.net_msg.to_whom.uuid, g_member_uuid) == 0)
        g_to_member++;
    if (uuid_compare(msg->info.net_msg.to_whom.uuid, g_field_uuid) == 0)
        g_to_field++;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Minimal process_t construction (mirrors late_joiner_caps_resync).   */
/* ------------------------------------------------------------------ */

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
    return proc;
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

static public_identity_t *_publish(identity_t *ident)
{
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(ident, &pub));
    ck_assert_ptr_nonnull(pub);
    return pub;
}

/* A real (empty) queue directory: _peer_accepted's local GROUP broadcast walks
 * the queues array, and array_size() dereferences it, so NULL is not an option
 * (same note as identity_resync_test.c). */
static directory_t *_mk_queues(void)
{
    directory_t *queues = NULL;
    ck_assert_ret_ok(array_create(&queues));
    ck_assert_ptr_nonnull(queues);
    return queues;
}

static bool _group_lists(group_t *grp, const char *addr)
{
    bool found = false;
    map_key_t key;
    data_t *val;
    map_entries_for_each(&grp->address_map, key, val)
        string_t a = NULL;
        if (data_string_ptr(val, &a) == 0 && a != NULL && strcmp(a, addr) == 0)
            found = true;
    map_end_for_each
    return found;
}

static void _run(bool gateway)
{
    identity_reset_state();
    g_to_member = g_to_field = 0;
    messaging_set_test_hook(_capture_hook);

    identity_t *me = _mk_identity("gw", "10.0.0.6");
    identity_t *member = _mk_identity("boss", "10.0.0.3");
    identity_t *field = _mk_identity("drone", "172.20.0.11");
    identity_t *joiner = _mk_identity("ben", "10.0.0.4");
    memcpy(g_member_uuid, member->uuid, sizeof(uuid_t));
    memcpy(g_field_uuid, field->uuid, sizeof(uuid_t));
    process_t *proc = _mk_process(me);
    char member_uuid[UUID_STRING_LEN + 1];
    uuid_unparse_lower(member->uuid, member_uuid);
    group_add_address(&proc->protocol.group, member_uuid, member->address);
    _add_peer(proc, member);
    _add_peer(proc, field);
    group_t *child = NULL;
    if (gateway) {
        child = calloc(1, sizeof(group_t));
        uuid_t cuuid;
        uuid_generate(cuuid);
        group_init(&cuuid, (char *)me->address, child);
        char field_uuid[UUID_STRING_LEN + 1];
        uuid_unparse_lower(field->uuid, field_uuid);
        group_add_address(child, field_uuid, field->address);
        ck_assert_ret_ok(identity_add_child_group(proc, child, NULL));
    }
    directory_t *queues = _mk_queues();
    public_identity_t *pub = _publish(joiner);
    identity_arm_pending_vote(pub, 2, -1.0);
    identity_periodic_vote_collection(proc, queues);

    smrt_deref(pub);
    array_free(queues);
    messaging_set_test_hook(NULL);
}

DEFINE_TEST(test_the_primary_update_skips_the_child_cohort)
{
    _run(true);
    ck_assert(g_to_member >= 1);
    ck_assert_uint_eq(g_to_field, 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_leaf_node_still_updates_every_peer)
{
    _run(false);
    ck_assert(g_to_member >= 1);
    ck_assert(g_to_field >= 1);
}
END_TEST_DEFINITION()

/* The network process learns the child groups from identity, so a frame that
 * lands in the instant between identity adopting a child and the network
 * process hearing of it arrives untagged. Identity places the sender itself:
 * an untagged update from a child-cohort member, for a larger foreign group,
 * leaves the primary alone. Mirrors TestUntaggedChildFrame. */
static void _untagged_foreign_update(bool sender_in_child)
{
    identity_reset_state();
    identity_t *me = _mk_identity("gw", "10.0.0.6");
    identity_t *member = _mk_identity("boss", "10.0.0.3");
    identity_t *field = _mk_identity("drone", "172.20.0.11");
    process_t *proc = _mk_process(me);
    char u[UUID_STRING_LEN + 1];
    uuid_unparse_lower(member->uuid, u);
    group_add_address(&proc->protocol.group, u, member->address);
    _add_peer(proc, member);
    _add_peer(proc, field);
    size_t primary_before = map_size(&proc->protocol.group.address_map);
    ck_assert_ret_ok(map_create(&proc->protocol.handlers));
    ck_assert_ret_ok(identity_register_handlers(proc));

    group_t *child = calloc(1, sizeof(group_t));
    uuid_t cuuid;
    uuid_generate(cuuid);
    group_init(&cuuid, (char *)me->address, child);
    if (sender_in_child) {
        uuid_unparse_lower(field->uuid, u);
        group_add_address(child, u, field->address);
    }
    ck_assert_ret_ok(identity_add_child_group(proc, child, NULL));

    /* A foreign group, larger than the primary, from the field member. */
    group_t other = {0};
    uuid_t ouuid;
    uuid_generate(ouuid);
    group_init(&ouuid, (char *)field->address, &other);
    for (int i = 0; i < 5; i++) {
        char addr[32], k[UUID_STRING_LEN + 1];
        uuid_t ku;
        uuid_generate(ku);
        uuid_unparse_lower(ku, k);
        snprintf(addr, sizeof(addr), "172.20.0.%d", 40 + i);
        group_add_address(&other, k, addr);
    }
    json_t *gj = NULL;
    ck_assert_ret_ok(group_to_json(&other, &gj));

    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = strdup("group_key_update");
    public_identity_t *pub = _publish(field);
    memcpy(&msg.info.net_msg.from_whom, pub, sizeof(*pub));
    msg.info.net_msg.verified = true;
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, gj));
    json_decref(gj);
    ck_assert_uint_eq(msg.info.net_msg.child_group[0], 0);   /* untagged */

    directory_t *queues = _mk_queues();
    run_message_handlers(proc, queues, NET_MESSAGE, &msg);
    ck_assert_uint_eq(map_size(&proc->protocol.group.address_map), primary_before);
    ck_assert(uuid_compare(proc->protocol.group.uuid, ouuid) != 0);

    net_msg_free_obj(&msg.info.net_msg);
    free(msg.info.net_msg.function);
    smrt_deref(pub);
    array_free(queues);
    map_free(&other.address_map);
}

DEFINE_TEST(test_identity_places_an_untagged_sender_itself)
{
    _untagged_foreign_update(true);
}
END_TEST_DEFINITION()

/* A field joiner the gateway has not yet recorded is in neither map, so its
 * update read as news about the primary, and its larger field group won the
 * size rule. A gateway's primary changes only through its own members.
 * Mirrors TestUnplacedSender. */
DEFINE_TEST(test_a_gateway_ignores_a_group_from_a_sender_it_cannot_place)
{
    _untagged_foreign_update(false);
}
END_TEST_DEFINITION()

/* One guard on every primary change: the primary refuses any group that would
 * make it span the gateway (invariant G as a postcondition). Mirrors
 * TestPrimaryGuard in test_child_group_routing.py. */
DEFINE_TEST(test_the_primary_guard_names_a_spanning_group)
{
    identity_reset_state();
    identity_t *me = _mk_identity("gw", "10.0.0.6");
    identity_t *field = _mk_identity("drone", "172.20.0.11");
    process_t *proc = _mk_process(me);
    char u[UUID_STRING_LEN + 1];

    group_t clean = {0};
    uuid_t cu;
    uuid_generate(cu);
    group_init(&cu, (char *)me->address, &clean);
    uuid_unparse_lower(me->uuid, u);
    group_add_address(&clean, u, me->address);
    group_t mixed = {0};
    uuid_generate(cu);
    group_init(&cu, (char *)me->address, &mixed);
    group_add_address(&mixed, u, me->address);
    uuid_unparse_lower(field->uuid, u);
    group_add_address(&mixed, u, field->address);

    /* A leaf: nothing spans anything. */
    ck_assert(!identity_group_spans_gateway(proc, &mixed));

    group_t *child = calloc(1, sizeof(group_t));
    uuid_generate(cu);
    group_init(&cu, (char *)me->address, child);
    uuid_unparse_lower(me->uuid, u);
    group_add_address(child, u, "172.20.0.10");   /* our own field-side entry */
    uuid_unparse_lower(field->uuid, u);
    group_add_address(child, u, field->address);
    ck_assert_ret_ok(identity_add_child_group(proc, child, NULL));

    ck_assert(identity_group_spans_gateway(proc, &mixed));
    ck_assert(!identity_group_spans_gateway(proc, &clean));
    ck_assert(identity_group_spans_gateway(proc, child));   /* the child itself */
    map_free(&clean.address_map);
    map_free(&mixed.address_map);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_primary_member_cannot_merge_the_field_in)
{
    identity_reset_state();
    identity_t *me = _mk_identity("gw", "10.0.0.6");
    identity_t *member = _mk_identity("boss", "10.0.0.3");
    identity_t *field = _mk_identity("drone", "172.20.0.11");
    process_t *proc = _mk_process(me);
    ck_assert_ret_ok(map_create(&proc->protocol.handlers));
    ck_assert_ret_ok(identity_register_handlers(proc));
    char u[UUID_STRING_LEN + 1];
    uuid_unparse_lower(member->uuid, u);
    group_add_address(&proc->protocol.group, u, member->address);
    _add_peer(proc, member);
    _add_peer(proc, field);

    group_t *child = calloc(1, sizeof(group_t));
    uuid_t cu;
    uuid_generate(cu);
    group_init(&cu, (char *)me->address, child);
    uuid_unparse_lower(field->uuid, u);
    group_add_address(child, u, field->address);
    ck_assert_ret_ok(identity_add_child_group(proc, child, NULL));

    /* Our own group, larger, now listing the field member: what a primary
     * member already polluted some other way would send. */
    json_t *gj = NULL;
    ck_assert_ret_ok(group_to_json(&proc->protocol.group, &gj));
    json_t *am = json_object_get(gj, "address_map");
    json_object_set_new(am, u, json_string(field->address));
    char extra[UUID_STRING_LEN + 1];
    uuid_t eu;
    uuid_generate(eu);
    uuid_unparse_lower(eu, extra);
    json_object_set_new(am, extra, json_string("10.0.0.9"));

    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = strdup("group_key_update");
    public_identity_t *pub = _publish(member);
    memcpy(&msg.info.net_msg.from_whom, pub, sizeof(*pub));
    msg.info.net_msg.verified = true;
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, gj));
    json_decref(gj);

    directory_t *queues = _mk_queues();
    run_message_handlers(proc, queues, NET_MESSAGE, &msg);
    ck_assert(!_group_lists(&proc->protocol.group, field->address));

    net_msg_free_obj(&msg.info.net_msg);
    free(msg.info.net_msg.function);
    smrt_deref(pub);
    array_free(queues);
}
END_TEST_DEFINITION()

static char g_child_uuid[UUID_STRING_LEN + 1];
static size_t g_child_queries;

static int _query_hook(const char *key, const message_type_t type,
                       generic_msg_t *msg, bool blocking)
{
    (void)key; (void)blocking;
    if (type != NET_MESSAGE || msg->info.net_msg.function == NULL
        || strcmp(msg->info.net_msg.function, "peer_identity_query") != 0)
        return 0;
    json_t *body = NULL;
    if (net_msg_unpack_json(&msg->info.net_msg, &body) == 0 && body != NULL) {
        const char *g = json_string_value(json_object_get(body, "group_uuid"));
        if (g != NULL && strcmp(g, g_child_uuid) == 0)
            g_child_queries++;
        json_decref(body);
    }
    return 0;
}

/* A resync query names one group, and only its members answer; the gateway's
 * named its primary, so a field peer that joined before its gateway was up was
 * never found. It also queries each child cohort it lacks identities for.
 * Mirrors TestChildResync.test_a_gateway_queries_each_child_cohort_it_lacks. */
DEFINE_TEST(test_a_gateway_queries_each_child_cohort_it_lacks)
{
    identity_reset_state();
    identity_t *me = _mk_identity("gw", "10.0.0.6");
    identity_t *field = _mk_identity("mq800", "172.20.0.12");
    process_t *proc = _mk_process(me);
    group_t *child = calloc(1, sizeof(group_t));
    uuid_t cu;
    uuid_generate(cu);
    group_init(&cu, (char *)me->address, child);
    char u[UUID_STRING_LEN + 1];
    uuid_unparse_lower(field->uuid, u);
    group_add_address(child, u, field->address);
    ck_assert_ret_ok(identity_add_child_group(proc, child, NULL));
    uuid_unparse_lower(cu, g_child_uuid);
    g_child_queries = 0;
    messaging_set_test_hook(_query_hook);
    identity_periodic_identity_resync(proc);
    messaging_set_test_hook(NULL);
    ck_assert_uint_eq(g_child_queries, 1);
}
END_TEST_DEFINITION()

RUN_TESTS(GatewayUpdateScope,
          test_a_gateway_queries_each_child_cohort_it_lacks,
          test_the_primary_guard_names_a_spanning_group,
          test_a_primary_member_cannot_merge_the_field_in,
          test_identity_places_an_untagged_sender_itself,
          test_a_gateway_ignores_a_group_from_a_sender_it_cannot_place,
          test_the_primary_update_skips_the_child_cohort,
          test_a_leaf_node_still_updates_every_peer)
