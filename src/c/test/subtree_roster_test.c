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

/** @file Unit tests for the C subtree member-roster enumeration — the mirror
 *  of Python's IdentityProcess.enumerate_local_members / handle_roster_request
 *  / aggregate_subtree_roster (tests/a_unit/test_subtree_roster.py). Covers the
 *  requestor-side BFS design and the AT_ROSTER_PRIVATE opt-out.
 *
 *  Surfaces (all via id_proc_priv.h):
 *   - identity_enumerate_local_members: self + primary group + child groups.
 *   - handle_roster_request: dispatched through run_message_handlers with a
 *     crafted roster_req; the roster_resp is captured via the messaging hook.
 *   - identity_aggregate_subtree_roster: BFS over an injected fetch stub.
 *
 *  See doc/architecture/gateway-reputation-tree.md.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

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

static char ID_ROSTER_QUERY_FN[] = "subtree_roster_query";
static char ID_ROSTER_RESPONSE_FN[] = "subtree_roster_response";

/* ------------------------------------------------------------------ */
/* Capture of the roster_resp emitted by handle_roster_request.        */
/* ------------------------------------------------------------------ */

static size_t g_resp_count;
static json_t *g_last_members;       /* owned; freed in _end */
static json_t *g_last_child_gws;     /* owned; freed in _end */
static bool g_last_private;
/* Which process the reply was addressed to. Inbound messages route by
 * net_msg.process alone, so this decides whether the answer ever reaches the
 * aggregation waiting for it. */
static char g_last_resp_proc[PROC_NAME_LEN + 1];

static int _capture_hook(const char *key, const message_type_t type,
                         generic_msg_t *msg, bool blocking)
{
    (void)key; (void)blocking;
    if (type != NET_MESSAGE || msg->info.net_msg.function == NULL)
        return 0;
    if (strcmp(msg->info.net_msg.function, ID_ROSTER_RESPONSE_FN) != 0)
        return 0;
    g_resp_count++;
    snprintf(g_last_resp_proc, sizeof(g_last_resp_proc), "%s",
             msg->info.net_msg.process);
    if (msg->info.net_msg.obj == NULL)
        return 0;
    json_error_t err;
    json_t *p = json_loads((const char *)msg->info.net_msg.obj, 0, &err);
    if (p == NULL || !json_is_object(p)) {
        if (p != NULL) json_decref(p);
        return 0;
    }
    if (g_last_members != NULL) json_decref(g_last_members);
    if (g_last_child_gws != NULL) json_decref(g_last_child_gws);
    g_last_members = json_incref(json_object_get(p, "members"));
    g_last_child_gws = json_incref(json_object_get(p, "child_gateways"));
    g_last_private = json_is_true(json_object_get(p, "private"));
    json_decref(p);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Minimal process_t construction (mirrors identity_resync_test).      */
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

    ck_assert_ret_ok(map_create(&proc->protocol.handlers));
    ck_assert_ret_ok(identity_register_handlers(proc));
    /* register_handlers reads AT_ROSTER_PRIVATE (unset in tests -> false). */
    return proc;
}

/* Seed a child group containing @p member, with @p member as the recursion
 * gateway. @p out must outlive the enumeration (stack in the test body). */
static void _mk_child_group(process_t *proc, identity_t *member, group_t *out)
{
    uuid_t cg;
    uuid_generate(cg);
    group_init(&cg, (char *)member->address, out);
    char mu[UUID_STRING_LEN + 1];
    uuid_unparse_lower(member->uuid, mu);
    group_add_address(out, mu, member->address);
    ck_assert_ret_ok(identity_add_child_group(proc, out, mu));
}

static void _uuid_str(const identity_t *id, char out[UUID_STRING_LEN + 1])
{
    uuid_unparse_lower(id->uuid, out);
}

/* Does a members json array contain @p uuid? */
static bool _members_have(json_t *members, const char *uuid)
{
    if (!json_is_array(members)) return false;
    size_t i, n = json_array_size(members);
    for (i = 0; i < n; i++) {
        const char *u =
            json_string_value(json_object_get(json_array_get(members, i), "uuid"));
        if (u != NULL && strcmp(u, uuid) == 0) return true;
    }
    return false;
}

/* Assert members is sorted ascending by uuid (canonical ordering). */
static void _assert_sorted(json_t *members)
{
    size_t i, n = json_array_size(members);
    for (i = 1; i < n; i++) {
        const char *a =
            json_string_value(json_object_get(json_array_get(members, i - 1), "uuid"));
        const char *b =
            json_string_value(json_object_get(json_array_get(members, i), "uuid"));
        ck_assert(a != NULL && b != NULL);
        ck_assert(strcmp(a, b) < 0);
    }
}

/* ------------------------------------------------------------------ */
/* Injected fetch for the aggregator (ctx = json object gw -> resp).   */
/* ------------------------------------------------------------------ */

static json_t *_tree_fetch(void *ctx, const char *gw)
{
    json_t *tree = (json_t *)ctx;
    json_t *r = json_object_get(tree, gw);  /* borrowed */
    if (r == NULL) return NULL;             /* unreachable */
    return json_deep_copy(r);               /* aggregator owns + decrefs */
}

/* Build a response object {members:[{uuid}], child_gateways:[str], private}. */
static json_t *_mk_resp(const char **members, size_t nm,
                        const char **children, size_t nc, bool private)
{
    json_t *r = json_object();
    json_t *ms = json_array();
    for (size_t i = 0; i < nm; i++) {
        json_t *m = json_object();
        json_object_set_new(m, "uuid", json_string(members[i]));
        json_array_append_new(ms, m);
    }
    json_object_set_new(r, "members", ms);
    json_t *cs = json_array();
    for (size_t i = 0; i < nc; i++)
        json_array_append_new(cs, json_string(children[i]));
    json_object_set_new(r, "child_gateways", cs);
    json_object_set_new(r, "private", private ? json_true() : json_false());
    return r;
}

/* ------------------------------------------------------------------ */

static void _begin(void)
{
    identity_reset_state();
    g_resp_count = 0;
    g_last_members = NULL;
    g_last_child_gws = NULL;
    g_last_private = false;
    g_last_resp_proc[0] = '\0';
    messaging_set_test_hook(_capture_hook);
}

static void _end(void)
{
    messaging_set_test_hook(NULL);
    if (g_last_members != NULL) { json_decref(g_last_members); g_last_members = NULL; }
    if (g_last_child_gws != NULL) { json_decref(g_last_child_gws); g_last_child_gws = NULL; }
}

/* ---- enumerate_local_members ------------------------------------- */

DEFINE_TEST(test_enumerate_leaf_is_self_only)
{
    _begin();
    identity_t *me = _mk_identity("leaf", "10.0.0.1");
    process_t *proc = _mk_process(me);

    json_t *members = identity_enumerate_local_members(proc);
    char su[UUID_STRING_LEN + 1];
    _uuid_str(me, su);
    ck_assert_int_eq((int)json_array_size(members), 1);
    ck_assert(_members_have(members, su));
    json_decref(members);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_enumerate_gateway_includes_child_group)
{
    _begin();
    identity_t *me = _mk_identity("top", "10.0.0.1");
    identity_t *mid = _mk_identity("mid", "10.0.0.2");
    process_t *proc = _mk_process(me);
    group_t child = {0};
    _mk_child_group(proc, mid, &child);

    json_t *members = identity_enumerate_local_members(proc);
    char su[UUID_STRING_LEN + 1], mu[UUID_STRING_LEN + 1];
    _uuid_str(me, su);
    _uuid_str(mid, mu);
    ck_assert_int_eq((int)json_array_size(members), 2);
    ck_assert(_members_have(members, su));
    ck_assert(_members_have(members, mu));
    _assert_sorted(members);
    json_decref(members);
    _end();
}
END_TEST_DEFINITION()

/* ---- handle_roster_request --------------------------------------- */

static void _dispatch_roster_req(process_t *proc)
{
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = ID_ROSTER_QUERY_FN;
    json_t *payload = json_object();
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, payload));
    json_decref(payload);
    run_message_handlers(proc, NULL, NET_MESSAGE, &msg);
}

/* As above, but the requestor NAMES the process its answer must come back to
 * (rep_req's requesting_process convention). */
static void _dispatch_roster_req_from(process_t *proc, const char *req_proc)
{
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = ID_ROSTER_QUERY_FN;
    json_t *payload = json_object();
    if (req_proc != NULL)
        json_object_set_new(payload, "requesting_process",
                            json_string(req_proc));
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, payload));
    json_decref(payload);
    run_message_handlers(proc, NULL, NET_MESSAGE, &msg);
}

DEFINE_TEST(test_handle_roster_request_replies_local_and_children)
{
    _begin();
    identity_t *me = _mk_identity("top", "10.0.0.1");
    identity_t *mid = _mk_identity("mid", "10.0.0.2");
    process_t *proc = _mk_process(me);
    group_t child = {0};
    _mk_child_group(proc, mid, &child);

    _dispatch_roster_req(proc);

    ck_assert_int_eq((int)g_resp_count, 1);
    ck_assert(!g_last_private);
    char su[UUID_STRING_LEN + 1], mu[UUID_STRING_LEN + 1];
    _uuid_str(me, su);
    _uuid_str(mid, mu);
    ck_assert(_members_have(g_last_members, su));
    ck_assert(_members_have(g_last_members, mu));
    /* child_gateways names mid as the recursion target */
    ck_assert_int_eq((int)json_array_size(g_last_child_gws), 1);
    ck_assert_str_eq(json_string_value(json_array_get(g_last_child_gws, 0)), mu);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_handle_roster_request_private_discloses_nothing)
{
    _begin();
    identity_t *me = _mk_identity("top", "10.0.0.1");
    identity_t *mid = _mk_identity("mid", "10.0.0.2");
    process_t *proc = _mk_process(me);
    group_t child = {0};
    _mk_child_group(proc, mid, &child);
    identity_set_roster_private(proc, true);  /* opt out */

    _dispatch_roster_req(proc);

    ck_assert_int_eq((int)g_resp_count, 1);
    ck_assert(g_last_private);
    ck_assert_int_eq((int)json_array_size(g_last_members), 0);
    ck_assert_int_eq((int)json_array_size(g_last_child_gws), 0);
    _end();
}
END_TEST_DEFINITION()

/* ---- aggregate_subtree_roster ------------------------------------ */

DEFINE_TEST(test_aggregate_flattens_three_level_tree)
{
    _begin();
    json_t *tree = json_object();
    const char *top_m[] = {"top", "a"}; const char *top_c[] = {"mid"};
    const char *mid_m[] = {"mid", "b"}; const char *mid_c[] = {"leaf"};
    const char *leaf_m[] = {"leaf", "c"};
    json_object_set_new(tree, "top", _mk_resp(top_m, 2, top_c, 1, false));
    json_object_set_new(tree, "mid", _mk_resp(mid_m, 2, mid_c, 1, false));
    json_object_set_new(tree, "leaf", _mk_resp(leaf_m, 2, NULL, 0, false));

    json_t *members = NULL, *privates = NULL;
    bool complete = false;
    ck_assert_ret_ok(identity_aggregate_subtree_roster(
        "top", _tree_fetch, tree, &members, &complete, &privates));
    ck_assert(complete);
    ck_assert_int_eq((int)json_array_size(privates), 0);
    ck_assert_int_eq((int)json_array_size(members), 6);
    ck_assert(_members_have(members, "a") && _members_have(members, "b")
              && _members_have(members, "c") && _members_have(members, "top")
              && _members_have(members, "mid") && _members_have(members, "leaf"));
    _assert_sorted(members);
    json_decref(members); json_decref(privates); json_decref(tree);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_aggregate_private_gateway_is_opaque_boundary)
{
    _begin();
    json_t *tree = json_object();
    const char *top_m[] = {"top", "a"}; const char *top_c[] = {"mid"};
    const char *mid_c[] = {"leaf"};
    const char *leaf_m[] = {"leaf", "c"};
    json_object_set_new(tree, "top", _mk_resp(top_m, 2, top_c, 1, false));
    json_object_set_new(tree, "mid", _mk_resp(NULL, 0, mid_c, 1, true));  /* private */
    json_object_set_new(tree, "leaf", _mk_resp(leaf_m, 2, NULL, 0, false));

    json_t *members = NULL, *privates = NULL;
    bool complete = false;
    ck_assert_ret_ok(identity_aggregate_subtree_roster(
        "top", _tree_fetch, tree, &members, &complete, &privates));
    ck_assert(complete);                                  /* privacy != failure */
    ck_assert_int_eq((int)json_array_size(privates), 1);
    ck_assert_str_eq(json_string_value(json_array_get(privates, 0)), "mid");
    /* mid visible (top listed it), but leaf/c behind mid are hidden */
    ck_assert_int_eq((int)json_array_size(members), 2);
    ck_assert(_members_have(members, "top") && _members_have(members, "a"));
    json_decref(members); json_decref(privates); json_decref(tree);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_aggregate_partial_when_child_unreachable)
{
    _begin();
    json_t *tree = json_object();
    const char *top_m[] = {"top"}; const char *top_c[] = {"ghost"};
    json_object_set_new(tree, "top", _mk_resp(top_m, 1, top_c, 1, false));
    /* "ghost" absent -> fetch returns NULL */

    json_t *members = NULL, *privates = NULL;
    bool complete = true;
    ck_assert_ret_ok(identity_aggregate_subtree_roster(
        "top", _tree_fetch, tree, &members, &complete, &privates));
    ck_assert(!complete);                                 /* a fetch failed */
    ck_assert_int_eq((int)json_array_size(privates), 0);  /* unreachable != private */
    ck_assert_int_eq((int)json_array_size(members), 1);
    ck_assert(_members_have(members, "top"));
    json_decref(members); json_decref(privates); json_decref(tree);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_aggregate_terminates_on_cycle)
{
    _begin();
    json_t *tree = json_object();
    const char *a_m[] = {"a"}; const char *a_c[] = {"b"};
    const char *b_m[] = {"b"}; const char *b_c[] = {"a"};  /* cycle */
    json_object_set_new(tree, "a", _mk_resp(a_m, 1, a_c, 1, false));
    json_object_set_new(tree, "b", _mk_resp(b_m, 1, b_c, 1, false));

    json_t *members = NULL, *privates = NULL;
    bool complete = false;
    ck_assert_ret_ok(identity_aggregate_subtree_roster(
        "a", _tree_fetch, tree, &members, &complete, &privates));
    ck_assert(complete);                                  /* visited-guard */
    ck_assert_int_eq((int)json_array_size(members), 2);
    ck_assert(_members_have(members, "a") && _members_have(members, "b"));
    json_decref(members); json_decref(privates); json_decref(tree);
    _end();
}
END_TEST_DEFINITION()

/* ---- identity_load_child_groups (config-file seeding) ------------------- */

DEFINE_TEST(test_load_child_groups_from_python_schema_config)
{
    _begin();
    identity_t *me = _mk_identity("gw", "10.0.0.1");
    process_t *proc = _mk_process(me);

    char dir[] = "/tmp/at-roster-cfg-XXXXXX";
    ck_assert_ptr_nonnull(mkdtemp(dir));
    char path[512];
    snprintf(path, sizeof(path), "%s/group_child_test.cfg.json", dir);
    FILE *f = fopen(path, "w");
    ck_assert_ptr_nonnull(f);
    /* On-disk Python `Group` schema: array [group, hist]; group carries
     * _uuid + _address_map (uuid -> address). */
    fputs("[{\"__type__\":"
          "\"autonomous_trust.core._python.identity.group.Group\","
          "\"_uuid\":\"518176b5-b8ff-4a1f-9bc5-874fde9f415a\","
          "\"_address_map\":{"
          "\"1a7f67a3-8f5d-4af7-844e-2b146d53229c\":\"squad-captain\","
          "\"392bbd76-a698-4507-a2dc-8622e0ff32ec\":\"squad-warrant\"},"
          "\"_nickname\":\"testcohort\",\"_public_only\":false},{}]", f);
    fclose(f);

    int n = identity_load_child_groups(proc, dir);
    ck_assert_int_eq(n, 1);

    json_t *members = identity_enumerate_local_members(proc);
    char su[UUID_STRING_LEN + 1];
    _uuid_str(me, su);
    ck_assert(_members_have(members, su));  /* self */
    ck_assert(_members_have(members,
                            "1a7f67a3-8f5d-4af7-844e-2b146d53229c"));
    ck_assert(_members_have(members,
                            "392bbd76-a698-4507-a2dc-8622e0ff32ec"));
    json_decref(members);

    unlink(path);
    rmdir(dir);
    _end();
}

/* ---- rank-based child-gateway discovery -------------------------------- */

/* Seed a child group with explicit member uuids. @p gateway (may be NULL)
 * sets an explicit child_gateways override; NULL forces rank-based discovery.
 * @p out must outlive the enumeration (stack in the test body). */
static void _mk_child_group_uuids(process_t *proc, group_t *out,
                                  const char **uuids, size_t n,
                                  const char *gateway)
{
    uuid_t cg;
    uuid_generate(cg);
    group_init(&cg, (char *)"child-addr", out);
    for (size_t i = 0; i < n; i++) {
        /* Distinct address per member — group_add_address drops a prior entry
         * that shares an address (address-collision handling). */
        char addr[32];
        snprintf(addr, sizeof(addr), "10.9.0.%zu", i + 1);
        group_add_address(out, (char *)uuids[i], addr);
    }
    ck_assert_ret_ok(identity_add_child_group(proc, out, gateway));
}

/* The single discovered/overridden gateway for a one-child-group node. */
static const char *_only_gateway(process_t *proc, json_t **hold)
{
    json_t *resp = identity_roster_response(proc);
    ck_assert_ptr_nonnull(resp);
    json_t *cgs = json_object_get(resp, "child_gateways");
    ck_assert_int_eq((int)json_array_size(cgs), 1);
    const char *gw = json_string_value(json_array_get(cgs, 0));
    *hold = resp;  /* keep alive for the caller's assert; caller decrefs */
    return gw;
}

#define U_LOW  "11111111-1111-1111-1111-111111111111"
#define U_HIGH "99999999-9999-9999-9999-999999999999"

DEFINE_TEST(test_discover_gateway_prefers_higher_rank)
{
    _begin();
    identity_t *me = _mk_identity("top", "10.0.0.1");
    process_t *proc = _mk_process(me);
    const char *members[] = {U_LOW, U_HIGH};
    group_t child = {0};
    _mk_child_group_uuids(proc, &child, members, 2, NULL);
    /* U_LOW has the LOWER uuid but the HIGHER rank -> rank dominates. */
    ck_assert_ret_ok(identity_set_peer_rank(proc, U_LOW, 5));
    ck_assert_ret_ok(identity_set_peer_rank(proc, U_HIGH, 1));

    json_t *hold = NULL;
    ck_assert_str_eq(_only_gateway(proc, &hold), U_LOW);
    json_decref(hold);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_discover_gateway_uuid_tiebreak)
{
    _begin();
    identity_t *me = _mk_identity("top", "10.0.0.1");
    process_t *proc = _mk_process(me);
    const char *members[] = {U_LOW, U_HIGH};
    group_t child = {0};
    _mk_child_group_uuids(proc, &child, members, 2, NULL);
    /* No ranks set (both 0) -> lexicographically greater uuid wins. */

    json_t *hold = NULL;
    ck_assert_str_eq(_only_gateway(proc, &hold), U_HIGH);
    json_decref(hold);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_explicit_gateway_overrides_discovery)
{
    _begin();
    identity_t *me = _mk_identity("top", "10.0.0.1");
    process_t *proc = _mk_process(me);
    const char *members[] = {U_LOW, U_HIGH};
    group_t child = {0};
    const char *pinned = "abcdef01-0000-0000-0000-000000000000";
    _mk_child_group_uuids(proc, &child, members, 2, pinned);
    /* Even with a high-rank member, the explicit override wins. */
    ck_assert_ret_ok(identity_set_peer_rank(proc, U_HIGH, 99));

    json_t *hold = NULL;
    ck_assert_str_eq(_only_gateway(proc, &hold), pinned);
    json_decref(hold);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_discover_gateway_excludes_self)
{
    _begin();
    identity_t *me = _mk_identity("top", "10.0.0.1");
    process_t *proc = _mk_process(me);
    char su[UUID_STRING_LEN + 1];
    _uuid_str(me, su);
    /* Self sits in the child group with the highest rank, yet must be
     * excluded from being its own recursion target. */
    const char *members[] = {su, U_HIGH};
    group_t child = {0};
    _mk_child_group_uuids(proc, &child, members, 2, NULL);
    ck_assert_ret_ok(identity_set_peer_rank(proc, su, 100));
    ck_assert_ret_ok(identity_set_peer_rank(proc, U_HIGH, 1));

    json_t *hold = NULL;
    ck_assert_str_eq(_only_gateway(proc, &hold), U_HIGH);
    json_decref(hold);
    _end();
}
END_TEST_DEFINITION()

/* The reply must reach the process that will actually consume it. Inbound
 * messages route by net_msg.process alone, and the aggregation lives in the
 * requestor's MAIN loop — its identity process registers no roster_resp
 * handler. Answering to our own process name stranded every reply there. */
DEFINE_TEST(test_handle_roster_request_replies_to_requestors_named_process)
{
    _begin();
    identity_t *me = _mk_identity("gw", "10.0.0.1");
    process_t *proc = _mk_process(me);

    _dispatch_roster_req_from(proc, "main");

    ck_assert_int_eq((int)g_resp_count, 1);
    ck_assert_str_eq(g_last_resp_proc, "main");
    _end();
}

/* An inspector bridge (or any non-main requestor) gets its answer where it
 * asked for it — the same freedom rep_req's requesting_process gives. */
DEFINE_TEST(test_handle_roster_request_honors_non_main_requesting_process)
{
    _begin();
    identity_t *me = _mk_identity("gw", "10.0.0.1");
    process_t *proc = _mk_process(me);

    _dispatch_roster_req_from(proc, "inspector");

    ck_assert_int_eq((int)g_resp_count, 1);
    ck_assert_str_eq(g_last_resp_proc, "inspector");
    _end();
}

/* A requestor that predates requesting_process still gets a usable answer:
 * main is where the aggregation lives, so the default is the right home. */
DEFINE_TEST(test_handle_roster_request_defaults_to_main)
{
    _begin();
    identity_t *me = _mk_identity("gw", "10.0.0.1");
    process_t *proc = _mk_process(me);

    _dispatch_roster_req_from(proc, NULL);

    ck_assert_int_eq((int)g_resp_count, 1);
    ck_assert_str_eq(g_last_resp_proc, "main");
    _end();
}

RUN_TESTS(SubtreeRoster,
          test_enumerate_leaf_is_self_only,
          test_enumerate_gateway_includes_child_group,
          test_handle_roster_request_replies_local_and_children,
          test_handle_roster_request_private_discloses_nothing,
          test_aggregate_flattens_three_level_tree,
          test_aggregate_private_gateway_is_opaque_boundary,
          test_aggregate_partial_when_child_unreachable,
          test_aggregate_terminates_on_cycle,
          test_load_child_groups_from_python_schema_config,
          test_discover_gateway_prefers_higher_rank,
          test_discover_gateway_uuid_tiebreak,
          test_explicit_gateway_overrides_discovery,
          test_discover_gateway_excludes_self,
          test_handle_roster_request_replies_to_requestors_named_process,
          test_handle_roster_request_honors_non_main_requesting_process,
          test_handle_roster_request_defaults_to_main)
