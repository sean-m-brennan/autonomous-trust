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

/** @file The anchored cohort, identity's half (RD_14.4_HOSTILE_JOIN_PLAN.md
 *  Phase 6, D8 (b)), on one node: forming, consent, the coordinator,
 *  persistence. The other nodes are played by hand: their invitations and
 *  replies are crafted NET_MESSAGEs, and what this node sends is captured. The
 *  Python twin, tests/a_unit/test_anchored_cohort.py, runs three nodes.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <jansson.h>
#include <uuid/uuid.h>

#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "identity/id_proc_priv.h"
#include "identity/group.h"
#include "identity/join_policy.h"
#include "identity/anchored_cohort.h"
#include "config/configuration.h"
#include "structures/data.h"
#include "structures/map.h"
#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
#include "utilities/msg_types_priv.h"
#include "utilities/allocation.h"

/* ---- capture --------------------------------------------------------------- */

#define MAX_SENT 16
static struct {
    char fn[48];
    char to[UUID_STRING_LEN + 1];
    json_t *payload;
} g_sent[MAX_SENT];
static int g_n_sent;
static anchored_cohort_msg_t g_published;
static int g_n_published;

static int _hook(const char *key, const message_type_t type, generic_msg_t *msg,
                 bool blocking)
{
    (void)blocking;
    if (type == ANCHORED_COHORT) {
        ck_assert_str_eq(key, "reputation");
        g_published = msg->info.anchored_cohort;
        g_n_published++;
        return 0;
    }
    if (type != NET_MESSAGE || msg->info.net_msg.function == NULL
        || strncmp(msg->info.net_msg.function, "anchored_cohort_", 16) != 0)
        return 0;
    if (g_n_sent < MAX_SENT) {
        snprintf(g_sent[g_n_sent].fn, sizeof(g_sent[0].fn), "%s",
                 msg->info.net_msg.function);
        uuid_unparse_lower(msg->info.net_msg.to_whom.uuid, g_sent[g_n_sent].to);
        g_sent[g_n_sent].payload = NULL;
        (void)net_msg_unpack_json(&msg->info.net_msg, &g_sent[g_n_sent].payload);
        g_n_sent++;
    }
    return 0;
}

static void _clear_sent(void)
{
    for (int i = 0; i < g_n_sent; i++)
        json_decref(g_sent[i].payload);
    g_n_sent = 0;
}

/* ---- the node and its peers ------------------------------------------------ */

static const char *ANCHORS[8];
static size_t g_n_anchors;

static bool _anchor_fn(const process_t *proc, const public_identity_t *peer)
{
    (void)proc;
    char k[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer->uuid, k);
    for (size_t i = 0; i < g_n_anchors; i++)
        if (strcmp(ANCHORS[i], k) == 0)
            return true;
    return false;
}

static double g_now = 1000.0;
static double _clock(void) { return g_now; }

static identity_t *_mk_identity(const char *uuid_str, const char *name,
                                const char *addr)
{
    uuid_t u;
    ck_assert_int_eq(uuid_parse(uuid_str, u), 0);
    identity_t *ident = NULL;
    ck_assert_ret_ok(identity_create(&u, addr, name, name, &ident));
    return ident;
}

static char g_root[64];

/* Self (@p me) and peers a, b, c in one primary group; the policy on or off. */
static process_t *_begin(const char *me, bool on, int cohort_min)
{
    snprintf(g_root, sizeof(g_root), "/tmp/at-cohort-XXXXXX");
    ck_assert(mkdtemp(g_root) != NULL);
    char etc[128];
    snprintf(etc, sizeof(etc), "%s/etc", g_root);
    mkdir(etc, 0700);
    snprintf(etc, sizeof(etc), "%s/etc/at", g_root);
    mkdir(etc, 0700);
    setenv("AUTONOMOUS_TRUST_ROOT", g_root, 1);

    at_join_policy_t policy;
    char err[128];
    char doc[128];
    snprintf(doc, sizeof(doc), "{\"version\": 1, \"enabled\": %s, "
             "\"anchored_cohort_min\": %d}", on ? "true" : "false", cohort_min);
    ck_assert(at_join_policy_parse(doc, &policy, err, sizeof(err)));
    identity_set_join_policy(&policy);
    identity_anchored_cohort_reset();
    identity_anchored_cohort_set_anchor_fn(_anchor_fn);
    identity_anchored_cohort_set_clock(_clock);
    g_n_anchors = 0;
    g_n_published = 0;
    memset(&g_published, 0, sizeof(g_published));
    _clear_sent();
    messaging_set_test_hook(_hook);

    identity_t *self = _mk_identity(me, "self", "10.8.0.1");
    process_t *proc = smrt_create(sizeof(process_t));
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    strncpy(proc->name, "identity", PROC_NAME_LEN);
    proc->protocol.phase = 3;
    uuid_t guuid;
    uuid_generate(guuid);
    group_init(&guuid, (char *)self->address, &proc->protocol.group);
    group_add_address(&proc->protocol.group, me, self->address);
    config_t *id_cfg = calloc(1, sizeof(config_t));
    id_cfg->name = "identity";
    id_cfg->data_struct = self;
    ck_assert_ret_ok(map_create(&proc->configs));
    map_set(proc->configs, (map_key_t)"identity",
            object_ptr_data((ptr_t)id_cfg, sizeof(config_t)));
    ck_assert_ret_ok(map_create(&proc->protocol.handlers));
    identity_anchored_cohort_register(proc);
    return proc;
}

static void _add_peer(process_t *proc, const char *uuid_str, const char *name,
                      const char *addr)
{
    identity_t *ident = _mk_identity(uuid_str, name, addr);
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(ident, &pub));
    proc->protocol.peers[proc->protocol.num_peers++] = *pub;
    smrt_deref(pub);
    group_add_address(&proc->protocol.group, uuid_str, addr);
}

static void _end(void)
{
    messaging_set_test_hook(NULL);
    identity_anchored_cohort_reset();
    identity_anchored_cohort_set_anchor_fn(NULL);
    identity_anchored_cohort_set_clock(NULL);
    identity_set_join_policy(NULL);
    _clear_sent();
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", g_root);
#ifndef _WIN32
    ck_assert_int_eq(system(cmd), 0);
#endif
}

#define U_ME   "00000000-0000-4000-8000-000000000005"
#define U_LOW  "00000000-0000-4000-8000-000000000001"
#define U_A    "00000000-0000-4000-8000-00000000000a"
#define U_B    "00000000-0000-4000-8000-00000000000b"
#define U_C    "00000000-0000-4000-8000-00000000000c"

static int _held_members(void)
{
    group_t g;
    if (!identity_anchored_cohort_held(&g))
        return -1;
    int n = (int)map_size(&g.address_map);
    identity_anchored_cohort_release(&g);
    return n;
}

static int64_t _held_epoch(void)
{
    group_t g;
    if (!identity_anchored_cohort_held(&g))
        return -1;
    int64_t e = g.key_epoch;
    identity_anchored_cohort_release(&g);
    return e;
}

/* A message from @p from carrying @p payload (stolen). */
static void _deliver(process_t *proc, char *fn, const char *from, json_t *payload)
{
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = fn;
    msg.info.net_msg.verified = true;
    for (size_t i = 0; i < proc->protocol.num_peers; i++) {
        char k[UUID_STRING_LEN + 1];
        uuid_unparse_lower(proc->protocol.peers[i].uuid, k);
        if (strcmp(k, from) == 0)
            msg.info.net_msg.from_whom = proc->protocol.peers[i];
    }
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, payload));
    json_decref(payload);
    run_message_handlers(proc, NULL, NET_MESSAGE, &msg);
    net_msg_free_obj(&msg.info.net_msg);
}

/* A cohort with private key and members {me} + @p others, at @p epoch. */
static json_t *_cohort_json(const char *uuid_str, int64_t epoch,
                            const char *const *members, size_t n)
{
    group_t g;
    memset(&g, 0, sizeof(g));
    uuid_t u;
    uuid_parse(uuid_str, u);
    char addr[] = "10.8.0.1";
    group_init(&u, addr, &g);
    for (size_t i = 0; i < n; i++) {
        char addr_i[32];                /* one address each: a shared one evicts */
        snprintf(addr_i, sizeof(addr_i), "10.8.1.%zu", i + 1);
        group_add_address(&g, members[i], addr_i);
    }
    g.key_epoch = epoch;
    json_t *j = NULL;
    ck_assert_ret_ok(group_to_json(&g, &j));
    map_free(&g.address_map);
    return j;
}

/* ---- forming --------------------------------------------------------------- */

DEFINE_TEST(test_the_lowest_uuid_forms_it_and_invites_its_anchors)
{
    process_t *proc = _begin(U_ME, true, 1);
    _add_peer(proc, U_A, "a", "10.8.0.2");
    _add_peer(proc, U_B, "b", "10.8.0.3");
    ANCHORS[g_n_anchors++] = U_A;
    identity_anchored_cohort_tick(proc);
    ck_assert_int_eq(_held_members(), 2);
    ck_assert_int_eq(g_n_sent, 1);
    ck_assert_str_eq(g_sent[0].fn, "anchored_cohort_invite");
    ck_assert_str_eq(g_sent[0].to, U_A);
    ck_assert(g_published.held);
    ck_assert_int_eq((int)g_published.n_members, 2);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_higher_uuid_waits)
{
    process_t *proc = _begin(U_ME, true, 1);
    _add_peer(proc, U_LOW, "low", "10.8.0.2");
    ANCHORS[g_n_anchors++] = U_LOW;
    identity_anchored_cohort_tick(proc);
    ck_assert_int_eq(_held_members(), -1);
    ck_assert_int_eq(g_n_sent, 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_policy_off_forms_nothing_and_ignores_invites)
{
    process_t *proc = _begin(U_ME, false, 1);
    _add_peer(proc, U_LOW, "low", "10.8.0.2");
    ANCHORS[g_n_anchors++] = U_LOW;
    identity_anchored_cohort_tick(proc);
    const char *m[] = {U_ME, U_LOW};
    _deliver(proc, ID_COHORT_INVITE, U_LOW,
             _cohort_json("11111111-0000-4000-8000-000000000001", 0, m, 2));
    ck_assert_int_eq(_held_members(), -1);
    ck_assert_int_eq(g_n_sent, 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_anchored_cohort_min_is_honoured)
{
    process_t *proc = _begin(U_ME, true, 2);
    _add_peer(proc, U_A, "a", "10.8.0.2");
    _add_peer(proc, U_B, "b", "10.8.0.3");
    ANCHORS[g_n_anchors++] = U_A;
    identity_anchored_cohort_tick(proc);
    ck_assert_int_eq(_held_members(), -1);
    ANCHORS[g_n_anchors++] = U_B;
    identity_anchored_cohort_tick(proc);
    ck_assert_int_eq(_held_members(), 3);
    _end();
}
END_TEST_DEFINITION()

/* ---- consent ---------------------------------------------------------------- */

#define G1 "11111111-0000-4000-8000-000000000001"

DEFINE_TEST(test_an_invite_from_anchors_is_accepted)
{
    process_t *proc = _begin(U_ME, true, 1);
    _add_peer(proc, U_LOW, "low", "10.8.0.2");
    _add_peer(proc, U_A, "a", "10.8.0.3");
    ANCHORS[g_n_anchors++] = U_LOW;
    ANCHORS[g_n_anchors++] = U_A;
    const char *m[] = {U_ME, U_LOW, U_A};
    _deliver(proc, ID_COHORT_INVITE, U_LOW, _cohort_json(G1, 0, m, 3));
    ck_assert_int_eq(_held_members(), 3);
    ck_assert_int_eq(g_n_sent, 1);
    ck_assert_str_eq(g_sent[0].fn, "anchored_cohort_reply");
    ck_assert(json_is_true(json_array_get(g_sent[0].payload, 2)));
    ck_assert_int_eq((int)json_integer_value(json_array_get(g_sent[0].payload, 1)), 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_invite_listing_a_stranger_is_refused)
{
    process_t *proc = _begin(U_ME, true, 1);
    _add_peer(proc, U_LOW, "low", "10.8.0.2");
    _add_peer(proc, U_A, "a", "10.8.0.3");
    ANCHORS[g_n_anchors++] = U_LOW;             /* a is no anchor here */
    const char *m[] = {U_ME, U_LOW, U_A};
    _deliver(proc, ID_COHORT_INVITE, U_LOW, _cohort_json(G1, 0, m, 3));
    ck_assert_int_eq(_held_members(), -1);
    ck_assert_int_eq(g_n_sent, 1);
    ck_assert(json_is_false(json_array_get(g_sent[0].payload, 2)));
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_stale_invite_is_ignored_and_an_update_is_taken)
{
    process_t *proc = _begin(U_ME, true, 1);
    _add_peer(proc, U_LOW, "low", "10.8.0.2");
    ANCHORS[g_n_anchors++] = U_LOW;
    const char *m[] = {U_ME, U_LOW};
    _deliver(proc, ID_COHORT_INVITE, U_LOW, _cohort_json(G1, 1, m, 2));
    _clear_sent();
    _deliver(proc, ID_COHORT_INVITE, U_LOW, _cohort_json(G1, 1, m, 2));
    ck_assert_int_eq(g_n_sent, 0);
    _deliver(proc, ID_COHORT_INVITE, U_LOW, _cohort_json(G1, 2, m, 2));
    ck_assert_int_eq((int)_held_epoch(), 2);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_update_adding_a_stranger_is_leaving)
{
    process_t *proc = _begin(U_ME, true, 1);
    _add_peer(proc, U_LOW, "low", "10.8.0.2");
    _add_peer(proc, U_A, "a", "10.8.0.3");
    ANCHORS[g_n_anchors++] = U_LOW;
    const char *m2[] = {U_ME, U_LOW};
    _deliver(proc, ID_COHORT_INVITE, U_LOW, _cohort_json(G1, 0, m2, 2));
    ck_assert_int_eq(_held_members(), 2);
    const char *m3[] = {U_ME, U_LOW, U_A};
    _deliver(proc, ID_COHORT_INVITE, U_LOW, _cohort_json(G1, 1, m3, 3));
    ck_assert_int_eq(_held_members(), -1);
    ck_assert(!g_published.held);
    _end();
}
END_TEST_DEFINITION()

/* ---- the coordinator ----------------------------------------------------- */

static json_t *_reply_json(const char *group, int64_t epoch, bool ok)
{
    return json_pack("[s, I, b]", group, (json_int_t)epoch, ok);
}

static void _held_uuid(char *out)
{
    group_t g;
    ck_assert(identity_anchored_cohort_held(&g));
    uuid_unparse_lower(g.uuid, out);
    identity_anchored_cohort_release(&g);
}

DEFINE_TEST(test_a_refusal_drops_the_member_and_it_is_not_reoffered)
{
    process_t *proc = _begin(U_LOW, true, 1);
    _add_peer(proc, U_A, "a", "10.8.0.2");
    _add_peer(proc, U_B, "b", "10.8.0.3");
    ANCHORS[g_n_anchors++] = U_A;
    ANCHORS[g_n_anchors++] = U_B;
    identity_anchored_cohort_tick(proc);
    ck_assert_int_eq(_held_members(), 3);
    char gu[UUID_STRING_LEN + 1];
    _held_uuid(gu);
    _deliver(proc, ID_COHORT_REPLY, U_A, _reply_json(gu, 0, false));
    ck_assert_int_eq(_held_members(), 2);
    ck_assert_int_eq((int)_held_epoch(), 1);
    /* a is still an anchor here, but is never offered {low, a, b} again. */
    _clear_sent();
    identity_anchored_cohort_tick(proc);
    ck_assert_int_eq(_held_members(), 2);
    ck_assert_int_eq(g_n_sent, 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_superseded_refusal_is_ignored)
{
    process_t *proc = _begin(U_LOW, true, 1);
    _add_peer(proc, U_A, "a", "10.8.0.2");
    ANCHORS[g_n_anchors++] = U_A;
    identity_anchored_cohort_tick(proc);
    char gu[UUID_STRING_LEN + 1];
    _held_uuid(gu);
    _deliver(proc, ID_COHORT_REPLY, U_A, _reply_json(gu, 7, false));
    ck_assert_int_eq(_held_members(), 2);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_late_anchor_is_added_and_a_silent_member_dropped)
{
    process_t *proc = _begin(U_LOW, true, 1);
    _add_peer(proc, U_A, "a", "10.8.0.2");
    _add_peer(proc, U_B, "b", "10.8.0.3");
    ANCHORS[g_n_anchors++] = U_A;
    identity_anchored_cohort_tick(proc);
    ck_assert_int_eq(_held_members(), 2);
    char gu[UUID_STRING_LEN + 1];
    _held_uuid(gu);
    _deliver(proc, ID_COHORT_REPLY, U_A, _reply_json(gu, 0, true));
    ANCHORS[g_n_anchors++] = U_B;
    identity_anchored_cohort_tick(proc);
    ck_assert_int_eq(_held_members(), 3);
    ck_assert_int_eq((int)_held_epoch(), 1);
    /* Nobody answers the rotation. */
    g_now += AT_COHORT_REPLY_TIMEOUT + 1.0;
    identity_anchored_cohort_tick(proc);
    ck_assert_int_eq(_held_members(), 1);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_restart_restores_the_cohort)
{
    process_t *proc = _begin(U_LOW, true, 1);
    _add_peer(proc, U_A, "a", "10.8.0.2");
    ANCHORS[g_n_anchors++] = U_A;
    identity_anchored_cohort_tick(proc);
    char gu[UUID_STRING_LEN + 1];
    _held_uuid(gu);
    identity_anchored_cohort_reset();
    ck_assert_int_eq(_held_members(), -1);
    identity_anchored_cohort_load(proc);
    char again[UUID_STRING_LEN + 1];
    _held_uuid(again);
    ck_assert_str_eq(again, gu);
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(AnchoredCohort,
          test_the_lowest_uuid_forms_it_and_invites_its_anchors,
          test_a_higher_uuid_waits,
          test_the_policy_off_forms_nothing_and_ignores_invites,
          test_anchored_cohort_min_is_honoured,
          test_an_invite_from_anchors_is_accepted,
          test_an_invite_listing_a_stranger_is_refused,
          test_a_stale_invite_is_ignored_and_an_update_is_taken,
          test_an_update_adding_a_stranger_is_leaving,
          test_a_refusal_drops_the_member_and_it_is_not_reoffered,
          test_a_superseded_refusal_is_ignored,
          test_a_late_anchor_is_added_and_a_silent_member_dropped,
          test_a_restart_restores_the_cohort)
