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

/** @file The anchored cohort, reputation's half (RD_14.4_HOSTILE_JOIN_PLAN.md
 *  Phase 6, D8 (b)): a half about a member names the cohort and goes only to
 *  its members; acceptors check the group; the scorers read the cohort chain
 *  beside the primary one. The Python twin is
 *  tests/a_unit/test_anchored_cohort_rep.py.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <jansson.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "identity/join_policy.h"
#include "reputation/reputation.h"
#include "reputation/rep_proc_priv.h"
#include "config/configuration.h"
#include "structures/data.h"
#include "structures/map.h"
#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
#include "utilities/msg_types_priv.h"
#include "utilities/allocation.h"

static char TX_VERB[] = "transaction";
static char ACCEPTED_VERB[] = "tx accepted";

/* What went out: `transaction` frames (recipient, group named) and
 * `tx accepted` replies. */
static int  g_tx;
static char g_tx_to[8][UUID_STRING_LEN + 1];
static char g_tx_group[UUID_STRING_LEN + 1];
static int  g_accepted;

static int _hook(const char *key, const message_type_t type, generic_msg_t *msg,
                 bool blocking)
{
    (void)key; (void)blocking;
    if (type != NET_MESSAGE || msg->info.net_msg.function == NULL)
        return 0;
    const char *fn = msg->info.net_msg.function;
    if (strcmp(fn, TX_VERB) == 0) {
        if (g_tx < 8)
            uuid_unparse_lower(msg->info.net_msg.to_whom.uuid, g_tx_to[g_tx]);
        g_tx++;
        json_t *p = NULL;
        if (net_msg_unpack_json(&msg->info.net_msg, &p) == 0 && p != NULL) {
            snprintf(g_tx_group, sizeof(g_tx_group), "%s",
                     json_string_value(json_object_get(p, "group")));
            json_decref(p);
        }
    } else if (strcmp(fn, ACCEPTED_VERB) == 0) {
        g_accepted++;
    }
    return 0;
}

static identity_t *_mk_identity(const char *name, const char *addr)
{
    uuid_t uuid;
    uuid_generate(uuid);
    identity_t *ident = NULL;
    ck_assert_ret_ok(identity_create(&uuid, addr, name, name, &ident));
    return ident;
}

static identity_t *me, *ally, *other;
static process_t *g_proc;
static char g_cohort[UUID_STRING_LEN + 1];
static char g_root[64];
static double g_present;

static void _add_peer(process_t *proc, identity_t *peer)
{
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(peer, &pub));
    proc->protocol.peers[proc->protocol.num_peers++] = *pub;
    smrt_deref(pub);
}

/* Self, a member `ally` and a non-member `other`, one primary group, and the
 * anchored cohort {self, ally}; the policy on or off. */
static void _begin(bool on)
{
    ck_assert(sodium_init() >= 0);
    snprintf(g_root, sizeof(g_root), "/tmp/at-repcohort-XXXXXX");
    ck_assert(mkdtemp(g_root) != NULL);
    char etc[128];
    snprintf(etc, sizeof(etc), "%s/etc", g_root);
    mkdir(etc, 0700);
    snprintf(etc, sizeof(etc), "%s/etc/at", g_root);
    mkdir(etc, 0700);
    setenv("AUTONOMOUS_TRUST_ROOT", g_root, 1);
    unsetenv("AT_REP_MIN_TENURE_SEC");
    reputation_reset_state(2);
    at_join_policy_t policy;
    char err[128];
    ck_assert(at_join_policy_parse(on ? "{\"version\": 1, \"enabled\": true}"
                                      : "{\"version\": 1}",
                                   &policy, err, sizeof(err)));
    reputation_set_join_policy(&policy);
    me = _mk_identity("self", "10.0.0.1");
    ally = _mk_identity("ally", "10.0.0.2");
    other = _mk_identity("other", "10.0.0.3");

    process_t *proc = smrt_create(sizeof(process_t));
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    strncpy(proc->name, "reputation", PROC_NAME_LEN);
    proc->protocol.phase = 1;
    uuid_generate(proc->protocol.group.uuid);
    config_t *id_cfg = calloc(1, sizeof(config_t));
    id_cfg->name = "identity";
    id_cfg->data_struct = me;
    ck_assert_ret_ok(map_create(&proc->configs));
    map_set(proc->configs, (map_key_t)"identity",
            object_ptr_data((ptr_t)id_cfg, sizeof(config_t)));
    ck_assert_ret_ok(map_create(&proc->protocol.handlers));
    ck_assert_ret_ok(reputation_register_handlers(proc));
    _add_peer(proc, ally);
    _add_peer(proc, other);
    g_proc = proc;

    anchored_cohort_msg_t m;
    memset(&m, 0, sizeof(m));
    m.held = true;
    uuid_generate(m.group_uuid);
    uuid_unparse_lower(m.group_uuid, g_cohort);
    uuid_copy(m.members[0], me->uuid);
    uuid_copy(m.members[1], ally->uuid);
    m.n_members = 2;
    reputation_set_anchored_cohort(&m);

    g_tx = 0;
    g_accepted = 0;
    g_tx_group[0] = '\0';
    g_present = (double)time(NULL);
    messaging_set_test_hook(_hook);
    /* Resolves self, as the process loop does first. */
    g_present += 1000.0;
    (void)reputation_rescore_sweep(g_proc, g_present, me->uuid);
}

static void _end(void)
{
    messaging_set_test_hook(NULL);
    reputation_reset_state(2);
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", g_root);
#ifndef _WIN32
    ck_assert_int_eq(system(cmd), 0);
#endif
}

static void _propose_about(identity_t *subject)
{
    uuid_t task;
    uuid_generate(task);
    _forward_transaction(g_proc, task, me->uuid, 0.9, "agora-post", NULL,
                         subject->uuid, 0.0);
}

DEFINE_TEST(test_a_half_about_a_member_goes_to_the_members_only)
{
    _begin(true);
    _propose_about(ally);
    ck_assert_int_eq(g_tx, 1);
    char a[UUID_STRING_LEN + 1];
    uuid_unparse_lower(ally->uuid, a);
    ck_assert_str_eq(g_tx_to[0], a);
    ck_assert_str_eq(g_tx_group, g_cohort);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_half_about_a_non_member_goes_to_everyone_on_the_primary)
{
    _begin(true);
    _propose_about(other);
    ck_assert_int_eq(g_tx, 2);
    char primary[UUID_STRING_LEN + 1];
    uuid_unparse_lower(g_proc->protocol.group.uuid, primary);
    ck_assert_str_eq(g_tx_group, primary);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_without_the_policy_nothing_routes_to_the_cohort)
{
    _begin(false);
    _propose_about(ally);
    ck_assert_int_eq(g_tx, 2);
    ck_assert(strcmp(g_tx_group, g_cohort) != 0);
    _end();
}
END_TEST_DEFINITION()

/* A proposal from @p sender naming @p group; whether it was accepted. */
static bool _proposal(identity_t *sender, const char *group)
{
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(sender, &pub));
    char su[UUID_STRING_LEN + 1], tu[UUID_STRING_LEN + 1];
    uuid_unparse_lower(sender->uuid, su);
    uuid_t task;
    uuid_generate(task);
    uuid_unparse_lower(task, tu);
    json_t *p = json_object();
    json_object_set_new(p, "id1", json_integer(100));
    json_object_set_new(p, "id2", json_integer(1));
    json_object_set_new(p, "peer_uuid", json_string(su));
    json_object_set_new(p, "score", json_real(0.8));
    json_object_set_new(p, "task_uuid", json_string(tu));
    json_object_set_new(p, "certify", json_true());
    json_object_set_new(p, "group", json_string(group));
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "reputation", PROC_NAME_LEN);
    msg.info.net_msg.function = TX_VERB;
    msg.info.net_msg.verified = true;
    msg.info.net_msg.from_whom = *pub;
    smrt_deref(pub);
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, p));
    json_decref(p);
    int before = g_accepted;
    run_message_handlers(g_proc, NULL, NET_MESSAGE, &msg);
    net_msg_free_obj(&msg.info.net_msg);
    return g_accepted > before;
}

DEFINE_TEST(test_an_acceptor_checks_the_cohort_and_unknown_groups)
{
    _begin(true);
    char primary[UUID_STRING_LEN + 1], stray[UUID_STRING_LEN + 1];
    uuid_unparse_lower(g_proc->protocol.group.uuid, primary);
    uuid_t s;
    uuid_generate(s);
    uuid_unparse_lower(s, stray);
    ck_assert(_proposal(ally, g_cohort));
    ck_assert(!_proposal(other, g_cohort));       /* not a member */
    ck_assert(!_proposal(ally, stray));           /* a group not held */
    ck_assert(_proposal(other, primary));
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_without_the_policy_an_unknown_group_is_accepted_as_before)
{
    _begin(false);
    char stray[UUID_STRING_LEN + 1];
    uuid_t s;
    uuid_generate(s);
    uuid_unparse_lower(s, stray);
    ck_assert(_proposal(other, stray));
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_scorers_read_the_cohort_chain)
{
    _begin(true);
    for (int i = 0; i < 3; i++) {
        uuid_t task;
        uuid_generate(task);
        reputation_install_tx_pair_in(g_cohort, task, me->uuid, 0.9,
                                      ally->uuid, 0.9);
    }
    reputation_install_peer_reputation(ally->uuid, 0.9);
    reputation_install_coop_mode(ally->uuid, true);
    reputation_note_interaction(ally->uuid);
    g_present += 1000.0;
    (void)reputation_rescore_sweep(g_proc, g_present, me->uuid);
    double v = 0.0;
    ck_assert_ret_ok(reputation_get_brought(ally->uuid, &v));
    ck_assert_double_eq_tol(v, 0.9, 1e-3);
    ck_assert_ret_ok(reputation_get_bounded(ally->uuid, &v));
    ck_assert_double_eq_tol(v, 0.9, 1e-3);
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(RepCohort,
          test_a_half_about_a_member_goes_to_the_members_only,
          test_a_half_about_a_non_member_goes_to_everyone_on_the_primary,
          test_without_the_policy_nothing_routes_to_the_cohort,
          test_an_acceptor_checks_the_cohort_and_unknown_groups,
          test_without_the_policy_an_unknown_group_is_accepted_as_before,
          test_the_scorers_read_the_cohort_chain)
