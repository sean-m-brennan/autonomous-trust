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

/** @file Entering the cooperation regime: own evidence wins
 *  (reputation_coop_regime).
 *
 *  Hostile-join runs without the policy, 2026-11-04: contrite tit-for-tat
 *  over a joiner's own transactions scored its contact 0.84, above
 *  COOP_ENTER, so the next rescore took the cooperation mean over everyone's
 *  entries; the cohort's slander made that 0.34, below COOP_EXIT, so the
 *  rescore after went back, and the tier flipped every minute. A peer now
 *  enters cooperation only if the cooperation score would itself be at or
 *  above COOP_EXIT, and leaves it in the same rescore that score falls
 *  below. The same rule holds for the brought score. The Python
 *  twin is tests/a_unit/test_coop_entry.py.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#include <jansson.h>
#include <uuid/uuid.h>

#include "identity/identity.h"
#include "identity/join_policy.h"
#include "reputation/reputation.h"
#include "reputation/rep_proc_priv.h"
#include "structures/data.h"
#include "structures/map.h"
#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
#include "utilities/msg_types_priv.h"
#include "utilities/allocation.h"

#define TIER1_CAP 0.65

static identity_t *_mk_identity(const char *addr, const char *name)
{
    uuid_t uuid;
    uuid_generate(uuid);
    identity_t *ident = NULL;
    ck_assert_ret_ok(identity_create(&uuid, addr, name, name, &ident));
    ck_assert_ptr_nonnull(ident);
    return ident;
}

/* Self, with @p peer admitted. */
static process_t *_mk_process(identity_t *self, identity_t *peer)
{
    process_t *proc = smrt_create(sizeof(process_t));
    ck_assert_ptr_nonnull(proc);
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    strncpy(proc->name, "reputation", PROC_NAME_LEN);
    proc->protocol.phase = 1;
    config_t *id_cfg = calloc(1, sizeof(config_t));
    ck_assert_ptr_nonnull(id_cfg);
    id_cfg->name = "identity";
    id_cfg->data_struct = self;
    ck_assert_ret_ok(map_create(&proc->configs));
    map_set(proc->configs, (map_key_t)"identity",
            object_ptr_data((ptr_t)id_cfg, sizeof(config_t)));
    ck_assert_ret_ok(map_create(&proc->protocol.handlers));
    ck_assert_ret_ok(reputation_register_handlers(proc));
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(peer, &pub));
    memcpy(&proc->protocol.peers[0], pub, sizeof(public_identity_t));
    smrt_deref(pub);
    proc->protocol.num_peers = 1;
    return proc;
}

static int g_last_tier;
static int g_excluded;   /* +1 exclude sent, -1 readmit sent, 0 none */
/* The join burst's counts sent to negotiation (Phase 5), and whether the hook
 * refuses them as a full queue would. */
static peer_probe_count_msg_t g_counts[8];
static int g_n_counts;
static bool g_refuse_counts;

static int _hook(const char *key, const message_type_t type,
                 generic_msg_t *msg, bool blocking)
{
    (void)blocking;
    if (type == PEER_PROBE_COUNT) {
        ck_assert_str_eq(key, "negotiation");
        if (g_refuse_counts)
            return EAGAIN;
        if (g_n_counts < 8)
            g_counts[g_n_counts++] = msg->info.peer_probe_count;
        return 0;
    }
    if (type != NET_MESSAGE || key == NULL || msg->info.net_msg.function == NULL)
        return 0;
    const char *fn = msg->info.net_msg.function;
    if (strcmp(key, "identity") == 0 && strcmp(fn, "tier_update") == 0) {
        json_t *arr = NULL;
        if (net_msg_unpack_json(&msg->info.net_msg, &arr) == 0 && arr != NULL) {
            g_last_tier = (int)json_integer_value(json_array_get(arr, 1));
            json_decref(arr);
        }
    }
    if (strcmp(key, "network") == 0 && strcmp(fn, "exclude") == 0)
        g_excluded = 1;
    if (strcmp(key, "network") == 0 && strcmp(fn, "readmit") == 0)
        g_excluded = -1;
    return 0;
}

static char g_root[64];
static identity_t *me, *them, *other;
static double g_present;

/* Self and one peer, a fresh root, and the join policy @p on (default bounds)
 * or off. */
static process_t *_begin(bool on)
{
    snprintf(g_root, sizeof(g_root), "/tmp/at-coop-XXXXXX");
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
    me = _mk_identity("10.0.0.1", "self");
    them = _mk_identity("10.0.0.2", "peer");
    other = _mk_identity("10.0.0.3", "other");
    process_t *proc = _mk_process(me, them);
    reputation_install_peer_reputation(other->uuid, 0.5);
    g_last_tier = -1;
    g_excluded = 0;
    g_n_counts = 0;
    g_refuse_counts = false;
    g_present = (double)time(NULL);
    messaging_set_test_hook(_hook);
    return proc;
}

/* @p n entries in which we gave the peer @p ours (and it gave us 0.9). */
static void _own(int n, double ours, const char *channel)
{
    for (int i = 0; i < n; i++) {
        uuid_t task;
        uuid_generate(task);
        reputation_install_tx_pair_tagged(task, me->uuid, tx_score_to_milli(ours), channel,
                                          them->uuid, 900, NULL);
    }
}

/* @p n entries in which a third party gave the peer @p told. */
static void _told(int n, double told)
{
    for (int i = 0; i < n; i++) {
        uuid_t task;
        uuid_generate(task);
        reputation_install_tx_pair(task, other->uuid, tx_score_to_milli(told), them->uuid, 900);
    }
}

/* Score the peer from a staged told @p told (<0: none) in cooperation mode. */
static void _sweep(process_t *proc, double told)
{
    if (told >= 0.0) {
        reputation_install_peer_reputation(them->uuid, told);
        reputation_install_coop_mode(them->uuid, true);
    }
    reputation_note_interaction(them->uuid);   /* due, as a commit makes it */
    g_present += 1000.0;            /* past the rescore throttle */
    (void)reputation_rescore_sweep(proc, g_present, me->uuid);
}

static void _end(void)
{
    messaging_set_test_hook(NULL);
    reputation_reset_state(2);
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", g_root);
#ifndef _WIN32   /* cleanup only; Windows' system() shell has no rm */
    ck_assert_int_eq(system(cmd), 0);
#endif
}

#define CTFT_10 ((10 * 0.9 + 3 * PREREP_NEUTRAL) / 13)

DEFINE_TEST(test_coop_the_rule)
{
    /* In cooperation: stay while previous > COOP_EXIT and the mean holds at
     * or above it. */
    ck_assert(reputation_coop_regime(true, 0.5, COOP_EXIT));
    ck_assert(!reputation_coop_regime(true, 0.5, 0.1));
    ck_assert(!reputation_coop_regime(true, 0.4, 0.9));
    /* Out of it: enter past COOP_ENTER only on a mean at or above the exit. */
    ck_assert(!reputation_coop_regime(false, 0.84, 0.34));
    ck_assert(reputation_coop_regime(false, 0.84, COOP_EXIT));
    ck_assert(!reputation_coop_regime(false, COOP_ENTER, 0.9));
}
END_TEST_DEFINITION()

static double _told_of(void)
{
    double v = 0.0;
    ck_assert_ret_ok(reputation_get_peer_reputation(them->uuid, &v));
    return v;
}

DEFINE_TEST(test_coop_a_slandered_mean_does_not_pull_a_peer_in)
{
    process_t *proc = _begin(false);
    _own(10, 0.9, NULL);
    _told(30, 0.1);
    for (int i = 0; i < 5; i++) {
        _sweep(proc, -1.0);
        ck_assert_double_eq_tol(_told_of(), CTFT_10, 1e-6);
    }
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_coop_a_mean_that_holds_enters)
{
    process_t *proc = _begin(false);
    _own(10, 0.9, NULL);
    _told(30, 0.9);
    _sweep(proc, -1.0);
    _sweep(proc, -1.0);
    ck_assert_double_eq_tol(_told_of(), 0.9, 1e-6);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_coop_a_peer_whose_mean_falls_leaves_at_once)
{
    process_t *proc = _begin(false);
    _own(10, 0.9, NULL);
    _told(30, 0.1);
    /* In cooperation at 0.8. The hostile-join runs of 2026-11-05 scored the
     * contact once on the slandered mean on the way out, and lost its tier
     * for a minute. */
    _sweep(proc, 0.8);
    ck_assert_double_eq_tol(_told_of(), CTFT_10, 1e-6);
    for (int i = 0; i < 4; i++) {
        _sweep(proc, -1.0);
        ck_assert_double_eq_tol(_told_of(), CTFT_10, 1e-6);
    }
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_coop_a_peer_whose_mean_holds_stays_in)
{
    process_t *proc = _begin(false);
    _own(10, 0.9, NULL);
    _told(30, 0.9);
    _sweep(proc, 0.8);                  /* in cooperation at 0.8 */
    for (int i = 0; i < 3; i++) {
        ck_assert_double_eq_tol(_told_of(), 0.9, 1e-6);
        _sweep(proc, -1.0);
    }
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_coop_the_brought_score_follows_the_same_rule)
{
    process_t *proc = _begin(true);
    _own(10, 0.9, NULL);
    /* Two heavy entries we scored low: the task-weighted mean of our scores
     * falls below the exit while contrite tit-for-tat stays above entry. */
    for (int i = 0; i < 2; i++) {
        uuid_t task;
        uuid_generate(task);
        reputation_install_tx_pair(task, me->uuid, 100, them->uuid, 900);
        reputation_install_task_weight(task, 100);
    }
    double ctft = (10 * 0.9 + 2 * 0.1 + 3 * PREREP_NEUTRAL) / 15;
    ck_assert(ctft > COOP_ENTER);
    for (int i = 0; i < 5; i++) {
        _sweep(proc, -1.0);
        double v = 0.0;
        ck_assert_ret_ok(reputation_get_brought(them->uuid, &v));
        ck_assert_double_eq_tol(v, ctft, 1e-6);
    }
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(RepCoopEntry,
          test_coop_the_rule,
          test_coop_a_slandered_mean_does_not_pull_a_peer_in,
          test_coop_a_mean_that_holds_enters,
          test_coop_a_peer_whose_mean_falls_leaves_at_once,
          test_coop_a_peer_whose_mean_holds_stays_in,
          test_coop_the_brought_score_follows_the_same_rule)
