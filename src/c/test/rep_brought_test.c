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

/** @file Brought and told scores (RD_14.4_HOSTILE_JOIN_PLAN.md Phase 4,
 *  D3 (b)): under an enabled join policy a node keeps, beside the told score,
 *  a brought score from its own evidence alone. Decisions read bounded
 *  (brought once the peer has own_evidence_min own entries, else told capped
 *  at told_tier; an anchored peer reads told), exclusion reads brought +
 *  slash, and with the policy off nothing changes. Assertions are on the tier
 *  the sweep PUBLISHES and on the scores reputation holds. The Python twin is
 *  tests/a_unit/test_brought_told.py.
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
    snprintf(g_root, sizeof(g_root), "/tmp/at-brought-XXXXXX");
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

DEFINE_TEST(test_told_only_is_held_at_tier_one)
{
    process_t *proc = _begin(true);
    _told(3, 0.95);
    _sweep(proc, 0.95);
    double v = 0.0;
    ck_assert_ret_ok(reputation_get_peer_reputation(them->uuid, &v));
    ck_assert_double_eq_tol(v, 0.95, 1e-3);
    ck_assert_int_eq(reputation_get_brought(them->uuid, &v), -1);
    ck_assert_ret_ok(reputation_get_bounded(them->uuid, &v));
    ck_assert_double_eq_tol(v, TIER1_CAP, 1e-3);
    ck_assert_int_eq(g_last_tier, 1);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_policy_off_reads_told)
{
    process_t *proc = _begin(false);
    _told(3, 0.95);
    _own(3, 0.9, NULL);
    _sweep(proc, 0.95);
    double v = 0.0;
    ck_assert_int_eq(reputation_get_brought(them->uuid, &v), -1);
    ck_assert_int_eq(g_last_tier, 4);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_own_evidence_min_lifts_the_bound)
{
    process_t *proc = _begin(true);
    _own(3, 0.9, NULL);
    _told(3, 0.3);
    _sweep(proc, 0.9);
    double v = 0.0;
    ck_assert_ret_ok(reputation_get_brought(them->uuid, &v));
    ck_assert_double_eq_tol(v, 0.9, 1e-3);
    ck_assert_ret_ok(reputation_get_bounded(them->uuid, &v));
    ck_assert_double_eq_tol(v, 0.9, 1e-3);
    ck_assert_int_eq(g_last_tier, 4);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_short_of_own_evidence_min_stays_capped)
{
    process_t *proc = _begin(true);
    _own(2, 0.9, NULL);
    _sweep(proc, 0.9);
    double v = 0.0;
    ck_assert_ret_ok(reputation_get_brought(them->uuid, &v));
    ck_assert_double_eq_tol(v, 0.9, 1e-3);
    ck_assert_int_eq(g_last_tier, 1);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_anchored_peer_reads_told)
{
    process_t *proc = _begin(true);
    _told(3, 0.95);
    reputation_set_anchored(them->uuid, true);
    _sweep(proc, 0.95);
    ck_assert_int_eq(g_last_tier, 4);
    /* Withdrawn: due again, and capped at the next sweep. */
    reputation_set_anchored(them->uuid, false);
    _sweep(proc, -1.0);
    ck_assert_int_eq(g_last_tier, 1);
    _end();
}
END_TEST_DEFINITION()

/* Phase 5 (the user's call, 2026-10-27): a probe verdict is own evidence
 * under the policy, toward own_evidence_min and into brought with its score. */
DEFINE_TEST(test_a_probe_verdict_is_own_evidence)
{
    process_t *proc = _begin(true);
    _own(3, 0.9, TX_CHANNEL_PROBE);
    _told(3, 0.3);
    _sweep(proc, 0.3);
    double v = 0.0;
    ck_assert_ret_ok(reputation_get_brought(them->uuid, &v));
    ck_assert_double_eq_tol(v, 0.9, 1e-3);
    ck_assert_ret_ok(reputation_get_bounded(them->uuid, &v));
    ck_assert_double_eq_tol(v, 0.9, 1e-3);
    ck_assert_int_eq(g_last_tier, 4);
    _end();
}
END_TEST_DEFINITION()

/* --- The join burst's counts (Phase 5) ------------------------------------ */

/* One publisher pass past the throttle; the counts it sent. */
static int _publish(process_t *proc)
{
    g_n_counts = 0;
    g_present += 10.0;
    reputation_publish_probe_counts(proc, g_present);
    return g_n_counts;
}

static void _note(void)
{
    reputation_note_interaction(them->uuid);
}

DEFINE_TEST(test_the_burst_count_is_probe_verdicts_while_bounded)
{
    process_t *proc = _begin(true);
    _sweep(proc, -1.0);             /* resolves self, as the loop does first */
    int n = -1;
    ck_assert(reputation_burst_count(them->uuid, &n));
    ck_assert_int_eq(n, 0);
    _own(1, 0.9, TX_CHANNEL_PROBE);
    _own(1, 0.9, NULL);
    ck_assert(reputation_burst_count(them->uuid, &n));
    ck_assert_int_eq(n, 1);
    _own(1, 0.9, TX_CHANNEL_PROBE);
    ck_assert(!reputation_burst_count(them->uuid, &n));   /* graduated */
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_counts_publish_on_change_only)
{
    process_t *proc = _begin(true);
    _sweep(proc, -1.0);
    ck_assert_int_eq(_publish(proc), 1);
    ck_assert(uuid_compare(g_counts[0].peer_uuid, them->uuid) == 0);
    ck_assert(g_counts[0].bounded);
    ck_assert_int_eq(g_counts[0].verdicts, 0);
    ck_assert_int_eq(_publish(proc), 0);
    _own(1, 0.9, TX_CHANNEL_PROBE);
    _note();
    ck_assert_int_eq(_publish(proc), 1);
    ck_assert_int_eq(g_counts[0].verdicts, 1);
    _own(2, 0.9, TX_CHANNEL_PROBE);
    _note();
    ck_assert_int_eq(_publish(proc), 1);
    ck_assert(!g_counts[0].bounded);                     /* graduated */
    ck_assert_int_eq(_publish(proc), 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_anchored_peer_or_one_off_the_roster_leaves)
{
    process_t *proc = _begin(true);
    ck_assert_int_eq(_publish(proc), 1);
    reputation_set_anchored(them->uuid, true);
    ck_assert_int_eq(_publish(proc), 1);
    ck_assert(!g_counts[0].bounded);
    reputation_set_anchored(them->uuid, false);
    ck_assert_int_eq(_publish(proc), 1);
    ck_assert(g_counts[0].bounded);
    proc->protocol.num_peers = 0;
    ck_assert_int_eq(_publish(proc), 1);
    ck_assert(!g_counts[0].bounded);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_refused_count_is_resent_and_the_pass_throttled)
{
    process_t *proc = _begin(true);
    g_refuse_counts = true;
    ck_assert_int_eq(_publish(proc), 0);
    g_refuse_counts = false;
    g_n_counts = 0;
    reputation_publish_probe_counts(proc, g_present + 0.5);   /* throttled */
    ck_assert_int_eq(g_n_counts, 0);
    ck_assert_int_eq(_publish(proc), 1);
    ck_assert(g_counts[0].bounded);
    /* A refused departure is resent too. */
    reputation_set_anchored(them->uuid, true);
    g_refuse_counts = true;
    ck_assert_int_eq(_publish(proc), 0);
    g_refuse_counts = false;
    ck_assert_int_eq(_publish(proc), 1);
    ck_assert(!g_counts[0].bounded);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_no_counts_without_the_policy)
{
    process_t *proc = _begin(false);
    ck_assert_int_eq(_publish(proc), 0);
    int n = 0;
    ck_assert(!reputation_burst_count(them->uuid, &n));
    _end();
}
END_TEST_DEFINITION()

/* The peer rating us 1.0 does not raise its brought score: our 0.3 counts. */
DEFINE_TEST(test_brought_reads_our_scores_not_the_peers)
{
    process_t *proc = _begin(true);
    for (int i = 0; i < 3; i++) {
        uuid_t task;
        uuid_generate(task);
        reputation_install_tx_pair(task, me->uuid, 300, them->uuid, 1000);
    }
    _sweep(proc, -1.0);
    double v = 0.0;
    ck_assert_ret_ok(reputation_get_brought(them->uuid, &v));
    ck_assert_double_eq_tol(v, 0.3, 1e-3);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_told_alone_never_excludes)
{
    process_t *proc = _begin(true);
    _told(3, 0.0);
    _sweep(proc, 0.95);
    double v = 1.0;
    ck_assert_ret_ok(reputation_get_peer_reputation(them->uuid, &v));
    ck_assert(v < 0.1);
    ck_assert_int_eq(g_excluded, 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_told_excludes_with_the_policy_off)
{
    process_t *proc = _begin(false);
    _told(3, 0.0);
    _sweep(proc, 0.95);
    ck_assert_int_eq(g_excluded, 1);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_brought_below_the_cutoff_excludes)
{
    process_t *proc = _begin(true);
    _own(3, 0.0, NULL);
    _sweep(proc, -1.0);
    ck_assert_int_eq(g_excluded, 1);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_prior_skips_told_entries)
{
    process_t *proc = _begin(true);
    _told(3, 0.9);
    int64_t idx[3] = {0, 1, 2};
    reputation_install_catchup_told(idx, 3);
    _sweep(proc, -1.0);
    double v = 0.0;
    ck_assert_ret_ok(reputation_get_peer_reputation(them->uuid, &v));
    ck_assert_double_eq_tol(v, PREREP_NEUTRAL, 1e-6);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_seed_replaces_a_told_only_score)
{
    process_t *proc = _begin(true);
    reputation_install_peer_reputation(them->uuid, 0.4);
    reputation_offer_seed(proc, "test", them->uuid, 0.3, "contact");
    double v = 0.0;
    ck_assert_ret_ok(reputation_get_peer_reputation(them->uuid, &v));
    ck_assert_double_eq_tol(v, 0.3, 1e-3);
    ck_assert_ret_ok(reputation_get_brought(them->uuid, &v));
    ck_assert_double_eq_tol(v, 0.3, 1e-3);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_seed_never_overrides_an_earned_score)
{
    process_t *proc = _begin(true);
    _own(1, 0.4, NULL);
    reputation_install_peer_reputation(them->uuid, 0.4);
    reputation_offer_seed(proc, "test", them->uuid, 0.3, "contact");
    double v = 0.0;
    ck_assert_ret_ok(reputation_get_peer_reputation(them->uuid, &v));
    ck_assert_double_eq_tol(v, 0.4, 1e-3);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_without_the_policy_a_held_score_blocks_the_seed)
{
    process_t *proc = _begin(false);
    reputation_install_peer_reputation(them->uuid, 0.4);
    reputation_offer_seed(proc, "test", them->uuid, 0.3, "contact");
    double v = 0.0;
    ck_assert_ret_ok(reputation_get_peer_reputation(them->uuid, &v));
    ck_assert_double_eq_tol(v, 0.4, 1e-3);
    ck_assert_int_eq(reputation_get_brought(them->uuid, &v), -1);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_peer_anchor_names_its_type)
{
    ck_assert_str_eq(message_type_to_string(PEER_ANCHOR), "PEER_ANCHOR");
    ck_assert_int_eq(message_type_core_by_name("PEER_ANCHOR"), PEER_ANCHOR);
    ck_assert_int_eq((int)message_size(PEER_ANCHOR), (int)sizeof(peer_anchor_msg_t));
    ck_assert_str_eq(message_type_to_string(PEER_PROBE_COUNT), "PEER_PROBE_COUNT");
    ck_assert_int_eq(message_type_core_by_name("PEER_PROBE_COUNT"), PEER_PROBE_COUNT);
    ck_assert_int_eq((int)message_size(PEER_PROBE_COUNT),
                     (int)sizeof(peer_probe_count_msg_t));
}
END_TEST_DEFINITION()

RUN_TESTS(RepBrought,
          test_told_only_is_held_at_tier_one,
          test_the_policy_off_reads_told,
          test_own_evidence_min_lifts_the_bound,
          test_short_of_own_evidence_min_stays_capped,
          test_an_anchored_peer_reads_told,
          test_a_probe_verdict_is_own_evidence,
          test_the_burst_count_is_probe_verdicts_while_bounded,
          test_counts_publish_on_change_only,
          test_an_anchored_peer_or_one_off_the_roster_leaves,
          test_a_refused_count_is_resent_and_the_pass_throttled,
          test_no_counts_without_the_policy,
          test_brought_reads_our_scores_not_the_peers,
          test_told_alone_never_excludes,
          test_told_excludes_with_the_policy_off,
          test_brought_below_the_cutoff_excludes,
          test_the_prior_skips_told_entries,
          test_a_seed_replaces_a_told_only_score,
          test_a_seed_never_overrides_an_earned_score,
          test_without_the_policy_a_held_score_blocks_the_seed,
          test_peer_anchor_names_its_type)
