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

/** @file Lone probe verdicts: a verdict from one of this node's own probes
 *  counts as its own evidence as soon as it is recorded, without the probed
 *  peer's half (the user's call, 2026-11-06). The hostile-join runs of
 *  2026-11-05 counted it only once the bilateral entry committed; at 18 nodes
 *  the colluders sat at the probe cap and dropped 90 halves, and a peer that
 *  never writes its half was never graded. Under the join policy only; never
 *  told; persisted. The Python twin is tests/a_unit/test_lone_verdicts.py.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <string.h>
#include <stdio.h>
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
/* The last PEER_PROBE_COUNT sent: how many, and its suspect flag. */
static int g_counts_sent;
static bool g_last_suspect;

static int _hook(const char *key, const message_type_t type,
                 generic_msg_t *msg, bool blocking)
{
    (void)blocking;
    if (type == PEER_PROBE_COUNT) {
        g_counts_sent++;
        g_last_suspect = msg->info.peer_probe_count.suspect;
        return 0;
    }
    if (type != NET_MESSAGE || key == NULL || msg->info.net_msg.function == NULL)
        return 0;
    if (strcmp(key, "identity") == 0
        && strcmp(msg->info.net_msg.function, "tier_update") == 0) {
        json_t *arr = NULL;
        if (net_msg_unpack_json(&msg->info.net_msg, &arr) == 0 && arr != NULL) {
            g_last_tier = (int)json_integer_value(json_array_get(arr, 1));
            json_decref(arr);
        }
    }
    return 0;
}

static char g_root[64];
static identity_t *me, *them, *other;
static double g_present;

static process_t *_begin(bool on)
{
    snprintf(g_root, sizeof(g_root), "/tmp/at-lone-XXXXXX");
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
    g_counts_sent = 0;
    g_last_suspect = false;
    g_present = (double)time(NULL);
    messaging_set_test_hook(_hook);
    return proc;
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

/* Our score of @p subject through the local entry point; the task into
 * @p task when given. */
static void _score(process_t *proc, const uuid_t subject, double score,
                   const char *cap, const char *channel, uuid_t task)
{
    generic_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    tx_score_msg_t *ts = &msg.info.tx_score;
    uuid_generate(ts->task_uuid);
    uuid_copy(ts->peer_uuid, subject);
    ts->score = score;
    snprintf(ts->capability_name, sizeof(ts->capability_name), "%s", cap);
    if (channel != NULL)
        snprintf(ts->channel, sizeof(ts->channel), "%s", channel);
    if (task != NULL)
        uuid_copy(task, ts->task_uuid);
    reputation_handle_local_tx_score(proc, &msg, me->uuid);
}

static void _probe(process_t *proc, double score, uuid_t task)
{
    _score(proc, them->uuid, score, "at.handshake", TX_CHANNEL_PROBE, task);
}

static void _sweep(process_t *proc)
{
    g_present += 1000.0;            /* past the rescore throttle */
    (void)reputation_rescore_sweep(proc, g_present, me->uuid);
}

DEFINE_TEST(test_a_verdict_is_kept_even_when_the_cap_drops_its_half)
{
    process_t *proc = _begin(true);
    for (int i = 0; i < 6; i++)
        _probe(proc, 0.1, NULL);
    ck_assert_int_eq((int)reputation_awaiting_commit_count(), 4);
    ck_assert_int_eq(reputation_lone_verdict_count(them->uuid), 6);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_app_score_and_a_targets_half_are_not_verdicts)
{
    process_t *proc = _begin(true);
    _score(proc, them->uuid, 0.9, "agora-post", NULL, NULL);
    /* The probed peer's own half: an at. capability on task_outcome. */
    _score(proc, them->uuid, 0.9, "at.handshake", NULL, NULL);
    ck_assert_int_eq(reputation_lone_verdict_count(NULL), 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_under_the_policy_lone_verdicts_are_own_evidence_everywhere)
{
    process_t *proc = _begin(true);
    _sweep(proc);                   /* resolves self, as the loop does first */
    for (int i = 0; i < 3; i++)
        _probe(proc, 0.1, NULL);
    ck_assert_int_eq(reputation_own_count(them->uuid), 3);
    /* Three 0.1s shrunk toward neutral, (0.3 + 3 * 0.2) / 6. */
    ck_assert_double_eq_tol(reputation_told_ctft(me->uuid, them->uuid), 0.15,
                            1e-9);
    _sweep(proc);
    double v = 0.0;
    ck_assert_ret_ok(reputation_get_brought(them->uuid, &v));
    ck_assert_double_eq_tol(v, 0.15, 1e-9);
    ck_assert_int_eq(g_last_tier, 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_burst_count_reads_lone_verdicts)
{
    process_t *proc = _begin(true);
    _sweep(proc);                   /* resolves self, as the loop does first */
    int n = -1;
    _probe(proc, 0.9, NULL);
    ck_assert(reputation_burst_count(them->uuid, &n));
    ck_assert_int_eq(n, 1);
    _probe(proc, 0.9, NULL);
    _probe(proc, 0.9, NULL);
    ck_assert(!reputation_burst_count(them->uuid, &n));   /* graduated */
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_without_the_policy_lone_verdicts_count_nowhere)
{
    process_t *proc = _begin(false);
    double prior = reputation_told_ctft(me->uuid, them->uuid);
    for (int i = 0; i < 3; i++)
        _probe(proc, 0.1, NULL);
    ck_assert_int_eq(reputation_own_count(them->uuid), 0);
    ck_assert_double_eq_tol(reputation_told_ctft(me->uuid, them->uuid), prior,
                            1e-12);
    _end();
}
END_TEST_DEFINITION()

/* No peer score of us stands behind a lone verdict, so two of them do not
 * trigger the 0.49 hold. */
DEFINE_TEST(test_a_lone_verdict_is_never_a_defection)
{
    process_t *proc = _begin(true);
    for (int i = 0; i < 10; i++)
        _probe(proc, 0.9, NULL);
    ck_assert_double_eq_tol(reputation_told_ctft(me->uuid, them->uuid),
                            (9.0 + 3 * 0.2) / 13, 1e-9);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_bilateral_entry_supersedes_its_lone_verdict)
{
    process_t *proc = _begin(true);
    _sweep(proc);                   /* resolves self, as the loop does first */
    uuid_t task;
    _probe(proc, 0.1, task);
    reputation_install_tx_pair_tagged(task, me->uuid, 100, TX_CHANNEL_PROBE,
                                      them->uuid, 900, NULL);
    ck_assert_int_eq(reputation_own_count(them->uuid), 1);
    ck_assert_double_eq_tol(reputation_told_ctft(me->uuid, them->uuid),
                            (0.1 + 0.6) / 4, 1e-9);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_store_bounds_oldest_out)
{
    process_t *proc = _begin(true);
    for (int i = 0; i < REP_RETAINED_PER_PEER + 1; i++)
        _probe(proc, 0.5, NULL);
    ck_assert_int_eq(reputation_lone_verdict_count(them->uuid),
                     REP_RETAINED_PER_PEER);
    /* The total bound: REP_RETAINED_MAX across subjects. */
    int subjects = REP_RETAINED_MAX / REP_RETAINED_PER_PEER + 1;
    for (int s = 0; s < subjects; s++) {
        uuid_t subject;
        uuid_generate(subject);
        for (int i = 0; i < REP_RETAINED_PER_PEER; i++)
            _score(proc, subject, 0.5, "at.handshake", TX_CHANNEL_PROBE, NULL);
    }
    ck_assert_int_eq(reputation_lone_verdict_count(NULL), REP_RETAINED_MAX);
    ck_assert_int_eq(reputation_lone_verdict_count(them->uuid), 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_store_survives_a_restart)
{
    process_t *proc = _begin(true);
    uuid_t placed;
    _probe(proc, 0.1, placed);
    for (int i = 0; i < 3; i++)
        _probe(proc, 0.1, NULL);
    reputation_install_tx_pair_tagged(placed, me->uuid, 100, TX_CHANNEL_PROBE,
                                      them->uuid, 900, NULL);
    reputation_persist_lone_verdicts(proc);
    /* The superseded one is dropped at the write. */
    ck_assert_int_eq(reputation_lone_verdict_count(them->uuid), 3);
    char path[256];
    snprintf(path, sizeof(path), "%s/etc/at/%s.cfg.json", g_root,
             REP_LONE_VERDICTS_FILE);
    json_error_t jerr;
    json_t *doc = json_load_file(path, 0, &jerr);
    ck_assert_ptr_nonnull(doc);
    ck_assert_int_eq((int)json_array_size(json_object_get(doc, "entries")), 3);
    json_decref(doc);
    reputation_reset_state(2);
    ck_assert_int_eq(reputation_lone_verdict_count(NULL), 0);
    reputation_load_lone_verdicts(proc);
    ck_assert_int_eq(reputation_lone_verdict_count(them->uuid), 3);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_unreadable_file_leaves_the_store_empty)
{
    process_t *proc = _begin(true);
    char path[256];
    snprintf(path, sizeof(path), "%s/etc/at/%s.cfg.json", g_root,
             REP_LONE_VERDICTS_FILE);
    FILE *f = fopen(path, "w");
    ck_assert_ptr_nonnull(f);
    fputs("{\"schema\": \"9\", \"entries\": []}", f);
    fclose(f);
    reputation_load_lone_verdicts(proc);
    ck_assert_int_eq(reputation_lone_verdict_count(NULL), 0);
    _end();
}
END_TEST_DEFINITION()

/* The live shape: three failed probes, no half from the peer and no chain
 * entry of ours; its told standing among the cohort is high. */
DEFINE_TEST(test_a_colluder_that_never_writes_its_half_sinks_on_our_verdicts)
{
    process_t *proc = _begin(true);
    for (int i = 0; i < 5; i++) {
        uuid_t task;
        uuid_generate(task);
        reputation_install_tx_pair(task, other->uuid, 950, them->uuid, 950);
    }
    for (int i = 0; i < 3; i++)
        _probe(proc, 0.0, NULL);
    _sweep(proc);
    double v = 0.0;
    ck_assert_ret_ok(reputation_get_bounded(them->uuid, &v));
    ck_assert(v < 0.5);
    ck_assert_int_eq(g_last_tier, 0);
    _end();
}
END_TEST_DEFINITION()

/* --- Two failed probes in a row hold the brought score --------------------
 * A gamer that answered rightly for eight minutes and wrongly after kept tier
 * 2..3 for twelve minutes on every honest node (red-team batch, 2026-11-10):
 * a lone verdict is never a defection, and its record outweighed the
 * failures. The latest two of our probe verdicts, both below 0.5, now hold
 * the brought score at 0.49 in either regime; one failure makes the peer a
 * suspect the worker probes again at once. Mirrors
 * tests/a_unit/test_probe_failure_hold.py. */

static void _trusted(process_t *proc)
{
    _sweep(proc);                   /* resolves self, as the loop does first */
    for (int i = 0; i < 20; i++)
        _probe(proc, 0.9, NULL);
    _sweep(proc);
    double v = 0.0;
    ck_assert_ret_ok(reputation_get_brought(them->uuid, &v));
    ck_assert(v > 0.8);
}

static double _brought_now(process_t *proc)
{
    _sweep(proc);
    double v = 0.0;
    ck_assert_ret_ok(reputation_get_brought(them->uuid, &v));
    return v;
}

DEFINE_TEST(test_two_failed_probes_hold_a_trusted_peer_below_tier_1)
{
    process_t *proc = _begin(true);
    _trusted(proc);
    _probe(proc, 0.1, NULL);
    _probe(proc, 0.1, NULL);
    ck_assert_double_eq_tol(_brought_now(proc), 0.49, 1e-9);
    ck_assert_int_eq(g_last_tier, 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_one_failed_probe_is_forgiven_and_a_pass_breaks_the_run)
{
    process_t *proc = _begin(true);
    _trusted(proc);
    _probe(proc, 0.1, NULL);
    ck_assert(_brought_now(proc) > 0.5);
    _probe(proc, 0.9, NULL);
    _probe(proc, 0.1, NULL);
    ck_assert(_brought_now(proc) > 0.5);
    _end();
}
END_TEST_DEFINITION()

/* A wrong time attestation scores 0.5, the same as drift: a re-probe that
 * lands on one says nothing either way (red-team rerun, 2026-11-10: 25 of 36
 * honest nodes kept a defected gamer at tier 3 this way). */
DEFINE_TEST(test_drift_neither_counts_nor_breaks_the_run)
{
    process_t *proc = _begin(true);
    _trusted(proc);
    _probe(proc, 0.1, NULL);
    _probe(proc, 0.5, NULL);
    ck_assert(reputation_is_suspect(them->uuid));
    _probe(proc, 0.1, NULL);
    ck_assert_double_eq_tol(_brought_now(proc), 0.49, 1e-9);
    _end();
}
END_TEST_DEFINITION()

/* A 0.5 is inconclusive: the worker asks again, and a probe with a right or
 * wrong answer settles it (red-team rerun, 2026-11-10: 16 of 36 honest nodes
 * met a defected gamer only through time attestations). A held peer is no
 * suspect, drift or not. */
DEFINE_TEST(test_drift_makes_a_suspect_until_a_clear_answer)
{
    process_t *proc = _begin(true);
    _trusted(proc);
    _probe(proc, 0.5, NULL);
    ck_assert(reputation_is_suspect(them->uuid));
    _probe(proc, 0.9, NULL);
    ck_assert(!reputation_is_suspect(them->uuid));
    ck_assert(_brought_now(proc) > 0.5);
    _probe(proc, 0.1, NULL);
    _probe(proc, 0.1, NULL);
    _probe(proc, 0.5, NULL);
    ck_assert(!reputation_is_suspect(them->uuid));
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_one_failed_probe_makes_a_suspect_and_the_hold_ends_it)
{
    process_t *proc = _begin(true);
    _trusted(proc);
    ck_assert(!reputation_is_suspect(them->uuid));
    _probe(proc, 0.1, NULL);
    ck_assert(reputation_is_suspect(them->uuid));
    _probe(proc, 0.1, NULL);
    ck_assert(!reputation_is_suspect(them->uuid));
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_repeated_task_counts_once)
{
    process_t *proc = _begin(true);
    _sweep(proc);
    uuid_t task;
    _probe(proc, 0.1, task);
    generic_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    tx_score_msg_t *ts = &msg.info.tx_score;
    uuid_copy(ts->task_uuid, task);
    uuid_copy(ts->peer_uuid, them->uuid);
    ts->score = 0.1;
    snprintf(ts->capability_name, sizeof(ts->capability_name), "at.handshake");
    snprintf(ts->channel, sizeof(ts->channel), "%s", TX_CHANNEL_PROBE);
    reputation_handle_local_tx_score(proc, &msg, me->uuid);
    ck_assert(reputation_is_suspect(them->uuid));   /* one failure, not two */
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_worker_is_told_the_suspect)
{
    process_t *proc = _begin(true);
    _trusted(proc);
    reputation_publish_probe_counts(proc, g_present);
    int before = g_counts_sent;
    _probe(proc, 0.1, NULL);
    g_present += 10.0;
    reputation_publish_probe_counts(proc, g_present);
    ck_assert_int_eq(g_counts_sent, before + 1);
    ck_assert(g_last_suspect);
    _probe(proc, 0.9, NULL);
    g_present += 10.0;
    reputation_publish_probe_counts(proc, g_present);
    ck_assert_int_eq(g_counts_sent, before + 2);
    ck_assert(!g_last_suspect);
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(RepLoneVerdict,
          test_two_failed_probes_hold_a_trusted_peer_below_tier_1,
          test_one_failed_probe_is_forgiven_and_a_pass_breaks_the_run,
          test_drift_neither_counts_nor_breaks_the_run,
          test_drift_makes_a_suspect_until_a_clear_answer,
          test_one_failed_probe_makes_a_suspect_and_the_hold_ends_it,
          test_a_repeated_task_counts_once,
          test_the_worker_is_told_the_suspect,
          test_a_verdict_is_kept_even_when_the_cap_drops_its_half,
          test_an_app_score_and_a_targets_half_are_not_verdicts,
          test_under_the_policy_lone_verdicts_are_own_evidence_everywhere,
          test_the_burst_count_reads_lone_verdicts,
          test_without_the_policy_lone_verdicts_count_nowhere,
          test_a_lone_verdict_is_never_a_defection,
          test_the_bilateral_entry_supersedes_its_lone_verdict,
          test_the_store_bounds_oldest_out,
          test_the_store_survives_a_restart,
          test_an_unreadable_file_leaves_the_store_empty,
          test_a_colluder_that_never_writes_its_half_sinks_on_our_verdicts)
