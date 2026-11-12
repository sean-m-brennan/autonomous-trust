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

/** @file Own entries outlive the chain window (tx_history_t.retained).
 *
 *  Hostile-join runs without the policy, 2026-11-04: the primary chain keeps
 *  MAX_CHAIN_LEN resident entries, and ten nodes' probes and tasks evicted a
 *  joiner's own transactions with its contact within minutes (35 fell to 2).
 *  An evicted entry this node is a party to now moves to a bounded store
 *  beside the window, which the scorers read before the resident entries. The
 *  window, its root, catch-up and the wire are unchanged. The Python twin is
 *  tests/a_unit/test_retained_evidence.py.
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
    snprintf(g_root, sizeof(g_root), "/tmp/at-retained-XXXXXX");
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

static void _hpair(tx_history_t *h, const uuid_t a, int a_milli,
                   const uuid_t b, int b_milli, uuid_t task_out)
{
    uuid_t task;
    uuid_generate(task);
    ck_assert_ret_ok(tx_history_update(h, task, a, a_milli, NULL));
    ck_assert_ret_ok(tx_history_update(h, task, b, b_milli, NULL));
    if (task_out != NULL)
        uuid_copy(task_out, task);
}

static tx_history_t *_kept_history(const uuid_t self)
{
    tx_history_t *h = NULL;
    ck_assert_ret_ok(tx_history_create(&h));
    if (self != NULL)
        tx_history_set_keep_party(h, self);
    return h;
}

static void _flush(tx_history_t *h)
{
    uuid_t x, y;
    uuid_generate(x);
    uuid_generate(y);
    for (int i = 0; i < MAX_CHAIN_LEN; i++)
        _hpair(h, x, 500, y, 500, NULL);
}

DEFINE_TEST(test_retained_an_evicted_own_entry_is_retained)
{
    uuid_t self_id, peer, own[3];
    uuid_generate(self_id);
    uuid_generate(peer);
    tx_history_t *h = _kept_history(self_id);
    for (int i = 0; i < 3; i++)
        _hpair(h, self_id, 900, peer, 800, own[i]);
    _flush(h);
    ck_assert_int_eq(tx_history_len(h), MAX_CHAIN_LEN);
    transaction_t out[8];
    int n = 0;
    tx_history_retained_by_peer(h, peer, out, &n, 8);
    ck_assert_int_eq(n, 3);
    for (int i = 0; i < 3; i++)
        ck_assert_int_eq(uuid_compare(out[i].task_uuid, own[i]), 0);
    tx_history_destroy(h);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_retained_a_third_partys_entry_is_not)
{
    uuid_t self_id, peer, x;
    uuid_generate(self_id);
    uuid_generate(peer);
    uuid_generate(x);
    tx_history_t *h = _kept_history(self_id);
    for (int i = 0; i < 3; i++)
        _hpair(h, x, 500, peer, 500, NULL);
    _flush(h);
    ck_assert_int_eq(h->retained_len, 0);
    tx_history_destroy(h);
    /* Without a party to keep, nothing is retained. */
    h = _kept_history(NULL);
    for (int i = 0; i < 3; i++)
        _hpair(h, self_id, 900, peer, 800, NULL);
    _flush(h);
    ck_assert_int_eq(h->retained_len, 0);
    tx_history_destroy(h);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_retained_the_bounds_drop_the_oldest)
{
    uuid_t self_id, a, b, at[3], bt[2];
    uuid_generate(self_id);
    uuid_generate(a);
    uuid_generate(b);
    tx_history_t *h = _kept_history(self_id);
    h->retained_per_peer = 2;
    h->retained_max = 3;
    for (int i = 0; i < 3; i++)
        _hpair(h, self_id, 900, a, 900, at[i]);
    for (int i = 0; i < 2; i++)
        _hpair(h, self_id, 900, b, 900, bt[i]);
    _flush(h);
    transaction_t out[8];
    int n = 0;
    tx_history_retained_by_peer(h, a, out, &n, 8);
    ck_assert_int_eq(n, 1);
    ck_assert_int_eq(uuid_compare(out[0].task_uuid, at[2]), 0);
    tx_history_retained_by_peer(h, b, out, &n, 8);
    ck_assert_int_eq(n, 2);
    ck_assert_int_eq(REP_RETAINED_PER_PEER, 64);
    ck_assert_int_eq(REP_RETAINED_MAX, 4 * MAX_CHAIN_LEN);
    tx_history_destroy(h);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_retained_the_window_is_unchanged)
{
    uuid_t self_id, peer, x, y;
    uuid_generate(self_id);
    uuid_generate(peer);
    uuid_generate(x);
    uuid_generate(y);
    tx_history_t *plain = _kept_history(NULL), *kept = _kept_history(self_id);
    for (int i = 0; i < MAX_CHAIN_LEN + 3; i++) {
        uuid_t task;
        uuid_generate(task);
        const unsigned char *a = i < 3 ? self_id : x, *b = i < 3 ? peer : y;
        tx_history_t *hs[2] = {plain, kept};
        for (int k = 0; k < 2; k++) {
            ck_assert_ret_ok(tx_history_update(hs[k], task, a, 900, NULL));
            ck_assert_ret_ok(tx_history_update(hs[k], task, b, 800, NULL));
        }
    }
    ck_assert_int_eq(tx_history_len(plain), tx_history_len(kept));
    ck_assert_int_eq(plain->first_index, kept->first_index);
    ck_assert_str_eq(plain->head_hash, kept->head_hash);
    transaction_t out[4];
    int n = 0;
    tx_history_by_peer(kept, peer, out, &n, 4);
    ck_assert_int_eq(n, 0);
    tx_history_destroy(plain);
    tx_history_destroy(kept);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_retained_the_store_round_trips)
{
    uuid_t self_id, peer, x, own[3];
    uuid_generate(self_id);
    uuid_generate(peer);
    uuid_generate(x);
    tx_history_t *h = _kept_history(self_id);
    for (int i = 0; i < 3; i++)
        _hpair(h, self_id, 900, peer, 900, own[i]);
    _flush(h);
    json_t *doc = NULL;
    ck_assert_ret_ok(reputation_retained_to_json(h, &doc));
    /* A foreign entry, and one already resident, are dropped on load. */
    tx_history_t *foreign = _kept_history(x);
    _hpair(foreign, x, 500, peer, 500, NULL);
    _flush(foreign);
    json_t *fdoc = NULL;
    ck_assert_ret_ok(reputation_retained_to_json(foreign, &fdoc));
    json_array_extend(json_object_get(doc, "chain"), json_object_get(fdoc, "chain"));
    tx_history_t *fresh = _kept_history(self_id);
    ck_assert_ret_ok(reputation_retained_from_json(doc, fresh));
    transaction_t out[8];
    int n = 0;
    tx_history_retained_by_peer(fresh, peer, out, &n, 8);
    ck_assert_int_eq(n, 3);
    for (int i = 0; i < 3; i++)
        ck_assert_int_eq(uuid_compare(out[i].task_uuid, own[i]), 0);
    ck_assert_int_eq(fresh->retained_len, 3);
    json_decref(doc);
    json_decref(fdoc);
    tx_history_destroy(h);
    tx_history_destroy(foreign);
    tx_history_destroy(fresh);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_retained_ctft_reads_them)
{
    process_t *proc = _begin(false);
    reputation_set_keep_party(me->uuid);
    _own(3, 0.9, NULL);
    _told(MAX_CHAIN_LEN, 0.5);
    ck_assert_int_eq(reputation_retained_count(""), 3);
    _sweep(proc, -1.0);
    double v = 0.0;
    ck_assert_ret_ok(reputation_get_peer_reputation(them->uuid, &v));
    ck_assert_double_eq_tol(v, (2.7 + 3 * PREREP_NEUTRAL) / 6, 1e-6);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_retained_own_evidence_reads_them)
{
    process_t *proc = _begin(true);
    reputation_set_keep_party(me->uuid);
    _own(3, 0.9, NULL);
    _told(MAX_CHAIN_LEN, 0.5);
    _sweep(proc, -1.0);
    double v = 0.0;
    ck_assert_ret_ok(reputation_get_brought(them->uuid, &v));
    ck_assert_double_eq_tol(v, (2.7 + 3 * PREREP_NEUTRAL) / 6, 1e-6);
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(RepRetained,
          test_retained_an_evicted_own_entry_is_retained,
          test_retained_a_third_partys_entry_is_not,
          test_retained_the_bounds_drop_the_oldest,
          test_retained_the_window_is_unchanged,
          test_retained_the_store_round_trips,
          test_retained_ctft_reads_them,
          test_retained_own_evidence_reads_them)
