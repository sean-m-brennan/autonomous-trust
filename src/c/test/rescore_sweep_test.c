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


/** @file The rescore sweep: what rates a peer in a running node (Phase 4 P4.1).
 *
 *  handle_rep_request used to be the only place a score was computed and
 *  stored, and nothing in a running node sends "request reputation". A commit
 *  only appended to the chain. So moderation_cohort.sh's first host run found
 *  every peer still unrated after eleven commits, which meant no tier had ever
 *  been published and every tier-gate above 0 was closed for good.
 *
 *  Every test here drives the sweep through the same entry point the process
 *  loop uses and asserts what it SENT, because an unsent tier is exactly the
 *  defect: the score store alone would have looked healthy. The Python twin
 *  is tests/a_unit/test_rescore_sweep.py.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include <jansson.h>
#include <errno.h>
#include <uuid/uuid.h>

#include "identity/identity.h"
#include "reputation/reputation.h"
#include "reputation/rep_proc_priv.h"
#include "structures/data.h"
#include "structures/map.h"
#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/send_retry.h"
#include "utilities/msg_types.h"
#include "utilities/msg_types_priv.h"
#include "utilities/allocation.h"

#define SCORE_TOL 1e-6
#define T0 1000000.0

static identity_t *_mk_identity(const char *addr, const char *name)
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
    strncpy(proc->name, "reputation", PROC_NAME_LEN);
    proc->protocol.phase = 1;
    proc->protocol.num_peers = 0;

    config_t *id_cfg = calloc(1, sizeof(config_t));
    ck_assert_ptr_nonnull(id_cfg);
    id_cfg->name = "identity";
    id_cfg->data_struct = self;
    data_t *id_dat = object_ptr_data((ptr_t)id_cfg, sizeof(config_t));
    ck_assert_ret_ok(map_create(&proc->configs));
    map_set(proc->configs, (map_key_t)"identity", id_dat);

    ck_assert_ret_ok(map_create(&proc->protocol.handlers));
    ck_assert_ret_ok(reputation_register_handlers(proc));
    return proc;
}

static void _admit(process_t *proc, identity_t *peer)
{
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(peer, &pub));
    ck_assert_ptr_nonnull(pub);
    memcpy(&proc->protocol.peers[proc->protocol.num_peers], pub,
           sizeof(public_identity_t));
    proc->protocol.num_peers++;
    smrt_deref(pub);
}

/* What the sweep SENT: tier_updates to identity and PEER_REPUTATIONs to the
 * main loop, counted, with the last of each kept. */
static int g_tiers, g_reps, g_last_tier, g_tier_lost;
static bool g_identity_full, g_negotiation_full;
static peer_reputation_msg_t g_last_rep;

static int _hook(const char *key, const message_type_t type,
                 generic_msg_t *msg, bool blocking)
{
    (void)blocking;
    if (type == NET_MESSAGE && key != NULL && strcmp(key, "identity") == 0 &&
        msg->info.net_msg.function != NULL &&
        strcmp(msg->info.net_msg.function, "tier_update") == 0) {
        if (g_identity_full)
            return EAGAIN;
        json_t *arr = NULL;
        if (net_msg_unpack_json(&msg->info.net_msg, &arr) == 0 && arr != NULL) {
            g_last_tier = (int)json_integer_value(json_array_get(arr, 1));
            g_tiers++;
            json_decref(arr);
        }
    } else if (type == NET_MESSAGE && key != NULL &&
               strcmp(key, "negotiation") == 0 &&
               msg->info.net_msg.function != NULL &&
               strcmp(msg->info.net_msg.function, "tier_lost") == 0) {
        if (g_negotiation_full)
            return EAGAIN;
        g_tier_lost++;
    } else if (type == PEER_REPUTATION) {
        g_last_rep = msg->info.peer_reputation;
        g_reps++;
    }
    return 0;
}

static void _begin(void)
{
    reputation_reset_state(3);
    g_tiers = 0; g_reps = 0; g_last_tier = -1; g_tier_lost = 0;
    g_identity_full = false; g_negotiation_full = false;
    memset(&g_last_rep, 0, sizeof(g_last_rep));
    messaging_set_test_hook(_hook);
}

static void _end(void) { messaging_set_test_hook(NULL); }

/* ------------------------------------------------------------------ */

DEFINE_TEST(test_an_unscored_peer_is_rated_at_its_prior_and_published)
{
    identity_t *me = _mk_identity("10.0.0.1", "self");
    identity_t *bob = _mk_identity("10.0.0.2", "bob");
    process_t *proc = _mk_process(me);
    _begin();
    _admit(proc, bob);

    ck_assert_int_eq(reputation_rescore_sweep(proc, T0, me->uuid), 1);
    double score = -1.0;
    ck_assert_ret_ok(reputation_get_peer_reputation(bob->uuid, &score));
    /* No history at all: the prereputation prior, which is PREREP_NEUTRAL. */
    ck_assert_double_eq_tol(score, PREREP_NEUTRAL, SCORE_TOL);
    ck_assert_int_eq(g_tiers, 1);   /* first publication: identity learns a tier */
    ck_assert_int_eq(g_reps, 1);
    ck_assert(g_last_rep.rated);
    ck_assert_int_eq(uuid_compare(g_last_rep.peer_uuid, bob->uuid), 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_rated_peer_is_rescored_only_when_its_chain_moved)
{
    identity_t *me = _mk_identity("10.0.0.1", "self");
    identity_t *bob = _mk_identity("10.0.0.2", "bob");
    process_t *proc = _mk_process(me);
    _begin();
    _admit(proc, bob);
    reputation_install_peer_reputation(bob->uuid, 0.9);

    /* The first sweep tells identity (see the restored-peer test); after
     * that, rated and untouched means nothing to do. */
    ck_assert_int_eq(reputation_rescore_sweep(proc, T0, me->uuid), 1);
    g_reps = 0;
    ck_assert_int_eq(reputation_rescore_sweep(proc, T0 + 1800.0, me->uuid), 0);
    ck_assert_int_eq(g_reps, 0);

    /* A commit with bob marks him; the next sweep scores and publishes him. */
    reputation_note_interaction(bob->uuid);
    ck_assert_int_eq(reputation_rescore_sweep(proc, T0 + 3600.0, me->uuid), 1);
    ck_assert_int_eq(g_reps, 1);
    /* ...and only once: the mark is spent. */
    ck_assert_int_eq(reputation_rescore_sweep(proc, T0 + 7200.0, me->uuid), 0);
    _end();
}
END_TEST_DEFINITION()

/* A RESTART: the score survives in the snapshot, identity's tiers do not.
 * Without this the restored peer is rated, never due, and identity gates him
 * at tier 0 until his tier next changes — moderation_cohort.sh's phase 6. */
DEFINE_TEST(test_a_restored_peer_is_told_to_identity_once)
{
    identity_t *me = _mk_identity("10.0.0.1", "self");
    identity_t *bob = _mk_identity("10.0.0.2", "bob");
    process_t *proc = _mk_process(me);
    _begin();
    _admit(proc, bob);
    reputation_install_peer_reputation(bob->uuid, 0.7);   /* the warm start */

    ck_assert_int_eq(reputation_rescore_sweep(proc, T0, me->uuid), 1);
    ck_assert_int_eq(g_tiers, 1);
    ck_assert_int_eq(g_reps, 1);
    /* Told once: the next sweep leaves him alone. */
    ck_assert_int_eq(reputation_rescore_sweep(proc, T0 + 3600.0, me->uuid), 0);
    ck_assert_int_eq(g_tiers, 1);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_sweep_is_throttled)
{
    identity_t *me = _mk_identity("10.0.0.1", "self");
    identity_t *bob = _mk_identity("10.0.0.2", "bob");
    process_t *proc = _mk_process(me);
    _begin();
    _admit(proc, bob);
    reputation_install_peer_reputation(bob->uuid, 0.9);

    ck_assert_int_eq(reputation_rescore_sweep(proc, T0, me->uuid), 1);
    reputation_note_interaction(bob->uuid);
    /* One second later is inside AT_REP_RESCORE_SEC: the mark waits... */
    ck_assert_int_eq(reputation_rescore_sweep(proc, T0 + 1.0, me->uuid), 0);
    /* ...and is still there for the next sweep that runs. */
    ck_assert_int_eq(reputation_rescore_sweep(proc, T0 + 3600.0, me->uuid), 1);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_node_never_scores_itself)
{
    identity_t *me = _mk_identity("10.0.0.1", "self");
    process_t *proc = _mk_process(me);
    _begin();
    reputation_note_interaction(me->uuid);
    ck_assert_int_eq(reputation_rescore_sweep(proc, T0, me->uuid), 0);
    double mine = 0.0;
    ck_assert(reputation_get_peer_reputation(me->uuid, &mine) != 0);
    ck_assert_int_eq(g_reps, 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_standing_bounds_what_the_sweep_writes)
{
    identity_t *me = _mk_identity("10.0.0.1", "self");
    identity_t *bob = _mk_identity("10.0.0.2", "bob");
    process_t *proc = _mk_process(me);
    _begin();
    _admit(proc, bob);

    peer_standing_msg_t st;
    memset(&st, 0, sizeof(st));
    memcpy(st.peer_uuid, bob->uuid, sizeof(uuid_t));
    st.standing = (int32_t)PEER_STANDING_CAPPED;
    st.ceiling = 0.10;
    strncpy(st.source, PEER_STANDING_SOURCE_ETHNE, sizeof(st.source) - 1);
    strncpy(st.reason, "test", sizeof(st.reason) - 1);
    ck_assert_ret_ok(reputation_apply_peer_standing(proc, &st));

    ck_assert_int_eq(reputation_rescore_sweep(proc, T0, me->uuid), 1);
    double score = -1.0;
    ck_assert_ret_ok(reputation_get_peer_reputation(bob->uuid, &score));
    ck_assert_double_eq_tol(score, 0.10, SCORE_TOL);
    ck_assert_int_eq(g_last_tier, 0);
    _end();
}
END_TEST_DEFINITION()


/* Moderation cohort mod-2505620 (2026-09-23): after ada restarted, her app
 * read bob at tier 1 while her post gate still held him at 0, and his tier-1
 * post never reached her. The publication record was written BEFORE the send
 * and the send's result discarded, so a tier_update lost to a full identity
 * queue was never repeated. */
DEFINE_TEST(test_a_tier_update_lost_to_a_full_queue_is_published_again)
{
    identity_t *me = _mk_identity("10.0.0.1", "self");
    identity_t *bob = _mk_identity("10.0.0.2", "bob");
    process_t *proc = _mk_process(me);
    _begin();
    _admit(proc, bob);
    reputation_install_peer_reputation(bob->uuid, 0.7);   /* the warm start */

    g_identity_full = true;
    ck_assert_int_eq(reputation_rescore_sweep(proc, T0, me->uuid), 1);
    ck_assert_int_eq(g_tiers, 0);                          /* lost */

    g_identity_full = false;
    ck_assert_int_eq(reputation_rescore_sweep(proc, T0 + 3600.0, me->uuid), 1);
    ck_assert_int_eq(g_tiers, 1);                          /* told after all */
    /* ...and once told, left alone. */
    ck_assert_int_eq(reputation_rescore_sweep(proc, T0 + 7200.0, me->uuid), 0);
    _end();
}
END_TEST_DEFINITION()

/* A demotion's tier_lost tells negotiation to cancel what the peer can no
 * longer authorize, and nothing republishes it (the tier_update rollback above
 * re-arms only identity's half). A full negotiation queue keeps it for this
 * process's tick (ISSUES §2.14); until then it was one bare try. */
DEFINE_TEST(test_a_tier_lost_to_a_full_queue_is_kept_for_the_tick)
{
    identity_t *me = _mk_identity("10.0.0.1", "self");
    identity_t *bob = _mk_identity("10.0.0.2", "bob");
    process_t *proc = _mk_process(me);
    _begin();
    _admit(proc, bob);
    ck_assert_int_eq(reputation_rescore_sweep(proc, T0, me->uuid), 1);
    reputation_install_peer_reputation(bob->uuid, 0.9);

    /* A lenient bound restates bob's tier from his stored 0.9: promoted. */
    peer_standing_msg_t st;
    memset(&st, 0, sizeof(st));
    memcpy(st.peer_uuid, bob->uuid, sizeof(uuid_t));
    st.standing = (int32_t)PEER_STANDING_CAPPED;
    st.ceiling = 0.99;
    strncpy(st.source, PEER_STANDING_SOURCE_ETHNE, sizeof(st.source) - 1);
    strncpy(st.reason, "test", sizeof(st.reason) - 1);
    ck_assert_ret_ok(reputation_apply_peer_standing(proc, &st));
    ck_assert(g_last_tier > 0);
    ck_assert_int_eq(g_tier_lost, 0);

    /* Then capped low: a demotion, with negotiation's queue full. */
    g_negotiation_full = true;
    st.ceiling = 0.10;
    ck_assert_ret_ok(reputation_apply_peer_standing(proc, &st));
    ck_assert_int_eq(g_last_tier, 0);
    ck_assert_int_eq(g_tier_lost, 0);
    ck_assert_uint_eq(at_send_retry_pending("negotiation"), 1);

    g_negotiation_full = false;
    ck_assert_uint_eq(at_send_retry_drain(proc, NULL, (double)time(NULL)), 1);
    ck_assert_int_eq(g_tier_lost, 1);
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(RescoreSweep,
          test_an_unscored_peer_is_rated_at_its_prior_and_published,
          test_a_rated_peer_is_rescored_only_when_its_chain_moved,
          test_a_restored_peer_is_told_to_identity_once,
          test_a_tier_update_lost_to_a_full_queue_is_published_again,
          test_the_sweep_is_throttled,
          test_a_node_never_scores_itself,
          test_a_standing_bounds_what_the_sweep_writes,
          test_a_tier_lost_to_a_full_queue_is_kept_for_the_tick)
