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

/** @file ZTA hardening: the DDIL cap binds, and a failure unwinds (ISSUES §10.5).
 *
 *  Two things were broken here in the FIELDED runtime, both invisible because
 *  nothing tested the ZTA→reputation path at all.
 *
 *  The cap: `ddil_fallback_reputation_cap` was in the policy, was serialized,
 *  and was printed in the operator log as though enforced ("admitting with
 *  reputation cap 0.50") while being read by nothing. `ZTA_GATE_ADMIT_CAPPED`
 *  was only ever compared against `ZTA_GATE_REJECT`, so a capped admission was
 *  byte-for-byte an ordinary one.
 *
 *  The penalty: `_send_reputation_penalty` stamped a zero `task_uuid`, which
 *  `_handle_local_tx_score` discards by design as the "system score" sentinel,
 *  AND sent `score = -0.8`, which `tx_score_in_range` has rejected since §11.2
 *  put the scale at [0, 1] with no negatives. A revoked credential cost a peer
 *  nothing, twice over.
 *
 *  So every assertion below is on the resulting SCORE, never on a message
 *  having been sent -- sending was exactly what already happened while nothing
 *  moved. The Python twin is tests/a_unit/test_zta_standing.py; keep the two
 *  in step, since a fleet is only as strict as its weaker runtime.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#include <jansson.h>
#include <uuid/uuid.h>

#include "identity/identity.h"
#include "reputation/reputation.h"
#include "reputation/rep_proc_priv.h"
#include "structures/data.h"
#include "structures/map.h"
#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
#include "utilities/msg_types_priv.h"
#include "utilities/allocation.h"

#define CAP 0.5
#define TX_SCORE 0.9

/* `reputations_t` keeps scores as a float (reputation.h: "uuid_str -> data_t*
 * (float score)"), so a value read back has ~1e-7 of rounding on it. Comparing
 * at double precision would fail on the storage, not on the behaviour. */
#define SCORE_TOL 1e-6

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

/* Swallow the tier_update / exclusion IPC an unwind emits: this suite asserts
 * the score, and an unhooked send would go nowhere useful under test. */
static int _sink_hook(const char *key, const message_type_t type,
                      generic_msg_t *msg, bool blocking)
{
    (void)key; (void)type; (void)msg; (void)blocking;
    return 0;
}

static void _standing(const process_t *proc, const uuid_t peer,
                      zta_standing_t which, double ceiling, const char *reason)
{
    zta_standing_msg_t st;
    memset(&st, 0, sizeof(st));
    memcpy(st.peer_uuid, peer, sizeof(uuid_t));
    st.standing = (int32_t)which;
    st.ceiling = ceiling;
    strncpy(st.reason, reason, sizeof(st.reason) - 1);
    ck_assert_ret_ok(reputation_apply_zta_standing(proc, &st));
}

/* `n` bilateral transactions between self and peer, committed into the
 * resident chain -- the evidence an unwind is judged against. */
static void _transact(const uuid_t self_uuid, const uuid_t peer, int n,
                      int first_task)
{
    for (int i = 0; i < n; i++) {
        uuid_t task;
        uuid_clear(task);
        task[0] = (unsigned char)(first_task + i);
        task[15] = 1;
        reputation_install_tx_pair(task, self_uuid, TX_SCORE,
                                   peer, TX_SCORE);
    }
}


/* Drive a handler the way rep_quorum_test does: the scoring path is static, so
 * it is reached through run_message_handlers with a crafted NET_MESSAGE. */
/* The verb whose handler WRITES the score. `handle_consensus_rep_request`
 * computes and reports one without storing it, so driving that would prove
 * nothing about the stored value this test is about. */
static char REP_REQ_FN[] = "request reputation";

static void _dispatch(process_t *proc, identity_t *sender, char *function,
                      json_t *payload)
{
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(sender, &pub));
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "reputation", PROC_NAME_LEN);
    msg.info.net_msg.function = function;
    msg.info.net_msg.verified = true;
    memcpy(&msg.info.net_msg.from_whom, pub, sizeof(public_identity_t));
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, payload));
    run_message_handlers(proc, NULL, NET_MESSAGE, &msg);
    smrt_deref(pub);
}

/* ------------------------------------------------------------------ */

DEFINE_TEST(test_a_capped_peer_is_bounded)
{
    identity_t *me = _mk_identity("10.0.0.1", "self");
    process_t *proc = _mk_process(me);
    reputation_reset_state(3);
    messaging_set_test_hook(_sink_hook);

    uuid_t peer;
    uuid_generate(peer);
    _standing(proc, peer, ZTA_STANDING_CAPPED, CAP, "DDIL");

    double ceiling = 0.0;
    ck_assert_ret_ok(reputation_get_zta_ceiling(peer, &ceiling));
    ck_assert_double_eq_tol(ceiling, CAP, 1e-9);
    messaging_set_test_hook(NULL);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_proved_peer_is_unbounded)
{
    identity_t *me = _mk_identity("10.0.0.1", "self");
    process_t *proc = _mk_process(me);
    reputation_reset_state(3);
    messaging_set_test_hook(_sink_hook);

    uuid_t peer;
    uuid_generate(peer);
    /* Capped first, so this also pins that a later verdict LIFTS the cap --
     * without which a peer that repairs its credential stays bounded for
     * ever. */
    _standing(proc, peer, ZTA_STANDING_CAPPED, CAP, "DDIL");
    _standing(proc, peer, ZTA_STANDING_PROVED, ZTA_NO_CEILING, "verified");

    double ceiling = 0.0;
    ck_assert_int_eq(reputation_get_zta_ceiling(peer, &ceiling), -1);
    messaging_set_test_hook(NULL);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_silence_bounds_nobody)
{
    identity_t *me = _mk_identity("10.0.0.1", "self");
    _mk_process(me);
    reputation_reset_state(3);

    uuid_t peer;
    uuid_generate(peer);
    double ceiling = 0.0;
    /* A deployment that has not enabled ZTA is not bounded by it. */
    ck_assert_int_eq(reputation_get_zta_ceiling(peer, &ceiling), -1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_failure_unwinds_to_pre_verification_evidence)
{
    identity_t *me = _mk_identity("10.0.0.1", "self");
    process_t *proc = _mk_process(me);
    reputation_reset_state(3);
    messaging_set_test_hook(_sink_hook);

    uuid_t peer;
    uuid_generate(peer);

    /* Two transactions while proved, then the proof point, then eight more
     * earned while nobody could confirm the peer. */
    _transact(me->uuid, peer, 2, 1);
    _standing(proc, peer, ZTA_STANDING_PROVED, ZTA_NO_CEILING, "verified");
    _transact(me->uuid, peer, 8, 100);
    reputation_install_peer_reputation(peer, 0.95);

    _standing(proc, peer, ZTA_STANDING_FAILED, 0.2, "REVOKED");

    double after = 0.0;
    ck_assert_ret_ok(reputation_get_peer_reputation(peer, &after));
    /* Judged on the two pre-anchor transactions, not the ten the chain holds. */
    ck_assert(after < 0.95);
    double evidence = (2 * TX_SCORE + REP_RESTORE_SHRINKAGE_K * PREREP_NEUTRAL)
                      / (2 + REP_RESTORE_SHRINKAGE_K);
    ck_assert_double_eq_tol(after, evidence, SCORE_TOL);
    messaging_set_test_hook(NULL);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_peer_never_proved_keeps_nothing)
{
    identity_t *me = _mk_identity("10.0.0.1", "self");
    process_t *proc = _mk_process(me);
    reputation_reset_state(3);
    messaging_set_test_hook(_sink_hook);

    uuid_t peer;
    uuid_generate(peer);
    _transact(me->uuid, peer, 5, 1);
    reputation_install_peer_reputation(peer, 0.95);

    /* No PROVED standing ever arrived: nothing this peer holds rests on a
     * credential anyone confirmed. */
    _standing(proc, peer, ZTA_STANDING_FAILED, 0.2, "REVOKED");

    double after = 0.0;
    ck_assert_ret_ok(reputation_get_peer_reputation(peer, &after));
    ck_assert_double_eq_tol(after, reputation_zta_unverified_ceiling(), SCORE_TOL);
    messaging_set_test_hook(NULL);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_unwind_never_raises_a_peer)
{
    identity_t *me = _mk_identity("10.0.0.1", "self");
    process_t *proc = _mk_process(me);
    reputation_reset_state(3);
    messaging_set_test_hook(_sink_hook);

    uuid_t peer;
    uuid_generate(peer);
    _transact(me->uuid, peer, 5, 1);
    _standing(proc, peer, ZTA_STANDING_PROVED, ZTA_NO_CEILING, "verified");
    reputation_install_peer_reputation(peer, 0.02);

    _standing(proc, peer, ZTA_STANDING_FAILED, 0.2, "REVOKED");

    double after = 0.0;
    ck_assert_ret_ok(reputation_get_peer_reputation(peer, &after));
    /* A peer already below what the evidence supports must not be LIFTED by
     * its own credential failing. */
    ck_assert_double_eq_tol(after, 0.02, SCORE_TOL);
    messaging_set_test_hook(NULL);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_repeated_verdict_unwinds_once)
{
    identity_t *me = _mk_identity("10.0.0.1", "self");
    process_t *proc = _mk_process(me);
    reputation_reset_state(3);
    messaging_set_test_hook(_sink_hook);

    uuid_t peer;
    uuid_generate(peer);
    _transact(me->uuid, peer, 2, 1);
    _standing(proc, peer, ZTA_STANDING_PROVED, ZTA_NO_CEILING, "verified");
    _transact(me->uuid, peer, 8, 100);
    reputation_install_peer_reputation(peer, 0.95);

    /* Periodic re-verification restates an unchanged verdict by the hour;
     * acting on each restatement would ratchet a peer down for one offence. */
    _standing(proc, peer, ZTA_STANDING_FAILED, 0.2, "REVOKED");
    double first = 0.0;
    ck_assert_ret_ok(reputation_get_peer_reputation(peer, &first));
    _standing(proc, peer, ZTA_STANDING_FAILED, 0.2, "REVOKED");
    _standing(proc, peer, ZTA_STANDING_FAILED, 0.2, "REVOKED");
    double again = 0.0;
    ck_assert_ret_ok(reputation_get_peer_reputation(peer, &again));
    ck_assert_double_eq_tol(again, first, SCORE_TOL);
    messaging_set_test_hook(NULL);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_cap_alone_does_not_lower_a_peer)
{
    identity_t *me = _mk_identity("10.0.0.1", "self");
    process_t *proc = _mk_process(me);
    reputation_reset_state(3);
    messaging_set_test_hook(_sink_hook);

    uuid_t peer;
    uuid_generate(peer);
    reputation_install_peer_reputation(peer, 0.30);
    _standing(proc, peer, ZTA_STANDING_CAPPED, CAP, "DDIL");

    /* A ceiling bounds what a peer may RISE to. Driving it down is what the
     * unwind is for, and only an affirmative failure justifies that --
     * otherwise every disconnected DDIL deployment is punished for being
     * disconnected. */
    double after = 0.0;
    ck_assert_ret_ok(reputation_get_peer_reputation(peer, &after));
    ck_assert_double_eq_tol(after, 0.30, SCORE_TOL);
    messaging_set_test_hook(NULL);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_cap_binds_the_score_the_scoring_path_writes)
{
    identity_t *me = _mk_identity("10.0.0.1", "self");
    identity_t *them = _mk_identity("10.0.0.2", "peer");
    process_t *proc = _mk_process(me);

    char peer_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(them->uuid, peer_str);
    json_t *payload = json_object();
    json_object_set_new(payload, "peer_uuid", json_string(peer_str));
    json_object_set_new(payload, "requesting_process",
                        json_string("negotiation"));

    /* Phase 1: score the peer with NO ZTA standing, to learn what this
     * scenario actually produces. Calibrating instead of hard-coding is the
     * point: an assertion of "<= 0.5" against a scenario that happens to score
     * 0.18 passes whether or not the cap exists, which is precisely the kind of
     * control that cannot fail (verified -- it still passed with the ceiling
     * neutered). */
    reputation_reset_state(3);
    messaging_set_test_hook(_sink_hook);
    _transact(me->uuid, them->uuid, 6, 1);
    reputation_install_peer_reputation(them->uuid, 0.95);
    reputation_install_coop_mode(them->uuid, true);
    _dispatch(proc, them, REP_REQ_FN, payload);
    double uncapped = 0.0;
    ck_assert_ret_ok(reputation_get_peer_reputation(them->uuid, &uncapped));

    /* Phase 2: identical scenario, with a ceiling set strictly BELOW what the
     * peer just scored, so the cap must bind or the assertion fails. */
    double cap = uncapped / 2.0;
    reputation_reset_state(3);
    _transact(me->uuid, them->uuid, 6, 1);
    reputation_install_peer_reputation(them->uuid, 0.95);
    reputation_install_coop_mode(them->uuid, true);
    _standing(proc, them->uuid, ZTA_STANDING_CAPPED, cap, "DDIL");
    _dispatch(proc, them, REP_REQ_FN, payload);

    /* The bound lands on the STORED score, not merely on what this request
     * reported: a ceiling applied at read time would leave the unbounded value
     * in the store for the next consumer -- persistence, the app carrier, a
     * peer answering a rep_req -- to leak. */
    double capped = 0.0;
    ck_assert_ret_ok(reputation_get_peer_reputation(them->uuid, &capped));
    ck_assert(uncapped > cap);            /* the scenario really does exceed it */
    ck_assert_double_eq_tol(capped, cap, SCORE_TOL);

    json_decref(payload);
    messaging_set_test_hook(NULL);
}
END_TEST_DEFINITION()

RUN_TESTS(ZtaStanding,
          test_a_capped_peer_is_bounded,
          test_a_proved_peer_is_unbounded,
          test_silence_bounds_nobody,
          test_a_failure_unwinds_to_pre_verification_evidence,
          test_a_peer_never_proved_keeps_nothing,
          test_the_unwind_never_raises_a_peer,
          test_a_repeated_verdict_unwinds_once,
          test_a_cap_alone_does_not_lower_a_peer,
          test_the_cap_binds_the_score_the_scoring_path_writes)
