/********************
 *  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *******************/

/** @file A verifier's attestation round whose propose went missing is proposed
 *  again, a bounded number of times (ISSUES §2.40).
 *
 *  Stele host cohort st-660084 (2026-10-02): the verifier's propose to the
 *  observer was refused by a full network queue, the owner's copy arrived and
 *  was declined (it is the subject), and the round sat pending forever, so
 *  the finding never landed. The messaging test hook stands in for the
 *  network queue and counts the proposes it accepts. Mirrors
 *  tests/a_unit/test_attested_scores.py TestReproposal.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <jansson.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "reputation/reputation.h"
#include "reputation/rep_proc_priv.h"
#include "config/configuration.h"
#include "structures/data.h"
#include "structures/map.h"
#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/send_retry.h"
#include "utilities/msg_types.h"
#include "utilities/msg_types_priv.h"
#include "utilities/allocation.h"

static const char DIGEST[] =
    "abababababababababababababababababababababababababababababababab";

static bool   g_refuse;      /* the network queue is full */
static size_t g_proposes;    /* attest proposes the queue accepted */

static int _hook(const char *key, const message_type_t type,
                 generic_msg_t *msg, bool blocking)
{
    (void)key; (void)blocking;
    if (type != NET_MESSAGE || msg->info.net_msg.function == NULL
        || strcmp(msg->info.net_msg.function, REP_PROTO_ATTEST_PROPOSE) != 0)
        return 0;
    if (g_refuse)
        return EAGAIN;
    g_proposes++;
    return 0;
}

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

static void _add_peer(process_t *proc, identity_t *peer)
{
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(peer, &pub));
    memcpy(&proc->protocol.peers[proc->protocol.num_peers], pub,
           sizeof(public_identity_t));
    proc->protocol.num_peers++;
    smrt_deref(pub);
}

static identity_t *g_ver, *g_subj, *g_obs;
static process_t *g_proc;

/* The verifier, with the subject and an observer on its roster, proposes an
 * attestation about the subject while the network queue is full: every copy
 * of the propose is lost, and the round is left pending. (A refused copy is
 * kept for this process's tick now, ISSUES §2.14; the list is cleared below
 * to stand for a copy lost past that: given up on, or on the far side.) */
static void _begin_with_a_lost_propose(void)
{
    ck_assert(sodium_init() >= 0);
    reputation_reset_state(2);
    g_refuse = false;
    g_proposes = 0;
    messaging_set_test_hook(_hook);
    g_ver = _mk_identity("ver", "10.0.0.1");
    g_subj = _mk_identity("subj", "10.0.0.2");
    g_obs = _mk_identity("obs", "10.0.0.3");
    g_proc = _mk_process(g_ver);
    _add_peer(g_proc, g_subj);
    _add_peer(g_proc, g_obs);

    tx_score_msg_t ts;
    memset(&ts, 0, sizeof(ts));
    uuid_copy(ts.peer_uuid, g_subj->uuid);
    ts.score = 0.3;
    snprintf(ts.channel, sizeof(ts.channel), "%s", "probe");
    ts.attested = true;
    snprintf(ts.evidence_digest, sizeof(ts.evidence_digest), "%s", DIGEST);
    g_refuse = true;
    _forward_attestation(g_proc, &ts, g_ver->uuid);
    g_refuse = false;
    at_send_retry_reset();
    ck_assert_int_eq((int)g_proposes, 0);
    ck_assert_int_eq((int)reputation_attest_pending_count(), 1);
    ck_assert_int_eq((int)reputation_attest_cosig_count(), 1);   /* our own */
}

static void _end(void)
{
    messaging_set_test_hook(NULL);
    reputation_reset_state(0);
}

static double _later(int n)
{
    /* n retry intervals from now, a second past each (the default 15 s). */
    return (double)time(NULL) + n * 15.0 + 1.0;
}

/* THE REGRESSION: once the interval has passed, the propose goes out again
 * to the whole roster, and keeps waiting for its quorum. */
DEFINE_TEST(test_a_lost_propose_is_sent_again_after_the_interval)
{
    _begin_with_a_lost_propose();
    ck_assert_int_eq((int)_retry_pending_attestations(g_proc, _later(0) - 2.0), 0);
    ck_assert_int_eq((int)g_proposes, 0);
    ck_assert_int_eq((int)_retry_pending_attestations(g_proc, _later(1)), 1);
    ck_assert_int_eq((int)g_proposes, 2);   /* subject and observer */
    ck_assert_int_eq((int)reputation_attest_pending_count(), 1);
    _end();
}

/* Bounded: after REP_ATTEST_RETRIES re-proposals the round is abandoned and
 * its pending state dropped. */
DEFINE_TEST(test_reproposals_are_bounded_then_the_round_is_abandoned)
{
    _begin_with_a_lost_propose();
    size_t sent = 0;
    for (int i = 1; i <= 15; i++)
        sent += _retry_pending_attestations(g_proc, _later(i));
    ck_assert_int_eq((int)sent, 5);
    ck_assert_int_eq((int)reputation_attest_pending_count(), 0);
    ck_assert_int_eq((int)reputation_attest_cosig_count(), 0);
    _end();
}

/* A round whose entry reached the chain anyway (a final from elsewhere) is
 * forgotten, not proposed again. */
DEFINE_TEST(test_a_round_already_in_the_chain_is_forgotten)
{
    _begin_with_a_lost_propose();
    ck_assert_ret_ok(reputation_install_tx_attested(g_ver->uuid, 0.3, "probe",
                                                    g_subj->uuid, DIGEST));
    ck_assert_int_eq((int)_retry_pending_attestations(g_proc, _later(1)), 0);
    ck_assert_int_eq((int)g_proposes, 0);
    ck_assert_int_eq((int)reputation_attest_pending_count(), 0);
    ck_assert_int_eq((int)reputation_attest_cosig_count(), 0);
    _end();
}

/* @p signer's attest_sign for the verifier's round about @p subject (digest
 * DIGEST, score 0.3, channel "probe"), dispatched to the verifier. */
static void _sign_from(identity_t *signer, identity_t *subject)
{
    char v_str[UUID_STRING_LEN + 1], s_str[UUID_STRING_LEN + 1];
    char g_str[UUID_STRING_LEN + 1], t_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(g_ver->uuid, v_str);
    uuid_unparse_lower(subject->uuid, s_str);
    uuid_unparse_lower(signer->uuid, g_str);
    uuid_t task;
    tx_attest_task_uuid(g_ver->uuid, subject->uuid, DIGEST, task);
    uuid_unparse_lower(task, t_str);

    /* "AT-ATTEST\0" verifier|subject|task|%.17g|channel|digest */
    static const char tag[] = "AT-ATTEST";
    uint8_t desig[512];
    memcpy(desig, tag, sizeof(tag));
    int n = snprintf((char *)desig + sizeof(tag), sizeof(desig) - sizeof(tag),
                     "%s|%s|%s|%.17g|%s|%s", v_str, s_str, t_str, 0.3, "probe",
                     DIGEST);
    ck_assert(n > 0 && (size_t)n < sizeof(desig) - sizeof(tag));
    unsigned char sig[crypto_sign_BYTES];
    ck_assert_ret_ok(crypto_sign_detached(sig, NULL, desig, sizeof(tag) + (size_t)n,
                                          signer->signature.private));
    char sig_hex[2 * crypto_sign_BYTES + 1];
    sodium_bin2hex(sig_hex, sizeof(sig_hex), sig, sizeof(sig));

    json_t *payload = json_pack("{s:s, s:s, s:s}", "task", t_str,
                                "signer_uuid", g_str, "signature", sig_hex);
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(signer, &pub));
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "reputation", PROC_NAME_LEN);
    msg.info.net_msg.function = REP_PROTO_ATTEST_SIGN;
    msg.info.net_msg.verified = true;
    memcpy(&msg.info.net_msg.from_whom, pub, sizeof(public_identity_t));
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, payload));
    run_message_handlers(g_proc, NULL, NET_MESSAGE, &msg);
    smrt_deref(pub);
    json_decref(payload);
}

/* The observer's co-signature completes the round (the verifier's and the
 * observer's are a strict majority of the two non-subjects): the round's
 * signatures are forgotten with it, not kept for the life of the process. */
DEFINE_TEST(test_a_round_that_reaches_its_quorum_forgets_its_signatures)
{
    _begin_with_a_lost_propose();
    _sign_from(g_obs, g_subj);
    ck_assert_int_eq((int)reputation_attest_pending_count(), 0);
    ck_assert_int_eq((int)reputation_attest_cosig_count(), 0);
    _end();
}

/* Forgetting one round leaves another's signatures countable. Round A (about
 * the subject) and round B (about the observer) are both open; A commits
 * elsewhere and is retired; B's verifier signature, recorded when B was
 * proposed, must still count when the subject's co-signature arrives. Freeing
 * the signature map's key index while retiring A used to lose it. */
DEFINE_TEST(test_retiring_one_round_keeps_another_rounds_signatures)
{
    _begin_with_a_lost_propose();
    tx_score_msg_t ts;
    memset(&ts, 0, sizeof(ts));
    uuid_copy(ts.peer_uuid, g_obs->uuid);
    ts.score = 0.3;
    snprintf(ts.channel, sizeof(ts.channel), "%s", "probe");
    ts.attested = true;
    snprintf(ts.evidence_digest, sizeof(ts.evidence_digest), "%s", DIGEST);
    _forward_attestation(g_proc, &ts, g_ver->uuid);
    ck_assert_int_eq((int)reputation_attest_pending_count(), 2);

    ck_assert_ret_ok(reputation_install_tx_attested(g_ver->uuid, 0.3, "probe",
                                                    g_subj->uuid, DIGEST));
    _retry_pending_attestations(g_proc, _later(1));   /* retires round A */
    ck_assert_int_eq((int)reputation_attest_pending_count(), 1);

    _sign_from(g_subj, g_obs);                        /* completes round B */
    ck_assert_int_eq((int)reputation_attest_pending_count(), 0);
    _end();
}

RUN_TESTS(RepAttestRetry,
          test_a_lost_propose_is_sent_again_after_the_interval,
          test_reproposals_are_bounded_then_the_round_is_abandoned,
          test_a_round_already_in_the_chain_is_forgotten,
          test_a_round_that_reaches_its_quorum_forgets_its_signatures,
          test_retiring_one_round_keeps_another_rounds_signatures)
