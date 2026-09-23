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

/** @file A first-person report, both halves (Phase 4 P4.1).
 *
 *  A report is a low scalar through the ordinary BILATERAL transaction: the
 *  reporter stages AT_SOCIAL_REPORT_SCORE on the `first_person` channel, the
 *  reported node stages AT_SOCIAL_REPORTER_SCORE about the reporter, and the
 *  two meet on a task neither side transmits. So what has to be pinned is
 *  mostly what must NOT happen:
 *
 *   - no frame -> no half (the reaction path's lesson, social_send_test.c);
 *   - a capped report never reaches the wire, or the reported node stages a
 *     half the reporter will never match;
 *   - a peer may not report on our behalf (the origin guard);
 *   - a block does not stop a report, but it does stop us pairing one FROM the
 *     peer we blocked.
 *
 *  The task is checked against an INDEPENDENT derivation of the canonical
 *  form, not against the other side's output: both sides calling the same
 *  helper would agree with each other while both being wrong about the tail.
 *  The cross-language half of that is the conformance corpus
 *  (identity/report-pairs-bilaterally).
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include <jansson.h>
#include <uuid/uuid.h>

#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "identity/id_proc_priv.h"
#include "identity/social_tx.h"
#include "config/configuration.h"
#include "reputation/tx_channel.h"
#include "structures/data.h"
#include "structures/map.h"
#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
#include "utilities/msg_types_priv.h"
#include "utilities/allocation.h"

static char REPORT_FN[] = AT_APP_REPORT_PEER;
static char PEER_REPORT_FN[] = "peer_report";

/* ------------------------------------------------------------------ */
/* Emission capture                                                    */
/* ------------------------------------------------------------------ */

static size_t  g_reports_sent;
static int64_t g_last_seq;
static bool    g_last_had_extra_keys;
static bool    g_network_full;
static bool    g_reputation_full;
static size_t  g_scores_submitted;

static int _hook(const char *key, const message_type_t type,
                 generic_msg_t *msg, bool blocking)
{
    (void)blocking;
    if (g_network_full && key != NULL && strcmp(key, "network") == 0)
        return EAGAIN;
    if (key != NULL && strcmp(key, "reputation") == 0
        && type == TRANSACTION_SCORE) {
        if (g_reputation_full)
            return EAGAIN;
        g_scores_submitted++;
    }
    if (type == NET_MESSAGE && msg->info.net_msg.function != NULL
        && strcmp(msg->info.net_msg.function, PEER_REPORT_FN) == 0) {
        g_reports_sent++;
        json_t *j = NULL;
        if (net_msg_unpack_json(&msg->info.net_msg, &j) == 0 && j != NULL) {
            json_t *js = json_object_get(j, "seq");
            g_last_seq = json_is_integer(js) ? json_integer_value(js) : 0;
            /* {seq, ts} and NOTHING ELSE may travel. */
            g_last_had_extra_keys = json_object_size(j) != 2
                || json_object_get(j, "ts") == NULL;
            json_decref(j);
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Fixtures (same shape as social_send_test.c's)                       */
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
    return proc;
}

static void _add_peer(process_t *proc, identity_t *peer)
{
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(peer, &pub));
    ck_assert_ptr_nonnull(pub);
    memcpy(&proc->protocol.peers[proc->protocol.num_peers], pub,
           sizeof(public_identity_t));
    proc->protocol.num_peers++;
    smrt_deref(pub);
}

static void _uuid_str(const identity_t *who, char out[UUID_STRING_LEN + 1])
{
    uuid_unparse_lower(who->uuid, out);
}

/* Drive AT_APP_REPORT_PEER. @p from is NULL for the local app (from_whom
 * zeroed, as the shim leaves it) or a peer, as the wire would deliver it. */
static void _report(process_t *proc, const identity_t *target,
                    const identity_t *from)
{
    char target_str[UUID_STRING_LEN + 1];
    _uuid_str(target, target_str);
    json_t *p = json_object();
    json_object_set_new(p, "peer", json_string(target_str));
    /* A reason the app might be tempted to pass along. It must go nowhere. */
    json_object_set_new(p, "reason", json_string("harassment"));

    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = REPORT_FN;
    msg.info.net_msg.verified = true;
    if (from != NULL) {
        public_identity_t *pub = NULL;
        ck_assert_ret_ok(identity_publish((identity_t *)from, &pub));
        memcpy(&msg.info.net_msg.from_whom, pub, sizeof(public_identity_t));
        smrt_deref(pub);
    }
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, p));
    json_decref(p);
    run_message_handlers(proc, NULL, NET_MESSAGE, &msg);
}

/* Deliver an inbound peer_report {seq, ts} from @p reporter. */
static void _receive_report(process_t *proc, const identity_t *reporter,
                            int64_t seq)
{
    json_t *p = json_object();
    json_object_set_new(p, "seq", json_integer(seq));
    json_object_set_new(p, "ts", json_real(1758500000.0));

    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = PEER_REPORT_FN;
    msg.info.net_msg.verified = true;
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish((identity_t *)reporter, &pub));
    memcpy(&msg.info.net_msg.from_whom, pub, sizeof(public_identity_t));
    smrt_deref(pub);
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, p));
    json_decref(p);
    run_message_handlers(proc, NULL, NET_MESSAGE, &msg);
}

/* The canonical report task, derived HERE rather than through id_proc.c:
 * domain "agora-report", reporter_uuid[16] || seq u64le as the tail. */
static void _expected_task(const identity_t *reporter, const identity_t *reported,
                           int64_t seq, char out[UUID_STRING_LEN + 1])
{
    uint8_t tail[24];
    memcpy(tail, reporter->uuid, 16);
    for (int i = 0; i < 8; i++)
        tail[16 + i] = (uint8_t)(((uint64_t)seq >> (8 * i)) & 0xFF);
    uuid_t task;
    ck_assert_ret_ok(at_social_task_uuid(AT_SOCIAL_DOMAIN_REPORT, reporter->uuid,
                                         reported->uuid, tail, sizeof(tail),
                                         task));
    uuid_unparse_lower(task, out);
}

typedef struct {
    bool   have;
    char   task[UUID_STRING_LEN + 1];
    double score;
    char   channel[TX_CHANNEL_NAMELEN + 1];
    int    n;
} staged_t;

static staged_t _staged_about(const identity_t *subject)
{
    staged_t st;
    memset(&st, 0, sizeof(st));
    char subj[UUID_STRING_LEN + 1];
    _uuid_str(subject, subj);
    st.have = identity_get_last_social_tx(subj, st.task, &st.score);
    if (st.have)
        identity_get_social_tx_detail(subj, st.channel, sizeof(st.channel),
                                      &st.n);
    return st;
}

static void _begin(void)
{
    identity_reset_state();
    g_reports_sent = 0;
    g_last_seq = 0;
    g_last_had_extra_keys = false;
    g_network_full = false;
    g_reputation_full = false;
    g_scores_submitted = 0;
    messaging_set_test_hook(_hook);
}

static void _end(void) { messaging_set_test_hook(NULL); g_network_full = false; }

/* ------------------------------------------------------------------ */
/* Reporter side                                                       */
/* ------------------------------------------------------------------ */

DEFINE_TEST(test_a_report_goes_out_and_stages_a_first_person_score)
{
    _begin();
    identity_t *me = _mk_identity("self", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    process_t *proc = _mk_process(me);
    _add_peer(proc, bob);

    _report(proc, bob, NULL);

    ck_assert_int_eq(g_reports_sent, 1);
    ck_assert(!g_last_had_extra_keys);   /* no reason on the wire */
    staged_t st = _staged_about(bob);
    ck_assert(st.have);
    ck_assert_double_eq_tol(st.score, AT_SOCIAL_REPORT_SCORE, 1e-9);
    ck_assert_str_eq(st.channel, TX_CHANNEL_FIRST_PERSON);
    ck_assert_int_eq(st.n, 1);
    char want[UUID_STRING_LEN + 1];
    _expected_task(me, bob, g_last_seq, want);
    ck_assert_str_eq(st.task, want);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_second_report_the_same_day_never_reaches_the_wire)
{
    /* Refused BEFORE the send. Sent-and-unscored would be worse than
     * nothing: the reported node would stage a half we never match. */
    _begin();
    identity_t *me = _mk_identity("self", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    identity_t *carol = _mk_identity("carol", "10.0.0.3");
    process_t *proc = _mk_process(me);
    _add_peer(proc, bob);
    _add_peer(proc, carol);

    _report(proc, bob, NULL);
    _report(proc, bob, NULL);
    ck_assert_int_eq(g_reports_sent, 1);
    ck_assert_int_eq(_staged_about(bob).n, 1);

    /* The cap is per TARGET: carol is still reportable the same day. */
    _report(proc, carol, NULL);
    ck_assert_int_eq(g_reports_sent, 2);
    ck_assert(_staged_about(carol).have);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_peer_may_not_report_on_our_behalf)
{
    _begin();
    identity_t *me = _mk_identity("self", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    identity_t *meddler = _mk_identity("meddler", "10.0.0.3");
    process_t *proc = _mk_process(me);
    _add_peer(proc, bob);
    _add_peer(proc, meddler);

    _report(proc, bob, meddler);

    ck_assert_int_eq(g_reports_sent, 0);
    ck_assert(!_staged_about(bob).have);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_block_does_not_stop_a_report)
{
    /* Two verbs, not one: "Block · Both" in the app must work whichever it
     * sends first. The block gate in _social_accrue is for peers we have told
     * nothing; a report tells them. */
    _begin();
    identity_t *me = _mk_identity("self", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    process_t *proc = _mk_process(me);
    _add_peer(proc, bob);
    char bob_str[UUID_STRING_LEN + 1];
    _uuid_str(bob, bob_str);
    identity_block_peer(bob_str);

    _report(proc, bob, NULL);

    ck_assert_int_eq(g_reports_sent, 1);
    ck_assert_double_eq_tol(_staged_about(bob).score, AT_SOCIAL_REPORT_SCORE,
                            1e-9);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_unsent_report_is_not_scored)
{
    _begin();
    identity_t *me = _mk_identity("self", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    process_t *proc = _mk_process(me);
    _add_peer(proc, bob);
    g_network_full = true;

    _report(proc, bob, NULL);

    ck_assert(!_staged_about(bob).have);
    /* And the failed attempt spent nothing: once the queue drains the
     * operator can report after all. */
    g_network_full = false;
    _report(proc, bob, NULL);
    ck_assert_int_eq(g_reports_sent, 1);
    ck_assert(_staged_about(bob).have);
    _end();
}
END_TEST_DEFINITION()

/* ------------------------------------------------------------------ */
/* Reported side                                                       */
/* ------------------------------------------------------------------ */

DEFINE_TEST(test_the_reported_node_stages_the_neutral_half)
{
    _begin();
    identity_t *me = _mk_identity("self", "10.0.0.1");
    identity_t *ada = _mk_identity("ada", "10.0.0.2");
    process_t *proc = _mk_process(me);
    _add_peer(proc, ada);

    _receive_report(proc, ada, 7);

    staged_t st = _staged_about(ada);
    ck_assert(st.have);
    ck_assert_double_eq_tol(st.score, AT_SOCIAL_REPORTER_SCORE, 1e-9);
    /* Not first_person: this is not the reported node's account of anything. */
    ck_assert_str_eq(st.channel, TX_CHANNEL_DEFAULT);
    /* The SAME task ada derived when she sent seq 7 — which is what makes the
     * two halves one transaction. Reporter first in the tail. */
    char want[UUID_STRING_LEN + 1];
    _expected_task(ada, me, 7, want);
    ck_assert_str_eq(st.task, want);
    ck_assert_int_eq(g_reports_sent, 0);   /* nothing sent back */
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_reported_side_pairs_one_report_per_reporter_per_day)
{
    /* The only bound on a FORKED reporter, whose own caps are whatever it
     * says. Fresh seqs, so this is the cap and not the replay guard. */
    _begin();
    identity_t *me = _mk_identity("self", "10.0.0.1");
    identity_t *ada = _mk_identity("ada", "10.0.0.2");
    identity_t *carol = _mk_identity("carol", "10.0.0.3");
    process_t *proc = _mk_process(me);
    _add_peer(proc, ada);
    _add_peer(proc, carol);

    _receive_report(proc, ada, 7);
    _receive_report(proc, ada, 8);
    ck_assert_int_eq(_staged_about(ada).n, 1);

    _receive_report(proc, carol, 1);   /* per reporter, not per day overall */
    ck_assert(_staged_about(carol).have);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_replayed_report_is_refused_by_freshness)
{
    /* The daily cap would refuse a second report anyway, so the observable is
     * the freshness refusal tally for this verb — otherwise the test could not
     * tell the replay guard from the cap. */
    _begin();
    identity_t *me = _mk_identity("self", "10.0.0.1");
    identity_t *ada = _mk_identity("ada", "10.0.0.2");
    process_t *proc = _mk_process(me);
    _add_peer(proc, ada);
    int64_t before = identity_freshness_refusals(PEER_REPORT_FN);

    _receive_report(proc, ada, 7);
    _receive_report(proc, ada, 7);

    ck_assert_int_eq(identity_freshness_refusals(PEER_REPORT_FN), before + 1);
    ck_assert_int_eq(_staged_about(ada).n, 1);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_report_from_a_peer_we_blocked_is_dropped)
{
    _begin();
    identity_t *me = _mk_identity("self", "10.0.0.1");
    identity_t *ada = _mk_identity("ada", "10.0.0.2");
    process_t *proc = _mk_process(me);
    _add_peer(proc, ada);
    char ada_str[UUID_STRING_LEN + 1];
    _uuid_str(ada, ada_str);
    identity_block_peer(ada_str);

    _receive_report(proc, ada, 7);

    ck_assert(!_staged_about(ada).have);
    _end();
}
END_TEST_DEFINITION()

/* Let the reputation "queue" drain partway through the bounded retry. */
static void *_relent_reputation(void *unused)
{
    (void)unused;
    usleep(60000);
    g_reputation_full = false;
    return NULL;
}

DEFINE_TEST(test_our_half_survives_a_briefly_full_reputation_queue)
{
    /* The moderation cohort (run 8, 2026-09-23): ada's reputation queue was
     * full of catch-up traffic, the single send of her 0.15 half failed, and
     * the report still went out, so bob staged a half that could never pair.
     * A queue that drains within the retry window must not lose the half. */
    _begin();
    identity_t *me = _mk_identity("self", "10.0.0.1");
    identity_t *bob = _mk_identity("bob", "10.0.0.2");
    process_t *proc = _mk_process(me);
    _add_peer(proc, bob);

    g_reputation_full = true;
    pthread_t drainer;
    pthread_create(&drainer, NULL, _relent_reputation, NULL);
    _report(proc, bob, NULL);
    pthread_join(drainer, NULL);

    ck_assert_int_eq(g_reports_sent, 1);
    ck_assert_int_eq(g_scores_submitted, 1);
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(Report,
          test_a_report_goes_out_and_stages_a_first_person_score,
          test_a_second_report_the_same_day_never_reaches_the_wire,
          test_a_peer_may_not_report_on_our_behalf,
          test_a_block_does_not_stop_a_report,
          test_an_unsent_report_is_not_scored,
          test_the_reported_node_stages_the_neutral_half,
          test_the_reported_side_pairs_one_report_per_reporter_per_day,
          test_a_replayed_report_is_refused_by_freshness,
          test_a_report_from_a_peer_we_blocked_is_dropped,
          test_our_half_survives_a_briefly_full_reputation_queue)
