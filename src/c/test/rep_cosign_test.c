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

/** @file Two ways a live island lost reputation work it had done (2026-09-29).
 *
 *  ISSUES §2.28: every reputation->network send discarded its result, so a
 *  burst past the network queue's 10 frames vanished. Partition cohort
 *  part-3518232 lost bob's whole commit broadcast; ben never held bob's half
 *  and the reaction never went bilateral. State frames now retry; Paxos
 *  chatter still gets one try, because retrying it too starved identity.
 *
 *  ISSUES §2.29: a member co-signed a checkpoint only when its WHOLE window
 *  matched the proposal on arrival, so a signer one entry ahead or behind
 *  declined, and nothing looked again. part-3592107 had four nodes propose the
 *  same root and none finalize. A signer now compares the proposed range, and
 *  parks a proposal it cannot match yet until its chain catches up.
 *
 *  The fixture is rep_commit_retry_test.c's. Mirrors
 *  tests/a_unit/test_repprocess_cosign.py.
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

static char GRANT_FN[]    = "permission granted";
static char ACCEPTED_FN[] = "tx accepted";
static char PROPOSE_FN[]  = "checkpoint propose";

#define REQUEST_VERB "ask permission"
#define COMMIT_VERB  "tx committed"
#define SIGN_VERB    "checkpoint sign"

/* Far enough past the default checkpoint interval (300 s) to be expired. */
#define LONG_AFTER(t) ((t) + 3600.0)

static size_t  g_commit_count;
static size_t  g_sign_count;
static size_t  g_refuse_commits;   /* EAGAIN this many commit sends first */
static size_t  g_refuse_requests;  /* EAGAIN this many Paxos asks first */
static size_t  g_request_tries;    /* every ask handed to the queue, refused or not */
static int64_t g_req_id1;
static int64_t g_req_id2;
static char    g_req_peer_uuid[UUID_STRING_LEN + 1];
static int64_t g_sign_epoch;

static json_t *_payload_of(const generic_msg_t *msg)
{
    if (msg->info.net_msg.obj == NULL)
        return NULL;
    json_error_t err;
    json_t *p = json_loads((const char *)msg->info.net_msg.obj, 0, &err);
    if (p != NULL && !json_is_object(p)) {
        json_decref(p);
        return NULL;
    }
    return p;
}

static int _capture_hook(const char *key, const message_type_t type,
                         generic_msg_t *msg, bool blocking)
{
    (void)key; (void)blocking;
    if (type != NET_MESSAGE || msg->info.net_msg.function == NULL)
        return 0;
    const char *fn = msg->info.net_msg.function;
    if (strcmp(fn, REQUEST_VERB) == 0) {
        g_request_tries++;
        if (g_refuse_requests > 0) {
            g_refuse_requests--;
            return EAGAIN;
        }
        json_t *p = _payload_of(msg);
        if (p != NULL) {
            g_req_id1 = json_integer_value(json_object_get(p, "id1"));
            g_req_id2 = json_integer_value(json_object_get(p, "id2"));
            const char *u = json_string_value(json_object_get(p, "peer_uuid"));
            snprintf(g_req_peer_uuid, sizeof(g_req_peer_uuid), "%s", u ? u : "");
            json_decref(p);
        }
    } else if (strcmp(fn, COMMIT_VERB) == 0) {
        /* A full network queue, as net.unix.max_dgram_qlen makes it. */
        if (g_refuse_commits > 0) {
            g_refuse_commits--;
            return EAGAIN;
        }
        g_commit_count++;
    } else if (strcmp(fn, SIGN_VERB) == 0) {
        json_t *p = _payload_of(msg);
        if (p != NULL) {
            g_sign_epoch = json_integer_value(json_object_get(p, "epoch"));
            json_decref(p);
        }
        g_sign_count++;
    }
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

static void _begin(void)
{
    ck_assert(sodium_init() >= 0);
    reputation_reset_state(2);
    g_commit_count = g_sign_count = g_refuse_commits = 0;
    g_refuse_requests = g_request_tries = 0;
    g_req_id1 = g_req_id2 = g_sign_epoch = 0;
    g_req_peer_uuid[0] = '\0';
    messaging_set_test_hook(_capture_hook);
}

static void _end(void) { messaging_set_test_hook(NULL); }

typedef struct { identity_t *me, *alice, *bob; process_t *proc; } cohort_t;

static void _cohort(cohort_t *c)
{
    c->me = _mk_identity("me", "10.0.0.1");
    c->alice = _mk_identity("alice", "10.0.0.2");
    c->bob = _mk_identity("bob", "10.0.0.3");
    c->proc = _mk_process(c->me);
    _add_peer(c->proc, c->alice);
    _add_peer(c->proc, c->bob);
}

/* ---- §2.28: a full network queue ---- */

static void _round(cohort_t *c, uuid_t task, char *task_str)
{
    uuid_generate(task);
    uuid_unparse_lower(task, task_str);
    uuid_t subject;
    uuid_clear(subject);
    _forward_transaction(c->proc, task, c->me->uuid, 0.9, "agora-post",
                         NULL, subject, 0.0);
    identity_t *voters[2] = { c->alice, c->bob };
    for (int i = 0; i < 2; i++) {
        json_t *p = json_object();
        json_object_set_new(p, "id1", json_integer(g_req_id1));
        json_object_set_new(p, "id2", json_integer(g_req_id2));
        json_object_set_new(p, "peer_uuid", json_string(g_req_peer_uuid));
        json_object_set_new(p, "last_id", json_integer(0));
        json_object_set_new(p, "chain_len", json_integer(0));
        _dispatch(c->proc, voters[i], GRANT_FN, p);
        json_decref(p);
    }
    for (int i = 0; i < 2; i++) {
        json_t *p = json_object();
        json_object_set_new(p, "id1", json_integer(g_req_id1));
        json_object_set_new(p, "id2", json_integer(g_req_id2));
        json_object_set_new(p, "peer_uuid", json_string(g_req_peer_uuid));
        json_object_set_new(p, "task_uuid", json_string(task_str));
        _dispatch(c->proc, voters[i], ACCEPTED_FN, p);
        json_decref(p);
    }
}

/* THE REGRESSION (part-3518232): the queue refuses the first sends of the
 * commit broadcast. Every peer must still get it. */
DEFINE_TEST(test_a_commit_broadcast_survives_a_full_network_queue)
{
    _begin();
    cohort_t c;
    _cohort(&c);
    uuid_t task;
    char task_str[UUID_STRING_LEN + 1];
    g_refuse_commits = 3;
    _round(&c, task, task_str);
    ck_assert_int_eq(reputation_get_chain_len(), 1);
    ck_assert_uint_eq(g_commit_count, 2);   /* one per peer, none lost */
    ck_assert_uint_eq(g_refuse_commits, 0);
    _end();
}
END_TEST_DEFINITION()

/* A queue wedged past the inline tries: the first commit is KEPT for this
 * process's tick and the second waits behind it (ISSUES §2.14); both land,
 * once each, when the queue drains. Until then each was given up on after
 * ten tries. */
DEFINE_TEST(test_a_wedged_network_queue_keeps_the_commits_for_the_tick)
{
    _begin();
    cohort_t c;
    _cohort(&c);
    uuid_t task;
    char task_str[UUID_STRING_LEN + 1];
    g_refuse_commits = 1000;
    _round(&c, task, task_str);
    ck_assert_int_eq(reputation_get_chain_len(), 1);  /* the commit stands */
    ck_assert_uint_eq(g_commit_count, 0);
    ck_assert_uint_eq(at_send_retry_pending("network"), 2);
    g_refuse_commits = 0;                             /* the queue drains */
    ck_assert_uint_eq(at_send_retry_drain(NULL, NULL, (double)time(NULL)), 2);
    ck_assert_uint_eq(g_commit_count, 2);
    ck_assert_uint_eq(at_send_retry_pending("network"), 0);
    _end();
}
END_TEST_DEFINITION()

/* Paxos chatter gets ONE try (part-3614473): retrying it kept the network
 * queue full for seconds and starved identity's hand-offs. The protocol
 * re-sends it, so a full queue costs nothing but that round. */
DEFINE_TEST(test_paxos_chatter_is_not_retried)
{
    _begin();
    cohort_t c;
    _cohort(&c);
    uuid_t task, subject;
    uuid_generate(task);
    uuid_clear(subject);
    g_refuse_requests = 100;
    _forward_transaction(c.proc, task, c.me->uuid, 0.9, "agora-post",
                         NULL, subject, 0.0);
    ck_assert_uint_eq(g_request_tries, 2);   /* one per peer, no retries */
    _end();
}
END_TEST_DEFINITION()

/* ---- §2.29: the co-sign rule ---- */

/* Stage @p n committed entries on our own chain, deterministic per index so
 * two calls with the same n build the same chain. */
static void _chain(identity_t *a, identity_t *b, int from, int n,
                   const char *salt)
{
    for (int i = from; i < from + n; i++) {
        char name[64];
        snprintf(name, sizeof(name), "%s-%d", salt, i);
        uuid_t task;
        uuid_generate_sha1(task, a->uuid, name, strlen(name));
        reputation_install_tx_pair(task, a->uuid, 0.8, b->uuid, 0.7);
    }
}

static void _propose(cohort_t *c, const char *root, int64_t epoch,
                     int first_index, int count)
{
    char proposer[UUID_STRING_LEN + 1];
    uuid_unparse_lower(c->alice->uuid, proposer);
    json_t *p = json_object();
    json_object_set_new(p, "proposer_uuid", json_string(proposer));
    json_object_set_new(p, "root", json_string(root));
    json_object_set_new(p, "epoch", json_integer(epoch));
    json_object_set_new(p, "first_index", json_integer(first_index));
    json_object_set_new(p, "count", json_integer(count));
    _dispatch(c->proc, c->alice, PROPOSE_FN, p);
    json_decref(p);
}

/* The root alice proposes: her window after the first three entries. */
static void _root_of_three(cohort_t *c, char root[TX_HASH_HEX_LEN + 1])
{
    reputation_reset_state(2);
    _chain(c->alice, c->bob, 0, 3, "t");
    reputation_get_window_root(root);
    ck_assert_uint_eq(strlen(root), TX_HASH_HEX_LEN);
    reputation_reset_state(2);
}

/* THE REGRESSION (part-3592107): our chain ran one entry past the proposal.
 * The range matches, so we sign; the whole window would not have. */
DEFINE_TEST(test_a_signer_ahead_of_the_proposal_signs_its_range)
{
    _begin();
    cohort_t c;
    _cohort(&c);
    char root[TX_HASH_HEX_LEN + 1];
    _root_of_three(&c, root);
    _chain(c.alice, c.bob, 0, 4, "t");
    char whole[TX_HASH_HEX_LEN + 1];
    reputation_get_window_root(whole);
    ck_assert(strcmp(whole, root) != 0);      /* the old rule would decline */

    _propose(&c, root, 7, 0, 3);
    ck_assert_uint_eq(g_sign_count, 1);
    ck_assert_int_eq(g_sign_epoch, 7);
    ck_assert_uint_eq(reputation_parked_cosign_count(), 0);
    _end();
}
END_TEST_DEFINITION()

/* A signer BEHIND the proposal cannot sign yet; it parks the proposal and signs
 * on the first pass after its chain holds the range. */
DEFINE_TEST(test_a_signer_behind_signs_once_it_catches_up)
{
    _begin();
    cohort_t c;
    _cohort(&c);
    char root[TX_HASH_HEX_LEN + 1];
    _root_of_three(&c, root);
    _chain(c.alice, c.bob, 0, 2, "t");
    double now = (double)time(NULL);

    _propose(&c, root, 7, 0, 3);
    ck_assert_uint_eq(g_sign_count, 0);
    ck_assert_uint_eq(reputation_parked_cosign_count(), 1);

    /* Still behind: nothing. */
    ck_assert_uint_eq(_recheck_parked_cosigns(c.proc, now), 0);
    ck_assert_uint_eq(g_sign_count, 0);

    /* Caught up, and past it: signed, and no longer parked. */
    _chain(c.alice, c.bob, 2, 2, "t");
    ck_assert_uint_eq(_recheck_parked_cosigns(c.proc, now), 1);
    ck_assert_uint_eq(g_sign_count, 1);
    ck_assert_int_eq(g_sign_epoch, 7);
    ck_assert_uint_eq(reputation_parked_cosign_count(), 0);

    /* Once only. */
    ck_assert_uint_eq(_recheck_parked_cosigns(c.proc, now), 0);
    ck_assert_uint_eq(g_sign_count, 1);
    _end();
}
END_TEST_DEFINITION()

/* A range we hold but that hashes differently is not signed -- the range rule
 * is not a looser rule. It stays parked, because an adoption can still rewrite
 * those entries, and it expires with the interval. */
DEFINE_TEST(test_a_diverged_range_is_never_signed_and_expires)
{
    _begin();
    cohort_t c;
    _cohort(&c);
    char root[TX_HASH_HEX_LEN + 1];
    _root_of_three(&c, root);
    _chain(c.alice, c.bob, 0, 4, "other");
    double now = (double)time(NULL);

    _propose(&c, root, 7, 0, 3);
    ck_assert_uint_eq(g_sign_count, 0);
    ck_assert_uint_eq(reputation_parked_cosign_count(), 1);
    ck_assert_uint_eq(_recheck_parked_cosigns(c.proc, now), 0);
    ck_assert_uint_eq(g_sign_count, 0);

    ck_assert_uint_eq(_recheck_parked_cosigns(c.proc, LONG_AFTER(now)), 0);
    ck_assert_uint_eq(reputation_parked_cosign_count(), 0);
    ck_assert_uint_eq(g_sign_count, 0);
    _end();
}
END_TEST_DEFINITION()

/* One slot per proposer: a newer epoch replaces the older one, and a late copy
 * of the older one does not bring it back. */
DEFINE_TEST(test_a_proposers_newer_epoch_replaces_its_parked_one)
{
    _begin();
    cohort_t c;
    _cohort(&c);
    char root[TX_HASH_HEX_LEN + 1];
    _root_of_three(&c, root);
    double now = (double)time(NULL);

    _propose(&c, root, 7, 0, 3);
    _propose(&c, root, 8, 0, 3);
    _propose(&c, root, 7, 0, 3);
    ck_assert_uint_eq(reputation_parked_cosign_count(), 1);

    _chain(c.alice, c.bob, 0, 3, "t");
    ck_assert_uint_eq(_recheck_parked_cosigns(c.proc, now), 1);
    ck_assert_int_eq(g_sign_epoch, 8);
    _end();
}
END_TEST_DEFINITION()

/* Control: an exact whole-window match signs on arrival and parks nothing,
 * as it always did. */
DEFINE_TEST(test_an_exact_window_match_signs_on_arrival)
{
    _begin();
    cohort_t c;
    _cohort(&c);
    char root[TX_HASH_HEX_LEN + 1];
    _root_of_three(&c, root);
    _chain(c.alice, c.bob, 0, 3, "t");
    _propose(&c, root, 7, 0, 3);
    ck_assert_uint_eq(g_sign_count, 1);
    ck_assert_uint_eq(reputation_parked_cosign_count(), 0);
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(RepCosign,
          test_a_commit_broadcast_survives_a_full_network_queue,
          test_a_wedged_network_queue_keeps_the_commits_for_the_tick,
          test_paxos_chatter_is_not_retried,
          test_a_signer_ahead_of_the_proposal_signs_its_range,
          test_a_signer_behind_signs_once_it_catches_up,
          test_a_diverged_range_is_never_signed_and_expires,
          test_a_proposers_newer_epoch_replaces_its_parked_one,
          test_an_exact_window_match_signs_on_arrival)
