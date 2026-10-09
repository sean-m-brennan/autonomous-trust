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

/** @file OUR half of a task is followed until it is in the chain (ISSUES §2.24).
 *
 *  Two ways a round used to vanish with nobody noticing: a GRANTED round leaves
 *  my_requests when its transaction goes out, so if the acceptors never commit
 *  it the half is gone; and a round nobody answers gets no nack, so the nack
 *  retry never fires. Partition cohort part-3490610 lost island B's app
 *  reaction the first way. _retry_uncommitted_halves re-proposes either, keyed
 *  by task, and parks what outlives the retries until the chain grows from a
 *  peer (§2.60). The fixture is rep_paxos_round_test.c's (that file is at the
 *  RUN_TESTS cap). Mirrors tests/a_unit/test_repprocess_commit_retry.py.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

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
#include "utilities/msg_types.h"
#include "utilities/msg_types_priv.h"
#include "utilities/allocation.h"

static char GRANT_FN[]    = "permission granted";
static char ACCEPTED_FN[] = "tx accepted";

#define REQUEST_VERB "ask permission"
#define TX_VERB      "transaction"

/* Far enough past any default timeout to make "overdue" unambiguous. */
#define LATER(n) ((double)time(NULL) + 60.0 * (n))

static size_t  g_request_count;
static size_t  g_tx_count;
static int64_t g_req_id1;
static int64_t g_req_id2;
static char    g_req_peer_uuid[UUID_STRING_LEN + 1];

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
        json_t *p = _payload_of(msg);
        if (p != NULL) {
            g_req_id1 = json_integer_value(json_object_get(p, "id1"));
            g_req_id2 = json_integer_value(json_object_get(p, "id2"));
            const char *u = json_string_value(json_object_get(p, "peer_uuid"));
            snprintf(g_req_peer_uuid, sizeof(g_req_peer_uuid), "%s", u ? u : "");
            json_decref(p);
        }
        g_request_count++;
    } else if (strcmp(fn, TX_VERB) == 0) {
        g_tx_count++;
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

/* Grant the round the proposer opened most recently, as handle_request does. */
static void _grant(process_t *proc, identity_t *voter)
{
    json_t *p = json_object();
    json_object_set_new(p, "id1", json_integer(g_req_id1));
    json_object_set_new(p, "id2", json_integer(g_req_id2));
    json_object_set_new(p, "peer_uuid", json_string(g_req_peer_uuid));
    json_object_set_new(p, "last_id", json_integer(0));
    json_object_set_new(p, "chain_len", json_integer(0));
    _dispatch(proc, voter, GRANT_FN, p);
    json_decref(p);
}

/* Accept that round's transaction, as handle_transaction does. */
static void _accept(process_t *proc, identity_t *voter, const char *task_str)
{
    json_t *p = json_object();
    json_object_set_new(p, "id1", json_integer(g_req_id1));
    json_object_set_new(p, "id2", json_integer(g_req_id2));
    json_object_set_new(p, "peer_uuid", json_string(g_req_peer_uuid));
    json_object_set_new(p, "task_uuid", json_string(task_str));
    _dispatch(proc, voter, ACCEPTED_FN, p);
    json_decref(p);
}

static void _begin(void)
{
    ck_assert(sodium_init() >= 0);
    reputation_reset_state(2);
    g_request_count = g_tx_count = 0;
    g_req_id1 = g_req_id2 = 0;
    g_req_peer_uuid[0] = '\0';
    messaging_set_test_hook(_capture_hook);
}

static void _end(void) { messaging_set_test_hook(NULL); }

/* Two peers, sized live as Python sizes them: one grant carries the round
 * (`>= 2 // 2`), and both must accept (`> 2 // 2`). */
typedef struct { identity_t *me, *alice, *bob; process_t *proc;
                 uuid_t task; char task_str[UUID_STRING_LEN + 1]; } cohort_t;

static void _cohort(cohort_t *c)
{
    c->me = _mk_identity("me", "10.0.0.1");
    c->alice = _mk_identity("alice", "10.0.0.2");
    c->bob = _mk_identity("bob", "10.0.0.3");
    c->proc = _mk_process(c->me);
    _add_peer(c->proc, c->alice);
    _add_peer(c->proc, c->bob);
    uuid_generate(c->task);
    uuid_unparse_lower(c->task, c->task_str);
}

static void _propose(cohort_t *c)
{
    uuid_t subject;
    uuid_clear(subject);
    _forward_transaction(c->proc, c->task, c->me->uuid, 0.9, "agora-post",
                         NULL, subject, 0.0);
}

/* THE REGRESSION (part-3490610): granted, transaction out, never accepted.
 * Before, nothing ever looked at it again. */
DEFINE_TEST(test_a_granted_round_that_never_commits_is_re_proposed)
{
    _begin();
    cohort_t c;
    _cohort(&c);
    _propose(&c);
    int64_t first_id1 = g_req_id1;
    _grant(c.proc, c.alice);
    _grant(c.proc, c.bob);
    ck_assert_uint_eq(g_tx_count, 2);        /* the transaction went out */
    ck_assert_uint_eq(reputation_awaiting_commit_count(), 1);

    /* Not overdue yet: nothing happens. */
    g_request_count = 0;
    _retry_uncommitted_halves(c.proc, (double)time(NULL));
    ck_assert_uint_eq(g_request_count, 0);

    /* Overdue: a fresh round for the same task. */
    _retry_uncommitted_halves(c.proc, LATER(1));
    ck_assert_uint_eq(g_request_count, 2);
    ck_assert(g_req_id1 >= first_id1);
    ck_assert_uint_eq(reputation_awaiting_commit_count(), 1);

    /* ...and it is a real round: granted and accepted, the half commits and
     * is no longer watched. */
    _grant(c.proc, c.alice);
    _grant(c.proc, c.bob);
    _accept(c.proc, c.alice, c.task_str);
    _accept(c.proc, c.bob, c.task_str);
    ck_assert_int_eq(reputation_get_chain_len(), 1);
    ck_assert_uint_eq(reputation_awaiting_commit_count(), 0);

    g_request_count = 0;
    _retry_uncommitted_halves(c.proc, LATER(2));
    ck_assert_uint_eq(g_request_count, 0);
    _end();
}
END_TEST_DEFINITION()

/* Control: a half that committed normally is never re-proposed. */
DEFINE_TEST(test_a_committed_half_is_left_alone)
{
    _begin();
    cohort_t c;
    _cohort(&c);
    _propose(&c);
    _grant(c.proc, c.alice);
    _grant(c.proc, c.bob);
    _accept(c.proc, c.alice, c.task_str);
    _accept(c.proc, c.bob, c.task_str);
    ck_assert_uint_eq(reputation_awaiting_commit_count(), 0);

    g_request_count = 0;
    _retry_uncommitted_halves(c.proc, LATER(1));
    ck_assert_uint_eq(g_request_count, 0);
    _end();
}
END_TEST_DEFINITION()

/* A round nobody answered: no grant, no nack. Re-proposed, and the stale
 * ballot is retired, so a grant that turns up late for it goes nowhere. */
DEFINE_TEST(test_an_unanswered_round_is_re_proposed_and_its_ballot_retired)
{
    _begin();
    cohort_t c;
    _cohort(&c);
    _propose(&c);
    int64_t stale1 = g_req_id1, stale2 = g_req_id2;
    uuid_t tasks[4];
    double scores[4];
    ck_assert_int_eq(reputation_get_my_request_tasks(tasks, scores, 4), 1);

    _retry_uncommitted_halves(c.proc, LATER(1));
    /* One live round for the task, the new one, not the old one beside it. */
    ck_assert_int_eq(reputation_get_my_request_tasks(tasks, scores, 4), 1);
    ck_assert_int_eq(uuid_compare(tasks[0], c.task), 0);

    /* A late grant for the dead ballot. */
    int64_t fresh1 = g_req_id1, fresh2 = g_req_id2;
    g_req_id1 = stale1; g_req_id2 = stale2;
    g_tx_count = 0;
    _grant(c.proc, c.alice);
    _grant(c.proc, c.bob);
    ck_assert_uint_eq(g_tx_count, 0);
    g_req_id1 = fresh1; g_req_id2 = fresh2;
    _end();
}
END_TEST_DEFINITION()

/* Bounded: a half that never lands is re-proposed REP_COMMIT_RETRIES (5)
 * times, then PARKED (§2.60), not dropped and not churned every 15 s. */
DEFINE_TEST(test_an_exhausted_half_is_parked_not_dropped)
{
    _begin();
    cohort_t c;
    _cohort(&c);
    _propose(&c);
    g_request_count = 0;
    for (int i = 1; i <= 6; i++)
        _retry_uncommitted_halves(c.proc, LATER(i));
    /* Five re-proposals, two peers asked each time; the sixth pass parks. */
    ck_assert_uint_eq(g_request_count, 10);
    ck_assert_uint_eq(reputation_awaiting_commit_count(), 1);
    ck_assert_uint_eq(reputation_parked_count(), 1);
    _end();
}
END_TEST_DEFINITION()

/* Contention, not a partition: alice (with us, a majority of three) is
 * reachable and the half still never committed. Given up as before §2.60, not
 * parked: parked contention losers swamped the heal in part-2123724. */
DEFINE_TEST(test_a_half_a_majority_reached_is_dropped_not_parked)
{
    _begin();
    cohort_t c;
    _cohort(&c);
    _propose(&c);
    for (int i = 1; i <= 6; i++) {
        reputation_note_heard(c.alice->uuid, LATER(i));
        _retry_uncommitted_halves(c.proc, LATER(i));
    }
    ck_assert_uint_eq(reputation_parked_count(), 0);
    ck_assert_uint_eq(reputation_awaiting_commit_count(), 0);
    _end();
}
END_TEST_DEFINITION()

/* THE REGRESSION (part-2136648): reach is any frame from the peer, not an
 * answer to one of the half's own rounds. A grant that arrives for a ballot
 * the retry already retired lands nowhere, and counting those parked a whole
 * connected group's contention losers. Here nothing answers a live round;
 * alice is merely heard, late, and that is enough. */
DEFINE_TEST(test_a_peer_heard_on_a_retired_ballot_still_counts)
{
    _begin();
    cohort_t c;
    _cohort(&c);
    _propose(&c);
    int64_t stale1 = g_req_id1, stale2 = g_req_id2;
    for (int i = 1; i <= 5; i++)
        _retry_uncommitted_halves(c.proc, LATER(i));
    g_req_id1 = stale1; g_req_id2 = stale2;
    _grant(c.proc, c.alice);               /* for a retired ballot */
    reputation_note_heard(c.alice->uuid, LATER(6));
    _retry_uncommitted_halves(c.proc, LATER(6));
    ck_assert_uint_eq(reputation_parked_count(), 0);
    _end();
}
END_TEST_DEFINITION()

/* The minority side of a partition: of five, only alice is reachable (two of
 * five, counting us), and whoever was heard before the split is stale. */
DEFINE_TEST(test_a_minority_island_parks_its_half)
{
    _begin();
    cohort_t c;
    _cohort(&c);
    identity_t *carol = _mk_identity("carol", "10.0.0.4");
    identity_t *dave = _mk_identity("dave", "10.0.0.5");
    _add_peer(c.proc, carol);
    _add_peer(c.proc, dave);
    _propose(&c);
    /* Everyone answered before the split, four timeouts back... */
    reputation_note_heard(c.bob->uuid, LATER(5));
    reputation_note_heard(carol->uuid, LATER(5));
    reputation_note_heard(dave->uuid, LATER(5));
    for (int i = 1; i <= 6; i++) {
        /* ...and only alice since. */
        reputation_note_heard(c.alice->uuid, LATER(i));
        _retry_uncommitted_halves(c.proc, LATER(i));
    }
    ck_assert_uint_eq(reputation_parked_count(), 1);
    _end();
}
END_TEST_DEFINITION()

/* Park the half, as the minority side of a partition does: five unanswered
 * re-proposals, parked on the sixth pass at LATER(6). */
static void _park(cohort_t *c)
{
    _propose(c);
    for (int i = 1; i <= 6; i++)
        _retry_uncommitted_halves(c->proc, LATER(i));
    ck_assert_uint_eq(reputation_parked_count(), 1);
    g_request_count = 0;
}

/* A parked half is re-proposed once every REP_PARK_RETRY (120 s), and stays
 * parked: the 15 s churn does not restart. */
DEFINE_TEST(test_a_parked_half_is_re_proposed_every_park_retry)
{
    _begin();
    cohort_t c;
    _cohort(&c);
    _park(&c);
    _retry_uncommitted_halves(c.proc, LATER(7));      /* 60 s parked */
    ck_assert_uint_eq(g_request_count, 0);
    _retry_uncommitted_halves(c.proc, LATER(8));      /* 120 s: due */
    ck_assert_uint_eq(g_request_count, 2);
    ck_assert_uint_eq(reputation_parked_count(), 1);
    _retry_uncommitted_halves(c.proc, LATER(9));      /* 60 s after that */
    ck_assert_uint_eq(g_request_count, 2);
    _retry_uncommitted_halves(c.proc, LATER(10));
    ck_assert_uint_eq(g_request_count, 4);
    _end();
}
END_TEST_DEFINITION()

/* THE HEAL (§2.60): the minority's chain is a strict prefix of the majority's,
 * so the heal arrives as an EXTENDED catch-up. That wakes the parked half at
 * once rather than at its next slow retry. */
/* alice sends a chain of @p n entries, unrelated tasks she committed with bob,
 * as the majority island's does at the heal. */
static void _catch_up(cohort_t *c, int n)
{
    tx_history_t theirs;
    ck_assert_ret_ok(tx_history_init(&theirs));
    for (int i = 0; i < n; i++) {
        uuid_t other;
        uuid_generate(other);
        ck_assert_ret_ok(tx_history_update(&theirs, other, c->alice->uuid, 0.8,
                                           NULL));
        ck_assert_ret_ok(tx_history_update(&theirs, other, c->bob->uuid, 0.7,
                                           NULL));
    }
    json_t *chain = NULL;
    ck_assert_ret_ok(tx_history_era_to_json(&theirs, 0, tx_history_len(&theirs),
                                            &chain));
    _dispatch(c->proc, c->alice, REP_PROTO_UPDATE, chain);
    json_decref(chain);
    tx_history_free(&theirs);
}

DEFINE_TEST(test_a_grown_chain_wakes_parked_halves)
{
    _begin();
    cohort_t c;
    _cohort(&c);
    _park(&c);
    _catch_up(&c, 1);

    /* Not at once: the last round has its COMMIT_TIMEOUT first. */
    _retry_uncommitted_halves(c.proc, (double)time(NULL));
    ck_assert_uint_eq(g_request_count, 0);
    /* LATER(7) is 60 s before the slow retry: only the wake makes it due. */
    _retry_uncommitted_halves(c.proc, LATER(7));
    ck_assert_uint_eq(g_request_count, 2);
    _end();
}
END_TEST_DEFINITION()

/* A wake UNPARKS (part-2272442): the half is active again, with
 * REP_WAKE_RETRIES (10) fresh retries, and with a majority now reachable it is
 * given up after them as a contention loser. Left parked, every chain growth
 * after the heal re-sent the island's whole backlog. */
DEFINE_TEST(test_a_woken_half_is_unparked_with_fresh_retries)
{
    _begin();
    cohort_t c;
    _cohort(&c);
    _park(&c);
    _catch_up(&c, 1);
    _retry_uncommitted_halves(c.proc, LATER(7));
    ck_assert_uint_eq(reputation_parked_count(), 0);
    ck_assert_uint_eq(reputation_awaiting_commit_count(), 1);
    /* A second growth leaves it unparked, with its count running. */
    _catch_up(&c, 2);
    ck_assert_uint_eq(reputation_parked_count(), 0);
    g_request_count = 0;
    /* Nine more retries (ten in all since the wake), then given up. */
    for (int i = 8; i <= 17; i++) {
        reputation_note_heard(c.alice->uuid, LATER(i));
        _retry_uncommitted_halves(c.proc, LATER(i));
    }
    ck_assert_uint_eq(g_request_count, 18);
    ck_assert_uint_eq(reputation_awaiting_commit_count(), 0);
    _end();
}
END_TEST_DEFINITION()

/* A parked half is given up after REP_PARK_TTL (a day), and one that turns
 * up in the chain meanwhile is forgotten. */
DEFINE_TEST(test_a_parked_half_expires_or_is_forgotten)
{
    _begin();
    cohort_t c;
    _cohort(&c);
    _park(&c);
    _retry_uncommitted_halves(c.proc, LATER(6) + 86400.0 + 60.0);
    ck_assert_uint_eq(g_request_count, 0);
    ck_assert_uint_eq(reputation_awaiting_commit_count(), 0);

    uuid_generate(c.task);
    uuid_unparse_lower(c.task, c.task_str);
    _park(&c);
    reputation_install_tx_single(c.task, c.me->uuid, 0.9);
    _retry_uncommitted_halves(c.proc, LATER(8));
    ck_assert_uint_eq(g_request_count, 0);
    ck_assert_uint_eq(reputation_awaiting_commit_count(), 0);
    _end();
}
END_TEST_DEFINITION()

/* Our half turned up inside a chain we adopted (or anyone else's commit put it
 * there): forgotten, not re-proposed. */
DEFINE_TEST(test_a_half_already_in_the_chain_is_forgotten)
{
    _begin();
    cohort_t c;
    _cohort(&c);
    _propose(&c);
    reputation_install_tx_single(c.task, c.me->uuid, 0.9);

    g_request_count = 0;
    _retry_uncommitted_halves(c.proc, LATER(1));
    ck_assert_uint_eq(g_request_count, 0);
    ck_assert_uint_eq(reputation_awaiting_commit_count(), 0);
    _end();
}
END_TEST_DEFINITION()

/* A NEW probe half (an "at." capability), through the same gate the local
 * TRANSACTION_SCORE handler uses. Returns whether it was admitted. */
static bool _probe(cohort_t *c, uuid_t task)
{
    uuid_generate(task);
    if (!_admit_new_half(c->proc, task, "at.handshake"))
        return false;
    uuid_t subject;
    uuid_clear(subject);
    _forward_transaction(c->proc, task, c->me->uuid, 0.9, "at.handshake",
                         NULL, subject, 0.0);
    return true;
}

/* PROBE BACKPRESSURE (part-2314213): at most AT_REP_MAX_PROBE_HALVES (4)
 * probe halves are followed at once; the fifth is dropped. An app half is
 * never capped. */
DEFINE_TEST(test_probe_halves_are_capped_app_halves_are_not)
{
    _begin();
    cohort_t c;
    _cohort(&c);
    uuid_t t;
    for (int i = 0; i < 4; i++)
        ck_assert(_probe(&c, t));
    ck_assert(!_probe(&c, t));
    ck_assert_uint_eq(reputation_awaiting_commit_count(), 4);
    ck_assert(_admit_new_half(c.proc, c.task, "agora-post"));
    ck_assert(_admit_new_half(c.proc, c.task, NULL));
    _end();
}
END_TEST_DEFINITION()

/* While an app half of ours is pending, our probes yield: a new one is
 * dropped, and an overdue one waits, its attempts unspent, until the app half
 * commits. bob's reaction lost 24 rounds in a row to probes in part-2314213. */
DEFINE_TEST(test_probes_yield_to_a_pending_app_half)
{
    _begin();
    cohort_t c;
    _cohort(&c);
    uuid_t probe;
    ck_assert(_probe(&c, probe));
    _propose(&c);                          /* the app half */
    uuid_t t;
    ck_assert(!_probe(&c, t));

    g_request_count = 0;
    _retry_uncommitted_halves(c.proc, LATER(1));
    ck_assert_uint_eq(g_request_count, 2);  /* the app half only */

    _grant(c.proc, c.alice);
    _grant(c.proc, c.bob);
    _accept(c.proc, c.alice, c.task_str);
    _accept(c.proc, c.bob, c.task_str);
    ck_assert_uint_eq(reputation_awaiting_commit_count(), 1);

    g_request_count = 0;
    _retry_uncommitted_halves(c.proc, LATER(2));
    ck_assert_uint_eq(g_request_count, 2);  /* now the probe goes */
    ck_assert(_probe(&c, t));
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(RepCommitRetry,
          test_a_granted_round_that_never_commits_is_re_proposed,
          test_a_committed_half_is_left_alone,
          test_an_unanswered_round_is_re_proposed_and_its_ballot_retired,
          test_an_exhausted_half_is_parked_not_dropped,
          test_a_parked_half_is_re_proposed_every_park_retry,
          test_a_grown_chain_wakes_parked_halves,
          test_a_woken_half_is_unparked_with_fresh_retries,
          test_probe_halves_are_capped_app_halves_are_not,
          test_probes_yield_to_a_pending_app_half,
          test_a_parked_half_expires_or_is_forgotten,
          test_a_half_a_majority_reached_is_dropped_not_parked,
          test_a_peer_heard_on_a_retired_ballot_still_counts,
          test_a_minority_island_parks_its_half,
          test_a_half_already_in_the_chain_is_forgotten)
