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

/** @file One Paxos round, driven through the PRODUCTION proposer.
 *
 *  WHERE THIS CAME FROM. Three live cohorts (agora reputation, 2026-09-21)
 *  sent 177 "ask permission" requests between three nodes, collected 8
 *  grants, and emitted NOT ONE transaction. `Reputation: Transaction
 *  committed` — an INFO line, at the level every cohort runs at — appears
 *  zero times in 25 preserved runs going back to September.
 *
 *  The cause was a key disagreement of two lines. `_forward_transaction`
 *  filed the pending round in `my_requests` under the TASK uuid; handle_grant
 *  looked it up under the PEER uuid echoed on the grant. Every grant landed
 *  in the "already-completed or unknown request" branch and the round died
 *  there. Python keys both sides by `(id1, id2)` (repprocess.py:991, :831).
 *
 *  WHY NOTHING CAUGHT IT. Every other test in the tree — rep_quorum_test.c
 *  here, the conformance corpus, the Python unit suite's twin — stages the
 *  pending round by calling `reputation_install_my_request` (or assigning
 *  `rp.my_requests[idx]`) and then dispatches a grant. Staging writes the key
 *  the READER expects, so the WRITER's key was never on trial. A test that
 *  never runs the proposer cannot see the proposer disagree with anyone.
 *
 *  So this file starts at the only place that closes the loop: call
 *  `_forward_transaction`, read (id1, id2) off the request it actually put on
 *  the wire, and answer THOSE ids. Nothing is staged.
 *
 *  Handlers are static, so grants are driven through run_message_handlers with
 *  a crafted NET_MESSAGE, following rep_quorum_test.c's precedent.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>

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

/* net_msg_t.function is `char *`, so const literals cannot be assigned. */
static char GRANT_FN[] = "permission granted";
static char NACK_FN[]  = "try again";
static char COMMITTED_FN[] = "tx committed";
static char REQUEST_FN[]   = "ask permission";

#define REQUEST_VERB "ask permission"
#define TX_VERB      "transaction"

/* ------------------------------------------------------------------ */
/* Emission capture                                                    */
/* ------------------------------------------------------------------ */

static size_t g_request_count;
static size_t g_tx_count;
/* What WE answered a peer's request with. The two verdicts are the acceptor
 * side of the chain-index rule: a grant means our index agreed with theirs. */
static size_t g_grant_count;
static size_t g_backdate_count;
/* The ids the proposer minted, taken off its OWN first request — never
 * invented here. Answering invented ids would test the handler against a
 * round that does not exist, which is the mistake this file exists to undo. */
static int64_t g_req_id1;
static int64_t g_req_id2;
static char    g_req_peer_uuid[UUID_STRING_LEN + 1];
/* What the transaction broadcast carried, so the test can prove the round it
 * committed is the round that was proposed. */
static char   g_tx_task_uuid[UUID_STRING_LEN + 1];
static char   g_tx_capability[CAP_NAMELEN + 1];
static double g_tx_score;

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

static void _copy_str(char *out, size_t cap, json_t *obj, const char *key)
{
    const char *s = json_string_value(json_object_get(obj, key));
    out[0] = '\0';
    if (s != NULL) {
        strncpy(out, s, cap - 1);
        out[cap - 1] = '\0';
    }
}

static int _capture_hook(const char *key, const message_type_t type,
                         generic_msg_t *msg, bool blocking)
{
    (void)key; (void)blocking;
    if (type != NET_MESSAGE || msg->info.net_msg.function == NULL)
        return 0;
    const char *fn = msg->info.net_msg.function;
    json_t *p = NULL;

    if (strcmp(fn, REQUEST_VERB) == 0) {
        p = _payload_of(msg);
        if (p != NULL) {
            g_req_id1 = json_integer_value(json_object_get(p, "id1"));
            g_req_id2 = json_integer_value(json_object_get(p, "id2"));
            _copy_str(g_req_peer_uuid, sizeof(g_req_peer_uuid), p, "peer_uuid");
        }
        g_request_count++;
    }
    else if (strcmp(fn, TX_VERB) == 0) {
        p = _payload_of(msg);
        if (p != NULL) {
            _copy_str(g_tx_task_uuid, sizeof(g_tx_task_uuid), p, "task_uuid");
            _copy_str(g_tx_capability, sizeof(g_tx_capability), p,
                      "capability_name");
            g_tx_score = json_number_value(json_object_get(p, "score"));
        }
        g_tx_count++;
    }
    else if (strcmp(fn, "permission granted") == 0)
        g_grant_count++;
    else if (strcmp(fn, "out of date") == 0)
        g_backdate_count++;
    if (p != NULL)
        json_decref(p);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Fixtures                                                            */
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
    ck_assert_ptr_nonnull(pub);
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

/* Answer the round the proposer actually opened, echoing the ids and the
 * peer_uuid exactly as handle_request would. */
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

/* Refuse the round the proposer opened, as handle_request's NACK branch
 * would. */
static void _nack(process_t *proc, identity_t *voter)
{
    json_t *p = json_object();
    json_object_set_new(p, "id1", json_integer(g_req_id1));
    json_object_set_new(p, "id2", json_integer(g_req_id2));
    json_object_set_new(p, "last_id", json_integer(g_req_id1 + 1));
    json_object_set_new(p, "chain_len", json_integer(0));
    _dispatch(proc, voter, NACK_FN, p);
    json_decref(p);
}

/* Answer the round the proposer opened with "out of date", as
 * handle_request's BACKDATE branch would: same {id1, id2} payload. */
static char BACKDATE_FN[] = "out of date";
static void _backdate(process_t *proc, identity_t *voter)
{
    json_t *p = json_object();
    json_object_set_new(p, "id1", json_integer(g_req_id1));
    json_object_set_new(p, "id2", json_integer(g_req_id2));
    _dispatch(proc, voter, BACKDATE_FN, p);
    json_decref(p);
}

static void _begin(int num_peers)
{
    reputation_reset_state(num_peers);
    g_request_count = 0;
    g_tx_count = 0;
    g_grant_count = 0;
    g_backdate_count = 0;
    g_req_id1 = 0;
    g_req_id2 = 0;
    g_req_peer_uuid[0] = '\0';
    g_tx_task_uuid[0] = '\0';
    g_tx_capability[0] = '\0';
    g_tx_score = 0.0;
    messaging_set_test_hook(_capture_hook);
}

static void _end(void) { messaging_set_test_hook(NULL); }

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

DEFINE_TEST(test_a_granted_round_reaches_a_transaction)
{
    /* THE regression. Two peers, so PAXOS_MAJORITY(2) == 2 and both have to
     * answer — a round that committed on one grant would not be a quorum. */
    _begin(2);
    identity_t *me = _mk_identity("me", "10.0.0.1");
    identity_t *alice = _mk_identity("alice", "10.0.0.2");
    identity_t *bob = _mk_identity("bob", "10.0.0.3");
    process_t *proc = _mk_process(me);
    _add_peer(proc, alice);
    _add_peer(proc, bob);

    uuid_t task;
    uuid_generate(task);
    char task_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(task, task_str);
    uuid_t subject;
    uuid_clear(subject);

    _forward_transaction(proc, task, me->uuid, 0.9, "at.handshake", NULL,
                         subject, 0.0);

    /* Phase 1a went to both peers, and it named us as the proposer. */
    ck_assert_uint_eq(g_request_count, 2);
    char me_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(me->uuid, me_str);
    ck_assert_str_eq(g_req_peer_uuid, me_str);
    ck_assert(g_req_id1 > 0);

    /* One grant is short of quorum: the round is pending, not committed. */
    _grant(proc, alice);
    ck_assert_uint_eq(g_tx_count, 0);

    /* The second grant carries it. Before the key fix this stayed at zero
     * however many grants arrived, because the lookup never found the
     * pending round at all. */
    _grant(proc, bob);
    ck_assert_uint_eq(g_tx_count, 2);   /* broadcast: one per peer */

    /* And it is THIS round that committed, not some other pending one. */
    ck_assert_str_eq(g_tx_task_uuid, task_str);
    ck_assert_str_eq(g_tx_capability, "at.handshake");
    ck_assert(g_tx_score > 0.89 && g_tx_score < 0.91);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_concurrent_rounds_do_not_collide)
{
    /* A node proposes for many tasks at once — in the live cohort, three
     * capabilities' probes land within the same millisecond. Keying the
     * pending round by anything per-NODE (the proposer uuid, as handle_grant
     * used to) collapses them onto one entry, so the second proposal evicts
     * the first and the first can never commit. Keying by the round keeps
     * them apart. */
    _begin(2);
    identity_t *me = _mk_identity("me", "10.0.0.1");
    identity_t *alice = _mk_identity("alice", "10.0.0.2");
    identity_t *bob = _mk_identity("bob", "10.0.0.3");
    process_t *proc = _mk_process(me);
    _add_peer(proc, alice);
    _add_peer(proc, bob);

    uuid_t subject;
    uuid_clear(subject);

    uuid_t first_task;
    uuid_generate(first_task);
    char first_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(first_task, first_str);
    _forward_transaction(proc, first_task, me->uuid, 0.5, "at.time-attest",
                         NULL, subject, 0.0);
    int64_t first_id1 = g_req_id1;
    int64_t first_id2 = g_req_id2;
    char first_peer[UUID_STRING_LEN + 1];
    memcpy(first_peer, g_req_peer_uuid, sizeof(first_peer));

    /* A second round opens before the first is answered. */
    g_request_count = 0;
    uuid_t second_task;
    uuid_generate(second_task);
    _forward_transaction(proc, second_task, me->uuid, 0.9, "at.echo-challenge",
                         NULL, subject, 0.0);
    ck_assert(g_req_id1 != first_id1);   /* ids are strictly monotonic */

    /* Now answer the FIRST round, which is the one a per-node key would have
     * thrown away. */
    g_req_id1 = first_id1;
    g_req_id2 = first_id2;
    memcpy(g_req_peer_uuid, first_peer, sizeof(g_req_peer_uuid));
    _grant(proc, alice);
    _grant(proc, bob);

    ck_assert_uint_eq(g_tx_count, 2);
    ck_assert_str_eq(g_tx_task_uuid, first_str);
    ck_assert_str_eq(g_tx_capability, "at.time-attest");
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_grant_for_an_unknown_round_is_ignored)
{
    /* The branch the live grants were wrongly taking. It must still exist and
     * still be quiet: a grant for a round we never opened is dropped without
     * emitting anything. */
    _begin(1);
    identity_t *me = _mk_identity("me", "10.0.0.1");
    identity_t *alice = _mk_identity("alice", "10.0.0.2");
    process_t *proc = _mk_process(me);
    _add_peer(proc, alice);

    uuid_unparse_lower(me->uuid, g_req_peer_uuid);
    g_req_id1 = 424242;
    g_req_id2 = 1;
    _grant(proc, alice);

    ck_assert_uint_eq(g_tx_count, 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_nacked_round_is_re_proposed_and_can_commit)
{
    /* The other half of the live failure. Three members propose on the same
     * probe in the same millisecond, so nearly every request is refused: 154
     * of 177 in the 2026-09-21 cohorts. Python answers a nack by sleeping the
     * backoff and re-proposing (_try_again); C recorded the backoff and
     * abandoned the round, so a refused round was gone for good. */
    _begin(2);
    identity_t *me = _mk_identity("me", "10.0.0.1");
    identity_t *alice = _mk_identity("alice", "10.0.0.2");
    identity_t *bob = _mk_identity("bob", "10.0.0.3");
    process_t *proc = _mk_process(me);
    _add_peer(proc, alice);
    _add_peer(proc, bob);

    uuid_t task;
    uuid_generate(task);
    char task_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(task, task_str);
    uuid_t subject;
    uuid_clear(subject);

    _forward_transaction(proc, task, me->uuid, 0.9, "agora-post", NULL,
                         subject, 0.0);
    int64_t first_id1 = g_req_id1;

    _nack(proc, alice);

    /* Still inside the backoff: nothing is re-sent, which is the point of
     * having one — an immediate retry re-collides with the peer that just
     * refused us. */
    double now = (double)time(NULL);
    g_request_count = 0;
    _retry_nacked_rounds(proc, now, me->uuid, true);
    ck_assert_uint_eq(g_request_count, 0);

    /* Past it, the round goes out again — new ballot, same task. */
    _retry_nacked_rounds(proc, now + 600.0, me->uuid, true);
    ck_assert_uint_eq(g_request_count, 2);
    ck_assert(g_req_id1 > first_id1);

    /* And the re-proposal is a real round: granted, it commits the score the
     * first attempt was carrying. */
    _grant(proc, alice);
    _grant(proc, bob);
    ck_assert_uint_eq(g_tx_count, 2);
    ck_assert_str_eq(g_tx_task_uuid, task_str);
    ck_assert_str_eq(g_tx_capability, "agora-post");

    /* One re-proposal, not a standing alarm: a second sweep finds nothing. */
    g_request_count = 0;
    _retry_nacked_rounds(proc, now + 1200.0, me->uuid, true);
    ck_assert_uint_eq(g_request_count, 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_backdated_round_is_re_proposed_and_can_commit)
{
    /* A backdate used to ask for the chain and abandon the round. With three
     * live proposers the chain moves constantly, so a round EVERY acceptor
     * backdated, with no nack among the replies to arm a retry, simply
     * vanished. moderation_cohort.sh's report: paired on both sides,
     * backdated by bob and carol, never committed. */
    _begin(2);
    identity_t *me = _mk_identity("me", "10.0.0.1");
    identity_t *alice = _mk_identity("alice", "10.0.0.2");
    identity_t *bob = _mk_identity("bob", "10.0.0.3");
    process_t *proc = _mk_process(me);
    _add_peer(proc, alice);
    _add_peer(proc, bob);

    uuid_t task;
    uuid_generate(task);
    char task_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(task, task_str);
    uuid_t subject;
    uuid_clear(subject);

    _forward_transaction(proc, task, me->uuid, 0.15, NULL, "first_person",
                         subject, 0.0);
    int64_t first_id1 = g_req_id1;
    _backdate(proc, alice);
    _backdate(proc, bob);

    double now = (double)time(NULL);
    g_request_count = 0;
    _retry_nacked_rounds(proc, now + 600.0, me->uuid, true);
    ck_assert_uint_eq(g_request_count, 2);     /* re-proposed to both */
    ck_assert(g_req_id1 > first_id1);

    _grant(proc, alice);
    _grant(proc, bob);
    ck_assert_uint_eq(g_tx_count, 2);
    ck_assert_str_eq(g_tx_task_uuid, task_str);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_nack_for_someone_elses_round_arms_nothing)
{
    /* A nack names a ballot; a ballot we never opened is not ours to retry.
     * Mirrors Python handle_nack's `idx not in self.my_requests` drop. */
    _begin(2);
    identity_t *me = _mk_identity("me", "10.0.0.1");
    identity_t *alice = _mk_identity("alice", "10.0.0.2");
    process_t *proc = _mk_process(me);
    _add_peer(proc, alice);

    g_req_id1 = 987654;
    g_req_id2 = 1;
    _nack(proc, alice);

    g_request_count = 0;
    _retry_nacked_rounds(proc, (double)time(NULL) + 600.0, me->uuid, true);
    ck_assert_uint_eq(g_request_count, 0);
    _end();
}
END_TEST_DEFINITION()

/* Tell this node a round committed elsewhere, the way the proposer's
 * broadcast does. Two different scorers for one task, because a chain entry
 * counts toward the length only when it is BILATERAL (reputation.c:856). */
static void _learn_commit(process_t *proc, identity_t *teller,
                          const char *task_str, const char *scorer_str,
                          double score)
{
    json_t *p = json_object();
    json_object_set_new(p, "task_uuid", json_string(task_str));
    json_object_set_new(p, "peer_uuid", json_string(scorer_str));
    json_object_set_new(p, "score", json_real(score));
    _dispatch(proc, teller, COMMITTED_FN, p);
    json_decref(p);
}

DEFINE_TEST(test_the_ballot_index_follows_the_chain_not_our_own_wins)
{
    /* The third live-only Paxos defect. C numbered ballots from a PRIVATE
     * counter that `paxos_advance_chain` bumps only on a round THIS node
     * proposed and won, while Python takes the number from the chain itself
     * on both sides (repprocess.py:990 and :761). Every node's chain grows on
     * every commit it LEARNS of, so with three proposers the counters scatter
     * within seconds, id2 stops matching `chain_len + 1` on the acceptors,
     * and the group falls into an "out of date" loop that never settles —
     * ninety seconds of it in the 2026-09-21 cohort, with one node committing
     * nothing at all.
     *
     * Here: this node proposes NOTHING and wins NOTHING. It only hears that a
     * round committed. Its next ballot must still move on, because the chain
     * moved. */
    _begin(2);
    identity_t *me = _mk_identity("me", "10.0.0.1");
    identity_t *alice = _mk_identity("alice", "10.0.0.2");
    identity_t *bob = _mk_identity("bob", "10.0.0.3");
    process_t *proc = _mk_process(me);
    _add_peer(proc, alice);
    _add_peer(proc, bob);

    uuid_t subject;
    uuid_clear(subject);
    uuid_t t0;
    uuid_generate(t0);
    char first_task[UUID_STRING_LEN + 1];
    uuid_unparse_lower(t0, first_task);

    /* Before hearing anything, our first ballot sits at index 1. */
    _forward_transaction(proc, t0, me->uuid, 0.9, "at.handshake", NULL,
                         subject, 0.0);
    ck_assert_int_eq((int)g_req_id2, 1);

    /* A round we had no part in commits, and both of its parties say so. */
    uuid_t other;
    uuid_generate(other);
    char other_task[UUID_STRING_LEN + 1];
    char alice_str[UUID_STRING_LEN + 1];
    char bob_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(other, other_task);
    uuid_unparse_lower(alice->uuid, alice_str);
    uuid_unparse_lower(bob->uuid, bob_str);
    _learn_commit(proc, alice, other_task, alice_str, 0.8);
    _learn_commit(proc, bob, other_task, bob_str, 0.8);

    /* Our next ballot must name the NEXT slot. Against the private counter
     * this stayed at 1 — and every peer whose chain HAD grown answered it
     * "out of date" forever. */
    uuid_t t1;
    uuid_generate(t1);
    _forward_transaction(proc, t1, me->uuid, 0.9, "at.handshake", NULL,
                         subject, 0.0);
    ck_assert_int_eq((int)g_req_id2, 2);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_request_is_judged_against_the_chain_we_actually_hold)
{
    /* The acceptor half of the same rule: a peer numbering its ballot from
     * the shared chain must be GRANTED, not backdated, by a node whose own
     * proposals have won nothing. */
    _begin(2);
    identity_t *me = _mk_identity("me", "10.0.0.1");
    identity_t *alice = _mk_identity("alice", "10.0.0.2");
    identity_t *bob = _mk_identity("bob", "10.0.0.3");
    process_t *proc = _mk_process(me);
    _add_peer(proc, alice);
    _add_peer(proc, bob);

    uuid_t other;
    uuid_generate(other);
    char other_task[UUID_STRING_LEN + 1];
    char alice_str[UUID_STRING_LEN + 1];
    char bob_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(other, other_task);
    uuid_unparse_lower(alice->uuid, alice_str);
    uuid_unparse_lower(bob->uuid, bob_str);
    _learn_commit(proc, alice, other_task, alice_str, 0.8);
    _learn_commit(proc, bob, other_task, bob_str, 0.8);

    /* alice asks for slot 2, which is what the shared chain says is next. */
    json_t *req = json_object();
    json_object_set_new(req, "id1", json_integer(7777777));
    json_object_set_new(req, "id2", json_integer(2));
    json_object_set_new(req, "peer_uuid", json_string(alice_str));
    _dispatch(proc, alice, REQUEST_FN, req);
    json_decref(req);

    ck_assert_uint_eq(g_grant_count, 1);
    ck_assert_uint_eq(g_backdate_count, 0);
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(RepPaxosRound,
          test_a_granted_round_reaches_a_transaction,
          test_concurrent_rounds_do_not_collide,
          test_a_grant_for_an_unknown_round_is_ignored,
          test_a_nacked_round_is_re_proposed_and_can_commit,
          test_a_backdated_round_is_re_proposed_and_can_commit,
          test_a_nack_for_someone_elses_round_arms_nothing,
          test_the_ballot_index_follows_the_chain_not_our_own_wins,
          test_a_request_is_judged_against_the_chain_we_actually_hold)
