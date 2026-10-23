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

/** @file A round's bar (doc/architecture/reputation.md, "Agreeing on an
 *  order").
 *
 *  A half carries once a strict majority of the group, counting the proposer,
 *  has accepted it with a signature: members / 2 of the others before the
 *  chain logs a roster. A member's acceptance counts once per round, and only
 *  a signed one counts at all. The slot is not a write index: two halves at
 *  one id2 are both accepted, since placement decides where each lands.
 *  Mirrors tests/a_unit/test_paxos_round_majority.py.
 *
 *  Driven through the production proposer (_forward_transaction) and
 *  run_message_handlers.
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

static char TX_FN[]        = "transaction";
static char ACCEPTED_FN[]  = "tx accepted";
static char COMMITTED_FN[] = "tx committed";

static size_t  g_tx_count;
static size_t  g_accepted_count;
static size_t  g_committed_count;
static int64_t g_req_id1;
static int64_t g_req_id2;
static char    g_req_peer_uuid[UUID_STRING_LEN + 1];

static int _capture_hook(const char *key, const message_type_t type,
                         generic_msg_t *msg, bool blocking)
{
    (void)key; (void)blocking;
    if (type != NET_MESSAGE || msg->info.net_msg.function == NULL)
        return 0;
    const char *fn = msg->info.net_msg.function;
    if (strcmp(fn, TX_FN) == 0)
    {
        g_tx_count++;
        json_error_t err;
        json_t *p = msg->info.net_msg.obj != NULL
            ? json_loads((const char *)msg->info.net_msg.obj, 0, &err) : NULL;
        if (p != NULL)
        {
            g_req_id1 = json_integer_value(json_object_get(p, "id1"));
            g_req_id2 = json_integer_value(json_object_get(p, "id2"));
            const char *u = json_string_value(json_object_get(p, "peer_uuid"));
            snprintf(g_req_peer_uuid, sizeof(g_req_peer_uuid), "%s", u ? u : "");
            json_decref(p);
        }
    }
    else if (strcmp(fn, ACCEPTED_FN) == 0)
        g_accepted_count++;
    else if (strcmp(fn, COMMITTED_FN) == 0)
        g_committed_count++;
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
    ck_assert_ptr_nonnull(pub);
    memcpy(&proc->protocol.peers[proc->protocol.num_peers], pub,
           sizeof(public_identity_t));
    proc->protocol.num_peers++;
    smrt_deref(pub);
}

static void _dispatch_as(process_t *proc, identity_t *sender, char *function,
                         json_t *payload, bool verified)
{
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(sender, &pub));
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "reputation", PROC_NAME_LEN);
    msg.info.net_msg.function = function;
    msg.info.net_msg.verified = verified;
    memcpy(&msg.info.net_msg.from_whom, pub, sizeof(public_identity_t));
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, payload));
    run_message_handlers(proc, NULL, NET_MESSAGE, &msg);
    smrt_deref(pub);
}

static void _dispatch(process_t *proc, identity_t *sender, char *function,
                      json_t *payload)
{
    _dispatch_as(proc, sender, function, payload, true);
}

static void _begin(void)
{
    reputation_reset_state(1);
    g_tx_count = 0;
    g_accepted_count = 0;
    g_committed_count = 0;
    g_req_id1 = 0;
    g_req_id2 = 0;
    g_req_peer_uuid[0] = '\0';
    messaging_set_test_hook(_capture_hook);
}

static void _end(void) { messaging_set_test_hook(NULL); }

/* A process for `me` with `n` other members, returned in `others`. */
static process_t *_group(identity_t *me, identity_t **others, size_t n)
{
    process_t *proc = _mk_process(me);
    char name[32], addr[32];
    for (size_t i = 0; i < n; i++)
    {
        snprintf(name, sizeof(name), "m%zu", i + 1);
        snprintf(addr, sizeof(addr), "10.0.0.%zu", i + 2);
        others[i] = _mk_identity(name, addr);
        _add_peer(proc, others[i]);
    }
    return proc;
}

/* Open a round of ours for `task` through the production proposer. */
static void _propose(process_t *proc, identity_t *me, uuid_t task)
{
    uuid_t subject;
    /* Our half names whom it scores (R+D.md §14.2); which peer does not
     * matter here. */
    uuid_generate(subject);
    uuid_generate(task);
    _forward_transaction(proc, task, me->uuid, 0.9, "at.handshake", NULL,
                         subject, 0.0);
}

/* `voter` accepts the open round for `task`, signing our half or not. */
static void _accept_as(process_t *proc, identity_t *voter, const uuid_t task,
                       bool sign)
{
    char task_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(task, task_str);
    json_t *p = json_object();
    json_object_set_new(p, "id1", json_integer(g_req_id1));
    json_object_set_new(p, "id2", json_integer(g_req_id2));
    json_object_set_new(p, "peer_uuid", json_string(g_req_peer_uuid));
    json_object_set_new(p, "task_uuid", json_string(task_str));
    if (sign)
    {
        uuid_t scorer;
        ck_assert_int_eq(uuid_parse(g_req_peer_uuid, scorer), 0);
        uint8_t desig[512];
        size_t dlen = commit_designation(scorer, task, 0.9, NULL, desig,
                                         sizeof(desig));
        ck_assert(dlen > 0);
        unsigned char sig[crypto_sign_BYTES];
        ck_assert(crypto_sign_detached(sig, NULL, desig, dlen,
                                       voter->signature.private) == 0);
        char hex[crypto_sign_BYTES * 2 + 1];
        hexlify(sig, crypto_sign_BYTES, (unsigned char *)hex);
        json_object_set_new(p, "sig", json_string(hex));
    }
    _dispatch(proc, voter, ACCEPTED_FN, p);
    json_decref(p);
}

static void _accept(process_t *proc, identity_t *voter, const uuid_t task)
{
    _accept_as(proc, voter, task, true);
}

/* `proposer` sends us its half for `task` at `slot`, under ballot `id1`, as
 * every proposer does: asking to be certified, naming the primary group. */
static void _send_tx(process_t *proc, identity_t *proposer, int64_t id1,
                     int64_t slot, const uuid_t task)
{
    char proposer_str[UUID_STRING_LEN + 1], task_str[UUID_STRING_LEN + 1];
    char group[UUID_STRING_LEN + 1];
    uuid_unparse_lower(proposer->uuid, proposer_str);
    uuid_unparse_lower(task, task_str);
    uuid_unparse_lower(proc->protocol.group.uuid, group);
    json_t *p = json_object();
    json_object_set_new(p, "id1", json_integer(id1));
    json_object_set_new(p, "id2", json_integer(slot));
    json_object_set_new(p, "peer_uuid", json_string(proposer_str));
    json_object_set_new(p, "score", json_real(0.8));
    json_object_set_new(p, "task_uuid", json_string(task_str));
    json_object_set_new(p, "certify", json_true());
    json_object_set_new(p, "group", json_string(group));
    _dispatch(proc, proposer, TX_FN, p);
    json_decref(p);
}

/* ------------------------------------------------------------------ */

DEFINE_TEST(test_two_of_three_commit)
{
    _begin();
    identity_t *me = _mk_identity("me", "10.0.0.1");
    identity_t *m[2];
    process_t *proc = _group(me, m, 2);
    uuid_t task;
    _propose(proc, me, task);
    ck_assert(g_tx_count > 0);
    _accept(proc, m[0], task);
    ck_assert(g_committed_count > 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_three_of_five_commit_and_a_member_counts_once)
{
    _begin();
    identity_t *me = _mk_identity("me", "10.0.0.1");
    identity_t *m[4];
    process_t *proc = _group(me, m, 4);
    uuid_t task;
    _propose(proc, me, task);
    _accept(proc, m[0], task);
    _accept(proc, m[0], task);           /* the same member again */
    ck_assert_uint_eq(g_committed_count, 0);
    _accept(proc, m[1], task);
    ck_assert(g_committed_count > 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_unsigned_acceptance_is_not_counted)
{
    _begin();
    identity_t *me = _mk_identity("me", "10.0.0.1");
    identity_t *m[2];
    process_t *proc = _group(me, m, 2);
    uuid_t task;
    _propose(proc, me, task);
    _accept_as(proc, m[0], task, false);
    _accept_as(proc, m[1], task, false);
    ck_assert_uint_eq(g_committed_count, 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_two_halves_at_one_slot_are_both_accepted)
{
    /* The slot is not a write index: placement decides where each lands, so
     * two different halves at one id2 are not rivals. */
    _begin();
    identity_t *me = _mk_identity("me", "10.0.0.1");
    identity_t *m[2];
    process_t *proc = _group(me, m, 2);
    uuid_t t1, t2;
    uuid_generate(t1);
    uuid_generate(t2);
    _send_tx(proc, m[0], 100, 1, t1);
    _send_tx(proc, m[1], 200, 1, t2);
    ck_assert_uint_eq(g_accepted_count, 2);
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(RepRoundMajority,
          test_two_of_three_commit,
          test_three_of_five_commit_and_a_member_counts_once,
          test_an_unsigned_acceptance_is_not_counted,
          test_two_halves_at_one_slot_are_both_accepted)
