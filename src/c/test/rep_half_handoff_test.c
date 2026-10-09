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

/** @file Our pending halves reach a member that joined after we committed
 *  them (ISSUES §2.62).
 *
 *  Stele rt-2404254: the verifier committed its half of a probe before the
 *  auditor and the observer joined, the join carried only bilateral entries,
 *  and the owner's half committed later. Owner and verifier paired it at index
 *  9; the late pair held the owner's half alone, their chains forked two and
 *  two, and no checkpoint ever reached a quorum. _hand_off_pending_halves
 *  re-sends our unpaired halves to each newcomer at 5, 15 and 30 s. The
 *  fixture is rep_commit_retry_test.c's. Mirrors
 *  tests/a_unit/test_repprocess_half_handoff.py.
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

static char COMMITTED_FN[] = "tx committed";

/* The `tx committed` frames the process hands the network, by recipient. */
#define MAX_FRAMES 32
static size_t  g_n_frames;
static uuid_t  g_to[MAX_FRAMES];
static json_t *g_payload[MAX_FRAMES];

static int _capture_hook(const char *key, const message_type_t type,
                         generic_msg_t *msg, bool blocking)
{
    (void)key; (void)blocking;
    if (type != NET_MESSAGE || msg->info.net_msg.function == NULL
        || strcmp(msg->info.net_msg.function, COMMITTED_FN) != 0
        || g_n_frames >= MAX_FRAMES || msg->info.net_msg.obj == NULL)
        return 0;
    json_t *p = json_loads((const char *)msg->info.net_msg.obj, 0, NULL);
    if (p == NULL)
        return 0;
    uuid_copy(g_to[g_n_frames], msg->info.net_msg.to_whom.uuid);
    g_payload[g_n_frames++] = p;
    return 0;
}

static void _clear_frames(void)
{
    for (size_t i = 0; i < g_n_frames; i++)
        json_decref(g_payload[i]);
    g_n_frames = 0;
}

static size_t _frames_to(const identity_t *who)
{
    size_t n = 0;
    for (size_t i = 0; i < g_n_frames; i++)
        if (uuid_compare(g_to[i], who->uuid) == 0)
            n++;
    return n;
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

/* Deliver @p payload to @p proc as a verified frame from @p sender. */
static void _dispatch(process_t *proc, identity_t *sender, json_t *payload)
{
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(sender, &pub));
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "reputation", PROC_NAME_LEN);
    msg.info.net_msg.function = COMMITTED_FN;
    msg.info.net_msg.verified = true;
    memcpy(&msg.info.net_msg.from_whom, pub, sizeof(public_identity_t));
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, payload));
    run_message_handlers(proc, NULL, NET_MESSAGE, &msg);
    smrt_deref(pub);
}

/* @p scorer's half of @p task, committed as handle_accepted broadcasts it. A
 * frame from ourselves plants our own half, which handle_committed accepts
 * because it writes only its sender's half. */
static void _commit_half(process_t *proc, identity_t *scorer,
                         const char *task_str, double score, const char *channel)
{
    char who[UUID_STRING_LEN + 1];
    uuid_unparse_lower(scorer->uuid, who);
    json_t *p = json_object();
    json_object_set_new(p, "task_uuid", json_string(task_str));
    json_object_set_new(p, "peer_uuid", json_string(who));
    json_object_set_new(p, "score", json_real(score));
    if (channel != NULL)
        json_object_set_new(p, "channel", json_string(channel));
    _dispatch(proc, scorer, p);
    json_decref(p);
}

typedef struct { identity_t *me, *alice, *carol; process_t *proc;
                 char t[UUID_STRING_LEN + 1]; } cohort_t;

static void _task(char *out)
{
    uuid_t u;
    uuid_generate(u);
    uuid_unparse_lower(u, out);
}

static void _begin(cohort_t *c)
{
    ck_assert(sodium_init() >= 0);
    reputation_reset_state(2);
    _clear_frames();
    messaging_set_test_hook(_capture_hook);
    c->me = _mk_identity("me", "10.0.0.1");
    c->alice = _mk_identity("alice", "10.0.0.2");
    c->carol = _mk_identity("carol", "10.0.0.3");
    c->proc = _mk_process(c->me);
    _add_peer(c->proc, c->alice);
    _task(c->t);
}

static void _end(void)
{
    _clear_frames();
    messaging_set_test_hook(NULL);
}

static size_t _pass(cohort_t *c, double at)
{
    return _hand_off_pending_halves(c->proc, at, c->me->uuid, true);
}

/* THE REGRESSION's sending side: a half of ours, committed before carol was in
 * the roster, reaches carol at each of the three passes and never after; only
 * our own unpaired half goes, not a bilateral entry nor another peer's half. */
DEFINE_TEST(test_a_half_committed_before_a_join_reaches_the_joiner)
{
    cohort_t c;
    _begin(&c);
    char both[UUID_STRING_LEN + 1], theirs[UUID_STRING_LEN + 1];
    _task(both);
    _task(theirs);
    _commit_half(c.proc, c.me, c.t, 0.9, "probe");
    _commit_half(c.proc, c.me, both, 0.9, NULL);
    _commit_half(c.proc, c.alice, both, 0.9, NULL);
    _commit_half(c.proc, c.alice, theirs, 0.9, NULL);
    _clear_frames();

    double t0 = (double)time(NULL);
    ck_assert_uint_eq(_pass(&c, t0), 0);          /* alice first seen */
    _add_peer(c.proc, c.carol);
    ck_assert_uint_eq(_pass(&c, t0 + 1), 0);      /* carol first seen */
    ck_assert_uint_eq(_pass(&c, t0 + 4), 0);      /* nobody due yet */

    ck_assert_uint_eq(_pass(&c, t0 + 6), 2);      /* pass 1, both */
    ck_assert_uint_eq(_frames_to(c.carol), 1);
    ck_assert_uint_eq(_frames_to(c.alice), 1);
    char me[UUID_STRING_LEN + 1];
    uuid_unparse_lower(c.me->uuid, me);
    for (size_t i = 0; i < g_n_frames; i++)
    {
        json_t *p = g_payload[i];
        ck_assert_str_eq(json_string_value(json_object_get(p, "task_uuid")), c.t);
        ck_assert_str_eq(json_string_value(json_object_get(p, "peer_uuid")), me);
        ck_assert_str_eq(json_string_value(json_object_get(p, "channel")), "probe");
        ck_assert(json_real_value(json_object_get(p, "score")) > 0.89);
        ck_assert_ptr_null(json_object_get(p, "group_uuid"));
    }
    _clear_frames();
    ck_assert_uint_eq(_pass(&c, t0 + 6), 0);      /* not twice in one pass */

    /* A late tick past both remaining passes sends once, not twice. */
    ck_assert_uint_eq(_pass(&c, t0 + 100), 2);
    ck_assert_uint_eq(_frames_to(c.carol), 1);
    ck_assert_uint_eq(_pass(&c, t0 + 200), 0);    /* all passes spent */
    _end();
}
END_TEST_DEFINITION()

/* A peer that leaves the roster is forgotten, so coming back is a new join;
 * without our identity, or without a half of ours pending, nothing goes. */
DEFINE_TEST(test_a_returning_peer_is_handed_them_again)
{
    cohort_t c;
    _begin(&c);
    double t0 = (double)time(NULL);
    ck_assert_uint_eq(_pass(&c, t0), 0);
    ck_assert_uint_eq(_pass(&c, t0 + 100), 0);    /* due, but nothing pending */

    _commit_half(c.proc, c.me, c.t, 0.9, NULL);
    _clear_frames();
    ck_assert_uint_eq(_hand_off_pending_halves(c.proc, t0 + 300, c.me->uuid,
                                               false), 0);
    c.proc->protocol.num_peers = 0;
    ck_assert_uint_eq(_pass(&c, t0 + 400), 0);    /* alice left */
    _add_peer(c.proc, c.alice);
    ck_assert_uint_eq(_pass(&c, t0 + 401), 0);    /* back: first seen again */
    ck_assert_uint_eq(_pass(&c, t0 + 406), 1);
    ck_assert_uint_eq(_frames_to(c.alice), 1);
    _end();
}
END_TEST_DEFINITION()

/* THE REGRESSION's receiving side, as carol: our counterpart's half arriving
 * after carol joined pairs into a committed entry only because the hand-off
 * gave carol ours first. */
DEFINE_TEST(test_the_joiner_pairs_the_late_half)
{
    cohort_t c;
    _begin(&c);
    _commit_half(c.proc, c.me, c.t, 0.9, "probe");
    _add_peer(c.proc, c.carol);
    _clear_frames();
    double t0 = (double)time(NULL);
    ck_assert_uint_eq(_pass(&c, t0), 0);
    ck_assert_uint_eq(_pass(&c, t0 + 6), 2);
    json_t *handed = NULL;
    for (size_t i = 0; i < g_n_frames; i++)
        if (uuid_compare(g_to[i], c.carol->uuid) == 0)
            handed = json_incref(g_payload[i]);
    ck_assert_ptr_nonnull(handed);

    /* Control: without it, carol holds alice's half alone. */
    reputation_reset_state(2);
    process_t *carol = _mk_process(c.carol);
    _add_peer(carol, c.me);
    _add_peer(carol, c.alice);
    _commit_half(carol, c.alice, c.t, 0.9, NULL);
    ck_assert_int_eq(reputation_get_committed_tx_count(), 0);

    /* With it, the same late half pairs. */
    reputation_reset_state(2);
    carol = _mk_process(c.carol);
    _add_peer(carol, c.me);
    _add_peer(carol, c.alice);
    _dispatch(carol, c.me, handed);
    ck_assert_int_eq(reputation_get_committed_tx_count(), 0);
    _commit_half(carol, c.alice, c.t, 0.9, NULL);
    ck_assert_int_eq(reputation_get_committed_tx_count(), 1);
    json_decref(handed);
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(RepHalfHandoff,
          test_a_half_committed_before_a_join_reaches_the_joiner,
          test_a_returning_peer_is_handed_them_again,
          test_the_joiner_pairs_the_late_half)
