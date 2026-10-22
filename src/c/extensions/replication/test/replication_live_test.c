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

/* Live replication, the requestor's side, end to end in process
 * (RD_12.6_LIVE_REPLICATION_PLAN.md section 3.7). The layer runs through the
 * core's own dispatch: the result hook, its periodic pass and the `replay
 * response` handler it registers. Outgoing frames and scores are captured by
 * the messaging test hook; two executors answer from real traces, one honest,
 * one not. Mirrors test_replication_live.py. */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <jansson.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "identity/identity.h"
#include "negotiation/neg_ext.h"
#include "negotiation/neg_proc_priv.h"
#include "negotiation/negotiation.h"
#include "processes/capabilities.h"
#include "processes/extension.h"
#include "processes/processes.h"
#include "replication/bisection.h"
#include "structures/map.h"
#include "utilities/allocation.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
#include "utilities/msg_types_priv.h"

static const char *HONEST[8] = {"s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7"};
static const char *CHEAT[8]  = {"s0", "s1", "X2", "X3", "X4", "X5", "X6", "X7"};

/* The requestor's own step contract for "demo.count": s0 .. s7. */
static int _init(const char *kwargs_json, char *out, size_t len)
{
    (void)kwargs_json;
    snprintf(out, len, "s0");
    return 0;
}

static int _step(const char *state, int i, char *next, size_t len)
{
    int s = atoi(state + 1);
    if (s >= 7)
        return 0;
    (void)i;
    snprintf(next, len, "s%d", s + 1);
    return 1;
}

static const capability_replay_t COUNT = { .init = _init, .step = _step };

/* ---- capture ------------------------------------------------------------- */

#define CAP_MAX 64
typedef struct { char fn[32]; uuid_t to; json_t *payload; } frame_t;
typedef struct { double score; char channel[32]; bool attested; uuid_t subject; } score_t;
static frame_t g_frames[CAP_MAX];
static size_t g_nframes, g_next_frame;
static score_t g_scores[CAP_MAX];
static size_t g_nscores;

static int _hook(const char *key, const message_type_t type, generic_msg_t *msg,
                 bool blocking)
{
    (void)blocking;
    if (key != NULL && strcmp(key, "reputation") == 0 && type == TRANSACTION_SCORE
        && g_nscores < CAP_MAX)
    {
        score_t *s = &g_scores[g_nscores++];
        s->score = msg->info.tx_score.score;
        snprintf(s->channel, sizeof(s->channel), "%s", msg->info.tx_score.channel);
        s->attested = msg->info.tx_score.attested;
        uuid_copy(s->subject, msg->info.tx_score.peer_uuid);
        return 0;
    }
    if (key == NULL || strcmp(key, "network") != 0 || type != NET_MESSAGE
        || g_nframes >= CAP_MAX)
        return 0;
    frame_t *f = &g_frames[g_nframes++];
    snprintf(f->fn, sizeof(f->fn), "%s", msg->info.net_msg.function);
    uuid_copy(f->to, msg->info.net_msg.to_whom.uuid);
    f->payload = NULL;
    (void)net_msg_unpack_json(&msg->info.net_msg, &f->payload);
    return 0;
}

/* ---- the cohort ------------------------------------------------------------ */

static process_t *g_proc;
static identity_t *g_primary, *g_replica;
static public_identity_t *g_pub[2];
static char g_decl[64];

static void _begin(void)
{
    ck_assert(sodium_init() >= 0);
    negotiation_reset_state();
    at_extensions_reset();
    for (size_t i = 0; i < g_nframes; i++)
        json_decref(g_frames[i].payload);
    g_nframes = g_next_frame = g_nscores = 0;
    messaging_set_test_hook(_hook);

    snprintf(g_decl, sizeof(g_decl), "/tmp/at-repl-live-XXXXXX");
    int fd = mkstemp(g_decl);
    ck_assert(fd >= 0);
    FILE *fp = fdopen(fd, "w");
    fputs("{\"version\":1,\"capabilities\":{\"demo.count\":"
          "{\"replicate_prob\":1.0,\"replay\":{}}}}", fp);
    fclose(fp);
    setenv("AT_REPLICATION", g_decl, 1);

    if (find_capability("demo.count") == NULL)
        ck_assert_int_eq(capability_table_append("demo.count", NULL, NULL), 0);
    ck_assert_int_eq(capability_table_set_replay("demo.count", &COUNT), 0);

    g_proc = smrt_create(sizeof(process_t));
    ck_assert_ptr_nonnull(g_proc);
    pthread_rwlock_init(&g_proc->protocol.peers_rwlock, NULL);
    strncpy(g_proc->name, "negotiation", PROC_NAME_LEN);
    ck_assert_ret_ok(map_create(&g_proc->protocol.handlers));
    g_proc->protocol.phase = 1;
    ck_assert_ret_ok(negotiation_register_handlers(g_proc));

    uuid_t u;
    uuid_generate(u);
    ck_assert_ret_ok(identity_create(&u, "10.0.70.2", "primary", "primary", &g_primary));
    uuid_generate(u);
    ck_assert_ret_ok(identity_create(&u, "10.0.70.3", "replica", "replica", &g_replica));
    identity_t *both[2] = { g_primary, g_replica };
    for (int i = 0; i < 2; i++)
    {
        ck_assert_ret_ok(identity_publish(both[i], &g_pub[i]));
        memcpy(&g_proc->protocol.peers[i], g_pub[i], sizeof(public_identity_t));
    }
    g_proc->protocol.num_peers = 2;
}

static void _end(void)
{
    messaging_set_test_hook(NULL);
    unsetenv("AT_REPLICATION");
    unlink(g_decl);
    capability_table_set_replay("demo.count", NULL);
    at_extensions_reset();
}

static void _root(const char *const *states, int n, char out[AT_REPL_HASH_HEX_LEN + 1])
{
    ck_assert(at_replication_commit_root(states, (size_t)n, out));
}

static neg_result_verdict_t _deliver_result(const uuid_t task, const identity_t *who,
                                            const char *const *states)
{
    char root[AT_REPL_HASH_HEX_LEN + 1];
    _root(states, 8, root);
    neg_result_info_t info = {
        .task = task, .executor = who->uuid, .capability = "demo.count",
        .kwargs_json = "{}", .result = states[7], .result_len = strlen(states[7]),
        .trace_root = root, .trace_len = 8 };
    return neg_ext_on_result(g_proc, &info);
}

/* The replica's task, from the invitation the periodic pass sent. */
static bool _replica_task(uuid_t out)
{
    for (size_t i = 0; i < g_nframes; i++)
        if (strcmp(g_frames[i].fn, NEG_PROTO_ANNOUNCE) == 0 && g_frames[i].payload)
        {
            const char *t = json_string_value(json_object_get(
                json_object_get(g_frames[i].payload, "uuid"), "__value__"));
            if (t != NULL && uuid_parse(t, out) == 0)
            {
                ck_assert(uuid_compare(g_frames[i].to, g_replica->uuid) == 0);
                return true;
            }
        }
    return false;
}

/* Answer every pending challenge or reveal as each executor would from its
 * trace; the one named `silent` (NULL for none) never answers. */
static void _play(const char *const *primary_states, const char *const *replica_states,
                  const identity_t *silent)
{
    for (int guard = 0; guard < 64 && g_next_frame < g_nframes; guard++)
    {
        frame_t *f = &g_frames[g_next_frame++];
        bool challenge = strcmp(f->fn, NEG_PROTO_REPLAY_CHALLENGE) == 0;
        if (!challenge && strcmp(f->fn, NEG_PROTO_REPLAY_REVEAL) != 0)
            continue;
        bool to_primary = uuid_compare(f->to, g_primary->uuid) == 0;
        const identity_t *who = to_primary ? g_primary : g_replica;
        if (who == silent)
            continue;
        const char *const *st = to_primary ? primary_states : replica_states;
        int index = (int)json_integer_value(json_object_get(f->payload, "index"));
        json_t *answer = json_pack("{s:O, s:O, s:i}",
                                   "task", json_object_get(f->payload, "task"),
                                   "round", json_object_get(f->payload, "round"),
                                   "index", index);
        char h[AT_REPL_HASH_HEX_LEN + 1];
        if (challenge)
        {
            _root(st, index + 1, h);
            json_object_set_new(answer, "digest", json_string(h));
        }
        else
        {
            json_t *rv = json_object();
            if (index >= 2)
            {
                _root(st, index - 1, h);
                json_object_set_new(rv, "prev", json_string(h));
            }
            else
                json_object_set_new(rv, "prev", json_null());
            json_object_set_new(rv, "pre", index >= 1 ? json_string(st[index - 1])
                                                      : json_null());
            json_object_set_new(rv, "state", index < 8 ? json_string(st[index])
                                                       : json_null());
            json_object_set_new(answer, "reveal", rv);
        }
        generic_msg_t msg = {0};
        msg.type = NET_MESSAGE;
        strncpy(msg.info.net_msg.process, "negotiation", PROC_NAME_LEN);
        msg.info.net_msg.function = NEG_PROTO_REPLAY_RESPONSE;
        msg.info.net_msg.verified = true;
        memcpy(&msg.info.net_msg.from_whom, to_primary ? g_pub[0] : g_pub[1],
               sizeof(public_identity_t));
        ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, answer));
        json_decref(answer);
        run_message_handlers(g_proc, NULL, NET_MESSAGE, &msg);
        net_msg_free_obj(&msg.info.net_msg);
    }
}

static const score_t *_score_about(const identity_t *who, bool attested)
{
    for (size_t i = 0; i < g_nscores; i++)
        if (uuid_compare(g_scores[i].subject, who->uuid) == 0
            && g_scores[i].attested == attested)
            return &g_scores[i];
    return NULL;
}

static void _replicate(const char *const *primary, const char *const *replica)
{
    uuid_t t1, t2;
    uuid_generate(t1);
    ck_assert_int_eq(_deliver_result(t1, g_primary, primary), NEG_RESULT_HOLD);
    neg_ext_periodic(g_proc);                  /* the replica goes out */
    ck_assert(_replica_task(t2));
    ck_assert_int_eq(_deliver_result(t2, g_replica, replica), NEG_RESULT_CONSUME);
    neg_ext_periodic(g_proc);                  /* adjudicated */
}

DEFINE_TEST(test_agreement_corroborates_both)
{
    _begin();
    _replicate(HONEST, HONEST);
    ck_assert_uint_eq(g_nscores, 2);
    ck_assert_double_eq_tol(_score_about(g_primary, false)->score, 0.9, 1e-12);
    ck_assert_double_eq_tol(_score_about(g_replica, false)->score, 0.9, 1e-12);
    ck_assert_str_eq(_score_about(g_replica, false)->channel, "replication");
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_game_convicts_the_cheater)
{
    _begin();
    _replicate(HONEST, CHEAT);
    ck_assert_uint_eq(g_nscores, 0);           /* the game is on */
    _play(HONEST, CHEAT, NULL);
    ck_assert_double_eq_tol(_score_about(g_primary, false)->score, 0.9, 1e-12);
    ck_assert_double_eq_tol(_score_about(g_replica, false)->score, 0.1, 1e-12);
    const score_t *att = _score_about(g_replica, true);
    ck_assert_ptr_nonnull(att);                /* D6: the outvoted is attested */
    ck_assert_double_eq_tol(att->score, 0.1, 1e-12);
    ck_assert_ptr_null(_score_about(g_primary, true));
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_primary_can_be_the_cheater)
{
    _begin();
    _replicate(CHEAT, HONEST);
    _play(CHEAT, HONEST, NULL);
    ck_assert_double_eq_tol(_score_about(g_primary, false)->score, 0.1, 1e-12);
    ck_assert_double_eq_tol(_score_about(g_replica, false)->score, 0.9, 1e-12);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_undeclared_capability_is_left_alone)
{
    _begin();
    uuid_t t;
    uuid_generate(t);
    char root[AT_REPL_HASH_HEX_LEN + 1];
    _root(HONEST, 8, root);
    neg_result_info_t info = {
        .task = t, .executor = g_primary->uuid, .capability = "demo.other",
        .kwargs_json = "{}", .result = "s7", .result_len = 2,
        .trace_root = root, .trace_len = 8 };
    ck_assert_int_eq(neg_ext_on_result(g_proc, &info), NEG_RESULT_LEAVE);
    _end();
}
END_TEST_DEFINITION()

/* The hold deadline, made short: twice a 10 ms commit timeout. */
static void _past_the_deadline(void)
{
    usleep(40000);
    neg_ext_periodic(g_proc);
}

DEFINE_TEST(test_silence_mid_game_settles_the_responder_alone)
{
    _begin();
    setenv("AT_REP_COMMIT_TIMEOUT_SEC", "0.01", 1);
    _replicate(HONEST, CHEAT);
    _play(HONEST, CHEAT, g_replica);          /* the replica goes quiet */
    ck_assert_uint_eq(g_nscores, 0);
    _past_the_deadline();
    /* The primary's whole trace re-run and matched; the replica unscored. */
    ck_assert_uint_eq(g_nscores, 1);
    ck_assert_double_eq_tol(_score_about(g_primary, false)->score, 0.9, 1e-12);
    ck_assert_ptr_null(_score_about(g_replica, false));
    unsetenv("AT_REP_COMMIT_TIMEOUT_SEC");
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_silence_from_the_cheater_side_convicts_the_responder)
{
    _begin();
    setenv("AT_REP_COMMIT_TIMEOUT_SEC", "0.01", 1);
    _replicate(HONEST, CHEAT);
    _play(HONEST, CHEAT, g_primary);          /* only the cheater answers */
    _past_the_deadline();
    ck_assert_uint_eq(g_nscores, 2);           /* its score and its attestation */
    ck_assert_double_eq_tol(_score_about(g_replica, false)->score, 0.1, 1e-12);
    ck_assert_ptr_nonnull(_score_about(g_replica, true));
    ck_assert_ptr_null(_score_about(g_primary, false));
    unsetenv("AT_REP_COMMIT_TIMEOUT_SEC");
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_silent_replica_releases_the_primary_to_the_ordinary_arms)
{
    _begin();
    setenv("AT_REP_COMMIT_TIMEOUT_SEC", "0.01", 1);
    uuid_t t1, t2;
    uuid_generate(t1);
    ck_assert_int_eq(_deliver_result(t1, g_primary, HONEST), NEG_RESULT_HOLD);
    neg_ext_periodic(g_proc);
    ck_assert(_replica_task(t2));
    _past_the_deadline();
    ck_assert_uint_eq(g_nscores, 1);
    ck_assert(strcmp(_score_about(g_primary, false)->channel, "replication") != 0);
    /* Its result, arriving after all, is consumed and not scored. */
    ck_assert_int_eq(_deliver_result(t2, g_replica, HONEST), NEG_RESULT_CONSUME);
    unsetenv("AT_REP_COMMIT_TIMEOUT_SEC");
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(ReplicationLive,
          test_agreement_corroborates_both,
          test_the_game_convicts_the_cheater,
          test_the_primary_can_be_the_cheater,
          test_an_undeclared_capability_is_left_alone,
          test_silence_mid_game_settles_the_responder_alone,
          test_silence_from_the_cheater_side_convicts_the_responder,
          test_a_silent_replica_releases_the_primary_to_the_ordinary_arms)
