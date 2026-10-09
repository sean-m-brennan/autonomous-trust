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

/**
 * @file neg_send_keep_test.c
 * @brief Negotiation's frames survive a full network queue (ISSUES §2.14).
 *
 * Every negotiation frame is a one-shot: nothing re-invites, re-refuses or
 * re-reports, so a refusal or an acceptance lost to a full queue left the
 * requestor's tracker waiting forever. Each is now kept and sent on this
 * process's tick (utilities/send_retry.h). The requestor's deadline sweep
 * (negotiation_status_sweep) is the backstop, and is tested here too.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <errno.h>
#include <string.h>
#include <time.h>

#include <jansson.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "identity/identity.h"
#include "identity/identity_priv.h"   /* public_identity_to_json */
#include "negotiation/negotiation.h"
#include "negotiation/neg_proc_priv.h"
#include "processes/capabilities.h"
#include "processes/capabilities_priv.h"
#include "processes/processes.h"
#include "structures/map.h"
#include "utilities/allocation.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
#include "utilities/msg_types_priv.h"
#include "utilities/send_retry.h"

static bool   g_full;          /* the network queue refuses */
static size_t g_out;           /* frames that reached the network queue */
static size_t g_stat_reqs;     /* of those, status requests */
static size_t g_results;       /* of those, task results */
static size_t g_invites;       /* of those, invitations */
static char   g_invited_peer[UUID_STRING_LEN + 1];
static char   g_last_status[32];   /* status named by the last status response */
static char   g_last_fn[32];

static int _hook(const char *key, const message_type_t type,
                 generic_msg_t *msg, bool blocking)
{
    (void)blocking;
    if (key == NULL || strcmp(key, "network") != 0 || type != NET_MESSAGE)
        return 0;
    if (g_full)
        return EAGAIN;
    g_out++;
    if (msg->info.net_msg.function != NULL
        && strcmp(msg->info.net_msg.function, NEG_PROTO_STAT_REQ) == 0)
        g_stat_reqs++;
    if (msg->info.net_msg.function != NULL
        && strcmp(msg->info.net_msg.function, NEG_PROTO_RESULT) == 0)
        g_results++;
    if (msg->info.net_msg.function != NULL
        && strcmp(msg->info.net_msg.function, NEG_PROTO_ANNOUNCE) == 0)
    {
        g_invites++;
        uuid_unparse_lower(msg->info.net_msg.to_whom.uuid, g_invited_peer);
    }
    if (msg->info.net_msg.function != NULL
        && strcmp(msg->info.net_msg.function, NEG_PROTO_STAT_RSP) == 0)
    {
        json_t *j = NULL;
        g_last_status[0] = '\0';
        if (net_msg_unpack_json(&msg->info.net_msg, &j) == 0 && j != NULL)
        {
            json_t *st = json_object_get(j, "status");
            const char *txt = json_is_string(st) ? json_string_value(st)
                : (json_is_object(st)
                   ? json_string_value(json_object_get(st, "__value__")) : NULL);
            snprintf(g_last_status, sizeof(g_last_status), "%s",
                     txt != NULL ? txt : "?");
            json_decref(j);
        }
    }
    snprintf(g_last_fn, sizeof(g_last_fn), "%s",
             msg->info.net_msg.function != NULL ? msg->info.net_msg.function : "");
    return 0;
}

static process_t *g_proc;
static identity_t *g_req_full;
static public_identity_t *g_req;

static void _begin(const char *const *caps, size_t n_caps)
{
    ck_assert(sodium_init() >= 0);
    negotiation_reset_state();
    at_send_retry_reset();
    g_full = false;
    g_out = 0;
    g_stat_reqs = 0;
    g_results = 0;
    g_invites = 0;
    g_last_status[0] = '\0';
    g_last_fn[0] = '\0';
    messaging_set_test_hook(_hook);

    g_proc = smrt_create(sizeof(process_t));
    ck_assert_ptr_nonnull(g_proc);
    pthread_rwlock_init(&g_proc->protocol.peers_rwlock, NULL);
    strncpy(g_proc->name, "negotiation", PROC_NAME_LEN);
    ck_assert_ret_ok(map_create(&g_proc->protocol.handlers));
    g_proc->protocol.phase = 1;
    ck_assert_ret_ok(negotiation_register_handlers(g_proc));
    negotiation_set_own_capabilities(g_proc, caps, n_caps);

    uuid_t u;
    uuid_generate(u);
    ck_assert_ret_ok(identity_create(&u, "10.0.60.1", "req", "req", &g_req_full));
    ck_assert_ret_ok(identity_publish(g_req_full, &g_req));
}

static void _end(void)
{
    messaging_set_test_hook(NULL);
    negotiation_set_own_capabilities(g_proc, NULL, 0);
    at_send_retry_reset();
}

/* An invitation for @p cap, as a requestor's node sends it (the Task JSON the
 * conformance adapter builds; negotiation.c _build_task_json). */
static char g_invited[UUID_STRING_LEN + 1];

static void _invite(const char *cap)
{
    json_t *j = json_object();
    json_object_set_new(j, "__type__", json_string(PY_TYPE_TASK));
    uuid_t task;
    uuid_generate(task);
    char task_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(task, task_str);
    snprintf(g_invited, sizeof(g_invited), "%s", task_str);
    json_object_set_new(j, "uuid", json_pack("{s:s, s:s}", "__type__", "UUID",
                                             "__value__", task_str));
    json_t *req_j = NULL;
    ck_assert_ret_ok(public_identity_to_json(g_req, &req_j));
    json_object_set_new(j, "requestor", req_j);
    json_object_set_new(j, "size", json_integer(1));
    json_object_set_new(j, "seq", json_integer(1));

    json_t *params = json_object();
    json_object_set_new(params, "__type__", json_string(PY_TYPE_TASK_PARAMS));
    json_object_set_new(params, "_capability",
                        json_pack("{s:s, s:s, s:i, s:i}", "__type__",
                                  PY_TYPE_CAPABILITY, "name", cap,
                                  "required_tier", 0, "transaction_weight", 1));
    json_object_set_new(params, "_flexible", json_true());
    time_t now = time(NULL);
    struct tm tm_utc;
    gmtime_r(&now, &tm_utc);
    char when[64];
    snprintf(when, sizeof(when), "%04d-%02d-%02dT%02d:%02d:%02d+00:00",
             tm_utc.tm_year + 1900, tm_utc.tm_mon + 1, tm_utc.tm_mday,
             tm_utc.tm_hour, tm_utc.tm_min, tm_utc.tm_sec);
    json_object_set_new(params, "when", json_pack("{s:s, s:s}", "__type__",
                                                  "datetime", "__value__", when));
    json_object_set_new(params, "duration", json_pack("{s:s, s:f}", "__type__",
                                                      "timedelta", "__value__", 60.0));
    json_object_set_new(params, "timeout", json_pack("{s:s, s:f}", "__type__",
                                                     "timedelta", "__value__", 0.0));
    json_object_set_new(params, "args", json_array());
    json_object_set_new(params, "kwargs", json_object());
    json_object_set_new(j, "parameters", params);

    generic_msg_t in;
    memset(&in, 0, sizeof(in));
    in.type = NET_MESSAGE;
    strncpy(in.info.net_msg.process, "negotiation", PROC_NAME_LEN);
    in.info.net_msg.function = NEG_PROTO_ANNOUNCE;
    memcpy(&in.info.net_msg.from_whom, g_req, sizeof(public_identity_t));
    ck_assert_ret_ok(net_msg_pack_json(&in.info.net_msg, j));
    json_decref(j);
    run_message_handlers(g_proc, NULL, NET_MESSAGE, &in);
    net_msg_free_obj(&in.info.net_msg);
}

/* THE REGRESSION: a refusal the full queue would not take is kept, and goes
 * out on the next tick; the requestor's tracker can then cancel its slot. */
DEFINE_TEST(test_a_refusal_survives_a_full_queue)
{
    static const char *const mine[] = { "not_the_one_asked" };
    _begin(mine, 1);
    g_full = true;
    _invite("noop");
    ck_assert_uint_eq(g_out, 0);
    ck_assert_uint_eq(at_send_retry_pending("network"), 1);

    g_full = false;
    ck_assert_uint_eq(at_send_retry_drain(g_proc, NULL, (double)time(NULL)), 1);
    ck_assert_uint_eq(g_out, 1);
    ck_assert_str_eq(g_last_fn, NEG_PROTO_REFUSE);
    _end();
}
END_TEST_DEFINITION()

/* The same for an acceptance. */
DEFINE_TEST(test_an_acceptance_survives_a_full_queue)
{
    static const char *const mine[] = { "noop" };
    _begin(mine, 1);
    g_full = true;
    _invite("noop");
    ck_assert_uint_eq(g_out, 0);
    ck_assert_uint_eq(at_send_retry_pending("network"), 1);

    g_full = false;
    ck_assert_uint_eq(at_send_retry_drain(g_proc, NULL, (double)time(NULL)), 1);
    ck_assert_str_eq(g_last_fn, NEG_PROTO_ACCEPT);
    _end();
}
END_TEST_DEFINITION()

/* -- the requestor's deadline sweep ------------------------------------------ */

static identity_t *g_peer_full;
static public_identity_t *g_peer;
static char g_task_str[UUID_STRING_LEN + 1];
static double g_t0;

static void _dispatch(char *function, const public_identity_t *from, json_t *j)
{
    generic_msg_t in;
    memset(&in, 0, sizeof(in));
    in.type = NET_MESSAGE;
    strncpy(in.info.net_msg.process, "negotiation", PROC_NAME_LEN);
    in.info.net_msg.function = function;
    memcpy(&in.info.net_msg.from_whom, from, sizeof(public_identity_t));
    ck_assert_ret_ok(net_msg_pack_json(&in.info.net_msg, j));
    run_message_handlers(g_proc, NULL, NET_MESSAGE, &in);
    net_msg_free_obj(&in.info.net_msg);
}

static json_t *_uuid_json(void)
{
    return json_pack("{s:s, s:s}", "__type__", "UUID", "__value__", g_task_str);
}

/* This node starts a one-second task with a one-second timeout, invites its
 * one peer, and (when @p ack) the peer accepts. The deadline is t0 + 2 s. */
static void _begin_requestor(bool ack)
{
    static const char *const none[] = { "unused" };
    _begin(none, 1);
    uuid_t u;
    uuid_generate(u);
    ck_assert_ret_ok(identity_create(&u, "10.0.60.2", "peer", "peer", &g_peer_full));
    ck_assert_ret_ok(identity_publish(g_peer_full, &g_peer));
    memcpy(&g_proc->protocol.peers[0], g_peer, sizeof(public_identity_t));
    g_proc->protocol.num_peers = 1;

    uuid_t task;
    uuid_generate(task);
    uuid_unparse_lower(task, g_task_str);
    time_t now = time(NULL);
    g_t0 = (double)now;
    struct tm tm_utc;
    gmtime_r(&now, &tm_utc);
    char when[64];
    snprintf(when, sizeof(when), "%04d-%02d-%02dT%02d:%02d:%02d+00:00",
             tm_utc.tm_year + 1900, tm_utc.tm_mon + 1, tm_utc.tm_mday,
             tm_utc.tm_hour, tm_utc.tm_min, tm_utc.tm_sec);
    json_t *params = json_object();
    json_object_set_new(params, "__type__", json_string(PY_TYPE_TASK_PARAMS));
    json_object_set_new(params, "_capability",
                        json_pack("{s:s, s:s, s:i, s:i}", "__type__",
                                  PY_TYPE_CAPABILITY, "name", "noop",
                                  "required_tier", 0, "transaction_weight", 1));
    json_object_set_new(params, "_flexible", json_true());
    json_object_set_new(params, "when", json_pack("{s:s, s:s}", "__type__",
                                                  "datetime", "__value__", when));
    json_object_set_new(params, "duration", json_pack("{s:s, s:f}", "__type__",
                                                      "timedelta", "__value__", 1.0));
    json_object_set_new(params, "timeout", json_pack("{s:s, s:f}", "__type__",
                                                     "timedelta", "__value__", 1.0));
    json_object_set_new(params, "args", json_array());
    json_object_set_new(params, "kwargs", json_object());
    json_t *j = json_object();
    json_object_set_new(j, "__type__", json_string(PY_TYPE_TASK));
    json_object_set_new(j, "uuid", _uuid_json());
    json_t *req_j = NULL;
    ck_assert_ret_ok(public_identity_to_json(g_req, &req_j));
    json_object_set_new(j, "requestor", req_j);
    json_object_set_new(j, "size", json_integer(1));
    json_object_set_new(j, "parameters", params);
    _dispatch(NEG_PROTO_START, g_req, j);
    json_decref(j);
    ck_assert(negotiation_has_my_task_uuid(task));
    ck_assert_str_eq(g_last_fn, NEG_PROTO_ANNOUNCE);

    if (ack)
    {
        json_t *a = json_object();
        json_object_set_new(a, "uuid", _uuid_json());
        _dispatch(NEG_PROTO_ACCEPT, g_peer, a);
        json_decref(a);
    }
}

static bool _still_tracked(void)
{
    uuid_t task;
    ck_assert_int_eq(uuid_parse(g_task_str, task), 0);
    return negotiation_has_my_task_uuid(task);
}

/* Before the deadline nothing is asked; after it the confirmed participant is
 * asked once per round, a round waits out an extension's worth (the 1 s
 * timeout) before the next, and after NEG_STATUS_ASKS silent rounds the task
 * is given up and forgotten. */
DEFINE_TEST(test_a_silent_participant_is_asked_then_given_up)
{
    _begin_requestor(true);
    ck_assert_uint_eq(negotiation_status_sweep(g_proc, g_t0 + 1.0), 0);
    ck_assert_uint_eq(g_stat_reqs, 0);

    ck_assert_uint_eq(negotiation_status_sweep(g_proc, g_t0 + 10.0), 0);
    ck_assert_uint_eq(g_stat_reqs, 1);
    ck_assert_uint_eq(negotiation_status_sweep(g_proc, g_t0 + 10.5), 0);
    ck_assert_uint_eq(g_stat_reqs, 1);           /* still waiting */
    ck_assert_uint_eq(negotiation_status_sweep(g_proc, g_t0 + 12.0), 0);
    ck_assert_uint_eq(negotiation_status_sweep(g_proc, g_t0 + 14.0), 0);
    ck_assert_uint_eq(g_stat_reqs, 3);
    ck_assert(_still_tracked());

    ck_assert_uint_eq(negotiation_status_sweep(g_proc, g_t0 + 16.0), 1);
    ck_assert_uint_eq(g_stat_reqs, 3);
    ck_assert(!_still_tracked());
    ck_assert_uint_eq(negotiation_status_sweep(g_proc, g_t0 + 30.0), 0);
    _end();
}
END_TEST_DEFINITION()

/* A live answer to an outstanding request moves the deadline, so the next
 * pass asks nothing, and the count of silent rounds starts over. */
DEFINE_TEST(test_a_live_answer_extends_and_resets_the_count)
{
    _begin_requestor(true);
    ck_assert_uint_eq(negotiation_status_sweep(g_proc, g_t0 + 3.0), 0);
    ck_assert_uint_eq(g_stat_reqs, 1);

    json_t *r = json_object();
    json_object_set_new(r, "uuid", _uuid_json());
    json_object_set_new(r, "status", json_integer(NEG_RUNNING));
    _dispatch(NEG_PROTO_STAT_RSP, g_peer, r);
    json_decref(r);

    /* Deadline now t0 + 3 s; asked again only after it. */
    ck_assert_uint_eq(negotiation_status_sweep(g_proc, g_t0 + 3.0), 0);
    ck_assert_uint_eq(g_stat_reqs, 1);
    for (int i = 0; i < 3; i++)
        ck_assert_uint_eq(negotiation_status_sweep(g_proc, g_t0 + 5.0 + 2.0 * i), 0);
    ck_assert_uint_eq(g_stat_reqs, 4);           /* three fresh rounds */
    ck_assert(_still_tracked());
    _end();
}
END_TEST_DEFINITION()

/* Nobody accepted: nobody to ask, so the task is given up at the deadline. */
DEFINE_TEST(test_an_unaccepted_task_is_given_up_at_the_deadline)
{
    _begin_requestor(false);
    ck_assert_uint_eq(negotiation_status_sweep(g_proc, g_t0 + 3.0), 1);
    ck_assert_uint_eq(g_stat_reqs, 0);
    ck_assert(!_still_tracked());
    _end();
}
END_TEST_DEFINITION()

/* -- the worker side: a job runs off the loop ---------------------------------- */

static bool g_release;   /* lets the blocking capability return (atomic) */

static int _block_until_released(const char *kwargs_json, char *out, size_t len)
{
    (void)kwargs_json;
    for (int i = 0; i < 500 && !__atomic_load_n(&g_release, __ATOMIC_ACQUIRE); i++)   /* at most 5 s */
        nanosleep(&(struct timespec){ .tv_sec = 0, .tv_nsec = 10000000 }, NULL);
    snprintf(out, len, "%s", "released");
    return 0;
}

/* A status request about g_invited, as the requestor sends it. */
static void _ask_status(void)
{
    json_t *j = json_object();
    json_object_set_new(j, "__type__", json_string(PY_TYPE_TASK));
    json_object_set_new(j, "uuid", json_pack("{s:s, s:s}", "__type__", "UUID",
                                             "__value__", g_invited));
    _dispatch(NEG_PROTO_STAT_REQ, g_req, j);
    json_decref(j);
}

/* While its capability runs, the job is answered `running`, and the loop is
 * free to answer at all; once it finishes the result goes out and the task is
 * no longer this worker's to report on. A C worker used to run the job inline
 * and could only ever say `pending` or `unknown`. */
DEFINE_TEST(test_a_running_job_answers_running)
{
    static bool registered = false;
    if (!registered)
    {
        ck_assert_ret_ok(capability_table_append("test.block", NULL,
                                                 _block_until_released));
        registered = true;
    }
    static const char *const mine[] = { "test.block" };
    _begin(mine, 1);
    memcpy(&g_proc->protocol.peers[0], g_req, sizeof(public_identity_t));
    g_proc->protocol.num_peers = 1;
    __atomic_store_n(&g_release, false, __ATOMIC_RELEASE);

    _invite("test.block");
    ck_assert_str_eq(g_last_fn, NEG_PROTO_ACCEPT);
    _ask_status();
    ck_assert_str_eq(g_last_status, "pending");

    ck_assert_uint_eq(negotiation_run_due_jobs(g_proc), 1);
    _ask_status();
    ck_assert_str_eq(g_last_status, "running");
    ck_assert_uint_eq(g_results, 0);

    __atomic_store_n(&g_release, true, __ATOMIC_RELEASE);
    size_t left = 1;
    for (int i = 0; i < 500 && left > 0; i++)
    {
        nanosleep(&(struct timespec){ .tv_sec = 0, .tv_nsec = 10000000 }, NULL);
        left = negotiation_run_due_jobs(g_proc);
    }
    ck_assert_uint_eq(left, 0);
    ck_assert_uint_eq(g_results, 1);
    _ask_status();
    ck_assert_str_eq(g_last_status, "unknown");
    _end();
}
END_TEST_DEFINITION()

/* With identity's capability matrix installed, a task is offered only to the
 * peers it names for the capability; without one, every peer is (the
 * fallback C used to be stuck on, since nothing ever installed one). */
DEFINE_TEST(test_the_matrix_narrows_the_fanout)
{
    _begin_requestor(false);                     /* one peer, broadcast */
    ck_assert_uint_eq(g_invites, 1);

    /* A second peer; the matrix says only it can do `noop`. */
    identity_t *other_full = NULL;
    public_identity_t *other = NULL;
    uuid_t u;
    uuid_generate(u);
    ck_assert_ret_ok(identity_create(&u, "10.0.60.3", "other", "other", &other_full));
    ck_assert_ret_ok(identity_publish(other_full, &other));
    memcpy(&g_proc->protocol.peers[1], other, sizeof(public_identity_t));
    g_proc->protocol.num_peers = 2;
    char other_str[UUID_STRING_LEN + 1], peer_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(other->uuid, other_str);
    uuid_unparse_lower(g_peer->uuid, peer_str);
    static const char *const noop[] = { "noop" };
    static const char *const elsewise[] = { "something_else" };
    map_t *matrix = NULL;
    ck_assert_ret_ok(map_create(&matrix));
    ck_assert_ret_ok(peer_capabilities_add(matrix, other_str, noop, 1));
    ck_assert_ret_ok(peer_capabilities_add(matrix, peer_str, elsewise, 1));
    g_proc->protocol.peer_capabilities = matrix;

    g_invites = 0;
    uuid_t task;
    uuid_generate(task);
    uuid_unparse_lower(task, g_task_str);
    json_t *params = json_pack("{s:s, s:{s:s, s:s, s:i, s:i}, s:b}",
                               "__type__", PY_TYPE_TASK_PARAMS,
                               "_capability", "__type__", PY_TYPE_CAPABILITY,
                               "name", "noop", "required_tier", 0,
                               "transaction_weight", 1, "_flexible", 1);
    json_t *j = json_pack("{s:s, s:o, s:i, s:o}", "__type__", PY_TYPE_TASK,
                          "uuid", _uuid_json(), "size", 1, "parameters", params);
    _dispatch(NEG_PROTO_START, g_req, j);
    json_decref(j);
    ck_assert_uint_eq(g_invites, 1);
    ck_assert_str_eq(g_invited_peer, other_str);

    g_proc->protocol.peer_capabilities = NULL;
    map_free(matrix);
    smrt_deref(other);
    _end();
}
END_TEST_DEFINITION()

/* A peer the network process reports absent (PEER_PRESENCE,
 * doc/architecture/peer-presence.md) is not invited: asking it to work would
 * only time out. It stays on the roster, and is invited again once present. */
DEFINE_TEST(test_an_absent_peer_is_not_invited)
{
    _begin_requestor(false);                     /* one peer, broadcast */
    ck_assert_uint_eq(g_invites, 1);

    identity_t *other_full = NULL;
    public_identity_t *other = NULL;
    uuid_t u;
    uuid_generate(u);
    ck_assert_ret_ok(identity_create(&u, "10.0.60.4", "other", "other", &other_full));
    ck_assert_ret_ok(identity_publish(other_full, &other));
    memcpy(&g_proc->protocol.peers[1], other, sizeof(public_identity_t));
    g_proc->protocol.num_peers = 2;
    char peer_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(g_peer->uuid, peer_str);

    /* Delivered the way the network process sends it. */
    generic_msg_t presence = {0};
    presence.type = PEER_PRESENCE;
    memcpy(presence.info.peer_presence.peer_uuid, other->uuid, sizeof(uuid_t));
    presence.info.peer_presence.present = false;
    ck_assert(run_message_handlers(g_proc, NULL, PEER_PRESENCE, &presence));
    ck_assert(g_proc->protocol.peer_absent[1]);

    for (int round = 0; round < 2; round++) {
        g_invites = 0;
        uuid_t task;
        uuid_generate(task);
        uuid_unparse_lower(task, g_task_str);
        json_t *params = json_pack("{s:s, s:{s:s, s:s, s:i, s:i}, s:b}",
                                   "__type__", PY_TYPE_TASK_PARAMS,
                                   "_capability", "__type__", PY_TYPE_CAPABILITY,
                                   "name", "noop", "required_tier", 0,
                                   "transaction_weight", 1, "_flexible", 1);
        json_t *j = json_pack("{s:s, s:o, s:i, s:o}", "__type__", PY_TYPE_TASK,
                              "uuid", _uuid_json(), "size", 1, "parameters", params);
        _dispatch(NEG_PROTO_START, g_req, j);
        json_decref(j);
        if (round == 0) {
            ck_assert_uint_eq(g_invites, 1);
            ck_assert_str_eq(g_invited_peer, peer_str);
            presence.info.peer_presence.present = true;
            ck_assert(run_message_handlers(g_proc, NULL, PEER_PRESENCE, &presence));
            ck_assert(!g_proc->protocol.peer_absent[1]);
        } else {
            ck_assert_uint_eq(g_invites, 2);     /* back: invited again */
        }
    }

    smrt_deref(other);
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(NegSendKeep,
          test_a_refusal_survives_a_full_queue,
          test_an_acceptance_survives_a_full_queue,
          test_a_silent_participant_is_asked_then_given_up,
          test_a_live_answer_extends_and_resets_the_count,
          test_an_unaccepted_task_is_given_up_at_the_deadline,
          test_a_running_job_answers_running,
          test_the_matrix_narrows_the_fanout,
          test_an_absent_peer_is_not_invited)
