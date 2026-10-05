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
 * re-reports, and C has no deadline sweep, so a refusal or an acceptance lost
 * to a full queue left the requestor's tracker waiting forever. Each is now
 * kept and sent on this process's tick (utilities/send_retry.h).
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
#include "processes/processes.h"
#include "structures/map.h"
#include "utilities/allocation.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
#include "utilities/msg_types_priv.h"
#include "utilities/send_retry.h"

static bool   g_full;          /* the network queue refuses */
static size_t g_out;           /* frames that reached the network queue */
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
static void _invite(const char *cap)
{
    json_t *j = json_object();
    json_object_set_new(j, "__type__", json_string(PY_TYPE_TASK));
    uuid_t task;
    uuid_generate(task);
    char task_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(task, task_str);
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

RUN_TESTS(NegSendKeep,
          test_a_refusal_survives_a_full_queue,
          test_an_acceptance_survives_a_full_queue)
