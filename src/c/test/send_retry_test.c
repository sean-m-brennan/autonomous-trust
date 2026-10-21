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

/** @file A one-shot frame a full queue refused past the inline 200 ms is kept
 *  and retried on the identity tick, not lost (ISSUES §2.40).
 *
 *  2026-10-02 host cohorts lost a joiner's full_history (Agora part-603464), a
 *  DM (dev-620062) and a Stele attestation's score hand-off to exactly this.
 *  The messaging test hook stands in for the queues: it refuses with EAGAIN
 *  while g_refuse is set (or fails hard while g_hard is), and records what it
 *  accepts.
 */

#define DEBUG_TESTS 1

#include "test_setup.h"

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

#include <uuid/uuid.h>

#include "identity/id_proc_priv.h"
#include "utilities/send_retry.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
#include "utilities/msg_registry.h"
#include "processes/processes.h"
#include "network/net_message.h"
#include "network/net_proc_priv.h"
#include "network/net_presence.h"

static char FN_DM[] = "peer_dm";

static bool g_refuse;
static bool g_hard;
#define SEEN_MAX 8
static size_t g_seen;
static char   g_seen_queue[SEEN_MAX][PROC_NAME_LEN + 1];
static char   g_seen_fn[SEEN_MAX][32];
static char   g_seen_obj[SEEN_MAX][64];
static double g_seen_score[SEEN_MAX];
static size_t g_tries;     /* every send the hook saw, refused or not */

static int _hook(const char *key, const message_type_t type,
                 generic_msg_t *msg, bool blocking)
{
    (void)blocking;
    g_tries++;
    if (g_hard)
        return EPIPE;
    if (g_refuse)
        return EAGAIN;
    if (g_seen < SEEN_MAX) {
        snprintf(g_seen_queue[g_seen], sizeof(g_seen_queue[0]), "%s", key);
        if (type == NET_MESSAGE) {
            const net_msg_t *nm = &msg->info.net_msg;
            snprintf(g_seen_fn[g_seen], sizeof(g_seen_fn[0]), "%s",
                     nm->function != NULL ? nm->function : "");
            size_t n = nm->len < sizeof(g_seen_obj[0]) - 1
                           ? nm->len : sizeof(g_seen_obj[0]) - 1;
            memcpy(g_seen_obj[g_seen], nm->obj, n);
            g_seen_obj[g_seen][n] = '\0';
        } else if (type == TRANSACTION_SCORE) {
            g_seen_score[g_seen] = msg->info.tx_score.score;
        } else if (type == TASK_RESULT) {
            const task_result_msg_t *tr = &msg->info.task_result;
            size_t n = tr->result_len < sizeof(g_seen_obj[0]) - 1
                           ? tr->result_len : sizeof(g_seen_obj[0]) - 1;
            if (tr->result_data != NULL)
                memcpy(g_seen_obj[g_seen], tr->result_data, n);
            g_seen_obj[g_seen][n] = '\0';
        }
    }
    g_seen++;
    return 0;
}

static void _begin(void)
{
    at_send_retry_reset();
    g_refuse = g_hard = false;
    g_seen = 0;
    g_tries = 0;
    memset(g_seen_queue, 0, sizeof(g_seen_queue));
    memset(g_seen_fn, 0, sizeof(g_seen_fn));
    memset(g_seen_obj, 0, sizeof(g_seen_obj));
    messaging_set_test_hook(_hook);
}

static void _end(void)
{
    messaging_set_test_hook(NULL);
    at_send_retry_reset();
}

/* A DM-shaped frame whose payload is a fresh malloc, as every sender's is. */
static void _mk_dm(generic_msg_t *out, const char *text)
{
    memset(out, 0, sizeof(*out));
    out->type = NET_MESSAGE;
    strncpy(out->info.net_msg.process, "identity", PROC_NAME_LEN);
    out->info.net_msg.function = FN_DM;
    out->info.net_msg.encrypt = true;
    out->info.net_msg.len = strlen(text);
    out->info.net_msg.obj = malloc(out->info.net_msg.len);
    ck_assert_ptr_nonnull(out->info.net_msg.obj);
    memcpy(out->info.net_msg.obj, text, out->info.net_msg.len);
    /* A heap field the kept copy must not share. */
    out->info.net_msg.to_whom.operator_key_binding = malloc(8);
    out->info.net_msg.to_whom.operator_key_binding_len = 8;
}

static void _free_dm(generic_msg_t *out)
{
    /* Scribble first: the kept copy must not be reading this memory. */
    memset(out->info.net_msg.obj, 'x', out->info.net_msg.len);
    net_msg_free_obj(&out->info.net_msg);
    free(out->info.net_msg.to_whom.operator_key_binding);
}

static double _now(void) { return (double)time(NULL); }

/* THE REGRESSION: refused past the inline tries, the frame is kept, the caller
 * frees its own copy, and the next tick delivers it intact. */
DEFINE_TEST(test_a_refused_frame_is_kept_and_lands_intact)
{
    _begin();
    generic_msg_t dm;
    _mk_dm(&dm, "hello bob");
    g_refuse = true;
    ck_assert_int_eq(identity_send_to_network(NULL, &dm, "a direct message", "bob"), 0);
    _free_dm(&dm);
    ck_assert_int_eq((int)at_send_retry_pending("network"), 1);
    ck_assert_int_eq((int)g_seen, 0);

    /* Still full on the next tick: kept, not dropped. */
    ck_assert_int_eq((int)at_send_retry_drain(NULL, NULL, _now()), 0);
    ck_assert_int_eq((int)at_send_retry_pending("network"), 1);

    g_refuse = false;
    ck_assert_int_eq((int)at_send_retry_drain(NULL, NULL, _now()), 1);
    ck_assert_int_eq((int)g_seen, 1);
    ck_assert_str_eq(g_seen_queue[0], "network");
    ck_assert_str_eq(g_seen_fn[0], FN_DM);
    ck_assert_str_eq(g_seen_obj[0], "hello bob");
    ck_assert_int_eq((int)at_send_retry_pending(NULL), 0);

    /* Delivered once: a further tick sends nothing. */
    ck_assert_int_eq((int)at_send_retry_drain(NULL, NULL, _now()), 0);
    ck_assert_int_eq((int)g_seen, 1);
    _end();
}

/* A frame sent while earlier ones are kept for the same queue waits behind
 * them, so two DMs arrive in the order they were sent. */
DEFINE_TEST(test_a_later_frame_waits_behind_a_backlog)
{
    _begin();
    generic_msg_t first, second;
    _mk_dm(&first, "first");
    _mk_dm(&second, "second");
    g_refuse = true;
    ck_assert_int_eq(identity_send_to_network(NULL, &first, "a direct message", "bob"), 0);
    ck_assert_int_eq(identity_send_to_network(NULL, &second, "a direct message", "bob"), 0);
    _free_dm(&first);
    _free_dm(&second);
    ck_assert_int_eq((int)at_send_retry_pending("network"), 2);

    g_refuse = false;
    ck_assert_int_eq((int)at_send_retry_drain(NULL, NULL, _now()), 2);
    ck_assert_int_eq((int)g_seen, 2);
    ck_assert_str_eq(g_seen_obj[0], "first");
    ck_assert_str_eq(g_seen_obj[1], "second");
    _end();
}

/* With the queue free again, a new send first flushes the backlog, then goes
 * out itself, behind it. */
DEFINE_TEST(test_a_send_after_the_queue_frees_flushes_the_backlog_first)
{
    _begin();
    generic_msg_t first, second;
    _mk_dm(&first, "first");
    _mk_dm(&second, "second");
    g_refuse = true;
    ck_assert_int_eq(identity_send_to_network(NULL, &first, "a direct message", "bob"), 0);
    g_refuse = false;
    ck_assert_int_eq(identity_send_to_network(NULL, &second, "a direct message", "bob"), 0);
    _free_dm(&first);
    _free_dm(&second);
    ck_assert_int_eq((int)g_seen, 2);
    ck_assert_str_eq(g_seen_obj[0], "first");
    ck_assert_str_eq(g_seen_obj[1], "second");
    ck_assert_int_eq((int)at_send_retry_pending(NULL), 0);
    _end();
}

/* A queue that never frees: the frame is given up on at the age bound, not
 * kept forever. */
DEFINE_TEST(test_a_frame_is_given_up_at_the_age_bound)
{
    _begin();
    generic_msg_t dm;
    _mk_dm(&dm, "never");
    g_refuse = true;
    ck_assert_int_eq(identity_send_to_network(NULL, &dm, "a direct message", "bob"), 0);
    _free_dm(&dm);
    ck_assert_int_eq((int)at_send_retry_drain(NULL, NULL, _now() + 1.0), 0);
    ck_assert_int_eq((int)at_send_retry_pending(NULL), 1);
    ck_assert_int_eq((int)at_send_retry_drain(
        NULL, NULL, _now() + AT_SEND_RETRY_AGE_DEFAULT + 5.0), 0);
    ck_assert_int_eq((int)at_send_retry_pending(NULL), 0);
    ck_assert_int_eq((int)g_seen, 0);
    _end();
}

/* The list is bounded: past AT_SEND_RETRY_MAX a defer is refused, and the
 * send reports the loss (non-zero) rather than claim it. */
DEFINE_TEST(test_the_list_is_bounded)
{
    _begin();
    generic_msg_t dm;
    _mk_dm(&dm, "x");
    for (int i = 0; i < AT_SEND_RETRY_MAX; i++)
        ck_assert_int_eq(at_send_retry_defer("network", &dm, "a dm", "bob", _now()), 0);
    ck_assert(at_send_retry_defer("network", &dm, "a dm", "bob", _now()) != 0);
    g_refuse = true;
    ck_assert(identity_send_to_network(NULL, &dm, "a dm", "bob") != 0);
    ck_assert_int_eq((int)at_send_retry_pending(NULL), AT_SEND_RETRY_MAX);
    _free_dm(&dm);
    _end();
}

/* A hard transport fault is not saturation: nothing is kept, and the caller
 * hears it. */
DEFINE_TEST(test_a_hard_fault_is_not_kept)
{
    _begin();
    generic_msg_t dm;
    _mk_dm(&dm, "x");
    g_hard = true;
    ck_assert(identity_send_to_network(NULL, &dm, "a dm", "bob") != 0);
    ck_assert_int_eq((int)at_send_retry_pending(NULL), 0);
    _free_dm(&dm);
    _end();
}

/* Not only the network queue, and not only NET_MESSAGE: a social or stele
 * score to the reputation process is kept and delivered the same way. */
DEFINE_TEST(test_a_score_to_reputation_is_kept_too)
{
    _begin();
    generic_msg_t ts = {0};
    ts.type = TRANSACTION_SCORE;
    ts.size = sizeof(tx_score_msg_t);
    uuid_generate(ts.info.tx_score.task_uuid);
    ts.info.tx_score.score = 0.3;
    g_refuse = true;
    ck_assert_int_eq(identity_send_to(NULL, "reputation", &ts, "the attested score",
                                      "reputation"), 0);
    ck_assert_int_eq((int)at_send_retry_pending("reputation"), 1);
    ck_assert_int_eq((int)at_send_retry_pending("network"), 0);
    g_refuse = false;
    ck_assert_int_eq((int)at_send_retry_drain(NULL, NULL, _now()), 1);
    ck_assert_str_eq(g_seen_queue[0], "reputation");
    ck_assert(g_seen_score[0] > 0.299 && g_seen_score[0] < 0.301);
    _end();
}

/* The on-sent callback hears each frame's fate exactly once, with its own
 * copy of the caller's context: at once when the inline send takes it, from
 * the drain when a kept frame lands or ages out, and never after a non-zero
 * return. Social scores a reaction or a report here, so a frame given up on
 * is never scored (ISSUES §2.40). */
static int g_outcomes;
static int g_sent_ok;
static int g_sent_tag;

static void _on_sent(const process_t *proc, const void *ctx, bool sent)
{
    (void)proc;
    g_outcomes++;
    if (sent)
        g_sent_ok++;
    g_sent_tag = *(const int *)ctx;
}

DEFINE_TEST(test_the_on_sent_callback_hears_each_fate_once)
{
    _begin();
    g_outcomes = g_sent_ok = g_sent_tag = 0;
    generic_msg_t dm;
    _mk_dm(&dm, "x");

    int tag = 7;                                    /* sent inline */
    ck_assert_int_eq(identity_send_to_network_then(NULL, &dm, "a dm", "bob",
                                                   _on_sent, &tag, sizeof(tag)), 0);
    ck_assert_int_eq(g_outcomes, 1);
    ck_assert_int_eq(g_sent_ok, 1);
    ck_assert_int_eq(g_sent_tag, 7);

    g_refuse = true;                                /* kept, then lands */
    tag = 8;
    ck_assert_int_eq(identity_send_to_network_then(NULL, &dm, "a dm", "bob",
                                                   _on_sent, &tag, sizeof(tag)), 0);
    tag = 0;                                        /* the list kept a copy */
    ck_assert_int_eq(g_outcomes, 1);
    ck_assert_int_eq((int)at_send_retry_drain(NULL, NULL, _now()), 0);
    ck_assert_int_eq(g_outcomes, 1);                /* still full: no word */
    g_refuse = false;
    ck_assert_int_eq((int)at_send_retry_drain(NULL, NULL, _now()), 1);
    ck_assert_int_eq(g_outcomes, 2);
    ck_assert_int_eq(g_sent_ok, 2);
    ck_assert_int_eq(g_sent_tag, 8);

    g_refuse = true;                                /* kept, then given up */
    tag = 9;
    ck_assert_int_eq(identity_send_to_network_then(NULL, &dm, "a dm", "bob",
                                                   _on_sent, &tag, sizeof(tag)), 0);
    ck_assert_int_eq((int)at_send_retry_drain(
        NULL, NULL, _now() + AT_SEND_RETRY_AGE_DEFAULT + 5.0), 0);
    ck_assert_int_eq(g_outcomes, 3);
    ck_assert_int_eq(g_sent_ok, 2);
    ck_assert_int_eq(g_sent_tag, 9);

    g_refuse = false;                               /* hard fault: no call */
    g_hard = true;
    ck_assert(identity_send_to_network_then(NULL, &dm, "a dm", "bob",
                                            _on_sent, &tag, sizeof(tag)) != 0);
    ck_assert_int_eq(g_outcomes, 3);
    _free_dm(&dm);
    _end();
}

/* Since §2.14 the list serves every process, and more than identity's frames.
 * A TASK_RESULT is kept with its own copy of the result bytes: negotiation
 * hands it a thread-local buffer that the next result overwrites. */
DEFINE_TEST(test_a_task_result_is_kept_with_its_own_bytes)
{
    _begin();
    char result[] = "the answer";
    generic_msg_t tr;
    memset(&tr, 0, sizeof(tr));
    tr.type = TASK_RESULT;
    tr.info.task_result.result_data = (uint8_t *)result;
    tr.info.task_result.result_len = strlen(result);
    g_refuse = true;
    ck_assert_int_eq(at_send(NULL, "AutonomousTrust", &tr, "a task result",
                             "the app", AT_SEND_NOW, NULL, NULL, 0), 0);
    memset(result, 'x', strlen(result));          /* the next result lands */
    g_refuse = false;
    ck_assert_int_eq((int)at_send_retry_drain(NULL, NULL, _now()), 1);
    ck_assert_str_eq(g_seen_obj[0], "the answer");
    _end();
}
END_TEST_DEFINITION()

/* A feature's type serialized as a fixed raw copy is plain data, so it can be
 * kept; one with its own serializer may own pointers, and a TASK does (a map
 * and an array), so those are refused and the loss is reported. */
static int _dummy_to_proto(const void *payload, void **data, size_t *len)
{
    (void)payload; (void)data; (void)len;
    return -1;
}
static const at_msg_vtable_t PLAIN_VT = { "test.kept_plain", 16, NULL, NULL, true };
static const at_msg_vtable_t PROTO_VT = { "test.kept_proto", 16, _dummy_to_proto,
                                          NULL, false };
#define PLAIN_ID (AT_MSG_TYPE_STELE_MAX)
#define PROTO_ID (AT_MSG_TYPE_STELE_MAX - 1)

DEFINE_TEST(test_what_can_be_kept)
{
    _begin();
    (void)at_msg_type_register(PLAIN_ID, &PLAIN_VT);
    (void)at_msg_type_register(PROTO_ID, &PROTO_VT);
    ck_assert(at_send_retry_supported(PLAIN_ID));
    ck_assert(!at_send_retry_supported(PROTO_ID));
    ck_assert(at_send_retry_supported(PEER_OBSERVED));
    ck_assert(at_send_retry_supported(PEER_PRESENCE));
    ck_assert(at_send_retry_supported(TASK_RESULT));
    ck_assert(!at_send_retry_supported(TASK));
    ck_assert(!at_send_retry_supported(GROUP));

    generic_msg_t task;
    memset(&task, 0, sizeof(task));
    task.type = TASK;
    g_refuse = true;
    ck_assert_int_eq(at_send(NULL, "negotiation", &task, "an app task",
                             "negotiation", AT_SEND_NOW, NULL, NULL, 0), EAGAIN);
    ck_assert_int_eq((int)at_send_retry_pending(NULL), 0);
    _end();
}
END_TEST_DEFINITION()

/* AT_SEND_NOW is one try, then kept; without it, ten tries first. */
DEFINE_TEST(test_now_makes_one_try_before_keeping)
{
    _begin();
    generic_msg_t dm;
    _mk_dm(&dm, "x");
    g_refuse = true;
    ck_assert_int_eq(at_send(NULL, "network", &dm, "a dm", "bob", AT_SEND_NOW,
                             NULL, NULL, 0), 0);
    ck_assert_int_eq((int)g_tries, 1);
    at_send_retry_reset();
    g_tries = 0;
    ck_assert_int_eq(at_send(NULL, "network", &dm, "a dm", "bob", 0,
                             NULL, NULL, 0), 0);
    ck_assert_int_eq((int)g_tries, 10);
    _free_dm(&dm);
    _end();
}
END_TEST_DEFINITION()

/* Every process's tick passes through sleep_until, which is where the kept
 * frames are retried: no process has to remember to drain. */
DEFINE_TEST(test_sleep_until_drains_the_list)
{
    _begin();
    generic_msg_t dm;
    _mk_dm(&dm, "tick");
    g_refuse = true;
    ck_assert_int_eq(identity_send_to_network(NULL, &dm, "a dm", "bob"), 0);
    _free_dm(&dm);
    g_refuse = false;
    process_t proc;
    memset(&proc, 0, sizeof(proc));
    gettimeofday(&proc.start, NULL);
    sleep_until(&proc, 0);
    ck_assert_int_eq((int)at_send_retry_pending(NULL), 0);
    ck_assert_int_eq((int)g_seen, 1);
    ck_assert_str_eq(g_seen_obj[0], "tick");
    _end();
}
END_TEST_DEFINITION()

/* The network process hands every inbound wire frame to its sibling in one
 * try, on a receiver thread. A full sibling queue used to drop it there,
 * whatever it was; now it is kept (its payload copied: the wire message owns
 * the bytes and is freed at once) and the tick delivers it. */
DEFINE_TEST(test_an_inbound_frame_is_kept_for_its_sibling)
{
    _begin();
    net_wire_msg_t w;
    memset(&w, 0, sizeof(w));
    snprintf(w.process, sizeof(w.process), "%s", "identity");
    w.function = strdup(FN_DM);
    w.data = (uint8_t *)strdup("from the wire");
    w.data_len = strlen("from the wire");
    logger_t logger = {0};
    g_refuse = true;
    ck_assert_int_eq(net_proc_test_route_to_process(&w, NULL, &logger), 0);
    ck_assert_int_eq((int)g_tries, 1);                 /* one try: a receiver thread */
    memset(w.data, 'x', w.data_len);
    free(w.data);
    free(w.function);
    g_refuse = false;
    ck_assert_int_eq((int)at_send_retry_drain(NULL, NULL, _now()), 1);
    ck_assert_str_eq(g_seen_queue[0], "identity");
    ck_assert_str_eq(g_seen_fn[0], FN_DM);
    ck_assert_str_eq(g_seen_obj[0], "from the wire");
    _end();
}
END_TEST_DEFINITION()

/* A presence frame (doc/architecture/peer-presence.md) is consumed where every
 * inbound frame is routed: its sender is marked heard, and nothing is handed to
 * any sibling. Routed onward it would reach a process that has no use for it,
 * and on a node predating presence, the network's own outbound loop. */
DEFINE_TEST(test_a_presence_frame_is_heard_and_consumed)
{
    _begin();
    net_presence_configure(30.0, 90.0);
    uuid_t peer;
    uuid_generate(peer);
    double t0 = (double)time(NULL);
    ck_assert(!net_presence_tick(&peer, 1, t0, NULL, 0, NULL));

    net_wire_msg_t w;
    memset(&w, 0, sizeof(w));
    snprintf(w.process, sizeof(w.process), "%s", NET_PRESENCE_PROCESS);
    w.function = strdup(NET_PRESENCE_FUNCTION);
    uuid_copy(w.from_whom.uuid, peer);
    logger_t logger = {0};
    ck_assert_int_eq(net_proc_test_route_to_process(&w, NULL, &logger), 0);
    ck_assert_int_eq((int)g_tries, 0);                 /* routed nowhere */
    free(w.function);

    net_presence_change_t row;
    ck_assert_uint_eq(net_presence_snapshot(&peer, 1, &row, 1), 1);
    ck_assert(row.present);
    ck_assert(row.last_heard > 0.0);

    /* Any other frame from the peer is heard AND routed. */
    memset(&w, 0, sizeof(w));
    snprintf(w.process, sizeof(w.process), "%s", "identity");
    w.function = strdup(FN_DM);
    uuid_copy(w.from_whom.uuid, peer);
    ck_assert_int_eq(net_proc_test_route_to_process(&w, NULL, &logger), 0);
    ck_assert_int_eq((int)g_tries, 1);
    free(w.function);
    net_presence_configure(30.0, 90.0);
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(SendRetry,
          test_a_refused_frame_is_kept_and_lands_intact,
          test_a_later_frame_waits_behind_a_backlog,
          test_a_send_after_the_queue_frees_flushes_the_backlog_first,
          test_a_frame_is_given_up_at_the_age_bound,
          test_the_list_is_bounded,
          test_a_hard_fault_is_not_kept,
          test_a_score_to_reputation_is_kept_too,
          test_the_on_sent_callback_hears_each_fate_once,
          test_a_task_result_is_kept_with_its_own_bytes,
          test_what_can_be_kept,
          test_now_makes_one_try_before_keeping,
          test_sleep_until_drains_the_list,
          test_an_inbound_frame_is_kept_for_its_sibling,
          test_a_presence_frame_is_heard_and_consumed)
