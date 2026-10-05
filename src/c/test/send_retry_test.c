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

#include <uuid/uuid.h>

#include "identity/id_proc_priv.h"
#include "identity/id_send_retry.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"

static char FN_DM[] = "peer_dm";

static bool g_refuse;
static bool g_hard;
#define SEEN_MAX 8
static size_t g_seen;
static char   g_seen_queue[SEEN_MAX][PROC_NAME_LEN + 1];
static char   g_seen_fn[SEEN_MAX][32];
static char   g_seen_obj[SEEN_MAX][64];
static double g_seen_score[SEEN_MAX];

static int _hook(const char *key, const message_type_t type,
                 generic_msg_t *msg, bool blocking)
{
    (void)blocking;
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
        }
    }
    g_seen++;
    return 0;
}

static void _begin(void)
{
    id_send_retry_reset();
    g_refuse = g_hard = false;
    g_seen = 0;
    memset(g_seen_queue, 0, sizeof(g_seen_queue));
    memset(g_seen_fn, 0, sizeof(g_seen_fn));
    memset(g_seen_obj, 0, sizeof(g_seen_obj));
    messaging_set_test_hook(_hook);
}

static void _end(void)
{
    messaging_set_test_hook(NULL);
    id_send_retry_reset();
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
    ck_assert_int_eq((int)id_send_retry_pending("network"), 1);
    ck_assert_int_eq((int)g_seen, 0);

    /* Still full on the next tick: kept, not dropped. */
    ck_assert_int_eq((int)id_send_retry_drain(NULL, NULL, _now()), 0);
    ck_assert_int_eq((int)id_send_retry_pending("network"), 1);

    g_refuse = false;
    ck_assert_int_eq((int)id_send_retry_drain(NULL, NULL, _now()), 1);
    ck_assert_int_eq((int)g_seen, 1);
    ck_assert_str_eq(g_seen_queue[0], "network");
    ck_assert_str_eq(g_seen_fn[0], FN_DM);
    ck_assert_str_eq(g_seen_obj[0], "hello bob");
    ck_assert_int_eq((int)id_send_retry_pending(NULL), 0);

    /* Delivered once: a further tick sends nothing. */
    ck_assert_int_eq((int)id_send_retry_drain(NULL, NULL, _now()), 0);
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
    ck_assert_int_eq((int)id_send_retry_pending("network"), 2);

    g_refuse = false;
    ck_assert_int_eq((int)id_send_retry_drain(NULL, NULL, _now()), 2);
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
    ck_assert_int_eq((int)id_send_retry_pending(NULL), 0);
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
    ck_assert_int_eq((int)id_send_retry_drain(NULL, NULL, _now() + 1.0), 0);
    ck_assert_int_eq((int)id_send_retry_pending(NULL), 1);
    ck_assert_int_eq((int)id_send_retry_drain(
        NULL, NULL, _now() + ID_SEND_RETRY_AGE_DEFAULT + 5.0), 0);
    ck_assert_int_eq((int)id_send_retry_pending(NULL), 0);
    ck_assert_int_eq((int)g_seen, 0);
    _end();
}

/* The list is bounded: past ID_SEND_RETRY_MAX a defer is refused, and the
 * send reports the loss (non-zero) rather than claim it. */
DEFINE_TEST(test_the_list_is_bounded)
{
    _begin();
    generic_msg_t dm;
    _mk_dm(&dm, "x");
    for (int i = 0; i < ID_SEND_RETRY_MAX; i++)
        ck_assert_int_eq(id_send_retry_defer("network", &dm, "a dm", "bob", _now()), 0);
    ck_assert(id_send_retry_defer("network", &dm, "a dm", "bob", _now()) != 0);
    g_refuse = true;
    ck_assert(identity_send_to_network(NULL, &dm, "a dm", "bob") != 0);
    ck_assert_int_eq((int)id_send_retry_pending(NULL), ID_SEND_RETRY_MAX);
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
    ck_assert_int_eq((int)id_send_retry_pending(NULL), 0);
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
    ck_assert_int_eq((int)id_send_retry_pending("reputation"), 1);
    ck_assert_int_eq((int)id_send_retry_pending("network"), 0);
    g_refuse = false;
    ck_assert_int_eq((int)id_send_retry_drain(NULL, NULL, _now()), 1);
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
    ck_assert_int_eq((int)id_send_retry_drain(NULL, NULL, _now()), 0);
    ck_assert_int_eq(g_outcomes, 1);                /* still full: no word */
    g_refuse = false;
    ck_assert_int_eq((int)id_send_retry_drain(NULL, NULL, _now()), 1);
    ck_assert_int_eq(g_outcomes, 2);
    ck_assert_int_eq(g_sent_ok, 2);
    ck_assert_int_eq(g_sent_tag, 8);

    g_refuse = true;                                /* kept, then given up */
    tag = 9;
    ck_assert_int_eq(identity_send_to_network_then(NULL, &dm, "a dm", "bob",
                                                   _on_sent, &tag, sizeof(tag)), 0);
    ck_assert_int_eq((int)id_send_retry_drain(
        NULL, NULL, _now() + ID_SEND_RETRY_AGE_DEFAULT + 5.0), 0);
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

RUN_TESTS(SendRetry,
          test_a_refused_frame_is_kept_and_lands_intact,
          test_a_later_frame_waits_behind_a_backlog,
          test_a_send_after_the_queue_frees_flushes_the_backlog_first,
          test_a_frame_is_given_up_at_the_age_bound,
          test_the_list_is_bounded,
          test_a_hard_fault_is_not_kept,
          test_a_score_to_reputation_is_kept_too,
          test_the_on_sent_callback_hears_each_fate_once)
