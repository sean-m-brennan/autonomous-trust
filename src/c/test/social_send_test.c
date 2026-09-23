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

/** @file A user's action must not be scored unless it actually went out.
 *
 *  WHERE THIS CAME FROM. The 2026-09-21 reputation cohort drove `react` on
 *  one node and watched the other never hear of it. The reaction verb
 *  returned rc=0, the reactor accrued its half of the bilateral score, and
 *  `peer_reaction` never reached the wire. An earlier run of the same script
 *  had worked — which is what a lost race looks like.
 *
 *  messaging_send is non-blocking and an AF_UNIX datagram queue holds
 *  net.unix.max_dgram_qlen (10) frames. In a cohort, a transaction burst
 *  fills it routinely. Every directed app sender in id_proc.c DISCARDED the
 *  result, so the frame vanished with nothing said.
 *
 *  WHY THE SECOND HALF MATTERS MORE THAN THE FIRST. A reaction scores
 *  BILATERALLY: the reactor submits on send and the author submits on
 *  receipt, against a task uuid neither side transmits. Accruing when the
 *  frame was lost leaves a transaction in the chain that can never complete —
 *  a permanent half-entry, and a score claimed for an interaction the other
 *  party never had. So the accrual has to be conditional on the send, not
 *  merely logged.
 *
 *  The send is forced to fail through messaging_set_test_hook, the same seam
 *  rep_quorum_test.c and identity_resync_test.c use to observe emissions.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include <jansson.h>
#include <uuid/uuid.h>

#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "identity/id_proc_priv.h"
#include "config/configuration.h"
#include "structures/data.h"
#include "structures/map.h"
#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
#include "utilities/msg_types_priv.h"
#include "utilities/allocation.h"

static char REACT_FN[] = AT_APP_REACT_POST;
static char PUBLISH_FN[] = AT_APP_PUBLISH_POST;

/* A 64-hex content id; only the first 32 chars are read (the task binding). */
static const char POST_ID[] =
    "aa11bb22cc33dd44ee55ff6677889900"
    "aa11bb22cc33dd44ee55ff6677889900";

/* ------------------------------------------------------------------ */
/* Emission capture, with a switch to make the network queue "full"    */
/* ------------------------------------------------------------------ */

static size_t g_reaction_sent;
static size_t g_post_sent;
static bool   g_network_full;

static int _hook(const char *key, const message_type_t type,
                 generic_msg_t *msg, bool blocking)
{
    (void)blocking;
    if (g_network_full && key != NULL && strcmp(key, "network") == 0)
        return EAGAIN;           /* exactly what a saturated queue returns */
    if (type == NET_MESSAGE && msg->info.net_msg.function != NULL
        && strcmp(msg->info.net_msg.function, "peer_reaction") == 0)
        g_reaction_sent++;
    if (type == NET_MESSAGE && msg->info.net_msg.function != NULL
        && strcmp(msg->info.net_msg.function, "peer_post") == 0
        && msg->info.net_msg.group_multicast)
        g_post_sent++;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Fixtures (same shape as identity_resync_test.c's)                   */
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
    strncpy(proc->name, "identity", PROC_NAME_LEN);
    proc->protocol.phase = 3;
    proc->protocol.num_peers = 0;

    uuid_t guuid;
    uuid_generate(guuid);
    group_init(&guuid, (char *)self->address, &proc->protocol.group);
    char self_uuid[UUID_STRING_LEN + 1];
    uuid_unparse_lower(self->uuid, self_uuid);
    group_add_address(&proc->protocol.group, self_uuid, self->address);

    config_t *id_cfg = calloc(1, sizeof(config_t));
    ck_assert_ptr_nonnull(id_cfg);
    id_cfg->name = "identity";
    id_cfg->data_struct = self;
    data_t *id_dat = object_ptr_data((ptr_t)id_cfg, sizeof(config_t));
    ck_assert_ret_ok(map_create(&proc->configs));
    map_set(proc->configs, (map_key_t)"identity", id_dat);

    ck_assert_ret_ok(map_create(&proc->protocol.handlers));
    ck_assert_ret_ok(identity_register_handlers(proc));
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

/* Drive the app verb exactly as the shim does. */
static void _react(process_t *proc, const identity_t *author)
{
    char author_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(author->uuid, author_str);
    json_t *p = json_object();
    json_object_set_new(p, "author", json_string(author_str));
    json_object_set_new(p, "post_id", json_string(POST_ID));

    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = REACT_FN;
    msg.info.net_msg.verified = true;
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, p));
    json_decref(p);
    run_message_handlers(proc, NULL, NET_MESSAGE, &msg);
}

/* Publish a public feed post exactly as the shim does. */
static void _publish(process_t *proc, const char *body)
{
    json_t *p = json_object();
    json_object_set_new(p, "body", json_string(body));
    json_object_set_new(p, "tier", json_integer(0));

    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = PUBLISH_FN;
    msg.info.net_msg.verified = true;
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, p));
    json_decref(p);
    run_message_handlers(proc, NULL, NET_MESSAGE, &msg);
}

static bool _scored(const identity_t *author)
{
    char author_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(author->uuid, author_str);
    return identity_get_last_social_tx(author_str, NULL, NULL);
}

static void _begin(bool network_full)
{
    identity_reset_state();
    g_reaction_sent = 0;
    g_post_sent = 0;
    g_network_full = network_full;
    messaging_set_test_hook(_hook);
}

static void _end(void) { messaging_set_test_hook(NULL); g_network_full = false; }

/* Let the "queue" drain partway through the bounded retry. */
static void *_relent(void *unused)
{
    (void)unused;
    usleep(60000);
    g_network_full = false;
    return NULL;
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

DEFINE_TEST(test_a_reaction_that_goes_out_is_scored)
{
    /* The baseline the failing case is measured against: when the frame
     * leaves, the reactor's half IS accrued. Without this, a bug that simply
     * stopped scoring everything would pass the test below. */
    _begin(false);
    identity_t *me = _mk_identity("me", "10.0.0.1");
    identity_t *author = _mk_identity("author", "10.0.0.2");
    process_t *proc = _mk_process(me);
    _add_peer(proc, author);

    _react(proc, author);

    ck_assert_uint_eq(g_reaction_sent, 1);
    ck_assert(_scored(author));
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_reaction_the_network_queue_refused_is_not_scored)
{
    /* THE regression. The queue is full for the whole bounded retry, so the
     * author never hears of the reaction. Our half must not be recorded:
     * a bilateral task with only one side submitted can never complete, and
     * it would credit an interaction that did not happen. */
    _begin(true);
    identity_t *me = _mk_identity("me", "10.0.0.1");
    identity_t *author = _mk_identity("author", "10.0.0.2");
    process_t *proc = _mk_process(me);
    _add_peer(proc, author);

    _react(proc, author);

    ck_assert_uint_eq(g_reaction_sent, 0);
    ck_assert(!_scored(author));
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_transient_refusal_is_retried_rather_than_dropped)
{
    /* The other half of the fix: a queue that is full NOW but drains a
     * moment later must not lose the action. The hook refuses the first few
     * attempts and then relents, which is what a burst actually looks like —
     * before the retry loop, the very first EAGAIN ended it. */
    _begin(true);
    identity_t *me = _mk_identity("me", "10.0.0.1");
    identity_t *author = _mk_identity("author", "10.0.0.2");
    process_t *proc = _mk_process(me);
    _add_peer(proc, author);

    /* Relent from a background thread after ~60ms — inside the 200ms the
     * bounded retry spends, and well after the first attempt. */
    pthread_t drainer;
    pthread_create(&drainer, NULL, _relent, NULL);

    _react(proc, author);
    pthread_join(drainer, NULL);

    ck_assert_uint_eq(g_reaction_sent, 1);
    ck_assert(_scored(author));
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_published_post_is_multicast)
{
    /* Baseline for the case below: with the queue open, one publish is one
     * group multicast. */
    _begin(false);
    identity_t *me = _mk_identity("me", "10.0.0.1");
    process_t *proc = _mk_process(me);

    _publish(proc, "baseline");

    ck_assert_uint_eq(g_post_sent, 1);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_post_behind_a_burst_still_goes_out)
{
    /* The 2026-09-22 moderation cohort (run 6): bob logged "published post",
     * his network process never multicast it, and neither peer saw it. The
     * post was queued in the same instant as a burst of Paxos asks and the
     * multicast sender discarded the EAGAIN, as the reaction sender above
     * once did. A feed post is a one-shot user action too. */
    _begin(true);
    identity_t *me = _mk_identity("me", "10.0.0.1");
    process_t *proc = _mk_process(me);

    pthread_t drainer;
    pthread_create(&drainer, NULL, _relent, NULL);

    _publish(proc, "behind a burst");
    pthread_join(drainer, NULL);

    ck_assert_uint_eq(g_post_sent, 1);
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(SocialSend,
          test_a_reaction_that_goes_out_is_scored,
          test_a_reaction_the_network_queue_refused_is_not_scored,
          test_a_transient_refusal_is_retried_rather_than_dropped,
          test_a_published_post_is_multicast,
          test_a_post_behind_a_burst_still_goes_out)
