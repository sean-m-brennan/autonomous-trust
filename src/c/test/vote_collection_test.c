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

/** @file Unit tests for identity_periodic_vote_collection — the C stand-in for
 *  Python's per-proposal _vote_collection thread (idprocess.py:2227), which
 *  sleeps vote_timeout and then decides the admission on the votes in hand.
 *
 *  What these pin is the gap that made them necessary: a vote tally used to be
 *  compared against the majority ONLY when an inbound vote message arrived
 *  (handle_count_vote). A proposer records its own self-vote immediately, and
 *  in a cohort whose other members are unreachable that self-vote is already a
 *  majority — but nothing ever looked at it, so the node proposed, logged
 *  "proposed peer X for voting", and waited forever. Found 2026-09-17, when a
 *  late joiner could not enter a cohort whose only other member had been
 *  stopped (agora business-ad cohort, phase 3).
 *
 *  Built on the same minimal-process_t pattern as
 *  late_joiner_caps_resync_test.c: real state, mocked plumbing, and the
 *  messaging test hook to observe what went out.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#include <uuid/uuid.h>

#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "identity/id_proc_priv.h"
#include "identity/group.h"
#include "config/configuration.h"
#include "structures/data.h"
#include "structures/map.h"
#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/allocation.h"

/* ------------------------------------------------------------------ */
/* Capture of the admission's outbound announcements.                  */
/* ------------------------------------------------------------------ */

#define MAX_CAPTURED 64
static char g_confirmed[MAX_CAPTURED][UUID_STRING_LEN + 1];
static size_t g_confirm_count;

/* _peer_accepted announces the new peer to the cohort ("peer_accepted") and
 * grants it access ("access_granted"). The confirm names the admitted peer in
 * its payload; for this test the COUNT of admissions is what matters, so the
 * hook records that an admission happened at all. */
static int _capture_hook(const char *key, const message_type_t type,
                         generic_msg_t *msg, bool blocking)
{
    (void)key; (void)blocking;
    if (type == NET_MESSAGE && msg->info.net_msg.function != NULL
        && strcmp(msg->info.net_msg.function, "access_granted") == 0
        && g_confirm_count < MAX_CAPTURED) {
        uuid_unparse_lower(msg->info.net_msg.to_whom.uuid,
                           g_confirmed[g_confirm_count++]);
    }
    return 0;
}

static bool _was_admitted(const uuid_t uuid)
{
    char want[UUID_STRING_LEN + 1];
    uuid_unparse_lower(uuid, want);
    for (size_t i = 0; i < g_confirm_count; i++)
        if (strcmp(g_confirmed[i], want) == 0)
            return true;
    return false;
}

/* ------------------------------------------------------------------ */
/* Minimal process_t construction (mirrors late_joiner_caps_resync).   */
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

static public_identity_t *_publish(identity_t *ident)
{
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(ident, &pub));
    ck_assert_ptr_nonnull(pub);
    return pub;
}

/* A real (empty) queue directory: _peer_accepted's local GROUP broadcast walks
 * the queues array, and array_size() dereferences it, so NULL is not an option
 * (same note as identity_resync_test.c). */
static directory_t *_mk_queues(void)
{
    directory_t *queues = NULL;
    ck_assert_ret_ok(array_create(&queues));
    ck_assert_ptr_nonnull(queues);
    return queues;
}

static void _begin(void)
{
    identity_reset_state();
    g_confirm_count = 0;
    messaging_set_test_hook(_capture_hook);
}

static void _end(void)
{
    messaging_set_test_hook(NULL);
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

/* THE REGRESSION. No vote will ever arrive: for a lone node the proposer's own
 * self-vote is already the whole group's majority, and once the grace period
 * is up the admission must go through on it alone. Before the sweep existed
 * this waited forever. */
DEFINE_TEST(test_self_vote_alone_admits_once_the_grace_period_is_up)
{
    _begin();
    identity_t *me = _mk_identity("ada", "10.0.0.1");
    identity_t *joiner = _mk_identity("bob", "10.0.0.3");
    process_t *proc = _mk_process(me);
    directory_t *queues = _mk_queues();

    public_identity_t *pub = _publish(joiner);
    identity_arm_pending_vote(pub, 1, -1.0);   /* deadline already passed */
    ck_assert(identity_pending_vote_armed(joiner->uuid));

    identity_periodic_vote_collection(proc, queues);

    ck_assert(_was_admitted(joiner->uuid));
    /* Disarmed, so a later tick cannot admit the same peer twice. */
    ck_assert(!identity_pending_vote_armed(joiner->uuid));

    smrt_deref(pub);
    array_free(queues);
    _end();
}
END_TEST_DEFINITION()

/* ISSUES §2.26. The tally counts our own vote, so the bar is a majority of the
 * whole group, roster plus this node. Two of a four-member group is half, not
 * a majority. Under the old MAJORITY(num_peers) it admitted, and both halves
 * of a 2+2 partition could each admit their own newcomers. */
DEFINE_TEST(test_half_of_an_even_group_does_not_admit)
{
    _begin();
    identity_t *me = _mk_identity("ada", "10.0.0.1");
    identity_t *p1 = _mk_identity("amy", "10.0.0.2");
    identity_t *p2 = _mk_identity("bob", "10.0.0.4");
    identity_t *p3 = _mk_identity("ben", "10.0.0.5");
    identity_t *joiner = _mk_identity("cal", "10.0.0.6");
    process_t *proc = _mk_process(me);
    directory_t *queues = _mk_queues();
    _add_peer(proc, p1);
    _add_peer(proc, p2);
    _add_peer(proc, p3);

    public_identity_t *pub = _publish(joiner);
    identity_arm_pending_vote(pub, 2, -1.0);   /* ada + amy: one island */
    identity_periodic_vote_collection(proc, queues);
    ck_assert_int_eq(g_confirm_count, 0);

    identity_arm_pending_vote(pub, 3, -1.0);   /* three of four: a majority */
    identity_periodic_vote_collection(proc, queues);
    ck_assert(_was_admitted(joiner->uuid));

    smrt_deref(pub);
    array_free(queues);
    _end();
}
END_TEST_DEFINITION()

/* The price, stated so it stays deliberate: a two-member group whose other
 * member has stopped answering cannot admit on its own vote any more, the
 * one-and-one split of the case above. */
DEFINE_TEST(test_one_of_two_does_not_admit)
{
    _begin();
    identity_t *me = _mk_identity("ada", "10.0.0.1");
    identity_t *gone = _mk_identity("biz", "10.0.0.2");
    identity_t *joiner = _mk_identity("bob", "10.0.0.3");
    process_t *proc = _mk_process(me);
    directory_t *queues = _mk_queues();
    _add_peer(proc, gone);

    public_identity_t *pub = _publish(joiner);
    identity_arm_pending_vote(pub, 1, -1.0);
    identity_periodic_vote_collection(proc, queues);

    ck_assert_int_eq(g_confirm_count, 0);

    smrt_deref(pub);
    array_free(queues);
    _end();
}
END_TEST_DEFINITION()

/* The grace period is a real wait, not a formality: while it is still running
 * the admission stays pending, so votes in flight can still be counted. */
DEFINE_TEST(test_admission_waits_while_the_grace_period_runs)
{
    _begin();
    identity_t *me = _mk_identity("ada", "10.0.0.1");
    identity_t *joiner = _mk_identity("bob", "10.0.0.3");
    process_t *proc = _mk_process(me);
    directory_t *queues = _mk_queues();

    public_identity_t *pub = _publish(joiner);
    identity_arm_pending_vote(pub, 1, 30.0);   /* plenty of time left */

    identity_periodic_vote_collection(proc, queues);

    ck_assert_int_eq(g_confirm_count, 0);
    ck_assert(identity_pending_vote_armed(joiner->uuid));

    smrt_deref(pub);
    array_free(queues);
    _end();
}
END_TEST_DEFINITION()

/* An expired grace period is not a rubber stamp. With five members (four
 * peers and us) a single self-vote is short of the three a majority needs, so the peer is NOT admitted — the
 * timeout decides on the votes in hand, it does not lower the bar. */
DEFINE_TEST(test_expired_grace_period_still_needs_the_majority)
{
    _begin();
    identity_t *me = _mk_identity("ada", "10.0.0.1");
    identity_t *p1 = _mk_identity("one", "10.0.0.4");
    identity_t *p2 = _mk_identity("two", "10.0.0.5");
    identity_t *p3 = _mk_identity("three", "10.0.0.6");
    identity_t *p4 = _mk_identity("four", "10.0.0.7");
    identity_t *joiner = _mk_identity("bob", "10.0.0.3");
    process_t *proc = _mk_process(me);
    directory_t *queues = _mk_queues();
    _add_peer(proc, p1);
    _add_peer(proc, p2);
    _add_peer(proc, p3);
    _add_peer(proc, p4);

    public_identity_t *pub = _publish(joiner);
    identity_arm_pending_vote(pub, 1, -1.0);

    identity_periodic_vote_collection(proc, queues);

    ck_assert_int_eq(g_confirm_count, 0);
    /* Still disarmed: one shot per proposal, as Python's thread is. A peer that
     * still wants in re-sends request_access, which re-proposes and re-arms. */
    ck_assert(!identity_pending_vote_armed(joiner->uuid));

    /* ...and with the votes actually in hand, the same expiry admits. */
    identity_arm_pending_vote(pub, 3, -1.0);
    identity_periodic_vote_collection(proc, queues);
    ck_assert(_was_admitted(joiner->uuid));

    smrt_deref(pub);
    array_free(queues);
    _end();
}
END_TEST_DEFINITION()

/* A converged cohort has nothing pending, so the sweep that runs on every
 * cadence tick must be silent — it is called ~2x/second forever. */
DEFINE_TEST(test_sweep_is_a_no_op_with_nothing_pending)
{
    _begin();
    identity_t *me = _mk_identity("ada", "10.0.0.1");
    process_t *proc = _mk_process(me);
    directory_t *queues = _mk_queues();

    identity_periodic_vote_collection(proc, queues);
    identity_periodic_vote_collection(proc, queues);

    ck_assert_int_eq(g_confirm_count, 0);
    array_free(queues);
    _end();
}
END_TEST_DEFINITION()

/* Several joiners arriving at once are all decided, not just the first. */
DEFINE_TEST(test_every_expired_admission_is_decided)
{
    _begin();
    identity_t *me = _mk_identity("ada", "10.0.0.1");
    identity_t *b1 = _mk_identity("bob", "10.0.0.3");
    identity_t *b2 = _mk_identity("cal", "10.0.0.8");
    identity_t *b3 = _mk_identity("dee", "10.0.0.9");
    process_t *proc = _mk_process(me);
    directory_t *queues = _mk_queues();

    public_identity_t *p1 = _publish(b1);
    public_identity_t *p2 = _publish(b2);
    public_identity_t *p3 = _publish(b3);
    identity_arm_pending_vote(p1, 1, -1.0);
    identity_arm_pending_vote(p2, 1, -1.0);
    identity_arm_pending_vote(p3, 1, -1.0);

    identity_periodic_vote_collection(proc, queues);

    ck_assert(_was_admitted(b1->uuid));
    ck_assert(_was_admitted(b2->uuid));
    ck_assert(_was_admitted(b3->uuid));

    smrt_deref(p1); smrt_deref(p2); smrt_deref(p3);
    array_free(queues);
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(VoteCollection,
          test_self_vote_alone_admits_once_the_grace_period_is_up,
          test_half_of_an_even_group_does_not_admit,
          test_one_of_two_does_not_admit,
          test_admission_waits_while_the_grace_period_runs,
          test_expired_grace_period_still_needs_the_majority,
          test_sweep_is_a_no_op_with_nothing_pending,
          test_every_expired_admission_is_decided)
