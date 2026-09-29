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

/** @file The admission's two frames to a joiner survive a full network queue
 *  (ISSUES §2.30).
 *
 *  access_granted and full_history went out as bare non-blocking sends, right
 *  behind the burst the admission's own key rotation queues. In partition
 *  cohort part-3616429 (2026-09-29) amy's access_granted reached bob and her
 *  full_history did not; bob found no history and bootstrapped a group of his
 *  own. Both now go through identity_send_to_network, as does the rotation's
 *  per-member group_key_update (ISSUES §2.31). The fixture is
 *  vote_collection_test.c's. C only: Python's queues are unbounded.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <errno.h>
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

static size_t g_refuse_each;   /* EAGAIN this many of EACH admission frame first */
static size_t g_refused_grant, g_refused_hist;
static size_t g_granted, g_history;
static size_t g_refuse_keys, g_refused_keys, g_keys_to_member;
static uuid_t g_member_uuid;

static int _capture_hook(const char *key, const message_type_t type,
                         generic_msg_t *msg, bool blocking)
{
    (void)key; (void)blocking;
    if (type != NET_MESSAGE || msg->info.net_msg.function == NULL)
        return 0;
    const char *fn = msg->info.net_msg.function;
    if (strcmp(fn, "access_granted") == 0) {
        if (g_refused_grant < g_refuse_each) { g_refused_grant++; return EAGAIN; }
        g_granted++;
    } else if (strcmp(fn, "group_key_update") == 0
               && uuid_compare(msg->info.net_msg.to_whom.uuid, g_member_uuid) == 0) {
        if (g_refused_keys < g_refuse_keys) { g_refused_keys++; return EAGAIN; }
        g_keys_to_member++;
    } else if (strcmp(fn, "full_history") == 0) {
        if (g_refused_hist < g_refuse_each) { g_refused_hist++; return EAGAIN; }
        g_history++;
    }
    return 0;
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

static void _admit(size_t refuse_each)
{
    identity_reset_state();
    g_refuse_each = refuse_each;
    g_refused_grant = g_refused_hist = g_granted = g_history = 0;
    messaging_set_test_hook(_capture_hook);

    identity_t *me = _mk_identity("amy", "10.0.0.2");
    identity_t *joiner = _mk_identity("bob", "10.0.0.3");
    process_t *proc = _mk_process(me);
    directory_t *queues = _mk_queues();
    public_identity_t *pub = _publish(joiner);
    /* A lone node's own vote is the majority once the grace period is up. */
    identity_arm_pending_vote(pub, 1, -1.0);
    identity_periodic_vote_collection(proc, queues);

    smrt_deref(pub);
    array_free(queues);
    messaging_set_test_hook(NULL);
}

/* THE REGRESSION (part-3616429): the queue refuses the first sends of both
 * frames; the joiner still gets each exactly once. */
DEFINE_TEST(test_a_joiner_gets_its_history_through_a_full_queue)
{
    _admit(3);
    ck_assert_uint_eq(g_refused_grant, 3);
    ck_assert_uint_eq(g_refused_hist, 3);
    ck_assert_uint_eq(g_granted, 1);
    ck_assert_uint_eq(g_history, 1);
}
END_TEST_DEFINITION()

/* Control: an idle queue, one of each, no retries. */
DEFINE_TEST(test_an_idle_queue_sends_each_once)
{
    _admit(0);
    ck_assert_uint_eq(g_granted, 1);
    ck_assert_uint_eq(g_history, 1);
}
END_TEST_DEFINITION()

/* Bounded: a wedged queue is given up on (and logged) after ten tries each. */
DEFINE_TEST(test_a_wedged_queue_is_given_up_on)
{
    _admit(1000);
    ck_assert_uint_eq(g_refused_grant, 10);
    ck_assert_uint_eq(g_refused_hist, 10);
    ck_assert_uint_eq(g_granted, 0);
    ck_assert_uint_eq(g_history, 0);
}
END_TEST_DEFINITION()

/* ISSUES §2.31 (part-3637905): admitting a joiner rotates the group key, and
 * each existing member is handed the new key by its own group_key_update. The
 * queue refuses the first three sends of the member's copy; the member still
 * gets it. Before, a lost copy left that member on the old key for good. */
DEFINE_TEST(test_a_rotation_reaches_a_member_through_a_full_queue)
{
    identity_reset_state();
    g_refuse_each = 0;
    g_refused_grant = g_refused_hist = g_granted = g_history = 0;
    g_refuse_keys = 3;
    g_refused_keys = g_keys_to_member = 0;
    messaging_set_test_hook(_capture_hook);

    identity_t *me = _mk_identity("dee", "10.0.0.6");
    identity_t *member = _mk_identity("bob", "10.0.0.3");
    identity_t *joiner = _mk_identity("ben", "10.0.0.4");
    memcpy(g_member_uuid, member->uuid, sizeof(uuid_t));
    process_t *proc = _mk_process(me);
    _add_peer(proc, member);
    int64_t epoch_before = proc->protocol.group.key_epoch;
    directory_t *queues = _mk_queues();
    public_identity_t *pub = _publish(joiner);
    identity_arm_pending_vote(pub, 2, -1.0);   /* both of us: a majority of two */
    identity_periodic_vote_collection(proc, queues);

    ck_assert_uint_eq(g_granted, 1);
    ck_assert(proc->protocol.group.key_epoch > epoch_before);  /* it rotated */
    ck_assert_uint_eq(g_refused_keys, 3);
    ck_assert(g_keys_to_member >= 1);

    smrt_deref(pub);
    array_free(queues);
    messaging_set_test_hook(NULL);
}
END_TEST_DEFINITION()

RUN_TESTS(AdmissionSend,
          test_a_joiner_gets_its_history_through_a_full_queue,
          test_an_idle_queue_sends_each_once,
          test_a_wedged_queue_is_given_up_on,
          test_a_rotation_reaches_a_member_through_a_full_queue)
