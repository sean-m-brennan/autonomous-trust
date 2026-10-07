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

/** @file Unit tests for identity_periodic_caps_resync — the C mirror of
 *  Python's IdentityProcess._periodic_caps_resync (the late-joiner
 *  capability-loss UDP backstop, memory feedback_late_joiner_caps layer 7).
 *
 *  Builds a minimal process_t (peers[] + group + configs["identity"]),
 *  installs caps for selected peers via the identity_install_peer_caps test
 *  accessor, captures the directed caps_query emissions through the
 *  messaging test hook, and asserts only cap-less peers are re-queried.
 *  Same six cases as tests/a_unit/test_late_joiner_caps_resync.py.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#include <uuid/uuid.h>
#include <jansson.h>

#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "identity/id_proc_priv.h"
#include "identity/group.h"
#include "config/configuration.h"
#include "structures/data.h"
#include "structures/map.h"
#include "processes/processes.h"
#include "utilities/msg_types_priv.h"
#include "processes/capabilities.h"
#include "utilities/message.h"
#include "utilities/allocation.h"

/* ------------------------------------------------------------------ */
/* Capture of caps_query emissions via the messaging test hook.        */
/* ------------------------------------------------------------------ */

#define MAX_CAPTURED 64
static char g_queried_uuids[MAX_CAPTURED][UUID_STRING_LEN + 1];
static size_t g_query_count;
static size_t g_matrix_sends;          /* PEER_CAPABILITIES hand-offs */
static char   g_matrix_names[128];     /* names the last one gave the peer */
static char   g_matrix_peer[UUID_STRING_LEN + 1];

static int _capture_hook(const char *key, const message_type_t type,
                         generic_msg_t *msg, bool blocking)
{
    (void)key; (void)blocking;
    if (type == PEER_CAPABILITIES) {
        g_matrix_sends++;
        g_matrix_names[0] = '\0';
        data_t *dat = NULL;
        array_t *arr = NULL;
        if (map_get(&msg->info.peer_capabilities, g_matrix_peer, &dat) == 0
            && data_object_ptr(dat, (void **)&arr) == 0 && arr != NULL)
            for (size_t i = 0; i < array_size(arr); i++) {
                data_t *cd = NULL;
                capability_t *cap = NULL;
                if (array_get(arr, (int)i, &cd) == 0
                    && data_object_ptr(cd, (void **)&cap) == 0 && cap != NULL) {
                    size_t used = strlen(g_matrix_names);
                    snprintf(g_matrix_names + used, sizeof(g_matrix_names) - used,
                             "%s%s", i ? "," : "", cap->name);
                }
            }
        return 0;
    }
    if (type == NET_MESSAGE && msg->info.net_msg.function != NULL
        && strcmp(msg->info.net_msg.function, "peer_caps_query") == 0
        && g_query_count < MAX_CAPTURED) {
        uuid_unparse_lower(msg->info.net_msg.to_whom.uuid,
                           g_queried_uuids[g_query_count++]);
    }
    return 0;
}

static bool _was_queried(const uuid_t uuid)
{
    char want[UUID_STRING_LEN + 1];
    uuid_unparse_lower(uuid, want);
    for (size_t i = 0; i < g_query_count; i++)
        if (strcmp(g_queried_uuids[i], want) == 0)
            return true;
    return false;
}

/* ------------------------------------------------------------------ */
/* Minimal process_t construction.                                     */
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

/* Build a process whose configs carry @p self, with a non-empty group so
 * the resync guard passes, and an empty peers list (caller appends). */
static process_t *_mk_process(identity_t *self)
{
    process_t *proc = smrt_create(sizeof(process_t));
    ck_assert_ptr_nonnull(proc);
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    strncpy(proc->name, "identity", PROC_NAME_LEN);
    proc->protocol.phase = 3;
    proc->protocol.num_peers = 0;

    /* Group: pinned uuid + one address so the "no group yet" guard fails. */
    uuid_t guuid;
    uuid_generate(guuid);
    group_init(&guuid, (char *)self->address, &proc->protocol.group);
    char self_uuid[UUID_STRING_LEN + 1];
    uuid_unparse_lower(self->uuid, self_uuid);
    group_add_address(&proc->protocol.group, self_uuid, self->address);

    /* configs["identity"] so identity_self_identity resolves self. */
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

static void _give_caps(identity_t *peer, const char *cap)
{
    const char *caps[1] = {cap};
    identity_install_peer_caps(peer->uuid, caps, 1);
}

static void _begin(void)
{
    identity_reset_state();   /* clears peer_caps_map + inits id_state */
    g_query_count = 0;
    g_matrix_sends = 0;
    g_matrix_names[0] = '\0';
    messaging_set_test_hook(_capture_hook);
}

static void _end(void)
{
    messaging_set_test_hook(NULL);
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

DEFINE_TEST(test_capless_peers_each_requeried)
{
    _begin();
    identity_t *me = _mk_identity("coord", "10.0.0.1");
    identity_t *a = _mk_identity("alice", "10.0.0.2");
    identity_t *b = _mk_identity("bob", "10.0.0.3");
    process_t *proc = _mk_process(me);
    _add_peer(proc, a);
    _add_peer(proc, b);

    identity_periodic_caps_resync(proc);

    ck_assert_int_eq(g_query_count, 2);
    ck_assert(_was_queried(a->uuid));
    ck_assert(_was_queried(b->uuid));
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_peer_with_caps_skipped)
{
    _begin();
    identity_t *me = _mk_identity("coord", "10.0.0.1");
    identity_t *a = _mk_identity("alice", "10.0.0.2");
    identity_t *b = _mk_identity("bob", "10.0.0.3");
    _give_caps(a, "airquality_stream");   /* alice known, bob cap-less */
    process_t *proc = _mk_process(me);
    _add_peer(proc, a);
    _add_peer(proc, b);

    identity_periodic_caps_resync(proc);

    ck_assert_int_eq(g_query_count, 1);
    ck_assert(_was_queried(b->uuid));
    ck_assert(!_was_queried(a->uuid));
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_converged_group_emits_nothing)
{
    _begin();
    identity_t *me = _mk_identity("coord", "10.0.0.1");
    identity_t *a = _mk_identity("alice", "10.0.0.2");
    _give_caps(a, "sensor_validation");
    process_t *proc = _mk_process(me);
    _add_peer(proc, a);

    identity_periodic_caps_resync(proc);

    ck_assert_int_eq(g_query_count, 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_self_is_never_queried)
{
    _begin();
    identity_t *me = _mk_identity("coord", "10.0.0.1");
    process_t *proc = _mk_process(me);
    _add_peer(proc, me);   /* self present in peers[] — must be skipped */

    identity_periodic_caps_resync(proc);

    ck_assert_int_eq(g_query_count, 0);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_sweep_bounded_per_run)
{
    _begin();
    identity_t *me = _mk_identity("coord", "10.0.0.1");
    process_t *proc = _mk_process(me);
    int n = CAPS_RESYNC_MAX_PER_SWEEP + 5;
    for (int i = 0; i < n; i++) {
        char nm[16], addr[24];
        snprintf(nm, sizeof(nm), "p%d", i);
        snprintf(addr, sizeof(addr), "10.0.1.%d", i + 1);
        _add_peer(proc, _mk_identity(nm, addr));
    }

    identity_periodic_caps_resync(proc);

    ck_assert_int_eq(g_query_count, CAPS_RESYNC_MAX_PER_SWEEP);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_suppressed_when_not_phase3)
{
    _begin();
    identity_t *me = _mk_identity("coord", "10.0.0.1");
    identity_t *a = _mk_identity("alice", "10.0.0.2");
    process_t *proc = _mk_process(me);
    _add_peer(proc, a);
    proc->protocol.phase = 1;   /* not operational */

    identity_periodic_caps_resync(proc);

    ck_assert_int_eq(g_query_count, 0);
    _end();
}
END_TEST_DEFINITION()

/* @p from's peer_caps_response naming @p caps, stamped @p seq. */
static void _caps_response(process_t *proc, directory_t *queues,
                           identity_t *from, const char *caps_json, int seq)
{
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(from, &pub));
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    static char fn[] = "peer_caps_response";
    msg.info.net_msg.function = fn;
    msg.info.net_msg.verified = true;
    memcpy(&msg.info.net_msg.from_whom, pub, sizeof(public_identity_t));
    json_t *body = json_pack("{s:o, s:i}", "caps", json_loads(caps_json, 0, NULL),
                             "seq", seq);
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, body));
    json_decref(body);
    run_message_handlers(proc, queues, NET_MESSAGE, &msg);
    net_msg_free_obj(&msg.info.net_msg);
    smrt_deref(pub);
}

/* A peer's capabilities, once learned or changed, are handed to the sibling
 * processes as the capability matrix (negotiation fans out only to the peers
 * it names) and kept as identity's own protocol.peer_capabilities. A refresh
 * that changes nothing is not sent again. C used to build no matrix at all,
 * so a C node invited every peer to every task. */
DEFINE_TEST(test_learned_caps_are_handed_on_as_the_matrix)
{
    _begin();
    identity_t *me = _mk_identity("coord", "10.0.0.1");
    identity_t *a = _mk_identity("alice", "10.0.0.2");
    process_t *proc = _mk_process(me);
    ck_assert_ret_ok(map_create(&proc->protocol.handlers));
    ck_assert_ret_ok(identity_register_handlers(proc));
    _add_peer(proc, a);
    uuid_unparse_lower(a->uuid, g_matrix_peer);
    array_t queues;
    ck_assert_ret_ok(array_init(&queues));
    char q_id[] = "identity", q_neg[] = "negotiation";
    array_append(&queues, string_data(q_id, strlen(q_id)));
    array_append(&queues, string_data(q_neg, strlen(q_neg)));

    _caps_response(proc, &queues, a, "[\"data_fetch\"]", 1);
    ck_assert_uint_eq(g_matrix_sends, 1);          /* to negotiation only */
    ck_assert_str_eq(g_matrix_names, "data_fetch");
    ck_assert_ptr_nonnull(proc->protocol.peer_capabilities);

    _caps_response(proc, &queues, a, "[\"data_fetch\"]", 2);
    ck_assert_uint_eq(g_matrix_sends, 1);          /* unchanged: not resent */

    _caps_response(proc, &queues, a, "[\"data_fetch\", \"at.echo-challenge\"]", 3);
    ck_assert_uint_eq(g_matrix_sends, 2);
    ck_assert_str_eq(g_matrix_names, "data_fetch,at.echo-challenge");

    map_free(proc->protocol.peer_capabilities);
    proc->protocol.peer_capabilities = NULL;
    array_free(&queues);
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(LateJoinerCapsResync,
          test_capless_peers_each_requeried,
          test_peer_with_caps_skipped,
          test_converged_group_emits_nothing,
          test_self_is_never_queried,
          test_sweep_bounded_per_run,
          test_suppressed_when_not_phase3,
          test_learned_caps_are_handed_on_as_the_matrix)
