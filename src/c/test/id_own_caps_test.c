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

/** @file A C node advertises what it can do (ISSUES §2.63).
 *
 *  Only the conformance adapter ever installed identity's own capability list,
 *  so every production C node answered a caps_query with an empty one. Once
 *  identity handed negotiation the capability matrix (§2.56), every peer in it
 *  held no capabilities and no task invited anybody: Stele tm-2434079 logged
 *  "no capable peers found" for every probe after the bootstrap window, and
 *  the observer never scored the verifier. identity_advertise_local_capabilities
 *  installs the capability table's local rows at startup. The fixture is
 *  late_joiner_caps_resync_test.c's.
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

/* The last peer_caps_response body, and the names the last capability matrix
 * gave g_matrix_peer. */
static json_t *g_response;
static size_t  g_matrix_sends;
static char    g_matrix_names[256];
static char    g_matrix_peer[UUID_STRING_LEN + 1];

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
                             "%s%s", used ? "," : "", cap->name);
                }
            }
        return 0;
    }
    if (type == NET_MESSAGE && msg->info.net_msg.function != NULL
        && strcmp(msg->info.net_msg.function, "peer_caps_response") == 0
        && msg->info.net_msg.obj != NULL) {
        json_decref(g_response);
        g_response = json_loads((const char *)msg->info.net_msg.obj, 0, NULL);
    }
    return 0;
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
    memcpy(&proc->protocol.peers[proc->protocol.num_peers], pub,
           sizeof(public_identity_t));
    proc->protocol.num_peers++;
    smrt_deref(pub);
}

/* Deliver @p function from @p from with @p body (borrowed) to @p proc. */
static void _deliver(process_t *proc, directory_t *queues, identity_t *from,
                     char *function, json_t *body)
{
    public_identity_t *pub = NULL;
    ck_assert_ret_ok(identity_publish(from, &pub));
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "identity", PROC_NAME_LEN);
    msg.info.net_msg.function = function;
    msg.info.net_msg.verified = true;
    memcpy(&msg.info.net_msg.from_whom, pub, sizeof(public_identity_t));
    ck_assert_ret_ok(net_msg_pack_json(&msg.info.net_msg, body));
    run_message_handlers(proc, queues, NET_MESSAGE, &msg);
    net_msg_free_obj(&msg.info.net_msg);
    smrt_deref(pub);
}

static char QUERY_FN[] = "peer_caps_query";
static char RESPONSE_FN[] = "peer_caps_response";

/* @p proc's answer to a caps_query from @p asker, as a comma-joined list. */
static void _answer(process_t *proc, identity_t *asker, char *out, size_t n)
{
    json_decref(g_response);
    g_response = NULL;
    json_t *empty = json_object();
    _deliver(proc, NULL, asker, QUERY_FN, empty);
    json_decref(empty);
    ck_assert_ptr_nonnull(g_response);
    json_t *caps = json_object_get(g_response, "caps");
    ck_assert(json_is_array(caps));
    out[0] = '\0';
    size_t i;
    json_t *c;
    json_array_foreach(caps, i, c) {
        size_t used = strlen(out);
        snprintf(out + used, n - used, "%s%s", used ? "," : "",
                 json_string_value(c));
    }
}

static void _begin(void)
{
    unsetenv("AT_BOOTSTRAP_DISABLED");
    identity_reset_state();
    g_matrix_sends = 0;
    g_matrix_names[0] = '\0';
    messaging_set_test_hook(_capture_hook);
}

static void _end(void)
{
    json_decref(g_response);
    g_response = NULL;
    unsetenv("AT_BOOTSTRAP_DISABLED");
    messaging_set_test_hook(NULL);
}

/* THE REGRESSION, answering side: before, the answer was an empty list. */
DEFINE_TEST(test_a_node_advertises_its_capability_table)
{
    _begin();
    identity_t *me = _mk_identity("verifier", "10.0.0.1");
    identity_t *asker = _mk_identity("observer", "10.0.0.2");
    process_t *proc = _mk_process(me);
    char got[256];
    _answer(proc, asker, got, sizeof(got));
    ck_assert_str_eq(got, "");                  /* nothing installed yet */

    ck_assert(identity_advertise_local_capabilities(proc) >= 3);
    _answer(proc, asker, got, sizeof(got));
    ck_assert_ptr_nonnull(strstr(got, "at.handshake"));
    ck_assert_ptr_nonnull(strstr(got, "at.time-attest"));
    ck_assert_ptr_nonnull(strstr(got, "at.echo-challenge"));
    _end();
}
END_TEST_DEFINITION()

/* A list already installed (the conformance adapter's fixtures) stands, and a
 * node that will not answer probes does not claim them. */
DEFINE_TEST(test_an_installed_list_stands_and_disabled_probes_are_not_claimed)
{
    _begin();
    identity_t *me = _mk_identity("verifier", "10.0.0.1");
    identity_t *asker = _mk_identity("observer", "10.0.0.2");
    process_t *proc = _mk_process(me);
    const char *mine[] = {"data_fetch"};
    identity_set_own_capabilities(proc, mine, 1);
    ck_assert_uint_eq(identity_advertise_local_capabilities(proc), 0);
    char got[256];
    _answer(proc, asker, got, sizeof(got));
    ck_assert_str_eq(got, "data_fetch");

    identity_reset_state();
    process_t *quiet = _mk_process(me);
    setenv("AT_BOOTSTRAP_DISABLED", "1", 1);
    identity_advertise_local_capabilities(quiet);
    _answer(quiet, asker, got, sizeof(got));
    ck_assert_ptr_null(strstr(got, "at."));
    _end();
}
END_TEST_DEFINITION()

/* THE REGRESSION, end to end: the observer hands negotiation a matrix in which
 * the verifier can run the probes. Before, the verifier's entry was empty and
 * negotiation's filter refused it every task. */
DEFINE_TEST(test_the_querier_learns_the_probes)
{
    _begin();
    identity_t *verifier = _mk_identity("verifier", "10.0.0.1");
    identity_t *observer = _mk_identity("observer", "10.0.0.2");
    process_t *vproc = _mk_process(verifier);
    identity_advertise_local_capabilities(vproc);
    char got[256];
    _answer(vproc, observer, got, sizeof(got));
    json_t *answer = json_incref(g_response);

    identity_reset_state();
    process_t *oproc = _mk_process(observer);
    _add_peer(oproc, verifier);
    uuid_unparse_lower(verifier->uuid, g_matrix_peer);
    array_t queues;
    ck_assert_ret_ok(array_init(&queues));
    char q_id[] = "identity", q_neg[] = "negotiation";
    array_append(&queues, string_data(q_id, strlen(q_id)));
    array_append(&queues, string_data(q_neg, strlen(q_neg)));
    _deliver(oproc, &queues, verifier, RESPONSE_FN, answer);
    json_decref(answer);

    ck_assert_uint_eq(g_matrix_sends, 1);
    ck_assert_ptr_nonnull(strstr(g_matrix_names, "at.handshake"));
    ck_assert_ptr_nonnull(strstr(g_matrix_names, "at.time-attest"));
    ck_assert(identity_get_peer_caps_count(verifier->uuid) >= 3);

    map_free(oproc->protocol.peer_capabilities);
    oproc->protocol.peer_capabilities = NULL;
    array_free(&queues);
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(IdOwnCaps,
          test_a_node_advertises_its_capability_table,
          test_an_installed_list_stands_and_disabled_probes_are_not_claimed,
          test_the_querier_learns_the_probes)
