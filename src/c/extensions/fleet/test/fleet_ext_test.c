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
 * Fleet as an extension (FEATURE_SPLIT_PLAN Phase 8): what libat_fleet adds to
 * a node when it is linked -- its four processes and their default subsystems,
 * its app verb, its app-bound message type -- and the app's proposal, which
 * this node signs as itself.
 */
#include "test_setup.h"

#include <math.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#include <jansson.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "config/configuration.h"
#include "fleet/at_fleet.h"
#include "fleet/fleet_proc.h"
#include "app_events_registry.h"
#include "utilities/util.h"   /* makedirs */
#include "fleet/update_proposal.h"
#include "identity/identity.h"
#include "processes/process_tracker.h"
#include "utilities/message.h"
#include "utilities/msg_registry.h"
#include "utilities/msg_types_priv.h"

static struct {
    int vote_requests;
    char last_to[UUID_STRING_LEN + 1];
    char proposal_uuid[UUID_STRING_LEN + 1];
} g_sent;

static int _hook(const char *key, const message_type_t type, generic_msg_t *msg, bool blocking)
{
    (void)blocking;
    if (strcmp(key, "network") != 0 || type != NET_MESSAGE
        || msg->info.net_msg.function == NULL
        || strcmp(msg->info.net_msg.function, "update vote request") != 0)
        return 0;
    g_sent.vote_requests++;
    uuid_unparse_lower(msg->info.net_msg.to_whom.uuid, g_sent.last_to);
    json_t *body = NULL;
    if (net_msg_unpack_json(&msg->info.net_msg, &body) == 0) {
        const char *u = json_string_value(json_object_get(body, "proposal_uuid"));
        if (u != NULL)
            snprintf(g_sent.proposal_uuid, sizeof(g_sent.proposal_uuid), "%s", u);
        json_decref(body);
    }
    return 0;
}

static identity_t *_mk_identity(const char *name, const char *addr)
{
    uuid_t uuid;
    uuid_generate(uuid);
    identity_t *ident = NULL;
    ck_assert_int_eq(identity_create(&uuid, addr, name, name, &ident), 0);
    return ident;
}

/* A fleet process: this node's identity in its configs, and one peer. */
static process_t *_mk_process(identity_t *self, identity_t *peer)
{
    process_t *proc = smrt_create(sizeof(process_t));
    ck_assert_ptr_nonnull(proc);
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    strncpy(proc->name, "fleet", PROC_NAME_LEN);
    config_t *id_cfg = calloc(1, sizeof(config_t));
    ck_assert_ptr_nonnull(id_cfg);
    id_cfg->name = "identity";
    id_cfg->data_struct = self;
    ck_assert_int_eq(map_create(&proc->configs), 0);
    map_set(proc->configs, (map_key_t)"identity",
            object_ptr_data((ptr_t)id_cfg, sizeof(config_t)));
    public_identity_t *pub = NULL;
    ck_assert_int_eq(identity_publish(peer, &pub), 0);
    memcpy(&proc->protocol.peers[0], pub, sizeof(public_identity_t));
    proc->protocol.num_peers = 1;
    smrt_deref(pub);
    return proc;
}

/* The app's request: no sender (local), {fields}. */
static void _propose(process_t *proc, json_t *fields, const uuid_t *sender)
{
    generic_msg_t req = {0};
    req.type = NET_MESSAGE;
    req.info.net_msg.function = (char *)AT_APP_FLEET_PROPOSE;
    if (sender != NULL)
        uuid_copy(req.info.net_msg.from_whom.uuid, *sender);
    ck_assert_int_eq(net_msg_pack_json(&req.info.net_msg, fields), 0);
    json_decref(fields);
    ck_assert(fleet_handle_app_propose(proc, NULL, &req));
    net_msg_free_obj(&req.info.net_msg);
}

static const char HASH[] =
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

DEFINE_TEST(test_linking_fleet_adds_its_processes_subsystems_verb_and_type)
{
    static const char *const procs[] = { "fleet_proc", "artifact_proc", "update_proc",
                                         "config_proc" };
    for (size_t i = 0; i < 4; i++)
        ck_assert_ptr_nonnull(find_process(procs[i]));
    const char *keys[AT_SUBSYSTEM_EXT_MAX], *impls[AT_SUBSYSTEM_EXT_MAX];
    size_t n = subsystem_defaults(keys, impls, AT_SUBSYSTEM_EXT_MAX);
    ck_assert_uint_eq(n, 4);
    ck_assert_str_eq(keys[0], "fleet");
    ck_assert_str_eq(impls[0], "fleet_proc");
    /* Linked, so a configuration that starts them is not refused. */
    tracker_t tracker;
    ck_assert_int_eq(tracker_init(NULL, &tracker), 0);
    for (size_t i = 0; i < n; i++)
        ck_assert_int_eq(tracker_register_subsystem(&tracker, keys[i], impls[i]), 0);
    ck_assert_int_eq(tracker_check_subsystem_libraries(&tracker, NULL), 0);
    tracker_free(&tracker);
    /* The verb goes to fleet; the acceptance is fleet's own app-bound type. */
    const char *target = at_app_verb_target(AT_APP_FLEET_PROPOSE);
    ck_assert_ptr_nonnull(target);
    ck_assert_str_eq(target, "fleet");
    const at_msg_vtable_t *vt = at_msg_type_lookup(FLEET_UPDATE_ACCEPTED);
    ck_assert_ptr_nonnull(vt);
    ck_assert(vt->app_bound);
    ck_assert_int_ge((int)FLEET_UPDATE_ACCEPTED, AT_MSG_TYPE_FLEET_MIN);
    ck_assert_int_le((int)FLEET_UPDATE_ACCEPTED, AT_MSG_TYPE_FLEET_MAX);
}
END_TEST_DEFINITION()

/* The app holds no key: this node builds the proposal, signs it with its own
 * identity key, names itself the signer, and starts the vote with its peers. */
DEFINE_TEST(test_the_node_signs_the_apps_proposal_and_starts_the_vote)
{
    identity_t *self = _mk_identity("self", "10.0.0.1");
    identity_t *peer = _mk_identity("peer", "10.0.0.2");
    process_t *proc = _mk_process(self, peer);
    memset(&g_sent, 0, sizeof(g_sent));
    messaging_set_test_hook(_hook);
    _propose(proc, json_pack("{s:s, s:s, s:s, s:f}", "version", "2.0.0",
                             "artifact_hash", HASH, "target_arch", "aarch64",
                             "min_proposer_reputation", 0.5), NULL);
    ck_assert_int_eq(g_sent.vote_requests, 1);
    char peer_uuid[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer->uuid, peer_uuid);
    ck_assert_str_eq(g_sent.last_to, peer_uuid);
    update_proposal_t prop;
    ck_assert(fleet_pending_proposal(g_sent.proposal_uuid, &prop));
    ck_assert_str_eq(prop.version, "2.0.0");
    ck_assert_str_eq(prop.target_arch, "aarch64");
    ck_assert(fabs(prop.min_proposer_reputation - 0.5) < 1e-12);
    ck_assert_int_eq(uuid_compare(prop.signer_uuid, self->uuid), 0);
    ck_assert(fleet_validate_proposal(&prop, self->signature.public));
    ck_assert(!fleet_validate_proposal(&prop, peer->signature.public));

    /* Refused: from the wire, a bad hash, no version. Nothing is sent. */
    memset(&g_sent, 0, sizeof(g_sent));
    _propose(proc, json_pack("{s:s, s:s}", "version", "2.0.1", "artifact_hash", HASH),
             (const uuid_t *)&peer->uuid);
    _propose(proc, json_pack("{s:s, s:s}", "version", "2.0.1", "artifact_hash", "abcd"), NULL);
    _propose(proc, json_pack("{s:s}", "artifact_hash", HASH), NULL);
    ck_assert_int_eq(g_sent.vote_requests, 0);
    messaging_set_test_hook(NULL);
}
END_TEST_DEFINITION()

/* The flat ABI (at_fleet.h): the sender refuses a malformed proposal before
 * sending anything and says when the node is not listening yet, and an
 * acceptance decodes into kind AT_APP_EVENT_FLEET_UPDATE_ACCEPTED. */
DEFINE_TEST(test_the_app_abi_sends_the_verb_and_decodes_the_acceptance)
{
    /* Socket paths live under <root>/var/at, so give the test a root. */
    static char root[] = "/tmp/at-fleet-abi-testXXXXXX";
    ck_assert_ptr_nonnull(mkdtemp(root));
    ck_assert_int_eq(setenv("AUTONOMOUS_TRUST_ROOT", root, 1), 0);
    char data_dir[CFG_PATH_LEN + 1] = {0};
    ck_assert(get_data_dir(data_dir, sizeof(data_dir)) >= 0);
    ck_assert_int_eq(makedirs(data_dir, 0755), 0);
    at_app_events_t *ev = at_app_events_open("_fleet_abi_in");
    ck_assert_ptr_nonnull(ev);
    ck_assert_int_eq(at_app_fleet_propose(ev, "_fleet_abi_out", "", HASH, NULL, 0.0), -1);
    ck_assert_int_eq(at_app_fleet_propose(ev, "_fleet_abi_out", "1.0", "abcd", NULL, 0.0), -1);
    ck_assert_int_eq(at_app_fleet_propose(NULL, "_fleet_abi_out", "1.0", HASH, NULL, 0.0), -1);
    ck_assert_int_eq(at_app_fleet_propose(ev, "_fleet_abi_out", "1.0", HASH, "arm64", 0.2),
                     AT_APP_NOT_READY);
    at_app_events_close(ev);

    generic_msg_t msg = {0};
    msg.type = FLEET_UPDATE_ACCEPTED;
    uuid_t u;
    uuid_generate(u);
    uuid_copy(AT_MSG_EXT(&msg, fleet_update_accepted_msg_t)->proposal_uuid, u);
    at_app_event_decoder_t dec = at_app_event_decoder_lookup((long)FLEET_UPDATE_ACCEPTED);
    ck_assert_ptr_nonnull(dec);
    at_app_event_t event;
    memset(&event, 0, sizeof(event));
    ck_assert_int_eq(dec(&msg, &event), 0);
    ck_assert_int_eq(event.kind, AT_APP_EVENT_FLEET_UPDATE_ACCEPTED);
    const at_app_fleet_accepted_t *acc = at_fleet_accepted_event(&event);
    ck_assert_ptr_nonnull(acc);
    ck_assert_int_eq(memcmp(acc->proposal_uuid, u, AT_APP_UUID_LEN), 0);
    event.kind = 1027;
    ck_assert_ptr_null(at_fleet_accepted_event(&event));
}
END_TEST_DEFINITION()

RUN_TESTS(FleetExtension,
          test_linking_fleet_adds_its_processes_subsystems_verb_and_type,
          test_the_node_signs_the_apps_proposal_and_starts_the_vote,
          test_the_app_abi_sends_the_verb_and_decodes_the_acceptance)
