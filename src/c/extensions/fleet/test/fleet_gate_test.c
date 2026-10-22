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
 * Who may propose a fleet or config update, and when a vote carries one
 * (fleet_gate.h). The proposer is an operator-bound member whose signature
 * verifies under the key this node holds for it and whose reputation reaches
 * THIS node's bar; a vote carries on ⌊N/2⌋ signed grants from other members of
 * the live group; and an acceptance is a certificate every node checks itself.
 */
#include "test_setup.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <jansson.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "config/configuration.h"
#include "fleet/artifact_proc.h"
#include "fleet/config_proc.h"
#include "fleet/fleet_gate.h"
#include "fleet/fleet_proc.h"
#include "fleet/update_proposal.h"
#include "identity/group.h"
#include "identity/identity.h"
#include "network/net_message.h"
#include "processes/processes.h"
#include "reputation/reputation.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"
#include "utilities/util.h"

/* -- what was sent ------------------------------------------------------- */

static struct {
    int grants, nacks, vote_requests, accepted, notified, artifact_requests, rep_queries;
    json_t *last_grant;
    json_t *last_vote_request;
    json_t *last_accepted;
} g;

static void _reset_sent(void)
{
    json_decref(g.last_grant);
    json_decref(g.last_vote_request);
    json_decref(g.last_accepted);
    memset(&g, 0, sizeof(g));
}

static bool _is(const generic_msg_t *msg, const char *function)
{
    return msg->info.net_msg.function != NULL
           && strcmp(msg->info.net_msg.function, function) == 0;
}

static int _hook(const char *key, const message_type_t type, generic_msg_t *msg, bool blocking)
{
    (void)key;
    (void)blocking;
    if (type == FLEET_UPDATE_ACCEPTED) {
        g.notified++;
        return 0;
    }
    if (type != NET_MESSAGE)
        return 0;
    json_t *body = NULL;
    (void)net_msg_unpack_json(&msg->info.net_msg, &body);
    if (_is(msg, FLEET_PROTO_VOTE_GRANT) || _is(msg, CONFIG_PROTO_VOTE_GRANT)) {
        g.grants++;
        json_decref(g.last_grant);
        g.last_grant = json_incref(body);
    } else if (_is(msg, FLEET_PROTO_VOTE_NACK) || _is(msg, CONFIG_PROTO_VOTE_NACK)) {
        g.nacks++;
    } else if (_is(msg, FLEET_PROTO_VOTE_REQ) || _is(msg, CONFIG_PROTO_VOTE_REQ)) {
        g.vote_requests++;
        json_decref(g.last_vote_request);
        g.last_vote_request = json_incref(body);
    } else if (_is(msg, FLEET_PROTO_ACCEPTED) || _is(msg, CONFIG_PROTO_ACCEPTED)) {
        g.accepted++;
        json_decref(g.last_accepted);
        g.last_accepted = json_incref(body);
    } else if (_is(msg, ARTIFACT_PROTO_REQUEST)) {
        g.artifact_requests++;
    } else if (_is(msg, REP_PROTO_LOCAL_QUERY)) {
        g.rep_queries++;
    }
    json_decref(body);
    return 0;
}

/* -- a node and its group ------------------------------------------------ */

#define MAX_NODES 5

typedef struct {
    identity_t *id[MAX_NODES];   /* [0] is this node */
    size_t n;
    process_t *proc;
} node_t;

static identity_t *_mk_identity(const char *name, const char *addr)
{
    uuid_t uuid;
    uuid_generate(uuid);
    identity_t *ident = NULL;
    ck_assert_int_eq(identity_create(&uuid, addr, name, name, &ident), 0);
    ident->operator_bound = true;
    return ident;
}

static void _publish(const identity_t *who, public_identity_t *out)
{
    public_identity_t *pub = NULL;
    ck_assert_int_eq(identity_publish(who, &pub), 0);
    memcpy(out, pub, sizeof(*out));
    out->operator_bound = who->operator_bound;
    smrt_deref(pub);
}

/* This node (as @p proc_name) in a group of @p n, everyone a member, peer and
 * operator-bound; every member clears the bar. */
static void _mk_node(node_t *node, size_t n, const char *proc_name)
{
    static const char *const names[MAX_NODES] = { "self", "m1", "m2", "m3", "m4" };
    static const char *const addrs[MAX_NODES] = { "10.0.0.1", "10.0.0.2", "10.0.0.3",
                                                  "10.0.0.4", "10.0.0.5" };
    memset(node, 0, sizeof(*node));
    node->n = n;
    for (size_t i = 0; i < n; i++)
        node->id[i] = _mk_identity(names[i], addrs[i]);
    process_t *proc = smrt_create(sizeof(process_t));
    ck_assert_ptr_nonnull(proc);
    pthread_rwlock_init(&proc->protocol.peers_rwlock, NULL);
    strncpy(proc->name, proc_name, PROC_NAME_LEN);
    uuid_t guuid;
    uuid_generate(guuid);
    group_init(&guuid, (char *)addrs[0], &proc->protocol.group);
    for (size_t i = 0; i < n; i++) {
        char u[UUID_STRING_LEN + 1];
        uuid_unparse_lower(node->id[i]->uuid, u);
        group_add_address(&proc->protocol.group, u, addrs[i]);
        if (i > 0) {
            _publish(node->id[i], &proc->protocol.peers[proc->protocol.num_peers++]);
            fleet_gate_set_reputation(node->id[i]->uuid, 0.9, true);
        }
    }
    config_t *id_cfg = calloc(1, sizeof(config_t));
    ck_assert_ptr_nonnull(id_cfg);
    id_cfg->name = "identity";
    id_cfg->data_struct = node->id[0];
    ck_assert_int_eq(map_create(&proc->configs), 0);
    map_set(proc->configs, (map_key_t)"identity",
            object_ptr_data((ptr_t)id_cfg, sizeof(config_t)));
    ck_assert_int_eq(map_create(&proc->protocol.handlers), 0);
    if (strcmp(proc_name, "config") == 0)
        ck_assert_int_eq(config_register_handlers(proc), 0);
    else
        ck_assert_int_eq(fleet_register_handlers(proc), 0);
    node->proc = proc;
}

static void _begin(void)
{
    fleet_gate_reset();
    fleet_gate_set_min_reputation(0.7);
    _reset_sent();
    messaging_set_test_hook(_hook);
}

static void _end(void)
{
    messaging_set_test_hook(NULL);
    _reset_sent();
    fleet_gate_reset();
}

/* A proposal signed by @p signer, named as signed by @p named. */
static void _proposal(update_proposal_t *prop, const identity_t *signer, const identity_t *named)
{
    memset(prop, 0, sizeof(*prop));
    strncpy(prop->version, "2.0.0", UPDATE_VERSION_LEN);
    randombytes_buf(prop->artifact_hash, UPDATE_HASH_LEN);
    strncpy(prop->target_arch, "aarch64", UPDATE_ARCH_LEN);
    uuid_copy(prop->signer_uuid, named->uuid);
    uuid_generate(prop->proposal_uuid);
    ck_assert_int_eq(update_proposal_sign(prop, signer->signature.private), 0);
}

static int _verify(const void *prop, const uint8_t *pk)
{
    return update_proposal_verify((const update_proposal_t *)prop, pk);
}

static fleet_gate_t _gate(const node_t *node, const update_proposal_t *prop)
{
    char why[160];
    return fleet_gate_proposer(node->proc, prop->signer_uuid, _verify, prop, why, sizeof(why));
}

/* Dispatch @p body as @p function from @p from. */
static void _deliver(const node_t *node, const char *function, json_t *body,
                     const identity_t *from)
{
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    msg.info.net_msg.function = (char *)function;
    at_strlcpy(msg.info.net_msg.process, node->proc->name, sizeof(msg.info.net_msg.process));
    if (from != NULL)
        _publish(from, &msg.info.net_msg.from_whom);
    ck_assert_int_eq(net_msg_pack_json(&msg.info.net_msg, body), 0);
    json_decref(body);
    run_message_handlers(node->proc, NULL, NET_MESSAGE, &msg);
    net_msg_free_obj(&msg.info.net_msg);
}

/* A grant @p who signs (as a node holding that identity would). */
static json_t *_grant(const identity_t *who, const char *kind, const uuid_t prop_uuid,
                      int64_t id1, int64_t id2, const uint8_t hash[32])
{
    uint8_t buf[128];
    size_t n = fleet_gate_grant_signable(kind, prop_uuid, id1, id2, hash, buf, sizeof(buf));
    ck_assert_uint_gt(n, 0);
    uint8_t sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, NULL, buf, n, who->signature.private);
    char sig_hex[crypto_sign_BYTES * 2 + 1], g_uuid[UUID_STRING_LEN + 1],
         p_uuid[UUID_STRING_LEN + 1];
    sodium_bin2hex(sig_hex, sizeof(sig_hex), sig, sizeof(sig));
    uuid_unparse_lower(who->uuid, g_uuid);
    uuid_unparse_lower(prop_uuid, p_uuid);
    return json_pack("{s:s, s:I, s:I, s:s, s:s}", "granter", g_uuid, "id1", (json_int_t)id1,
                     "id2", (json_int_t)id2, "proposal_uuid", p_uuid, "signature", sig_hex);
}

/* -- the proposer -------------------------------------------------------- */

DEFINE_TEST(test_a_proposer_that_is_not_a_member_is_refused)
{
    _begin();
    node_t node;
    _mk_node(&node, 3, "fleet");
    identity_t *stranger = _mk_identity("stranger", "10.0.0.9");
    /* A peer, operator-bound, with a good reputation -- but not in the group. */
    _publish(stranger, &node.proc->protocol.peers[node.proc->protocol.num_peers++]);
    fleet_gate_set_reputation(stranger->uuid, 0.9, true);
    update_proposal_t prop;
    _proposal(&prop, stranger, stranger);
    ck_assert_int_eq(_gate(&node, &prop), FLEET_GATE_REFUSE);
    _proposal(&prop, node.id[1], node.id[1]);
    ck_assert_int_eq(_gate(&node, &prop), FLEET_GATE_PASS);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_signature_must_verify_under_the_members_recorded_key)
{
    _begin();
    node_t node;
    _mk_node(&node, 3, "fleet");
    identity_t *impostor = _mk_identity("m1", "10.0.0.2");
    update_proposal_t prop;
    /* Names member m1, signed by another key. */
    _proposal(&prop, impostor, node.id[1]);
    ck_assert_int_eq(_gate(&node, &prop), FLEET_GATE_REFUSE);
    /* Signed by m1, then re-labelled as m2's: the signer is part of what is
     * signed, so neither key verifies it. */
    _proposal(&prop, node.id[1], node.id[1]);
    uuid_copy(prop.signer_uuid, node.id[2]->uuid);
    ck_assert_int_eq(_gate(&node, &prop), FLEET_GATE_REFUSE);
    _end();
}
END_TEST_DEFINITION()

/* The signature covers who signed and which proposal: a proposal cannot be
 * re-labelled, nor replayed as a new vote under a fresh uuid. */
DEFINE_TEST(test_the_signature_covers_the_signer_and_the_proposal_uuid)
{
    identity_t *who = _mk_identity("m1", "10.0.0.2");
    update_proposal_t prop;
    _proposal(&prop, who, who);
    ck_assert_int_eq(update_proposal_verify(&prop, who->signature.public), 0);
    update_proposal_t relabelled = prop;
    uuid_generate(relabelled.signer_uuid);
    ck_assert_int_ne(update_proposal_verify(&relabelled, who->signature.public), 0);
    update_proposal_t replayed = prop;
    uuid_generate(replayed.proposal_uuid);
    ck_assert_int_ne(update_proposal_verify(&replayed, who->signature.public), 0);

    config_proposal_t cprop;
    memset(&cprop, 0, sizeof(cprop));
    strncpy(cprop.config_name, "negotiation", CFG_NAME_SIZE);
    strncpy(cprop.version, "1", UPDATE_VERSION_LEN);
    uuid_copy(cprop.proposer_uuid, who->uuid);
    uuid_generate(cprop.proposal_uuid);
    ck_assert_int_eq(config_proposal_sign(&cprop, who->signature.private), 0);
    config_proposal_t creplayed = cprop;
    uuid_generate(creplayed.proposal_uuid);
    ck_assert_int_ne(config_proposal_verify(&creplayed, who->signature.public), 0);
    config_proposal_t crelabelled = cprop;
    uuid_generate(crelabelled.proposer_uuid);
    ck_assert_int_ne(config_proposal_verify(&crelabelled, who->signature.public), 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_proposer_that_is_not_operator_bound_is_refused)
{
    _begin();
    node_t node;
    _mk_node(&node, 3, "fleet");
    node.proc->protocol.peers[0].operator_bound = false;   /* m1 */
    update_proposal_t prop;
    _proposal(&prop, node.id[1], node.id[1]);
    ck_assert_int_eq(_gate(&node, &prop), FLEET_GATE_REFUSE);
    /* This node's own proposal too. */
    node.id[0]->operator_bound = false;
    _proposal(&prop, node.id[0], node.id[0]);
    ck_assert_int_eq(_gate(&node, &prop), FLEET_GATE_REFUSE);
    node.id[0]->operator_bound = true;
    ck_assert_int_eq(_gate(&node, &prop), FLEET_GATE_PASS);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_bar_is_this_nodes_not_the_proposals)
{
    _begin();
    node_t node;
    _mk_node(&node, 3, "fleet");
    update_proposal_t prop;
    _proposal(&prop, node.id[1], node.id[1]);
    /* The proposal's own bar is 0 and m1 is at 0.5: our bar of 0.7 decides. */
    fleet_gate_set_reputation(node.id[1]->uuid, 0.5, true);
    ck_assert_int_eq(_gate(&node, &prop), FLEET_GATE_REFUSE);
    fleet_gate_set_min_reputation(0.4);
    ck_assert_int_eq(_gate(&node, &prop), FLEET_GATE_PASS);
    /* No reputation recorded at all is below any bar. */
    fleet_gate_set_reputation(node.id[1]->uuid, 0.0, false);
    fleet_gate_set_min_reputation(0.0);
    ck_assert_int_eq(_gate(&node, &prop), FLEET_GATE_REFUSE);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_bar_is_read_from_fleet_cfg)
{
    _begin();
    static char root[] = "/tmp/at-fleet-gate-testXXXXXX";
    ck_assert_ptr_nonnull(mkdtemp(root));
    ck_assert_int_eq(setenv("AUTONOMOUS_TRUST_ROOT", root, 1), 0);
    char dir[CFG_PATH_LEN + 1] = {0}, path[CFG_PATH_LEN + 32];
    ck_assert(get_cfg_dir(dir, sizeof(dir)) >= 0);
    char cmd[CFG_PATH_LEN + 16];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", dir);
    ck_assert_int_eq(system(cmd), 0);
    fleet_gate_set_min_reputation(-1.0);
    ck_assert(fleet_gate_min_reputation() > FLEET_DEFAULT_MIN_REPUTATION - 1e-9
              && fleet_gate_min_reputation() < FLEET_DEFAULT_MIN_REPUTATION + 1e-9);
    snprintf(path, sizeof(path), "%s/fleet.cfg.json", dir);
    FILE *f = fopen(path, "w");
    ck_assert_ptr_nonnull(f);
    fputs("{\"min_proposer_reputation\": 0.35}", f);
    fclose(f);
    fleet_gate_set_min_reputation(-1.0);
    ck_assert(fleet_gate_min_reputation() > 0.35 - 1e-9
              && fleet_gate_min_reputation() < 0.35 + 1e-9);
    unlink(path);
    unsetenv("AUTONOMOUS_TRUST_ROOT");
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_unknown_reputation_is_asked_for_and_the_message_held)
{
    _begin();
    node_t node;
    _mk_node(&node, 3, "fleet");
    fleet_gate_reset();               /* forget every reputation */
    fleet_gate_set_min_reputation(0.7);
    update_proposal_t prop;
    _proposal(&prop, node.id[1], node.id[1]);
    json_t *req = json_pack("{s:I, s:I, s:o}", "id1", (json_int_t)1, "id2", (json_int_t)1,
                            "proposal", update_proposal_to_json(&prop));
    _deliver(&node, FLEET_PROTO_VOTE_REQ, req, node.id[1]);
    ck_assert_int_eq(g.rep_queries, 1);
    ck_assert_uint_eq(fleet_gate_held(), 1);
    ck_assert_int_eq(g.grants, 0);
    /* The answer arrives: the held request is checked again, and granted. */
    char u[UUID_STRING_LEN + 1];
    uuid_unparse_lower(node.id[1]->uuid, u);
    _deliver(&node, REP_PROTO_LOCAL_RESP,
             json_pack("{s:s, s:f, s:b}", "peer_uuid", u, "score", 0.8, "found", 1), NULL);
    ck_assert_uint_eq(fleet_gate_held(), 0);
    ck_assert_int_eq(g.grants, 1);
    /* An answer from the wire is not the reputation process's. */
    fleet_gate_reset();
    fleet_gate_set_min_reputation(0.7);
    _deliver(&node, FLEET_PROTO_VOTE_REQ,
             json_pack("{s:I, s:I, s:o}", "id1", (json_int_t)1, "id2", (json_int_t)2,
                       "proposal", update_proposal_to_json(&prop)), node.id[1]);
    _deliver(&node, REP_PROTO_LOCAL_RESP,
             json_pack("{s:s, s:f, s:b}", "peer_uuid", u, "score", 0.8, "found", 1), node.id[2]);
    ck_assert_uint_eq(fleet_gate_held(), 1);
    ck_assert_int_eq(g.grants, 1);
    _end();
}
END_TEST_DEFINITION()

/* -- the quorum ---------------------------------------------------------- */

DEFINE_TEST(test_the_quorum_is_half_the_live_group_from_other_members)
{
    _begin();
    for (size_t n = 1; n <= MAX_NODES; n++) {
        ck_assert_uint_eq(fleet_gate_quorum(n), n / 2);
        node_t node;
        _mk_node(&node, n, "fleet");
        ck_assert_uint_eq(fleet_gate_group_size(node.proc), n);
    }
    /* Sized when counted: a member that joins raises it. */
    node_t node;
    _mk_node(&node, 3, "fleet");
    ck_assert_uint_eq(fleet_gate_quorum(fleet_gate_group_size(node.proc)), 1);
    group_add_address(&node.proc->protocol.group,
                      "00000000-0000-4000-8000-0000000000aa", "10.0.0.7");
    ck_assert_uint_eq(fleet_gate_quorum(fleet_gate_group_size(node.proc)), 2);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_grants_count_once_per_other_member)
{
    _begin();
    node_t node;
    _mk_node(&node, 5, "fleet");
    update_proposal_t prop;
    _proposal(&prop, node.id[1], node.id[1]);   /* m1 proposes */
    const uint8_t *h = prop.artifact_hash;
    const unsigned char *pu = prop.proposal_uuid;
    identity_t *stranger = _mk_identity("stranger", "10.0.0.9");
    json_t *grants = json_array();
    json_array_append_new(grants, _grant(node.id[2], "update", pu, 1, 7, h));
    json_array_append_new(grants, _grant(node.id[2], "update", pu, 1, 7, h));   /* duplicate */
    json_array_append_new(grants, _grant(node.id[1], "update", pu, 1, 7, h));   /* proposer */
    json_array_append_new(grants, _grant(stranger, "update", pu, 1, 7, h));     /* not a member */
    json_array_append_new(grants, _grant(node.id[3], "update", pu, 1, 8, h));   /* other ballot */
    json_array_append_new(grants, _grant(node.id[3], "config", pu, 1, 7, h));   /* other kind */
    json_t *forged = _grant(stranger, "update", pu, 1, 7, h);
    char m4[UUID_STRING_LEN + 1];
    uuid_unparse_lower(node.id[4]->uuid, m4);
    json_object_set_new(forged, "granter", json_string(m4));                  /* forged */
    json_array_append_new(grants, forged);
    ck_assert_uint_eq(fleet_gate_count_grants(node.proc, grants, "update", pu,
                                              prop.signer_uuid, 1, 7, h), 1);
    json_array_append_new(grants, _grant(node.id[0], "update", pu, 1, 7, h));   /* this node */
    ck_assert_uint_eq(fleet_gate_count_grants(node.proc, grants, "update", pu,
                                              prop.signer_uuid, 1, 7, h), 2);
    json_decref(grants);
    _end();
}
END_TEST_DEFINITION()

/* -- the voter ----------------------------------------------------------- */

DEFINE_TEST(test_a_voter_grants_only_a_proposal_it_can_check)
{
    _begin();
    node_t node;
    _mk_node(&node, 3, "fleet");
    update_proposal_t prop;
    _proposal(&prop, node.id[1], node.id[1]);
    /* No proposal in the request: nothing to check, no grant. */
    _deliver(&node, FLEET_PROTO_VOTE_REQ,
             json_pack("{s:I, s:I, s:s}", "id1", (json_int_t)40, "id2", (json_int_t)1,
                       "proposal_uuid", "00000000-0000-4000-8000-000000000001"), node.id[1]);
    /* A tampered proposal. */
    update_proposal_t bad = prop;
    strncpy(bad.version, "6.6.6", UPDATE_VERSION_LEN);
    _deliver(&node, FLEET_PROTO_VOTE_REQ,
             json_pack("{s:I, s:I, s:o}", "id1", (json_int_t)40, "id2", (json_int_t)1,
                       "proposal", update_proposal_to_json(&bad)), node.id[1]);
    /* m1's proposal, asked for by m2. */
    _deliver(&node, FLEET_PROTO_VOTE_REQ,
             json_pack("{s:I, s:I, s:o}", "id1", (json_int_t)40, "id2", (json_int_t)1,
                       "proposal", update_proposal_to_json(&prop)), node.id[2]);
    ck_assert_int_eq(g.grants, 0);
    /* The real thing. */
    _deliver(&node, FLEET_PROTO_VOTE_REQ,
             json_pack("{s:I, s:I, s:o}", "id1", (json_int_t)40, "id2", (json_int_t)1,
                       "proposal", update_proposal_to_json(&prop)), node.id[1]);
    ck_assert_int_eq(g.grants, 1);
    /* The grant is this node's signature over the ballot. */
    uuid_t granter;
    ck_assert(fleet_gate_grant_valid(node.proc, g.last_grant, "update", prop.proposal_uuid,
                                     40, 1, prop.artifact_hash, granter));
    ck_assert_int_eq(uuid_compare(granter, node.id[0]->uuid), 0);
    _end();
}
END_TEST_DEFINITION()

/* -- the proposer's round and the certificate ---------------------------- */

DEFINE_TEST(test_the_proposer_carries_on_half_the_group_and_sends_the_certificate)
{
    _begin();
    node_t node;
    _mk_node(&node, 5, "fleet");   /* needs 2 grants from others */
    update_proposal_t prop;
    _proposal(&prop, node.id[0], node.id[0]);
    json_t *body = update_proposal_to_json(&prop);
    _deliver(&node, FLEET_PROTO_PROPOSE, body, NULL);
    ck_assert_int_eq(g.vote_requests, 4);
    ck_assert_ptr_nonnull(json_object_get(g.last_vote_request, "proposal"));
    int64_t id1 = json_integer_value(json_object_get(g.last_vote_request, "id1"));
    int64_t id2 = json_integer_value(json_object_get(g.last_vote_request, "id2"));
    /* m1 grants twice, and m2 sends a grant signed by m3: one valid grant. */
    _deliver(&node, FLEET_PROTO_VOTE_GRANT,
             _grant(node.id[1], "update", prop.proposal_uuid, id1, id2, prop.artifact_hash),
             node.id[1]);
    _deliver(&node, FLEET_PROTO_VOTE_GRANT,
             _grant(node.id[1], "update", prop.proposal_uuid, id1, id2, prop.artifact_hash),
             node.id[1]);
    _deliver(&node, FLEET_PROTO_VOTE_GRANT,
             _grant(node.id[3], "update", prop.proposal_uuid, id1, id2, prop.artifact_hash),
             node.id[2]);
    ck_assert_int_eq(g.accepted, 0);
    ck_assert_int_eq(g.notified, 0);
    _deliver(&node, FLEET_PROTO_VOTE_GRANT,
             _grant(node.id[2], "update", prop.proposal_uuid, id1, id2, prop.artifact_hash),
             node.id[2]);
    ck_assert_int_eq(g.accepted, 4);
    ck_assert_int_eq(g.notified, 1);
    ck_assert_uint_eq(json_array_size(json_object_get(g.last_accepted, "grants")), 2);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_group_of_one_carries_its_own_proposal)
{
    _begin();
    node_t node;
    _mk_node(&node, 1, "fleet");
    update_proposal_t prop;
    _proposal(&prop, node.id[0], node.id[0]);
    _deliver(&node, FLEET_PROTO_PROPOSE, update_proposal_to_json(&prop), NULL);
    ck_assert_int_eq(g.vote_requests, 0);
    ck_assert_int_eq(g.notified, 1);
    _end();
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_node_runs_the_vote_only_on_its_own_proposal)
{
    _begin();
    node_t node;
    _mk_node(&node, 3, "fleet");
    update_proposal_t prop;
    _proposal(&prop, node.id[1], node.id[1]);
    _deliver(&node, FLEET_PROTO_PROPOSE, update_proposal_to_json(&prop), node.id[1]);
    _deliver(&node, FLEET_PROTO_PROPOSE, update_proposal_to_json(&prop), NULL);
    ck_assert_int_eq(g.vote_requests, 0);
    _end();
}
END_TEST_DEFINITION()

static json_t *_certificate(const update_proposal_t *prop, json_t *grants)
{
    return json_pack("{s:o, s:I, s:I, s:o}", "proposal", update_proposal_to_json(prop),
                     "id1", (json_int_t)3, "id2", (json_int_t)4, "grants", grants);
}

DEFINE_TEST(test_an_acceptance_needs_a_certificate_this_node_can_count)
{
    _begin();
    node_t node;
    _mk_node(&node, 5, "fleet");   /* 2 grants from members other than m1 */
    update_proposal_t prop;
    _proposal(&prop, node.id[1], node.id[1]);
    const unsigned char *pu = prop.proposal_uuid;
    const uint8_t *h = prop.artifact_hash;

    /* No grants at all: the old acceptance, which any peer could send. */
    _deliver(&node, FLEET_PROTO_ACCEPTED, _certificate(&prop, json_array()), node.id[1]);
    /* One grant, padded with the proposer's own and a duplicate. */
    _deliver(&node, FLEET_PROTO_ACCEPTED,
             _certificate(&prop, json_pack("[o, o, o]",
                                           _grant(node.id[2], "update", pu, 3, 4, h),
                                           _grant(node.id[2], "update", pu, 3, 4, h),
                                           _grant(node.id[1], "update", pu, 3, 4, h))),
             node.id[1]);
    /* Two, one of them forged (signed by a stranger, named m3). */
    identity_t *stranger = _mk_identity("stranger", "10.0.0.9");
    json_t *forged = _grant(stranger, "update", pu, 3, 4, h);
    char m3[UUID_STRING_LEN + 1];
    uuid_unparse_lower(node.id[3]->uuid, m3);
    json_object_set_new(forged, "granter", json_string(m3));
    _deliver(&node, FLEET_PROTO_ACCEPTED,
             _certificate(&prop, json_pack("[o, o]", _grant(node.id[2], "update", pu, 3, 4, h),
                                           forged)),
             node.id[1]);
    /* Enough grants for a proposal that is not m1's to make: m1 is not bound. */
    node.proc->protocol.peers[0].operator_bound = false;
    _deliver(&node, FLEET_PROTO_ACCEPTED,
             _certificate(&prop, json_pack("[o, o]", _grant(node.id[2], "update", pu, 3, 4, h),
                                           _grant(node.id[3], "update", pu, 3, 4, h))),
             node.id[1]);
    node.proc->protocol.peers[0].operator_bound = true;
    ck_assert_int_eq(g.notified, 0);
    ck_assert_int_eq(g.artifact_requests, 0);

    /* A valid certificate: applied once, the artifact fetched from the sender. */
    _deliver(&node, FLEET_PROTO_ACCEPTED,
             _certificate(&prop, json_pack("[o, o]", _grant(node.id[2], "update", pu, 3, 4, h),
                                           _grant(node.id[3], "update", pu, 3, 4, h))),
             node.id[2]);
    ck_assert_int_eq(g.notified, 1);
    ck_assert_int_eq(g.artifact_requests, 1);
    _deliver(&node, FLEET_PROTO_ACCEPTED,
             _certificate(&prop, json_pack("[o, o]", _grant(node.id[2], "update", pu, 3, 4, h),
                                           _grant(node.id[3], "update", pu, 3, 4, h))),
             node.id[2]);
    ck_assert_int_eq(g.notified, 1);
    _end();
}
END_TEST_DEFINITION()

/* -- config -------------------------------------------------------------- */

static void _config_proposal(config_proposal_t *prop, const identity_t *signer, const char *name)
{
    memset(prop, 0, sizeof(*prop));
    strncpy(prop->config_name, name, CFG_NAME_SIZE);
    randombytes_buf(prop->content_hash, UPDATE_HASH_LEN);
    strncpy(prop->version, "1", UPDATE_VERSION_LEN);
    uuid_copy(prop->proposer_uuid, signer->uuid);
    uuid_generate(prop->proposal_uuid);
    ck_assert_int_eq(config_proposal_sign(prop, signer->signature.private), 0);
}

DEFINE_TEST(test_config_follows_the_same_rules)
{
    _begin();
    node_t node;
    _mk_node(&node, 3, "config");
    config_proposal_t prop;
    _config_proposal(&prop, node.id[1], "negotiation");
    const unsigned char *pu = prop.proposal_uuid;
    const uint8_t *h = prop.content_hash;
    /* The voter checks it and grants. */
    _deliver(&node, CONFIG_PROTO_VOTE_REQ,
             json_pack("{s:I, s:I, s:o}", "id1", (json_int_t)1, "id2", (json_int_t)1,
                       "proposal", config_proposal_to_json(&prop)), node.id[1]);
    ck_assert_int_eq(g.grants, 1);
    /* A config the bar lives in, or identity, may not be proposed. */
    config_proposal_t bar;
    _config_proposal(&bar, node.id[1], "fleet");
    _deliver(&node, CONFIG_PROTO_VOTE_REQ,
             json_pack("{s:I, s:I, s:o}", "id1", (json_int_t)2, "id2", (json_int_t)1,
                       "proposal", config_proposal_to_json(&bar)), node.id[1]);
    ck_assert_int_eq(g.grants, 1);
    /* Nor the ZTA policy (it decides who is operator-bound), nor any name that
     * is not plain, which could reach another file or dodge the exact names. */
    static const char *const refused[] = {"zta_policy", "identity", "./identity",
                                          "../fleet", "a/b", ""};
    for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++) {
        config_proposal_t bad;
        _config_proposal(&bad, node.id[1], refused[i]);
        _deliver(&node, CONFIG_PROTO_VOTE_REQ,
                 json_pack("{s:I, s:I, s:o}", "id1", (json_int_t)(3 + i), "id2",
                           (json_int_t)1, "proposal", config_proposal_to_json(&bad)),
                 node.id[1]);
        ck_assert_msg(g.grants == 1, "granted a proposal for '%s'", refused[i]);
    }
    /* An acceptance without a grant from another member does nothing... */
    json_t *none = json_pack("{s:o, s:I, s:I, s:[]}", "proposal",
                             config_proposal_to_json(&prop), "id1", (json_int_t)5,
                             "id2", (json_int_t)6, "grants");
    _deliver(&node, CONFIG_PROTO_ACCEPTED, none, node.id[1]);
    ck_assert_int_eq(g.artifact_requests, 0);
    /* ...a grant signed for fleet does not count for config... */
    _deliver(&node, CONFIG_PROTO_ACCEPTED,
             json_pack("{s:o, s:I, s:I, s:[o]}", "proposal", config_proposal_to_json(&prop),
                       "id1", (json_int_t)5, "id2", (json_int_t)6, "grants",
                       _grant(node.id[2], "update", pu, 5, 6, h)), node.id[1]);
    ck_assert_int_eq(g.artifact_requests, 0);
    /* ...and one from m2 fetches the content. */
    _deliver(&node, CONFIG_PROTO_ACCEPTED,
             json_pack("{s:o, s:I, s:I, s:[o]}", "proposal", config_proposal_to_json(&prop),
                       "id1", (json_int_t)5, "id2", (json_int_t)6, "grants",
                       _grant(node.id[2], "config", pu, 5, 6, h)), node.id[1]);
    ck_assert_int_eq(g.artifact_requests, 1);
    _end();
}
END_TEST_DEFINITION()

RUN_TESTS(FleetGate,
          test_a_proposer_that_is_not_a_member_is_refused,
          test_the_signature_must_verify_under_the_members_recorded_key,
          test_the_signature_covers_the_signer_and_the_proposal_uuid,
          test_a_proposer_that_is_not_operator_bound_is_refused,
          test_the_bar_is_this_nodes_not_the_proposals,
          test_the_bar_is_read_from_fleet_cfg,
          test_an_unknown_reputation_is_asked_for_and_the_message_held,
          test_the_quorum_is_half_the_live_group_from_other_members,
          test_grants_count_once_per_other_member,
          test_a_voter_grants_only_a_proposal_it_can_check,
          test_the_proposer_carries_on_half_the_group_and_sends_the_certificate,
          test_a_group_of_one_carries_its_own_proposal,
          test_a_node_runs_the_vote_only_on_its_own_proposal,
          test_an_acceptance_needs_a_certificate_this_node_can_count,
          test_config_follows_the_same_rules)
