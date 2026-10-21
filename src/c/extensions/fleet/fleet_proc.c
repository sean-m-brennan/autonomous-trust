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

#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sodium.h>

#include "processes/processes.h"
#include "processes/process_tracker.h"
#include "fleet/fleet_proc.h"
#include "fleet/update_proposal.h"
#include "fleet/artifact_proc.h"
#include "fleet/artifact_store.h"
#include "algorithms/paxos.h"
#include "structures/map.h"
#include "structures/array.h"
#include "structures/data.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"
#include "utilities/exception.h"
#include "network/net_message.h"
#include "utilities/msg_registry.h"
#include "utilities/util.h"
#include "config/configuration.h"
#include "identity/identity.h"
#include "identity/id_proc_priv.h"   /* identity_self_identity */
#include "utilities/send_retry.h"   /* at_send: keep a refused frame (ISSUES §2.14) */
#include "fleet/fleet_gate.h"
#include "reputation/reputation.h"   /* REP_PROTO_LOCAL_RESP */

#define EFLEET_PAXOS 260
DEFINE_ERROR(EFLEET_PAXOS, "Fleet Paxos consensus error");

/* Protocol-string definitions (declared `extern char[]` in
 * fleet_proc.h). Writable arrays for direct `char *` assignment. */
char FLEET_PROTO_PROPOSE[]    = "update proposal";
char FLEET_PROTO_VOTE_REQ[]   = "update vote request";
char FLEET_PROTO_VOTE_GRANT[] = "update vote grant";
char FLEET_PROTO_VOTE_NACK[]  = "update vote nack";
char FLEET_PROTO_ACCEPTED[]   = "update accepted";
char FLEET_PROTO_REJECTED[]   = "update rejected";

AT_MSG_ASSERT_FITS(fleet_update_accepted_msg_t);
static const at_msg_vtable_t fleet_update_accepted_vt = {
    .name = "FLEET_UPDATE_ACCEPTED", .size = sizeof(fleet_update_accepted_msg_t),
    .app_bound = true };
AT_MSG_TYPE_REGISTER(fleet_update_accepted, FLEET_UPDATE_ACCEPTED, &fleet_update_accepted_vt)


/****************************
 * Process state (file-scope static, thread-safe via mutex)
 ****************************/

static struct {
    paxos_instance_t vote_paxos;
    map_t pending_proposals;   /* proposal_uuid_str -> update_proposal_t* */
    map_t accepted_updates;    /* proposal_uuid_str -> update_proposal_t* */
    json_t *rounds;            /* proposal_uuid_str -> {id1, id2, grants[]} (proposer) */
    pthread_mutex_t lock;
    bool initialized;
} fleet_state;

static void _ensure_init(void)
{
    if (!fleet_state.initialized)
    {
        map_init(&fleet_state.pending_proposals);
        map_init(&fleet_state.accepted_updates);
        fleet_state.rounds = json_object();
        pthread_mutex_init(&fleet_state.lock, NULL);
        fleet_state.initialized = true;
    }
}

/* Forward declarations */
static bool handle_update_proposal(const process_t *proc, directory_t *queues, generic_msg_t *msg);
static bool handle_vote_request(const process_t *proc, directory_t *queues, generic_msg_t *msg);
static bool handle_update_accepted(const process_t *proc, directory_t *queues, generic_msg_t *msg);

/* What a grant is signed over names the protocol, so a fleet grant cannot be
 * replayed as a config grant. */
static const char FLEET_KIND[] = "update";

static int _verify(const void *prop, const uint8_t *pk)
{
    return update_proposal_verify((const update_proposal_t *)prop, pk);
}

/* Send @p body as @p function to every member of our group. */
static void _send_to_members(const process_t *proc, const char *function, json_t *body,
                             const char *what)
{
    public_identity_t *members = NULL;
    size_t n = fleet_gate_members(proc, &members);
    for (size_t i = 0; i < n; i++) {
        generic_msg_t out = {0};
        out.type = NET_MESSAGE;
        at_strlcpy(out.info.net_msg.process, "fleet", sizeof(out.info.net_msg.process));
        out.info.net_msg.function = (char *)function;
        out.info.net_msg.encrypt = true;
        memcpy(&out.info.net_msg.to_whom, &members[i], sizeof(public_identity_t));
        at_strlcpy(out.info.net_msg.return_to, "fleet", sizeof(out.info.net_msg.return_to));
        net_msg_pack_json(&out.info.net_msg, body);
        at_send(proc, "network", &out, what, "network", 0, NULL, NULL, 0);
        net_msg_free_obj(&out.info.net_msg);
    }
    free(members);
}

/* Run the proposer checks (fleet_gate.h) on @p prop. PENDING holds @p msg for
 * @p handler; a refusal is logged. True only on PASS. */
static bool _gate(const process_t *proc, const update_proposal_t *prop, generic_msg_t *msg,
                  fleet_gate_handler_fn handler, const char *stage)
{
    char why[160] = {0};
    fleet_gate_t verdict = fleet_gate_proposer(proc, prop->signer_uuid, _verify, prop,
                                               why, sizeof(why));
    if (verdict == FLEET_GATE_PASS)
        return true;
    char u[UUID_STRING_LEN + 1];
    uuid_unparse_lower(prop->proposal_uuid, u);
    if (verdict == FLEET_GATE_PENDING && msg != NULL && handler != NULL) {
        log_info(proc->logger, "Fleet: %s for %s held: %s\n", stage, u, why);
        fleet_gate_hold(proc, msg, handler);
    } else {
        log_warn(proc->logger, "Fleet: %s for %s refused: %s\n", stage, u, why);
    }
    return false;
}

/* A proposal from @p body's "proposal", whose uuid must match "proposal_uuid"
 * when the body names one. */
static bool _proposal_of(const json_t *body, update_proposal_t *prop)
{
    const json_t *jp = json_object_get(body, "proposal");
    if (!json_is_object(jp) || update_proposal_from_json(jp, prop) != 0)
        return false;
    const char *named = json_string_value(json_object_get(body, "proposal_uuid"));
    uuid_t u;
    return named == NULL || (uuid_parse(named, u) == 0
                             && uuid_compare(u, prop->proposal_uuid) == 0);
}

/* Act on an update that carried: keep it, tell the app, fetch the artifact
 * from @p from unless we hold it. Caller has verified the certificate. */
static void _apply(const process_t *proc, const update_proposal_t *prop,
                   const public_identity_t *from)
{
    char prop_uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(prop->proposal_uuid, prop_uuid_str);
    char artifact_hash_hex[UPDATE_HASH_LEN * 2 + 1] = {0};
    sodium_bin2hex(artifact_hash_hex, sizeof(artifact_hash_hex), prop->artifact_hash,
                   UPDATE_HASH_LEN);

    pthread_mutex_lock(&fleet_state.lock);
    data_t *dat = NULL;
    if (map_get(&fleet_state.accepted_updates, prop_uuid_str, &dat) == 0 && dat != NULL) {
        pthread_mutex_unlock(&fleet_state.lock);
        log_debug(proc->logger, "Fleet: %s already accepted\n", prop_uuid_str);
        return;
    }
    /* A plain struct (no smrt header) owned by its data_t. */
    update_proposal_t *copy = malloc(sizeof(update_proposal_t));
    data_t *cd = copy != NULL ? owned_object_data(memcpy(copy, prop, sizeof(*prop)),
                                                  sizeof(*prop))
                              : NULL;
    if (cd == NULL)
        free(copy);
    else if (map_set(&fleet_state.accepted_updates, prop_uuid_str, cd) != 0)
        smrt_deref(cd);
    if (map_get(&fleet_state.pending_proposals, prop_uuid_str, &dat) == 0)
        map_remove(&fleet_state.pending_proposals, prop_uuid_str);
    pthread_mutex_unlock(&fleet_state.lock);
    log_info(proc->logger, "Fleet: proposal %s accepted\n", prop_uuid_str);

    /* Tell the app, through the main process: FLEET_UPDATE_ACCEPTED is
     * app-bound, so the main loop forwards it. */
    generic_msg_t notify = {0};
    notify.type = FLEET_UPDATE_ACCEPTED;
    uuid_copy(AT_MSG_EXT(&notify, fleet_update_accepted_msg_t)->proposal_uuid,
              prop->proposal_uuid);
    at_send(proc, AT_MAIN_QUEUE, &notify, "an accepted update", AT_MAIN_QUEUE,
            0, NULL, NULL, 0);

    if (artifact_store_has(artifact_hash_hex)) {
        log_info(proc->logger, "Fleet: already holding artifact %s\n", artifact_hash_hex);
        return;
    }
    if (from == NULL || from->address[0] == '\0')
        return;
    json_t *fetch_req = json_pack("{s:s}", "hash", artifact_hash_hex);
    if (fetch_req == NULL)
        return;
    generic_msg_t artifact_msg = {0};
    artifact_msg.type = NET_MESSAGE;
    net_msg_t *anmsg = &artifact_msg.info.net_msg;
    at_strlcpy(anmsg->process, "artifact", sizeof(anmsg->process));
    anmsg->function = ARTIFACT_PROTO_REQUEST;
    memcpy(&anmsg->to_whom, from, sizeof(public_identity_t));
    anmsg->encrypt = true;
    at_strlcpy(anmsg->return_to, "artifact", sizeof(anmsg->return_to));
    net_msg_pack_json(anmsg, fetch_req);
    json_decref(fetch_req);
    at_send(proc, "network", &artifact_msg, "an artifact request", "network",
            0, NULL, NULL, 0);
    net_msg_free_obj(anmsg);
    log_info(proc->logger, "Fleet: triggered artifact fetch for %s from %s\n",
             artifact_hash_hex, from->address);
}

/* The proposer's round: once ⌊N/2⌋ other members have granted, send the
 * certificate (the proposal and its grants) to every member and apply it. */
static void _try_commit(const process_t *proc, const char *prop_uuid_str)
{
    update_proposal_t prop;
    bool have = false;
    json_t *round = NULL;
    pthread_mutex_lock(&fleet_state.lock);
    data_t *dat = NULL;
    update_proposal_t *p = NULL;
    if (map_get(&fleet_state.pending_proposals, (map_key_t)prop_uuid_str, &dat) == 0
        && dat != NULL && data_object_ptr(dat, (ptr_t *)&p) == 0 && p != NULL) {
        memcpy(&prop, p, sizeof(prop));
        have = true;
    }
    round = json_object_get(fleet_state.rounds, prop_uuid_str);
    if (round != NULL)
        json_incref(round);
    pthread_mutex_unlock(&fleet_state.lock);
    if (!have || round == NULL) {
        json_decref(round);
        return;
    }
    int64_t id1 = json_integer_value(json_object_get(round, "id1"));
    int64_t id2 = json_integer_value(json_object_get(round, "id2"));
    json_t *grants = json_object_get(round, "grants");
    size_t n = fleet_gate_group_size(proc);
    size_t need = fleet_gate_quorum(n);
    size_t count = fleet_gate_count_grants(proc, grants, FLEET_KIND, prop.proposal_uuid,
                                           prop.signer_uuid, id1, id2, prop.artifact_hash);
    if (count < need) {
        log_debug(proc->logger, "Fleet: %s has %zu of %zu grants (group of %zu)\n",
                  prop_uuid_str, count, need, n);
        json_decref(round);
        return;
    }
    json_t *acc = json_pack("{s:o, s:I, s:I, s:s, s:O}", "proposal",
                            update_proposal_to_json(&prop), "id1", (json_int_t)id1,
                            "id2", (json_int_t)id2, "proposal_uuid", prop_uuid_str,
                            "grants", grants);
    json_decref(round);
    pthread_mutex_lock(&fleet_state.lock);
    json_object_del(fleet_state.rounds, prop_uuid_str);
    pthread_mutex_unlock(&fleet_state.lock);
    log_info(proc->logger, "Fleet: proposal %s carried (%zu of %zu grants, group of "
             "%zu); sending the certificate\n", prop_uuid_str, count, need, n);
    if (acc != NULL) {
        _send_to_members(proc, FLEET_PROTO_ACCEPTED, acc, "an acceptance");
        json_decref(acc);
    }
    paxos_advance_chain(&fleet_state.vote_paxos);
    _apply(proc, &prop, NULL);
}

/* Start the vote on a proposal this node signed or holds. */
static void _start_vote(const process_t *proc, const update_proposal_t *prop)
{
    char prop_uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(prop->proposal_uuid, prop_uuid_str);
    int64_t id1, id2;
    paxos_next_ids(&fleet_state.vote_paxos, &id1, &id2);

    pthread_mutex_lock(&fleet_state.lock);
    /* A plain struct (no smrt header) owned by its data_t, so the map
     * releases it when the last reference goes. */
    update_proposal_t *heap_prop = malloc(sizeof(update_proposal_t));
    data_t *prop_dat = heap_prop != NULL
        ? owned_object_data(memcpy(heap_prop, prop, sizeof(*prop)), sizeof(*prop))
        : NULL;
    if (prop_dat == NULL)
        free(heap_prop);
    else if (map_set(&fleet_state.pending_proposals, prop_uuid_str, prop_dat) != 0)
        smrt_deref(prop_dat);
    json_object_set_new(fleet_state.rounds, prop_uuid_str,
                        json_pack("{s:I, s:I, s:[]}", "id1", (json_int_t)id1,
                                  "id2", (json_int_t)id2, "grants"));
    pthread_mutex_unlock(&fleet_state.lock);

    /* The vote request carries the proposal itself, so each voter checks
     * what it is granting. */
    json_t *req_json = json_pack("{s:I, s:I, s:s, s:o}", "id1", (json_int_t)id1,
                                 "id2", (json_int_t)id2, "proposal_uuid", prop_uuid_str,
                                 "proposal", update_proposal_to_json(prop));
    if (req_json == NULL) {
        log_error(proc->logger, "Fleet: out of memory building a vote request\n");
        return;
    }
    _send_to_members(proc, FLEET_PROTO_VOTE_REQ, req_json, "a vote request");
    json_decref(req_json);
    log_info(proc->logger, "Fleet: Proposal %s stored, vote initiated\n", prop_uuid_str);
    /* A group of one carries it at once (⌊1/2⌋ = 0 grants). */
    _try_commit(proc, prop_uuid_str);
}

/****************************
 * Handler: handle_update_proposal
 * A local proposal (the node's own, or one handed to it to run): run the
 * proposer checks, then the vote.
 ****************************/

/* Frama-C: skipped — [solver-timeout] json + gate + map cascade. */
static bool handle_update_proposal(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    json_t *payload = NULL;
    update_proposal_t proposal;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL
        || update_proposal_from_json(payload, &proposal) != 0) {
        json_decref(payload);
        log_warn(proc->logger, "Fleet: update proposal refused: not a proposal\n");
        return true;
    }
    json_decref(payload);
    /* A node runs the vote only on a proposal it signed: another member's
     * proposal reaches it as a vote request, and is checked there. */
    if (!uuid_is_null(nmsg->from_whom.uuid)
        && uuid_compare(nmsg->from_whom.uuid, proposal.signer_uuid) != 0) {
        log_warn(proc->logger, "Fleet: update proposal from %s refused: it is signed "
                 "by another node\n", nmsg->from_whom.nickname);
        return true;
    }
    if (!fleet_gate_is_self(proc, proposal.signer_uuid)) {
        log_warn(proc->logger, "Fleet: update proposal refused: this node runs the vote "
                 "only on its own proposals\n");
        return true;
    }
    if (!_gate(proc, &proposal, msg, handle_update_proposal, "proposal"))
        return true;
    _start_vote(proc, &proposal);
    return true;
}

/****************************
 * Handler: handle_vote_request
 * A voter checks the proposal it carries, then the ballot, and signs a grant.
 ****************************/

/* Frama-C: skipped — [solver-timeout] json + gate + crypto cascade. */
static bool handle_vote_request(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Fleet: vote request from %s\n", nmsg->from_whom.nickname);

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL) {
        log_error(proc->logger, "Fleet: handle_vote_request: failed to unpack JSON\n");
        return true;
    }
    json_t *j_id1 = json_object_get(payload, "id1");
    json_t *j_id2 = json_object_get(payload, "id2");
    update_proposal_t prop;
    if (!json_is_integer(j_id1) || !json_is_integer(j_id2) || !_proposal_of(payload, &prop)) {
        json_decref(payload);
        log_warn(proc->logger, "Fleet: vote request from %s refused: no proposal to "
                 "check\n", nmsg->from_whom.nickname);
        return true;
    }
    int64_t id1 = json_integer_value(j_id1);
    int64_t id2 = json_integer_value(j_id2);
    json_decref(payload);

    /* The requester runs the vote on its own proposal. */
    if (uuid_compare(nmsg->from_whom.uuid, prop.signer_uuid) != 0) {
        log_warn(proc->logger, "Fleet: vote request from %s refused: the proposal is "
                 "signed by another node\n", nmsg->from_whom.nickname);
        return true;
    }
    if (!_gate(proc, &prop, msg, handle_vote_request, "vote request"))
        return true;

    char prop_uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(prop.proposal_uuid, prop_uuid_str);
    int64_t out_last_id = 0;
    int out_chain_len = 0;
    paxos_response_t result = paxos_handle_request(&fleet_state.vote_paxos, id1, id2,
                                                   &out_last_id, &out_chain_len);
    json_t *reply = NULL;
    const char *function = FLEET_PROTO_VOTE_NACK;
    if (result == PAXOS_GRANT) {
        reply = fleet_gate_sign_grant(proc, FLEET_KIND, prop.proposal_uuid, id1, id2,
                                      prop.artifact_hash);
        if (reply == NULL) {
            log_error(proc->logger, "Fleet: could not sign a grant for %s\n", prop_uuid_str);
            return true;
        }
        json_object_set_new(reply, "last_id", json_integer(out_last_id));
        json_object_set_new(reply, "chain_len", json_integer(out_chain_len));
        function = FLEET_PROTO_VOTE_GRANT;
    } else {
        reply = json_pack("{s:I, s:I, s:s}", "id1", (json_int_t)id1, "id2", (json_int_t)id2,
                          "proposal_uuid", prop_uuid_str);
        if (reply == NULL)
            return true;
    }
    generic_msg_t out = {0};
    out.type = NET_MESSAGE;
    at_strlcpy(out.info.net_msg.process, "fleet", sizeof(out.info.net_msg.process));
    out.info.net_msg.function = (char *)function;
    out.info.net_msg.encrypt = true;
    memcpy(&out.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
    at_strlcpy(out.info.net_msg.return_to, "fleet", sizeof(out.info.net_msg.return_to));
    net_msg_pack_json(&out.info.net_msg, reply);
    json_decref(reply);
    log_debug(proc->logger, "Fleet: Vote %s\n", result == PAXOS_GRANT ? "granted" : "nacked");
    at_send(proc, "network", &out,
            result == PAXOS_GRANT ? "a vote grant" : "a vote refusal", "network",
            0, NULL, NULL, 0);
    net_msg_free_obj(&out.info.net_msg);
    return true;
}

/****************************
 * Handler: handle_vote_grant
 * The proposer keeps each member's signed grant; enough of them carry it.
 ****************************/

/* Frama-C: skipped — [solver-timeout] json + crypto cascade. */
static bool handle_vote_grant(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Fleet: vote grant from %s\n", nmsg->from_whom.nickname);

    json_t *grant = NULL;
    if (net_msg_unpack_json(nmsg, &grant) != 0 || grant == NULL)
        return true;
    const char *prop_uuid_raw = json_string_value(json_object_get(grant, "proposal_uuid"));
    char prop_uuid_str[UUID_STRING_LEN + 1] = {0};
    if (prop_uuid_raw != NULL)
        at_strlcpy(prop_uuid_str, prop_uuid_raw, sizeof(prop_uuid_str));

    update_proposal_t prop;
    bool have = false;
    pthread_mutex_lock(&fleet_state.lock);
    data_t *dat = NULL;
    update_proposal_t *p = NULL;
    json_t *round = json_object_get(fleet_state.rounds, prop_uuid_str);
    if (round != NULL && map_get(&fleet_state.pending_proposals, prop_uuid_str, &dat) == 0
        && dat != NULL && data_object_ptr(dat, (ptr_t *)&p) == 0 && p != NULL) {
        memcpy(&prop, p, sizeof(prop));
        have = true;
    }
    int64_t id1 = have ? json_integer_value(json_object_get(round, "id1")) : 0;
    int64_t id2 = have ? json_integer_value(json_object_get(round, "id2")) : 0;
    pthread_mutex_unlock(&fleet_state.lock);
    if (!have) {
        json_decref(grant);
        log_debug(proc->logger, "Fleet: grant for %s, which is not an open round here\n",
                  prop_uuid_str);
        return true;
    }
    uuid_t granter;
    if (!fleet_gate_grant_valid(proc, grant, FLEET_KIND, prop.proposal_uuid, id1, id2,
                                prop.artifact_hash, granter)
        || uuid_compare(granter, nmsg->from_whom.uuid) != 0) {
        json_decref(grant);
        log_warn(proc->logger, "Fleet: grant for %s from %s refused: not a valid "
                 "member's signature over this ballot\n", prop_uuid_str,
                 nmsg->from_whom.nickname);
        return true;
    }
    json_object_del(grant, "last_id");
    json_object_del(grant, "chain_len");
    pthread_mutex_lock(&fleet_state.lock);
    round = json_object_get(fleet_state.rounds, prop_uuid_str);
    if (round != NULL) {
        /* One grant per member: a repeat is not kept, so the certificate
         * carries each granter once. */
        json_t *kept = json_object_get(round, "grants");
        const char *who = json_string_value(json_object_get(grant, "granter"));
        bool repeat = false;
        size_t i;
        json_t *g;
        json_array_foreach(kept, i, g)
            repeat = repeat || (who != NULL && json_string_value(json_object_get(g, "granter"))
                                && strcmp(who, json_string_value(json_object_get(g, "granter"))) == 0);
        if (!repeat)
            json_array_append(kept, grant);
    }
    pthread_mutex_unlock(&fleet_state.lock);
    json_decref(grant);
    _try_commit(proc, prop_uuid_str);
    return true;
}

/****************************
 * Handler: handle_vote_nack
 * Record nack with exponential backoff.
 ****************************/

/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
  requires fleet_state.vote_paxos.initialized == \true;
*/
static bool handle_vote_nack(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Fleet: vote nack from %s\n", nmsg->from_whom.nickname);

    json_t *payload = NULL;
    int64_t id1 = 0, id2 = 0;
    if (net_msg_unpack_json(nmsg, &payload) == 0 && payload != NULL)
    {
        json_t *j_id1 = json_object_get(payload, "id1");
        json_t *j_id2 = json_object_get(payload, "id2");
        if (j_id1) id1 = json_integer_value(j_id1);
        if (j_id2) id2 = json_integer_value(j_id2);
        json_decref(payload);
    }

    int wait_sec = paxos_record_nack(&fleet_state.vote_paxos, id1, id2);

    log_debug(proc->logger, "Fleet: vote nack backoff %d seconds\n", wait_sec);
    (void)wait_sec;

    return true;
}

/****************************
 * Handler: handle_update_accepted
 * An acceptance is a certificate: the proposal and its grants. Every node
 * checks both itself, against its own view of the group, before acting.
 ****************************/

/* Frama-C: skipped — [solver-timeout] json + gate + crypto cascade. */
static bool handle_update_accepted(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Fleet: update accepted from %s\n", nmsg->from_whom.nickname);

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
        return true;
    update_proposal_t prop;
    json_t *j_id1 = json_object_get(payload, "id1");
    json_t *j_id2 = json_object_get(payload, "id2");
    if (!json_is_integer(j_id1) || !json_is_integer(j_id2) || !_proposal_of(payload, &prop)) {
        json_decref(payload);
        log_warn(proc->logger, "Fleet: acceptance from %s ignored: it carries no "
                 "proposal\n", nmsg->from_whom.nickname);
        return true;
    }
    if (!_gate(proc, &prop, msg, handle_update_accepted, "acceptance")) {
        json_decref(payload);
        return true;
    }
    size_t n = fleet_gate_group_size(proc);
    size_t need = fleet_gate_quorum(n);
    size_t count = fleet_gate_count_grants(proc, json_object_get(payload, "grants"),
                                           FLEET_KIND, prop.proposal_uuid, prop.signer_uuid,
                                           json_integer_value(j_id1),
                                           json_integer_value(j_id2), prop.artifact_hash);
    json_decref(payload);
    if (count < need) {
        char u[UUID_STRING_LEN + 1];
        uuid_unparse_lower(prop.proposal_uuid, u);
        log_warn(proc->logger, "Fleet: acceptance of %s from %s ignored: %zu valid "
                 "grant(s) from other members, %zu needed in our group of %zu\n", u,
                 nmsg->from_whom.nickname, count, need, n);
        return true;
    }
    _apply(proc, &prop, &nmsg->from_whom);
    return true;
}

/****************************
 * Fleet process main entry
 ****************************/

/* Frama-C: skipped — [solver-timeout] state-cascade through paxos_init +
 * process_register_handler stubs prevents WP from discharging
 * valid_rw(proc) and valid_rd(signal) at downstream call sites */
/* -- the app's proposal (app_fleet_propose) ---------------------------------- */

char FLEET_APP_PROPOSE[] = AT_APP_FLEET_PROPOSE;

/* The app proposes an update: {version, artifact_hash (64 hex), target_arch,
 * min_proposer_reputation}. An app holds no private key, so THIS node builds
 * the proposal, signs it with its identity key and names itself the signer,
 * then runs it through the proposer checks (fleet_gate.h: this node must be
 * operator-bound) and the vote. The bar the app names travels with the
 * proposal but decides nothing: each node applies its own. Local only: a frame
 * from the wire is refused. FEATURE_SPLIT_PLAN Phase 8 (the user's call,
 * 2026-10-02). */
bool fleet_handle_app_propose(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    _ensure_init();     /* idempotent; fleet_run has done it in a running node */
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!uuid_is_null(nmsg->from_whom.uuid)) {
        log_warn(proc->logger, "Fleet: refusing %s from the wire\n", AT_APP_FLEET_PROPOSE);
        return true;
    }
    json_t *req = NULL;
    if (net_msg_unpack_json(nmsg, &req) != 0 || !json_is_object(req)) {
        json_decref(req);
        log_warn(proc->logger, "Fleet: %s: not a JSON object\n", AT_APP_FLEET_PROPOSE);
        return true;
    }
    const char *version = json_string_value(json_object_get(req, "version"));
    const char *hash_hex = json_string_value(json_object_get(req, "artifact_hash"));
    const char *arch = json_string_value(json_object_get(req, "target_arch"));
    json_t *min_rep = json_object_get(req, "min_proposer_reputation");
    update_proposal_t prop;
    memset(&prop, 0, sizeof(prop));
    size_t hash_len = 0;
    bool ok = version != NULL && version[0] != '\0' && strlen(version) <= UPDATE_VERSION_LEN
              && hash_hex != NULL && strlen(hash_hex) == 2 * UPDATE_HASH_LEN
              && sodium_hex2bin(prop.artifact_hash, UPDATE_HASH_LEN, hash_hex,
                                strlen(hash_hex), NULL, &hash_len, NULL) == 0
              && hash_len == UPDATE_HASH_LEN
              && (arch == NULL || strlen(arch) <= UPDATE_ARCH_LEN)
              && (min_rep == NULL || json_is_number(min_rep));
    const identity_t *self = identity_self_identity(proc);
    if (!ok || self == NULL) {
        json_decref(req);
        log_warn(proc->logger, "Fleet: %s: %s\n", AT_APP_FLEET_PROPOSE,
                 ok ? "no identity to sign with" : "bad proposal fields");
        return true;
    }
    at_strlcpy(prop.version, version, sizeof(prop.version));
    at_strlcpy(prop.target_arch, arch != NULL ? arch : "unknown", sizeof(prop.target_arch));
    prop.min_proposer_reputation = min_rep != NULL ? json_number_value(min_rep) : 0.0;
    json_decref(req);
    uuid_generate(prop.proposal_uuid);
    uuid_copy(prop.signer_uuid, self->uuid);
    if (update_proposal_sign(&prop, self->signature.private) != 0) {
        log_error(proc->logger, "Fleet: %s: signing failed\n", AT_APP_FLEET_PROPOSE);
        return true;
    }
    public_identity_t *pub = NULL;
    json_t *body = update_proposal_to_json(&prop);
    if (body == NULL || identity_publish(self, &pub) != 0 || pub == NULL) {
        json_decref(body);
        smrt_deref(pub);
        return true;
    }
    generic_msg_t own = {0};
    own.type = NET_MESSAGE;
    net_msg_t *onmsg = &own.info.net_msg;
    at_strlcpy(onmsg->process, "fleet", sizeof(onmsg->process));
    onmsg->function = FLEET_PROTO_PROPOSE;
    memcpy(&onmsg->from_whom, pub, sizeof(public_identity_t));
    smrt_deref(pub);
    int rc = net_msg_pack_json(onmsg, body);
    json_decref(body);
    if (rc == 0) {
        char u[UUID_STRING_LEN + 1];
        uuid_unparse_lower(prop.proposal_uuid, u);
        log_info(proc->logger, "Fleet: proposing %s (%s) for the app as %s\n",
                 prop.version, prop.target_arch, u);
        (void)handle_update_proposal(proc, queues, &own);
    }
    net_msg_free_obj(onmsg);
    return true;
}

bool fleet_pending_proposal(const char *proposal_uuid, update_proposal_t *out)
{
    if (proposal_uuid == NULL || out == NULL)
        return false;
    _ensure_init();
    bool found = false;
    pthread_mutex_lock(&fleet_state.lock);
    data_t *dat = NULL;
    update_proposal_t *prop = NULL;
    if (map_get(&fleet_state.pending_proposals, (map_key_t)proposal_uuid, &dat) == 0
        && dat != NULL && data_object_ptr(dat, (ptr_t *)&prop) == 0 && prop != NULL) {
        memcpy(out, prop, sizeof(*out));
        found = true;
    }
    pthread_mutex_unlock(&fleet_state.lock);
    return found;
}

/* The app may send it, only to fleet (msg_registry.h). */
AT_APP_VERB_REGISTER(fleet_propose, AT_APP_FLEET_PROPOSE, "fleet")

/* The fleet handlers, registered on @p proc (fleet_run, and tests). */
int fleet_register_handlers(const process_t *proc)
{
    _ensure_init();
    /* The quorum is sized from the live group each time it is counted
     * (fleet_gate_quorum), so Paxos here only orders the ballots. */
    if (!fleet_state.vote_paxos.initialized)
        paxos_init(&fleet_state.vote_paxos, 0, proc->logger);
    process_register_handler(proc, FLEET_PROTO_PROPOSE,    (handler_ptr_t)handle_update_proposal);
    process_register_handler(proc, FLEET_PROTO_VOTE_REQ,   (handler_ptr_t)handle_vote_request);
    process_register_handler(proc, FLEET_PROTO_VOTE_GRANT, (handler_ptr_t)handle_vote_grant);
    process_register_handler(proc, FLEET_PROTO_VOTE_NACK,  (handler_ptr_t)handle_vote_nack);
    process_register_handler(proc, FLEET_PROTO_ACCEPTED,   (handler_ptr_t)handle_update_accepted);
    process_register_handler(proc, FLEET_APP_PROPOSE,      (handler_ptr_t)fleet_handle_app_propose);
    process_register_handler(proc, REP_PROTO_LOCAL_RESP,   (handler_ptr_t)fleet_gate_handle_rep_reply);

    return 0;
}

int fleet_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger)
{
    _ensure_init();


    fleet_register_handlers(proc);

    proc->protocol.phase = 1;

    return process_run(proc, queues, signal, logger);
}
/* An extension's process (FEATURE_SPLIT_PLAN Phase 8): registered at load,
 * and started by default once this library is linked. */
DEFINE_PROCESS(fleet, fleet_proc, fleet_run)
DEFINE_SUBSYSTEM(fleet, "fleet", "fleet_proc")
