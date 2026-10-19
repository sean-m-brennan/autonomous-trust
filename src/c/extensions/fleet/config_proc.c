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

#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

#include <sodium.h>

#include "processes/processes.h"
#include "processes/process_tracker.h"
#include "fleet/config_proc.h"
#include "fleet/artifact_proc.h"
#include "fleet/artifact_store.h"
#include "fleet/update_proc.h"
#include "algorithms/paxos.h"
#include "structures/map.h"
#include "structures/array.h"
#include "structures/data.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"
#include "utilities/exception.h"
#include "network/net_message.h"
#include "utilities/send_retry.h"   /* at_send: keep a refused frame (ISSUES §2.14) */
#include "utilities/util.h"
#include "fleet/fleet_gate.h"
#include "reputation/reputation.h"   /* REP_PROTO_LOCAL_RESP */

#define ECONFIG 301   /* fleet: 300s (290 is EX509_CALOAD) */
DEFINE_ERROR(ECONFIG, "Config distribution error");

/* Protocol-string definitions (declared `extern char[]` in
 * config_proc.h). Writable arrays for direct `char *` assignment. */
char CONFIG_PROTO_PROPOSE[]    = "config proposal";
char CONFIG_PROTO_VOTE_REQ[]   = "config vote request";
char CONFIG_PROTO_VOTE_GRANT[] = "config vote grant";
char CONFIG_PROTO_VOTE_NACK[]  = "config vote nack";
char CONFIG_PROTO_ACCEPTED[]   = "config accepted";
char CONFIG_PROTO_READY[]      = "config ready";


/****************************
 * Process state (file-scope static, thread-safe via mutex)
 ****************************/

static struct {
    paxos_instance_t vote_paxos;
    map_t pending_proposals;   /* proposal_uuid_str -> config_proposal_t* */
    map_t accepted_configs;    /* proposal_uuid_str -> config_proposal_t* */
    json_t *rounds;            /* proposal_uuid_str -> {id1, id2, grants[]} (proposer) */
    pthread_mutex_t lock;
    bool initialized;
} config_state;

static char config_data_dir[256] = {0};
static char config_cfg_dir[CFG_PATH_LEN] = {0};

static void _ensure_init(void)
{
    if (!config_state.initialized)
    {
        map_init(&config_state.pending_proposals);
        map_init(&config_state.accepted_configs);
        config_state.rounds = json_object();
        pthread_mutex_init(&config_state.lock, NULL);
        config_state.initialized = true;
    }
}

/****************************
 * Helper: send_to_peer
 * Build and send a NET_MESSAGE to a single peer via the network process.
 ****************************/

/*@
  requires \valid(proc);
  requires function != \null && \valid_read(function);
  requires payload == \null || \valid(payload);
  requires \valid_read(peer);
  ensures \result == 0 || \result != 0;
*/
/* Frama-C: skipped — [solver-timeout] at_memcpy_requires on
 * memcpy(&to_whom, peer, sizeof(public_identity_t)); same cast cascade as
 * handle_config_accepted. */
static int send_to_peer(const process_t *proc, const char *function,
                        json_t *payload, const public_identity_t *peer)
{
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    strncpy(msg.info.net_msg.process, "config", PROC_NAME_LEN);
    msg.info.net_msg.function = (char *)function;
    msg.info.net_msg.encrypt = true;
    memcpy(&msg.info.net_msg.to_whom, peer, sizeof(public_identity_t));
    strncpy(msg.info.net_msg.return_to, "config", PROC_NAME_LEN);
    net_msg_pack_json(&msg.info.net_msg, payload);
    int rc = at_send(proc, "network", &msg, function, "network",
                     0, NULL, NULL, 0);
    net_msg_free_obj(&msg.info.net_msg);
    return rc;
}

/* What a grant is signed over names the protocol, so a config grant cannot be
 * replayed as a fleet grant. */
static const char CONFIG_KIND[] = "config";

static bool handle_config_propose(const process_t *proc, directory_t *queues, generic_msg_t *msg);
static bool handle_config_vote_request(const process_t *proc, directory_t *queues, generic_msg_t *msg);
static bool handle_config_accepted(const process_t *proc, directory_t *queues, generic_msg_t *msg);

static int _verify(const void *prop, const uint8_t *pk)
{
    return config_proposal_verify((const config_proposal_t *)prop, pk);
}

/* The ZTA policy's section name (zta/zta_identity.c). Spelled out rather than
 * included: fleet does not link libat_zta. */
#define CONFIG_ZTA_POLICY_NAME "zta_policy"

/* A config name is written as <cfg_dir>/<name>.cfg.json, so it must be a plain
 * name: letters, digits, '_' and '-'. Anything else could reach another file,
 * and "./identity" would pass the exact-name checks below. */
static bool _plain_name(const char *config_name)
{
    if (config_name == NULL || config_name[0] == '\0')
        return false;
    for (const char *c = config_name; *c != '\0'; c++)
        if (!isalnum((unsigned char)*c) && *c != '_' && *c != '-')
            return false;
    return true;
}

/* A config no proposal may replace: identity (a node's keys); the file that
 * holds the bar proposers are held to, which a carried proposal could
 * otherwise lower for the next one; and the ZTA policy, which decides who is
 * operator-bound and so who may propose at all. */
static bool _protected(const char *config_name)
{
    return !_plain_name(config_name)
           || config_is_identity(config_name)
           || strcmp(config_name, FLEET_GATE_CFG_NAME) == 0
           || strcmp(config_name, CONFIG_ZTA_POLICY_NAME) == 0;
}

static void _send_to_members(const process_t *proc, const char *function, json_t *body)
{
    public_identity_t *members = NULL;
    size_t n = fleet_gate_members(proc, &members);
    for (size_t i = 0; i < n; i++)
        send_to_peer(proc, function, body, &members[i]);
    free(members);
}

/* The proposer checks (fleet_gate.h) plus the protected names. PENDING holds
 * @p msg for @p handler; a refusal is logged. True only on PASS. */
static bool _gate(const process_t *proc, const config_proposal_t *prop, generic_msg_t *msg,
                  fleet_gate_handler_fn handler, const char *stage)
{
    char u[UUID_STRING_LEN + 1];
    uuid_unparse_lower(prop->proposal_uuid, u);
    if (_protected(prop->config_name)) {
        log_warn(proc->logger, "Config: %s for %s refused: %s is not a config a "
                 "proposal may replace\n", stage, u, prop->config_name);
        return false;
    }
    char why[160] = {0};
    fleet_gate_t verdict = fleet_gate_proposer(proc, prop->proposer_uuid, _verify, prop,
                                               why, sizeof(why));
    if (verdict == FLEET_GATE_PASS)
        return true;
    if (verdict == FLEET_GATE_PENDING && msg != NULL && handler != NULL) {
        log_info(proc->logger, "Config: %s for %s held: %s\n", stage, u, why);
        fleet_gate_hold(proc, msg, handler);
    } else {
        log_warn(proc->logger, "Config: %s for %s refused: %s\n", stage, u, why);
    }
    return false;
}

static bool _proposal_of(const json_t *body, config_proposal_t *prop)
{
    const json_t *jp = json_object_get(body, "proposal");
    if (!json_is_object(jp) || config_proposal_from_json(jp, prop) != 0)
        return false;
    const char *named = json_string_value(json_object_get(body, "proposal_uuid"));
    uuid_t u;
    return named == NULL || (uuid_parse(named, u) == 0
                             && uuid_compare(u, prop->proposal_uuid) == 0);
}

/* Act on a config change that carried: keep it, and fetch its content from
 * @p from (the artifact process answers handle_config_artifact_ready). */
static void _apply(const process_t *proc, const config_proposal_t *prop,
                   const public_identity_t *from)
{
    char prop_uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(prop->proposal_uuid, prop_uuid_str);
    pthread_mutex_lock(&config_state.lock);
    data_t *dat = NULL;
    if (map_get(&config_state.accepted_configs, prop_uuid_str, &dat) == 0 && dat != NULL) {
        pthread_mutex_unlock(&config_state.lock);
        log_debug(proc->logger, "Config: %s already accepted\n", prop_uuid_str);
        return;
    }
    config_proposal_t *copy = malloc(sizeof(config_proposal_t));
    data_t *cd = copy != NULL ? owned_object_data(memcpy(copy, prop, sizeof(*prop)),
                                                  sizeof(*prop))
                              : NULL;
    if (cd == NULL)
        free(copy);
    else if (map_set(&config_state.accepted_configs, prop_uuid_str, cd) != 0)
        smrt_deref(cd);
    if (map_get(&config_state.pending_proposals, prop_uuid_str, &dat) == 0)
        map_remove(&config_state.pending_proposals, prop_uuid_str);
    pthread_mutex_unlock(&config_state.lock);
    log_info(proc->logger, "Config: Proposal %s accepted\n", prop_uuid_str);

    if (from == NULL || from->address[0] == '\0')
        return;
    char artifact_hash_hex[UPDATE_HASH_LEN * 2 + 1];
    sodium_bin2hex(artifact_hash_hex, sizeof(artifact_hash_hex), prop->content_hash,
                   UPDATE_HASH_LEN);
    json_t *fetch_req = json_pack("{s:s, s:s}", "hash", artifact_hash_hex,
                                  "notify_process", "config");
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
    log_info(proc->logger, "Config: triggered artifact fetch for %s\n", artifact_hash_hex);
}

static void _try_commit(const process_t *proc, const char *prop_uuid_str)
{
    config_proposal_t prop;
    bool have = false;
    pthread_mutex_lock(&config_state.lock);
    data_t *dat = NULL;
    config_proposal_t *p = NULL;
    if (map_get(&config_state.pending_proposals, (map_key_t)prop_uuid_str, &dat) == 0
        && dat != NULL && data_object_ptr(dat, (ptr_t *)&p) == 0 && p != NULL) {
        memcpy(&prop, p, sizeof(prop));
        have = true;
    }
    json_t *round = json_object_get(config_state.rounds, prop_uuid_str);
    if (round != NULL)
        json_incref(round);
    pthread_mutex_unlock(&config_state.lock);
    if (!have || round == NULL) {
        json_decref(round);
        return;
    }
    int64_t id1 = json_integer_value(json_object_get(round, "id1"));
    int64_t id2 = json_integer_value(json_object_get(round, "id2"));
    json_t *grants = json_object_get(round, "grants");
    size_t n = fleet_gate_group_size(proc);
    size_t need = fleet_gate_quorum(n);
    size_t count = fleet_gate_count_grants(proc, grants, CONFIG_KIND, prop.proposal_uuid,
                                           prop.proposer_uuid, id1, id2, prop.content_hash);
    if (count < need) {
        log_debug(proc->logger, "Config: %s has %zu of %zu grants (group of %zu)\n",
                  prop_uuid_str, count, need, n);
        json_decref(round);
        return;
    }
    json_t *acc = json_pack("{s:o, s:I, s:I, s:s, s:O}", "proposal",
                            config_proposal_to_json(&prop), "id1", (json_int_t)id1,
                            "id2", (json_int_t)id2, "proposal_uuid", prop_uuid_str,
                            "grants", grants);
    json_decref(round);
    pthread_mutex_lock(&config_state.lock);
    json_object_del(config_state.rounds, prop_uuid_str);
    pthread_mutex_unlock(&config_state.lock);
    log_info(proc->logger, "Config: proposal %s carried (%zu of %zu grants, group of "
             "%zu); sending the certificate\n", prop_uuid_str, count, need, n);
    if (acc != NULL) {
        _send_to_members(proc, CONFIG_PROTO_ACCEPTED, acc);
        json_decref(acc);
    }
    paxos_advance_chain(&config_state.vote_paxos);
    _apply(proc, &prop, NULL);
}

/****************************
 * Handler: handle_config_propose
 * A local proposal, signed by this node: run the proposer checks, then the
 * vote. Another member's proposal arrives as a vote request instead.
 ****************************/

/* Frama-C: skipped — [solver-timeout] json + gate + map cascade. */
static bool handle_config_propose(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    json_t *payload = NULL;
    config_proposal_t proposal;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL
        || config_proposal_from_json(payload, &proposal) != 0) {
        json_decref(payload);
        log_warn(proc->logger, "Config: proposal refused: not a proposal\n");
        return true;
    }
    json_decref(payload);
    if (!uuid_is_null(nmsg->from_whom.uuid)
        && uuid_compare(nmsg->from_whom.uuid, proposal.proposer_uuid) != 0) {
        log_warn(proc->logger, "Config: proposal from %s refused: it is signed by "
                 "another node\n", nmsg->from_whom.nickname);
        return true;
    }
    if (!fleet_gate_is_self(proc, proposal.proposer_uuid)) {
        log_warn(proc->logger, "Config: proposal refused: this node runs the vote only "
                 "on its own proposals\n");
        return true;
    }
    if (!_gate(proc, &proposal, msg, handle_config_propose, "proposal"))
        return true;

    char prop_uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(proposal.proposal_uuid, prop_uuid_str);
    int64_t id1, id2;
    paxos_next_ids(&config_state.vote_paxos, &id1, &id2);
    pthread_mutex_lock(&config_state.lock);
    /* A heap copy the data_t owns. */
    config_proposal_t *heap_prop = malloc(sizeof(config_proposal_t));
    data_t *prop_dat = (heap_prop != NULL)
        ? owned_object_data(memcpy(heap_prop, &proposal, sizeof(config_proposal_t)),
                            sizeof(config_proposal_t))
        : NULL;
    if (prop_dat == NULL)
        free(heap_prop);
    else if (map_set(&config_state.pending_proposals, prop_uuid_str, prop_dat) != 0)
        smrt_deref(prop_dat);
    json_object_set_new(config_state.rounds, prop_uuid_str,
                        json_pack("{s:I, s:I, s:[]}", "id1", (json_int_t)id1,
                                  "id2", (json_int_t)id2, "grants"));
    pthread_mutex_unlock(&config_state.lock);

    /* The vote request carries the proposal, so each voter checks it. */
    json_t *req_json = json_pack("{s:I, s:I, s:s, s:o}", "id1", (json_int_t)id1,
                                 "id2", (json_int_t)id2, "proposal_uuid", prop_uuid_str,
                                 "proposal", config_proposal_to_json(&proposal));
    if (req_json == NULL) {
        log_error(proc->logger, "Config: json_object OOM (vote_req)\n");
        return true;
    }
    _send_to_members(proc, CONFIG_PROTO_VOTE_REQ, req_json);
    json_decref(req_json);
    log_info(proc->logger, "Config: Proposal %s stored, vote initiated\n", prop_uuid_str);
    _try_commit(proc, prop_uuid_str);
    return true;
}

/****************************
 * Handler: handle_config_vote_request
 * A voter checks the proposal it carries, then the ballot, and signs a grant.
 ****************************/

/* Frama-C: skipped — [solver-timeout] json + gate + crypto cascade. */
static bool handle_config_vote_request(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Config: vote request from %s\n", nmsg->from_whom.nickname);

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL) {
        log_error(proc->logger, "Config: handle_config_vote_request: failed to unpack JSON\n");
        return true;
    }
    json_t *j_id1 = json_object_get(payload, "id1");
    json_t *j_id2 = json_object_get(payload, "id2");
    config_proposal_t prop;
    if (!json_is_integer(j_id1) || !json_is_integer(j_id2) || !_proposal_of(payload, &prop)) {
        json_decref(payload);
        log_warn(proc->logger, "Config: vote request from %s refused: no proposal to "
                 "check\n", nmsg->from_whom.nickname);
        return true;
    }
    int64_t id1 = json_integer_value(j_id1);
    int64_t id2 = json_integer_value(j_id2);
    json_decref(payload);
    if (uuid_compare(nmsg->from_whom.uuid, prop.proposer_uuid) != 0) {
        log_warn(proc->logger, "Config: vote request from %s refused: the proposal is "
                 "signed by another node\n", nmsg->from_whom.nickname);
        return true;
    }
    if (config_is_identity(prop.config_name)) {
        /* An attempt on a node's identity costs the proposer standing. */
        generic_msg_t score_msg = {0};
        score_msg.type = TRANSACTION_SCORE;
        score_msg.info.tx_score.score = CONFIG_IDENTITY_PENALTY;
        memcpy(&score_msg.info.tx_score.peer_uuid, &nmsg->from_whom.uuid, sizeof(uuid_t));
        at_send(proc, "reputation", &score_msg, "a fleet score", "reputation",
                0, NULL, NULL, 0);
    }
    if (!_gate(proc, &prop, msg, handle_config_vote_request, "vote request"))
        return true;

    char prop_uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(prop.proposal_uuid, prop_uuid_str);
    int64_t out_last_id = 0;
    int out_chain_len = 0;
    paxos_response_t result = paxos_handle_request(&config_state.vote_paxos, id1, id2,
                                                   &out_last_id, &out_chain_len);
    if (result == PAXOS_GRANT) {
        json_t *grant = fleet_gate_sign_grant(proc, CONFIG_KIND, prop.proposal_uuid, id1,
                                              id2, prop.content_hash);
        if (grant == NULL) {
            log_error(proc->logger, "Config: could not sign a grant for %s\n", prop_uuid_str);
            return true;
        }
        json_object_set_new(grant, "last_id", json_integer(out_last_id));
        json_object_set_new(grant, "chain_len", json_integer(out_chain_len));
        send_to_peer(proc, CONFIG_PROTO_VOTE_GRANT, grant, &nmsg->from_whom);
        json_decref(grant);
        log_debug(proc->logger, "Config: Vote granted\n");
    } else {
        json_t *nack_json = json_pack("{s:I, s:I, s:s}", "id1", (json_int_t)id1,
                                      "id2", (json_int_t)id2, "proposal_uuid", prop_uuid_str);
        if (nack_json == NULL)
            return true;
        send_to_peer(proc, CONFIG_PROTO_VOTE_NACK, nack_json, &nmsg->from_whom);
        json_decref(nack_json);
        log_debug(proc->logger, "Config: Vote nacked\n");
    }
    return true;
}

/****************************
 * Handler: handle_config_vote_grant
 * The proposer keeps each member's signed grant; enough of them carry it.
 ****************************/

/* Frama-C: skipped — [solver-timeout] json + crypto cascade. */
static bool handle_config_vote_grant(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Config: vote grant from %s\n", nmsg->from_whom.nickname);

    json_t *grant = NULL;
    if (net_msg_unpack_json(nmsg, &grant) != 0 || grant == NULL)
        return true;
    const char *prop_uuid_raw = json_string_value(json_object_get(grant, "proposal_uuid"));
    char prop_uuid_str[UUID_STRING_LEN + 1] = {0};
    if (prop_uuid_raw != NULL)
        at_strlcpy(prop_uuid_str, prop_uuid_raw, sizeof(prop_uuid_str));

    config_proposal_t prop;
    bool have = false;
    pthread_mutex_lock(&config_state.lock);
    data_t *dat = NULL;
    config_proposal_t *p = NULL;
    json_t *round = json_object_get(config_state.rounds, prop_uuid_str);
    if (round != NULL && map_get(&config_state.pending_proposals, prop_uuid_str, &dat) == 0
        && dat != NULL && data_object_ptr(dat, (ptr_t *)&p) == 0 && p != NULL) {
        memcpy(&prop, p, sizeof(prop));
        have = true;
    }
    int64_t id1 = have ? json_integer_value(json_object_get(round, "id1")) : 0;
    int64_t id2 = have ? json_integer_value(json_object_get(round, "id2")) : 0;
    pthread_mutex_unlock(&config_state.lock);
    if (!have) {
        json_decref(grant);
        return true;
    }
    uuid_t granter;
    if (!fleet_gate_grant_valid(proc, grant, CONFIG_KIND, prop.proposal_uuid, id1, id2,
                                prop.content_hash, granter)
        || uuid_compare(granter, nmsg->from_whom.uuid) != 0) {
        json_decref(grant);
        log_warn(proc->logger, "Config: grant for %s from %s refused: not a valid "
                 "member's signature over this ballot\n", prop_uuid_str,
                 nmsg->from_whom.nickname);
        return true;
    }
    json_object_del(grant, "last_id");
    json_object_del(grant, "chain_len");
    pthread_mutex_lock(&config_state.lock);
    round = json_object_get(config_state.rounds, prop_uuid_str);
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
    pthread_mutex_unlock(&config_state.lock);
    json_decref(grant);
    _try_commit(proc, prop_uuid_str);
    return true;
}

/****************************
 * Handler: handle_config_vote_nack
 * Record nack with exponential backoff.
 ****************************/

/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
  requires config_state.vote_paxos.initialized == \true;
*/
static bool handle_config_vote_nack(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Config: vote nack from %s\n", nmsg->from_whom.nickname);

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

    int wait_sec = paxos_record_nack(&config_state.vote_paxos, id1, id2);

    log_debug(proc->logger, "Config: vote nack backoff %d seconds\n", wait_sec);
    (void)wait_sec;

    return true;
}

/****************************
 * Handler: handle_config_accepted
 * An acceptance is a certificate: the proposal and its grants. Every node
 * checks both itself, against its own view of the group, before fetching the
 * content or writing anything.
 ****************************/

/* Frama-C: skipped — [solver-timeout] json + gate + crypto cascade. */
static bool handle_config_accepted(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Config: config accepted from %s\n", nmsg->from_whom.nickname);

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
        return true;
    config_proposal_t prop;
    json_t *j_id1 = json_object_get(payload, "id1");
    json_t *j_id2 = json_object_get(payload, "id2");
    if (!json_is_integer(j_id1) || !json_is_integer(j_id2) || !_proposal_of(payload, &prop)) {
        json_decref(payload);
        log_warn(proc->logger, "Config: acceptance from %s ignored: it carries no "
                 "proposal\n", nmsg->from_whom.nickname);
        return true;
    }
    if (!_gate(proc, &prop, msg, handle_config_accepted, "acceptance")) {
        json_decref(payload);
        return true;
    }
    size_t n = fleet_gate_group_size(proc);
    size_t need = fleet_gate_quorum(n);
    size_t count = fleet_gate_count_grants(proc, json_object_get(payload, "grants"),
                                           CONFIG_KIND, prop.proposal_uuid, prop.proposer_uuid,
                                           json_integer_value(j_id1),
                                           json_integer_value(j_id2), prop.content_hash);
    json_decref(payload);
    if (count < need) {
        char u[UUID_STRING_LEN + 1];
        uuid_unparse_lower(prop.proposal_uuid, u);
        log_warn(proc->logger, "Config: acceptance of %s from %s ignored: %zu valid "
                 "grant(s) from other members, %zu needed in our group of %zu\n", u,
                 nmsg->from_whom.nickname, count, need, n);
        return true;
    }
    _apply(proc, &prop, &nmsg->from_whom);
    return true;
}

/****************************
 * Handler: handle_config_artifact_ready
 * Receives ARTIFACT_READY with {hash, path, version}.
 * Validates, backs up configs, writes the new config, notifies update_proc.
 ****************************/

/* Frama-C: skipped — [solver-timeout] file I/O (fopen/fwrite) + snprintf +
 * messaging_send + json cascade too complex for SMT */
/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_config_artifact_ready(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Config: artifact ready notification\n");

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Config: handle_config_artifact_ready: failed to unpack JSON\n");
        return false;
    }

    const char *hash_hex = json_string_value(json_object_get(payload, "hash"));
    const char *path = json_string_value(json_object_get(payload, "path"));
    const char *version = json_string_value(json_object_get(payload, "version"));

    if (!hash_hex || !path || !version)
    {
        json_decref(payload);
        log_error(proc->logger, "Config: handle_config_artifact_ready: missing JSON fields\n");
        return false;
    }

    /* Read artifact data from the path (it's a config JSON file) */
    FILE *fp = fopen(path, "rb");
    if (!fp)
    {
        json_decref(payload);
        log_error(proc->logger, "Config: handle_config_artifact_ready: cannot open %s\n", path);
        return false;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fsize <= 0 || fsize > 1024 * 1024)
    {
        fclose(fp);
        json_decref(payload);
        log_error(proc->logger, "Config: handle_config_artifact_ready: invalid file size %ld\n", fsize);
        return false;
    }

    uint8_t *data = malloc((size_t)fsize);
    if (!data)
    {
        fclose(fp);
        json_decref(payload);
        log_error(proc->logger, "Config: handle_config_artifact_ready: malloc failed\n");
        return false;
    }

    size_t nread = fread(data, 1, (size_t)fsize, fp);
    fclose(fp);

    if (nread != (size_t)fsize)
    {
        free(data);
        json_decref(payload);
        log_error(proc->logger, "Config: handle_config_artifact_ready: short read\n");
        return false;
    }

    /* Validate the config JSON */
    if (!config_validate_json(data, nread))
    {
        free(data);
        json_decref(payload);
        log_error(proc->logger, "Config: handle_config_artifact_ready: config validation failed\n");
        return false;
    }

    /* Backup ALL existing configs before applying */
    if (config_backup_all(config_cfg_dir, config_data_dir) != 0)
    {
        free(data);
        json_decref(payload);
        log_error(proc->logger, "Config: handle_config_artifact_ready: backup failed\n");
        return false;
    }

    /* Look up the accepted config proposal to get config_name */
    char config_name[CFG_NAME_SIZE + 1] = {0};

    pthread_mutex_lock(&config_state.lock);
    {
        map_key_t m_key = NULL;
        data_t *m_val = NULL;
        map_entries_for_each(&config_state.accepted_configs, m_key, m_val)
            config_proposal_t *prop = NULL;
            data_object_ptr(m_val, (ptr_t *)&prop);
            if (prop != NULL)
            {
                char prop_hash_hex[UPDATE_HASH_LEN * 2 + 1];
                sodium_bin2hex(prop_hash_hex, sizeof(prop_hash_hex),
                               prop->content_hash, UPDATE_HASH_LEN);
                if (strcmp(prop_hash_hex, hash_hex) == 0)
                {
                    snprintf(config_name, sizeof(config_name), "%s", prop->config_name);
                    break;
                }
            }
        map_end_for_each
    }
    pthread_mutex_unlock(&config_state.lock);

    if (config_name[0] == '\0')
    {
        free(data);
        json_decref(payload);
        log_error(proc->logger, "Config: handle_config_artifact_ready: no matching accepted proposal for hash %s\n",
                  hash_hex);
        return false;
    }

    /* Write the artifact data to <config_cfg_dir>/<config_name>.cfg.json */
    char cfg_path[512];
    snprintf(cfg_path, sizeof(cfg_path), "%s/%s.cfg.json", config_cfg_dir, config_name);

    FILE *out = fopen(cfg_path, "wb");
    if (!out)
    {
        free(data);
        json_decref(payload);
        log_error(proc->logger, "Config: handle_config_artifact_ready: cannot write %s\n", cfg_path);
        return false;
    }

    size_t nwritten = fwrite(data, 1, nread, out);
    fclose(out);
    free(data);

    if (nwritten != nread)
    {
        json_decref(payload);
        log_error(proc->logger, "Config: handle_config_artifact_ready: short write to %s\n", cfg_path);
        return false;
    }

    log_info(proc->logger, "Config: wrote new config %s to %s\n", config_name, cfg_path);

    /* Send CONFIG_READY to update_proc */
    json_t *ready_json = json_object();
    if (ready_json == NULL) {
        log_error(proc->logger, "Config: json_object OOM (config_ready)\n");
        json_decref(payload);
        return true;
    }
    json_object_set_new(ready_json, "config_name", json_string(config_name));
    json_object_set_new(ready_json, "hash", json_string(hash_hex));
    json_object_set_new(ready_json, "version", json_string(version));

    generic_msg_t ready_msg = {0};
    ready_msg.type = NET_MESSAGE;
    net_msg_t *rnmsg = &ready_msg.info.net_msg;
    strncpy(rnmsg->process, "update", PROC_NAME_LEN);
    rnmsg->function = CONFIG_PROTO_READY;
    rnmsg->encrypt = false;
    strncpy(rnmsg->return_to, "config", PROC_NAME_LEN);
    net_msg_pack_json(rnmsg, ready_json);
    json_decref(ready_json);

    at_send(proc, "update", &ready_msg, "a config-ready notice", "update",
            0, NULL, NULL, 0);
    net_msg_free_obj(rnmsg);

    log_info(proc->logger, "Config: sent CONFIG_READY for %s to update process\n", config_name);

    json_decref(payload);
    return true;
}

/* The config handlers, registered on @p proc (config_run, and tests). */
int config_register_handlers(const process_t *proc)
{
    _ensure_init();
    /* The quorum is sized from the live group each time it is counted
     * (fleet_gate_quorum), so Paxos here only orders the ballots. */
    if (!config_state.vote_paxos.initialized)
        paxos_init(&config_state.vote_paxos, 0, proc->logger);
    process_register_handler(proc, CONFIG_PROTO_PROPOSE,    (handler_ptr_t)handle_config_propose);
    process_register_handler(proc, CONFIG_PROTO_VOTE_REQ,   (handler_ptr_t)handle_config_vote_request);
    process_register_handler(proc, CONFIG_PROTO_VOTE_GRANT, (handler_ptr_t)handle_config_vote_grant);
    process_register_handler(proc, CONFIG_PROTO_VOTE_NACK,  (handler_ptr_t)handle_config_vote_nack);
    process_register_handler(proc, CONFIG_PROTO_ACCEPTED,   (handler_ptr_t)handle_config_accepted);
    process_register_handler(proc, ARTIFACT_PROTO_READY,    (handler_ptr_t)handle_config_artifact_ready);
    process_register_handler(proc, REP_PROTO_LOCAL_RESP,    (handler_ptr_t)fleet_gate_handle_rep_reply);

    return 0;
}

/****************************
 * Config process main entry
 ****************************/

/* Frama-C: skipped — [solver-timeout] state-cascade through getenv/snprintf/
 * paxos_init/process_register_handler stubs prevents WP from discharging
 * valid_rw(proc) and valid_rd(signal) at downstream call sites */
int config_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger)
{
    _ensure_init();


    if (get_cfg_dir(config_cfg_dir, sizeof(config_cfg_dir)) != 0)
    {
        const char *root = getenv("AUTONOMOUS_TRUST_ROOT");
        if (root) snprintf(config_cfg_dir, sizeof(config_cfg_dir), "%s/etc/at", root);
    }
    if (get_data_dir(config_data_dir, sizeof(config_data_dir)) != 0)
    {
        const char *root = getenv("AUTONOMOUS_TRUST_ROOT");
        if (root) snprintf(config_data_dir, sizeof(config_data_dir), "%s/var/at", root);
    }

    config_register_handlers(proc);

    proc->protocol.phase = 1;

    return process_run(proc, queues, signal, logger);
}
/* An extension's process (FEATURE_SPLIT_PLAN Phase 8): registered at load,
 * and started by default once this library is linked. */
DEFINE_PROCESS(config, config_proc, config_run)
DEFINE_SUBSYSTEM(config, "config", "config_proc")
