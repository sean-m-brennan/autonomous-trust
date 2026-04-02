/********************
 *  Copyright 2025 Sean M. Brennan and contributors
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
#include "fleet/fleet_proc.h"
#include "fleet/update_proposal.h"
#include "fleet/artifact_proc.h"
#include "algorithms/paxos.h"
#include "structures/map.h"
#include "structures/map_priv.h"
#include "structures/array_priv.h"
#include "structures/data_priv.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"
#include "utilities/exception.h"
#include "network/net_message.h"

#define EFLEET_PAXOS 260
DEFINE_ERROR(EFLEET_PAXOS, "Fleet Paxos consensus error");


/****************************
 * Process state (file-scope static, thread-safe via mutex)
 ****************************/

static struct {
    paxos_instance_t vote_paxos;
    map_t pending_proposals;   /* proposal_uuid_str -> update_proposal_t* */
    map_t accepted_updates;    /* proposal_uuid_str -> update_proposal_t* */
    int num_peers;
    pthread_mutex_t lock;
    bool initialized;
} fleet_state;

static void _ensure_init(void)
{
    if (!fleet_state.initialized)
    {
        map_init(&fleet_state.pending_proposals);
        map_init(&fleet_state.accepted_updates);
        /* paxos_init is called in fleet_run after num_peers is known */
        fleet_state.num_peers = 0;
        pthread_mutex_init(&fleet_state.lock, NULL);
        fleet_state.initialized = true;
    }
}

/****************************
 * Handler: handle_update_proposal
 * Receive an update proposal, verify signature, store it, initiate Paxos vote.
 ****************************/

static bool handle_update_proposal(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Fleet: update proposal from %s\n", nmsg->from_whom.fullname);

    /* Unpack proposal JSON from payload */
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Fleet: handle_update_proposal: failed to unpack JSON\n");
        return false;
    }

    /* Deserialize proposal */
    update_proposal_t proposal;
    if (update_proposal_from_json(payload, &proposal) != 0)
    {
        json_decref(payload);
        log_error(proc->logger, "Fleet: handle_update_proposal: invalid proposal JSON\n");
        return false;
    }

    /* Verify signature using sender's public key */
    if (!fleet_validate_proposal(&proposal, nmsg->from_whom.signature.public))
    {
        json_decref(payload);
        log_error(proc->logger, "Fleet: handle_update_proposal: signature verification failed\n");
        return false;
    }

    /* Store proposal in pending map keyed by proposal UUID */
    char prop_uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(proposal.proposal_uuid, prop_uuid_str);

    pthread_mutex_lock(&fleet_state.lock);
    data_t *prop_dat = object_ptr_data(&proposal, sizeof(update_proposal_t));
    map_set(&fleet_state.pending_proposals, prop_uuid_str, prop_dat);
    pthread_mutex_unlock(&fleet_state.lock);

    json_decref(payload);

    /* Initiate Paxos vote: broadcast vote request to all peers */
    double id1, id2;
    paxos_next_ids(&fleet_state.vote_paxos, &id1, &id2);

    json_t *req_json = json_object();
    json_object_set_new(req_json, "id1", json_real(id1));
    json_object_set_new(req_json, "id2", json_real(id2));
    json_object_set_new(req_json, "proposal_uuid", json_string(prop_uuid_str));

    for (size_t i = 0; i < proc->protocol.num_peers; i++)
    {
        generic_msg_t req = {0};
        req.type = NET_MESSAGE;
        strncpy(req.info.net_msg.process, "fleet", PROC_NAME_LEN);
        req.info.net_msg.function = (char *)FLEET_PROTO_VOTE_REQ;
        req.info.net_msg.encrypt = true;
        memcpy(&req.info.net_msg.to_whom, &proc->protocol.peers[i], sizeof(public_identity_t));
        strncpy(req.info.net_msg.return_to, "fleet", PROC_NAME_LEN);
        net_msg_pack_json(&req.info.net_msg, req_json);
        messaging_send("network", NET_MESSAGE, &req, false);
    }
    json_decref(req_json);

    log_info(proc->logger, "Fleet: Proposal %s stored, vote initiated\n", prop_uuid_str);
    return true;
}

/****************************
 * Handler: handle_vote_request
 * Paxos Phase 1a: check proposal via paxos_handle_request, send grant or nack.
 ****************************/

static bool handle_vote_request(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Fleet: vote request from %s\n", nmsg->from_whom.fullname);

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Fleet: handle_vote_request: failed to unpack JSON\n");
        return false;
    }

    json_t *j_id1 = json_object_get(payload, "id1");
    json_t *j_id2 = json_object_get(payload, "id2");
    json_t *j_prop_uuid = json_object_get(payload, "proposal_uuid");

    if (!j_id1 || !j_id2 || !j_prop_uuid)
    {
        json_decref(payload);
        log_error(proc->logger, "Fleet: handle_vote_request: missing JSON fields\n");
        return false;
    }

    double id1 = json_real_value(j_id1);
    double id2 = json_real_value(j_id2);
    const char *prop_uuid_str = json_string_value(j_prop_uuid);

    double out_last_id = 0.0;
    int out_chain_len = 0;
    paxos_response_t result = paxos_handle_request(&fleet_state.vote_paxos, id1, id2,
                                                   &out_last_id, &out_chain_len);

    json_decref(payload);

    if (result == PAXOS_GRANT)
    {
        /* Build grant payload */
        json_t *grant_json = json_object();
        json_object_set_new(grant_json, "id1", json_real(id1));
        json_object_set_new(grant_json, "id2", json_real(id2));
        json_object_set_new(grant_json, "proposal_uuid", json_string(prop_uuid_str));
        json_object_set_new(grant_json, "last_id", json_real(out_last_id));
        json_object_set_new(grant_json, "chain_len", json_integer(out_chain_len));

        generic_msg_t grant = {0};
        grant.type = NET_MESSAGE;
        strncpy(grant.info.net_msg.process, "fleet", PROC_NAME_LEN);
        grant.info.net_msg.function = (char *)FLEET_PROTO_VOTE_GRANT;
        grant.info.net_msg.encrypt = true;
        memcpy(&grant.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
        strncpy(grant.info.net_msg.return_to, "fleet", PROC_NAME_LEN);
        net_msg_pack_json(&grant.info.net_msg, grant_json);
        json_decref(grant_json);

        log_debug(proc->logger, "Fleet: Vote granted\n");
        messaging_send("network", NET_MESSAGE, &grant, false);
    }
    else
    {
        /* NACK */
        json_t *nack_json = json_object();
        json_object_set_new(nack_json, "id1", json_real(id1));
        json_object_set_new(nack_json, "id2", json_real(id2));
        json_object_set_new(nack_json, "proposal_uuid", json_string(prop_uuid_str));

        generic_msg_t nack = {0};
        nack.type = NET_MESSAGE;
        strncpy(nack.info.net_msg.process, "fleet", PROC_NAME_LEN);
        nack.info.net_msg.function = (char *)FLEET_PROTO_VOTE_NACK;
        nack.info.net_msg.encrypt = true;
        memcpy(&nack.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
        strncpy(nack.info.net_msg.return_to, "fleet", PROC_NAME_LEN);
        net_msg_pack_json(&nack.info.net_msg, nack_json);
        json_decref(nack_json);

        log_debug(proc->logger, "Fleet: Vote nacked\n");
        messaging_send("network", NET_MESSAGE, &nack, false);
    }

    return true;
}

/****************************
 * Handler: handle_vote_grant
 * Paxos Phase 1b: count grants; on quorum, broadcast accepted.
 ****************************/

static bool handle_vote_grant(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Fleet: vote grant from %s\n", nmsg->from_whom.fullname);

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Fleet: handle_vote_grant: failed to unpack JSON\n");
        return false;
    }

    json_t *j_id1 = json_object_get(payload, "id1");
    json_t *j_id2 = json_object_get(payload, "id2");
    json_t *j_prop_uuid = json_object_get(payload, "proposal_uuid");

    if (!j_id1 || !j_id2 || !j_prop_uuid)
    {
        json_decref(payload);
        log_error(proc->logger, "Fleet: handle_vote_grant: missing JSON fields\n");
        return false;
    }

    double id1 = json_real_value(j_id1);
    double id2 = json_real_value(j_id2);
    const char *prop_uuid_str = json_string_value(j_prop_uuid);

    /* Record grant with score=1.0 (vote weight) */
    int count = paxos_record_grant(&fleet_state.vote_paxos, id1, id2, 1.0);
    bool quorum = (count >= PAXOS_MAJORITY(fleet_state.num_peers));

    json_decref(payload);

    if (quorum)
    {
        /* Broadcast FLEET_PROTO_ACCEPTED to all peers */
        json_t *acc_json = json_object();
        json_object_set_new(acc_json, "id1", json_real(id1));
        json_object_set_new(acc_json, "id2", json_real(id2));
        json_object_set_new(acc_json, "proposal_uuid", json_string(prop_uuid_str));

        log_info(proc->logger, "Fleet: Quorum reached for proposal %s, broadcasting accepted\n",
                 prop_uuid_str);

        for (size_t i = 0; i < proc->protocol.num_peers; i++)
        {
            generic_msg_t acc_msg = {0};
            acc_msg.type = NET_MESSAGE;
            strncpy(acc_msg.info.net_msg.process, "fleet", PROC_NAME_LEN);
            acc_msg.info.net_msg.function = (char *)FLEET_PROTO_ACCEPTED;
            acc_msg.info.net_msg.encrypt = true;
            memcpy(&acc_msg.info.net_msg.to_whom, &proc->protocol.peers[i], sizeof(public_identity_t));
            strncpy(acc_msg.info.net_msg.return_to, "fleet", PROC_NAME_LEN);
            net_msg_pack_json(&acc_msg.info.net_msg, acc_json);
            messaging_send("network", NET_MESSAGE, &acc_msg, false);
        }
        json_decref(acc_json);

        paxos_advance_chain(&fleet_state.vote_paxos);
    }
    else
    {
        log_debug(proc->logger, "Fleet: Vote grant recorded (%d so far)\n", count);
    }

    return true;
}

/****************************
 * Handler: handle_vote_nack
 * Record nack with exponential backoff.
 ****************************/

static bool handle_vote_nack(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Fleet: vote nack from %s\n", nmsg->from_whom.fullname);

    json_t *payload = NULL;
    double id1 = 0.0, id2 = 0.0;
    if (net_msg_unpack_json(nmsg, &payload) == 0 && payload != NULL)
    {
        json_t *j_id1 = json_object_get(payload, "id1");
        json_t *j_id2 = json_object_get(payload, "id2");
        if (j_id1) id1 = json_real_value(j_id1);
        if (j_id2) id2 = json_real_value(j_id2);
        json_decref(payload);
    }

    int wait_sec = paxos_record_nack(&fleet_state.vote_paxos, id1, id2);

    log_debug(proc->logger, "Fleet: vote nack backoff %d seconds\n", wait_sec);
    (void)wait_sec;

    return true;
}

/****************************
 * Handler: handle_update_accepted
 * Move proposal from pending to accepted.
 ****************************/

static bool handle_update_accepted(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Fleet: update accepted from %s\n", nmsg->from_whom.fullname);

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Fleet: handle_update_accepted: failed to unpack JSON\n");
        return false;
    }

    json_t *j_prop_uuid = json_object_get(payload, "proposal_uuid");
    if (!j_prop_uuid)
    {
        json_decref(payload);
        log_error(proc->logger, "Fleet: handle_update_accepted: missing proposal_uuid\n");
        return false;
    }

    const char *prop_uuid_raw = json_string_value(j_prop_uuid);
    char prop_uuid_str[UUID_STRING_LEN + 2];
    strncpy(prop_uuid_str, prop_uuid_raw, sizeof(prop_uuid_str) - 1);
    prop_uuid_str[sizeof(prop_uuid_str) - 1] = '\0';

    pthread_mutex_lock(&fleet_state.lock);

    /* Look up proposal in pending */
    data_t *prop_dat = NULL;
    if (map_get(&fleet_state.pending_proposals, prop_uuid_str, &prop_dat) == 0 && prop_dat != NULL)
    {
        /* Move to accepted */
        map_set(&fleet_state.accepted_updates, prop_uuid_str, prop_dat);
        map_remove(&fleet_state.pending_proposals, prop_uuid_str);
        log_info(proc->logger, "Fleet: Proposal %s accepted and moved to accepted_updates\n",
                 prop_uuid_str);
    }
    else
    {
        log_debug(proc->logger, "Fleet: Accepted proposal %s not found in pending\n",
                  prop_uuid_str);
    }

    pthread_mutex_unlock(&fleet_state.lock);

    json_decref(payload);

    /* Also notify the main process about the acceptance via UPDATE_ACCEPTED */
    generic_msg_t notify = {0};
    notify.type = UPDATE_ACCEPTED;
    uuid_parse(prop_uuid_str, notify.info.update_accepted.proposal_uuid);
    messaging_send("AutonomousTrust", UPDATE_ACCEPTED, &notify, false);

    /* Trigger artifact download for the accepted proposal */
    pthread_mutex_lock(&fleet_state.lock);
    data_t *accepted_dat = NULL;
    if (map_get(&fleet_state.accepted_updates, prop_uuid_str, &accepted_dat) == 0 && accepted_dat != NULL)
    {
        update_proposal_t *accepted_prop = NULL;
        data_object_ptr(accepted_dat, (ptr_t *)&accepted_prop);
        if (accepted_prop != NULL)
        {
            char artifact_hash_hex[UPDATE_HASH_LEN * 2 + 1];
            sodium_bin2hex(artifact_hash_hex, sizeof(artifact_hash_hex),
                           accepted_prop->artifact_hash, UPDATE_HASH_LEN);

            /* Send artifact request to the peer who sent us the acceptance */
            json_t *fetch_req = json_object();
            json_object_set_new(fetch_req, "hash", json_string(artifact_hash_hex));

            generic_msg_t artifact_msg = {0};
            artifact_msg.type = NET_MESSAGE;
            net_msg_t *anmsg = &artifact_msg.info.net_msg;
            strncpy(anmsg->process, "artifact", PROC_NAME_LEN);
            anmsg->function = (char *)ARTIFACT_PROTO_REQUEST;
            memcpy(&anmsg->to_whom, &nmsg->from_whom, sizeof(public_identity_t));
            anmsg->encrypt = true;
            strncpy(anmsg->return_to, "artifact", PROC_NAME_LEN);

            net_msg_pack_json(anmsg, fetch_req);
            json_decref(fetch_req);
            messaging_send("network", NET_MESSAGE, &artifact_msg, false);

            log_info(proc->logger, "Fleet: triggered artifact fetch for %s\n", artifact_hash_hex);
        }
    }
    pthread_mutex_unlock(&fleet_state.lock);

    return true;
}

/****************************
 * Fleet process main entry
 ****************************/

int fleet_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger)
{
    _ensure_init();

    fleet_state.num_peers = (int)proc->protocol.num_peers;
    paxos_init(&fleet_state.vote_paxos, fleet_state.num_peers, logger);

    /* Register protocol handlers */
    process_register_handler(proc, (char *)FLEET_PROTO_PROPOSE,    (handler_ptr_t)handle_update_proposal);
    process_register_handler(proc, (char *)FLEET_PROTO_VOTE_REQ,   (handler_ptr_t)handle_vote_request);
    process_register_handler(proc, (char *)FLEET_PROTO_VOTE_GRANT, (handler_ptr_t)handle_vote_grant);
    process_register_handler(proc, (char *)FLEET_PROTO_VOTE_NACK,  (handler_ptr_t)handle_vote_nack);
    process_register_handler(proc, (char *)FLEET_PROTO_ACCEPTED,   (handler_ptr_t)handle_update_accepted);

    proc->protocol.phase = 1;

    return process_run(proc, queues, signal, logger);
}
DECLARE_PROCESS(fleet, fleet_proc, fleet_run);
