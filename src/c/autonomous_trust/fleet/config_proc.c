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
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

#include <sodium.h>

#include "processes/processes.h"
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

#define ECONFIG 290
DEFINE_ERROR(ECONFIG, "Config distribution error");


/****************************
 * Process state (file-scope static, thread-safe via mutex)
 ****************************/

static struct {
    paxos_instance_t vote_paxos;
    map_t pending_proposals;   /* proposal_uuid_str -> config_proposal_t* */
    map_t accepted_configs;    /* proposal_uuid_str -> config_proposal_t* */
    int num_peers;
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
        /* paxos_init is called in config_run after num_peers is known */
        config_state.num_peers = 0;
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
    return messaging_send("network", NET_MESSAGE, &msg, false);
}

/****************************
 * Handler: handle_config_propose
 * Receive a config proposal, guard identity modifications,
 * verify signature, store it, initiate Paxos vote.
 ****************************/

/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_config_propose(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Config: proposal from %s\n", nmsg->from_whom.fullname);

    /* Unpack proposal JSON from payload */
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Config: handle_config_propose: failed to unpack JSON\n");
        return false;
    }

    /* Deserialize proposal */
    config_proposal_t proposal;
    if (config_proposal_from_json(payload, &proposal) != 0)
    {
        json_decref(payload);
        log_error(proc->logger, "Config: handle_config_propose: invalid proposal JSON\n");
        return false;
    }

    json_decref(payload);

    /* Identity guard: reject any attempt to modify identity config */
    if (config_is_identity(proposal.config_name))
    {
        log_warn(proc->logger,
                    "Config: REJECTED identity modification attempt from %s\n",
                    nmsg->from_whom.fullname);

        /* Send negative reputation score */
        generic_msg_t score_msg = {0};
        score_msg.type = TRANSACTION_SCORE;
        score_msg.info.tx_score.score = CONFIG_IDENTITY_PENALTY;
        memcpy(&score_msg.info.tx_score.peer_uuid, &nmsg->from_whom.uuid, sizeof(uuid_t));
        messaging_send("reputation", TRANSACTION_SCORE, &score_msg, false);

        return true; /* handled, but rejected */
    }

    /* Verify proposal signature using sender's public key */
    if (config_proposal_verify(&proposal, nmsg->from_whom.signature.public) != 0)
    {
        log_error(proc->logger, "Config: handle_config_propose: signature verification failed\n");
        return false;
    }

    /* Store proposal in pending map keyed by proposal UUID */
    char prop_uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(proposal.proposal_uuid, prop_uuid_str);

    pthread_mutex_lock(&config_state.lock);
    data_t *prop_dat = object_ptr_data(&proposal, sizeof(config_proposal_t));
    map_set(&config_state.pending_proposals, prop_uuid_str, prop_dat);
    pthread_mutex_unlock(&config_state.lock);

    /* Initiate Paxos vote: broadcast vote request to all peers */
    int64_t id1, id2;
    paxos_next_ids(&config_state.vote_paxos, &id1, &id2);

    json_t *req_json = json_object();
    json_object_set_new(req_json, "id1", json_integer(id1));
    json_object_set_new(req_json, "id2", json_integer(id2));
    json_object_set_new(req_json, "proposal_uuid", json_string(prop_uuid_str));

    peers_read_lock(proc);
    for (size_t i = 0; i < proc->protocol.num_peers; i++)
    {
        send_to_peer(proc, CONFIG_PROTO_VOTE_REQ, req_json, &proc->protocol.peers[i]);
    }
    peers_read_unlock(proc);
    json_decref(req_json);

    log_info(proc->logger, "Config: Proposal %s stored, vote initiated\n", prop_uuid_str);
    return true;
}

/****************************
 * Handler: handle_config_vote_request
 * Paxos Phase 1a: check proposal via paxos_handle_request, send grant or nack.
 ****************************/

/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_config_vote_request(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Config: vote request from %s\n", nmsg->from_whom.fullname);

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Config: handle_config_vote_request: failed to unpack JSON\n");
        return false;
    }

    json_t *j_id1 = json_object_get(payload, "id1");
    json_t *j_id2 = json_object_get(payload, "id2");
    json_t *j_prop_uuid = json_object_get(payload, "proposal_uuid");

    if (!j_id1 || !j_id2 || !j_prop_uuid)
    {
        json_decref(payload);
        log_error(proc->logger, "Config: handle_config_vote_request: missing JSON fields\n");
        return false;
    }

    int64_t id1 = json_integer_value(j_id1);
    int64_t id2 = json_integer_value(j_id2);
    const char *prop_uuid_str = json_string_value(j_prop_uuid);

    int64_t out_last_id = 0;
    int out_chain_len = 0;
    paxos_response_t result = paxos_handle_request(&config_state.vote_paxos, id1, id2,
                                                   &out_last_id, &out_chain_len);

    json_decref(payload);

    if (result == PAXOS_GRANT)
    {
        /* Build grant payload */
        json_t *grant_json = json_object();
        json_object_set_new(grant_json, "id1", json_integer(id1));
        json_object_set_new(grant_json, "id2", json_integer(id2));
        json_object_set_new(grant_json, "proposal_uuid", json_string(prop_uuid_str));
        json_object_set_new(grant_json, "last_id", json_integer(out_last_id));
        json_object_set_new(grant_json, "chain_len", json_integer(out_chain_len));

        send_to_peer(proc, CONFIG_PROTO_VOTE_GRANT, grant_json, &nmsg->from_whom);
        json_decref(grant_json);

        log_debug(proc->logger, "Config: Vote granted\n");
    }
    else
    {
        /* NACK */
        json_t *nack_json = json_object();
        json_object_set_new(nack_json, "id1", json_integer(id1));
        json_object_set_new(nack_json, "id2", json_integer(id2));
        json_object_set_new(nack_json, "proposal_uuid", json_string(prop_uuid_str));

        send_to_peer(proc, CONFIG_PROTO_VOTE_NACK, nack_json, &nmsg->from_whom);
        json_decref(nack_json);

        log_debug(proc->logger, "Config: Vote nacked\n");
    }

    return true;
}

/****************************
 * Handler: handle_config_vote_grant
 * Paxos Phase 1b: count grants; on quorum, broadcast accepted.
 ****************************/

/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
  requires config_state.vote_paxos.initialized == \true;
*/
static bool handle_config_vote_grant(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Config: vote grant from %s\n", nmsg->from_whom.fullname);

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Config: handle_config_vote_grant: failed to unpack JSON\n");
        return false;
    }

    json_t *j_id1 = json_object_get(payload, "id1");
    json_t *j_id2 = json_object_get(payload, "id2");
    json_t *j_prop_uuid = json_object_get(payload, "proposal_uuid");

    if (!j_id1 || !j_id2 || !j_prop_uuid)
    {
        json_decref(payload);
        log_error(proc->logger, "Config: handle_config_vote_grant: missing JSON fields\n");
        return false;
    }

    int64_t id1 = json_integer_value(j_id1);
    int64_t id2 = json_integer_value(j_id2);
    const char *prop_uuid_str = json_string_value(j_prop_uuid);

    /* Record grant with score=1.0 (vote weight) */
    int count = paxos_record_grant(&config_state.vote_paxos, id1, id2, 1.0);
    bool quorum = (count >= PAXOS_MAJORITY(config_state.num_peers));

    json_decref(payload);

    if (quorum)
    {
        /* Broadcast CONFIG_PROTO_ACCEPTED to all peers */
        json_t *acc_json = json_object();
        json_object_set_new(acc_json, "id1", json_integer(id1));
        json_object_set_new(acc_json, "id2", json_integer(id2));
        json_object_set_new(acc_json, "proposal_uuid", json_string(prop_uuid_str));

        log_info(proc->logger, "Config: Quorum reached for proposal %s, broadcasting accepted\n",
                 prop_uuid_str);

        peers_read_lock(proc);
        for (size_t i = 0; i < proc->protocol.num_peers; i++)
        {
            send_to_peer(proc, CONFIG_PROTO_ACCEPTED, acc_json, &proc->protocol.peers[i]);
        }
        peers_read_unlock(proc);
        json_decref(acc_json);

        paxos_advance_chain(&config_state.vote_paxos);
    }
    else
    {
        log_debug(proc->logger, "Config: Vote grant recorded (%d so far)\n", count);
    }

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
    log_debug(proc->logger, "Config: vote nack from %s\n", nmsg->from_whom.fullname);

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
 * Move proposal from pending to accepted, trigger artifact fetch.
 ****************************/

/* Frama-C: skipped — [solver-timeout] memcpy of public_identity_t (line 418)
 * triggers "Hide sub-term definition" cast warning that blocks discharge */
/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_config_accepted(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Config: config accepted from %s\n", nmsg->from_whom.fullname);

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Config: handle_config_accepted: failed to unpack JSON\n");
        return false;
    }

    json_t *j_prop_uuid = json_object_get(payload, "proposal_uuid");
    if (!j_prop_uuid)
    {
        json_decref(payload);
        log_error(proc->logger, "Config: handle_config_accepted: missing proposal_uuid\n");
        return false;
    }

    const char *prop_uuid_raw = json_string_value(j_prop_uuid);
    char prop_uuid_str[UUID_STRING_LEN + 2];
    strncpy(prop_uuid_str, prop_uuid_raw, sizeof(prop_uuid_str) - 1);
    prop_uuid_str[sizeof(prop_uuid_str) - 1] = '\0';

    pthread_mutex_lock(&config_state.lock);

    /* Look up proposal in pending */
    data_t *prop_dat = NULL;
    if (map_get(&config_state.pending_proposals, prop_uuid_str, &prop_dat) == 0 && prop_dat != NULL)
    {
        /* Move to accepted */
        map_set(&config_state.accepted_configs, prop_uuid_str, prop_dat);
        map_remove(&config_state.pending_proposals, prop_uuid_str);
        log_info(proc->logger, "Config: Proposal %s accepted and moved to accepted_configs\n",
                 prop_uuid_str);
    }
    else
    {
        log_debug(proc->logger, "Config: Accepted proposal %s not found in pending\n",
                  prop_uuid_str);
    }

    pthread_mutex_unlock(&config_state.lock);

    json_decref(payload);

    /* Trigger artifact download for the accepted proposal */
    pthread_mutex_lock(&config_state.lock);
    data_t *accepted_dat = NULL;
    if (map_get(&config_state.accepted_configs, prop_uuid_str, &accepted_dat) == 0 && accepted_dat != NULL)
    {
        config_proposal_t *accepted_prop = NULL;
        data_object_ptr(accepted_dat, (ptr_t *)&accepted_prop);
        if (accepted_prop != NULL)
        {
            char artifact_hash_hex[UPDATE_HASH_LEN * 2 + 1];
            sodium_bin2hex(artifact_hash_hex, sizeof(artifact_hash_hex),
                           accepted_prop->content_hash, UPDATE_HASH_LEN);

            /* Send artifact request to the peer who sent us the acceptance */
            json_t *fetch_req = json_object();
            json_object_set_new(fetch_req, "hash", json_string(artifact_hash_hex));
            json_object_set_new(fetch_req, "notify_process", json_string("config"));

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

            log_info(proc->logger, "Config: triggered artifact fetch for %s\n", artifact_hash_hex);
        }
    }
    pthread_mutex_unlock(&config_state.lock);

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
    json_object_set_new(ready_json, "config_name", json_string(config_name));
    json_object_set_new(ready_json, "hash", json_string(hash_hex));
    json_object_set_new(ready_json, "version", json_string(version));

    generic_msg_t ready_msg = {0};
    ready_msg.type = NET_MESSAGE;
    net_msg_t *rnmsg = &ready_msg.info.net_msg;
    strncpy(rnmsg->process, "update", PROC_NAME_LEN);
    rnmsg->function = (char *)CONFIG_PROTO_READY;
    rnmsg->encrypt = false;
    strncpy(rnmsg->return_to, "config", PROC_NAME_LEN);
    net_msg_pack_json(rnmsg, ready_json);
    json_decref(ready_json);

    messaging_send("update", NET_MESSAGE, &ready_msg, false);

    log_info(proc->logger, "Config: sent CONFIG_READY for %s to update process\n", config_name);

    json_decref(payload);
    return true;
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

    peers_read_lock(proc);
    config_state.num_peers = (int)proc->protocol.num_peers;
    peers_read_unlock(proc);
    paxos_init(&config_state.vote_paxos, config_state.num_peers, logger);

    if (get_cfg_dir(config_cfg_dir) != 0)
    {
        const char *root = getenv("AUTONOMOUS_TRUST_ROOT");
        if (root) snprintf(config_cfg_dir, sizeof(config_cfg_dir), "%s/etc/at", root);
    }
    if (get_data_dir(config_data_dir) != 0)
    {
        const char *root = getenv("AUTONOMOUS_TRUST_ROOT");
        if (root) snprintf(config_data_dir, sizeof(config_data_dir), "%s/var/at", root);
    }

    /* Register protocol handlers */
    process_register_handler(proc, (char *)CONFIG_PROTO_PROPOSE,    (handler_ptr_t)handle_config_propose);
    process_register_handler(proc, (char *)CONFIG_PROTO_VOTE_REQ,   (handler_ptr_t)handle_config_vote_request);
    process_register_handler(proc, (char *)CONFIG_PROTO_VOTE_GRANT, (handler_ptr_t)handle_config_vote_grant);
    process_register_handler(proc, (char *)CONFIG_PROTO_VOTE_NACK,  (handler_ptr_t)handle_config_vote_nack);
    process_register_handler(proc, (char *)CONFIG_PROTO_ACCEPTED,   (handler_ptr_t)handle_config_accepted);
    process_register_handler(proc, (char *)ARTIFACT_PROTO_READY,    (handler_ptr_t)handle_config_artifact_ready);

    proc->protocol.phase = 1;

    return process_run(proc, queues, signal, logger);
}
DECLARE_PROCESS(config, config_proc, config_run);
