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
#include <math.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>

#include "processes/processes.h"
#include "reputation/reputation.h"
#include "algorithms/paxos.h"
#include "structures/map.h"
#include "structures/map_priv.h"
#include "structures/array_priv.h"
#include "structures/data_priv.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"
#include "utilities/exception.h"
#include "network/net_message.h"

#define EREP_PAXOS 253
DEFINE_ERROR(EREP_PAXOS, "Paxos consensus error");

/****************************
 * Process state (file-scope static, thread-safe via mutex)
 ****************************/

#define STALE_TIMEOUT    300  /* seconds */

static struct {
    tx_history_t history;
    reputations_t reputations;
    map_t my_requests;     /* uuid_str -> tx_score_t* (pending Paxos requests) */
    map_t updates;         /* uuid_str -> json_t* (pending chain updates) */
    array_t requested_reps; /* array of pending reputation responses */
    paxos_instance_t paxos;
    int num_peers;
    pthread_mutex_t lock;
    bool initialized;
} rep_state;

static void _ensure_init(void)
{
    if (!rep_state.initialized)
    {
        tx_history_init(&rep_state.history);
        reputations_init(&rep_state.reputations);
        map_init(&rep_state.my_requests);
        map_init(&rep_state.updates);
        array_init(&rep_state.requested_reps);
        /* paxos_init is called in reputation_run after num_peers is known */
        rep_state.num_peers = 0;
        pthread_mutex_init(&rep_state.lock, NULL);
        rep_state.initialized = true;
    }
}

/****************************
 * Handler: handle_request (ask permission) — Paxos Phase 1a
 * Validate peer, check id1 > last_id AND chain index matches → grant/nack/backdate
 ****************************/

static bool handle_request(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Reputation: permission request from %s\n", nmsg->from_whom.fullname);

    /* Unpack (id1, id2, peer_uuid) from JSON payload */
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Reputation: handle_request: failed to unpack JSON\n");
        return false;
    }

    json_t *j_id1     = json_object_get(payload, "id1");
    json_t *j_id2     = json_object_get(payload, "id2");
    json_t *j_peer_uuid = json_object_get(payload, "peer_uuid");

    if (!j_id1 || !j_id2 || !j_peer_uuid)
    {
        json_decref(payload);
        log_error(proc->logger, "Reputation: handle_request: missing JSON fields\n");
        return false;
    }

    int64_t id1 = json_integer_value(j_id1);
    int64_t id2 = json_integer_value(j_id2);
    const char *peer_uuid_str = json_string_value(j_peer_uuid);

    int64_t out_last_id = 0;
    int out_chain_len = 0;
    paxos_response_t result = paxos_handle_request(&rep_state.paxos, id1, id2,
                                                   &out_last_id, &out_chain_len);

    json_decref(payload);

    if (result == PAXOS_GRANT)
    {
        /* Build grant payload: (id1, id2, peer_uuid, last_id, chain_len) */
        json_t *grant_json = json_object();
        json_object_set_new(grant_json, "id1", json_integer(id1));
        json_object_set_new(grant_json, "id2", json_integer(id2));
        json_object_set_new(grant_json, "peer_uuid", json_string(peer_uuid_str));
        json_object_set_new(grant_json, "last_id", json_integer(out_last_id));
        json_object_set_new(grant_json, "chain_len", json_integer(out_chain_len));

        generic_msg_t grant = {0};
        grant.type = NET_MESSAGE;
        strncpy(grant.info.net_msg.process, "reputation", PROC_NAME_LEN);
        grant.info.net_msg.function = (char *)REP_PROTO_GRANT;
        grant.info.net_msg.encrypt = true;
        memcpy(&grant.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
        strncpy(grant.info.net_msg.return_to, "reputation", PROC_NAME_LEN);
        net_msg_pack_json(&grant.info.net_msg, grant_json);
        json_decref(grant_json);

        log_debug(proc->logger, "Reputation: Request granted\n");
        messaging_send("network", NET_MESSAGE, &grant, false);
    }
    else if (result == PAXOS_BACKDATE)
    {
        /* BACKDATE: chain index mismatch */
        json_t *bd_json = json_object();
        json_object_set_new(bd_json, "id1", json_integer(id1));
        json_object_set_new(bd_json, "id2", json_integer(id2));

        generic_msg_t backdate = {0};
        backdate.type = NET_MESSAGE;
        strncpy(backdate.info.net_msg.process, "reputation", PROC_NAME_LEN);
        backdate.info.net_msg.function = (char *)REP_PROTO_BACKDATE;
        backdate.info.net_msg.encrypt = true;
        memcpy(&backdate.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
        strncpy(backdate.info.net_msg.return_to, "reputation", PROC_NAME_LEN);
        net_msg_pack_json(&backdate.info.net_msg, bd_json);
        json_decref(bd_json);

        log_debug(proc->logger, "Reputation: Request backdated\n");
        messaging_send("network", NET_MESSAGE, &backdate, false);
    }
    else
    {
        /* NACK: id1 <= last_id */
        json_t *nack_json = json_object();
        json_object_set_new(nack_json, "id1", json_integer(id1));
        json_object_set_new(nack_json, "id2", json_integer(id2));

        generic_msg_t nack = {0};
        nack.type = NET_MESSAGE;
        strncpy(nack.info.net_msg.process, "reputation", PROC_NAME_LEN);
        nack.info.net_msg.function = (char *)REP_PROTO_NACK;
        nack.info.net_msg.encrypt = true;
        memcpy(&nack.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
        strncpy(nack.info.net_msg.return_to, "reputation", PROC_NAME_LEN);
        net_msg_pack_json(&nack.info.net_msg, nack_json);
        json_decref(nack_json);

        log_debug(proc->logger, "Reputation: Request refused\n");
        messaging_send("network", NET_MESSAGE, &nack, false);
    }

    return true;
}

/****************************
 * Handler: handle_grant (permission granted) — Paxos Phase 1b
 * Count grants; on majority, broadcast REP_PROTO_TX
 ****************************/

static bool handle_grant(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Reputation: grant from %s\n", nmsg->from_whom.fullname);

    /* Unpack (id1, id2, peer_uuid, last_id, chain_len) */
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Reputation: handle_grant: failed to unpack JSON\n");
        return false;
    }

    json_t *j_id1      = json_object_get(payload, "id1");
    json_t *j_id2      = json_object_get(payload, "id2");
    json_t *j_peer_uuid = json_object_get(payload, "peer_uuid");

    if (!j_id1 || !j_id2 || !j_peer_uuid)
    {
        json_decref(payload);
        log_error(proc->logger, "Reputation: handle_grant: missing JSON fields\n");
        return false;
    }

    int64_t id1 = json_integer_value(j_id1);
    int64_t id2 = json_integer_value(j_id2);
    const char *peer_uuid_str = json_string_value(j_peer_uuid);

    pthread_mutex_lock(&rep_state.lock);

    /* Look up this request in my_requests (keyed by peer_uuid) */
    char peer_uuid_key[UUID_STRING_LEN + 2];
    strncpy(peer_uuid_key, peer_uuid_str, sizeof(peer_uuid_key) - 1);
    peer_uuid_key[sizeof(peer_uuid_key) - 1] = '\0';
    data_t *tx_dat = NULL;
    if (map_get(&rep_state.my_requests, peer_uuid_key, &tx_dat) != 0)
    {
        /* Grant not for one of our requests */
        pthread_mutex_unlock(&rep_state.lock);
        json_decref(payload);
        log_debug(proc->logger, "Reputation: Grant for already-completed or unknown request\n");
        return true;
    }

    tx_score_t *tx = NULL;
    data_object_ptr(tx_dat, (void **)&tx);
    double tx_score = (tx != NULL) ? tx->score : 0.0;

    int count = paxos_record_grant(&rep_state.paxos, id1, id2, tx_score);
    bool send_tx = (count >= PAXOS_MAJORITY(rep_state.num_peers));

    /* Capture task_uuid before potential removal */
    char task_uuid_str[UUID_STRING_LEN + 1] = {0};
    if (send_tx && tx != NULL)
        uuid_unparse_lower(tx->task_uuid, task_uuid_str);

    if (send_tx)
    {
        /* Remove from my_requests */
        map_remove(&rep_state.my_requests, peer_uuid_key);
    }

    pthread_mutex_unlock(&rep_state.lock);

    if (send_tx)
    {
        /* Broadcast REP_PROTO_TX to all peers */
        json_t *tx_json = json_object();
        json_object_set_new(tx_json, "id1", json_integer(id1));
        json_object_set_new(tx_json, "id2", json_integer(id2));
        json_object_set_new(tx_json, "peer_uuid", json_string(peer_uuid_str));
        json_object_set_new(tx_json, "score", json_real(tx_score));
        if (task_uuid_str[0] != '\0')
            json_object_set_new(tx_json, "task_uuid", json_string(task_uuid_str));

        log_debug(proc->logger, "Reputation: Submit transaction score\n");

        for (size_t i = 0; i < proc->protocol.num_peers; i++)
        {
            generic_msg_t tx_msg = {0};
            tx_msg.type = NET_MESSAGE;
            strncpy(tx_msg.info.net_msg.process, "reputation", PROC_NAME_LEN);
            tx_msg.info.net_msg.function = (char *)REP_PROTO_TX;
            tx_msg.info.net_msg.encrypt = true;
            memcpy(&tx_msg.info.net_msg.to_whom, &proc->protocol.peers[i], sizeof(public_identity_t));
            strncpy(tx_msg.info.net_msg.return_to, "reputation", PROC_NAME_LEN);
            net_msg_pack_json(&tx_msg.info.net_msg, tx_json);
            messaging_send("network", NET_MESSAGE, &tx_msg, false);
        }
        json_decref(tx_json);
    }

    json_decref(payload);
    return true;
}

/****************************
 * Handler: handle_nack (try again) — exponential backoff retry
 ****************************/

static bool handle_nack(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Reputation: nack from %s\n", nmsg->from_whom.fullname);

    /* Unpack (id1, id2) from payload for retry capability */
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

    int wait_sec = paxos_record_nack(&rep_state.paxos, id1, id2);

    log_debug(proc->logger, "Reputation: nack backoff %d seconds\n", wait_sec);
    (void)wait_sec;

    return true;
}

/****************************
 * Handler: handle_backdate (out of date)
 * Remote peer tells us our chain index is behind; request update.
 ****************************/

static bool handle_backdate(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Reputation: backdate notification from %s\n", nmsg->from_whom.fullname);

    /* Request chain update from this peer */
    generic_msg_t update_req = {0};
    update_req.type = NET_MESSAGE;
    strncpy(update_req.info.net_msg.process, "reputation", PROC_NAME_LEN);
    update_req.info.net_msg.function = (char *)REP_PROTO_OUTDATED;
    update_req.info.net_msg.encrypt = true;
    memcpy(&update_req.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
    strncpy(update_req.info.net_msg.return_to, "reputation", PROC_NAME_LEN);

    messaging_send("network", NET_MESSAGE, &update_req, false);
    return true;
}

/****************************
 * Handler: handle_transaction (transaction) — Paxos Phase 2a
 * Validate that we granted this proposal, then send accepted.
 ****************************/

static bool handle_transaction(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Reputation: transaction from %s\n", nmsg->from_whom.fullname);

    /* Unpack (id1, id2, peer_uuid, score) */
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Reputation: handle_transaction: failed to unpack JSON\n");
        return false;
    }

    json_t *j_id1      = json_object_get(payload, "id1");
    json_t *j_id2      = json_object_get(payload, "id2");
    json_t *j_peer_uuid = json_object_get(payload, "peer_uuid");
    json_t *j_score    = json_object_get(payload, "score");

    if (!j_id1 || !j_id2 || !j_peer_uuid || !j_score)
    {
        json_decref(payload);
        log_error(proc->logger, "Reputation: handle_transaction: missing JSON fields\n");
        return false;
    }

    int64_t id2 = json_integer_value(j_id2);
    int64_t id1 = json_integer_value(j_id1);
    double score = json_real_value(j_score);
    const char *peer_uuid_str = json_string_value(j_peer_uuid);
    const char *task_uuid_str = json_string_value(json_object_get(payload, "task_uuid"));

    if (!paxos_has_granted_id(&rep_state.paxos, (int)id2))
    {
        json_decref(payload);
        log_debug(proc->logger, "Reputation: Transaction not granted by us, dropping\n");
        return true;
    }

    /* Record the grant (score) in the paxos proposals for later acceptance tracking */
    paxos_record_grant(&rep_state.paxos, id1, id2, score);
    json_decref(payload);

    /* Send ACCEPTED back */
    json_t *acc_json = json_object();
    json_object_set_new(acc_json, "id1", json_integer(id1));
    json_object_set_new(acc_json, "id2", json_integer(id2));
    json_object_set_new(acc_json, "peer_uuid", json_string(peer_uuid_str));
    if (task_uuid_str)
        json_object_set_new(acc_json, "task_uuid", json_string(task_uuid_str));

    generic_msg_t accepted = {0};
    accepted.type = NET_MESSAGE;
    strncpy(accepted.info.net_msg.process, "reputation", PROC_NAME_LEN);
    accepted.info.net_msg.function = (char *)REP_PROTO_ACCEPTED;
    accepted.info.net_msg.encrypt = true;
    memcpy(&accepted.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
    strncpy(accepted.info.net_msg.return_to, "reputation", PROC_NAME_LEN);
    net_msg_pack_json(&accepted.info.net_msg, acc_json);
    json_decref(acc_json);

    messaging_send("network", NET_MESSAGE, &accepted, false);
    return true;
}

/****************************
 * Handler: handle_accepted (tx accepted) — Paxos Phase 2b
 * Count acceptances; commit to history on majority.
 ****************************/

static bool handle_accepted(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Reputation: tx accepted by %s\n", nmsg->from_whom.fullname);

    /* Unpack (id1, id2, peer_uuid) */
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Reputation: handle_accepted: failed to unpack JSON\n");
        return false;
    }

    json_t *j_id1      = json_object_get(payload, "id1");
    json_t *j_id2      = json_object_get(payload, "id2");
    json_t *j_peer_uuid = json_object_get(payload, "peer_uuid");

    if (!j_id1 || !j_id2 || !j_peer_uuid)
    {
        json_decref(payload);
        log_error(proc->logger, "Reputation: handle_accepted: missing JSON fields\n");
        return false;
    }

    int64_t id1 = json_integer_value(j_id1);
    int64_t id2 = json_integer_value(j_id2);
    const char *peer_uuid_str = json_string_value(j_peer_uuid);

    /* Look up score from paxos proposals */
    char paxos_key[PAXOS_KEY_LEN];
    paxos_id_index(paxos_key, sizeof(paxos_key), id1, id2);

    pthread_mutex_lock(&rep_state.paxos.lock);
    data_t *prop_dat = NULL;
    double score = 0.0;
    if (map_get(&rep_state.paxos.proposals, paxos_key, &prop_dat) == 0)
    {
        paxos_proposal_t *ptc = NULL;
        data_object_ptr(prop_dat, (void **)&ptc);
        if (ptc != NULL) score = ptc->score;
    }
    pthread_mutex_unlock(&rep_state.paxos.lock);

    int acc_count = paxos_record_acceptance(&rep_state.paxos, id1, id2);
    bool commit = (acc_count >= PAXOS_MAJORITY(rep_state.num_peers));

    if (commit)
    {
        /* Parse UUIDs and commit to history */
        uuid_t peer_uuid;
        uuid_t task_uuid;
        uuid_parse(peer_uuid_str, peer_uuid);

        const char *task_uuid_str = json_string_value(json_object_get(payload, "task_uuid"));
        if (task_uuid_str && uuid_parse(task_uuid_str, task_uuid) == 0)
        {
            tx_history_update(&rep_state.history, task_uuid, peer_uuid, score);
        }
        else
        {
            tx_history_update(&rep_state.history, peer_uuid, peer_uuid, score);
        }
        paxos_advance_chain(&rep_state.paxos);
        log_info(proc->logger, "Reputation: Transaction committed\n");
    }
    else
    {
        log_debug(proc->logger, "Reputation: Tx accepted (%d so far)\n", acc_count);
    }

    json_decref(payload);
    return true;
}

/****************************
 * Handler: handle_outdated (update needed)
 * Send chain slice to requesting peer.
 ****************************/

static bool handle_outdated(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Reputation: update requested by %s\n", nmsg->from_whom.fullname);

    pthread_mutex_lock(&rep_state.lock);

    json_t *era_json = NULL;
    int chain_len = tx_history_len(&rep_state.history);
    tx_history_era_to_json(&rep_state.history, 0, chain_len, &era_json);

    pthread_mutex_unlock(&rep_state.lock);

    /* Send update with the era JSON packed into the message */
    generic_msg_t update = {0};
    update.type = NET_MESSAGE;
    strncpy(update.info.net_msg.process, "reputation", PROC_NAME_LEN);
    update.info.net_msg.function = (char *)REP_PROTO_UPDATE;
    update.info.net_msg.encrypt = true;
    memcpy(&update.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
    strncpy(update.info.net_msg.return_to, "reputation", PROC_NAME_LEN);

    if (era_json != NULL)
    {
        net_msg_pack_json(&update.info.net_msg, era_json);
        json_decref(era_json);
    }

    log_debug(proc->logger, "Reputation: Sent update\n");
    messaging_send("network", NET_MESSAGE, &update, false);
    return true;
}

/****************************
 * Handler: handle_update (latest update)
 * Collect chain slices, vote on consistency, merge.
 ****************************/

static bool handle_update(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Reputation: chain update from %s\n", nmsg->from_whom.fullname);

    /* Unpack chain JSON from payload */
    json_t *chain_json = NULL;
    if (net_msg_unpack_json(nmsg, &chain_json) != 0 || chain_json == NULL)
    {
        log_error(proc->logger, "Reputation: handle_update: failed to unpack JSON\n");
        return false;
    }

    /* Key by sender UUID */
    char sender_uuid[UUID_STRING_LEN + 1];
    uuid_unparse_lower(nmsg->from_whom.uuid, sender_uuid);

    pthread_mutex_lock(&rep_state.lock);

    /* Store in rep_state.updates keyed by sender UUID */
    data_t *chain_dat = object_ptr_data(chain_json, sizeof(json_t));
    map_set(&rep_state.updates, sender_uuid, chain_dat);

    size_t up_count = map_size(&rep_state.updates);

    if (up_count >= 3)
    {
        /* Group identical updates: find majority by comparing JSON dumps */
        /* Build parallel arrays of keys and serialized strings */
        array_t *keys = map_keys(&rep_state.updates);
        size_t nkeys = array_size(keys);

        /* Allocate string representations */
        char **strs = calloc(nkeys, sizeof(char *));
        json_t **jsons = calloc(nkeys, sizeof(json_t *));
        if (strs != NULL && jsons != NULL)
        {
            for (size_t ki = 0; ki < nkeys; ki++)
            {
                data_t *kdat = NULL;
                if (array_get(keys, (int)ki, &kdat) != 0) continue;
                char *kstr = NULL;
                if (data_string_ptr(kdat, &kstr) != 0 || kstr == NULL) continue;
                data_t *vdat = NULL;
                if (map_get(&rep_state.updates, kstr, &vdat) != 0) continue;
                void *jptr = NULL;
                if (data_object_ptr(vdat, &jptr) != 0 || jptr == NULL) continue;
                jsons[ki] = (json_t *)jptr;
                strs[ki] = json_dumps(jsons[ki], JSON_COMPACT);
            }

            /* Find best candidate */
            char *best_str = NULL;
            json_t *best_json = NULL;
            int best_count = 0;

            for (size_t oi = 0; oi < nkeys; oi++)
            {
                if (strs[oi] == NULL) continue;
                int count = 0;
                for (size_t ci = 0; ci < nkeys; ci++)
                {
                    if (strs[ci] != NULL && strcmp(strs[oi], strs[ci]) == 0)
                        count++;
                }
                if (count > best_count)
                {
                    best_count = count;
                    best_str = strs[oi];
                    best_json = jsons[oi];
                }
            }

            if (best_json != NULL && best_count > (int)(up_count / 2))
            {
                tx_history_era_from_json(&rep_state.history, best_json);
                log_debug(proc->logger, "Reputation: Updated\n");
            }
            else
            {
                log_error(proc->logger,
                          "Reputation: Closest %zu peers unable to agree on history\n",
                          up_count);
            }

            /* Free all string dumps */
            for (size_t fi = 0; fi < nkeys; fi++)
            {
                if (strs[fi] != NULL && strs[fi] != best_str)
                    free(strs[fi]);
            }
            if (best_str != NULL)
                free(best_str);
        }
        if (strs != NULL) free(strs);
        if (jsons != NULL) free(jsons);
    }

    pthread_mutex_unlock(&rep_state.lock);
    return true;
}

/****************************
 * Handler: handle_rep_request (reputation request)
 * Compute reputation for a peer and respond.
 ****************************/

static bool handle_rep_request(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Reputation: rep request from %s\n", nmsg->from_whom.fullname);

    /* Unpack (peer_uuid, requesting_process) */
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Reputation: handle_rep_request: failed to unpack JSON\n");
        return false;
    }

    json_t *j_peer_uuid  = json_object_get(payload, "peer_uuid");
    json_t *j_req_proc   = json_object_get(payload, "requesting_process");

    if (!j_peer_uuid || !j_req_proc)
    {
        json_decref(payload);
        log_error(proc->logger, "Reputation: handle_rep_request: missing JSON fields\n");
        return false;
    }

    const char *peer_uuid_str = json_string_value(j_peer_uuid);
    const char *req_proc_str  = json_string_value(j_req_proc);

    /* Parse UUID and compute reputation */
    uuid_t peer_uuid;
    double score = 0.0;
    if (uuid_parse(peer_uuid_str, peer_uuid) == 0)
    {
        pthread_mutex_lock(&rep_state.lock);
        /* Use a dummy self uuid (zero) for now — process doesn't carry self identity */
        uuid_t self_uuid;
        uuid_clear(self_uuid);
        score = reputation_compute(&rep_state.history, &rep_state.reputations,
                                   self_uuid, peer_uuid);
        reputations_update(&rep_state.reputations, peer_uuid, score);
        pthread_mutex_unlock(&rep_state.lock);
    }

    /* Pack response (peer_uuid, score, requesting_process) */
    json_t *resp_json = json_object();
    json_object_set_new(resp_json, "peer_uuid", json_string(peer_uuid_str));
    json_object_set_new(resp_json, "score", json_real(score));
    json_object_set_new(resp_json, "requesting_process", json_string(req_proc_str));

    json_decref(payload);

    generic_msg_t resp = {0};
    resp.type = NET_MESSAGE;
    strncpy(resp.info.net_msg.process, "reputation", PROC_NAME_LEN);
    resp.info.net_msg.function = (char *)REP_PROTO_REP_RESP;
    resp.info.net_msg.encrypt = true;
    memcpy(&resp.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
    strncpy(resp.info.net_msg.return_to, "reputation", PROC_NAME_LEN);
    net_msg_pack_json(&resp.info.net_msg, resp_json);
    json_decref(resp_json);

    messaging_send("network", NET_MESSAGE, &resp, false);
    return true;
}

/****************************
 * Handler: handle_rep_response (reputation response)
 ****************************/

static bool handle_rep_response(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Reputation: rep response from %s\n", nmsg->from_whom.fullname);

    /* Unpack and store in requested_reps array */
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Reputation: handle_rep_response: failed to unpack JSON\n");
        return false;
    }

    /* Store the JSON payload in requested_reps for later processing */
    data_t *resp_dat = object_ptr_data(payload, sizeof(json_t));
    pthread_mutex_lock(&rep_state.lock);
    array_append(&rep_state.requested_reps, resp_dat);
    pthread_mutex_unlock(&rep_state.lock);

    return true;
}

/****************************
 * Handler: handle_local_rep_query (local IPC reputation query)
 * Another local process (e.g. ZTA) asks for a peer's reputation score.
 * Responds via local IPC to the requesting process.
 ****************************/

static bool handle_local_rep_query(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Reputation: handle_local_rep_query: failed to unpack JSON\n");
        return false;
    }

    json_t *j_peer_uuid  = json_object_get(payload, "peer_uuid");
    json_t *j_return_proc = json_object_get(payload, "return_process");

    if (!j_peer_uuid || !j_return_proc)
    {
        json_decref(payload);
        log_error(proc->logger, "Reputation: handle_local_rep_query: missing JSON fields\n");
        return false;
    }

    const char *peer_uuid_str = json_string_value(j_peer_uuid);
    const char *return_proc   = json_string_value(j_return_proc);

    uuid_t peer_uuid;
    double score = 0.0;
    bool found = false;
    if (uuid_parse(peer_uuid_str, peer_uuid) == 0)
    {
        pthread_mutex_lock(&rep_state.lock);
        if (reputations_contains(&rep_state.reputations, peer_uuid))
        {
            reputations_get(&rep_state.reputations, peer_uuid, &score);
            found = true;
        }
        pthread_mutex_unlock(&rep_state.lock);
    }

    /* Build response */
    json_t *resp_json = json_object();
    json_object_set_new(resp_json, "peer_uuid", json_string(peer_uuid_str));
    json_object_set_new(resp_json, "score", json_real(score));
    json_object_set_new(resp_json, "found", json_boolean(found));

    json_decref(payload);

    generic_msg_t resp = {0};
    resp.type = NET_MESSAGE;
    strncpy(resp.info.net_msg.process, return_proc, PROC_NAME_LEN);
    resp.info.net_msg.function = (char *)REP_PROTO_LOCAL_RESP;
    net_msg_pack_json(&resp.info.net_msg, resp_json);
    json_decref(resp_json);

    messaging_send(return_proc, NET_MESSAGE, &resp, false);
    return true;
}

/****************************
 * Forward transaction: start Paxos for a local score
 * Called when TRANSACTION_SCORE message arrives from negotiation.
 ****************************/

void _forward_transaction(const process_t *proc, const uuid_t task_uuid,
                          const uuid_t peer_uuid, double score)
{
    char task_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(task_uuid, task_str);
    log_info(proc->logger, "Reputation: forwarding transaction for task %s, score %.2f\n",
             task_str, score);

    pthread_mutex_lock(&rep_state.lock);

    /* Store in my_requests */
    tx_score_t *tx = smrt_create(sizeof(tx_score_t));
    if (tx != NULL)
    {
        uuid_copy(tx->task_uuid, task_uuid);
        tx->score = score;
        data_t *tx_dat = object_ptr_data(tx, sizeof(tx_score_t));
        map_set(&rep_state.my_requests, task_str, tx_dat);
    }

    pthread_mutex_unlock(&rep_state.lock);

    /* Compute Paxos IDs via shared engine */
    int64_t id1, id2;
    paxos_next_ids(&rep_state.paxos, &id1, &id2);

    /* Get identity UUID for the request */
    char identity_uuid[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer_uuid, identity_uuid);

    /* Broadcast Paxos Phase 1a: request permission from all peers */
    for (size_t i = 0; i < proc->protocol.num_peers; i++)
    {
        generic_msg_t req = {0};
        req.type = NET_MESSAGE;
        strncpy(req.info.net_msg.process, "reputation", PROC_NAME_LEN);
        req.info.net_msg.function = (char *)REP_PROTO_REQUEST;
        req.info.net_msg.encrypt = true;
        memcpy(&req.info.net_msg.to_whom, &proc->protocol.peers[i], sizeof(public_identity_t));
        strncpy(req.info.net_msg.return_to, "reputation", PROC_NAME_LEN);

        /* Pack (id1, id2, identity_uuid) as JSON into the request */
        json_t *req_json = json_object();
        json_object_set_new(req_json, "id1", json_integer(id1));
        json_object_set_new(req_json, "id2", json_integer(id2));
        json_object_set_new(req_json, "peer_uuid", json_string(identity_uuid));
        net_msg_pack_json(&req.info.net_msg, req_json);
        json_decref(req_json);

        messaging_send("network", NET_MESSAGE, &req, false);
    }

}

/****************************
 * Reputation process main entry
 ****************************/

int reputation_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger)
{
    _ensure_init();

    rep_state.num_peers = (int)proc->protocol.num_peers;
    paxos_init(&rep_state.paxos, rep_state.num_peers, logger);

    /* Register protocol handlers */
    process_register_handler(proc, (char *)REP_PROTO_REQUEST,   (handler_ptr_t)handle_request);
    process_register_handler(proc, (char *)REP_PROTO_GRANT,     (handler_ptr_t)handle_grant);
    process_register_handler(proc, (char *)REP_PROTO_NACK,      (handler_ptr_t)handle_nack);
    process_register_handler(proc, (char *)REP_PROTO_BACKDATE,  (handler_ptr_t)handle_backdate);
    process_register_handler(proc, (char *)REP_PROTO_TX,        (handler_ptr_t)handle_transaction);
    process_register_handler(proc, (char *)REP_PROTO_ACCEPTED,  (handler_ptr_t)handle_accepted);
    process_register_handler(proc, (char *)REP_PROTO_OUTDATED,  (handler_ptr_t)handle_outdated);
    process_register_handler(proc, (char *)REP_PROTO_UPDATE,    (handler_ptr_t)handle_update);
    process_register_handler(proc, (char *)REP_PROTO_REP_REQ,   (handler_ptr_t)handle_rep_request);
    process_register_handler(proc, (char *)REP_PROTO_REP_RESP,  (handler_ptr_t)handle_rep_response);
    process_register_handler(proc, (char *)REP_PROTO_LOCAL_QUERY, (handler_ptr_t)handle_local_rep_query);

    proc->protocol.phase = 1;

    return process_run(proc, queues, signal, logger);
}
DECLARE_PROCESS(reputation, rep_proc, reputation_run);
