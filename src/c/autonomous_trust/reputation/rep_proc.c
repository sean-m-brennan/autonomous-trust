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

#define BACKOFF_MULT     1.5
#define BACKOFF_MAX_SEC  90
#define STALE_TIMEOUT    300  /* seconds */
#define MAJORITY(n)      (((n) / 2) + 1)

typedef struct {
    double score;
    int grant_count;
} paxos_tx_count_t;

static struct {
    tx_history_t history;
    reputations_t reputations;
    map_t my_requests;     /* uuid_str -> tx_score_t* (pending Paxos requests) */
    map_t proposals;       /* uuid_str -> paxos_tx_count_t* */
    map_t acceptances;     /* uuid_str -> int (acceptance count) */
    map_t backoff;         /* uuid_str -> time_t (next retry time) */
    map_t updates;         /* uuid_str -> json_t* (pending chain updates) */
    array_t requests;      /* array of incoming reputation request UUIDs */
    array_t requested_reps; /* array of pending reputation responses */
    double last_id;
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
        map_init(&rep_state.proposals);
        map_init(&rep_state.acceptances);
        map_init(&rep_state.backoff);
        map_init(&rep_state.updates);
        array_init(&rep_state.requests);
        array_init(&rep_state.requested_reps);
        rep_state.last_id = 0.0;
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

    pthread_mutex_lock(&rep_state.lock);

    /* In full impl: extract paxos_id from message data, compare with last_id
     * For now, always grant to progress the protocol */

    /* Send grant */
    generic_msg_t grant = {0};
    grant.type = NET_MESSAGE;
    strncpy(grant.info.net_msg.process, "reputation", PROC_NAME_LEN);
    grant.info.net_msg.function = (char *)REP_PROTO_GRANT;
    grant.info.net_msg.encrypt = true;
    memcpy(&grant.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
    strncpy(grant.info.net_msg.return_to, "reputation", PROC_NAME_LEN);

    pthread_mutex_unlock(&rep_state.lock);

    messaging_send("network", NET_MESSAGE, &grant, false);
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

    pthread_mutex_lock(&rep_state.lock);

    /* In full impl: extract task_uuid, increment grant count in proposals map
     * When grants >= majority, broadcast the transaction */

    /* For now, simulate majority reached and broadcast TX */
    /* This would iterate my_requests to find matching proposal */

    pthread_mutex_unlock(&rep_state.lock);
    return true;
}

/****************************
 * Handler: handle_nack (try again) — exponential backoff retry
 ****************************/

static bool handle_nack(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Reputation: nack from %s\n", nmsg->from_whom.fullname);

    pthread_mutex_lock(&rep_state.lock);

    /* In full impl: extract task_uuid, compute backoff time, schedule retry
     * backoff = min(BACKOFF_MULT * current_backoff, BACKOFF_MAX_SEC) */
    char from_uuid[UUID_STRING_LEN + 1];
    uuid_unparse_lower(nmsg->from_whom.uuid, from_uuid);

    data_t *backoff_dat = NULL;
    time_t next_retry = time(NULL) + 2;  /* Default 2 second initial backoff */

    if (map_get(&rep_state.backoff, from_uuid, &backoff_dat) == 0)
    {
        int prev = 0;
        data_integer(backoff_dat, &prev);
        time_t wait = (time_t)((double)((long)prev - time(NULL)) * BACKOFF_MULT);
        if (wait > BACKOFF_MAX_SEC) wait = BACKOFF_MAX_SEC;
        if (wait < 1) wait = 2;
        next_retry = time(NULL) + wait;
    }

    data_t *retry_dat = integer_data((int)next_retry);
    map_set(&rep_state.backoff, from_uuid, retry_dat);

    pthread_mutex_unlock(&rep_state.lock);
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

    /* In full impl: verify we granted this, validate transaction data */

    /* Send accepted */
    generic_msg_t accepted = {0};
    accepted.type = NET_MESSAGE;
    strncpy(accepted.info.net_msg.process, "reputation", PROC_NAME_LEN);
    accepted.info.net_msg.function = (char *)REP_PROTO_ACCEPTED;
    accepted.info.net_msg.encrypt = true;
    memcpy(&accepted.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
    strncpy(accepted.info.net_msg.return_to, "reputation", PROC_NAME_LEN);

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

    pthread_mutex_lock(&rep_state.lock);

    /* In full impl: increment acceptance count for this task_uuid
     * When acceptances >= majority, commit transaction to history */

    pthread_mutex_unlock(&rep_state.lock);
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

    /* In full impl: extract requested range from message,
     * serialize chain slice via tx_history_era_to_json, send via REP_PROTO_UPDATE */
    json_t *era_json = NULL;
    int chain_len = tx_history_len(&rep_state.history);
    tx_history_era_to_json(&rep_state.history, 0, chain_len, &era_json);

    /* Send update (in full impl, the JSON would be serialized into net_msg obj/len) */
    generic_msg_t update = {0};
    update.type = NET_MESSAGE;
    strncpy(update.info.net_msg.process, "reputation", PROC_NAME_LEN);
    update.info.net_msg.function = (char *)REP_PROTO_UPDATE;
    update.info.net_msg.encrypt = true;
    memcpy(&update.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
    strncpy(update.info.net_msg.return_to, "reputation", PROC_NAME_LEN);

    if (era_json != NULL)
        json_decref(era_json);

    pthread_mutex_unlock(&rep_state.lock);

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

    pthread_mutex_lock(&rep_state.lock);

    /* In full impl: deserialize JSON chain from message,
     * compare with local chain, merge if consistent */

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

    /* In full impl: extract target peer UUID from message,
     * compute reputation, send response via REP_PROTO_REP_RESP */

    generic_msg_t resp = {0};
    resp.type = NET_MESSAGE;
    strncpy(resp.info.net_msg.process, "reputation", PROC_NAME_LEN);
    resp.info.net_msg.function = (char *)REP_PROTO_REP_RESP;
    resp.info.net_msg.encrypt = true;
    memcpy(&resp.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
    strncpy(resp.info.net_msg.return_to, "reputation", PROC_NAME_LEN);

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

    /* In full impl: extract score from response, store in requested_reps */

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

    /* Compute Paxos ID */
    rep_state.last_id += 1.0;
    double paxos_id = paxos_id_index(rep_state.last_id, (double)rep_state.num_peers);

    pthread_mutex_unlock(&rep_state.lock);

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
        /* In full impl: pack paxos_id + task_uuid + chain_index into obj */
        (void)paxos_id;  /* Used in full impl */
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

    proc->protocol.phase = 1;

    return process_run(proc, queues, signal, logger);
}
DECLARE_PROCESS(reputation, rep_proc, reputation_run);
