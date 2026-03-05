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

#include "processes/processes.h"
#include "negotiation/negotiation.h"
#include "structures/map_priv.h"
#include "structures/data_priv.h"
#include "structures/array_priv.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"
#include "utilities/exception.h"
#include "network/net_message.h"
#include "negotiation/neg_proc_priv.h"

DEFINE_ERROR(ENEG_NOPEERS, "No capable peers available");

/****************************
 * Process state (file-scope static, thread-safe via mutex)
 ****************************/

static struct {
    job_queue_t task_stack;
    map_t proposed_tasks;  /* uuid_str -> task_t* */
    map_t my_tasks;        /* uuid_str -> task_tracker_t* */
    map_t confirmed;       /* uuid_str -> int */
    array_t status_pending;
    int max_concurrency;
    pthread_mutex_t lock;
    bool initialized;
} neg_state;

static void _ensure_init(void)
{
    if (!neg_state.initialized)
    {
        job_queue_init(&neg_state.task_stack);
        map_init(&neg_state.proposed_tasks);
        map_init(&neg_state.my_tasks);
        map_init(&neg_state.confirmed);
        array_init(&neg_state.status_pending);
        neg_state.max_concurrency = 4;
        pthread_mutex_init(&neg_state.lock, NULL);
        neg_state.initialized = true;
    }
}

/****************************
 * Handler: handle_start_task (spawn task) — NEG_PROTO_START
 * Log the new task, find capable peers, send invite.
 ****************************/

static bool handle_start_task(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Negotiation: start task from %s\n", nmsg->from_whom.fullname);

    pthread_mutex_lock(&neg_state.lock);

    /* In full impl: deserialize task_t from nmsg->obj/len,
     * store in proposed_tasks, find peers with matching capabilities */

    /* For now, broadcast invitation to all known peers */
    for (size_t i = 0; i < proc->protocol.num_peers; i++)
    {
        generic_msg_t invite = {0};
        invite.type = NET_MESSAGE;
        strncpy(invite.info.net_msg.process, "negotiation", PROC_NAME_LEN);
        invite.info.net_msg.function = (char *)NEG_PROTO_ANNOUNCE;
        invite.info.net_msg.encrypt = true;
        memcpy(&invite.info.net_msg.to_whom, &proc->protocol.peers[i],
               sizeof(public_identity_t));
        strncpy(invite.info.net_msg.return_to, "negotiation", PROC_NAME_LEN);
        /* In full impl: attach serialized task_t as obj/len payload */

        messaging_send("network", NET_MESSAGE, &invite, false);
    }

    pthread_mutex_unlock(&neg_state.lock);
    return true;
}

/****************************
 * Handler: handle_invite (invitation) — NEG_PROTO_ANNOUNCE
 * Log the invite, check capability, accept or refuse.
 ****************************/

static bool handle_invite(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Negotiation: invitation from %s\n", nmsg->from_whom.fullname);

    /* In full impl: deserialize task_t from payload, check own capabilities
     * against task requirements, and determine accept or refuse */

    /* For now, accept unconditionally */
    generic_msg_t reply = {0};
    reply.type = NET_MESSAGE;
    strncpy(reply.info.net_msg.process, "negotiation", PROC_NAME_LEN);
    reply.info.net_msg.function = (char *)NEG_PROTO_ACCEPT;
    reply.info.net_msg.encrypt = true;
    memcpy(&reply.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
    strncpy(reply.info.net_msg.return_to, "negotiation", PROC_NAME_LEN);

    messaging_send("network", NET_MESSAGE, &reply, false);
    return true;
}

/****************************
 * Handler: handle_haggle (haggle) — NEG_PROTO_RESPONSE
 * Log the haggle response; re-announce if flexible on terms.
 ****************************/

static bool handle_haggle(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Negotiation: haggle response from %s\n", nmsg->from_whom.fullname);

    /* In full impl: deserialize counter-offer from payload,
     * evaluate whether terms are acceptable, re-announce if adjustable */

    /* For now, accept the counter-offer as-is */
    generic_msg_t ack = {0};
    ack.type = NET_MESSAGE;
    strncpy(ack.info.net_msg.process, "negotiation", PROC_NAME_LEN);
    ack.info.net_msg.function = (char *)NEG_PROTO_ACCEPT;
    ack.info.net_msg.encrypt = true;
    memcpy(&ack.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
    strncpy(ack.info.net_msg.return_to, "negotiation", PROC_NAME_LEN);

    messaging_send("network", NET_MESSAGE, &ack, false);
    return true;
}

/****************************
 * Handler: handle_accept (ack) — NEG_PROTO_ACCEPT
 * Log the acceptance and record in confirmed map.
 ****************************/

static bool handle_accept(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Negotiation: accepted by %s\n", nmsg->from_whom.fullname);

    pthread_mutex_lock(&neg_state.lock);

    /* In full impl: extract task_uuid from payload, record this peer
     * in the confirmed map for that task */
    char from_uuid[UUID_STRING_LEN + 1];
    uuid_unparse_lower(nmsg->from_whom.uuid, from_uuid);

    data_t *count_dat = NULL;
    int count = 0;
    if (map_get(&neg_state.confirmed, from_uuid, &count_dat) == 0)
        data_integer(count_dat, &count);

    count++;
    data_t *new_count = integer_data(count);
    map_set(&neg_state.confirmed, from_uuid, new_count);

    pthread_mutex_unlock(&neg_state.lock);
    return true;
}

/****************************
 * Handler: handle_refuse (nack) — NEG_PROTO_REFUSE
 * Log the refusal and cancel this participant.
 ****************************/

static bool handle_refuse(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Negotiation: refused by %s\n", nmsg->from_whom.fullname);

    pthread_mutex_lock(&neg_state.lock);

    /* In full impl: extract task_uuid from payload, remove this peer
     * from proposed_tasks participant list for that task */

    pthread_mutex_unlock(&neg_state.lock);
    return true;
}

/****************************
 * Handler: handle_stat_req (status request) — NEG_PROTO_STAT_REQ
 * Reply to a status query with current task status.
 ****************************/

static bool handle_stat_req(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Negotiation: status request from %s\n", nmsg->from_whom.fullname);

    /* In full impl: extract task_uuid from payload, look up status
     * in my_tasks map, serialize task_status_t into response */

    generic_msg_t resp = {0};
    resp.type = NET_MESSAGE;
    strncpy(resp.info.net_msg.process, "negotiation", PROC_NAME_LEN);
    resp.info.net_msg.function = (char *)NEG_PROTO_STAT_RSP;
    resp.info.net_msg.encrypt = true;
    memcpy(&resp.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
    strncpy(resp.info.net_msg.return_to, "negotiation", PROC_NAME_LEN);

    messaging_send("network", NET_MESSAGE, &resp, false);
    return true;
}

/****************************
 * Handler: handle_stat_resp (status response) — NEG_PROTO_STAT_RSP
 * Log the received status response.
 ****************************/

static bool handle_stat_resp(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Negotiation: status response from %s\n", nmsg->from_whom.fullname);

    pthread_mutex_lock(&neg_state.lock);

    /* In full impl: deserialize task_status_t from payload,
     * update tracking state and remove from status_pending */

    pthread_mutex_unlock(&neg_state.lock);
    return true;
}

/****************************
 * Handler: handle_results (report results) — NEG_PROTO_RESULT
 * Log the result and collect into task tracker.
 ****************************/

static bool handle_results(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Negotiation: results from %s\n", nmsg->from_whom.fullname);

    pthread_mutex_lock(&neg_state.lock);

    /* In full impl: deserialize task_result_t from payload,
     * look up tracker in my_tasks, call task_tracker_set_result(),
     * check if all expected results have arrived */

    pthread_mutex_unlock(&neg_state.lock);
    return true;
}

/****************************
 * Negotiation process main entry
 ****************************/

int negotiation_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger)
{
    _ensure_init();

    /* Register protocol handlers */
    process_register_handler(proc, (char *)NEG_PROTO_START,    (handler_ptr_t)handle_start_task);
    process_register_handler(proc, (char *)NEG_PROTO_ANNOUNCE, (handler_ptr_t)handle_invite);
    process_register_handler(proc, (char *)NEG_PROTO_RESPONSE, (handler_ptr_t)handle_haggle);
    process_register_handler(proc, (char *)NEG_PROTO_ACCEPT,   (handler_ptr_t)handle_accept);
    process_register_handler(proc, (char *)NEG_PROTO_REFUSE,   (handler_ptr_t)handle_refuse);
    process_register_handler(proc, (char *)NEG_PROTO_STAT_REQ, (handler_ptr_t)handle_stat_req);
    process_register_handler(proc, (char *)NEG_PROTO_STAT_RSP, (handler_ptr_t)handle_stat_resp);
    process_register_handler(proc, (char *)NEG_PROTO_RESULT,   (handler_ptr_t)handle_results);

    proc->protocol.phase = 1;

    return process_run(proc, queues, signal, logger);
}
DECLARE_PROCESS(negotiation, neg_proc, negotiation_run);
