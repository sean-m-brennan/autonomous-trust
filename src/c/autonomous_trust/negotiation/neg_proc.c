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
#include <time.h>
#include <pthread.h>

#include "processes/processes.h"
#include "negotiation/negotiation.h"
#include "structures/map.h"
#include "structures/map_priv.h"
#include "structures/data_priv.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"
#include "utilities/exception.h"
#include "network/net_message.h"

#define ENEG_NOPEERS 243
DEFINE_ERROR(ENEG_NOPEERS, "No capable peers available");

/****************************
 * Process state (file-scope static)
 ****************************/

#define MAX_FLOOD_COUNT 3
#define DEFAULT_MAX_CONCURRENCY 4
#define TASK_OVERDUE_TIMEOUT 300  /* seconds */

static struct {
    job_queue_t task_stack;
    map_t proposed_tasks;   /* uuid_str -> task_tracker_t* */
    map_t my_tasks;         /* uuid_str -> task_t* */
    map_t confirmed;        /* uuid_str -> array_t* of peer uuids */
    map_t flood_counts;     /* uuid_str -> int */
    array_t status_pending; /* array of uuid_t waiting for status */
    int max_concurrency;
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
        map_init(&neg_state.flood_counts);
        array_init(&neg_state.status_pending);
        neg_state.max_concurrency = DEFAULT_MAX_CONCURRENCY;
        neg_state.initialized = true;
    }
}

/****************************
 * Helper: find peers with a given capability
 ****************************/

static int _find_capable_peers(const process_t *proc, const char *cap_name,
                               public_identity_t *out_peers, size_t *out_count)
{
    *out_count = 0;
    if (proc->protocol.peer_capabilities == NULL)
        return 0;

    for (size_t i = 0; i < proc->protocol.num_peers; i++)
    {
        char uuid_str[UUID_STRING_LEN + 1];
        uuid_unparse_lower(proc->protocol.peers[i].uuid, uuid_str);

        data_t *caps_dat = NULL;
        if (map_get(proc->protocol.peer_capabilities, uuid_str, &caps_dat) != 0)
            continue;

        /* For now, assume peer has the capability if it's in the map */
        /* Full implementation would iterate the capabilities array */
        if (*out_count < MAX_PEERS)
        {
            memcpy(&out_peers[*out_count], &proc->protocol.peers[i], sizeof(public_identity_t));
            (*out_count)++;
        }
    }
    return 0;
}

/****************************
 * Handler: handle_start_task (spawn task)
 * Received from main process when external task arrives.
 ****************************/

static bool handle_start_task(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    task_t *task = &msg->info.task;

    char uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(task->uuid, uuid_str);
    log_info(proc->logger, "Negotiation: starting task %s\n", uuid_str);

    /* Find capable peers */
    public_identity_t capable_peers[MAX_PEERS];
    size_t num_capable = 0;
    _find_capable_peers(proc, task->capability.name, capable_peers, &num_capable);

    if (num_capable == 0)
    {
        log_warn(proc->logger, "Negotiation: no capable peers for %s\n", task->capability.name);
        /* Send TASK_STATUS DEAD back to main */
        generic_msg_t status_msg = {0};
        status_msg.type = TASK_STATUS;
        uuid_copy(status_msg.info.task_status.task_uuid, task->uuid);
        uuid_copy(status_msg.info.task_status.requestor_uuid, task->requestor_uuid);
        status_msg.info.task_status.status = TASK_STATUS_DEAD;
        messaging_send("AutonomousTrust", TASK_STATUS, &status_msg, false);
        return true;
    }

    /* Create task tracker */
    task_tracker_t *tracker = smrt_create(sizeof(task_tracker_t));
    if (tracker == NULL)
        return true;
    task_tracker_init(tracker, task->uuid, (int)num_capable);
    data_t *tracker_dat = object_ptr_data(tracker, sizeof(task_tracker_t));
    map_set(&neg_state.proposed_tasks, uuid_str, tracker_dat);

    /* Store my task */
    task_t *task_copy = smrt_create(sizeof(task_t));
    if (task_copy == NULL)
        return true;
    memcpy(task_copy, task, sizeof(task_t));
    data_t *task_dat = object_ptr_data(task_copy, sizeof(task_t));
    map_set(&neg_state.my_tasks, uuid_str, task_dat);

    /* Send announce (invitation) to each capable peer */
    for (size_t i = 0; i < num_capable; i++)
    {
        generic_msg_t invite = {0};
        invite.type = NET_MESSAGE;
        strncpy(invite.info.net_msg.process, "negotiation", PROC_NAME_LEN);
        invite.info.net_msg.function = (char *)NEG_PROTO_ANNOUNCE;
        invite.info.net_msg.encrypt = true;
        memcpy(&invite.info.net_msg.to_whom, &capable_peers[i], sizeof(public_identity_t));
        strncpy(invite.info.net_msg.return_to, "negotiation", PROC_NAME_LEN);
        /* Task data would be serialized into obj/len in full impl */
        messaging_send("network", NET_MESSAGE, &invite, false);
    }

    log_info(proc->logger, "Negotiation: announced task %s to %zu peers\n", uuid_str, num_capable);
    return true;
}

/****************************
 * Handler: handle_invite (invitation)
 * Received when another peer wants us to do a task.
 ****************************/

static bool handle_invite(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Negotiation: received invitation from %s\n", nmsg->from_whom.fullname);

    /* Flood check */
    char from_uuid[UUID_STRING_LEN + 1];
    uuid_unparse_lower(nmsg->from_whom.uuid, from_uuid);
    data_t *count_dat = NULL;
    int flood = 0;
    if (map_get(&neg_state.flood_counts, from_uuid, &count_dat) == 0)
    {
        data_integer(count_dat, &flood);
    }

    if (flood >= MAX_FLOOD_COUNT)
    {
        log_warn(proc->logger, "Negotiation: flood limit reached for %s, refusing\n", from_uuid);
        /* Send refuse */
        generic_msg_t refuse = {0};
        refuse.type = NET_MESSAGE;
        strncpy(refuse.info.net_msg.process, "negotiation", PROC_NAME_LEN);
        refuse.info.net_msg.function = (char *)NEG_PROTO_REFUSE;
        refuse.info.net_msg.encrypt = true;
        memcpy(&refuse.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
        messaging_send("network", NET_MESSAGE, &refuse, false);
        return true;
    }

    /* Update flood count */
    data_t *new_count = integer_data(flood + 1);
    map_set(&neg_state.flood_counts, from_uuid, new_count);

    /* Check if we have the required capability */
    /* In full impl, deserialize task from nmsg->obj and check capability */

    /* Check slot availability */
    time_t slot_time = 0;
    int ret = job_queue_find_nearest_slot(&neg_state.task_stack, 60, /* default duration */
                                          neg_state.max_concurrency, &slot_time);
    if (ret != 0)
    {
        /* No slot: refuse */
        generic_msg_t refuse = {0};
        refuse.type = NET_MESSAGE;
        strncpy(refuse.info.net_msg.process, "negotiation", PROC_NAME_LEN);
        refuse.info.net_msg.function = (char *)NEG_PROTO_REFUSE;
        refuse.info.net_msg.encrypt = true;
        memcpy(&refuse.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
        messaging_send("network", NET_MESSAGE, &refuse, false);
        return true;
    }

    /* Accept */
    generic_msg_t accept = {0};
    accept.type = NET_MESSAGE;
    strncpy(accept.info.net_msg.process, "negotiation", PROC_NAME_LEN);
    accept.info.net_msg.function = (char *)NEG_PROTO_ACCEPT;
    accept.info.net_msg.encrypt = true;
    memcpy(&accept.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
    messaging_send("network", NET_MESSAGE, &accept, false);

    log_info(proc->logger, "Negotiation: accepted task from %s\n", nmsg->from_whom.fullname);
    return true;
}

/****************************
 * Handler: handle_haggle (haggle)
 * Counter-offer from peer - re-announce if flexible, else cancel.
 ****************************/

static bool handle_haggle(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Negotiation: haggle from %s\n", nmsg->from_whom.fullname);

    /* In full impl: check if task is flexible, then re-announce or cancel */
    /* For now, just refuse the haggle */
    generic_msg_t refuse = {0};
    refuse.type = NET_MESSAGE;
    strncpy(refuse.info.net_msg.process, "negotiation", PROC_NAME_LEN);
    refuse.info.net_msg.function = (char *)NEG_PROTO_CANCEL;
    refuse.info.net_msg.encrypt = true;
    memcpy(&refuse.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
    messaging_send("network", NET_MESSAGE, &refuse, false);

    return true;
}

/****************************
 * Handler: handle_accept (ack)
 * Peer accepted our task.
 ****************************/

static bool handle_accept(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Negotiation: peer %s accepted task\n", nmsg->from_whom.fullname);

    /* Record in confirmed map */
    /* In full impl: extract task UUID from message, add peer to confirmed set */

    return true;
}

/****************************
 * Handler: handle_refuse (nack)
 * Peer refused our task.
 ****************************/

static bool handle_refuse(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Negotiation: peer %s refused task\n", nmsg->from_whom.fullname);

    /* In full impl: remove peer from expected participants, check if enough remain */
    return true;
}

/****************************
 * Handler: handle_stat_req (status request)
 ****************************/

static bool handle_stat_req(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Negotiation: status request from %s\n", nmsg->from_whom.fullname);

    /* Reply with status of requested task */
    generic_msg_t resp = {0};
    resp.type = NET_MESSAGE;
    strncpy(resp.info.net_msg.process, "negotiation", PROC_NAME_LEN);
    resp.info.net_msg.function = (char *)NEG_PROTO_STAT_RSP;
    resp.info.net_msg.encrypt = true;
    memcpy(&resp.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
    messaging_send("network", NET_MESSAGE, &resp, false);

    return true;
}

/****************************
 * Handler: handle_stat_resp (status response)
 ****************************/

static bool handle_stat_resp(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Negotiation: status response from %s\n", nmsg->from_whom.fullname);

    /* In full impl: extend timeout or cancel based on response */
    return true;
}

/****************************
 * Handler: handle_results (report results)
 * Peer reports task completion results.
 ****************************/

static bool handle_results(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Negotiation: results from %s\n", nmsg->from_whom.fullname);

    /* In full impl:
     * 1. Deserialize task_uuid and result from message
     * 2. Find tracker in proposed_tasks
     * 3. Add result to tracker
     * 4. If all results collected, aggregate and forward to main
     */

    return true;
}

/****************************
 * Handler: handle_cancel (cancel)
 ****************************/

static bool handle_cancel(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Negotiation: cancel from %s\n", nmsg->from_whom.fullname);
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
    process_register_handler(proc, (char *)NEG_PROTO_CANCEL,   (handler_ptr_t)handle_cancel);

    proc->protocol.phase = 1;

    return process_run(proc, queues, signal, logger);
}
DECLARE_PROCESS(negotiation, neg_proc, negotiation_run);
