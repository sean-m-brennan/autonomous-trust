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

#ifndef MSG_TYPES_H
#define MSG_TYPES_H

#include <stdint.h>

#include "identity/identity.h"
#include "identity/group.h"
#include "identity/peers.h"
#include "processes/capabilities.h"
#include "negotiation/task.h"
#include "utilities/util.h"

typedef enum {
    SIGNAL = 1,
    GROUP,
    PEER,
    PEER_CAPABILITIES,
    TASK,
    NET_MESSAGE,  // generic
    TASK_STATUS,
    TASK_RESULT,
    TRANSACTION_SCORE
} message_type_t;

typedef enum {
    TASK_STATUS_RUNNING = 1,
    TASK_STATUS_SLEEPING,
    TASK_STATUS_ZOMBIE,
    TASK_STATUS_STOPPED,
    TASK_STATUS_DEAD,
    TASK_STATUS_PENDING,
    TASK_STATUS_UNKNOWN
} task_status_val_t;

typedef struct {
    uuid_t task_uuid;
    uuid_t requestor_uuid;
    task_status_val_t status;
} task_status_msg_t;

typedef struct {
    uuid_t task_uuid;
    uuid_t requestor_uuid;
    uint8_t *result_data;
    size_t result_len;
} task_result_msg_t;

typedef struct {
    uuid_t task_uuid;
    uuid_t peer_uuid;
    double score;
} tx_score_msg_t;

/**
 * @brief Network message wrapper
 * @details Network messages are strictly between net_proc and other processes, 
 *          and always in packed protobuf format.
 * 
 */
typedef struct
{
    char process[PROC_NAME_LEN+1];
    char *function;  //??
    uint8_t *obj;  // FIXME protobuf obj member, needs max size
    size_t len;
    public_identity_t to_whom;
    public_identity_t from_whom;
    bool encrypt;
    char return_to[PROC_NAME_LEN+1];
} net_msg_t;

#define SIGNAL_LEN 32

typedef struct
{
    char descr[SIGNAL_LEN+1];
    int sig;
} signal_t;

typedef struct 
{
    long type;
    size_t size;
    union {
        signal_t signal;
        group_t group;
        public_identity_t peer;
        peer_capabilities_matrix_t peer_capabilities;
        task_t task;
        net_msg_t net_msg;
        task_status_msg_t task_status;
        task_result_msg_t task_result;
        tx_score_msg_t tx_score;
    } info;
} generic_msg_t;

size_t message_size(message_type_t type);


#endif  // MSG_TYPES_H
