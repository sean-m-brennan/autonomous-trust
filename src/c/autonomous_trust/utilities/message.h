/********************
 *  Copyright 2024 TekFive, Inc. and contributors
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

#ifndef MESSAGE_H
#define MESSAGE_H

#include <stdbool.h>
#include <sys/socket.h>

#include "structures/map.h"
#include "msg_types.h"

#define MSG_KEY_LEN PROC_NAME_LEN
#define MAX_MSG_SIZE 1024  // FIXME

typedef struct
{
    int fd;
    char key[MSG_KEY_LEN+1];
} queue_t;

/**
 * @brief Initialize a message queue
 *
 * @param id A message queue id
 * @param queue Queue object
 * @return int Success or error
 */
int messaging_init(const char *id, queue_t *queue);

/**
 * @brief Identify the queue that belong to this process.
 * 
 * @param queue Queue object
 */
void messaging_assign(queue_t *queue);

/**
 * @brief Receive a message from a specific queue (usually external)
 * 
 * @param queue Queue object
 * @param msg Generic message
 * @param their_addr Sender's info
 * @param blocking 
 * @return int 
 */
int messaging_recv_on(queue_t *q, generic_msg_t *msg, struct sockaddr_storage *their_addr, bool blocking);

/**
 * @brief Receive a message from the assigned queue
 * 
 * @param data 
 * @param their_addr 
 * @param blocking 
 * @return int 
 */
int messaging_recv_from(generic_msg_t *data, struct sockaddr_storage *their_addr, bool blocking);

/**
 * @brief 
 * 
 */
#define messaging_recv(data) messaging_recv_from(data, NULL, false)

int signal_recv(queue_t *q, long *msg_type, signal_t * sig);

/**
 * @brief Send a message internally
 *
 * @param queue_id
 * @param type
 * @param msg
 * @return int
 */
int messaging_send(const char *key, const message_type_t type, generic_msg_t *msg, bool blocking);

/**
 * @brief 
 * 
 * @param queue 
 */
void messaging_qclose(queue_t *queue);

/**
 * @brief 
 * 
 */
void messaging_close();

#define EMSG_NOCONN 204
DECLARE_ERROR(EMSG_NOCONN, "Attempting to send/recv without a queue (see message_assign())");

#endif  // MESSAGE_H
