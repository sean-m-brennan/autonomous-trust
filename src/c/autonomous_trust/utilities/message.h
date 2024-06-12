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

#include "structures/map.h"
#include "msg_types.h"

#define U_SOCK 1
#define MSG_Q 2

#ifndef IPC_MSG_IMPL
#define IPC_MSG_IMPL U_SOCK
#endif

#if IPC_MSG_IMPL == MSG_Q
typedef key_t msg_key_t;

typedef int queue_id_t;

#define MSG_KEY_DECL(x) int x

#define data_key(d, i) data_integer(d, &i)

#define key_data(i) integer_data(&i)

#elif IPC_MSG_IMPL == U_SOCK
typedef char *msg_key_t;

typedef struct
{
    int fd;
    char name[PROC_NAMELEN]
} queue_id_t;

#define MSG_KEY_DECL(x) char *x

#define data_key(d, s) data_string_ptr(d, s)

#define key_data(s) string_data(s, strlen(s))

#else
#error "Invalid IPC messaging implementation: IPC_MSG_IMPL"
#endif

/**
 * @brief
 *
 * @param id
 * @param key
 * @return int
 */
int messaging_new_id(char *id, msg_key_t *key);

/**
 * @brief Initialize a message queue
 *
 * @param id A message queue id
 * @return int File descriptor of the open queue
 */
int messaging_init(msg_key_t id);

/**
 * @brief Pull an existing queue from storage
 *
 * @param map
 * @param key
 * @return queue_id_t
 */
queue_id_t messaging_fetch_queue(map_t *map, const char *key);

/**
 * @brief Receive an internal message
 *
 * @param qid
 * @param data
 * @param data_len
 * @return int
 */
int messaging_recv(queue_id_t qid, generic_msg_t *data);

/**
 * @brief
 *
 * @param type
 * @return size_t
 */
size_t message_size(message_type_t type);

/**
 * @brief Send a message internally
 *
 * @param qid
 * @param type
 * @param data
 * @param data_len
 * @return int
 */
int messaging_send(queue_id_t qid, message_type_t type, void *data);

#endif // MESSAGE_H
