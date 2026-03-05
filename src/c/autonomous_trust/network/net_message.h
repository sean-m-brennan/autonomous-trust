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

#ifndef NET_MESSAGE_H
#define NET_MESSAGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "identity/identity.h"
#include "identity/group.h"
#include "utilities/exception.h"
#include "utilities/util.h"

#define NET_MSG_DELIMITER '|'
#define NET_MSG_ENCODING "utf-8"
#define NET_MSG_BROADCAST "anyone"

#define NET_MSG_FUNC_LEN 64
#define NET_MSG_MAX_DATA (64 * 1024)

/**
 * @brief Recipient type for a network message.
 */
typedef enum {
    RECIPIENT_NONE = 0,
    RECIPIENT_PEER,
    RECIPIENT_GROUP,
    RECIPIENT_BROADCAST,
    RECIPIENT_LIST
} recipient_type_t;

/**
 * @brief Recipients union for a network message.
 */
typedef struct {
    recipient_type_t type;
    union {
        public_identity_t peer;
        group_t group;
        struct {
            public_identity_t *peers;
            size_t count;
        } list;
    } target;
} net_recipients_t;

/**
 * @brief Network wire message: process|function|data
 * @details Mirrors Python Message class. Used for inter-node communication.
 *          The internal IPC (utilities/message.h) is separate.
 */
typedef struct {
    char process[PROC_NAME_LEN + 1];
    char function[NET_MSG_FUNC_LEN + 1];
    uint8_t *data;
    size_t data_len;
    net_recipients_t to_whom;
    public_identity_t from_whom;
    bool encrypt;
    char return_to[PROC_NAME_LEN + 1];
} net_wire_msg_t;

/**
 * @brief Serialize a network message to wire format: "process|function|data"
 *
 * @param msg Source message
 * @param wire_out Output buffer (caller must free)
 * @param wire_len Output length
 * @return 0 on success, -1 on error
 */
int net_message_to_wire(const net_wire_msg_t *msg, uint8_t **wire_out, size_t *wire_len);

/**
 * @brief Deserialize a wire-format message: "process|function|data"
 *
 * @param wire Input wire bytes
 * @param wire_len Input length
 * @param sender Identity of sender (may be NULL for unvalidated)
 * @param msg Output message
 * @return 0 on success, -1 on error
 */
int net_message_from_wire(const uint8_t *wire, size_t wire_len,
                          const public_identity_t *sender, net_wire_msg_t *msg);

/**
 * @brief Initialize a net_wire_msg_t to default values.
 */
void net_wire_msg_init(net_wire_msg_t *msg);

/**
 * @brief Free dynamically allocated members of a net_wire_msg_t.
 */
void net_wire_msg_free(net_wire_msg_t *msg);

/**
 * @brief Set recipient to broadcast.
 */
void net_wire_msg_set_broadcast(net_wire_msg_t *msg);

/**
 * @brief Set recipient to a single peer.
 */
void net_wire_msg_set_peer(net_wire_msg_t *msg, const public_identity_t *peer);

/**
 * @brief Set recipient to a group.
 */
void net_wire_msg_set_group(net_wire_msg_t *msg, const group_t *group);

#define ENET_MSG_FMT 220
DECLARE_ERROR(ENET_MSG_FMT, "Invalid network message wire format");

#define ENET_MSG_TRUNC 221
DECLARE_ERROR(ENET_MSG_TRUNC, "Network message data truncated");

#endif // NET_MESSAGE_H
