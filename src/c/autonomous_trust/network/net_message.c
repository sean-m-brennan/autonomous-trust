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
#include <stdlib.h>

#include "network/net_message.h"
#include "utilities/exception.h"
#include "utilities/allocation.h"

DEFINE_ERROR(ENET_MSG_FMT, "Invalid network message wire format");
DEFINE_ERROR(ENET_MSG_TRUNC, "Network message data truncated");

void net_wire_msg_init(net_wire_msg_t *msg)
{
    memset(msg, 0, sizeof(net_wire_msg_t));
    msg->encrypt = true;
    msg->to_whom.type = RECIPIENT_NONE;
}

void net_wire_msg_free(net_wire_msg_t *msg)
{
    if (msg == NULL)
        return;
    if (msg->data != NULL)
    {
        free(msg->data);
        msg->data = NULL;
    }
    if (msg->to_whom.type == RECIPIENT_LIST && msg->to_whom.target.list.peers != NULL)
    {
        free(msg->to_whom.target.list.peers);
        msg->to_whom.target.list.peers = NULL;
    }
}

void net_wire_msg_set_broadcast(net_wire_msg_t *msg)
{
    msg->to_whom.type = RECIPIENT_BROADCAST;
    msg->encrypt = false;
}

void net_wire_msg_set_peer(net_wire_msg_t *msg, const public_identity_t *peer)
{
    msg->to_whom.type = RECIPIENT_PEER;
    memcpy(&msg->to_whom.target.peer, peer, sizeof(public_identity_t));
}

void net_wire_msg_set_group(net_wire_msg_t *msg, const group_t *group)
{
    msg->to_whom.type = RECIPIENT_GROUP;
    memcpy(&msg->to_whom.target.group, group, sizeof(group_t));
}

/**
 * Wire format: "process|function|data"
 * Splits on first two '|' delimiters only.
 * Data portion may contain '|' characters.
 */
int net_message_to_wire(const net_wire_msg_t *msg, uint8_t **wire_out, size_t *wire_len)
{
    if (msg == NULL || wire_out == NULL || wire_len == NULL)
        return EXCEPTION(EINVAL);

    size_t proc_len = strlen(msg->process);
    size_t func_len = strlen(msg->function);
    /* format: process|function|data */
    size_t total = proc_len + 1 + func_len + 1 + msg->data_len;

    uint8_t *buf = malloc(total);
    if (buf == NULL)
        return SYS_EXCEPTION();

    size_t offset = 0;
    memcpy(buf + offset, msg->process, proc_len);
    offset += proc_len;
    buf[offset++] = NET_MSG_DELIMITER;
    memcpy(buf + offset, msg->function, func_len);
    offset += func_len;
    buf[offset++] = NET_MSG_DELIMITER;
    if (msg->data_len > 0 && msg->data != NULL)
        memcpy(buf + offset, msg->data, msg->data_len);

    *wire_out = buf;
    *wire_len = total;
    return 0;
}

int net_message_from_wire(const uint8_t *wire, size_t wire_len,
                          const public_identity_t *sender, net_wire_msg_t *msg)
{
    if (wire == NULL || wire_len == 0 || msg == NULL)
        return EXCEPTION(EINVAL);

    net_wire_msg_init(msg);

    /* Find first delimiter: process */
    const uint8_t *first_delim = memchr(wire, NET_MSG_DELIMITER, wire_len);
    if (first_delim == NULL)
        return EXCEPTION(ENET_MSG_FMT);

    size_t proc_len = (size_t)(first_delim - wire);
    if (proc_len == 0 || proc_len > PROC_NAME_LEN)
        return EXCEPTION(ENET_MSG_FMT);

    memcpy(msg->process, wire, proc_len);
    msg->process[proc_len] = '\0';

    /* Find second delimiter: function */
    size_t remaining_start = proc_len + 1;
    if (remaining_start >= wire_len)
        return EXCEPTION(ENET_MSG_FMT);

    const uint8_t *second_delim = memchr(wire + remaining_start, NET_MSG_DELIMITER,
                                         wire_len - remaining_start);
    if (second_delim == NULL)
        return EXCEPTION(ENET_MSG_FMT);

    size_t func_len = (size_t)(second_delim - (wire + remaining_start));
    if (func_len == 0 || func_len > NET_MSG_FUNC_LEN)
        return EXCEPTION(ENET_MSG_FMT);

    memcpy(msg->function, wire + remaining_start, func_len);
    msg->function[func_len] = '\0';

    /* Remainder is data (may contain '|') */
    size_t data_start = remaining_start + func_len + 1;
    size_t data_len = 0;
    if (data_start < wire_len)
        data_len = wire_len - data_start;

    if (data_len > 0)
    {
        msg->data = malloc(data_len);
        if (msg->data == NULL)
        {
            SYS_EXCEPTION();
            return -1;
        }
        memcpy(msg->data, wire + data_start, data_len);
        msg->data_len = data_len;
    }

    /* Set sender if provided */
    if (sender != NULL)
        memcpy(&msg->from_whom, sender, sizeof(public_identity_t));

    return 0;
}
