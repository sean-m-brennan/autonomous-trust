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

#include <string.h>
#include <errno.h>
#include <stdint.h>

#include "msg_types_priv.h"

#include "identity/identity_priv.h"
#include "processes/capabilities_priv.h"
#include "negotiation/task_priv.h"
#include "google/protobuf/any.pb-c.h"

size_t message_size(message_type_t type)
{
    switch (type)
    {
    case SIGNAL:
        return sizeof(signal_t);
    case GROUP:
        return sizeof(group_t);
    case PEER:
        return sizeof(public_identity_t);
    case PEER_CAPABILITIES:
        return sizeof(capability_t) * MAX_PEERS * MAX_CAPABILITIES;
    case NET_MESSAGE:
        return sizeof(net_msg_t);
    case TASK:
        return sizeof(task_t);
    default:
        return 0;
    }
}

char *message_type_to_string(message_type_t type)
{
    switch (type)
    {
    case SIGNAL:
        return (char*)"SIGNAL";
    case GROUP:
        return (char*)autonomous_trust__core__identity__group__descriptor.c_name;
    case PEER:
        return (char*)autonomous_trust__core__identity__identity__descriptor.c_name;
    case PEER_CAPABILITIES:
        return (char*)autonomous_trust__core__processes__peer_capabilities__descriptor.c_name;
    case TASK:
        return (char*)"TASK"; // FIXME
    case NET_MESSAGE:
        return (char*)"NET_MSG";
    default:
        return (char*)"";
    }
}

message_type_t string_to_message_type(const char *str)
{
    if (strncmp(str, "SIGNAL", strlen("SIGNAL")) == 0)
        return SIGNAL;
    if (strncmp(str, autonomous_trust__core__identity__group__descriptor.c_name,
                strlen(autonomous_trust__core__identity__group__descriptor.c_name)) == 0)
        return GROUP;
    if (strncmp(str, autonomous_trust__core__identity__identity__descriptor.c_name,
                strlen(autonomous_trust__core__identity__identity__descriptor.c_name)) == 0)
        return PEER;
    if (strncmp(str, autonomous_trust__core__processes__peer_capabilities__descriptor.c_name,
                strlen(autonomous_trust__core__processes__peer_capabilities__descriptor.c_name)) == 0)
        return PEER_CAPABILITIES;
    if (strncmp(str, "TASK", strlen("TASK")) == 0) // FIXME
        return TASK;
    if (strncmp(str, "NET_MSG", strlen("NET_MSG")) == 0)
        return NET_MESSAGE;
    return 0;
}

// FIXME
int signal_to_proto(const signal_t *msg, void **data_ptr, size_t *data_len_ptr)
{
    *data_len_ptr = strlen(msg->descr) + 1;
    *data_ptr = calloc(1, *data_len_ptr);
    strcpy(*data_ptr, msg->descr);
    return 0;
}

int net_msg_to_proto(const net_msg_t *msg, void **data_ptr, size_t *data_len_ptr)
{
    return 0;  // FIXME
}

int wrap_in_any(message_type_t type, void *data_in, size_t data_in_len, void **data_ptr, size_t *data_len_ptr)
{
    Google__Protobuf__Any pb_msg = GOOGLE__PROTOBUF__ANY__INIT;
    pb_msg.type_url = message_type_to_string(type);
    pb_msg.value.data = data_in;
    pb_msg.value.len = data_in_len;

    *data_len_ptr = google__protobuf__any__get_packed_size(&pb_msg);
    *data_ptr = malloc(*data_len_ptr);
    if (*data_ptr == NULL)
    {
        free(data_in);
        return EXCEPTION(ENOMEM);
    }
    google__protobuf__any__pack(&pb_msg, *data_ptr); // FIXME error check
    free(data_in);
    return 0;
}

int generic_msg_to_proto(generic_msg_t *msg, void **data, size_t *data_len)
{
    void *subdata;
    size_t subdata_len;
    switch (msg->type)
    {
    case SIGNAL:
    {
        if (signal_to_proto(&msg->info.signal, &subdata, &subdata_len) != 0)
            return -1;
        break;
    }
    case GROUP:
    {
        if (group_to_proto(&msg->info.group, &subdata, &subdata_len) != 0)
            return -1;
        break;
    }
    case PEER:
    {
        if (peer_to_proto(&msg->info.peer, &subdata, &subdata_len) != 0)
            return -1;
        break;
    }
    case PEER_CAPABILITIES:
    {
        if (peer_capabilities_to_proto(&msg->info.peer_capabilities, &subdata, &subdata_len) != 0)
            return -1;
        break;
    }
    case TASK:
    {
        if (task_to_proto(&msg->info.task, msg->size, &subdata, &subdata_len) != 0)
            return -1;
        break;
    }
    case NET_MESSAGE:
    {
        if (net_msg_to_proto(&msg->info.net_msg, &subdata, &subdata_len) != 0)
            return -1;
        break;
    }
    default:
        return -1;
    }
    return wrap_in_any(msg->type, subdata, subdata_len, data, data_len);
}

// FIXME
int proto_to_signal(uint8_t *data, size_t len, signal_t *sig)
{
    return 0;
}

int proto_to_net_msg(uint8_t *data, size_t len, net_msg_t *net_msg)
{
    return 0;
}

int proto_to_generic_msg(void *data, size_t data_len, generic_msg_t *msg)
{
    Google__Protobuf__Any *pb_msg;

    pb_msg = google__protobuf__any__unpack(NULL, data_len, data);
    if (pb_msg == NULL)
        ; // FIXME

    message_type_t type = string_to_message_type(pb_msg->type_url);
    switch (type)
    {
    case SIGNAL:
        return proto_to_signal(pb_msg->value.data, pb_msg->value.len, &msg->info.signal);
    case GROUP:
        return proto_to_group(pb_msg->value.data, pb_msg->value.len, &msg->info.group);
    case PEER:
        return proto_to_peer(pb_msg->value.data, pb_msg->value.len, &msg->info.peer);
    case PEER_CAPABILITIES:
        return proto_to_peer_capabilities(pb_msg->value.data, pb_msg->value.len, &msg->info.peer_capabilities);
    case NET_MESSAGE:
        return proto_to_net_msg(pb_msg->value.data, pb_msg->value.len, &msg->info.net_msg);
    case TASK:
        return proto_to_task(pb_msg->value.data, pb_msg->value.len, &msg->info.task);
    default:
        return -1;
    }
    return 0;
}