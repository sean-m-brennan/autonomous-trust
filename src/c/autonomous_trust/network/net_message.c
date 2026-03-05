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
#include <stdlib.h>
#include <jansson.h>
#include <sodium.h>

#include "network/net_message.h"
#include "utilities/exception.h"

#define ENET_WIRE 232
DEFINE_ERROR(ENET_WIRE, "Wire message serialization error");

int net_message_to_wire(const net_wire_msg_t *msg, uint8_t **wire_out, size_t *wire_len)
{
    if (msg == NULL || wire_out == NULL || wire_len == NULL)
        return EXCEPTION(EINVAL);

    json_t *root = json_object();
    if (root == NULL)
        return EXCEPTION(ENOMEM);

    json_object_set_new(root, "process", json_string(msg->process));
    json_object_set_new(root, "function",
                        json_string(msg->function ? msg->function : ""));
    json_object_set_new(root, "encrypt", json_boolean(msg->encrypt));

    if (msg->data != NULL && msg->data_len > 0)
    {
        size_t b64_len = sodium_base64_encoded_len(msg->data_len,
                                                    sodium_base64_VARIANT_ORIGINAL);
        char *b64 = malloc(b64_len);
        if (b64 == NULL)
        {
            json_decref(root);
            return EXCEPTION(ENOMEM);
        }
        sodium_bin2base64(b64, b64_len, msg->data, msg->data_len,
                          sodium_base64_VARIANT_ORIGINAL);
        json_object_set_new(root, "data", json_string(b64));
        free(b64);
    }
    else
    {
        json_object_set_new(root, "data", json_string(""));
    }

    char uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(msg->from_whom.uuid, uuid_str);
    json_object_set_new(root, "from_uuid", json_string(uuid_str));
    json_object_set_new(root, "from_name", json_string(msg->from_whom.fullname));

    char *json_str = json_dumps(root, JSON_COMPACT);
    json_decref(root);
    if (json_str == NULL)
        return EXCEPTION(ENET_WIRE);

    *wire_len = strlen(json_str);
    *wire_out = (uint8_t *)json_str;
    return 0;
}

int net_message_from_wire(const uint8_t *data, size_t len,
                          const public_identity_t *peer, net_wire_msg_t *msg_out)
{
    if (data == NULL || msg_out == NULL)
        return EXCEPTION(EINVAL);

    memset(msg_out, 0, sizeof(net_wire_msg_t));

    json_error_t err;
    json_t *root = json_loadb((const char *)data, len, 0, &err);
    if (root == NULL)
        return EXCEPTION(ENET_WIRE);

    const char *process = json_string_value(json_object_get(root, "process"));
    const char *function = json_string_value(json_object_get(root, "function"));
    json_t *encrypt_val = json_object_get(root, "encrypt");
    const char *data_b64 = json_string_value(json_object_get(root, "data"));

    if (process == NULL || function == NULL)
    {
        json_decref(root);
        return EXCEPTION(ENET_WIRE);
    }

    strncpy(msg_out->process, process, PROC_NAME_LEN);
    msg_out->process[PROC_NAME_LEN] = '\0';
    msg_out->function = strdup(function);
    msg_out->encrypt = encrypt_val ? json_boolean_value(encrypt_val) : false;

    if (data_b64 != NULL && strlen(data_b64) > 0)
    {
        size_t b64_len = strlen(data_b64);
        size_t bin_maxlen = b64_len;
        uint8_t *bin = malloc(bin_maxlen);
        if (bin == NULL)
        {
            json_decref(root);
            free(msg_out->function);
            msg_out->function = NULL;
            return EXCEPTION(ENOMEM);
        }
        size_t bin_len = 0;
        if (sodium_base642bin(bin, bin_maxlen, data_b64, b64_len,
                              NULL, &bin_len, NULL,
                              sodium_base64_VARIANT_ORIGINAL) != 0)
        {
            free(bin);
            json_decref(root);
            free(msg_out->function);
            msg_out->function = NULL;
            return EXCEPTION(ENET_WIRE);
        }
        msg_out->data = bin;
        msg_out->data_len = bin_len;
    }

    if (peer != NULL)
    {
        memcpy(&msg_out->from_whom, peer, sizeof(public_identity_t));
    }
    else
    {
        const char *from_uuid = json_string_value(json_object_get(root, "from_uuid"));
        const char *from_name = json_string_value(json_object_get(root, "from_name"));
        if (from_uuid != NULL)
            uuid_parse(from_uuid, msg_out->from_whom.uuid);
        if (from_name != NULL)
            strncpy(msg_out->from_whom.fullname, from_name, NAME_LEN);
    }

    json_decref(root);
    return 0;
}

void net_wire_msg_free(net_wire_msg_t *msg)
{
    if (msg == NULL)
        return;
    if (msg->function != NULL)
    {
        free(msg->function);
        msg->function = NULL;
    }
    if (msg->data != NULL)
    {
        free(msg->data);
        msg->data = NULL;
    }
}
