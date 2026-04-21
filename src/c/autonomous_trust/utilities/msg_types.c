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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <jansson.h>

#include "msg_types_priv.h"
#include "logger.h"

#include "fleet/update_proposal.h"
#include "identity/identity_priv.h"
#include "processes/capabilities_priv.h"
#include "negotiation/task_priv.h"
#include "negotiation/task.pb-c.h"
#include "google/protobuf/any.pb-c.h"

/*@
  assigns \nothing;
  ensures \result >= 0;
*/
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
        return sizeof(capability_t) * DEFAULT_MAX_PEERS * MAX_CAPABILITIES;
    case NET_MESSAGE:
        return sizeof(net_msg_t);
    case TASK:
        return sizeof(task_t);
    case TASK_STATUS:
        return sizeof(task_status_msg_t);
    case TASK_RESULT:
        return sizeof(task_result_msg_t);
    case TRANSACTION_SCORE:
        return sizeof(tx_score_msg_t);
    case UPDATE_PROPOSAL:
        return sizeof(update_proposal_t);
    case UPDATE_VOTE:
        return sizeof(update_vote_msg_t);
    case UPDATE_ACCEPTED:
        return sizeof(update_accepted_msg_t);
#ifdef AT_ZTA_ENABLED
    case ZTA_REVOCATION_ALERT:
    case ZTA_VERIFICATION_RESULT:
        return sizeof(zta_event_msg_t);
#endif
    default:
        return 0;
    }
}

/*@
  assigns \nothing;
  ensures \result != \null;
  ensures \valid_read(\result);
*/
char *message_type_to_string(message_type_t type)
{
    switch (type)
    {
    case SIGNAL:
        return (char*)"SIGNAL";
    case GROUP:
        return (char*)autonomous_trust__core__protobuf__identity__group__descriptor.c_name;
    case PEER:
        return (char*)autonomous_trust__core__protobuf__identity__identity__descriptor.c_name;
    case PEER_CAPABILITIES:
        return (char*)autonomous_trust__core__protobuf__processes__peer_capabilities__descriptor.c_name;
    case TASK:
        return (char*)autonomous_trust__core__protobuf__negotiation__task__descriptor.c_name;
    case NET_MESSAGE:
        return (char*)"NET_MSG";
    case TASK_STATUS:
        return (char*)"TASK_STATUS";
    case TASK_RESULT:
        return (char*)"TASK_RESULT";
    case TRANSACTION_SCORE:
        return (char*)"TRANSACTION_SCORE";
    case UPDATE_PROPOSAL:
        return (char*)"UPDATE_PROPOSAL";
    case UPDATE_VOTE:
        return (char*)"UPDATE_VOTE";
    case UPDATE_ACCEPTED:
        return (char*)"UPDATE_ACCEPTED";
#ifdef AT_ZTA_ENABLED
    case ZTA_REVOCATION_ALERT:
        return (char*)"ZTA_REVOCATION_ALERT";
    case ZTA_VERIFICATION_RESULT:
        return (char*)"ZTA_VERIFICATION_RESULT";
#endif
    default:
        return (char*)"";
    }
}

/*@
  requires str != \null && \valid_read(str);
  assigns \nothing;
*/
message_type_t string_to_message_type(const char *str)
{
    if (strcmp(str, "SIGNAL") == 0)
        return SIGNAL;
    if (strcmp(str, autonomous_trust__core__protobuf__identity__group__descriptor.c_name) == 0)
        return GROUP;
    if (strcmp(str, autonomous_trust__core__protobuf__identity__identity__descriptor.c_name) == 0)
        return PEER;
    if (strcmp(str, autonomous_trust__core__protobuf__processes__peer_capabilities__descriptor.c_name) == 0)
        return PEER_CAPABILITIES;
    if (strcmp(str, autonomous_trust__core__protobuf__negotiation__task__descriptor.c_name) == 0)
        return TASK;
    if (strcmp(str, "NET_MSG") == 0)
        return NET_MESSAGE;
    if (strcmp(str, "TASK_STATUS") == 0)
        return TASK_STATUS;
    if (strcmp(str, "TASK_RESULT") == 0)
        return TASK_RESULT;
    if (strcmp(str, "TRANSACTION_SCORE") == 0)
        return TRANSACTION_SCORE;
    if (strcmp(str, "UPDATE_PROPOSAL") == 0)
        return UPDATE_PROPOSAL;
    if (strcmp(str, "UPDATE_VOTE") == 0)
        return UPDATE_VOTE;
    if (strcmp(str, "UPDATE_ACCEPTED") == 0)
        return UPDATE_ACCEPTED;
    return -1;  // No matching message type found (all valid types are > 0)
}

int signal_to_proto(const signal_t *msg, void **data_ptr, size_t *data_len_ptr)
{
    char data_str[1024];
    sprintf(data_str, "%d-%s", msg->sig, msg->descr);
    *data_len_ptr = strlen(data_str) + 1;
    *data_ptr = smrt_create(*data_len_ptr);
    strcpy(*data_ptr, data_str);
    return 0;
}

/* Frama-C: skipped — [solver-timeout] JSON + protobuf preconditions */
int net_msg_pack_json(net_msg_t *msg, json_t *json)
{
    char *str = json_dumps(json, JSON_COMPACT);
    if (str == NULL)
        return -1;
    size_t slen = strlen(str);
    msg->obj = smrt_create(slen + 1);
    if (msg->obj == NULL)
    {
        free(str);
        return EXCEPTION(ENOMEM);
    }
    memcpy(msg->obj, str, slen + 1);
    msg->len = slen;
    free(str);
    return 0;
}

int net_msg_unpack_json(const net_msg_t *msg, json_t **json)
{
    if (msg->obj == NULL || msg->len == 0)
        return -1;
    json_error_t error;
    *json = json_loads((const char *)msg->obj, 0, &error);
    if (*json == NULL)
        return -1;
    return 0;
}

/* Frama-C: skipped — [solver-timeout] protobuf serialization preconditions */
int net_msg_to_proto(const net_msg_t *msg, void **data_ptr, size_t *data_len_ptr)
{
    json_t *root = json_object();
    if (root == NULL)
        return -1;

    json_object_set_new(root, "process", json_string(msg->process));
    json_object_set_new(root, "function", json_string(msg->function ? msg->function : ""));
    json_object_set_new(root, "encrypt", json_boolean(msg->encrypt));
    json_object_set_new(root, "return_to", json_string(msg->return_to));

    char uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(msg->from_whom.uuid, uuid_str);
    json_object_set_new(root, "from_uuid", json_string(uuid_str));
    json_object_set_new(root, "from_name", json_string(msg->from_whom.fullname));
    json_object_set_new(root, "from_address", json_string(msg->from_whom.address));
    json_object_set_new(root, "from_sig_hex",
                        json_string((const char *)msg->from_whom.signature.public_hex));
    json_object_set_new(root, "from_enc_hex",
                        json_string((const char *)msg->from_whom.encryptor.public_hex));

    uuid_unparse_lower(msg->to_whom.uuid, uuid_str);
    json_object_set_new(root, "to_uuid", json_string(uuid_str));
    json_object_set_new(root, "to_name", json_string(msg->to_whom.fullname));
    json_object_set_new(root, "to_address", json_string(msg->to_whom.address));
    json_object_set_new(root, "to_sig_hex",
                        json_string((const char *)msg->to_whom.signature.public_hex));
    json_object_set_new(root, "to_enc_hex",
                        json_string((const char *)msg->to_whom.encryptor.public_hex));

    if (msg->obj != NULL && msg->len > 0)
    {
        json_object_set_new(root, "obj", json_stringn((const char *)msg->obj, msg->len));
        json_object_set_new(root, "obj_len", json_integer((json_int_t)msg->len));
    }

    char *str = json_dumps(root, JSON_COMPACT);
    json_decref(root);
    if (str == NULL)
        return -1;

    size_t slen = strlen(str);
    *data_ptr = smrt_create(slen + 1);
    if (*data_ptr == NULL)
    {
        free(str);
        return EXCEPTION(ENOMEM);
    }
    memcpy(*data_ptr, str, slen + 1);
    *data_len_ptr = slen;
    free(str);
    return 0;
}

/* Frama-C: skipped — [solver-timeout] protobuf wrapper preconditions */
int wrap_in_any(message_type_t type, void *data_in, size_t data_in_len, void **data_ptr, size_t *data_len_ptr)
{
    Google__Protobuf__Any pb_msg = GOOGLE__PROTOBUF__ANY__INIT;
    pb_msg.type_url = message_type_to_string(type);
    pb_msg.value.data = data_in;
    pb_msg.value.len = data_in_len;

    *data_len_ptr = google__protobuf__any__get_packed_size(&pb_msg);
    *data_ptr = smrt_create(*data_len_ptr);
    if (*data_ptr == NULL)
    {
        smrt_deref(data_in);
        return EXCEPTION(ENOMEM);
    }
    size_t packed = google__protobuf__any__pack(&pb_msg, *data_ptr);
    if (packed == 0)
    {
        smrt_deref(*data_ptr);
        return EXCEPTION(EINVAL);
    }
    smrt_deref(data_in);
    return 0;
}

/* Frama-C: skipped — [serialization] protobuf pack with dynamic type switch */
int generic_msg_to_proto(generic_msg_t *msg, void **data, size_t *data_len)
{
    void *subdata = NULL;
    size_t subdata_len = 0;
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
    case TASK_STATUS:
    {
        subdata_len = sizeof(task_status_msg_t);
        subdata = smrt_create(subdata_len);
        if (subdata == NULL) return EXCEPTION(ENOMEM);
        memcpy(subdata, &msg->info.task_status, subdata_len);
        break;
    }
    case TASK_RESULT:
    {
        subdata_len = sizeof(task_result_msg_t);
        subdata = smrt_create(subdata_len);
        if (subdata == NULL) return EXCEPTION(ENOMEM);
        memcpy(subdata, &msg->info.task_result, subdata_len);
        break;
    }
    case TRANSACTION_SCORE:
    {
        subdata_len = sizeof(tx_score_msg_t);
        subdata = smrt_create(subdata_len);
        if (subdata == NULL) return EXCEPTION(ENOMEM);
        memcpy(subdata, &msg->info.tx_score, subdata_len);
        break;
    }
    case UPDATE_VOTE:
    {
        subdata_len = sizeof(update_vote_msg_t);
        subdata = smrt_create(subdata_len);
        if (subdata == NULL) return EXCEPTION(ENOMEM);
        memcpy(subdata, &msg->info.update_vote, subdata_len);
        break;
    }
    case UPDATE_ACCEPTED:
    {
        subdata_len = sizeof(update_accepted_msg_t);
        subdata = smrt_create(subdata_len);
        if (subdata == NULL) return EXCEPTION(ENOMEM);
        memcpy(subdata, &msg->info.update_accepted, subdata_len);
        break;
    }
#ifdef AT_ZTA_ENABLED
    case ZTA_REVOCATION_ALERT:
    case ZTA_VERIFICATION_RESULT:
    {
        subdata_len = sizeof(zta_event_msg_t);
        subdata = smrt_create(subdata_len);
        if (subdata == NULL) return EXCEPTION(ENOMEM);
        memcpy(subdata, &msg->info.zta_event, subdata_len);
        break;
    }
#endif
    case UPDATE_PROPOSAL:
        /* UPDATE_PROPOSAL uses its own JSON serialization, not proto */
        return -1;
    default:
        return -1;
    }
    return wrap_in_any(msg->type, subdata, subdata_len, data, data_len);
}

int proto_to_signal(uint8_t *data, size_t len, signal_t *sig)
{
    if (data == NULL || sig == NULL || len == 0)
    {
        log_error(NULL, "proto_to_signal: null data/sig or zero len (len=%zu)\n", len);
        return EXCEPTION(EINVAL);
    }

    /* Find the "N-" separator within the first `len` bytes; the payload is
     * NOT guaranteed NUL-terminated (it is a raw protobuf value), so stay
     * inside `len` throughout. */
    const char *s = (const char *)data;
    size_t dash = 0;
    while (dash < len && s[dash] != '-')
        dash++;
    if (dash == 0 || dash >= len)
    {
        log_error(NULL, "proto_to_signal: malformed frame, no 'N-' separator in %zu bytes\n", len);
        return EXCEPTION(EINVAL);
    }

    /* Parse the integer prefix through strtol.  Cap the prefix at enough
     * digits to hold INT_MIN ("-2147483648" + NUL = 12 bytes). */
    char num_buf[16];
    if (dash >= sizeof(num_buf))
    {
        log_error(NULL, "proto_to_signal: signal int prefix %zu bytes exceeds limit\n", dash);
        return EXCEPTION(EINVAL);
    }
    memcpy(num_buf, s, dash);
    num_buf[dash] = '\0';

    char *endp = NULL;
    long v = strtol(num_buf, &endp, 10);
    if (endp == num_buf || *endp != '\0' || v < INT_MIN || v > INT_MAX)
    {
        log_error(NULL, "proto_to_signal: unparseable signal int '%s'\n", num_buf);
        return EXCEPTION(EINVAL);
    }
    sig->sig = (int)v;

    /* Copy the descr body bounded by BOTH the wire length and SIGNAL_LEN,
     * then explicitly NUL-terminate.  Stop at the first embedded NUL so we
     * do not copy protobuf padding. */
    size_t body_start = dash + 1;
    size_t body_len = len - body_start;
    if (body_len > SIGNAL_LEN)
        body_len = SIGNAL_LEN;
    size_t copy_len = 0;
    while (copy_len < body_len && s[body_start + copy_len] != '\0')
        copy_len++;
    memcpy(sig->descr, s + body_start, copy_len);
    sig->descr[copy_len] = '\0';

    return 0;
}

/* Frama-C: skipped — [solver-timeout] protobuf deserialization preconditions */
int proto_to_net_msg(uint8_t *data, size_t len, net_msg_t *net_msg)
{
    json_error_t error;
    json_t *root = json_loadb((const char *)data, len, 0, &error);
    if (root == NULL)
        return -1;

    const char *proc = json_string_value(json_object_get(root, "process"));
    if (proc)
        strncpy(net_msg->process, proc, PROC_NAME_LEN);

    const char *func = json_string_value(json_object_get(root, "function"));
    if (func && func[0] != '\0')
    {
        /* strcpy is bounded: the destination was just allocated for
         * strlen(func) + 1 bytes.  Not a missing-bounds-check site. */
        net_msg->function = smrt_create(strlen(func) + 1);
        if (net_msg->function != NULL)
            strcpy(net_msg->function, func);
    }

    net_msg->encrypt = json_boolean_value(json_object_get(root, "encrypt"));

    const char *ret = json_string_value(json_object_get(root, "return_to"));
    if (ret)
        strncpy(net_msg->return_to, ret, PROC_NAME_LEN);

    const char *from_uuid = json_string_value(json_object_get(root, "from_uuid"));
    if (from_uuid)
        uuid_parse(from_uuid, net_msg->from_whom.uuid);
    const char *from_name = json_string_value(json_object_get(root, "from_name"));
    if (from_name)
        strncpy(net_msg->from_whom.fullname, from_name, NAME_LEN);
    const char *from_addr = json_string_value(json_object_get(root, "from_address"));
    if (from_addr)
        strncpy(net_msg->from_whom.address, from_addr, ADDR_LEN);
    const char *from_sig = json_string_value(json_object_get(root, "from_sig_hex"));
    if (from_sig && from_sig[0] != '\0')
        public_signature_init(&net_msg->from_whom.signature, (const unsigned char *)from_sig);
    const char *from_enc = json_string_value(json_object_get(root, "from_enc_hex"));
    if (from_enc && from_enc[0] != '\0')
        public_encryptor_init(&net_msg->from_whom.encryptor, (const unsigned char *)from_enc);

    const char *to_uuid = json_string_value(json_object_get(root, "to_uuid"));
    if (to_uuid)
        uuid_parse(to_uuid, net_msg->to_whom.uuid);
    const char *to_name = json_string_value(json_object_get(root, "to_name"));
    if (to_name)
        strncpy(net_msg->to_whom.fullname, to_name, NAME_LEN);
    const char *to_addr = json_string_value(json_object_get(root, "to_address"));
    if (to_addr)
        strncpy(net_msg->to_whom.address, to_addr, ADDR_LEN);
    const char *to_sig = json_string_value(json_object_get(root, "to_sig_hex"));
    if (to_sig && to_sig[0] != '\0')
        public_signature_init(&net_msg->to_whom.signature, (const unsigned char *)to_sig);
    const char *to_enc = json_string_value(json_object_get(root, "to_enc_hex"));
    if (to_enc && to_enc[0] != '\0')
        public_encryptor_init(&net_msg->to_whom.encryptor, (const unsigned char *)to_enc);

    const char *obj_str = json_string_value(json_object_get(root, "obj"));
    json_int_t obj_len = json_integer_value(json_object_get(root, "obj_len"));
    if (obj_str && obj_len > 0)
    {
        net_msg->obj = smrt_create((size_t)obj_len + 1);
        if (net_msg->obj != NULL)
        {
            memcpy(net_msg->obj, obj_str, (size_t)obj_len);
            net_msg->obj[obj_len] = '\0';
            net_msg->len = (size_t)obj_len;
        }
    }

    json_decref(root);
    return 0;
}

/* Frama-C: skipped — [serialization] protobuf unpack with union unpacking */
int proto_to_generic_msg(void *data, size_t data_len, generic_msg_t *msg)
{
    Google__Protobuf__Any *pb_msg;

    pb_msg = google__protobuf__any__unpack(NULL, data_len, data);
    if (pb_msg == NULL)
        return -1; /* FIXME proper error code */

    message_type_t type = string_to_message_type(pb_msg->type_url);
    msg->type = type;
    msg->size = message_size(msg->type);
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
    case TASK_STATUS:
        memcpy(&msg->info.task_status, pb_msg->value.data, sizeof(task_status_msg_t));
        return 0;
    case TASK_RESULT:
        memcpy(&msg->info.task_result, pb_msg->value.data, sizeof(task_result_msg_t));
        return 0;
    case TRANSACTION_SCORE:
        memcpy(&msg->info.tx_score, pb_msg->value.data, sizeof(tx_score_msg_t));
        return 0;
    case UPDATE_VOTE:
        memcpy(&msg->info.update_vote, pb_msg->value.data, sizeof(update_vote_msg_t));
        return 0;
    case UPDATE_ACCEPTED:
        memcpy(&msg->info.update_accepted, pb_msg->value.data, sizeof(update_accepted_msg_t));
        return 0;
#ifdef AT_ZTA_ENABLED
    case ZTA_REVOCATION_ALERT:
    case ZTA_VERIFICATION_RESULT:
        memcpy(&msg->info.zta_event, pb_msg->value.data, sizeof(zta_event_msg_t));
        return 0;
#endif
    case UPDATE_PROPOSAL:
        /* UPDATE_PROPOSAL uses its own JSON serialization, not proto */
        return -1;
    default:
        return -1;
    }
    return 0;
}