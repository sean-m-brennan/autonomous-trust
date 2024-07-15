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

#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <uuid/uuid.h>
#include <sodium.h>
#include <jansson.h>

#include "config/configuration.h"
#include "group.h"
#include "identity_priv.h"
#include "utilities/util.h"

int group_init(uuid_t *uuid, char *address, group_t *group)
{
    if (uuid == NULL)
        uuid_generate((unsigned char *)group->uuid);
    else
        memcpy(&group->uuid, uuid, sizeof(uuid_t));
    strncpy(group->address, address, ADDR_LEN);
    unsigned char *eseed = encryptor_generate();
    if (eseed == NULL)
        return -1;
    encryptor_init(&group->encryptor, eseed);
    smrt_deref(eseed);
    return 0;
}

int group_create(uuid_t *uuid, char *address, group_t **grp)
{
    *grp = smrt_create(sizeof(group_t));
    group_t *group = *grp;
    if (group == NULL)
        return EXCEPTION(ENOMEM);

    return group_init(uuid, address, group);
}

int group_encrypt(const group_t *ident, const msg_str_t *in, const group_t *whom, const unsigned char *nonce, unsigned char *cipher)
{
    return crypto_box_easy(cipher, in->msg, in->len, nonce, whom->encryptor.public, ident->encryptor.private);
}

int group_decrypt(const group_t *ident, const msg_str_t *cipher, const group_t *whom, const unsigned char *nonce, unsigned char *out)
{
    return crypto_box_open_easy(out, cipher->msg, cipher->len, nonce, whom->encryptor.public, ident->encryptor.private);
}

int group_to_json(const void *data_struct, json_t **obj_ptr)
{
    const group_t *ident = data_struct;
    *obj_ptr = json_object();
    json_t *obj = *obj_ptr;
    if (obj == NULL)
        return EXCEPTION(ENOMEM);
 
    int err = json_object_set_new(obj, "typename", json_string("group"));
    if (err != 0)
        return EXCEPTION(EJSN_OBJ_SET);
 
    char uuid_str[UUID_STRING_LEN+1] = {0};
    uuid_unparse(ident->uuid, uuid_str);
    json_object_set(obj, "uuid", json_string(uuid_str));
    json_object_set(obj, "address", json_string((char *)ident->address));

    json_t *encr = json_object();
    unsigned char *hex = encryptor_publish(&ident->encryptor); // encoded
    json_object_set(encr, "hex_seed", json_string((char *)hex));
    smrt_deref(hex);
    json_object_set(obj, "encryptor", encr);

    return 0;
}

int group_from_json(const json_t *obj, void *data_struct)
{
    group_t *group = data_struct;
    json_t *uuid_obj = json_object_get(obj, "uuid");
    const char *uuid_str = json_string_value(uuid_obj);
    if (uuid_parse(uuid_str, group->uuid) < 0)
        return -1;
    uint8_t *seed = (uint8_t *)json_object_get(json_object_get(obj, "encryptor"), "hex_seed");
    encryptor_init(&group->encryptor, seed); // decoded
    return 0;
}

DECLARE_CONFIGURATION(group, sizeof(group_t), group_to_json, group_from_json);

int group_sync_out(group_t *group, AutonomousTrust__Core__Protobuf__Identity__Group *proto)
{
    proto->uuid.data = group->uuid;
    proto->uuid.len = sizeof(uuid_t);
    proto->address = group->address;

    proto->encryptor = malloc(sizeof(AutonomousTrust__Core__Protobuf__Identity__Encryptor));
    AutonomousTrust__Core__Protobuf__Identity__Encryptor tmp_e = AUTONOMOUS_TRUST__CORE__PROTOBUF__IDENTITY__ENCRYPTOR__INIT;
    memcpy(proto->encryptor, &tmp_e, sizeof(tmp_e));
    proto->encryptor->hex_seed.data = group->encryptor.public_hex;
    proto->encryptor->hex_seed.len = crypto_box_PUBLICKEYBYTES * 2;
    return 0;
}

int group_sync_in(AutonomousTrust__Core__Protobuf__Identity__Group *proto, group_t *group)
{
    memcpy(group->uuid, proto->uuid.data, sizeof(uuid_t));
    strncpy(group->address, proto->address, ADDR_LEN);
    memcpy(group->encryptor.public_hex, proto->encryptor->hex_seed.data, crypto_box_PUBLICKEYBYTES * 2);
    return 0;
}

void group_proto_free(AutonomousTrust__Core__Protobuf__Identity__Group *proto)
{
    free(proto->encryptor);
}

int group_to_proto(group_t *msg, void **data_ptr, size_t *data_len_ptr)
{
    AutonomousTrust__Core__Protobuf__Identity__Group proto;
    group_sync_out(msg, &proto);
    *data_len_ptr = autonomous_trust__core__protobuf__identity__group__get_packed_size(&proto);
    *data_ptr = smrt_create(*data_len_ptr);
    if (*data_ptr == NULL)
        return EXCEPTION(ENOMEM);
    autonomous_trust__core__protobuf__identity__group__pack(&proto, *data_ptr);
    group_proto_free(&proto);
    return 0;
}

int proto_to_group(uint8_t *data, size_t len, group_t *group)
{
    AutonomousTrust__Core__Protobuf__Identity__Group *msg =
        autonomous_trust__core__protobuf__identity__group__unpack(NULL, len, data);
    group_sync_in(msg, group);
    free(msg);
    return 0;
}

void group_free(group_t *group)
{
    smrt_deref(group);
}
