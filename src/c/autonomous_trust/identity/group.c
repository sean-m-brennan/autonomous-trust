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
#include "identity_priv.h"


int group_init(group_t *group)
{
    AutonomousTrust__Core__Identity__Group tmp = AUTONOMOUS_TRUST__CORE__IDENTITY__GROUP__INIT;
    memcpy(&group->proto, &tmp, sizeof(group->proto));
    group->proto.uuid.data = group->uuid;
    group->proto.uuid.len = sizeof(uuid_t);
    group->proto.address = group->address;
    group->proto.encryptor->hex_seed.data = group->encryptor.public_hex;
    group->proto.encryptor->hex_seed.len = group->encryptor.proto.hex_seed.len;
    return 0;
}

int group_create(char *address, group_t **grp)
{
    *grp = calloc(1, sizeof(group_t));
    group_t *group = *grp;
    if (group == NULL)
        return EXCEPTION(ENOMEM);

    unsigned char *eseed = encryptor_generate();
    if (eseed == NULL)
        return -1;
    encryptor_init(&group->encryptor, eseed);
    free(eseed);

    uuid_generate((unsigned char *)group->uuid);

    group_init(group);
    return 0;
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
    group_t *ident = (group_t *)data_struct;
    *obj_ptr = json_object();
    json_t *obj = *obj_ptr;
    if (obj == NULL)
        return ENOMEM;
    char uuid_str[37] = {0};
    uuid_unparse(ident->uuid, uuid_str);
    json_object_set(obj, "uuid", json_string(uuid_str));
    json_object_set(obj, "address", json_string((char *)ident->address));

    json_t *encr = json_object();
    unsigned char *hex = encryptor_publish(&ident->encryptor); // encoded
    json_object_set(encr, "hex_seed", json_string((char *)hex));
    free(hex);
    json_object_set(obj, "encryptor", encr);

    return 0;
}

int group_from_json(const json_t *obj, void *data_struct)
{
    group_t *group = (group_t *)data_struct;
    json_t *uuid_obj = json_object_get(obj, "uuid");
    const char *uuid_str = json_string_value(uuid_obj);
    if (uuid_parse(uuid_str, group->uuid) < 0)
        return -1;
    uint8_t *seed = (uint8_t *)json_object_get(json_object_get(obj, "encryptor"), "hex_seed");
    encryptor_init(&group->encryptor, seed); // decoded
    group_init(group);
    return 0;
}

DECLARE_CONFIGURATION(group, sizeof(group_t), group_to_json, group_from_json);

int group_to_proto(const group_t *msg, void **data_ptr, size_t *data_len_ptr)
{
    *data_len_ptr = autonomous_trust__core__identity__group__get_packed_size(&msg->proto);
    *data_ptr = malloc(*data_len_ptr);
    if (*data_ptr == NULL)
        return EXCEPTION(ENOMEM);
    autonomous_trust__core__identity__group__pack(&msg->proto, *data_ptr);
    return 0;
}

int proto_to_group(uint8_t *data, size_t len, group_t *group)
{
    AutonomousTrust__Core__Identity__Group *msg =
        autonomous_trust__core__identity__group__unpack(NULL, len, data);
    memcpy(&group->proto, msg, sizeof(group->proto));
    free(msg);
    return 0;
}

void group_free(group_t *group)
{
    free(group);
}
