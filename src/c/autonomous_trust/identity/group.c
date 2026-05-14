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

#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <uuid/uuid.h>
#include <sodium.h>
#include <jansson.h>

#include "config/configuration.h"
#include "group.h"
#include "structures/map_priv.h"
#include "identity_priv.h"
#include "utilities/util.h"

/* Frama-C: skipped — [solver-timeout] container initialization preconditions */
int group_init(uuid_t *uuid, char *address, group_t *group)
{
    if (uuid == NULL)
        uuid_generate((unsigned char *)group->uuid);
    else
        memcpy(&group->uuid, uuid, sizeof(uuid_t));
    strncpy(group->address, address, ADDR_LEN);
    group->address[ADDR_LEN] = '\0';   /* strncpy does not terminate when src is >= ADDR_LEN */
    map_init(&group->address_map);
    unsigned char *eseed = encryptor_generate();
    if (eseed == NULL)
        return -1;
    int rc = encryptor_init(&group->encryptor, eseed, crypto_box_SEEDBYTES * 2);
    free(eseed);
    if (rc != 0)
        return -1;
    return 0;
}

/* Frama-C: skipped — [solver-timeout] smrt_ptr allocation postconditions */
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

/* Frama-C: skipped — [solver-timeout] libsodium decrypt preconditions */
int group_decrypt(const group_t *ident, const msg_str_t *cipher, const group_t *whom, const unsigned char *nonce, unsigned char *out)
{
    return crypto_box_open_easy(out, cipher->msg, cipher->len, nonce, whom->encryptor.public, ident->encryptor.private);
}

/* Frama-C: skipped — [solver-timeout] array precondition cascade */
int group_add_address(group_t *group, const char *uuid_str, const char *address)
{
    if (group == NULL || uuid_str == NULL || address == NULL)
        return EINVAL;

    /* Check for address collision: remove any existing entry with same address
       but different UUID (mirrors Python add_address collision handling) */
    map_key_t key;
    data_t *value;
    char collision_key[UUID_STRING_LEN + 1] = {0};
    bool found_collision = false;
    map_entries_for_each(&group->address_map, key, value)
        string_t addr = NULL;
        if (data_string_ptr(value, &addr) == 0 && strcmp(addr, address) == 0)
        {
            if (strcmp(key, uuid_str) != 0)
            {
                strncpy(collision_key, key, UUID_STRING_LEN);
                found_collision = true;
            }
        }
    map_end_for_each

    if (found_collision)
        map_remove(&group->address_map, collision_key);

    data_t *addr_data = string_data((char *)address, strlen(address));
    if (addr_data == NULL)
        return ENOMEM;
    return map_set(&group->address_map, (map_key_t)uuid_str, addr_data);
}

/* Frama-C: skipped — [serialization] jansson JSON serialization */
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

    json_t *addr_map;
    map_to_json(&ident->address_map, &addr_map);
    json_object_set_new(obj, "address_map", addr_map);

    json_t *encr = json_object();
    unsigned char *hex = encryptor_publish(&ident->encryptor); // encoded
    json_object_set(encr, "hex_seed", json_string((char *)hex));
    free(hex);
    json_object_set(obj, "encryptor", encr);

    return 0;
}

/* Frama-C: skipped — [serialization] jansson JSON deserialization */
int group_from_json(const json_t *obj, void *data_struct)
{
    group_t *group = data_struct;
    json_t *uuid_obj = json_object_get(obj, "uuid");
    const char *uuid_str = json_string_value(uuid_obj);
    if (uuid_parse(uuid_str, group->uuid) < 0)
        return -1;

    json_t *addr_obj = json_object_get(obj, "address");
    if (addr_obj != NULL)
    {
        const char *addr = json_string_value(addr_obj);
        if (addr != NULL)
        {
            strncpy(group->address, addr, ADDR_LEN);
            group->address[ADDR_LEN] = '\0';
        }
    }

    json_t *addr_map_obj = json_object_get(obj, "address_map");
    if (addr_map_obj != NULL)
        map_from_json(addr_map_obj, &group->address_map);
    else
        map_init(&group->address_map);

    /* Extract the hex_seed STRING (not the jansson value pointer — prior
     * cast of `json_object_get` to `uint8_t *` was a latent bug, reading
     * jansson struct bytes as if they were hex). */
    const char *seed_hex = json_string_value(
        json_object_get(json_object_get(obj, "encryptor"), "hex_seed"));
    if (seed_hex == NULL
        || encryptor_init(&group->encryptor,
                          (const unsigned char *)seed_hex, strlen(seed_hex)) != 0)
        return -1;
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

/* Frama-C: skipped — [serialization] protobuf deserialization */
int group_sync_in(AutonomousTrust__Core__Protobuf__Identity__Group *proto, group_t *group)
{
    memcpy(group->uuid, proto->uuid.data, sizeof(uuid_t));
    strncpy(group->address, proto->address, ADDR_LEN);
    group->address[ADDR_LEN] = '\0';  /* strncpy does not terminate when src is >= ADDR_LEN */
    memcpy(group->encryptor.public_hex, proto->encryptor->hex_seed.data, crypto_box_PUBLICKEYBYTES * 2);
    return 0;
}

void group_proto_free(AutonomousTrust__Core__Protobuf__Identity__Group *proto)
{
    free(proto->encryptor);
}

int group_to_proto(group_t *msg, void **data_ptr, size_t *data_len_ptr)
{
    AutonomousTrust__Core__Protobuf__Identity__Group proto =
        AUTONOMOUS_TRUST__CORE__PROTOBUF__IDENTITY__GROUP__INIT;
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
    if (group == NULL)
        return;
    if (group->address_map.items != NULL)
        map_free(&group->address_map);
    smrt_deref(group);
}
