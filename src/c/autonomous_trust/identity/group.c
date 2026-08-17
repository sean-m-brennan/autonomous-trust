/********************
 *  Copyright 2024 TekFive, Inc., Sean M. Brennan, and contributors
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
#include <time.h>
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
    int rc = crypto_box_open_easy(out, cipher->msg, cipher->len, nonce,
                                  whom->encryptor.public, ident->encryptor.private);
    if (rc == 0)
        return rc;
    /* A rotation is not synchronous across a cohort: a member that has not yet
     * processed the key update is still sending under the old one. Retry the
     * recently retired keys rather than drop those frames. Bounded by age, so a
     * retired key stops working soon after it is retired — an unbounded
     * fallback would make rotation decorative. Mirrors Python Group.decrypt. */
    double stamp = (double)time(NULL);
    for (size_t i = 0; i < ident->num_previous_keys; i++)
    {
        if (stamp - ident->previous_retired_at[i] > GROUP_PREVIOUS_KEY_GRACE)
            continue;
        if (crypto_box_open_easy(out, cipher->msg, cipher->len, nonce,
                                 whom->encryptor.public,
                                 ident->previous_keys[i].private) == 0)
            return 0;
    }
    return rc;
}

/* Whether this group holds the shared PRIVATE key (and can therefore decrypt
 * cohort traffic). Same predicate group_to_json uses to decide which key to
 * emit — one spelling, so "we own this group" cannot mean two things. Mirrors
 * Python Group.owns_private_key. */
static bool _group_owns_private(const group_t *group)
{
    return group != NULL
        && !sodium_is_zero(group->encryptor.private, crypto_box_SECRETKEYBYTES);
}

/* Mint a fresh shared key, retiring the current one into the grace window.
 * Returns the new epoch, or -1 when we do not hold the current private key —
 * a public-only view of somebody else's group has no standing to rotate it,
 * and silently minting a key here would fork the cohort into two halves that
 * cannot hear each other. Mirrors Python Group.rotate_key. */
int64_t group_rotate_key(group_t *group)
{
    if (!_group_owns_private(group))
        return -1;
    size_t keep = group->num_previous_keys;
    if (keep > GROUP_PREVIOUS_KEY_MAX - 1)
        keep = GROUP_PREVIOUS_KEY_MAX - 1;
    for (size_t i = keep; i > 0; i--)
    {
        group->previous_keys[i] = group->previous_keys[i - 1];
        group->previous_retired_at[i] = group->previous_retired_at[i - 1];
    }
    group->previous_keys[0] = group->encryptor;
    group->previous_retired_at[0] = (double)time(NULL);
    group->num_previous_keys = keep + 1;

    unsigned char *seed = encryptor_generate();
    if (seed == NULL)
        return -1;
    int rc = encryptor_init_from_private(&group->encryptor, seed,
                                         crypto_box_SECRETKEYBYTES * 2);
    free(seed);
    if (rc != 0)
        return -1;
    group->key_epoch += 1;
    return group->key_epoch;
}

/* Adopt @p other's shared key if it supersedes ours. Same group, strictly
 * higher epoch, and the sender must actually hold the private key — an equal
 * or lower epoch is a replay, and accepting one would let a captured old key be
 * reinstated over a newer one, which is precisely what rotation forecloses.
 * Authenticating WHO may rotate is the caller's job. Mirrors Python
 * Group.accept_rotation. */
bool group_accept_rotation(group_t *group, const group_t *other)
{
    if (group == NULL || other == NULL)
        return false;
    if (uuid_compare(group->uuid, other->uuid) != 0)
        return false;
    if (other->key_epoch <= group->key_epoch)
        return false;
    if (!_group_owns_private(other))
        return false;
    if (_group_owns_private(group))
    {
        size_t keep = group->num_previous_keys;
        if (keep > GROUP_PREVIOUS_KEY_MAX - 1)
            keep = GROUP_PREVIOUS_KEY_MAX - 1;
        for (size_t i = keep; i > 0; i--)
        {
            group->previous_keys[i] = group->previous_keys[i - 1];
            group->previous_retired_at[i] = group->previous_retired_at[i - 1];
        }
        group->previous_keys[0] = group->encryptor;
        group->previous_retired_at[0] = (double)time(NULL);
        group->num_previous_keys = keep + 1;
    }
    group->encryptor = other->encryptor;
    group->key_epoch = other->key_epoch;
    return true;
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

    /* DRY canonical: emit address_map as a FLAT {uuid: addr} object (mirrors
     * Python's _address_map dict), NOT map_to_json's verbose internal hashmap
     * dump — so a Python peer can parse it and vice versa. */
    json_t *addr_map = json_object();
    if (addr_map == NULL)
        return EXCEPTION(ENOMEM);
    {
        map_key_t key;
        data_t *value;
        map_entries_for_each((map_t *)&ident->address_map, key, value)
            string_t addr_s = NULL;
            if (data_string_ptr(value, &addr_s) == 0 && addr_s != NULL)
                json_object_set_new(addr_map, (const char *)key,
                                    json_string((const char *)addr_s));
        map_end_for_each
    }
    json_object_set_new(obj, "address_map", addr_map);

    json_t *encr = json_object();
    if (encr == NULL)
        return EXCEPTION(ENOMEM);
    /* DRY canonical group-key form (matches Python Encryptor.to_dict): when we
     * own the shared private key, serialize the RAW private key so a peer can
     * decrypt group traffic (full_history is box-encrypted in transit); when
     * public-only, emit the public key. `public_only` disambiguates on read —
     * both keys are 64 hex chars. (The prior code always wrote the PUBLIC key
     * but group_from_json read it as a seed, so the keypair never round-tripped.) */
    bool has_private = !sodium_is_zero(ident->encryptor.private, crypto_box_SECRETKEYBYTES);
    unsigned char *hex = has_private
                             ? encryptor_serialize_private(&ident->encryptor)
                             : encryptor_publish(&ident->encryptor);
    if (hex == NULL)
    {
        json_decref(encr);
        return EXCEPTION(ENOMEM);
    }
    json_object_set_new(encr, "hex_seed", json_string((char *)hex));
    json_object_set_new(encr, "public_only", json_boolean(!has_private));
    free(hex);
    json_object_set_new(obj, "encryptor", encr);

    /* Group age (§3.1-b) for the merge size-tie tiebreaker. Mirrors Python
     * to_canonical's "created". Omitted-on-read defaults to 0 (unknown → uuid
     * tiebreak), so a peer that doesn't send it stays compatible. */
    json_object_set_new(obj, "created", json_real(ident->created));
    /* Key rotation epoch (ISSUES.md 10.2). Additive and defaulted on read, so
     * a peer predating rotation sends nothing and reads as epoch 0 — which is
     * exactly "never rotated" and needs no special case. Mirrors Python
     * to_canonical's "key_epoch". */
    json_object_set_new(obj, "key_epoch", json_integer(ident->key_epoch));

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

    /* DRY canonical: parse the FLAT {uuid: addr} address_map (see
     * group_to_json). group_add_address handles map_set + collision. */
    map_init(&group->address_map);
    json_t *addr_map_obj = json_object_get(obj, "address_map");
    if (addr_map_obj != NULL && json_is_object(addr_map_obj))
    {
        const char *k;
        json_t *v;
        json_object_foreach(addr_map_obj, k, v)
        {
            const char *addr = json_string_value(v);
            if (addr != NULL)
                group_add_address(group, k, addr);
        }
    }

    /* Extract the hex_seed STRING (not the jansson value pointer — prior
     * cast of `json_object_get` to `uint8_t *` was a latent bug, reading
     * jansson struct bytes as if they were hex). */
    json_t *encr_obj = json_object_get(obj, "encryptor");
    const char *seed_hex = json_string_value(json_object_get(encr_obj, "hex_seed"));
    if (seed_hex == NULL)
        return -1;
    /* DRY canonical: `public_only` selects how to read hex_seed. When false
     * (we received the shared private key), reconstruct from the RAW private
     * key (crypto_scalarmult_base); when true, it's a public key. Absent flag
     * (legacy/public-only peers) defaults to public-only. Mirrors C
     * group_to_json + Python Encryptor.to_dict/from on the wire. */
    json_t *po = json_object_get(encr_obj, "public_only");
    bool public_only = (po == NULL) ? true : json_boolean_value(po);
    int rc = public_only
                 ? public_encryptor_init(&group->encryptor,
                                         (const unsigned char *)seed_hex, strlen(seed_hex))
                 : encryptor_init_from_private(&group->encryptor,
                                               (const unsigned char *)seed_hex, strlen(seed_hex));
    if (rc != 0)
        return -1;

    /* Group age (§3.1-b): absent defaults to 0 (unknown → uuid tiebreak). */
    json_t *created_obj = json_object_get(obj, "created");
    group->created = (created_obj != NULL && json_is_number(created_obj))
                     ? json_number_value(created_obj) : 0.0;
    json_t *epoch_obj = json_object_get(obj, "key_epoch");
    group->key_epoch = (epoch_obj != NULL && json_is_integer(epoch_obj))
                       ? json_integer_value(epoch_obj) : 0;
    return 0;
}

DECLARE_CONFIGURATION(group, sizeof(group_t), group_to_json, group_from_json);

int group_sync_out(group_t *group, AutonomousTrust__Core__Protobuf__Identity__Group *proto)
{
    proto->uuid.data = group->uuid;
    proto->uuid.len = sizeof(uuid_t);
    proto->address = group->address;
    proto->created = group->created;  /* §3.1-b group age */

    /* Full address_map (§1.4) as a proto3 map (repeated key/value entries).
     * Keys/values are SHARED with group->address_map: group_to_proto packs
     * immediately, and group_proto_free releases only the entry structs + the
     * array, never the shared strings (which the map still owns). */
    size_t n = map_size(&group->address_map);
    proto->n_address_map = 0;
    proto->address_map = NULL;
    if (n > 0)
    {
        proto->address_map = calloc(
            n, sizeof(AutonomousTrust__Core__Protobuf__Identity__Group__AddressMapEntry *));
        if (proto->address_map == NULL)
            return EXCEPTION(ENOMEM);
        map_key_t key;
        data_t *value;
        size_t i = 0;
        map_entries_for_each(&group->address_map, key, value)
            string_t addr_s = NULL;
            if (data_string_ptr(value, &addr_s) == 0 && addr_s != NULL)
            {
                AutonomousTrust__Core__Protobuf__Identity__Group__AddressMapEntry *entry =
                    calloc(1, sizeof(*entry));
                if (entry == NULL)
                    return EXCEPTION(ENOMEM);
                AutonomousTrust__Core__Protobuf__Identity__Group__AddressMapEntry tmp_m =
                    AUTONOMOUS_TRUST__CORE__PROTOBUF__IDENTITY__GROUP__ADDRESS_MAP_ENTRY__INIT;
                memcpy(entry, &tmp_m, sizeof(tmp_m));
                entry->key = (char *)key;       /* shared, not freed here */
                entry->value = (char *)addr_s;  /* shared, not freed here */
                proto->address_map[i++] = entry;
            }
        map_end_for_each
        proto->n_address_map = i;
    }

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
    group->created = proto->created;  /* §3.1-b group age */

    /* Rebuild the full address_map (§1.4). proto_to_group deserializes into a
     * fresh (zeroed) group, so initialise the map before populating it. */
    map_init(&group->address_map);
    for (size_t i = 0; i < proto->n_address_map; i++)
    {
        AutonomousTrust__Core__Protobuf__Identity__Group__AddressMapEntry *entry = proto->address_map[i];
        if (entry != NULL && entry->key != NULL && entry->value != NULL)
            group_add_address(group, entry->key, entry->value);
    }
    memcpy(group->encryptor.public_hex, proto->encryptor->hex_seed.data, crypto_box_PUBLICKEYBYTES * 2);
    return 0;
}

void group_proto_free(AutonomousTrust__Core__Protobuf__Identity__Group *proto)
{
    /* Free the entry structs + the array only; the key/value strings are shared
     * with group->address_map (see group_sync_out) and are owned by the map. */
    for (size_t i = 0; i < proto->n_address_map; i++)
        free(proto->address_map[i]);
    free(proto->address_map);
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
