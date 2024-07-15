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

#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>

#include <sodium.h>

#include "map_priv.h"
#include "array_priv.h"
#include "utilities/exception.h"

const size_t GAP = 128; // approximate prime gap

size_t increment_capacity(size_t prev)
{
    size_t next = prev + GAP;
    for (size_t i = next; i < UINT64_MAX; i++) // find next prime, brute-force but good enough
    {
        size_t j;
        for (j = 2; j < i; j++)
        {
            if (i % j == 0)
                break;
        }
        if (j == i)
        {
            next = i;
            break;
        }
    }
    return next;
}

typedef uint64_t hash_t; // size must be synced with crypto_shorthash_BYTES

hash_t nacl_hash(map_t *map, map_key_t key)
{
    union
    {
        uint8_t hash_bytes[crypto_shorthash_BYTES]; // i.e. 8 bytes
        hash_t hash_int;
    } hash;
    crypto_shorthash(hash.hash_bytes, (const unsigned char *)key, strlen(key), map->hashkey);
    return hash.hash_int;
}

size_t djb_hash(map_key_t key)
{
    size_t hash = 5381;
    int c;
    while ((c = *key++))
    {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

size_t map_hash2index(map_t *map, hash_t hash)
{
#ifdef __SIZEOF_INT128__
    return (uint64_t)(((__uint128_t)hash * (__uint128_t)(map->capacity - 1)) >> 64);
#else
    return hash % (map->capacity - 1);
#endif
}

size_t map_key2index(map_t *map, map_key_t key)
{
    return map_hash2index(map, nacl_hash(map, key));
}

int reindex(map_t *map)
{
    size_t old_capacity = map->capacity;
    map->capacity = increment_capacity(map->capacity);
    map_item_t *items = smrt_create(map->capacity * sizeof(map_item_t));
    if (items == NULL)
        return EXCEPTION(ENOMEM);
    memset(items, 0, map->capacity * sizeof(map_item_t));
    for (size_t i = 0; i < old_capacity; i++)
    {
        map_item_t entry = map->items[i];
        if (entry.key != NULL && entry.key[0] != 0)
        {
            size_t idx = map_hash2index(map, entry.hash);
            items[idx] = entry;
        }
    }
    free(map->items); // no deref, force free
    map->items = items;
    return 0;
}

inline size_t map_size(map_t *map)
{
    return map->length;
}

int map_init(map_t *map)
{
    map->capacity = increment_capacity(0);
    map->length = 0;
    crypto_shorthash_keygen(map->hashkey);
    array_init(&map->keys);
    map->alloc = false;
    map->refs = 0;
    map->items = smrt_create(map->capacity * sizeof(map_item_t));
    if (map->items == NULL)
        return EXCEPTION(ENOMEM);
    return 0;
}

int map_create(map_t **map_ptr)
{
    if (map_ptr == NULL)
        return EXCEPTION(EINVAL);
    *map_ptr = smrt_create(sizeof(map_t));
    map_t *map = *map_ptr;
    if (map == NULL)
        return EXCEPTION(ENOMEM);

    int err = map_init(map);
    if (err != 0)
    {
        smrt_deref(map);
        return err;
    }
    return err;
}

array_t *map_keys(map_t *map)
{
    return &map->keys;
}

int map_get(map_t *map, const map_key_t key, data_t **value)
{
    size_t index = map_key2index(map, key);

    while (map->items[index].key != NULL)
    {
        if (strcmp(key, map->items[index].key) == 0)
        {
            *value = map->items[index].value;
            return 0;
        }
        index++;
        if (index >= map->capacity)
            index = 0;
    }
    return EXCEPTION(EMAP_NOKEY);
}

int map_set(map_t *map, const map_key_t key, data_t *value)
{
    if (value == NULL)
        return EXCEPTION(EINVAL);

    if (map->length >= 3 * map->capacity / 4)
    {
        if (reindex(map) != 0)
            return -1;
    }

    hash_t hash = nacl_hash(map, key);
    size_t index = map_hash2index(map, hash);

    // if the entry is already here, change it; otherwise find an empty slot nearby (hopefully)
    while (map->items[index].key != NULL)
    {
        if (strcmp(key, map->items[index].key) == 0)
        {
            smrt_ref(value);
            map->items[index].value = value;
            return 0;
        }
        index++;
        if (index >= map->capacity)
            index = 0;
    }

    // new entry
    map_item_t *item = &map->items[index];
    map_key_t key_cpy = strdup(key);
    if (key_cpy == NULL)
        return EXCEPTION(ENOMEM);
    // FIXME potential issues
    item->key = key_cpy; // FIXME ownership?
    item->hash = hash;
    smrt_ref(value);
    item->value = value;
    data_t *str_dat = string_data(key_cpy, strlen(key_cpy));
    int err = array_append(&map->keys, str_dat);
    if (err != 0)
        return err;
    map->length++;

    return 0;
}

int map_remove(map_t *map, map_key_t key)
{
    size_t index = map_key2index(map, key);
    map->length--;
    size_t tail_len = (map->length - index) * sizeof(map_item_t);
    memmove(map->items + index, map->items + index + 1, tail_len);
    return 0;
}

void map_free(map_t *map)
{
    smrt_deref(map->items);
    smrt_deref(map);
}

int map_sync_out(map_t *map, AutonomousTrust__Core__Protobuf__Structures__DataMap *dmap)
{
    size_t size = map_size(map);
    dmap->map = calloc(size, sizeof(AutonomousTrust__Core__Protobuf__Structures__DataMap__DataMapEntry));
    dmap->n_map = size;

    char *key;
    data_t *elt;
    size_t i = 0;
    map_entries_for_each(map, key, elt)
        AutonomousTrust__Core__Protobuf__Structures__DataMap__DataMapEntry *entry = dmap->map[i++];
    entry->key = key; // shared, do not free
    entry->value = malloc(sizeof(AutonomousTrust__Core__Protobuf__Structures__Data));
    data_sync_out(elt, entry->value);
    map_end_for_each return 0;
}

void map_proto_free(AutonomousTrust__Core__Protobuf__Structures__DataMap *dmap)
{
    for (int i = 0; i < dmap->n_map; i++)
        data_proto_free(dmap->map[i]->value);
    smrt_deref(dmap->map);
}

int map_sync_in(AutonomousTrust__Core__Protobuf__Structures__DataMap *dmap, map_t *map)
{
    for (int i = 0; i < dmap->n_map; i++)
    {
        data_t *elt = smrt_create(sizeof(data_t));
        if (elt == NULL)
            return EXCEPTION(ENOMEM);
        char *key = smrt_create(strlen(dmap->map[i]->key));
        if (key == NULL)
            return EXCEPTION(ENOMEM);
        strcpy(key, dmap->map[i]->key);
        data_sync_in(dmap->map[i]->value, elt);
        if (map_set(map, key, elt) != 0)
            return -1;
    }
    return 0;
}

int map_to_json(const void *data_struct, json_t **obj_ptr)
{
    const map_t *map = data_struct;
    *obj_ptr = json_object();
    json_t *obj = *obj_ptr;
    if (obj == NULL)
        return EXCEPTION(ENOMEM);

    json_object_set_new(obj, "length", json_integer(map->length));
    json_object_set_new(obj, "capacity", json_integer(map->capacity));
    json_t *hash_arr = json_array();
    for (int i = 0; i < crypto_shorthash_KEYBYTES; i++)
    {
        json_array_append(hash_arr, json_integer(map->hashkey[i]));
    }
    json_object_set_new(obj, "hashkey", hash_arr);

    json_t *keys;
    if (array_to_json(&map->keys, &keys) < 0)
        return -1;
    json_object_set_new(obj, "keys", keys);

    json_t *j_arr = json_array();
    for (int i = 0; i < map->capacity; i++)
    {
        json_t *elt;
        if (strlen(map->items[i].key) == 0)
            elt = json_null();
        else
        {
            elt = json_object();
            json_object_set_new(elt, "key", json_string(map->items[i].key));
            json_t *val;
            data_to_json(map->items[i].value, &val);
            json_object_set_new(elt, "value", val);
            json_object_set_new(elt, "hash", json_integer(map->items[i].hash));
        }
        json_array_append(j_arr, elt);
    }
    json_object_set_new(obj, "items", j_arr);
    return 0;
}

int map_from_json(const json_t *obj, void *data_struct)
{
    map_t *map = data_struct;
    map->length = json_integer_value(json_object_get(obj, "length"));
    map->capacity = json_integer_value(json_object_get(obj, "capacity"));
    map->items = smrt_create(map->capacity * sizeof(map_item_t));

    json_t *hash_arr = json_object_get(obj, "hashkey");
    for (int i = 0; i < crypto_shorthash_KEYBYTES; i++)
    {
        map->hashkey[i] = json_integer_value(json_array_get(hash_arr, i));
    }

    json_t *keys = json_object_get(obj, "keys");
    if (array_from_json(keys, &map->keys) < 0)
        return -1;

    json_t *j_arr = json_object_get(obj, "items");
    for (int i = 0; i < map->capacity; i++)
    {
        json_t *elt = json_array_get(j_arr, i);
        if (!json_is_null(elt))
        {
            map->items[i].hash = json_integer_value(json_object_get(elt, "hash"));
            const char *key = json_string_value(json_object_get(elt, "key"));
            map->items[i].key = malloc(strlen(key) + 1);
            strcpy(map->items[i].key, key);
            data_from_json(json_object_get(elt, "value"), map->items[i].value);
        }
    }
    return 0;
}
