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

#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>

#include <sodium.h>

#include "map_priv.h"
#include "array_priv.h"
#include "utilities/at_jansson.h"
#include "utilities/exception.h"

const size_t GAP = 128; // approximate prime gap

/*@
  requires prev <= UINT64_MAX - GAP;
  assigns \nothing;
  ensures \result > prev;
  ensures \result >= prev + GAP;
*/
/* Frama-C: skipped — [alloc-pattern] capacity growth with realloc */
size_t increment_capacity(size_t prev)
{
    size_t next = prev + GAP;
    /*@
      loop invariant next <= i;
      loop invariant i >= prev + GAP;
      loop assigns i, j, next;
      loop variant UINT64_MAX - i;
    */
    for (size_t i = next; i < UINT64_MAX; i++) // find next prime, brute-force but good enough
    {
        size_t j;
        /*@
          loop invariant 2 <= j <= i;
          loop assigns j;
          loop variant i - j;
        */
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

/*@
  requires \valid(map);
  requires \valid_read(key);
  assigns \nothing;
*/
/* Frama-C: skipped — [string-loop] iterates over key bytes for hashing */
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

/*@
  requires \valid_read(key);
  assigns \nothing;
*/
size_t djb_hash(map_key_t key)
{
    size_t hash = 5381;
    int c;
    /*@
      loop assigns hash, c, key;
    */
    while ((c = *key++))
    {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

/*@
  requires \valid(map);
  requires map->capacity > 0;
  assigns \nothing;
  ensures \result < map->capacity;
*/
size_t map_hash2index(map_t *map, hash_t hash)
{
    if (map->capacity <= 1)
        return 0;
#ifdef __SIZEOF_INT128__
    return (uint64_t)(((__uint128_t)hash * (__uint128_t)(map->capacity - 1)) >> 64);
#else
    return hash % (map->capacity - 1);
#endif
}

/*@
  requires \valid(map);
  requires \valid_read(key);
  requires map->capacity > 0;
  assigns \nothing;
  ensures \result < map->capacity;
*/
size_t map_key2index(map_t *map, map_key_t key)
{
    return map_hash2index(map, nacl_hash(map, key));
}

/*@
  requires \valid(map);
  requires map->items != \null;
  requires map->capacity > 0;
  requires map->length <= map->capacity;
  assigns map->capacity, map->items;
  behavior success:
    ensures \result == 0;
    ensures map->capacity > \old(map->capacity);
    ensures map->items != \null;
    ensures map->length <= map->capacity;
  behavior failure:
    ensures \result != 0;
  complete behaviors;
  disjoint behaviors;
*/
/* Frama-C: skipped — [alloc-pattern] realloc on capacity change */
int reindex(map_t *map)
{
    size_t old_capacity = map->capacity;
    map->capacity = increment_capacity(map->capacity);
    map_item_t *items = smrt_create(map->capacity * sizeof(map_item_t));
    if (items == NULL)
        return EXCEPTION(ENOMEM);
    memset(items, 0, map->capacity * sizeof(map_item_t));
    /*@
      loop invariant 0 <= i <= old_capacity;
      loop assigns i, items[0 .. map->capacity - 1];
      loop variant old_capacity - i;
    */
    for (size_t i = 0; i < old_capacity; i++)
    {
        map_item_t entry = map->items[i];
        if (entry.key != NULL && entry.key[0] != 0)
        {
            size_t idx = map_hash2index(map, entry.hash);
            /* Linear probe is guaranteed to terminate: reindex() runs at
             * the 75%-full threshold and grows capacity, so we always have
             * at least 25% empty slots to land in. */
            /*@
              loop invariant 0 <= idx < map->capacity;
              loop assigns idx;
            */
            while (items[idx].key != NULL)
            {
                idx++;
                if (idx >= map->capacity)
                    idx = 0;
            }
            items[idx] = entry;
        }
    }
    free(map->items); // no deref, force free
    map->items = items;
    //@ assert map->length <= map->capacity;
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
    //@ assert map->length == 0;
    //@ assert map->capacity > 0;
    //@ assert map->length <= map->capacity;
    return 0;
}

/* Frama-C: skipped — [solver-timeout] _set_exception precondition */
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

/* Frama-C: skipped — [solver-timeout] strcmp valid_string preconditions */
int map_get(map_t *map, const map_key_t key, data_t **value)
{
    size_t index = map_key2index(map, key);

    /*@
      loop invariant 0 <= i <= map->capacity;
      loop invariant 0 <= index < map->capacity;
      loop assigns i, index, *value;
      loop variant map->capacity - i;
    */
    for (size_t i = 0; i < map->capacity; i++)
    {
        if (map->items[index].key == NULL)
            break;
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

/* Frama-C: skipped — [alloc-pattern] hash bucket manipulation with realloc */
int map_set(map_t *map, const map_key_t key, data_t *value)
{
    if (value == NULL)
        return EXCEPTION(EINVAL);

    if (map->length >= 3 * map->capacity / 4)
    {
        if (reindex(map) != 0)
            return -1;
    }

    //@ assert map->length < map->capacity;
    hash_t hash = nacl_hash(map, key);
    size_t index = map_hash2index(map, hash);

    // if the entry is already here, change it; otherwise find an empty slot nearby (hopefully)
    /*@
      loop invariant 0 <= i <= map->capacity;
      loop invariant 0 <= index < map->capacity;
      loop assigns i, index, map->items[0 .. map->capacity - 1];
      loop variant map->capacity - i;
    */
    for (size_t i = 0; i < map->capacity; i++)
    {
        if (map->items[index].key == NULL)
            break;
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
    item->key = key_cpy; // map owns this strdup'd copy; freed in map_delete/map_free
    item->hash = hash;
    smrt_ref(value);
    item->value = value;
    data_t *str_dat = string_data(key_cpy, strlen(key_cpy));
    int err = array_append(&map->keys, str_dat);
    if (err != 0)
        return err;
    map->length++;

    //@ assert map->length <= map->capacity;
    return 0;
}

/* Frama-C: skipped — [alloc-pattern] hash bucket removal with memmove */
int map_remove(map_t *map, map_key_t key)
{
    size_t index = map_key2index(map, key);
    /* find the actual slot (handle collision chains) */
    size_t start = index;
    /*@
      loop invariant 0 <= index < map->capacity;
      loop assigns index, map->items[0 .. map->capacity - 1], map->length;
      loop variant map->capacity;
    */
    while (map->items[index].key != NULL)
    {
        if (strcmp(key, map->items[index].key) == 0)
        {
            free(map->items[index].key);
            map->items[index].key = NULL;
            map->items[index].value = NULL;
            map->items[index].hash = 0;
            map->length--;

            //@ assert map->length < \old(map->length);

            /* Backward-shift deletion: move subsequent entries in the
               same probe chain back to fill the gap, so that linear
               probing in map_get/map_set is not broken. */
            size_t empty = index;
            size_t j = (index + 1) % map->capacity;
            /*@
              loop invariant 0 <= j < map->capacity;
              loop invariant 0 <= empty < map->capacity;
              loop assigns j, empty, map->items[0 .. map->capacity - 1];
              loop variant map->capacity;
            */
            while (map->items[j].key != NULL)
            {
                size_t natural = map_hash2index(map, map->items[j].hash);
                /* Check if entry at j belongs at or before the empty slot
                   in the circular probe sequence. */
                bool should_move;
                if (empty <= j)
                    should_move = (natural <= empty || natural > j);
                else
                    should_move = (natural <= empty && natural > j);
                if (should_move)
                {
                    map->items[empty] = map->items[j];
                    map->items[j].key = NULL;
                    map->items[j].value = NULL;
                    map->items[j].hash = 0;
                    empty = j;
                }
                j = (j + 1) % map->capacity;
            }
            //@ assert map->length <= map->capacity;
            return 0;
        }
        index++;
        if (index >= map->capacity)
            index = 0;
        if (index == start)
            break;
    }
    return EXCEPTION(EMAP_NOKEY);
}

/* Frama-C: skipped — [solver-timeout] free/smrt_deref requires */
void map_free(map_t *map)
{
    /* WHY the two free phases are not interchangeable:
     *   map->items[i].key points into heap memory that was strdup'd when the
     *   entry was inserted (see map_set). Those key strings are independent
     *   allocations from the items array itself. We MUST free every key
     *   before smrt_deref'ing map->items, because once items is freed the
     *   items[i].key pointers are no longer dereferenceable — even reading
     *   them to pass to free() would be a use-after-free.
     *
     * Consequence: when composing map_free() inside a larger destructor that
     * frees other fields pointing into the items array (arrays, nested
     * maps), map_free() must be called LAST of the siblings, or the sibling
     * frees will clobber WP state that assumes items-backed memory is still
     * valid. See memory: reference_framac_free_ordering. */
    /*@
      loop invariant 0 <= i <= map->capacity;
      loop assigns i;
      loop variant map->capacity - i;
    */
    for (size_t i = 0; i < map->capacity; i++)
    {
        if (map->items[i].key != NULL)
            free(map->items[i].key);
    }
    smrt_deref(map->items);
    smrt_deref(map);
}

/* Frama-C: skipped — [serialization] protobuf serialization */
int map_sync_out(map_t *map, AutonomousTrust__Core__Protobuf__Structures__DataMap *dmap)
{
    //@ assert map->length <= map->capacity;
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

/* Frama-C: skipped — [serialization] protobuf cleanup */
void map_proto_free(AutonomousTrust__Core__Protobuf__Structures__DataMap *dmap)
{
    if (dmap->map == NULL)
        return;
    /*@
      loop invariant 0 <= i <= dmap->n_map;
      loop assigns i;
      loop variant dmap->n_map - i;
    */
    for (size_t i = 0; i < dmap->n_map; i++) {
        if (dmap->map[i] != NULL && dmap->map[i]->value != NULL)
            data_proto_free(dmap->map[i]->value);
    }
    free(dmap->map);
    dmap->map = NULL;
}

/* Frama-C: skipped — [serialization] protobuf deserialization */
int map_sync_in(AutonomousTrust__Core__Protobuf__Structures__DataMap *dmap, map_t *map)
{
    /*@
      loop invariant 0 <= i <= (int)dmap->n_map;
      loop assigns i, map->items[0 .. map->capacity - 1], map->length, map->capacity, map->keys;
      loop variant (int)dmap->n_map - i;
    */
    for (int i = 0; i < dmap->n_map; i++)
    {
        data_t *elt = smrt_create(sizeof(data_t));
        if (elt == NULL)
            return EXCEPTION(ENOMEM);
        char *key = smrt_create(strlen(dmap->map[i]->key) + 1);
        if (key == NULL)
            return EXCEPTION(ENOMEM);
        strcpy(key, dmap->map[i]->key);
        data_sync_in(dmap->map[i]->value, elt);
        if (map_set(map, key, elt) != 0)
            return -1;
    }
    return 0;
}

/* Frama-C: skipped — [serialization] jansson JSON serialization */
int map_to_json(const void *data_struct, json_t **obj_ptr)
{
    const map_t *map = data_struct;
    //@ assert \valid(map);
    //@ assert map->length <= map->capacity;
    *obj_ptr = json_object();
    json_t *obj = *obj_ptr;
    if (obj == NULL)
        return EXCEPTION(ENOMEM);

    json_object_set_new(obj, "length", json_integer(map->length));
    json_object_set_new(obj, "capacity", json_integer(map->capacity));
    json_t *hash_arr = json_array();
    /*@
      loop invariant 0 <= i <= crypto_shorthash_KEYBYTES;
      loop assigns i;
      loop variant crypto_shorthash_KEYBYTES - i;
    */
    for (int i = 0; i < crypto_shorthash_KEYBYTES; i++)
    {
        json_array_append_new(hash_arr, json_integer(map->hashkey[i]));
    }
    json_object_set_new(obj, "hashkey", hash_arr);

    json_t *keys;
    if (array_to_json(&map->keys, &keys) < 0)
        return -1;
    json_object_set_new(obj, "keys", keys);

    json_t *j_arr = json_array();
    /*@
      loop invariant 0 <= i <= (int)map->capacity;
      loop assigns i;
      loop variant (int)map->capacity - i;
    */
    for (int i = 0; i < map->capacity; i++)
    {
        json_t *elt;
        if (map->items[i].key == NULL || strlen(map->items[i].key) == 0)
            elt = json_null();
        else
        {
            elt = json_object();
            if (elt == NULL) {
                /* Fall back to null on allocator failure rather than
                 * propagating an inconsistent partially-built array. */
                elt = json_null();
            } else {
                json_object_set_new(elt, "key", json_string(map->items[i].key));
                json_t *val;
                data_to_json(map->items[i].value, &val);
                json_object_set_new(elt, "value", val);
                json_object_set_new(elt, "hash", json_integer(map->items[i].hash));
            }
        }
        json_array_append_new(j_arr, elt);
    }
    json_object_set_new(obj, "items", j_arr);
    return 0;
}

/* Frama-C: skipped — [serialization] jansson JSON deserialization */
int map_from_json(const json_t *obj, void *data_struct)
{
    map_t *map = data_struct;
    map->length = json_integer_value(json_object_get(obj, "length"));
    map->capacity = json_integer_value(json_object_get(obj, "capacity"));
    map->items = smrt_create(map->capacity * sizeof(map_item_t));

    json_t *hash_arr = json_object_get(obj, "hashkey");
    /*@
      loop invariant 0 <= i <= crypto_shorthash_KEYBYTES;
      loop assigns i, map->hashkey[0 .. crypto_shorthash_KEYBYTES - 1];
      loop variant crypto_shorthash_KEYBYTES - i;
    */
    for (int i = 0; i < crypto_shorthash_KEYBYTES; i++)
    {
        map->hashkey[i] = json_integer_value(json_array_get(hash_arr, i));
    }

    json_t *keys = json_object_get(obj, "keys");
    if (array_from_json(keys, &map->keys) < 0)
        return -1;

    json_t *j_arr = json_object_get(obj, "items");
    /*@
      loop invariant 0 <= i <= (int)map->capacity;
      loop assigns i, map->items[0 .. map->capacity - 1];
      loop variant (int)map->capacity - i;
    */
    for (int i = 0; i < map->capacity; i++)
    {
        json_t *elt = json_array_get(j_arr, i);
        if (!json_is_null(elt))
        {
            map->items[i].hash = json_integer_value(json_object_get(elt, "hash"));
            /* Guard against malformed input: a missing or non-string
             * "key" used to crash via strlen(NULL). Treat such an entry
             * as an empty slot and continue. */
            if (at_json_string_dup(elt, "key", &map->items[i].key) != 0) {
                map->items[i].key = NULL;
                continue;
            }
            map->items[i].value = calloc(1, sizeof(data_t));
            data_from_json(json_object_get(elt, "value"), map->items[i].value);
        }
    }
    //@ assert map->length <= map->capacity;
    return 0;
}
