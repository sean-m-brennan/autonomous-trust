#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <strings.h>

#include <sodium.h>

#include "map_priv.h"
#include "array_priv.h"

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

size_t key2index(map_t *map, map_key_t key)
{
    typedef uint64_t hash_t; // 8 bytes, sync with crypto_shorthash_BYTES size
    uint8_t byte_len = crypto_shorthash_BYTES;

    unsigned char hash[byte_len];
    crypto_shorthash(hash, (const unsigned char *)key, strlen(key), map->hashkey);
    hash_t hash_int = 0;
    for (int8_t i = byte_len - 1, shift = 0; i >= 0; i--)
    {
        hash_int |= hash[i] << shift; // FIXME wrong?
        shift += 8;
    }
    return (size_t)(hash_int & (hash_t)(map->capacity - 1));
}

int reindex(map_t *map)
{
    map_item_t *old = calloc(map->capacity, sizeof(map_item_t));
    memcpy(old, map->items, map->capacity * sizeof(map_item_t));
    bzero(map->items, map->capacity * sizeof(map_item_t));
    for (size_t i = 0; i < map->capacity; i++)
    {
        if (old[i].key[0] != 0)
        {
            size_t idx = key2index(map, old[i].key);
            map->items[idx] = old[i];
        }
    }
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
    map->items = calloc(map->capacity, sizeof(map_item_t));
    if (map->items == NULL)
        return ENOMEM;
    return 0;
}

int map_create(map_t **map_ptr)
{
    if (map_ptr == NULL)
        return EINVAL;
    *map_ptr = calloc(1, sizeof(map_t));
    map_t *map = *map_ptr;
    if (map == NULL)
        return ENOMEM;

    int err = map_init(map);
    if (err != 0)
        free(map);
    map->alloc = true;
    return err;
}

array_t *map_keys(map_t *map)
{
    return &map->keys;
}

int map_get(map_t *map, const map_key_t key, data_t *value)
{
    size_t index = key2index(map, key);

    if (!array_contains(&map->keys, (void *)key))
        return -1;

    while (index < map->capacity)
    {
        if (strcmp(key, map->items[index].key) == 0) {
            memcpy(value, &map->items[index].value, sizeof(data_t));
            return 0;
        }
        index++;
    }
    return -1;
}

int map_set(map_t *map, const map_key_t key, const data_t *value)
{
    if (value == NULL)
        return EINVAL;

    if (map->length >= map->capacity - 1) // always leave room at the end
    {
        map->capacity = increment_capacity(map->capacity);
        map_item_t *items = realloc(map->items, map->capacity * sizeof(map_item_t));
        if (items == NULL)
            return ENOMEM;
        map->items = items; // FIXME rehash?
    }

    size_t index = key2index(map, key);

    while (index < map->length)
    {
        if (strcmp(key, map->items[index].key) == 0)  // FIXME Access not within mapped region at address 0x0
        {
            memcpy(&map->items[index].value, value, sizeof(data_t));
            return 0;
        }
        index++;
    }

    map_key_t key_cpy = strdup(key);
    if (key_cpy == NULL)
        return ENOMEM;
    // FIXME potential issues
    map->items[index].key = key_cpy;
    memcpy(&map->items[index].value, value, sizeof(data_t));
    data_t str_dat = sdat(key_cpy);
    int err = array_append(&map->keys, &str_dat);
    if (err != 0)
        return err;
    map->length++;

    return 0;
}

int map_remove(map_t *map, map_key_t key)
{
    size_t index = key2index(map, key);
    map->length--;
    size_t tail_len = (map->length - index) * sizeof(map_item_t);
    memmove(map->items + index, map->items + index + 1, tail_len);
    return 0;
}

void map_free(map_t *map)
{
    free(map->items);
    if (map->alloc)
        free(map);
}
