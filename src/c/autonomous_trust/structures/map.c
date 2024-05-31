#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <strings.h>

#include <sodium.h>

#include "map.h"
#include "array.h"

struct map_s
{
    map_item_t *items;
    size_t length;
    size_t capacity;
    array_t *keys;
    unsigned char hashkey[crypto_shorthash_KEYBYTES];
};

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
    size_t byte_len = crypto_shorthash_BYTES;

    unsigned char hash[byte_len];
    crypto_shorthash(hash, (const unsigned char *)key, strlen(key), map->hashkey);
    hash_t hash_int = 0;
    for (size_t i = byte_len - 1, shift = 0; i >= 0; i--)
    {
        hash_int |= hash[i] << shift;
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
        if (old[i].key[0] != 0 && old[i].value != NULL)
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

int map_create(map_t **map_ptr)
{
    if (map_ptr == NULL)
        return EINVAL;
    *map_ptr = calloc(1, sizeof(map_t));
    map_t *map = *map_ptr;
    if (map == NULL)
        return ENOMEM;

    map->items = calloc(map->capacity, sizeof(map_item_t));
    if (map->items == NULL)
    {
        free(map);
        return ENOMEM;
    }
    map->capacity = increment_capacity(0);
    map->length = 0;
    crypto_shorthash_keygen(map->hashkey);
    int err = array_create(&map->keys);
    if (err != 0)
        map_free(map);
    return err;
}

array_t *map_keys(map_t *map)
{
    return map->keys;
}

map_data_t map_get(map_t *map, const map_key_t key)
{
    size_t index = key2index(map, key);

    if (!array_contains(map->keys, (void *)key))
        return NULL;

    while (index < map->capacity)
    {
        if (strcmp(key, map->items[index].key) == 0)
            return map->items[index].value;
        index++;
    }
    return NULL;
}

int map_set(map_t *map, const map_key_t key, const map_data_t value)
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

    while (index < map->capacity)
    {
        if (strcmp(key, map->items[index].key) == 0)
        {
            map->items[index].value = value;
            return 0;
        }
        index++;
    }

    map_key_t key_cpy = strdup(key);
    if (key_cpy == NULL)
        return ENOMEM;
    map->items[index].key = key_cpy;
    map->items[index].value = value;
    int err = array_append(map->keys, (void *)key_cpy);
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
    for (size_t i = 0; i < map->capacity; i++)
        free((void *)map->items[i].key);
    free(map->items);
    free(map);
}
