#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <strings.h>

#include <sodium.h>
#include <cyaml/cyaml.h>

#include "map.h"
#include "array.h"


typedef struct
{
    map_key_t key;
    map_data_t value;
} entry_t;

struct map_s
{
    entry_t *entries;
    cfg_size_t length;
    size_t capacity;
    array_t *keys;
    unsigned char hashkey[crypto_shorthash_KEYBYTES];
    representer_t repr;
    const type_t *elt_type;
};

#if YAML_LIB == CYAML
cyaml_schema_value_t map_schema(const type_t *type) {
    //if (type == NULL)
    //    return CYAML_VALUE_IGNORE;
    const cyaml_schema_value_t data = type->schema(NULL);  // FIXME wrong
    const cyaml_schema_field_t fields[] = {
        CYAML_FIELD_SEQUENCE_COUNT("entries", CYAML_FLAG_POINTER, map_t, entries, length, &data, 0, CYAML_UNLIMITED),
        CYAML_FIELD_END
    };
    cyaml_schema_value_t schema = {
        CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, map_t, fields)
    };
    return schema;
}
#endif

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
    entry_t *old = calloc(map->capacity, sizeof(entry_t));
    memcpy(old, map->entries, map->capacity * sizeof(entry_t));
    bzero(map->entries, map->capacity * sizeof(entry_t));
    for (size_t i=0; i<map->capacity; i++) {
        if (old[i].key[0] != 0 && old[i].value != NULL) {
            size_t idx = key2index(map, old[i].key);
            map->entries[idx] = old[i];
        }
    }
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

    map->entries = calloc(map->capacity, sizeof(entry_t));
    if (map->entries == NULL) {
        free(map);
        return ENOMEM;
    }
    map->capacity = increment_capacity(0);
    map->length = 0;
    map->elt_type = NULL;
    crypto_shorthash_keygen(map->hashkey);
    int err = array_create(&map->keys);
    if (err != 0)
        map_free(map);
#if YAML_LIB == CYAML
    map->repr = (representer_t){ 
        .tag = "", 
        .yml_cfg = default_yaml_config, 
        .schema_bld = map_schema,
        };
#endif
    return err;
}

int map_of_type(const type_t *elt_type, map_t **map_ptr)
{
    int err = map_create(map_ptr);
    if (err != 0)
        return err;
    map_t *map = *map_ptr;
    map->elt_type = elt_type;
    representer_init(&map->repr, elt_type);
    return 0;
}

int map_from_file(const char *filename, const type_t *elt_type, map_t **map_ptr) {
    if (elt_type == NULL)
        return EINVAL;
    *map_ptr = (map_t*)malloc(sizeof(map_t));
    if (*map_ptr == NULL)
        return ENOMEM;

    map_t *map = *map_ptr;
    int err = array_create(&map->keys);
    if (err != 0) {
        map_free(map);
        return err;
    }
    map->elt_type = elt_type;

    crypto_shorthash_keygen(map->hashkey);
    cyaml_schema_value_t schema = map_schema(elt_type);
    err = yaml_load_file(filename, &map->repr, (void**)&map->entries, &map->length);
    // FIXME rehash?
    // FIXME load keys
    return err;
}

int map_to_file(const map_t * map, char *filename)
{
    if (map->elt_type == NULL)
        return EINVAL;
    cyaml_schema_value_t schema = map_schema(map->elt_type);
    return cyaml_save_file(filename, &default_yaml_config, &schema, map->entries, map->length);
}

array_t *map_keys(map_t *map)
{
    return map->keys;
}

map_data_t map_get(map_t *map, map_key_t key)
{
    size_t index = key2index(map, key);

    if (!array_contains(map->keys, (void *)key))
        return NULL;

    while (index < map->capacity)
    {
        if (strcmp(key, map->entries[index].key) == 0)
            return map->entries[index].value;
        index++;
    }
    return NULL;
}

int map_set(map_t *map, map_key_t key, map_data_t value)
{
    if (value == NULL)
        return EINVAL;

    if (map->length >= map->capacity - 1) // always leave room at the end
    {
        map->capacity = increment_capacity(map->capacity);
        entry_t *entries = realloc(map->entries, map->capacity * sizeof(entry_t));
        if (entries == NULL)
            return ENOMEM;
        map->entries = entries;  // FIXME rehash?
    }

    size_t index = key2index(map, key);

    while (index < map->capacity)
    {
        if (strcmp(key, map->entries[index].key) == 0)
        {
            map->entries[index].value = value;
            return 0;
        }
        index++;
    }

    map_key_t key_cpy = strdup(key);
    if (key_cpy == NULL)
        return ENOMEM;
    map->entries[index].key = key_cpy;
    map->entries[index].value = value;
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
    size_t tail_len = (map->length - index) * sizeof(entry_t);
    memmove(map->entries + index, map->entries + index + 1, tail_len);
    return 0;
}

void map_free(map_t *map)
{
    for (size_t i = 0; i < map->capacity; i++)
        free((void *)map->entries[i].key);
    free(map->entries);
    free(map);
}
