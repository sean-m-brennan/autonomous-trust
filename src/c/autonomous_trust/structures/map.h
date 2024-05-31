#ifndef MAP_H
#define MAP_H

#include "array.h"

typedef char *map_key_t;

typedef void *map_data_t;

typedef struct
{
    map_key_t key;
    map_data_t value;
} map_item_t;

typedef struct map_s map_t;

/**
 * @brief Allocate a mapping of map_key_t to map_data_t
 *
 * @param map_ptr
 * @return int 0 on success, or error codes: EINVAL (bad pointer), ENOMEM (failed alloc)
 */
int map_create(map_t **map_ptr);

/**
 * @brief
 *
 * @param map
 * @return size_t
 */
size_t map_size(map_t *map);

/**
 * @brief
 *
 * @param map
 * @return array_t*
 */
array_t *map_keys(map_t *map);

/**
 * @brief For-each macro; requires array_t *keys, map_t *map, map_key_t key, and map_data_t value to be defined.
 *
 */
#define map_entries_for_each(map, key, value)  \
    keys = map_keys(map);            \
    for (int i = 0; i < array_size(keys); i++) \
    {                                          \
        key = array_get(keys, i);             \
        value = map_get(map, #key);

#define map_end_for_each() \
    }

/**
 * @brief
 *
 * @param map
 * @param key
 * @return map_data_t
 */
map_data_t map_get(map_t *map, const map_key_t key);

/**
 * @brief
 *
 * @param map
 * @param key
 * @param value
 * @return int
 */
int map_set(map_t *map, const map_key_t key, const map_data_t value);

/**
 * @brief
 *
 * @param map
 * @param key
 * @return int
 */
int map_remove(map_t *map, map_key_t key);

/**
 * @brief
 *
 * @param map
 */
void map_free(map_t *map);

#endif // MAP_H