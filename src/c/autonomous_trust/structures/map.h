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

#ifndef MAP_H
#define MAP_H

#include "array.h"
#include "data.h"

typedef char *map_key_t;

typedef struct
{
    map_key_t key;
    data_t *value;
    size_t hash;
} map_item_t;

typedef struct map_s map_t;

/**
 * @brief
 *
 * @param map
 * @return int
 */
int map_init(map_t *map);

/**
 * @brief Allocate a mapping of map_key_t to data_t
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

// #define CONCAT_IMPL(x, y) x##y
// #define CONCAT(x, y) CONCAT_IMPL(x, y)
// #define DYNAVAR2(x) CONCAT(x, __COUNTER__)
// #define DYNAVAR(x) DYNAVAR2(x)
// #define MAP_KEYS_VAR DYNAVAR(keys)

#define __MAKE_SYMBOL(name, num) name##num
#define _MAKE_SYMBOL(name, num) __MAKE_SYMBOL(name, num)
#define MAKE_SYMBOL(name) _MAKE_SYMBOL(name, __COUNTER__)
#define MAP_KEYS_VAR MAKE_SYMBOL(_keys_)

/**
 * @brief For-each macro
 * @details requires map_t *map, map_key_t key, and data_t *value to be defined.
 */
#define map_entries_for_each(map, key, value)                       \
    {                                                               \
        array_t *__keys = map_keys(map);                            \
        for (size_t _incr = 0; _incr < array_size(__keys); _incr++) \
        {                                                           \
            int __attribute__((unused)) errors[3] = {0};            \
            data_t *__k_dat = NULL;                                 \
            int _err = array_get(__keys, _incr, &__k_dat);           \
            if (_err != 0)                                           \
            {                                                       \
                errors[0] = _err;                                    \
                continue;                                           \
            }                                                       \
            _err = data_string_ptr(__k_dat, &key);                   \
            if (_err != 0)                                           \
            {                                                       \
                errors[1] = _err;                                    \
                continue;                                           \
            }                                                       \
            _err = map_get(map, key, &value);                        \
            if (_err != 0)                                           \
            {                                                       \
                errors[2] = _err;                                    \
                continue;                                           \
            }

#define map_end_for_each \
    }                    \
    }

/**
 * @brief
 *
 * @param map
 * @param key
 * @param value
 * @return int
 */
int map_get(map_t *map, const map_key_t key, data_t **value);

/**
 * @brief
 *
 * @param map
 * @param key
 * @param value
 * @return int
 */
int map_set(map_t *map, const map_key_t key, data_t *value);

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

#endif  // MAP_H
