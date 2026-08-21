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

#ifndef MAP_H
#define MAP_H

/** @addtogroup internal_structures
 *  @{
 */

#include "array.h"
#include "data.h"
#include "utilities/exception.h"

typedef char *map_key_t;

typedef struct
{
    smrt_ptr_t;
    map_key_t key;
    data_t *value;
    size_t hash;
} map_item_t;

#define MAP_HASHKEY_BYTES 16  /* matches MAP_HASHKEY_BYTES from libsodium */

typedef struct map_s
{
    smrt_ptr_t;
    map_item_t *items;
    size_t length;
    size_t capacity;
    array_t keys;
    unsigned char hashkey[MAP_HASHKEY_BYTES];
} map_t;

/*@ predicate map_valid(map_t *m) =
      m != \null && \valid(m) &&
      smrt_valid((smrt_ptr_t *)m) &&
      m->length <= m->capacity &&
      (m->capacity > 0 ==>
        m->items != \null &&
        \valid(m->items + (0 .. m->capacity - 1)));
*/

/*@ type invariant map_length_bounded(struct map_s m) =
      m.items != \null ==> m.length <= m.capacity;
*/

/**
 * @brief Initialize an existing map structure.
 *
 * @param map Pointer to an already-allocated map_t.
 * @return int 0 on success, ENOMEM on allocation failure.
 */
/*@
  requires \valid(map);
  assigns map->length, map->capacity, map->items, map->keys,
          map->hashkey[0 .. MAP_HASHKEY_BYTES - 1],
          map->alloc, map->refs;
  behavior success:
    ensures \result == 0;
    ensures map->length == 0;
    ensures map->capacity > 0;
    ensures map->items != \null;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int map_init(map_t *map);

/**
 * @brief Allocate a mapping of map_key_t to data_t
 *
 * @param map_ptr
 * @return int 0 on success, or error codes: EINVAL (bad pointer), ENOMEM (failed alloc)
 */
/*@
  requires \valid(map_ptr);
  allocates *map_ptr;
  assigns *map_ptr;
  behavior null_ptr:
    assumes map_ptr == \null;
    ensures \result == 22;
  behavior success:
    assumes map_ptr != \null;
    ensures \result == 0;
    ensures *map_ptr != \null;
    ensures \fresh(*map_ptr, sizeof(map_t));
    ensures (*map_ptr)->length == 0;
    ensures (*map_ptr)->capacity > 0;
  behavior failure:
    assumes map_ptr != \null;
    ensures \result != 0;
  disjoint behaviors;
*/
int map_create(map_t **map_ptr);

/**
 * @brief Return the number of entries in the map.
 *
 * @param map Pointer to an initialized map.
 * @return size_t Number of key-value pairs stored.
 */
/*@
  requires \valid(map);
  assigns \nothing;
  ensures \result == map->length;
  ensures \result <= map->capacity;
*/
size_t map_size(map_t *map);

/**
 * @brief Return a pointer to the internal keys array.
 *
 * @param map Pointer to an initialized map.
 * @return array_t* Pointer to the keys array (owned by the map).
 */
/*@
  requires \valid(map);
  assigns \nothing;
  ensures \result == &map->keys;
  ensures \valid(\result);
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
            int __attribute__((unused)) m_errors[3] = {0};          \
            data_t *__k_dat = NULL;                                 \
            int _m_err = array_get(__keys, _incr, &__k_dat);        \
            if (_m_err != 0)                                        \
            {                                                       \
                m_errors[0] = _m_err;                               \
                continue;                                           \
            }                                                       \
            _m_err = data_string_ptr(__k_dat, &key);                \
            if (_m_err != 0)                                        \
            {                                                       \
                m_errors[1] = _m_err;                               \
                continue;                                           \
            }                                                       \
            _m_err = map_get(map, key, &value);                     \
            if (_m_err != 0)                                        \
            {                                                       \
                m_errors[2] = _m_err;                               \
                continue;                                           \
            }

#define map_end_for_each \
    }                    \
    }

/**
 * @brief Retrieve a value by key from the map.
 *
 * @param map Pointer to an initialized map.
 * @param key Null-terminated string key to look up.
 * @param value Output pointer; set to the stored data_t on success.
 * @return int 0 on success, EMAP_NOKEY if the key is not present.
 */
/*@
  requires \valid(map);
  requires \valid_read(key);
  requires \valid(value);
  requires map->length <= map->capacity;
  assigns *value;
  behavior found:
    assumes \exists integer i; 0 <= i < map->capacity &&
            map->items[i].key != \null &&
            strcmp(key, map->items[i].key) == 0;
    ensures \result == 0;
    ensures *value != \null;
  behavior not_found:
    assumes \forall integer i; 0 <= i < map->capacity ==>
            (map->items[i].key == \null ||
             strcmp(key, map->items[i].key) != 0);
    ensures \result == 218;
  complete behaviors;
  disjoint behaviors;
*/
int map_get(map_t *map, const map_key_t key, data_t **value);

/**
 * @brief Insert or update a key-value pair in the map.
 *
 * @details OWNERSHIP: the map ADOPTS the caller's reference to @p value. It
 * does not take one of its own, so a caller that wants to keep using @p value
 * beyond the map's lifetime — or store it in a second container — must
 * @c smrt_ref it first. The map releases what it holds in @ref map_remove,
 * @ref map_free, and when an insert displaces an existing value. This is the
 * same contract @c array_set / @c array_free have always had, and it is what
 * every call site in the tree already assumed: the prevailing idiom is
 * @c map_set(&m, k, integer_data(n)) with no matching deref, which under the
 * old behaviour (map_set took a second reference, map_free released none)
 * leaked every value ever stored in any map.
 *
 * @param map Pointer to an initialized map.
 * @param key Null-terminated string key.
 * @param value Non-null data_t pointer to associate with the key; adopted.
 * @return int 0 on success, EINVAL if value is null, ENOMEM on allocation failure.
 */
/*@
  requires \valid(map);
  requires \valid_read(key);
  requires \valid(value);
  requires map->length <= map->capacity;
  assigns map->items[0 .. map->capacity - 1],
          map->length, map->capacity, map->keys;
  behavior null_value:
    assumes value == \null;
    ensures \result == 22;
    assigns \nothing;
  behavior update_existing:
    assumes value != \null;
    assumes \exists integer i; 0 <= i < map->capacity &&
            map->items[i].key != \null &&
            strcmp(key, map->items[i].key) == 0;
    ensures \result == 0;
    ensures map->length == \old(map->length);
  behavior insert_new:
    assumes value != \null;
    assumes \forall integer i; 0 <= i < map->capacity ==>
            (map->items[i].key == \null ||
             strcmp(key, map->items[i].key) != 0);
    ensures \result == 0 ==> map->length == \old(map->length) + 1;
    ensures \result == 0 ==> map->length <= map->capacity;
  disjoint behaviors;
*/
int map_set(map_t *map, const map_key_t key, data_t *value);

/**
 * @brief Remove a key-value pair from the map.
 *
 * @details Releases the map's reference to the removed value (see
 * @ref map_set for the ownership contract), so the value is freed unless
 * someone else has referenced it. Moving an entry to another map therefore
 * reads @c smrt_ref, @c map_set, @c map_remove — in that order.
 *
 * @param map Pointer to an initialized map.
 * @param key Null-terminated string key to remove.
 * @return int 0 on success, EMAP_NOKEY if the key is not present.
 */
/*@
  requires \valid(map);
  requires \valid_read(key);
  requires map->length <= map->capacity;
  assigns map->items[0 .. map->capacity - 1], map->length;
  behavior found:
    assumes \exists integer i; 0 <= i < map->capacity &&
            map->items[i].key != \null &&
            strcmp(key, map->items[i].key) == 0;
    ensures \result == 0;
    ensures map->length == \old(map->length) - 1;
    ensures map->length <= map->capacity;
  behavior not_found:
    assumes \forall integer i; 0 <= i < map->capacity ==>
            (map->items[i].key == \null ||
             strcmp(key, map->items[i].key) != 0);
    ensures \result == 218;
    ensures map->length == \old(map->length);
  complete behaviors;
  disjoint behaviors;
*/
int map_remove(map_t *map, map_key_t key);

/**
 * @brief Free all map resources (keys, stored values, internal storage).
 *
 * @details Releases the map's reference to every value it still holds — see
 * @ref map_set for why the map owns exactly one — then frees @c map->keys,
 * the parallel array of key copies. What it still does NOT release is the
 * @c map_t itself when the map came from @ref map_create: @c map_init zeroes
 * the smrt header that @c map_create's allocation established, so the closing
 * @c smrt_deref finds alloc=false and does nothing. @c array_create restores
 * its header after @c array_init for exactly this reason; @c map_create does
 * not.
 *
 * @param map Pointer to an initialized map.
 */
/*@
  requires \valid(map);
  requires map->items != \null;
  requires map->length <= map->capacity;
  assigns map->items[0 .. map->capacity - 1];
  frees map->items;
*/
void map_free(map_t *map);

#define EMAP_NOKEY 218
DECLARE_ERROR(EMAP_NOKEY, "No such key in the map");


/** @} */ /* end of internal_structures */

#endif // MAP_H
