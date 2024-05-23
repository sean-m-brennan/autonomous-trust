#ifndef MAP_H
#define MAP_H

#include "types.h"
#include "array.h"

typedef const char *map_key_t;

typedef void *map_data_t;

typedef struct map_s map_t;

cyaml_schema_value_t map_schema(const type_t *type);

/**
 * @brief Allocate a mapping of map_key_t to map_data_t
 * 
 * @param map_ptr 
 * @return int 0 on success, or error codes: EINVAL (bad pointer), ENOMEM (failed alloc)
 */
int map_create(map_t **map_ptr);

/**
 * @brief Allocate a serializable mapping where map_data_t is of elt_type (cannot be mixed types)
 * 
 * @param elt_type 
 * @param map_ptr 
 * @return int 0 on success, or error codes: EINVAL(bad pointer), ENOMEM (failed alloc)
 */
int map_of_type(const type_t *elt_type, map_t **map_ptr);

/**
 * @brief Load a YAML file that is (only) a map of elt_type
 * 
 * @param filename 
 * @param elt_type 
 * @param map_ptr 
 * @return int 0 on success, or error codes: EINVAL(bad pointer), ENOMEM (failed alloc)
 */
int map_from_file(const char *filename, const type_t *elt_type, map_t **map_ptr);

/**
 * @brief Save the given map to a YAML file
 * 
 * @param map 
 * @param filename 
 * @return int 0 on success, or error codes: EINVAL
 */
int map_to_file(const map_t *map, char *filename);

/**
 * @brief 
 * 
 * @param map 
 * @return array_t* 
 */
array_t *map_keys(map_t *map);

/**
 * @brief
 *
 * @param map
 * @param key
 * @return map_data_t
 */
map_data_t map_get(map_t *map, map_key_t key);

/**
 * @brief
 *
 * @param map
 * @param key
 * @param value
 * @return int
 */
int map_set(map_t *map, map_key_t key, map_data_t value);

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