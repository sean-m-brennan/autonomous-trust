#ifndef ARRAY_H
#define ARRAY_H

#include <stddef.h>
#include <stdbool.h>

#include "data.h"

typedef struct array_s array_t;

/**
 * @brief Initialize an existing array
 *
 * @param a
 */
void array_init(array_t *a);

/**
 * @brief Allocate a new array
 *
 * @param a_ptr
 * @return int 0 on success, or error codes: EINVAL(bad pointer), ENOMEM (failed alloc)
 */
int array_create(array_t **a_ptr);

/**
 * @brief Append data onto an array.
 *
 * @param array Pointer to array.
 * @param element Pointer to data.
 * @return Success (0) or error code.
 *
 */
int array_append(array_t *a, data_t *element);

/**
 * @brief Find the given element in the array.
 *
 * @param array Pointer to array.
 * @param element Pointer to data.
 * @return Index of element or -1 if not present.
 */
int array_find(array_t *a, data_t *element);

/**
 * @brief Filter array elements per the given function.
 *
 * @param array Pointer to array.
 * @param filter Pointer to function.
 * @return Index of first element that satisfies filter or -1 if none present.
 */
int array_filter(array_t *a, bool (*filter)(data_t*));

/**
 * @brief Is the given element in the array?
 *
 * @param array Pointer to array.
 * @param element Pointer to data.
 * @return True/false
 */
bool array_contains(array_t *a, data_t *element);

/**
 * @brief
 *
 * @return size_t
 */
size_t array_size();

/**
 * @brief For-each macro; requires array_t *array, int index, and data_t value to be defined.
 *
 */
#define array_for_each(array, index, value)             \
    for (index = 0; index < array_size(array); index++) \
    {                                                   \
        array_get(array, index, &value);

#define array_end_for_each }

/**
 * @brief
 *
 * @param a Pointer to array.
 * @param index Position in the array.
 * @param element Pointer to data
 * @return int Success (0) or not present (-1)
 */
int array_get(array_t *a, int index, data_t *element);

/**
 * @brief Set the element at the given index.
 *
 * @param array Pointer to array.
 * @param index Position in the array.
 * @param element Pointer to data.
 * @return Success (0) or error code.
 */
int array_set(array_t *a, int index, data_t *element);

/**
 * @brief Remove the given element from the array.
 *
 * @param array Pointer to array.
 * @param element Pointer to data.
 * @return Success (0) or error code.
 */
int array_remove(array_t *a, data_t *element);

/**
 * @brief Free all array structures (not data though).
 *
 * @param array Pointer to array.
 */
void array_free(array_t *a);

/**
 * Error code: out-of-bounds for indexing
 */
#define EARR_OOB 150

/**
 * Error code: element not present in array
 */
#define EARR_NOELT 151

#endif // ARRAY_H
