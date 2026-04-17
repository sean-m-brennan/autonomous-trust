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

#ifndef ARRAY_H
#define ARRAY_H

/** @addtogroup internal_structures
 *  @{
 */

#include <stddef.h>
#include <stdbool.h>

#include "data.h"
#include "utilities/exception.h"

typedef struct array_s
{
    smrt_ptr_t;
    size_t size;
    data_t **array;
} array_t;

/*@ predicate valid_array(array_t *a) =
      a != \null && \valid(a) &&
      smrt_valid((smrt_ptr_t *)a) &&
      (a->size == 0 ==> a->array == \null || \valid(a->array + (0 .. 0))) &&
      (a->size > 0  ==>
        a->array != \null &&
        \valid(a->array + (0 .. a->size - 1)));
*/

/**
 * @brief Initialize an existing array
 *
 * @param a
 * @return int
 */
/*@
  requires \valid(a);
  assigns a->size, a->array;
  behavior success:
    ensures \result == 0;
    ensures a->size == 0;
    ensures a->array != \null;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int array_init(array_t *a);

/**
 * @brief Allocate a new array
 *
 * @param a_ptr
 * @return int 0 on success, or error codes: EINVAL(bad pointer), ENOMEM (failed alloc)
 */
/*@
  requires \valid(a_ptr);
  allocates *a_ptr;
  assigns *a_ptr;
  behavior null_ptr:
    assumes a_ptr == \null;
    ensures \result != 0;
  behavior success:
    assumes a_ptr != \null;
    ensures \result == 0;
    ensures *a_ptr != \null;
    ensures \fresh(*a_ptr, sizeof(array_t));
    ensures (*a_ptr)->size == 0;
  behavior failure:
    assumes a_ptr != \null;
    ensures \result != 0;
  disjoint behaviors;
*/
int array_create(array_t **a_ptr);

/**
 * @brief
 *
 * @param a
 * @param cpy_ptr
 * @return int
 */
/*@
  requires \valid(a);
  requires \valid(cpy);
  assigns cpy->size, cpy->array;
  behavior success:
    ensures \result == 0;
    ensures cpy->size == a->size;
    ensures cpy->array != \null;
  behavior null_input:
    assumes a == \null;
    ensures \result != 0;
  behavior failure:
    assumes a != \null;
    ensures \result != 0;
  disjoint behaviors;
*/
int array_copy(array_t *a, array_t *cpy);

/**
 * @brief Append data onto an array.
 *
 * @param array Pointer to array.
 * @param element Pointer to data.
 * @return Success (0) or error code.
 *
 */
/*@
  requires \valid(a);
  requires \valid(element);
  assigns a->size, a->array;
  behavior success:
    ensures \result == 0;
    ensures a->size == \old(a->size) + 1;
  behavior failure:
    ensures \result != 0;
  complete behaviors;
  disjoint behaviors;
*/
int array_append(array_t *a, data_t *element);

/**
 * @brief Find the given element in the array.
 *
 * @param array Pointer to array.
 * @param element Pointer to data.
 * @return Index of element or -1 if not present.
 */
/*@
  requires \valid(a);
  requires \valid(element);
  assigns \nothing;
  ensures \result >= -1;
  ensures \result < (int)a->size;
  behavior found:
    ensures \result >= 0 && \result < (int)a->size;
  behavior not_found:
    ensures \result == -1;
  complete behaviors;
  disjoint behaviors;
*/
int array_find(array_t *a, data_t *element);

/**
 * @brief Filter array elements per the given function.
 *
 * @param array Pointer to array.
 * @param filter Pointer to function.
 * @return Index of first element that satisfies filter or -1 if none present.
 */
/*@
  requires \valid(a);
  requires filter != \null;
  assigns \nothing;
  ensures \result >= -1;
  ensures \result < (int)a->size;
  behavior found:
    ensures \result >= 0 && \result < (int)a->size;
  behavior not_found:
    ensures \result == -1;
  complete behaviors;
  disjoint behaviors;
*/
int array_filter(array_t *a, bool (*filter)(data_t *));

/**
 * @brief Is the given element in the array?
 *
 * @param array Pointer to array.
 * @param element Pointer to data.
 * @return True/false
 */
/*@
  requires \valid(a);
  requires \valid(element);
  assigns \nothing;
  ensures \result == true || \result == false;
*/
bool array_contains(array_t *a, data_t *element);

/**
 * @brief
 *
 * @return size_t
 */
/*@
  requires \valid(a);
  assigns \nothing;
  ensures \result == a->size;
  ensures \result >= 0;
*/
size_t array_size(array_t *a);

/**
 * @brief For-each macro
 * @details requires array_t *array, int index, and data_t value to be defined.
 *
 */
#define array_for_each(array, index, value)                      \
    for (index = 0; (size_t)index < array_size(array); index++) \
    {                                                   \
        int __attribute__((unused)) a_errors[1] = {0};  \
        int _a_err = array_get(array, index, &value);   \
        if (_a_err != 0)                                \
        {                                               \
            a_errors[0] = _a_err;                       \
            continue;                                   \
        }

#define array_end_for_each }

/**
 * @brief
 *
 * @param a Pointer to array.
 * @param index Position in the array.
 * @param element Pointer to data
 * @return int Success (0) or not present (-1)
 */
/*@
  requires \valid(a);
  requires \valid(element);
  assigns *element;
  behavior in_bounds:
    assumes (index >= 0 && (size_t)index < a->size) ||
            (index < 0 && (size_t)(-index) <= a->size);
    ensures \result == 0;
    ensures *element != \null;
  behavior out_of_bounds:
    assumes (index >= 0 && (size_t)index >= a->size) ||
            (index < 0 && (size_t)(-index) > a->size);
    ensures \result != 0;
  complete behaviors;
  disjoint behaviors;
*/
int array_get(array_t *a, int index, data_t **element);

/**
 * @brief Set the element at the given index.
 *
 * @param array Pointer to array.
 * @param index Position in the array.
 * @param element Pointer to data.
 * @return Success (0) or error code.
 */
/*@
  requires \valid(a);
  requires \valid(element);
  assigns a->size, a->array;
  behavior in_bounds:
    assumes (index >= 0 && (size_t)index <= a->size) ||
            (index < 0 && (size_t)(-index) <= a->size);
    ensures \result == 0;
    ensures (size_t)\old(index) == \old(a->size) ==>
            a->size == \old(a->size) + 1;
    ensures (size_t)\old(index) < \old(a->size) ==>
            a->size == \old(a->size);
  behavior out_of_bounds:
    assumes (index >= 0 && (size_t)index > a->size) ||
            (index < 0 && (size_t)(-index) > a->size);
    ensures \result != 0;
  complete behaviors;
  disjoint behaviors;
*/
int array_set(array_t *a, int index, data_t *element);

/**
 * @brief Remove the given element from the array.
 *
 * @param array Pointer to array.
 * @param element Pointer to data.
 * @return Success (0) or error code.
 */
/*@
  requires \valid(a);
  requires \valid(element);
  assigns a->size, a->array;
  behavior found:
    ensures \result == 0;
    ensures a->size == \old(a->size) - 1;
  behavior not_found:
    ensures \result == 209;
    ensures a->size == \old(a->size);
  disjoint behaviors;
*/
int array_remove(array_t *a, data_t *element);

/**
 * @brief Free all array structures (not data though).
 *
 * @param array Pointer to array.
 */
/*@
  requires \valid(a);
  requires a->array != \null;
  assigns a->size, a->array;
  frees a->array;
  ensures a->array == \null;
  ensures a->size == 0;
*/
void array_free(array_t *a);

/**
 * Error code: out-of-bounds for indexing
 */
#define EARR_OOB 208

DECLARE_ERROR(EARR_OOB, "Array index out-of-bounds (beyond the final entry)");

/**
 * Error code: element not present in array
 */
#define EARR_NOELT 209
DECLARE_ERROR(EARR_NOELT, "Element not present in array");


/** @} */ /* end of internal_structures */

#endif // ARRAY_H
