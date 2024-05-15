#ifndef ARRAY_H
#define ARRAY_H

#include <stddef.h>
#include <stdbool.h>

typedef void* array_data_ptr_t;

struct arrayStruct;

typedef struct arrayStruct array_t;


/**
* @brief Initialize an existing array.
*
* @param array Pointer to array.
*/
void array_init(array_t *a);

/**
* @brief Append data onto an array.
*
* @param array Pointer to array.
* @param element Pointer to data.
* @return Success (0) or error code.
*
*/
int array_append(array_t *a, array_data_ptr_t element);

/**
* @brief Find the given element in the array.
*
* @param array Pointer to array.
* @param element Pointer to data.
* @return Index of element or -1 if not present.
*/
int array_find(array_t *a, array_data_ptr_t element);

/**
* @brief Filter array elements per the given function.
*
* @param array Pointer to array.
* @param filter Pointer to function.
* @return Index of first element that satisfies filter or -1 if none present.
*/
int array_filter(array_t *a, bool (*filter)(array_data_ptr_t));

/**
* @brief Is the given element in the array?
*
* @param array Pointer to array.
* @param element Pointer to data.
* @return True/false
*/
bool aray_contains(array_t *a, array_data_ptr_t element);

/**
* @brief Get the element at the given index.
*
* @param array Pointer to array.
* @param index Position in the array.
* @return Pointer to data (null on error, errno set)
*/
array_data_ptr_t *array_get(array_t *a, int index);

/**
* @brief Set the element at the given index.
*
* @param array Pointer to array.
* @param index Position in the array.
* @param element Pointer to data.
* @return Success (0) or error code.
*/
int array_set(array_t *a, int index, array_data_ptr_t element);

/**
* @brief Remove the given element from the array.
*
* @param array Pointer to array.
* @param element Pointer to data.
* @return Success (0) or error code.
*/
int array_remove(array_t *a, array_data_ptr_t element);

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
