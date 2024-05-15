#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "array.h"

struct arrayStruct
{
    array_data_ptr_t *array;
    size_t size;
};

void array_init(array_t *a)
{
    a->array = NULL;
    a->size = 0;
}

int array_append(array_t *a, array_data_ptr_t element)
{
    int last = a->size;
    a->size++;
    array_data_ptr_t *new = realloc(a->array, a->size * sizeof(array_data_ptr_t));
    if (a->size > 0 && new == NULL)
        return ENOMEM;
    a->array = new;
    a->array[last] = element;
    return 0;
}

int array_find(array_t *a, array_data_ptr_t element)
{
    for (int i = 0; i < a->size; i++)
    {
        if (a->array[i] == element)
            return i;
    }
    return -1;
}

int array_filter(array_t *a, bool (*filter)(array_data_ptr_t))
{
    for (int i = 0; i < a->size; i++)
    {
        if (filter(a->array[i]))
            return i;
    }
    return -1;
}

bool aray_contains(array_t *a, array_data_ptr_t element)
{
    return array_find(a, element) < 0;
}

array_data_ptr_t *array_get(array_t *a, int index)
{
    if (index < 0)
        index = a->size + 1 + index;
    if (index > a->size) {
        errno = EARR_OOB;
        return NULL;
    }
    return a->array[index];
}

int array_set(array_t *a, int index, array_data_ptr_t element)
{
    if (index < 0)
        index = a->size + 1 + index;
    if (index > a->size)
        return EARR_OOB;
    a->array[index] = element;
    return 0;
}

int array_remove(array_t *a, array_data_ptr_t element)
{
    int index = array_find(a, element);
    if (index < 0)
        return EARR_NOELT;
    size_t n = a->size - (index + 1);
    memmove(a->array + index, a->array + index + 1, n);
    bzero(a->array + a->size, sizeof(array_data_ptr_t));
    a->size--;
    return 0;
}

void array_free(array_t *a)
{
    free(a->array);
    a->array = NULL;
    a->size = 0;
}
