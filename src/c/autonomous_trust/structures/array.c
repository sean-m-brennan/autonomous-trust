#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "array.h"

struct array_s
{
    array_data_t *array;
    size_t size;
};

int array_create(array_t **array_ptr)
{
    if (array_ptr == NULL)
        return EINVAL;
    *array_ptr = (array_t *)calloc(1, sizeof(array_t));
    if (*array_ptr == NULL)
        return ENOMEM;
    array_t *arr = *array_ptr;
    arr->size = 0;
    return 0;
}

int array_find(array_t *a, array_data_t element)
{
    for (int i = 0; i < a->size; i++)
    {
        if (a->array[i] == element)
            return i;
    }
    return -1;
}

int array_filter(array_t *a, bool (*filter)(array_data_t))
{
    for (int i = 0; i < a->size; i++)
    {
        if (filter(a->array[i]))
            return i;
    }
    return -1;
}

bool array_contains(array_t *a, array_data_t element)
{
    return array_find(a, element) >= 0;
}

size_t array_size(array_t *a)
{
    return a->size;
}

int array_append(array_t *a, array_data_t element)
{
    return array_set(a, a->size, element);
}

array_data_t array_get(array_t *a, int index)
{
    if (index < 0)
        index = a->size + 1 + index;
    if (index > a->size)
    {
        errno = EARR_OOB;
        return NULL;
    }
    return a->array[index];
}

int array_set(array_t *a, int index, array_data_t element)
{
    if (index < 0)
        index = a->size + 1 + index;
    if (index > a->size)
        return EARR_OOB;
    a->array[index] = element;
    return 0;
}

int array_remove(array_t *a, array_data_t element)
{
    int index = array_find(a, element);
    if (index < 0)
        return EARR_NOELT;
    size_t n = a->size - (index + 1);
    memmove(a->array + index, a->array + index + 1, n);
    bzero(a->array + a->size, sizeof(array_data_t));
    a->size--;
    return 0;
}

void array_free(array_t *a)
{
    free(a->array);
    a->array = NULL;
    a->size = 0;
    free(a);
}
