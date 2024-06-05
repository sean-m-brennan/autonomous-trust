#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "array_priv.h"

void array_init(array_t *a)
{
    a->size = 0;
    a->alloc = false;
    a->array = malloc(sizeof(data_t));
}

int array_create(array_t **array_ptr)
{
    if (array_ptr == NULL)
        return EINVAL;
    *array_ptr = (array_t *)calloc(1, sizeof(array_t));
    if (*array_ptr == NULL)
        return ENOMEM;
    array_t *arr = *array_ptr;
    array_init(arr);
    arr->alloc = true;
    return 0;
}

int array_find(array_t *a, data_t *element)
{
    for (int i = 0; i < a->size; i++)
    {
        if (data_equal(&a->array[i], element))
            return i;
    }
    return -1;
}

int array_filter(array_t *a, bool (*filter)(data_t*))
{
    for (int i = 0; i < a->size; i++)
    {
        if (filter(&a->array[i]))
            return i;
    }
    return -1;
}

bool array_contains(array_t *a, data_t *element)
{
    return array_find(a, element) >= 0;
}

size_t array_size(array_t *a)
{
    return a->size;
}

int array_append(array_t *a, data_t *element)
{
    return array_set(a, a->size, element);
}

int array_get(array_t *a, int index, data_t *element)
{
    if (index < 0)
        index = a->size + 1 + index;
    if (index > a->size)
        return EARR_OOB;
    memcpy(element, &a->array[index], sizeof(data_t));
    return 0;
}

int array_set(array_t *a, int index, data_t *element)
{
    if (index < 0)
        index = a->size + 1 + index;
    if (index > a->size)
        return EARR_OOB;

    if (index == a->size) {
        if (a->size > 0) {
            size_t new_size = (a->size + 1) * sizeof(data_t);
            a->array = realloc(a->array, new_size);
            if (a->array == NULL)
                return ENOMEM;
        }
        a->size++;
    }
    memcpy(&a->array[index], element, sizeof(data_t));
    return 0;
}

int array_remove(array_t *a, data_t *element)
{
    int index = array_find(a, element);
    if (index < 0)
        return EARR_NOELT;
    size_t n = a->size - (index + 1);
    memmove(a->array + index, a->array + index + 1, n);
    bzero(a->array + a->size, sizeof(data_t));
    a->size--;
    return 0;
}

void array_free(array_t *a)
{
    free(a->array);
    a->array = NULL;
    a->size = 0;
    if (a->alloc)
        free(a);
}
