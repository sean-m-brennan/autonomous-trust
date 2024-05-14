#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "array.h"

inline int max(int a, int b)
{
    return ((a) > (b) ? a : b);
}

inline int min(int a, int b)
{
    return ((a) < (b) ? a : b);
}

void array_init(Array *a, size_t initialSize)
{
    a->array = NULL;
    a->size = 0;
}

int array_insert(Array *a, array_data element)
{
    int last = a->size;
    a->size++;
    array_data *new = realloc(a->array, a->size * sizeof(array_data));
    if (a->size > 0 && new == NULL)
        return ENOMEM;
    a->array = new;
    a->array[last] = element;
    return 0;
}

int array_find(Array *a, array_data element)
{
    for (int i = 0; i < a->size; i++)
    {
        if (a->array[i] == element)
            return i;
    }
    return -1;
}

int array_filter(Array *a, bool (*filter)(array_data))
{
    for (int i = 0; i < a->size; i++)
    {
        if (filter(a->array[i]))
            return i;
    }
    return -1;
}

bool aray_contains(Array *a, array_data element)
{
    return array_find(a, element) < 0;
}

int array_get(Array *a, int index, array_data *element)
{
    if (index < 0)
        index = a->size + 1 + index;
    if (index > a->size)
        return EARR_OOB;
    *element = a->array[index];
    return 0;
}

int array_set(Array *a, int index, array_data element)
{
    if (index < 0)
        index = a->size + 1 + index;
    if (index > a->size)
        return EARR_OOB;
    a->array[index] = element;
    return 0;
}

int array_remove(Array *a, array_data element)
{
    int index = array_find(a, element);
    if (index < 0)
        return EARR_NOELT;
    size_t n = a->size - (index + 1);
    memmove(a->array + index, a->array + index + 1, n);
    bzero(a->array + a->size, sizeof(array_data));
    a->size--;
    return 0;
}

void array_free(Array *a)
{
    free(a->array);
    a->array = NULL;
    a->size = 0;
}
