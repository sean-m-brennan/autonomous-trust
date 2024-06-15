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

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "array_priv.h"
#include "data_priv.h"
#include "utilities/exception.h"

int array_init(array_t *a)
{
    a->size = 0;
    a->alloc = false;
    a->array = malloc(sizeof(data_t));
    if (a->array == NULL)
        return EXCEPTION(ENOMEM);
    return 0;
}

int array_create(array_t **array_ptr)
{
    if (*array_ptr == NULL)
        return EXCEPTION(EINVAL);
    *array_ptr = (array_t *)calloc(1, sizeof(array_t));
    if (*array_ptr == NULL)
        return EXCEPTION(ENOMEM);
    array_t *arr = *array_ptr;
    int err = array_init(arr);
    arr->alloc = true;
    return err;
}

int array_copy(array_t *a, array_t *cpy)
{
    if (a == NULL)
        return EXCEPTION(EINVAL);
    cpy->alloc = false;
    cpy->array = calloc(a->size, sizeof(data_t));
    if (cpy->array == NULL)
        return EXCEPTION(ENOMEM);
    memcpy(cpy->array, a->array, sizeof(data_t) * a->size);
    return 0;
}

int array_find(array_t *a, data_t *element)
{
    for (int i = 0; i < a->size; i++)
    {
        if (data_equal(a->array[i], element))
            return i;
    }
    return -1;
}

int array_filter(array_t *a, bool (*filter)(data_t*))
{
    for (int i = 0; i < a->size; i++)
    {
        if (filter(a->array[i]))
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

int array_get(array_t *a, int index, data_t **element)
{
    if (index < 0)
        index = a->size + 1 + index;
    if (index > a->size)
        return EXCEPTION(EARR_OOB);
    *element = a->array[index];
    return 0;
}

int array_set(array_t *a, int index, data_t *element)
{
    if (index < 0)
        index = a->size + 1 + index;
    if (index > a->size)
        return EXCEPTION(EARR_OOB);

    if (index == a->size) {
        if (a->size > 0) {
            size_t new_size = (a->size + 1) * sizeof(data_t*);
            data_t **bigger_array = realloc(a->array, new_size);
            if (bigger_array == NULL)
                return EXCEPTION(ENOMEM);
            a->array = bigger_array;
        }
        a->size++;
    }
    a->array[index] = element;
    return 0;
}

int array_remove(array_t *a, data_t *element)
{
    int index = array_find(a, element);
    if (index < 0)
        return EXCEPTION(EARR_NOELT);
    size_t n = a->size - (index + 1);
    memmove(a->array + index, a->array + index + 1, n);
    memset(a->array + a->size, 0, sizeof(data_t));
    a->size--;
    return 0;
}

void array_free(array_t *a)
{
    for (int i=0; i< a->size; i++)
        data_decr(a->array[i]);
    free(a->array);
    a->array = NULL;
    a->size = 0;
    if (a->alloc)
        free(a);
}

int proto_repeated_sync_out(array_t *array, AutonomousTrust__Core__Structures__Data **parr, size_t *n)
{
    parr = calloc(array->size, sizeof(AutonomousTrust__Core__Structures__Data));
    *n = array->size;
    for (int i=0; i<array->size; i++) {
        data_t *elt;
        if (array_get(array, i, &elt) != 0)
            return -1;
        data_sync_out(elt, parr[i]);
    }
    return 0;
}

void proto_repeated_free_out_sync(AutonomousTrust__Core__Structures__Data **parr)
{
    free(parr);
}

int proto_repeated_sync_in(AutonomousTrust__Core__Structures__Data **parr, size_t n, array_t *array)
{
    for(int i=0; i<n; i++) {
        data_t *elt = malloc(sizeof(data_t));
        if (elt == NULL)
            return EXCEPTION(ENOMEM);
        data_sync_in(parr[i], elt);
        if (array_append(array, elt) != 0)
            return -1;
    }
    return 0;
}

void proto_repeated_free_in_sync(array_t *array)
{
    for(int i=0; i<array->size; i++) {
        data_t *elt;
        if (array_get(array, i, &elt) != 0)
            continue;
        data_free_in_sync(elt);
    }
    array_free(array);
}
