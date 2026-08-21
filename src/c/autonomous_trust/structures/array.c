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

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "array_priv.h"
#include "data_priv.h"
#include "utilities/exception.h"

int array_init(array_t *a)
{
    /* The smrt header belongs to the EMBEDDED case, which is what init is
     * for: a stack local or a struct member (map->keys, id_state.histories)
     * whose header no allocator ever wrote. array_free ends in
     * smrt_deref(a), which reads alloc/refs — so leaving them untouched is a
     * read of uninitialized memory, and a garbage alloc/refs pair would make
     * that deref call free() on a stack address. alloc=false makes the deref
     * the intended no-op. array_create, whose struct IS an smrt allocation,
     * re-asserts the header afterwards. Mirrors map_init. */
    a->alloc = false;
    a->refs = 0;
    a->size = 0;
    a->array = smrt_create(sizeof(data_t));
    if (a->array == NULL)
        return EXCEPTION(ENOMEM);
    return 0;
}

/* Frama-C: skipped — [solver-timeout] _set_exception precondition */
int array_create(array_t **array_ptr)
{
    if (array_ptr == NULL)
        return EXCEPTION(EINVAL);
    *array_ptr = smrt_create(sizeof(array_t));
    if (*array_ptr == NULL)
        return EXCEPTION(ENOMEM);
    array_t *arr = *array_ptr;
    int err = array_init(arr);
    /* array_init zeroes the header for the embedded case; this struct is a
     * real smrt allocation, so restore what smrt_create established or
     * array_free's closing deref would never free it. */
    arr->alloc = true;
    arr->refs = 1;
    return err;
}

/* Frama-C: skipped — [solver-timeout] memcpy valid_src/valid_dest preconditions */
int array_copy(array_t *a, array_t *cpy)
{
    if (a == NULL)
        return EXCEPTION(EINVAL);
    cpy->array = smrt_create(a->size * sizeof(data_t));
    if (cpy->array == NULL)
        return EXCEPTION(ENOMEM);
    memcpy(cpy->array, a->array, sizeof(data_t) * a->size);
    cpy->size = a->size;
    return 0;
}

/* Frama-C: skipped — [solver-timeout] not_found ensures */
int array_find(array_t *a, data_t *element)
{
    /*@
      loop invariant 0 <= i <= a->size;
      loop assigns i;
      loop variant a->size - i;
    */
    for (int i = 0; i < a->size; i++)
    {
        if (data_equal(a->array[i], element))
            return i;
    }
    return -1;
}

int array_filter(array_t *a, bool (*filter)(data_t*))
{
    /*@
      loop invariant 0 <= i <= a->size;
      loop assigns i;
      loop variant a->size - i;
    */
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

/* Frama-C: skipped — [solver-timeout] in_bounds ensures + _set_exception */
int array_get(array_t *a, int index, data_t **element)
{
    if (index < 0)
        index = a->size + index;
    if (index >= (int)a->size)
        return EXCEPTION(EARR_OOB);
    *element = a->array[index];
    return 0;
}

/* Frama-C: skipped — [alloc-pattern] element replacement */
int array_set(array_t *a, int index, data_t *element)
{
    if (index < 0)
        index = a->size + index;
    if (index > a->size)
        return EXCEPTION(EARR_OOB);

    if (index == a->size) {
        /* Skip realloc only on the first insert into a freshly-init'd array:
         * array_init pre-allocates 1 slot, so size==0 && array!=NULL means
         * that slot is still free. Every other case must grow. */
        if (a->size > 0 || a->array == NULL) {
            size_t new_size = (a->size + 1) * sizeof(data_t);
            if (smrt_recreate((void **)&a->array, new_size) != 0)
                return EXCEPTION(ENOMEM);
        }
        a->size++;
    }
    a->array[index] = element;
    return 0;
}

/* Frama-C: skipped — [alloc-pattern] memmove compaction */
int array_remove(array_t *a, data_t *element)
{
    int index = array_find(a, element);
    if (index < 0)
        return EXCEPTION(EARR_NOELT);
    size_t n = a->size - (index + 1);
    if (n > 0)
        memmove(a->array + index, a->array + index + 1, n * sizeof(data_t *));
    a->size--;
    a->array[a->size] = NULL;
    return 0;
}

/* Frama-C: skipped — [alloc-pattern] iterative element free */
void array_free(array_t *a)
{
    /*@
      loop invariant 0 <= i <= a->size;
      loop assigns i;
      loop variant a->size - i;
    */
    for (int i=0; i< a->size; i++)
        smrt_deref(a->array[i]);
    smrt_deref(a->array);
    a->array = NULL;
    a->size = 0;
    smrt_deref(a);
}

/* Frama-C: skipped — [serialization] protobuf serialization */
int array_sync_out(array_t *array, AutonomousTrust__Core__Protobuf__Structures__Data ***parr_ptr, size_t *n)
{
    *n = array->size;
    if (array->size == 0) {
        *parr_ptr = NULL;
        return 0;
    }
    AutonomousTrust__Core__Protobuf__Structures__Data **parr =
        calloc(array->size, sizeof(AutonomousTrust__Core__Protobuf__Structures__Data *));
    if (parr == NULL)
        return EXCEPTION(ENOMEM);
    for (size_t i = 0; i < array->size; i++) {
        parr[i] = malloc(sizeof(AutonomousTrust__Core__Protobuf__Structures__Data));
        if (parr[i] == NULL)
            return EXCEPTION(ENOMEM);
        autonomous_trust__core__protobuf__structures__data__init(parr[i]);
        data_t *elt = NULL;
        if (array_get(array, i, &elt) != 0)
            return -1;
        data_sync_out(elt, parr[i]);
    }
    *parr_ptr = parr;
    return 0;
}

/* Frama-C: skipped — [serialization] protobuf cleanup */
void array_proto_free(AutonomousTrust__Core__Protobuf__Structures__Data **parr, size_t n)
{
    if (parr == NULL)
        return;
    for (size_t i = 0; i < n; i++) {
        if (parr[i] != NULL) {
            data_proto_free(parr[i]);
            free(parr[i]);
        }
    }
    free(parr);
}

/* Frama-C: skipped — [serialization] protobuf deserialization */
int array_sync_in(AutonomousTrust__Core__Protobuf__Structures__Data **parr, size_t n, array_t *array)
{
    for(int i=0; i<n; i++) {
        data_t *elt = smrt_create(sizeof(data_t));
        if (elt == NULL)
            return EXCEPTION(ENOMEM);
        data_sync_in(parr[i], elt);
        if (array_append(array, elt) != 0)
            return -1;
    }
    return 0;
}

/* Frama-C: skipped — [serialization] jansson JSON serialization */
int array_to_json(const void *data_struct, json_t **obj_ptr)
{
    const array_t *array = data_struct;
    *obj_ptr = json_object();
    json_t *obj = *obj_ptr;
    if (obj == NULL)
        return EXCEPTION(ENOMEM);

    json_object_set_new(obj, "size", json_integer(array->size));
    json_t *j_arr = json_array();
    for (int i=0; i<array->size; i++) {
        json_t *dat;
        if (data_to_json(array->array[i], &dat) < 0)
            return -1;
        json_array_append_new(j_arr, dat);
    }
    json_object_set_new(obj, "array", j_arr);
    return 0;
}

/* Frama-C: skipped — [serialization] jansson JSON deserialization */
int array_from_json(const json_t *obj, void *data_struct)
{
    array_t *array = data_struct;
    array->size = json_integer_value(json_object_get(obj, "size"));
    array->array = smrt_create(array->size * sizeof(data_t *));
    json_t *j_arr = json_object_get(obj, "array");
    for (int i=0; i<array->size; i++) {
        json_t *elt = json_array_get(j_arr, i);
        array->array[i] = smrt_create(sizeof(data_t));
        data_from_json(elt, array->array[i]);
    }
    return 0;
}
