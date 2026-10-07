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
    a->magic = 0;
    a->alloc = false;
    a->refs = 0;
    a->size = 0;
    /* The element buffer is a plain heap block of data_t pointers, NOT an
     * smrt allocation: slot 0 sits at offset 0, so an smrt header there is
     * overwritten by the first element, and a deref of the buffer then reads
     * a pointer as `refs` and a pointer as `dtor`. */
    a->array = calloc(1, sizeof(data_t *));
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
    arr->magic = SMRT_MAGIC;
    arr->alloc = true;
    arr->refs = 1;
    if (err != 0)
    {
        /* No element buffer: hand back nothing rather than a half-built
         * array the caller would have to know to release. */
        smrt_deref(arr);
        *array_ptr = NULL;
    }
    return err;
}

/* Frama-C: skipped — [solver-timeout] memcpy valid_src/valid_dest preconditions */
int array_copy(array_t *a, array_t *cpy)
{
    if (a == NULL)
        return EXCEPTION(EINVAL);
    data_t **buf = calloc(a->size > 0 ? a->size : 1, sizeof(data_t *));
    if (buf == NULL)
        return EXCEPTION(ENOMEM);
    memcpy(buf, a->array, sizeof(data_t *) * a->size);
    /* The copy owns a reference to each element: array_free derefs every
     * element of whichever array it is given, so a copy that shared them
     * unreferenced released them once per array. */
    for (size_t i = 0; i < a->size; i++)
        smrt_ref(buf[i]);
    free(cpy->array);  /* cpy is zeroed or array_init'd: NULL or init's slot */
    cpy->array = buf;
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

/* Frama-C: skipped — [alloc-pattern] releases the dropped elements */
size_t array_keep_if(array_t *a, bool (*keep)(data_t *, void *), void *ctx)
{
    size_t kept = 0;
    for (size_t i = 0; i < a->size; i++)
    {
        data_t *e = a->array[i];
        if (keep(e, ctx))
            a->array[kept++] = e;
        else
            smrt_deref(e);
    }
    size_t dropped = a->size - kept;
    for (size_t i = kept; i < a->size; i++)
        a->array[i] = NULL;
    a->size = kept;
    return dropped;
}

static void _owned_array_dtor(void *ptr)
{
    data_t *dat = ptr;
    if (dat->obj != NULL)
        array_free((array_t *)dat->obj);
    dat->obj = NULL;
}

data_t *owned_array_data(array_t *a)
{
    data_t *dat = object_ptr_data(a, sizeof(array_t));
    if (dat == NULL)
        return dat;
    dat->dtor = _owned_array_dtor;
    return dat;
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
            data_t **grown = realloc(a->array, (a->size + 1) * sizeof(data_t *));
            if (grown == NULL)
                return EXCEPTION(ENOMEM);
            a->array = grown;
        }
        a->size++;
        a->array[index] = element;
        return 0;
    }
    /* Overwrite: the array ADOPTS the caller's reference and releases the
     * element it displaces, as map_set does. Guarded against a self-assign,
     * where the release would free the element being stored. */
    data_t *displaced = a->array[index];
    a->array[index] = element;
    if (displaced != element)
        smrt_deref(displaced);
    return 0;
}

/* Frama-C: skipped — [alloc-pattern] memmove compaction */
int array_remove_at(array_t *a, int index)
{
    if (index < 0)
        index = (int)a->size + index;
    if (index < 0 || (size_t)index >= a->size)
        return EXCEPTION(EARR_OOB);
    data_t *removed = a->array[index];
    size_t n = a->size - ((size_t)index + 1);
    if (n > 0)
        memmove(a->array + index, a->array + index + 1, n * sizeof(data_t *));
    a->size--;
    a->array[a->size] = NULL;
    /* The array's reference leaves with the element, as map_remove's does.
     * A caller that still needs it takes its own (smrt_ref) first. */
    smrt_deref(removed);
    return 0;
}

int array_remove(array_t *a, data_t *element)
{
    /* array_find matches by VALUE (data_equal), so what leaves may be an
     * equal element rather than @p element itself. A caller that knows the
     * slot uses array_remove_at. */
    int index = array_find(a, element);
    if (index < 0)
        return EXCEPTION(EARR_NOELT);
    return array_remove_at(a, index);
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
    free(a->array);
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
    array->array = calloc(array->size > 0 ? array->size : 1, sizeof(data_t *));
    if (array->array == NULL)
        return -1;
    json_t *j_arr = json_object_get(obj, "array");
    for (int i=0; i<array->size; i++) {
        json_t *elt = json_array_get(j_arr, i);
        array->array[i] = smrt_create(sizeof(data_t));
        if (array->array[i] == NULL)
            return -1;
        data_from_json(elt, array->array[i]);
    }
    return 0;
}
