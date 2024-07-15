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

#include "allocation.h"

void *smrt_create(size_t size)
{
    void *ptr = calloc(1, size);
    if (ptr == NULL)
        return ptr;
    smrt_ptr_t *sptr = ptr;
    sptr->alloc = true;
    sptr->refs = 1;
    return ptr;
}

void *smrt_recreate(void *orig, size_t size)
{
    void *ptr = realloc(orig, size);
    if (ptr == NULL)
        return ptr;
    return ptr;
}

void smrt_ref(void *ptr)
{
    smrt_ptr_t *sptr = ptr;
    sptr->refs++;
}

void smrt_deref(void *ptr)
{
    smrt_ptr_t *sptr = ptr;
    sptr->refs--;
    if (sptr->alloc && sptr->refs <= 0)
        free(ptr);
}
