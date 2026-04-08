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

#include "allocation.h"

void *smrt_create(size_t size)
{
    void *ptr = calloc(1, size);
    if (ptr == NULL)
        return ptr;
    //@ assert ptr != \null;
    smrt_ptr_t *sptr = ptr;
    sptr->alloc = true;
    sptr->refs = 1;
    //@ assert sptr->alloc == true && sptr->refs == 1;
    return ptr;
}

void *smrt_recreate(void *orig, size_t size)
{
    void *ptr = realloc(orig, size);
    if (ptr == NULL)
        return ptr;
    //@ assert ptr != \null;
    return ptr;
}

void smrt_ref(void *ptr)
{
    smrt_ptr_t *sptr = ptr;
    //@ assert sptr->refs >= 1;
    //@ assert sptr->refs < 18446744073709551615UL;
    sptr->refs++;
    //@ assert sptr->refs == \at(sptr->refs, Pre) + 1;
}

/*
 * Internal implementation of smart-pointer dereference.
 * Always call through the smrt_deref() macro (see allocation.h), which
 * NULLs the caller's pointer after this function returns, preventing
 * use-after-free on the caller's side.  Note that other aliases to the
 * same allocation are *not* automatically invalidated — callers must
 * ensure no stale copies remain.
 */
/*@
  requires ptr == \null || \valid((smrt_ptr_t *)ptr);
  requires ptr != \null ==> ((smrt_ptr_t *)ptr)->refs >= 1;
  behavior null_ptr:
    assumes ptr == \null;
    assigns \nothing;
    frees \nothing;
  behavior last_ref:
    assumes ptr != \null;
    assumes ((smrt_ptr_t *)ptr)->alloc == true;
    assumes ((smrt_ptr_t *)ptr)->refs == 1;
    assigns ((smrt_ptr_t *)ptr)->alloc,
            ((smrt_ptr_t *)ptr)->refs;
    frees ptr;
  behavior decrement:
    assumes ptr != \null;
    assumes ((smrt_ptr_t *)ptr)->refs > 1;
    assigns ((smrt_ptr_t *)ptr)->refs;
    ensures ((smrt_ptr_t *)ptr)->refs == \old(((smrt_ptr_t *)ptr)->refs) - 1;
    frees \nothing;
  behavior not_allocated:
    assumes ptr != \null;
    assumes ((smrt_ptr_t *)ptr)->alloc == false;
    assumes ((smrt_ptr_t *)ptr)->refs == 1;
    assigns ((smrt_ptr_t *)ptr)->refs;
    frees \nothing;
  disjoint behaviors;
*/
void _smrt_deref_impl(void *ptr)
{
    if (ptr == NULL)
        return;
    //@ assert ptr != \null;
    smrt_ptr_t *sptr = ptr;
    //@ assert sptr->refs >= 1;
    sptr->refs--;
    //@ assert sptr->refs == \at(sptr->refs, Pre) - 1;
    if (sptr->alloc && sptr->refs <= 0) {
        //@ assert sptr->alloc == true && sptr->refs == 0;
        sptr->alloc = false;
        sptr->refs = 0;
        free(ptr);
        //@ assert \at(sptr->alloc, Pre) == true;
    }
    //@ assert sptr->refs == \at(sptr->refs, Pre) - 1 || \at(sptr->refs, Pre) == 1;
}
