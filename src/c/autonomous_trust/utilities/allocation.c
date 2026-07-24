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

#include "allocation.h"

void *smrt_create(size_t size)
{
    /* Every smrt allocation carries a smrt_ptr_t header at offset 0 (the
     * `sptr->alloc`/`sptr->refs` writes below). Callers that use smrt_create
     * as a plain buffer allocator (e.g. smrt_create(strlen(s) + 1) for a
     * string, or net_msg_pack_json for a short JSON payload) can request
     * fewer than sizeof(smrt_ptr_t) bytes; the header write would then run
     * past the allocation. Enforce the documented `requires size >=
     * sizeof(smrt_ptr_t)` precondition with a floor so the header always
     * fits. Over-allocating a few bytes is harmless — callers track their
     * own logical length separately. */
    if (size < sizeof(smrt_ptr_t))
        size = sizeof(smrt_ptr_t);
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

/* Frama-C: skipped — [solver-timeout] realloc libc spec inference of
 * assigns \from (unbounded heap state) causes assigns_normal_part2 to
 * time out regardless of explicit \from clauses or body simplification.
 * Experiments 2026-04-23: removing the `assert ptr != \null` and adding
 * `\from pptr, *pptr, size` both left the timeout unchanged. */
int smrt_recreate(void **pptr, size_t size)
{
    if (pptr == NULL)
        return -1;
    void *ptr = realloc(*pptr, size);
    if (ptr == NULL)
        return -1;
    *pptr = ptr;
    return 0;
}

/* WHY no runtime overflow check on refs:
 *
 * refs is size_t (uint64 on all supported platforms). An overflow would
 * require 2^64 live references to the same allocation, which is physically
 * impossible — every reference occupies at least one machine word of real
 * memory, so the pointer table alone would require 2^67 bytes. The ACSL
 * precondition `refs < UINT64_MAX` is therefore a static claim the calling
 * code trivially satisfies, not a runtime invariant that needs guarding.
 *
 * The assertions below carry that contract into WP so proofs of callers
 * (who pass arbitrary smrt_ptr_t*) can discharge the precondition via the
 * system-wide refcount axioms in allocation.h (SmrtPtrInvariant). Do not
 * replace with a branch-and-abort; it would add a proof obligation WP
 * cannot discharge without weakening the invariant. */
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

/* Real-symbol wrapper for FFI callers (Python via CFFI). The
 * smrt_deref macro at allocation.h:103 expands to
 * `_smrt_deref_impl(ptr); ptr = NULL;` so in-tree C code still
 * gets the NULL-on-deref safety net; this function exists only
 * because macros don't generate ELF symbols and Python's
 * `lib.smrt_deref(ptr)` would otherwise fail to resolve. The
 * NULL-on-deref behaviour isn't needed on the Python side: CFFI
 * wrappers track ownership themselves and __del__ runs at most
 * once per wrapper.
 *
 * #undef the macro before the function declaration so the
 * preprocessor doesn't mangle `smrt_deref(ptr)` into the
 * macro's `do { ... } while(0)` body. */
#undef smrt_deref
void smrt_deref(void *ptr)
{
    _smrt_deref_impl(ptr);
}
