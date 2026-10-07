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

#ifndef ALLOCATION_H
#define ALLOCATION_H

/** @addtogroup internal_utilities
 *  @{
 */

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

/** Written by smrt_create into @c magic; anything else is not an smrt block. */
#define SMRT_MAGIC 0x534d52545f484452ULL  /* "SMRT_HDR" */

/**
 * Header at offset 0 of every smrt allocation.
 *
 * @c magic is a canary: smrt_create writes SMRT_MAGIC, and smrt_deref is a
 * no-op on a block that does not carry it. A buffer written from offset 0
 * (a string, a packed protobuf, a raw struct copy) destroys it, so a stray
 * smrt_deref of such a buffer can neither decrement payload bytes as @c refs
 * nor call payload bytes as @c dtor. smrt_create is for structs that embed
 * this header; plain buffers come from malloc/calloc and go back via free.
 *
 * @c dtor is an optional finalizer, called with the allocation's own address
 * when the LAST reference is dropped, just before the block is freed. It
 * releases whatever the struct owns beyond its own bytes (e.g. a @c data_t's
 * STRING/BYTES buffer). It must not free the block itself or touch @c refs.
 * smrt_create leaves it NULL; the owning type's constructor sets it.
 *
 * The layout is mirrored by the CFFI cdef (core/_native/_ffi.py) — once as
 * this typedef and once inline in every struct that embeds it.
 */
typedef struct {
    uint64_t magic;
    bool alloc;
    size_t refs;
    void (*dtor)(void *);
} smrt_ptr_t;

/*@ predicate smrt_valid(smrt_ptr_t *p) =
      \valid(p) && p->alloc == true && p->refs >= 1;
*/

/*@ axiomatic SmrtPtrInvariant {
      axiom smrt_refs_positive:
        \forall smrt_ptr_t s; s.alloc == true ==> s.refs >= 1;
    }
*/

/*@
  requires size > 0;
  requires size >= sizeof(smrt_ptr_t);
  assigns \result \from size;
  ensures \result == \null ||
    (\valid((char *)\result + (0 .. size - 1)) &&
     ((smrt_ptr_t *)\result)->magic == SMRT_MAGIC &&
     ((smrt_ptr_t *)\result)->alloc == true &&
     ((smrt_ptr_t *)\result)->refs == 1 &&
     ((smrt_ptr_t *)\result)->dtor == \null);
*/
void *smrt_create(size_t size);

/*@
  requires \valid(pptr);
  requires *pptr == \null || \valid((char *)*pptr + (0 .. size - 1));
  requires size > 0;
  assigns *pptr;
  ensures \result == 0 || \result != 0;
*/
/**
 * @brief Resize @c *pptr to @p size bytes.
 * @details On success (return 0), @c *pptr is replaced with the (possibly
 * moved) new block. On failure (non-zero), @c *pptr is unchanged and still
 * points at the original block — no memory is leaked and no dangling
 * pointer is produced. This contract is enforced by the double-pointer
 * API: callers cannot accidentally overwrite the original pointer on
 * failure, unlike a plain realloc-shaped signature.
 */
int smrt_recreate(void **pptr, size_t size);

/*@
  requires \valid((smrt_ptr_t *)ptr);
  requires ((smrt_ptr_t *)ptr)->alloc == true;
  requires ((smrt_ptr_t *)ptr)->refs >= 1;
  requires ((smrt_ptr_t *)ptr)->refs < 18446744073709551615UL;
  assigns ((smrt_ptr_t *)ptr)->refs;
  ensures ((smrt_ptr_t *)ptr)->refs == \old(((smrt_ptr_t *)ptr)->refs) + 1;
*/
void smrt_ref(void *ptr);

/*@
  requires ptr == \null || \valid((smrt_ptr_t *)ptr);
  requires ptr != \null && ((smrt_ptr_t *)ptr)->magic == SMRT_MAGIC
           ==> ((smrt_ptr_t *)ptr)->refs >= 1;
  assigns ((smrt_ptr_t *)ptr)->magic,
          ((smrt_ptr_t *)ptr)->alloc,
          ((smrt_ptr_t *)ptr)->refs;
  behavior null_ptr:
    assumes ptr == \null;
    assigns \nothing;
  behavior not_smrt:
    assumes ptr != \null;
    assumes ((smrt_ptr_t *)ptr)->magic != SMRT_MAGIC;
    assigns \nothing;
  behavior last_ref:
    assumes ptr != \null;
    assumes ((smrt_ptr_t *)ptr)->magic == SMRT_MAGIC;
    assumes ((smrt_ptr_t *)ptr)->alloc == true;
    assumes ((smrt_ptr_t *)ptr)->refs == 1;
    ensures ((smrt_ptr_t *)ptr)->refs == 0;
  behavior decrement:
    assumes ptr != \null;
    assumes ((smrt_ptr_t *)ptr)->magic == SMRT_MAGIC;
    assumes ((smrt_ptr_t *)ptr)->refs > 1;
    ensures ((smrt_ptr_t *)ptr)->refs == \old(((smrt_ptr_t *)ptr)->refs) - 1;
  disjoint behaviors;
*/
void _smrt_deref_impl(void *ptr);

/**
 * @brief free() for FFI callers.
 *
 * Plain buffers the library hands out (the *_to_proto outputs,
 * net_message_to_wire_fmt, ...) come from malloc and must go back through
 * free, never smrt_deref. A foreign caller cannot name libc's free through
 * the library handle reliably, so this exports it.
 */
void at_free(void *ptr);

/* Macro NULLs the caller's pointer after free to prevent use-after-free */
#define smrt_deref(ptr) do { _smrt_deref_impl(ptr); (ptr) = NULL; } while(0)


/** @} */ /* end of internal_utilities */

#endif  // ALLOCATION_H
