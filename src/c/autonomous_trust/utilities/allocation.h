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

#ifndef ALLOCATION_H
#define ALLOCATION_H

#include <stdlib.h>
#include <stdbool.h>

typedef struct {
    bool alloc;
    size_t refs;
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
     ((smrt_ptr_t *)\result)->alloc == true &&
     ((smrt_ptr_t *)\result)->refs == 1);
*/
void *smrt_create(size_t size);

/*@
  requires orig == \null || \valid((char *)orig + (0 .. size - 1));
  requires size > 0;
  assigns \nothing;
  ensures \result == \null ||
    \valid((char *)\result + (0 .. size - 1));
*/
void *smrt_recreate(void *orig, size_t size);

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
  requires ptr != \null ==> ((smrt_ptr_t *)ptr)->refs >= 1;
  assigns ((smrt_ptr_t *)ptr)->alloc,
          ((smrt_ptr_t *)ptr)->refs;
  behavior null_ptr:
    assumes ptr == \null;
    assigns \nothing;
  behavior last_ref:
    assumes ptr != \null;
    assumes ((smrt_ptr_t *)ptr)->alloc == true;
    assumes ((smrt_ptr_t *)ptr)->refs == 1;
    ensures ((smrt_ptr_t *)ptr)->refs == 0;
  behavior decrement:
    assumes ptr != \null;
    assumes ((smrt_ptr_t *)ptr)->refs > 1;
    ensures ((smrt_ptr_t *)ptr)->refs == \old(((smrt_ptr_t *)ptr)->refs) - 1;
  disjoint behaviors;
*/
void _smrt_deref_impl(void *ptr);

/* Macro NULLs the caller's pointer after free to prevent use-after-free */
#define smrt_deref(ptr) do { _smrt_deref_impl(ptr); (ptr) = NULL; } while(0)

#endif  // ALLOCATION_H
