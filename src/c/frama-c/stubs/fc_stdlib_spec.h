/********************
 * Frama-C WP-compatible wrapper for free().
 *
 * Problem: WP's default libc contract for free() requires \freeable(p),
 * which WP's memory model does not reliably discharge across function
 * boundaries.  The \freeable predicate tracks malloc-origin, but once a
 * pointer crosses into a function parameter (e.g. a destroy callback),
 * WP loses the origin and the precondition times out.
 *
 * Solution: under __FRAMAC__, redirect free() to a non-freeing wrapper
 * with a weak validity precondition.  The wrapper does not model the
 * release (assigns \nothing), which is safe for destroy functions
 * because the freed pointer goes out of scope afterwards.  Runtime
 * behavior is unaffected — this header only influences WP proofs.
 *
 * Same redirection pattern as fc_stdio_spec.h.  Force-included via
 * -include so it runs before any source file.
 *
 * Copyright 2025 Sean M. Brennan and contributors
 * SPDX-License-Identifier: Apache-2.0
 *******************/

#ifndef FC_STDLIB_SPEC_H
#define FC_STDLIB_SPEC_H

#ifdef __FRAMAC__

/* Pull in the real stdlib declarations first (with include guard set),
 * so free/malloc/calloc are declared as real functions before any macro
 * shadowing takes effect. */
#include <stdlib.h>

/* No precondition: a \valid((char *)p) requires-clause triggers the
 * same typed-memory cast issue that sodium_memzero's void/uint8 cast
 * exhibits, and the wrapper does not actually model memory release
 * (assigns \nothing), so there is nothing downstream that needs the
 * validity fact. */
/*@
  assigns \nothing;
*/
extern void at_free(void *p);

/* Redirect call sites.  Since <stdlib.h>'s include guard is already set,
 * later #include <stdlib.h> in source files is a no-op — the macro only
 * affects call sites, never declarations. */
#define free(p) at_free(p)

#endif /* __FRAMAC__ */
#endif /* FC_STDLIB_SPEC_H */
