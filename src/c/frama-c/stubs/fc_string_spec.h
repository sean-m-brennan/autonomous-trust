/********************
 * Frama-C WP-compatible wrappers for memcpy/memcmp.
 *
 * Problem: Frama-C's libc specs for memcpy/memcmp declare their pointer
 * parameters as `char *` (signed char). This project consistently uses
 * `uint8_t *` (unsigned char) for byte buffers, which causes WP's Typed
 * memory model to hide sub-term definitions at each call site:
 *
 *   [wp] Warning: Hide sub-term definition
 *     Reason: Cast with incompatible pointers types (source: uint8*)
 *             (target: sint8*)
 *
 * As a consequence WP introduces fresh opaque pointers (w, w_1, ...)
 * for the cast-through args, and no caller-side precondition can be
 * related back to them — every valid_src/valid_dest/separation goal
 * on a memcpy or memcmp call times out.
 *
 * Solution: redirect memcpy/memcmp to wrappers whose signatures AND
 * ACSL both use `unsigned char *`. The redirecting macro applies the
 * (unsigned char *) cast explicitly in source — so WP sees one cast
 * at the visible call site rather than implicit casts hidden through
 * void* or through libc's char* params. Since uint8_t IS unsigned
 * char, the cast is an identity for our uint8_t * call sites.
 *
 * This header is force-included (-include) so it is processed BEFORE
 * any source file. By including <string.h> here first, we ensure the
 * real declarations are parsed before the macros are defined. When
 * source files later #include <string.h>, the include guard makes it
 * a no-op — the macros only affect call sites, not decls.
 *
 * Copyright 2025 Sean M. Brennan and contributors
 * SPDX-License-Identifier: Apache-2.0
 *******************/

#ifndef FC_STRING_SPEC_H
#define FC_STRING_SPEC_H

#ifdef __FRAMAC__

/* Step 1: Pull in the real string declarations (with include guard set).
 * This ensures memcpy/memcmp are declared as functions BEFORE we shadow
 * them with macros below. */
#include <string.h>
#include <stddef.h>

/* Step 2: Declare wrapper functions with ACSL contracts using
 * `unsigned char *` semantics inside the spec. WP sees these as regular
 * extern functions and uses the contracts directly. */

/*@
  requires n == 0 || \valid(dest + (0 .. n - 1));
  requires n == 0 || \valid_read(src + (0 .. n - 1));
  requires n == 0 || \separated(dest + (0 .. n - 1), src + (0 .. n - 1));
  assigns dest[0 .. n - 1] \from src[0 .. n - 1];
  ensures \result == (void *)dest;
*/
extern void *at_memcpy(unsigned char *dest,
                       const unsigned char *src,
                       size_t n);

/*@
  requires n == 0 || \valid_read(s1 + (0 .. n - 1));
  requires n == 0 || \valid_read(s2 + (0 .. n - 1));
  assigns \result \from s1[0 .. n - 1], s2[0 .. n - 1], n;
  ensures \result == 0 <==>
          (n == 0 ||
           \forall integer k; 0 <= k < n ==> s1[k] == s2[k]);
*/
extern int at_memcmp(const unsigned char *s1,
                     const unsigned char *s2,
                     size_t n);

/* Step 3: Redirect call sites via macros that apply the cast to
 * `unsigned char *` explicitly. For callers that already pass
 * uint8_t * (== unsigned char * on Linux), this cast is an identity
 * in WP's Typed memory model — it neither introduces an opaque
 * pointer region nor requires a cross-region reasoning step, so
 * caller-side preconditions flow straight to the wrapper's ACSL. */

#define memcpy(d, s, n)  at_memcpy((unsigned char *)(d), \
                                   (const unsigned char *)(s), (n))
#define memcmp(a, b, n)  at_memcmp((const unsigned char *)(a), \
                                   (const unsigned char *)(b), (n))

#endif /* __FRAMAC__ */
#endif /* FC_STRING_SPEC_H */
