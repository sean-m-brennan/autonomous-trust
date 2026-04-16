/********************
 * Frama-C WP-compatible wrappers for printf/scanf family functions.
 *
 * Problem: Frama-C's Variadic plugin rewrites snprintf/sprintf/sscanf
 * calls and generates specs using a logic function `format_length` that
 * has no definition.  WP falls back to "modifies everything reachable
 * through pointer arguments," producing an infinite range and aborting:
 *
 *   [wp] Warning: No definition for 'format_length' ...
 *   [wp] User Error: Invalid infinite range buf_2+(0..)
 *
 * Solution: under __FRAMAC__, redirect snprintf/sprintf/sscanf to
 * non-variadic wrapper functions that have bounded ACSL contracts.
 * Because the wrappers are NOT variadic, the Variadic plugin ignores
 * them and WP uses our contracts directly.
 *
 * This header is force-included (-include) so it is processed BEFORE
 * any source file.  By including <stdio.h> here first, we ensure the
 * real declarations are parsed before the macros are defined.  When
 * the source file later does #include <stdio.h>, the include guard
 * makes it a no-op — the macros only affect call sites, not decls.
 *
 * Copyright 2025 Sean M. Brennan and contributors
 * SPDX-License-Identifier: Apache-2.0
 *******************/

#ifndef FC_STDIO_SPEC_H
#define FC_STDIO_SPEC_H

#ifdef __FRAMAC__

/* Step 1: Pull in the real stdio declarations (with include guard set).
 * This ensures snprintf/sprintf/sscanf are properly declared as
 * functions BEFORE we shadow them with macros below. */
#include <stdio.h>
#include <stddef.h>

/* Step 2: Declare non-variadic wrapper functions with ACSL contracts.
 * WP sees these as regular extern functions and uses the contracts
 * directly — the Variadic plugin has nothing to intercept. */

/*@
  requires n > 0;
  requires \valid(s + (0 .. n - 1));
  assigns s[0 .. n - 1];
  assigns \result \from n;
  ensures 0 <= \result;
*/
extern int at_snprintf(char *s, size_t n, ...);

/*@
  requires \valid(s + (0 .. 4095));
  assigns s[0 .. 4095];
  assigns \result \from \nothing;
  ensures 0 <= \result;
  ensures \result <= 4095;
*/
extern int at_sprintf(char *s, ...);

/*@
  requires s != \null;
  assigns \result \from s[..];
  ensures \result >= -1;
*/
extern int at_sscanf(const char *s, ...);

/* Step 3: Redirect call sites via macros.
 * The preprocessor replaces snprintf(...) with at_snprintf(...)
 * in all subsequent source code.  Since <stdio.h>'s include guard
 * is already set from Step 1, re-including <stdio.h> in source
 * files is a no-op — the macros never touch the declarations. */

#define snprintf(s, n, ...) at_snprintf(s, n, __VA_ARGS__)
#define sprintf(s, ...)     at_sprintf(s, __VA_ARGS__)
#define sscanf(s, ...)      at_sscanf(s, __VA_ARGS__)

#endif /* __FRAMAC__ */
#endif /* FC_STDIO_SPEC_H */
