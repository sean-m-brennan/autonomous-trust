/**
 * @file uuid_stubs.h
 * @brief ACSL-annotated stub declarations for libuuid functions used by
 *        AutonomousTrust.  Allows Frama-C/WP to verify code that
 *        generates, parses, compares and formats UUIDs.
 *
 * uuid_t is defined as unsigned char[16] by libuuid.
 * uuid_unparse_lower writes a 36-character string plus NUL (37 bytes).
 *
 * Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef UUID_STUBS_H
#define UUID_STUBS_H

#include <stddef.h>

/* uuid_t is unsigned char[16] in the real libuuid */
#ifndef _UUID_T_DEFINED
#define _UUID_T_DEFINED
typedef unsigned char uuid_t[16];
#endif

/* Canonical string length: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" (36 chars + NUL) */
#define UUID_STR_LEN 37

/* ================================================================
 * Generation
 * ================================================================ */

/*@
  requires \valid(out + (0 .. 15));
  assigns out[0 .. 15];
  // After this call, out contains a random (v4) UUID.
*/
void uuid_generate(uuid_t out);

/*@
  requires \valid(out + (0 .. 15));
  assigns out[0 .. 15];
*/
void uuid_generate_random(uuid_t out);

/* ================================================================
 * Parsing / Formatting
 * ================================================================ */

/*@
  requires \valid_read(uu + (0 .. 15));
  requires \valid(out + (0 .. UUID_STR_LEN - 1));
  assigns out[0 .. UUID_STR_LEN - 1];
  ensures out[36] == '\0';
  // Writes lowercase hex: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx\0"
*/
void uuid_unparse_lower(const uuid_t uu, char *out);

/*@
  requires \valid_read(uu + (0 .. 15));
  requires \valid(out + (0 .. UUID_STR_LEN - 1));
  assigns out[0 .. UUID_STR_LEN - 1];
  ensures out[36] == '\0';
*/
void uuid_unparse(const uuid_t uu, char *out);

/*@
  requires \valid_read(in);
  requires \valid(uu + (0 .. 15));
  assigns uu[0 .. 15];
  ensures \result == 0 || \result == -1;
  // 0 = success, -1 = parse error
*/
int uuid_parse(const char *in, uuid_t uu);

/* ================================================================
 * Comparison / Utility
 * ================================================================ */

/*@
  requires \valid_read(a + (0 .. 15));
  requires \valid_read(b + (0 .. 15));
  assigns \nothing;
  ensures \result < 0 || \result == 0 || \result > 0;
  // Semantics: memcmp-like ordering on the 16-byte UUIDs.
*/
int uuid_compare(const uuid_t a, const uuid_t b);

/*@
  requires \valid(uu + (0 .. 15));
  assigns uu[0 .. 15];
  ensures \forall integer i; 0 <= i < 16 ==> uu[i] == 0;
*/
void uuid_clear(uuid_t uu);

/*@
  requires \valid_read(dst + (0 .. 15));
  requires \valid_read(src + (0 .. 15));
  requires \separated(dst + (0 .. 15), src + (0 .. 15));
  assigns ((unsigned char *)dst)[0 .. 15];
  ensures \forall integer i; 0 <= i < 16 ==>
    ((unsigned char *)dst)[i] == ((unsigned char *)src)[i];
*/
void uuid_copy(uuid_t dst, const uuid_t src);

/*@
  requires \valid_read(uu + (0 .. 15));
  assigns \nothing;
  ensures \result == 0 || \result == 1;
  // 1 = the UUID is the NULL UUID (all zeros), 0 otherwise.
*/
int uuid_is_null(const uuid_t uu);

#endif /* UUID_STUBS_H */
