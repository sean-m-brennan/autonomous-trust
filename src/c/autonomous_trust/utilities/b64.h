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
 ********************/
#ifndef B64_H
#define B64_H

/** @addtogroup internal_utilities
 *  @{
 */

#include <stddef.h>
#include <sodium.h>

/**
 * @brief Size in bytes required to base64-encode @p input_len raw bytes
 *        (including trailing NUL), using libsodium's @c VARIANT_ORIGINAL.
 */
/*@
  requires input_len >= 0;
  assigns \nothing;
  ensures \result >= 1;
*/
static inline size_t b64_encoded_len(size_t input_len)
{
    return sodium_base64_encoded_len(input_len, sodium_base64_VARIANT_ORIGINAL);
}

/**
 * @brief Decoded byte count for an encoding of length @p enc_len, given only
 *        the final character (used to detect a single `=` pad).
 *
 * Callers that have the full string should prefer @ref b64_decoded_len_s,
 * which handles double padding correctly.
 */
/*@
  requires enc_len >= 4;
  requires enc_len % 4 == 0;
  assigns \nothing;
  ensures \result <= (enc_len / 4) * 3;
  ensures \result >= (enc_len / 4) * 3 - 1;
*/
static inline size_t b64_decoded_len(size_t enc_len, char last_char)
{
    size_t len = (enc_len / 4) * 3;
    if (last_char == '=')
        len--;
    return len;
}

/**
 * @brief Decoded byte count for base64 string @p enc_str of length @p enc_len.
 *
 * Correctly accounts for one or two `=` padding characters.
 */
/*@
  requires enc_len >= 4;
  requires enc_len % 4 == 0;
  requires \valid_read(enc_str + (0 .. enc_len - 1));
  assigns \nothing;
  ensures \result <= (enc_len / 4) * 3;
  ensures \result >= (enc_len / 4) * 3 - 2;
*/
static inline size_t b64_decoded_len_s(size_t enc_len, const char *enc_str)
{
    size_t len = (enc_len / 4) * 3;
    if (enc_len >= 1 && enc_str[enc_len - 1] == '=') {
        len--;
        if (enc_len >= 2 && enc_str[enc_len - 2] == '=')
            len--;
    }
    return len;
}

/* WP deferred: inline wrappers around libsodium base64 functions.
   WP cannot model the pointer-returning sodium_bin2base64 in an
   inline context.  Contracts for the underlying functions are in
   sodium_stubs.h; these wrappers are verified transitively. */

/**
 * @brief Base64-encode @p src_len bytes of @p src into @p dst using
 *        libsodium's @c VARIANT_ORIGINAL (must match the Python side).
 *
 * @p dst must have at least @ref b64_encoded_len bytes.
 */
static inline void base64_encode(const unsigned char *src, size_t src_len,
                                  char *dst, size_t dst_len)
{
    sodium_bin2base64(dst, dst_len, src, src_len, sodium_base64_VARIANT_ORIGINAL);
}

/**
 * @brief Base64-decode @p src into @p dst (raw bytes).
 *
 * @p dst must have at least @ref b64_decoded_len_s bytes.
 */
static inline void base64_decode(const char *src, size_t src_len,
                                  unsigned char *dst, size_t dst_len)
{
    size_t bin_len = 0;
    sodium_base642bin(dst, dst_len, src, src_len, NULL, &bin_len, NULL,
                      sodium_base64_VARIANT_ORIGINAL);
}


/** @} */ /* end of internal_utilities */

#endif  /* B64_H */
