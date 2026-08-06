/* ******************
 *  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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
 * ****************** */

/* RFC 8785 JSON Canonicalization (JCS) for the AT C conformance harness.
 *
 * Mirrors `harness/common/canonical.py` on the Python side. The wire-byte
 * pinning contract is canonical-form equality: both implementations parse
 * their emitted JSON, walk it in JCS order, format numbers per ES6, and
 * byte-compare against the corpus fixture.
 *
 * Number formatting delegates to vendored Ryu d2s (see third_party/ryu/).
 *
 * Key-sort note: JCS specifies UTF-16 code-unit ordering. For BMP-only
 * ASCII keys (the only kind that appear in AT scenarios) UTF-8 byte order
 * is identical to UTF-16 code-unit order. Keys outside the BMP are not
 * supported; pinning a scenario with such keys is a corpus-author bug.
 */
#ifndef AT_CONFORMANCE_JCS_H
#define AT_CONFORMANCE_JCS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Canonicalise UTF-8 JSON input.  On success, returns 0 and sets *out to a
 * newly-malloc'd, NUL-terminated buffer of canonical bytes; *out_len receives
 * the byte length (excluding NUL).  Caller must free(*out).
 *
 * Returns:
 *    0   on success
 *   -1   on parse error or allocation failure (caller should treat the
 *        canonical form as "diverged" — the implementation under test
 *        emitted invalid JSON, which is itself a conformance failure).
 */
int jcs_canonicalize(const char *json_utf8, size_t len, char **out, size_t *out_len);

/* Test seam (ISSUES §2.1.2).  Reshape a Ryu `d2s_buffered_n` output to the
 * ES6/JCS canonical form, reading EXACTLY @p n_in bytes of @p ryu.
 *
 * Exposed only so a test can hand it a buffer that is deliberately NOT
 * NUL-terminated, which is the contract `d2s_buffered_n` actually provides and
 * the one that broke: the exponent used to be read with `strtol`, running off
 * the end into uninitialized stack and producing a garbage exponent in ~3% of
 * runs.  Since JCS is what wire bytes are signed over, that made a node sign a
 * byte string its verifier could not reproduce.  Going through the public
 * canonicalizer cannot pin this — whatever follows a local buffer is incidental
 * — so the counted contract is tested directly.
 *
 * Writes at most @p out_cap bytes to @p out (no NUL).
 *
 * @return the number of bytes written, or -1 on a malformed/oversized input.
 */
int jcs_es6_from_ryu_for_test(const char *ryu, size_t n_in,
                              char *out, size_t out_cap);

#ifdef __cplusplus
}
#endif

#endif /* AT_CONFORMANCE_JCS_H */
