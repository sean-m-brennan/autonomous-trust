/********************
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
 *******************/

#ifndef NEG_CERTIFIED_H
#define NEG_CERTIFIED_H

/**
 * @file neg_certified.h
 * @brief Certified-result wire helpers (R+D.md §12.3) the core keeps.
 *
 * The `certificate` payload key and the `{"at_certified": ...}` wrapper are
 * negotiation wire format: a worker splits a certifying capability's result
 * before it goes on the wire whether or not this node can CHECK witnesses, so
 * these stay in the core while the checking moved to libat_certificates
 * (FEATURE_SPLIT_PLAN Phase 3). Names kept for their callers.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief A fresh 64-bit verifier challenge seed.
 *
 * The requirement is that the peer could not have predicted this before it
 * answered, so this draws from the system CSPRNG rather than from a
 * process-global PRNG that anything else in the node may have observed or
 * reseeded. Mirrors Python certificates.default_seed().
 */
uint64_t at_cert_verifier_seed(void);

/****************************
 * Producing a witness
 *
 * The C twin of Python's `Certified(answer, witness)` wrapper. A certifying
 * capability writes
 *
 *     {"at_certified": {"value": <answer>, "certificate": <witness>}}
 *
 * into its result buffer, and the worker splits the two apart before they go
 * on the wire, so the reply carries them in SEPARATE fields exactly as Python
 * does. A marker key rather than a bare {"value", "certificate"} object
 * because the split must never be a guess: an answer that legitimately had
 * those keys would otherwise be silently torn in half, and the checker would
 * then be verifying the wrong object.
 *
 * A wrapper rather than a new out-parameter on capability_result_function_t:
 * that signature is already implemented by every declared capability, and
 * widening it for a feature most capabilities will never use would break them
 * all to serve the few.
 ****************************/

/**
 * @brief Split a possibly-wrapped result into its answer and its witness.
 *
 * @param result_json  What the capability wrote.
 * @param value_out    Receives the answer as JSON text (the whole input when
 *                     it is not wrapped).
 * @param cert_out     Receives the witness as JSON text, or "" when there is
 *                     none. May be NULL.
 * @return true if the input was a wrapped result.
 */
bool at_cert_split_result(const char *result_json,
                          char *value_out, size_t value_len,
                          char *cert_out, size_t cert_len);

/**
 * @brief Build the wrapper a certifying capability should emit.
 * @return true on success; false if the buffer is too small or either input
 *         is not JSON.
 */
bool at_cert_wrap_result(const char *value_json, const char *certificate_json,
                         char *out, size_t out_len);

#endif /* NEG_CERTIFIED_H */
