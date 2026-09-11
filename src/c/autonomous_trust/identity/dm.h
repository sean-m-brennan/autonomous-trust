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

/**
 * @file dm.h
 * @brief Direct-message body model + wire JSON round-trip (Increment 6).
 *
 * A DM is a single directed, ENCRYPTED peer→peer text message carrying
 * {text, seq, ts}. crypto_box already authenticates the sender (only the real
 * peer's key produces the frame), so — UNLIKE the connection accept — there is
 * NO extra Ed25519 signature and NO canonical byte form: the payload is plain
 * JSON and the sender identity comes from the authenticated envelope. These
 * helpers only frame the payload and bound the body, so both the C handler and
 * the conformance adapter build/parse it identically. Mirrors the trivial
 * Python side (bound_dm_text in capabilities.py).
 */

#ifndef AUTONOMOUS_TRUST_IDENTITY_DM_H
#define AUTONOMOUS_TRUST_IDENTITY_DM_H

#include <stddef.h>
#include <stdint.h>
#include <jansson.h>

/* Max bytes of a DM body (excluding NUL). MUST match AT_DM_TEXT_LEN
 * (utilities/msg_types.h), AT_APP_DM_TEXT_LEN (app_events.h), and
 * AGORA_DM_TEXT_MAX in the shim / cohort ctypes. */
#define AT_DM_TEXT_MAX 1024

/* Copy @p in into @p out (capacity @p out_sz including the NUL), truncated to at
 * most AT_DM_TEXT_MAX bytes AND to fit @p out_sz. Always NUL-terminates when
 * @p out_sz > 0. Returns the number of bytes written (excluding NUL). A NULL
 * @p in yields an empty string. */
size_t at_dm_bound_text(const char *in, char *out, size_t out_sz);

/* Build a NEW json object (caller decrefs) holding {"text","seq","ts"} with the
 * body bound-truncated to AT_DM_TEXT_MAX. Returns NULL on allocation error. */
json_t *at_dm_to_json(const char *text, int64_t seq, double ts);

/* Parse a peer_dm payload {"text","seq","ts"}: require an integer seq and a
 * numeric ts (a stripped/mistyped field is refused), bound-truncate @c text into
 * @p text_out (capacity @p text_sz, always NUL-terminated). Writes @p seq_out
 * and @p ts_out on success. Returns 0 on success, non-zero on a malformed
 * payload (nothing written to the outputs on failure except @p text_out being
 * cleared). Unknown keys are ignored. */
int at_dm_from_json(const json_t *obj, char *text_out, size_t text_sz,
                    int64_t *seq_out, double *ts_out);

#endif /* AUTONOMOUS_TRUST_IDENTITY_DM_H */
