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
 * @file profile.h
 * @brief agora.profile field model, canonical serialization, and Ed25519
 *        signing/verification (AT "with-distance" Increment 3).
 *
 * A profile is a small set of OPTIONAL, bounded, operator-set fields a node
 * shares with admitted peers on request (the peer_profile_query/response
 * exchange in id_proc.c, modeled on the position exchange). Every field is
 * bounded in BYTES (not codepoints) so the receiver's bound-check unit matches
 * the signer's clamp unit across the C and Python runtimes.
 *
 * SIGNING (the cross-language crux): a profile carries a detached Ed25519
 * signature over a CANONICAL byte serialization that BOTH runtimes must produce
 * identically, or no cross-runtime signature verifies. The canonical form is
 * deliberately framing-only (no JSON, whose whitespace/key-order/escaping
 * diverge):
 *
 *   canonical = signer_uuid[16]
 *             || field(display_name) || field(handle)
 *             || field(bio)          || field(avatar_ref)
 *             || u32le(num_links) || field(link[0]) .. field(link[n-1])
 *   where field(s) = u32le(byte_len(s)) || utf8_bytes(s)   (absent/empty => len 0)
 *
 * The signer_uuid binds the profile to its identity, so a validly-signed
 * profile cannot be re-attributed to another node on relay. The receiver
 * reconstructs canonical from the RECEIVED field values (as-is) using the
 * SENDER's uuid and verifies before any local clamping — so only this framing,
 * not the sanitize step, must match byte-for-byte across runtimes. MUST stay in
 * lockstep with Python profile_canonical() in capabilities.py.
 */

#ifndef AUTONOMOUS_TRUST_IDENTITY_PROFILE_H
#define AUTONOMOUS_TRUST_IDENTITY_PROFILE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <uuid/uuid.h>
#include <jansson.h>
#include <sodium.h>

/* Takes raw Ed25519 keys (see at_profile_sign/verify) rather than identity_t so
 * this unit stays independent of the identity struct layout. Callers pass
 * ident->signature.private / peer->signature.public. */

/* Per-field byte bounds (excluding NUL). MUST match Python
 * capabilities.PROFILE_MAX_* and the app-boundary caps in app_events.h. */
#define AT_PROFILE_MAX_DISPLAY_NAME 64
#define AT_PROFILE_MAX_HANDLE       32
#define AT_PROFILE_MAX_BIO          256
#define AT_PROFILE_MAX_AVATAR_REF   128
#define AT_PROFILE_MAX_LINK         128
#define AT_PROFILE_MAX_LINKS        4

/* Detached Ed25519 signature as lowercase hex (crypto_sign_BYTES * 2 + NUL). */
#define AT_PROFILE_SIG_HEX_LEN (crypto_sign_BYTES * 2)

/* Max bytes of the COMPACT profile JSON that crosses the AT->app boundary (the
 * sanitized field object; the signature does not cross). Sized for the worst
 * case: every field at its byte bound with quote/backslash escaping (~2x) plus
 * JSON framing. MUST match AT_APP_PROFILE_JSON_LEN (app_events.h) and
 * AGORA_PROFILE_JSON_MAX (the shim / cohort ctypes). */
#define AT_PROFILE_JSON_MAX 2560

/* Flat, fixed-size profile. Empty string ("") == field absent. */
typedef struct
{
    char display_name[AT_PROFILE_MAX_DISPLAY_NAME + 1];
    char handle[AT_PROFILE_MAX_HANDLE + 1];
    char bio[AT_PROFILE_MAX_BIO + 1];
    char avatar_ref[AT_PROFILE_MAX_AVATAR_REF + 1];
    char links[AT_PROFILE_MAX_LINKS][AT_PROFILE_MAX_LINK + 1];
    uint8_t num_links;
} at_profile_t;

/* True if every field is empty (opted out / no profile set). */
bool at_profile_is_empty(const at_profile_t *p);

/* Parse a wire/app "profile" JSON object into @p out.
 *
 * @param validate  When true (RECEIVE path), REJECT (return non-zero, leaving
 *                   @p out zeroed) if any field exceeds its byte bound, if
 *                   `handle` contains a char outside [A-Za-z0-9_.-], or if
 *                   links exceeds AT_PROFILE_MAX_LINKS. A well-behaved signer
 *                   already clamped, so an over-bound field means a misbehaving
 *                   peer — dropped, mirroring an invalid geohash.
 *                   When false (used only for locally-trusted input), fields are
 *                   truncated to their bounds instead.
 * Returns 0 on success, non-zero on reject/error. Unknown keys are ignored.
 */
int at_profile_from_json(const json_t *obj, bool validate, at_profile_t *out);

/* Build a NEW json object (caller decrefs) holding only the non-empty fields,
 * in fixed key order. Returns NULL on error. */
json_t *at_profile_to_json(const at_profile_t *p);

/* Serialize @p p to compact JSON into @p out (NUL-terminated). Returns the
 * written length (excluding NUL), or -1 if it would not fit @p outcap. Empty
 * profile yields "{}". Used to fill the app-boundary profile_json buffer. */
int at_profile_to_compact_str(const at_profile_t *p, char *out, size_t outcap);

/* Write the canonical signing bytes for (@p signer_uuid, @p p) into @p out.
 * Returns the number of bytes written, or (size_t)-1 if it would exceed
 * @p outcap. THE cross-language contract — see the file header. */
size_t at_profile_canonical(const uuid_t signer_uuid, const at_profile_t *p,
                            uint8_t *out, size_t outcap);

/* Sign (@p signer_uuid, @p p) with the Ed25519 secret key @p sk; write the
 * detached signature as lowercase hex (AT_PROFILE_SIG_HEX_LEN + NUL) into
 * @p sig_hex_out. Returns 0 on success. */
int at_profile_sign(const unsigned char sk[crypto_sign_SECRETKEYBYTES],
                    const uuid_t signer_uuid, const at_profile_t *p,
                    char *sig_hex_out);

/* Verify @p sig_hex (lowercase hex detached signature) over the canonical bytes
 * of (@p signer_uuid, @p p) against the Ed25519 public key @p pk. Returns true
 * iff the signature is valid. */
bool at_profile_verify(const unsigned char pk[crypto_sign_PUBLICKEYBYTES],
                       const uuid_t signer_uuid, const at_profile_t *p,
                       const char *sig_hex);

#endif /* AUTONOMOUS_TRUST_IDENTITY_PROFILE_H */
