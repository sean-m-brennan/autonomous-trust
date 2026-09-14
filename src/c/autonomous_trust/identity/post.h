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
 * @file post.h
 * @brief Feed-post body model: canonical form, Ed25519 sign/verify, and the
 *        blake2b content-address id (Increment 7).
 *
 * A "post" is a signed, content-addressed feed item distributed by encrypted
 * GROUP MULTICAST and gossip-forwarded a bounded number of hops. Unlike a DM
 * (whose crypto_box envelope authenticates the sender), a post is relayed by
 * peers other than its author, so the author identity CANNOT come from the wire
 * envelope: the post carries a DETACHED Ed25519 signature over a canonical,
 * framing-only serialization that binds author+seq+ts+required_tier+body. Any
 * receiver — including one a hop beyond the author's own cohort — verifies that
 * signature against the author's signing key before acting.
 *
 * CANONICAL (the cross-language crux; no JSON, whose whitespace/key-order
 * diverge):
 *
 *   canonical = author_uuid[16]
 *             || u64le(seq)
 *             || f64le(ts)                 (raw IEEE-754 little-endian)
 *             || u8(required_tier)
 *             || u32le(body_len) || body_bytes
 *
 * The blake2b-256 hash of the canonical bytes, lowercase-hex, is the post's
 * content id (@ref AT_POST_ID_HEX_LEN chars) — the dedup/merge key. MUST stay in
 * lockstep with the Python post_canonical()/post_content_id() in capabilities.py.
 */

#ifndef AUTONOMOUS_TRUST_IDENTITY_POST_H
#define AUTONOMOUS_TRUST_IDENTITY_POST_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <uuid/uuid.h>
#include <sodium.h>
#include <jansson.h>

/* Max bytes of a post body (excluding NUL). MUST match AT_POST_BODY_LEN
 * (utilities/msg_types.h), AT_APP_POST_BODY_LEN (app_events.h), and
 * AGORA_POST_BODY_MAX in the shim / cohort ctypes. */
#define AT_POST_BODY_MAX 4096

/* Content id: blake2b-256 digest, lowercase hex (32 bytes -> 64 chars). MUST
 * match AT_POST_ID_LEN (msg_types.h), AT_APP_POST_ID_LEN (app_events.h) and
 * AGORA_POST_ID_MAX in the shim / cohort ctypes. */
#define AT_POST_ID_HEX_LEN 64

/* Detached Ed25519 signature as lowercase hex (crypto_sign_BYTES * 2 + NUL). */
#define AT_POST_SIG_HEX_LEN (crypto_sign_BYTES * 2)

/* Audience tiers a post may require (mirrors the reputation trust tiers 0..4 and
 * the app-side PostAudience bands). A reader delivers a post only when its own
 * view of the AUTHOR's tier meets required_tier. */
#define AT_POST_TIER_MIN 0
#define AT_POST_TIER_MAX 4

/* Upper bound on the canonical buffer: uuid + u64 + f64 + u8 + u32 + body. */
#define AT_POST_CANON_MAX (16 + 8 + 8 + 1 + 4 + AT_POST_BODY_MAX)

/* Copy @p in into @p out (capacity @p out_sz including the NUL), truncated to at
 * most AT_POST_BODY_MAX bytes AND to fit @p out_sz. Always NUL-terminates when
 * @p out_sz > 0. Returns the number of bytes written (excluding NUL). A NULL
 * @p in yields an empty string. */
size_t at_post_bound_body(const char *in, char *out, size_t out_sz);

/* Write the canonical signing bytes for a post into @p out. Returns the number
 * of bytes written, or (size_t)-1 if it would exceed @p outcap. THE
 * cross-language contract — see the header. @p body is bound-truncated to
 * AT_POST_BODY_MAX before hashing so the canonical matches what is carried. */
size_t at_post_canonical(const uuid_t author_uuid, int64_t seq, double ts,
                         uint8_t required_tier, const char *body,
                         uint8_t *out, size_t outcap);

/* blake2b-256 over the canonical bytes -> lowercase hex content id into
 * @p id_hex_out (capacity AT_POST_ID_HEX_LEN + 1). Returns 0 on success. */
int at_post_content_id(const uuid_t author_uuid, int64_t seq, double ts,
                       uint8_t required_tier, const char *body,
                       char *id_hex_out);

/* Sign the canonical (author, seq, ts, tier, body) with the author's Ed25519
 * secret key @p sk; write the detached signature as lowercase hex
 * (AT_POST_SIG_HEX_LEN + NUL) into @p sig_hex_out. Returns 0 on success. */
int at_post_sign(const unsigned char sk[crypto_sign_SECRETKEYBYTES],
                 const uuid_t author_uuid, int64_t seq, double ts,
                 uint8_t required_tier, const char *body, char *sig_hex_out);

/* Verify @p sig_hex (lowercase hex detached signature) over the canonical bytes
 * of (author, seq, ts, tier, body) against the author's Ed25519 public key
 * @p pk. Returns true iff the signature is valid. */
bool at_post_verify(const unsigned char pk[crypto_sign_PUBLICKEYBYTES],
                    const uuid_t author_uuid, int64_t seq, double ts,
                    uint8_t required_tier, const char *body, const char *sig_hex);

/* Build a NEW json object (caller decrefs) holding the wire form
 * {"author","author_pk","seq","ts","tier","body","sig","hops"} with the body
 * bound-truncated. Returns NULL on allocation error. */
json_t *at_post_to_json(const uuid_t author_uuid, const char *author_pk_hex,
                        int64_t seq, double ts, uint8_t required_tier,
                        const char *body, const char *sig_hex, int hops);

/* Parse a peer_post payload. Requires string author + author_pk + sig, integer
 * seq + tier + hops, numeric ts, string body. Bound-truncates @c body into
 * @p body_out (capacity @p body_sz, always NUL-terminated) and copies the raw
 * author_pk / sig hex into their outputs. Writes the scalar outputs on success.
 * Returns 0 on success, non-zero on a malformed payload. Unknown keys ignored. */
int at_post_from_json(const json_t *obj, uuid_t author_out,
                      char author_pk_out[AT_POST_SIG_HEX_LEN + 1],
                      int64_t *seq_out, double *ts_out,
                      uint8_t *tier_out, char *body_out, size_t body_sz,
                      char sig_out[AT_POST_SIG_HEX_LEN + 1], int *hops_out);

#endif /* AUTONOMOUS_TRUST_IDENTITY_POST_H */
