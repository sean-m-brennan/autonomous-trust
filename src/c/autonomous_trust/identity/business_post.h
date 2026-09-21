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
 * @file business_post.h
 * @brief Business-post body model: canonical form, Ed25519 sign/verify, and the
 *        blake2b content-address id (Phase 3, P3.4 — business posts in the feed).
 *
 * A "business post" is what a polity SAYS, where its page is what it IS. It
 * carries one opaque, SELF-VERIFYING Ethne bundle — `{post, delegation}`,
 * proving polity-root -> envoy -> post — together with the signed statement of
 * the node that put it on the wire. It is distributed by encrypted GROUP
 * MULTICAST and GOSSIP-FORWARDED a bounded number of hops, exactly like a feed
 * post and UNLIKE a business ad.
 *
 * WHY IT RELAYS WHERE AN AD DOES NOT. An ad is a recommendation, so it is only
 * ever spoken in the first person by a customer and carries that customer's own
 * satisfaction (business_ad.h). A post is the business's own words, and its
 * authority does not come from whoever passed it along — it comes from the
 * envoy signature inside the bundle, which no relay can forge or alter. So a
 * post may be carried by anyone, unchanged, with a hop count to bound how far.
 *
 * TWO INDEPENDENT TRUST LAYERS meet here and MUST NOT be confused:
 *   - The AT layer (this file): a DETACHED Ed25519 signature binding WHO
 *     PUBLISHED these exact bundle bytes, at which seq and when. A relay
 *     forwards that signature untouched and changes only the hop count, so a
 *     post keeps ONE content id however many paths it travels — which is what
 *     makes gossip converge instead of multiplying copies. It says nothing
 *     about who may speak for the business.
 *   - The Ethne layer: the bundle proves polity-root -> envoy -> post. The core
 *     NEVER parses it — it is opaque bytes here. The APP verifies it
 *     (ethne_business_post_verify_bundle). Keeping the core out of Ethne is what
 *     lets a post be verified by a reader with no charter log.
 * A node on the business's roll is NOT thereby allowed to speak for it. That
 * distinction is the whole point of box 5, and it lives in the Ethne layer.
 *
 * THE AUDIENCE GATE IS NOT HERE. A receiver drops a post whose polity it holds
 * no page for, and does not relay it (id_proc.c). This file neither knows nor
 * enforces that; it only makes the bytes checkable.
 *
 * CANONICAL (the cross-language crux; no JSON, whose whitespace/key-order
 * diverge):
 *
 *   canonical = author_uuid[16]
 *             || u32le(did_len)    || polity_did_bytes
 *             || u64le(seq)
 *             || f64le(ts)                 (raw IEEE-754 little-endian)
 *             || u32le(bundle_len) || bundle_bytes
 *
 * HOPS ARE DELIBERATELY ABSENT from the canonical form, exactly as in post.h: a
 * relay increments the hop count, so signing over it would invalidate the
 * signature at the first forward. It travels in the JSON envelope only.
 *
 * The blake2b-256 hash of the canonical bytes, lowercase-hex, is the post's
 * content id (@ref AT_BUSINESS_POST_ID_HEX_LEN chars) — the dedup/merge key
 * that makes gossip converge, and what forecloses replay (a replay carries a
 * seen id; a fresh id cannot be minted without the author's key). MUST stay in
 * lockstep with the Python business_post_canonical()/business_post_id() in
 * capabilities.py.
 */

#ifndef AUTONOMOUS_TRUST_IDENTITY_BUSINESS_POST_H
#define AUTONOMOUS_TRUST_IDENTITY_BUSINESS_POST_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <uuid/uuid.h>
#include <sodium.h>
#include <jansson.h>

/* Max bytes of the opaque Ethne post bundle (excluding NUL). MEASURED, not
 * guessed: the bundle's fixed cost (the polity-root SpeakerDelegation, two
 * signature blocks and the JSON frame) is ~1514 bytes, and the Ethne side
 * clamps the body to 512 CHARS, which is 4 bytes each at worst — so the
 * worst-case bundle measures 3550 bytes and this leaves 546 spare. The
 * measurement is re-taken on every run by
 * `the_worst_case_post_bundle_fits_the_wire_bound` in ethne_ffi/src/lib.rs.
 *
 * A POST DOES NOT REUSE THE PAGE'S 3072: the same arithmetic there would leave
 * a business ~370 characters. It still stays UNDER the co-signing payload
 * (6144), so at_app_event_t's union does not widen and agora_events_poll's
 * batch budget is untouched. MUST match AT_BUSINESS_POST_BUNDLE_LEN
 * (utilities/msg_types.h), AT_APP_BUSINESS_POST_BUNDLE_LEN (app_events.h), and
 * AGORA_BUSINESS_POST_BUNDLE_MAX in the shim / cohort ctypes. */
#define AT_BUSINESS_POST_BUNDLE_MAX 4096

/* Max bytes of a polity DID (excluding NUL). A did:key Ed25519 DID is 56 chars;
 * this leaves room for other methods. Same bound as a business ad's, pinned
 * against AT_BUSINESS_DID_LEN (msg_types.h) in the .c. */
#define AT_BUSINESS_POST_DID_MAX 95

/* Content id: blake2b-256 digest, lowercase hex (32 bytes -> 64 chars). */
#define AT_BUSINESS_POST_ID_HEX_LEN 64

/* Detached Ed25519 signature as lowercase hex (crypto_sign_BYTES * 2 + NUL). */
#define AT_BUSINESS_POST_SIG_HEX_LEN (crypto_sign_BYTES * 2)

/* Upper bound on the canonical buffer: uuid + u32+did + u64 + f64 +
 * u32+bundle. No hop byte — see the header. */
#define AT_BUSINESS_POST_CANON_MAX \
    (16 + 4 + AT_BUSINESS_POST_DID_MAX + 8 + 8 + 4 + AT_BUSINESS_POST_BUNDLE_MAX)

/* Copy @p in into @p out (capacity @p out_sz including the NUL), truncated to at
 * most AT_BUSINESS_POST_BUNDLE_MAX bytes AND to fit @p out_sz. Always
 * NUL-terminates when @p out_sz > 0. Returns the number of bytes written
 * (excluding NUL). A NULL @p in yields an empty string. */
size_t at_business_post_bound_bundle(const char *in, char *out, size_t out_sz);

/* As @ref at_business_post_bound_bundle, but to AT_BUSINESS_POST_DID_MAX — for
 * the polity DID. */
size_t at_business_post_bound_did(const char *in, char *out, size_t out_sz);

/* Write the canonical signing bytes for a business post into @p out. Returns the
 * number of bytes written, or (size_t)-1 if it would exceed @p outcap. THE
 * cross-language contract — see the header. @p polity_did and @p bundle are
 * bound-truncated before hashing so the canonical matches what is carried. */
size_t at_business_post_canonical(const uuid_t author_uuid,
                                  const char *polity_did, int64_t seq, double ts,
                                  const char *bundle, uint8_t *out, size_t outcap);

/* blake2b-256 over the canonical bytes -> lowercase hex content id into
 * @p id_hex_out (capacity AT_BUSINESS_POST_ID_HEX_LEN + 1). Returns 0 on
 * success. */
int at_business_post_content_id(const uuid_t author_uuid, const char *polity_did,
                                int64_t seq, double ts, const char *bundle,
                                char *id_hex_out);

/* Sign the canonical form with the author's Ed25519 secret key @p sk; write the
 * detached signature as lowercase hex (AT_BUSINESS_POST_SIG_HEX_LEN + NUL) into
 * @p sig_hex_out. Returns 0 on success. */
int at_business_post_sign(const unsigned char sk[crypto_sign_SECRETKEYBYTES],
                          const uuid_t author_uuid, const char *polity_did,
                          int64_t seq, double ts, const char *bundle,
                          char *sig_hex_out);

/* Verify @p sig_hex (lowercase hex detached signature) over the canonical bytes
 * against the author's Ed25519 public key @p pk. Returns true iff valid. */
bool at_business_post_verify(const unsigned char pk[crypto_sign_PUBLICKEYBYTES],
                             const uuid_t author_uuid, const char *polity_did,
                             int64_t seq, double ts, const char *bundle,
                             const char *sig_hex);

/* Build a NEW json object (caller decrefs) holding the wire form
 * {"author","author_pk","polity","seq","ts","bundle","sig","hops"} with the did
 * and bundle bound-truncated. @p hops rides OUTSIDE the signature, which is
 * precisely so a relay can increment it while forwarding everything else
 * verbatim — see the header. Returns NULL on allocation error. */
json_t *at_business_post_to_json(const uuid_t author_uuid,
                                 const char *author_pk_hex,
                                 const char *polity_did, int64_t seq, double ts,
                                 const char *bundle, const char *sig_hex,
                                 int hops);

/* Parse a peer_business_post payload. Requires string author + author_pk +
 * polity + bundle + sig, integer seq + hops, numeric ts. Bound-truncates the did
 * and bundle into their outputs (always NUL-terminated) and copies the raw pk /
 * sig hex. Writes the scalar outputs on success. Returns 0 on success, non-zero
 * on a malformed payload (an empty polity did, or a negative hop count, is
 * malformed). Unknown keys ignored. */
int at_business_post_from_json(const json_t *obj, uuid_t author_out,
                               char author_pk_out[AT_BUSINESS_POST_SIG_HEX_LEN + 1],
                               char *did_out, size_t did_sz,
                               int64_t *seq_out, double *ts_out,
                               char *bundle_out, size_t bundle_sz,
                               char sig_out[AT_BUSINESS_POST_SIG_HEX_LEN + 1],
                               int *hops_out);

#endif /* AUTONOMOUS_TRUST_IDENTITY_BUSINESS_POST_H */
