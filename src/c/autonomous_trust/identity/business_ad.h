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
 * @file business_ad.h
 * @brief Business-ad body model: canonical form, Ed25519 sign/verify, and the
 *        blake2b content-address id (Phase 3, P3.2 — "businesses near me").
 *
 * A "business ad" carries one business page — an opaque, SELF-VERIFYING Ethne
 * bundle — together with the signed statement of the node that is advertising
 * it. It is distributed by encrypted GROUP MULTICAST, like a feed post.
 *
 * THE ONE STRUCTURAL DIFFERENCE FROM A POST: a post is relayed by any peer, so
 * it carries a hop count. A business ad is NEVER relayed. Only a CUSTOMER
 * carries a business's page, and a customer does not forward someone else's ad —
 * it RE-ADVERTISES from its own cache, in the first person, signed with its own
 * key and its own satisfaction. So every ad on the wire is a node speaking for
 * itself, there is no hop count, and a business's reach is exactly the sum of
 * its customers' voices. Distribution and reputation are the same fact.
 *
 * TWO INDEPENDENT TRUST LAYERS meet here and MUST NOT be confused:
 *   - The AT layer (this file): a DETACHED Ed25519 signature binding WHO is
 *     advertising, HOW satisfied they are, and WHICH EXACT page bytes they mean.
 *     Because the bundle bytes are inside the canonical form, an endorsement
 *     cannot be lifted off one page and re-attached to another.
 *   - The Ethne layer: the bundle itself proves polity-root -> envoy -> page.
 *     The core NEVER parses it — it is opaque bytes here. The APP verifies it
 *     (ethne_business_page_verify_bundle). Keeping the core out of Ethne is what
 *     lets the page be verified by a stranger with no charter log.
 *
 * SATISFACTION is 0..4 (@ref AT_BUSINESS_SAT_MIN .. @ref AT_BUSINESS_SAT_MAX),
 * or @ref AT_BUSINESS_SAT_SELF for a business advertising its OWN page. An
 * unhappy customer does not publish a negative — it simply stops advertising,
 * so silence is the only negative signal and there is nothing to brigade with.
 *
 * CANONICAL (the cross-language crux; no JSON, whose whitespace/key-order
 * diverge):
 *
 *   canonical = advertiser_uuid[16]
 *             || u32le(did_len)    || polity_did_bytes
 *             || u8(satisfaction)
 *             || u64le(page_seq)
 *             || f64le(ts)                 (raw IEEE-754 little-endian)
 *             || u32le(bundle_len) || bundle_bytes
 *
 * The blake2b-256 hash of the canonical bytes, lowercase-hex, is the ad's
 * content id (@ref AT_BUSINESS_AD_ID_HEX_LEN chars) — the dedup/merge key, and
 * what forecloses replay (a replay carries a seen id; a fresh id cannot be
 * minted without the advertiser's key). MUST stay in lockstep with the Python
 * business_ad_canonical()/business_ad_id() in capabilities.py.
 */

#ifndef AUTONOMOUS_TRUST_IDENTITY_BUSINESS_AD_H
#define AUTONOMOUS_TRUST_IDENTITY_BUSINESS_AD_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <uuid/uuid.h>
#include <sodium.h>
#include <jansson.h>

/* Max bytes of the opaque Ethne page bundle (excluding NUL). A real bundle with
 * every page field at its Ethne-side bound measures ~2.4 KB (a did:key is 56
 * chars, the Signed<BusinessPage> ~1.5 KB, the SpeakerDelegation ~0.9 KB), so
 * this leaves room for the artifact to grow without an ABI break — and stays
 * UNDER the post body (4096), so the app-event union does not widen. MUST match
 * AT_BUSINESS_BUNDLE_LEN (utilities/msg_types.h), AT_APP_BUSINESS_BUNDLE_LEN
 * (app_events.h), and AGORA_BUSINESS_BUNDLE_MAX in the shim / cohort ctypes. */
#define AT_BUSINESS_BUNDLE_MAX 3072

/* Max bytes of a polity DID (excluding NUL). A did:key Ed25519 DID is 56 chars;
 * this leaves room for other methods. MUST match AT_BUSINESS_DID_LEN
 * (msg_types.h), AT_APP_BUSINESS_DID_LEN (app_events.h) and
 * AGORA_BUSINESS_DID_MAX in the shim / cohort ctypes. */
#define AT_BUSINESS_DID_MAX 95

/* Content id: blake2b-256 digest, lowercase hex (32 bytes -> 64 chars). MUST
 * match AT_BUSINESS_AD_ID_LEN (msg_types.h), AT_APP_BUSINESS_AD_ID_LEN
 * (app_events.h) and AGORA_BUSINESS_AD_ID_MAX in the shim / cohort ctypes. */
#define AT_BUSINESS_AD_ID_HEX_LEN 64

/* Detached Ed25519 signature as lowercase hex (crypto_sign_BYTES * 2 + NUL). */
#define AT_BUSINESS_AD_SIG_HEX_LEN (crypto_sign_BYTES * 2)

/* Satisfaction a customer may declare: 0 (kept the receipt, no more) .. 4
 * (delighted). Ranking weighs this by the reader's OWN tie strength to the
 * advertiser, so a stranger's 4 counts for almost nothing. */
#define AT_BUSINESS_SAT_MIN 0
#define AT_BUSINESS_SAT_MAX 4

/* A business advertising its OWN page. Not a customer rating: it is excluded
 * from the vouch term app-side, because self-vouching is free. */
#define AT_BUSINESS_SAT_SELF 0xFF

/* Upper bound on the canonical buffer: uuid + u32+did + u8 + u64 + f64 +
 * u32+bundle. */
#define AT_BUSINESS_AD_CANON_MAX \
    (16 + 4 + AT_BUSINESS_DID_MAX + 1 + 8 + 8 + 4 + AT_BUSINESS_BUNDLE_MAX)

/* True iff @p sat is a declarable customer satisfaction (0..4) or the
 * business's own AT_BUSINESS_SAT_SELF marker. */
bool at_business_sat_valid(unsigned sat);

/* Copy @p in into @p out (capacity @p out_sz including the NUL), truncated to at
 * most AT_BUSINESS_BUNDLE_MAX bytes AND to fit @p out_sz. Always NUL-terminates
 * when @p out_sz > 0. Returns the number of bytes written (excluding NUL). A
 * NULL @p in yields an empty string. */
size_t at_business_bound_bundle(const char *in, char *out, size_t out_sz);

/* As @ref at_business_bound_bundle, but to AT_BUSINESS_DID_MAX — for the polity
 * DID. */
size_t at_business_bound_did(const char *in, char *out, size_t out_sz);

/* Write the canonical signing bytes for a business ad into @p out. Returns the
 * number of bytes written, or (size_t)-1 if it would exceed @p outcap. THE
 * cross-language contract — see the header. @p polity_did and @p bundle are
 * bound-truncated before hashing so the canonical matches what is carried. */
size_t at_business_ad_canonical(const uuid_t advertiser_uuid,
                                const char *polity_did, uint8_t satisfaction,
                                int64_t page_seq, double ts, const char *bundle,
                                uint8_t *out, size_t outcap);

/* blake2b-256 over the canonical bytes -> lowercase hex content id into
 * @p id_hex_out (capacity AT_BUSINESS_AD_ID_HEX_LEN + 1). Returns 0 on success. */
int at_business_ad_content_id(const uuid_t advertiser_uuid,
                              const char *polity_did, uint8_t satisfaction,
                              int64_t page_seq, double ts, const char *bundle,
                              char *id_hex_out);

/* Sign the canonical form with the advertiser's Ed25519 secret key @p sk; write
 * the detached signature as lowercase hex (AT_BUSINESS_AD_SIG_HEX_LEN + NUL)
 * into @p sig_hex_out. Returns 0 on success. */
int at_business_ad_sign(const unsigned char sk[crypto_sign_SECRETKEYBYTES],
                        const uuid_t advertiser_uuid, const char *polity_did,
                        uint8_t satisfaction, int64_t page_seq, double ts,
                        const char *bundle, char *sig_hex_out);

/* Verify @p sig_hex (lowercase hex detached signature) over the canonical bytes
 * against the advertiser's Ed25519 public key @p pk. Returns true iff valid. */
bool at_business_ad_verify(const unsigned char pk[crypto_sign_PUBLICKEYBYTES],
                           const uuid_t advertiser_uuid, const char *polity_did,
                           uint8_t satisfaction, int64_t page_seq, double ts,
                           const char *bundle, const char *sig_hex);

/* Build a NEW json object (caller decrefs) holding the wire form
 * {"advertiser","advertiser_pk","polity","sat","seq","ts","bundle","sig"} with
 * the did and bundle bound-truncated. NOTE: no "hops" — an ad is never relayed,
 * only re-advertised in the first person (see the header). Returns NULL on
 * allocation error. */
json_t *at_business_ad_to_json(const uuid_t advertiser_uuid,
                               const char *advertiser_pk_hex,
                               const char *polity_did, uint8_t satisfaction,
                               int64_t page_seq, double ts, const char *bundle,
                               const char *sig_hex);

/* Parse a peer_business_ad payload. Requires string advertiser + advertiser_pk +
 * polity + bundle + sig, integer sat + seq, numeric ts. Bound-truncates the did
 * and bundle into their outputs (always NUL-terminated) and copies the raw pk /
 * sig hex. Writes the scalar outputs on success. Returns 0 on success, non-zero
 * on a malformed payload (an out-of-range satisfaction, or an empty polity did,
 * is malformed). Unknown keys ignored. */
int at_business_ad_from_json(const json_t *obj, uuid_t advertiser_out,
                             char advertiser_pk_out[AT_BUSINESS_AD_SIG_HEX_LEN + 1],
                             char *did_out, size_t did_sz,
                             uint8_t *sat_out, int64_t *seq_out, double *ts_out,
                             char *bundle_out, size_t bundle_sz,
                             char sig_out[AT_BUSINESS_AD_SIG_HEX_LEN + 1]);

#endif /* AUTONOMOUS_TRUST_IDENTITY_BUSINESS_AD_H */
