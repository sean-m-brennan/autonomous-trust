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
#ifndef AT_CONTACTS_DIRECTORY_H
#define AT_CONTACTS_DIRECTORY_H

/**
 * @file directory.h
 * @brief Directory entries and the attestations behind them
 * (FIRST_CONTACT_PLAN §4.3, Phase 3). C twin of Python first_contact/directory.py:
 * same formats, same checks in the same order, same refusal reasons.
 *
 *     Attestation := issuer over "at-dir-attest-v1|" + body
 *       body := {v, typename: "at-dir-attest", handle, key, issuer, expiry}
 *     Entry       := holder over "at-dir-entry-v1|" + body
 *       body := {v, typename: "at-dir-entry", handle, uuid, key, visibility,
 *                seq, expiry, attestation: {body, sig}}
 *
 * An attestation is an issuer's word that a handle belongs to a KEY; an entry
 * is the holder's opt-in to be found by it. Neither grants trust.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <jansson.h>

#include "identity/identity.h"

#define AT_DIR_ATTEST_DOMAIN "at-dir-attest-v1|"
#define AT_DIR_ENTRY_DOMAIN "at-dir-entry-v1|"
#define AT_DIR_ATTEST_TYPENAME "at-dir-attest"
#define AT_DIR_ENTRY_TYPENAME "at-dir-entry"
#define AT_DIR_VERSION 1
#define AT_DIR_VISIBILITY_ANYONE "anyone"
#define AT_DIR_VISIBILITY_PUBLISHED "published"
/** Longest handle in bytes. Same as Python's HANDLE_MAX. */
#define AT_DIR_HANDLE_MAX 128
/** An entry's default lifetime (30 days). Same as Python's. */
#define AT_DIR_DEFAULT_TTL_SECONDS (30L * 24 * 3600)

/** Refusal reasons; -status indexes Python's directory.REASONS. */
typedef enum {
    AT_DIR_OK = 0,
    AT_DIR_MALFORMED = -1,
    AT_DIR_BAD_SIG = -2,
    AT_DIR_EXPIRED = -3,
    AT_DIR_UNTRUSTED = -4,
    AT_DIR_MISMATCH = -5,
} at_dir_status_t;

/** A signed object: the exact body bytes, their parse, and the signature. */
typedef struct {
    json_t *body;          /* the parse of body_str (owned) */
    char *body_str;        /* the EXACT signed bytes (owned) */
    char sig_hex[129];
} at_dir_signed_t;

/** @p in folded to lower case into @p out (room for AT_DIR_HANDLE_MAX + 1).
 *  0, or -1 when it is not a handle: ASCII [a-z0-9._@+-], 1..128 bytes. */
int at_dir_normalize_handle(const char *in, char *out, size_t out_len);

/** Parse {body, sig} (@p wire, or its JSON @p text). Does NOT verify. */
int at_dir_from_wire(const json_t *wire, at_dir_signed_t *out);
int at_dir_from_text(const char *text, at_dir_signed_t *out);
/** {body, sig}, new reference. */
json_t *at_dir_to_wire(const at_dir_signed_t *obj);
void at_dir_free(at_dir_signed_t *obj);

/** Verify an attestation at @p now; @p trusted (hex keys, @p n_trusted of
 *  them) limits the issuer when non-NULL. An at_dir_status_t. */
int at_dir_attest_verify(const at_dir_signed_t *att, const char *const *trusted,
                         size_t n_trusted, double now);
/** Verify an entry and the attestation it carries, which must be for the
 *  same handle and key. An at_dir_status_t. */
int at_dir_entry_verify(const at_dir_signed_t *entry, const char *const *trusted,
                        size_t n_trusted, double now);

/** Sign an attestation that @p handle belongs to @p key_hex, with the issuer
 *  keypair's 64-byte secret key @p issuer_sk. For tests and issuer tooling. */
int at_dir_attest(const unsigned char *issuer_sk, const char *handle,
                  const char *key_hex, long expiry, at_dir_signed_t *out);
/** Sign @p self's entry for the handle @p att vouches for. @p expiry 0 = the
 *  default lifetime; either way capped at the attestation's expiry. */
int at_dir_create_entry(const identity_t *self, const at_dir_signed_t *att,
                        int64_t seq, const char *visibility, long expiry,
                        double now, at_dir_signed_t *out);

/** Sign @p body (stolen, even on failure) with the 64-byte secret key @p sk
 *  over @p domain + its compact JSON; the {body, sig} into @p out. Shared by
 *  every {body, sig} record in contacts/ (the directory's, device certs). */
int at_dir_sign(const unsigned char *sk, const char *domain, json_t *body,
                at_dir_signed_t *out);
/** AT_DIR_OK iff @p obj's sig is @p key_hex's over @p domain + its exact body. */
int at_dir_check_sig(const char *key_hex, const char *domain, const at_dir_signed_t *obj);
/** 64 lower-case hex digits: an ed25519 public key as the records carry it. */
bool at_dir_is_hex_key(const char *key);

/* -- the contact request a finder sends ------------------------------------ */
#define AT_DIR_REQUEST_DOMAIN "at-contact-request-v1|"
#define AT_DIR_REQUEST_TYPENAME "at-contact-request"
/** How long a request stands, by default. Same as Python's REQUEST_TTL_SECONDS. */
#define AT_DIR_REQUEST_TTL_SECONDS 3600
/** Most relay hints a request names. Same as Python's REQUEST_MAX_RELAYS. */
#define AT_DIR_REQUEST_MAX_RELAYS 4
/** A request nonce: 32 lower-case hex digits. */
#define AT_DIR_NONCE_HEX 32

/** Verify a contact request at @p now: well formed, signed by its own @c key,
 *  unexpired. Whether it is addressed to US, for a handle we published, from
 *  the sender the envelope names, is the receiver's check. Same checks, same
 *  order, as Python ContactRequest.verify. An at_dir_status_t. */
int at_dir_request_verify(const at_dir_signed_t *req, double now);
/** Sign @p self's request to the holder of @p entry. @p nonce NULL = a fresh
 *  one; @p expiry 0 = @p now + AT_DIR_REQUEST_TTL_SECONDS. At most
 *  AT_DIR_REQUEST_MAX_RELAYS of @p relays are kept. */
int at_dir_request_create(const identity_t *self, const at_dir_signed_t *entry,
                          const char *const *relays, size_t n_relays,
                          const char *nonce, long expiry, double now,
                          at_dir_signed_t *out);
/** Request fields ("from", "to" lower-cased as Python's properties). */
const char *at_dir_request_from(const at_dir_signed_t *req);
const char *at_dir_request_to(const at_dir_signed_t *req);
const char *at_dir_request_nonce(const at_dir_signed_t *req);

/** Borrowed field accessors (NULL / 0 when absent). */
const char *at_dir_handle(const at_dir_signed_t *obj);
const char *at_dir_key(const at_dir_signed_t *obj);
const char *at_dir_uuid(const at_dir_signed_t *obj);
const char *at_dir_visibility(const at_dir_signed_t *obj);
const char *at_dir_issuer(const at_dir_signed_t *obj);
int64_t at_dir_seq(const at_dir_signed_t *obj);
long at_dir_expiry(const at_dir_signed_t *obj);

#endif /* AT_CONTACTS_DIRECTORY_H */
