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

#ifndef AT_CONTACTS_REACH_H
#define AT_CONTACTS_REACH_H

/**
 * @file reach.h
 * @brief Signed reachability records (FIRST_CONTACT_PLAN §4.2). C twin of
 * Python contacts/reach.py; the two sign, file and verify the same records.
 *
 * A node's own statement of how to reach it now -- its relays (pinned hints)
 * and any direct endpoints -- signed by its identity key over
 * "at-reach-v1|" + the EXACT body bytes transmitted, numbered and dated:
 *
 *     body := {v, typename: "at-reach", uuid, key, seq, expiry, relays, endpoints}
 *     wire := {body: <body string>, sig: <hex>}
 *
 * Filed and looked up by the fingerprint of its key (net_relay_key_fingerprint).
 * The highest unexpired seq wins; a receiver refuses a seq at or below the one
 * it applied, and applies a record to a CONTACT only when its key is the key
 * that contact already has on record.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <jansson.h>

#include "identity/identity.h"

#define AT_REACH_DOMAIN "at-reach-v1|"
#define AT_REACH_TYPENAME "at-reach"
#define AT_REACH_VERSION 1
/** A record's default lifetime (a week). Same as Python's. */
#define AT_REACH_DEFAULT_TTL_SECONDS (7L * 24 * 3600)
/** Most endpoints one record carries. Same as Python's MAX_ENDPOINTS. */
#define AT_REACH_MAX_ENDPOINTS 4

typedef enum {
    AT_REACH_OK = 0,
    AT_REACH_MALFORMED = -1,
    AT_REACH_BAD_SIG = -2,
    AT_REACH_EXPIRED = -3,
} at_reach_status_t;

typedef struct {
    json_t *body;          /* the parse of body_str (owned) */
    char *body_str;        /* the EXACT signed bytes (owned) */
    char sig_hex[129];
} at_reach_record_t;

/** Parse @p wire ({body, sig}) into @p out. Does NOT verify. */
int at_reach_from_wire(const json_t *wire, at_reach_record_t *out);
/** Parse the JSON text of a wire record. Does NOT verify. */
int at_reach_from_text(const char *text, at_reach_record_t *out);
/** The key's own signature over the body, and unexpired at @p now. */
int at_reach_verify(const at_reach_record_t *rec, double now);
/** Sign a record for @p self. @p expiry absolute (0 = never). */
int at_reach_create(const identity_t *self, int64_t seq,
                    const char *const *relays, size_t n_relays,
                    const char *const *endpoints, size_t n_endpoints,
                    long expiry, at_reach_record_t *out);
/** {body, sig}, new reference. */
json_t *at_reach_to_wire(const at_reach_record_t *rec);

const char *at_reach_uuid(const at_reach_record_t *rec);
const char *at_reach_key(const at_reach_record_t *rec);
int64_t at_reach_seq(const at_reach_record_t *rec);
long at_reach_expiry(const at_reach_record_t *rec);
/** The relays / endpoints arrays (borrowed; may be NULL). */
json_t *at_reach_relays(const at_reach_record_t *rec);
json_t *at_reach_endpoints(const at_reach_record_t *rec);
/** Where the record is filed: the fingerprint of its key, into @p out. */
int at_reach_record_id(const at_reach_record_t *rec, char *out, size_t out_len);

void at_reach_free(at_reach_record_t *rec);

#endif /* AT_CONTACTS_REACH_H */
