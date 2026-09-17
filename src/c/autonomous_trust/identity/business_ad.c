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

#include "identity/business_ad.h"
#include "utilities/msg_types.h"

#include <string.h>

/* The bounds are spelled once per header (self-contained like post.h/dm.h); a
 * drift between them would corrupt the app-boundary buffer, so pin them here
 * where both are visible. */
_Static_assert(AT_BUSINESS_BUNDLE_MAX == AT_BUSINESS_BUNDLE_LEN,
               "AT_BUSINESS_BUNDLE_MAX (business_ad.h) out of sync with "
               "AT_BUSINESS_BUNDLE_LEN (msg_types.h)");
_Static_assert(AT_BUSINESS_DID_MAX == AT_BUSINESS_DID_LEN,
               "AT_BUSINESS_DID_MAX (business_ad.h) out of sync with "
               "AT_BUSINESS_DID_LEN (msg_types.h)");
_Static_assert(AT_BUSINESS_AD_ID_HEX_LEN == AT_BUSINESS_AD_ID_LEN,
               "AT_BUSINESS_AD_ID_HEX_LEN (business_ad.h) out of sync with "
               "AT_BUSINESS_AD_ID_LEN (msg_types.h)");

/* Signing public-key hex length (32 raw bytes -> 64 chars). */
#define AT_BUSINESS_PK_HEX_LEN ((size_t)(crypto_sign_PUBLICKEYBYTES * 2))

bool at_business_sat_valid(unsigned sat)
{
    /* AT_BUSINESS_SAT_MIN is 0 and sat is unsigned, so the lower bound is
     * structural rather than a comparison (-Wtype-limits rejects writing it). */
    _Static_assert(AT_BUSINESS_SAT_MIN == 0,
                   "at_business_sat_valid assumes a zero satisfaction floor");
    return sat == AT_BUSINESS_SAT_SELF || sat <= AT_BUSINESS_SAT_MAX;
}

/* Shared bound-copy: truncate @p in to at most @p cap bytes AND to fit @p out_sz. */
static size_t bound_copy(const char *in, char *out, size_t out_sz, size_t cap)
{
    if (out == NULL || out_sz == 0) return 0;
    if (in == NULL) { out[0] = '\0'; return 0; }
    if (out_sz - 1 < cap) cap = out_sz - 1;
    size_t n = strnlen(in, cap);
    memcpy(out, in, n);
    out[n] = '\0';
    return n;
}

size_t at_business_bound_bundle(const char *in, char *out, size_t out_sz)
{
    return bound_copy(in, out, out_sz, AT_BUSINESS_BUNDLE_MAX);
}

size_t at_business_bound_did(const char *in, char *out, size_t out_sz)
{
    return bound_copy(in, out, out_sz, AT_BUSINESS_DID_MAX);
}

/* Append a little-endian u32 at @p out + *off. */
static void put_u32le(uint8_t *out, size_t *off, uint32_t v)
{
    out[(*off)++] = (uint8_t)(v & 0xFF);
    out[(*off)++] = (uint8_t)((v >> 8) & 0xFF);
    out[(*off)++] = (uint8_t)((v >> 16) & 0xFF);
    out[(*off)++] = (uint8_t)((v >> 24) & 0xFF);
}

size_t at_business_ad_canonical(const uuid_t advertiser_uuid,
                                const char *polity_did, uint8_t satisfaction,
                                int64_t page_seq, double ts, const char *bundle,
                                uint8_t *out, size_t outcap)
{
    if (out == NULL) return (size_t)-1;
    char did[AT_BUSINESS_DID_MAX + 1];
    size_t dlen = at_business_bound_did(polity_did, did, sizeof(did));
    char bnd[AT_BUSINESS_BUNDLE_MAX + 1];
    size_t blen = at_business_bound_bundle(bundle, bnd, sizeof(bnd));
    size_t need = 16 + 4 + dlen + 1 + 8 + 8 + 4 + blen;
    if (outcap < need) return (size_t)-1;

    size_t off = 0;
    memcpy(out + off, advertiser_uuid, sizeof(uuid_t)); off += sizeof(uuid_t);

    put_u32le(out, &off, (uint32_t)dlen);
    if (dlen > 0) { memcpy(out + off, did, dlen); off += dlen; }

    out[off++] = satisfaction;

    uint64_t u = (uint64_t)page_seq;
    for (int i = 0; i < 8; i++) out[off++] = (uint8_t)((u >> (8 * i)) & 0xFF);

    /* ts as its raw IEEE-754 little-endian bytes: deterministic across C and
     * Python (struct.pack('<d', ts)). */
    uint64_t tb;
    memcpy(&tb, &ts, sizeof(tb));
    for (int i = 0; i < 8; i++) out[off++] = (uint8_t)((tb >> (8 * i)) & 0xFF);

    put_u32le(out, &off, (uint32_t)blen);
    if (blen > 0) { memcpy(out + off, bnd, blen); off += blen; }
    return off;
}

int at_business_ad_content_id(const uuid_t advertiser_uuid,
                              const char *polity_did, uint8_t satisfaction,
                              int64_t page_seq, double ts, const char *bundle,
                              char *id_hex_out)
{
    if (id_hex_out == NULL) return -1;
    uint8_t canon[AT_BUSINESS_AD_CANON_MAX];
    size_t clen = at_business_ad_canonical(advertiser_uuid, polity_did,
                                           satisfaction, page_seq, ts, bundle,
                                           canon, sizeof(canon));
    if (clen == (size_t)-1) return -1;
    unsigned char digest[crypto_generichash_BYTES];   /* 32 */
    crypto_generichash(digest, sizeof(digest), canon, clen, NULL, 0);
    sodium_bin2hex(id_hex_out, AT_BUSINESS_AD_ID_HEX_LEN + 1, digest,
                   sizeof(digest));
    return 0;
}

int at_business_ad_sign(const unsigned char sk[crypto_sign_SECRETKEYBYTES],
                        const uuid_t advertiser_uuid, const char *polity_did,
                        uint8_t satisfaction, int64_t page_seq, double ts,
                        const char *bundle, char *sig_hex_out)
{
    if (sk == NULL || sig_hex_out == NULL) return -1;
    uint8_t canon[AT_BUSINESS_AD_CANON_MAX];
    size_t clen = at_business_ad_canonical(advertiser_uuid, polity_did,
                                           satisfaction, page_seq, ts, bundle,
                                           canon, sizeof(canon));
    if (clen == (size_t)-1) return -1;
    unsigned char sig[crypto_sign_BYTES];
    if (crypto_sign_detached(sig, NULL, canon, clen, sk) != 0)
        return -1;
    sodium_bin2hex(sig_hex_out, AT_BUSINESS_AD_SIG_HEX_LEN + 1, sig, sizeof(sig));
    return 0;
}

bool at_business_ad_verify(const unsigned char pk[crypto_sign_PUBLICKEYBYTES],
                           const uuid_t advertiser_uuid, const char *polity_did,
                           uint8_t satisfaction, int64_t page_seq, double ts,
                           const char *bundle, const char *sig_hex)
{
    if (pk == NULL || sig_hex == NULL) return false;
    if (strlen(sig_hex) != AT_BUSINESS_AD_SIG_HEX_LEN) return false;
    unsigned char sig[crypto_sign_BYTES];
    size_t bin_len = 0;
    if (sodium_hex2bin(sig, sizeof(sig), sig_hex, strlen(sig_hex),
                       NULL, &bin_len, NULL) != 0 || bin_len != sizeof(sig))
        return false;
    uint8_t canon[AT_BUSINESS_AD_CANON_MAX];
    size_t clen = at_business_ad_canonical(advertiser_uuid, polity_did,
                                           satisfaction, page_seq, ts, bundle,
                                           canon, sizeof(canon));
    if (clen == (size_t)-1) return false;
    return crypto_sign_verify_detached(sig, canon, clen, pk) == 0;
}

json_t *at_business_ad_to_json(const uuid_t advertiser_uuid,
                               const char *advertiser_pk_hex,
                               const char *polity_did, uint8_t satisfaction,
                               int64_t page_seq, double ts, const char *bundle,
                               const char *sig_hex)
{
    char did[AT_BUSINESS_DID_MAX + 1];
    at_business_bound_did(polity_did, did, sizeof(did));
    char bnd[AT_BUSINESS_BUNDLE_MAX + 1];
    at_business_bound_bundle(bundle, bnd, sizeof(bnd));
    char adv_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(advertiser_uuid, adv_str);
    json_t *env = json_object();
    if (env == NULL) return NULL;
    if (json_object_set_new(env, "advertiser", json_string(adv_str)) != 0
        || json_object_set_new(env, "advertiser_pk",
                               json_string(advertiser_pk_hex ? advertiser_pk_hex : "")) != 0
        || json_object_set_new(env, "polity", json_string(did)) != 0
        || json_object_set_new(env, "sat", json_integer(satisfaction)) != 0
        || json_object_set_new(env, "seq", json_integer((json_int_t)page_seq)) != 0
        || json_object_set_new(env, "ts", json_real(ts)) != 0
        || json_object_set_new(env, "bundle", json_string(bnd)) != 0
        || json_object_set_new(env, "sig", json_string(sig_hex ? sig_hex : "")) != 0) {
        json_decref(env);
        return NULL;
    }
    return env;
}

int at_business_ad_from_json(const json_t *obj, uuid_t advertiser_out,
                             char advertiser_pk_out[AT_BUSINESS_AD_SIG_HEX_LEN + 1],
                             char *did_out, size_t did_sz,
                             uint8_t *sat_out, int64_t *seq_out, double *ts_out,
                             char *bundle_out, size_t bundle_sz,
                             char sig_out[AT_BUSINESS_AD_SIG_HEX_LEN + 1])
{
    if (did_out != NULL && did_sz > 0) did_out[0] = '\0';
    if (bundle_out != NULL && bundle_sz > 0) bundle_out[0] = '\0';
    if (advertiser_pk_out != NULL) advertiser_pk_out[0] = '\0';
    if (sig_out != NULL) sig_out[0] = '\0';
    if (obj == NULL || !json_is_object(obj)) return -1;

    const json_t *j_adv    = json_object_get(obj, "advertiser");
    const json_t *j_pk     = json_object_get(obj, "advertiser_pk");
    const json_t *j_polity = json_object_get(obj, "polity");
    const json_t *j_sat    = json_object_get(obj, "sat");
    const json_t *j_seq    = json_object_get(obj, "seq");
    const json_t *j_ts     = json_object_get(obj, "ts");
    const json_t *j_bundle = json_object_get(obj, "bundle");
    const json_t *j_sig    = json_object_get(obj, "sig");

    if (!json_is_string(j_adv) || !json_is_string(j_pk)
        || !json_is_string(j_polity) || !json_is_integer(j_sat)
        || !json_is_integer(j_seq) || !json_is_number(j_ts)
        || !json_is_string(j_bundle) || !json_is_string(j_sig))
        return -1;

    if (uuid_parse(json_string_value(j_adv), advertiser_out) != 0)
        return -1;

    const char *pk = json_string_value(j_pk);
    if (strlen(pk) != AT_BUSINESS_PK_HEX_LEN) return -1;
    const char *sg = json_string_value(j_sig);
    if (strlen(sg) != AT_BUSINESS_AD_SIG_HEX_LEN) return -1;

    /* An ad for no polity is meaningless — and an empty did would let two
     * different businesses collide in the page store. */
    if (json_string_value(j_polity)[0] == '\0') return -1;

    json_int_t sat = json_integer_value(j_sat);
    if (sat < 0 || sat > 0xFF || !at_business_sat_valid((unsigned)sat)) return -1;

    if (advertiser_pk_out != NULL) {
        memcpy(advertiser_pk_out, pk, AT_BUSINESS_PK_HEX_LEN);
        advertiser_pk_out[AT_BUSINESS_PK_HEX_LEN] = '\0';
    }
    if (sig_out != NULL) {
        memcpy(sig_out, sg, AT_BUSINESS_AD_SIG_HEX_LEN);
        sig_out[AT_BUSINESS_AD_SIG_HEX_LEN] = '\0';
    }
    at_business_bound_did(json_string_value(j_polity), did_out, did_sz);
    at_business_bound_bundle(json_string_value(j_bundle), bundle_out, bundle_sz);
    if (sat_out != NULL) *sat_out = (uint8_t)sat;
    if (seq_out != NULL) *seq_out = (int64_t)json_integer_value(j_seq);
    if (ts_out != NULL) *ts_out = json_number_value(j_ts);
    return 0;
}
