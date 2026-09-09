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

/** @file Out-of-band invitations + safety-number verification (C twin of
 *  contacts/invitation.py). See contacts.h for the wire-parity contract. */

#include "contacts/contacts.h"
#include "identity/identity_priv.h"   /* public_identity_to_json / _from_json */
#include "utilities/util.h"           /* at_strlcpy (NUL-safe bounded copy) */

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sodium.h>
#include <uuid/uuid.h>

/* ------------------------------------------------------------------------- */
/* Invitation decode / verify / redeem                                        */
/* ------------------------------------------------------------------------- */

int at_invitation_decode(const char *blob, at_invitation_t *out)
{
    if (out == NULL)
        return AT_INVITE_MALFORMED;
    memset(out, 0, sizeof(*out));
    if (blob == NULL)
        return AT_INVITE_MALFORMED;

    const char *text = blob;
    size_t scheme_len = strlen(AT_INVITATION_URI_SCHEME);
    if (strncmp(text, AT_INVITATION_URI_SCHEME ":", scheme_len + 1) == 0)
        text += scheme_len + 1;
    size_t tlen = strlen(text);

    /* Decoded length is strictly < the base64 length. */
    unsigned char *raw = malloc(tlen + 1);
    if (raw == NULL)
        return AT_INVITE_MALFORMED;
    size_t rawlen = 0;
    if (sodium_base642bin(raw, tlen, text, tlen, NULL, &rawlen, NULL,
                          sodium_base64_VARIANT_URLSAFE_NO_PADDING) != 0) {
        free(raw);
        return AT_INVITE_MALFORMED;
    }

    json_error_t err;
    json_t *env = json_loadb((const char *)raw, rawlen, 0, &err);
    free(raw);
    if (!json_is_object(env)) {
        if (env != NULL)
            json_decref(env);
        return AT_INVITE_MALFORMED;
    }

    const char *body_str = json_string_value(json_object_get(env, "body"));
    const char *sig_hex = json_string_value(json_object_get(env, "sig"));
    if (body_str == NULL || sig_hex == NULL) {
        json_decref(env);
        return AT_INVITE_MALFORMED;
    }
    json_t *body = json_loads(body_str, 0, &err);
    if (!json_is_object(body)) {
        if (body != NULL)
            json_decref(body);
        json_decref(env);
        return AT_INVITE_MALFORMED;
    }
    const char *tn = json_string_value(json_object_get(body, "typename"));
    if (tn == NULL || strcmp(tn, AT_INVITATION_TYPENAME) != 0) {
        json_decref(body);
        json_decref(env);
        return AT_INVITE_MALFORMED;
    }

    out->envelope = env;
    out->body = body;
    out->body_str = body_str;   /* borrows env */
    out->sig_hex = sig_hex;     /* borrows env */
    return AT_INVITE_OK;
}

void at_invitation_free(at_invitation_t *inv)
{
    if (inv == NULL)
        return;
    if (inv->body != NULL)
        json_decref(inv->body);
    if (inv->envelope != NULL)
        json_decref(inv->envelope);
    memset(inv, 0, sizeof(*inv));
}

int at_invitation_verify(const at_invitation_t *inv, public_identity_t *ident_out)
{
    if (inv == NULL || inv->body == NULL || inv->sig_hex == NULL ||
        inv->body_str == NULL || ident_out == NULL)
        return AT_INVITE_MALFORMED;
    json_t *id_obj = json_object_get(inv->body, "identity");
    if (!json_is_object(id_obj))
        return AT_INVITE_MALFORMED;

    public_identity_t p;
    if (public_identity_from_json(id_obj, &p) != 0)
        return AT_INVITE_MALFORMED;

    unsigned char sig_raw[crypto_sign_BYTES];
    size_t binlen = 0;
    if (sodium_hex2bin(sig_raw, sizeof(sig_raw), inv->sig_hex,
                       strlen(inv->sig_hex), NULL, &binlen, NULL) != 0 ||
        binlen != crypto_sign_BYTES) {
        if (p.operator_key_binding != NULL)
            free(p.operator_key_binding);
        return AT_INVITE_BAD_SIG;
    }
    /* Detached ed25519 verify over the EXACT signed bytes -- the same wire form
     * PyNaCl produces (SignedMessage.signature). */
    if (crypto_sign_verify_detached(sig_raw,
                                    (const unsigned char *)inv->body_str,
                                    strlen(inv->body_str),
                                    p.signature.public) != 0) {
        if (p.operator_key_binding != NULL)
            free(p.operator_key_binding);
        return AT_INVITE_BAD_SIG;
    }
    *ident_out = p;   /* move; ownership of operator_key_binding transfers */
    return AT_INVITE_OK;
}

int at_invitation_is_expired(const at_invitation_t *inv, double now)
{
    if (inv == NULL || inv->body == NULL)
        return 0;
    json_t *e = json_object_get(inv->body, "expiry");
    long exp = json_is_integer(e) ? (long)json_integer_value(e) : 0;
    if (exp == 0)
        return 0;
    return now >= (double)exp ? 1 : 0;
}

int at_redeem_invitation(const char *blob, bool in_person, double now,
                         contact_t *out)
{
    if (out == NULL)
        return AT_INVITE_MALFORMED;
    memset(out, 0, sizeof(*out));

    at_invitation_t inv;
    int rc = at_invitation_decode(blob, &inv);
    if (rc != AT_INVITE_OK)
        return rc;

    public_identity_t p;
    rc = at_invitation_verify(&inv, &p);
    if (rc != AT_INVITE_OK) {
        at_invitation_free(&inv);
        return rc;
    }
    if (at_invitation_is_expired(&inv, now)) {
        if (p.operator_key_binding != NULL)
            free(p.operator_key_binding);
        at_invitation_free(&inv);
        return AT_INVITE_EXPIRED;
    }

    out->identity = p;   /* move */
    at_strlcpy(out->petname, p.petname, sizeof(out->petname));
    const char *nonce = json_string_value(json_object_get(inv.body, "nonce"));
    if (nonce != NULL)
        at_strlcpy(out->nonce, nonce, sizeof(out->nonce));
    /* Copy the reachability hints out of the invitation body. */
    json_t *rv = json_object_get(inv.body, "rendezvous");
    if (json_is_array(rv) && json_array_size(rv) > 0) {
        size_t n = json_array_size(rv);
        out->rendezvous = calloc(n, sizeof(char *));
        if (out->rendezvous != NULL) {
            for (size_t i = 0; i < n; i++) {
                const char *hint = json_string_value(json_array_get(rv, i));
                if (hint != NULL)
                    out->rendezvous[out->rendezvous_count++] = strdup(hint);
            }
        }
    }
    out->added_at = (double)time(NULL);
    out->provenance = in_person ? AT_PROV_IN_PERSON : AT_PROV_TOKEN;
    out->verified = false;
    out->trust_seed = 0.0;
    if (in_person)
        contact_mark_verified(out, AT_FIRST_CONTACT_VERIFIED_SEED);

    at_invitation_free(&inv);
    return AT_INVITE_OK;
}

/* ------------------------------------------------------------------------- */
/* Minting                                                                     */
/* ------------------------------------------------------------------------- */

int at_create_invitation(const identity_t *self,
                         const char *const *rendezvous, size_t n_rv,
                         long expiry, const char *nonce, char **blob_out)
{
    if (self == NULL || blob_out == NULL)
        return -1;
    *blob_out = NULL;

    json_t *id_obj = NULL;
    /* identity_t embeds public_identity_t at offset 0 (anonymous member); the
     * public serializer reads only public fields, so no publish()/free dance. */
    if (public_identity_to_json((const public_identity_t *)self, &id_obj) != 0)
        return -1;

    json_t *body = json_object();
    json_t *rv = json_array();
    for (size_t i = 0; i < n_rv; i++)
        json_array_append_new(rv, json_string(rendezvous[i]));
    json_object_set_new(body, "v", json_integer(AT_INVITATION_VERSION));
    json_object_set_new(body, "typename", json_string(AT_INVITATION_TYPENAME));
    json_object_set_new(body, "identity", id_obj);
    json_object_set_new(body, "rendezvous", rv);
    json_object_set_new(body, "nonce", json_string(nonce != NULL ? nonce : ""));
    json_object_set_new(body, "expiry", json_integer(expiry));

    /* Sign the exact transmitted bytes: sorted-key, compact, ASCII-escaped --
     * byte-identical to Python json.dumps(body, sort_keys=True,
     * separators=(',',':'), ensure_ascii=True). */
    char *body_str = json_dumps(body,
                                JSON_COMPACT | JSON_SORT_KEYS | JSON_ENSURE_ASCII);
    json_decref(body);
    if (body_str == NULL)
        return -1;

    unsigned char sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, NULL, (const unsigned char *)body_str,
                         strlen(body_str), self->signature.private);
    char sig_hex[crypto_sign_BYTES * 2 + 1];
    sodium_bin2hex(sig_hex, sizeof(sig_hex), sig, sizeof(sig));

    json_t *env = json_object();
    json_object_set_new(env, "body", json_string(body_str));
    json_object_set_new(env, "sig", json_string(sig_hex));
    free(body_str);
    char *env_str = json_dumps(env, JSON_COMPACT | JSON_ENSURE_ASCII);
    json_decref(env);
    if (env_str == NULL)
        return -1;

    size_t env_len = strlen(env_str);
    size_t b64max = sodium_base64_encoded_len(env_len,
                                              sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    char *blob = malloc(b64max);
    if (blob == NULL) {
        free(env_str);
        return -1;
    }
    sodium_bin2base64(blob, b64max, (const unsigned char *)env_str, env_len,
                      sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    free(env_str);
    *blob_out = blob;
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Safety number (§4.4)                                                        */
/* ------------------------------------------------------------------------- */

/* One per-identity fingerprint: AT_SAFETY_NUMBER_GROUPS groups of 5 digits,
 * from iterated blake2b over PUBLIC material only. Mirrors Python
 * _fingerprint_groups exactly (domain, material layout, iteration count). */
static void _fingerprint_groups(const public_identity_t *p,
                                char groups[AT_SAFETY_NUMBER_GROUPS][6])
{
    char uuid_s[UUID_STRING_LEN + 1];
    uuid_unparse(p->uuid, uuid_s);

    char material[256];
    int mlen = snprintf(material, sizeof(material), "%s|%s|%s|%s",
                        AT_SAFETY_NUMBER_DOMAIN, uuid_s,
                        (const char *)p->signature.public_hex,
                        (const char *)p->encryptor.public_hex);

    unsigned char digest[32];
    crypto_generichash(digest, sizeof(digest),
                       (const unsigned char *)material, (size_t)mlen, NULL, 0);
    for (int i = 1; i < AT_SAFETY_NUMBER_ITERATIONS; i++)
        crypto_generichash(digest, sizeof(digest), digest, sizeof(digest),
                           NULL, 0);

    for (int g = 0; g < AT_SAFETY_NUMBER_GROUPS; g++) {
        const unsigned char *chunk = digest + g * 4;
        unsigned long v = ((unsigned long)chunk[0] << 24) |
                          ((unsigned long)chunk[1] << 16) |
                          ((unsigned long)chunk[2] << 8) |
                          (unsigned long)chunk[3];
        snprintf(groups[g], 6, "%05lu", v % 100000UL);
    }
}

static void _join_groups(char groups[AT_SAFETY_NUMBER_GROUPS][6],
                         char *out, size_t out_len)
{
    size_t pos = 0;
    for (int g = 0; g < AT_SAFETY_NUMBER_GROUPS && pos < out_len; g++) {
        int n = snprintf(out + pos, out_len - pos, "%s%s",
                         g == 0 ? "" : " ", groups[g]);
        if (n < 0)
            break;
        pos += (size_t)n;
    }
}

int at_safety_number(const public_identity_t *a, const public_identity_t *b,
                     char *out, size_t out_len)
{
    if (a == NULL || b == NULL || out == NULL)
        return -1;
    char ga[AT_SAFETY_NUMBER_GROUPS][6];
    char gb[AT_SAFETY_NUMBER_GROUPS][6];
    _fingerprint_groups(a, ga);
    _fingerprint_groups(b, gb);

    char fa[AT_SAFETY_NUMBER_GROUPS * 6];
    char fb[AT_SAFETY_NUMBER_GROUPS * 6];
    _join_groups(ga, fa, sizeof(fa));
    _join_groups(gb, fb, sizeof(fb));

    /* Symmetric: sort the two fingerprints so both parties derive the same
     * string regardless of which they call "mine". */
    const char *first = fa;
    const char *second = fb;
    if (strcmp(fa, fb) > 0) {
        first = fb;
        second = fa;
    }
    int n = snprintf(out, out_len, "%s %s", first, second);
    return (n > 0 && (size_t)n < out_len) ? 0 : -1;
}

static void _strip_ws(const char *in, char *out, size_t out_len)
{
    size_t j = 0;
    for (size_t i = 0; in[i] != '\0' && j + 1 < out_len; i++) {
        unsigned char ch = (unsigned char)in[i];
        if (ch != ' ' && ch != '\t' && ch != '\n' && ch != '\r' && ch != '\f' &&
            ch != '\v')
            out[j++] = in[i];
    }
    out[j] = '\0';
}

int at_verify_contact(contact_t *c, const char *presented,
                      const public_identity_t *my_identity)
{
    if (c == NULL || presented == NULL || my_identity == NULL)
        return AT_INVITE_MALFORMED;

    char expected[AT_SAFETY_NUMBER_LEN];
    if (at_safety_number(my_identity, &c->identity, expected,
                         sizeof(expected)) != 0)
        return AT_INVITE_MALFORMED;

    char en[AT_SAFETY_NUMBER_LEN];
    _strip_ws(expected, en, sizeof(en));
    size_t plen = strlen(presented);
    char *pn = malloc(plen + 1);
    if (pn == NULL)
        return AT_INVITE_MALFORMED;
    _strip_ws(presented, pn, plen + 1);

    size_t elen = strlen(en);
    int match = (strlen(pn) == elen) &&
                (sodium_memcmp(en, pn, elen) == 0);
    free(pn);
    if (!match)
        return AT_INVITE_BAD_SIG;
    contact_mark_verified(c, AT_FIRST_CONTACT_VERIFIED_SEED);
    return AT_INVITE_OK;
}
