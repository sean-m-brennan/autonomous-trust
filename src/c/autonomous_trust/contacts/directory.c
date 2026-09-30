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

#include "contacts/directory.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <sodium.h>

#include "identity/identity_priv.h"
#include "network/net_relay.h"
#include "utilities/util.h"

int at_dir_normalize_handle(const char *in, char *out, size_t out_len)
{
    if (in == NULL || out == NULL)
        return -1;
    size_t n = strlen(in);
    if (n == 0 || n > AT_DIR_HANDLE_MAX || out_len < n + 1)
        return -1;
    for (size_t i = 0; i < n; i++) {
        char c = in[i];
        if (c >= 'A' && c <= 'Z')
            c = (char)(c - 'A' + 'a');
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.'
              || c == '_' || c == '@' || c == '+' || c == '-'))
            return -1;
        out[i] = c;
    }
    out[n] = '\0';
    return 0;
}

void at_dir_free(at_dir_signed_t *obj)
{
    if (obj == NULL)
        return;
    json_decref(obj->body);
    free(obj->body_str);
    memset(obj, 0, sizeof(*obj));
}

int at_dir_from_wire(const json_t *wire, at_dir_signed_t *out)
{
    if (out == NULL)
        return AT_DIR_MALFORMED;
    memset(out, 0, sizeof(*out));
    const char *body_str = json_string_value(json_object_get(wire, "body"));
    const char *sig = json_string_value(json_object_get(wire, "sig"));
    if (body_str == NULL || sig == NULL || strlen(sig) >= sizeof(out->sig_hex))
        return AT_DIR_MALFORMED;
    json_t *body = json_loads(body_str, 0, NULL);
    if (!json_is_object(body)) {
        json_decref(body);
        return AT_DIR_MALFORMED;
    }
    out->body = body;
    out->body_str = strdup(body_str);
    if (out->body_str == NULL) {
        at_dir_free(out);
        return AT_DIR_MALFORMED;
    }
    snprintf(out->sig_hex, sizeof(out->sig_hex), "%s", sig);
    return AT_DIR_OK;
}

int at_dir_from_text(const char *text, at_dir_signed_t *out)
{
    json_t *wire = text != NULL ? json_loads(text, 0, NULL) : NULL;
    int rc = at_dir_from_wire(wire, out);
    json_decref(wire);
    return rc;
}

json_t *at_dir_to_wire(const at_dir_signed_t *obj)
{
    if (obj == NULL || obj->body_str == NULL)
        return NULL;
    return json_pack("{s:s, s:s}", "body", obj->body_str, "sig", obj->sig_hex);
}

static const char *_str(const at_dir_signed_t *obj, const char *field)
{
    return obj != NULL ? json_string_value(json_object_get(obj->body, field)) : NULL;
}

const char *at_dir_handle(const at_dir_signed_t *obj) { return _str(obj, "handle"); }
const char *at_dir_key(const at_dir_signed_t *obj) { return _str(obj, "key"); }
const char *at_dir_uuid(const at_dir_signed_t *obj) { return _str(obj, "uuid"); }
const char *at_dir_visibility(const at_dir_signed_t *obj) { return _str(obj, "visibility"); }
const char *at_dir_issuer(const at_dir_signed_t *obj) { return _str(obj, "issuer"); }

int64_t at_dir_seq(const at_dir_signed_t *obj)
{
    json_t *v = obj != NULL ? json_object_get(obj->body, "seq") : NULL;
    return json_is_integer(v) ? (int64_t)json_integer_value(v) : 0;
}

long at_dir_expiry(const at_dir_signed_t *obj)
{
    json_t *v = obj != NULL ? json_object_get(obj->body, "expiry") : NULL;
    return json_is_integer(v) ? (long)json_integer_value(v) : 0;
}

static bool _is_version(const json_t *body, const char *typename)
{
    const char *t = json_string_value(json_object_get(body, "typename"));
    json_t *v = json_object_get(body, "v");
    return t != NULL && strcmp(t, typename) == 0 && json_is_integer(v)
        && json_integer_value(v) == AT_DIR_VERSION;
}

/* Already a normalized handle (Python: normalize_handle(h) == h). */
static bool _is_handle(const char *h)
{
    char folded[AT_DIR_HANDLE_MAX + 1];
    return h != NULL && at_dir_normalize_handle(h, folded, sizeof(folded)) == 0
        && strcmp(folded, h) == 0;
}

/* 64 lower-case hex digits (Python: _is_hex_key). */
static bool _is_hex_key(const char *k)
{
    if (k == NULL || strlen(k) != 2 * crypto_sign_PUBLICKEYBYTES)
        return false;
    for (const char *c = k; *c != '\0'; c++)
        if (!((*c >= '0' && *c <= '9') || (*c >= 'a' && *c <= 'f')))
            return false;
    return true;
}

static bool _positive_int(const json_t *body, const char *field, long long min)
{
    json_t *v = json_object_get(body, field);
    return json_is_integer(v) && json_integer_value(v) >= min;
}

static int _check_sig(const char *key_hex, const char *domain, const at_dir_signed_t *obj)
{
    unsigned char pk[crypto_sign_PUBLICKEYBYTES], sig[crypto_sign_BYTES];
    size_t pkl = 0, sl = 0;
    if (sodium_hex2bin(pk, sizeof(pk), key_hex, strlen(key_hex), NULL, &pkl, NULL) != 0
        || pkl != sizeof(pk)
        || sodium_hex2bin(sig, sizeof(sig), obj->sig_hex, strlen(obj->sig_hex),
                          NULL, &sl, NULL) != 0
        || sl != sizeof(sig))
        return AT_DIR_BAD_SIG;
    size_t dl = strlen(domain), bl = strlen(obj->body_str);
    unsigned char *msg = malloc(dl + bl);
    if (msg == NULL)
        return AT_DIR_MALFORMED;
    memcpy(msg, domain, dl);
    memcpy(msg + dl, obj->body_str, bl);
    int ok = crypto_sign_verify_detached(sig, msg, dl + bl, pk);
    free(msg);
    return ok == 0 ? AT_DIR_OK : AT_DIR_BAD_SIG;
}

int at_dir_attest_verify(const at_dir_signed_t *att, const char *const *trusted,
                         size_t n_trusted, double now)
{
    if (att == NULL || att->body == NULL)
        return AT_DIR_MALFORMED;
    const json_t *b = att->body;
    if (!_is_version(b, AT_DIR_ATTEST_TYPENAME) || !_is_handle(at_dir_handle(att))
        || !_is_hex_key(at_dir_key(att)) || !_is_hex_key(at_dir_issuer(att))
        || !_positive_int(b, "expiry", 1))
        return AT_DIR_MALFORMED;
    int rc = _check_sig(at_dir_issuer(att), AT_DIR_ATTEST_DOMAIN, att);
    if (rc != AT_DIR_OK)
        return rc;
    if (now >= (double)at_dir_expiry(att))
        return AT_DIR_EXPIRED;
    if (trusted != NULL) {
        bool found = false;
        for (size_t i = 0; i < n_trusted && !found; i++)
            found = trusted[i] != NULL && strcmp(trusted[i], at_dir_issuer(att)) == 0;
        if (!found)
            return AT_DIR_UNTRUSTED;
    }
    return AT_DIR_OK;
}

int at_dir_entry_verify(const at_dir_signed_t *entry, const char *const *trusted,
                        size_t n_trusted, double now)
{
    if (entry == NULL || entry->body == NULL)
        return AT_DIR_MALFORMED;
    const json_t *b = entry->body;
    const char *vis = at_dir_visibility(entry);
    json_t *ident = json_object_get(b, "identity");
    const char *ident_type = json_string_value(json_object_get(ident, "typename"));
    const char *ident_uuid = json_string_value(json_object_get(ident, "uuid"));
    const char *ident_key = json_string_value(
        json_object_get(json_object_get(ident, "signature"), "hex_seed"));
    if (!_is_version(b, AT_DIR_ENTRY_TYPENAME) || !_is_handle(at_dir_handle(entry))
        || !_is_hex_key(at_dir_key(entry)) || at_dir_uuid(entry) == NULL
        || !json_is_object(ident) || ident_type == NULL
        || strcmp(ident_type, "identity") != 0 || ident_uuid == NULL || ident_key == NULL
        || vis == NULL
        || (strcmp(vis, AT_DIR_VISIBILITY_ANYONE) != 0
            && strcmp(vis, AT_DIR_VISIBILITY_PUBLISHED) != 0)
        || !_positive_int(b, "seq", 1) || !_positive_int(b, "expiry", 1))
        return AT_DIR_MALFORMED;
    int rc = _check_sig(at_dir_key(entry), AT_DIR_ENTRY_DOMAIN, entry);
    if (rc != AT_DIR_OK)
        return rc;
    if (now >= (double)at_dir_expiry(entry))
        return AT_DIR_EXPIRED;
    if (strcasecmp(ident_uuid, at_dir_uuid(entry)) != 0
        || strcasecmp(ident_key, at_dir_key(entry)) != 0)
        return AT_DIR_MISMATCH;
    at_dir_signed_t att;
    rc = at_dir_from_wire(json_object_get(b, "attestation"), &att);
    if (rc == AT_DIR_OK)
        rc = at_dir_attest_verify(&att, trusted, n_trusted, now);
    if (rc == AT_DIR_OK
        && (strcmp(at_dir_handle(&att), at_dir_handle(entry)) != 0
            || strcmp(at_dir_key(&att), at_dir_key(entry)) != 0))
        rc = AT_DIR_MISMATCH;
    at_dir_free(&att);
    return rc;
}

/* Sign @p body (stolen) with @p sk over @p domain into @p out. */
static int _sign(const unsigned char *sk, const char *domain, json_t *body,
                 at_dir_signed_t *out)
{
    memset(out, 0, sizeof(*out));
    char *body_str = json_dumps(body, JSON_COMPACT | JSON_ENSURE_ASCII);
    if (body_str == NULL) {
        json_decref(body);
        return AT_DIR_MALFORMED;
    }
    size_t dl = strlen(domain), bl = strlen(body_str);
    unsigned char *msg = malloc(dl + bl);
    unsigned char sig[crypto_sign_BYTES];
    int rc = -1;
    if (msg != NULL) {
        memcpy(msg, domain, dl);
        memcpy(msg + dl, body_str, bl);
        rc = crypto_sign_detached(sig, NULL, msg, dl + bl, sk);
        free(msg);
    }
    if (rc != 0) {
        free(body_str);
        json_decref(body);
        return AT_DIR_MALFORMED;
    }
    out->body = body;
    out->body_str = body_str;
    sodium_bin2hex(out->sig_hex, sizeof(out->sig_hex), sig, sizeof(sig));
    return AT_DIR_OK;
}

int at_dir_attest(const unsigned char *issuer_sk, const char *handle,
                  const char *key_hex, long expiry, at_dir_signed_t *out)
{
    char folded[AT_DIR_HANDLE_MAX + 1];
    if (issuer_sk == NULL || out == NULL
        || at_dir_normalize_handle(handle, folded, sizeof(folded)) != 0
        || !_is_hex_key(key_hex))
        return AT_DIR_MALFORMED;
    /* The public half of an ed25519 secret key is its last 32 bytes. */
    char issuer_hex[2 * crypto_sign_PUBLICKEYBYTES + 1];
    sodium_bin2hex(issuer_hex, sizeof(issuer_hex),
                   issuer_sk + crypto_sign_SECRETKEYBYTES - crypto_sign_PUBLICKEYBYTES,
                   crypto_sign_PUBLICKEYBYTES);
    json_t *body = json_pack("{s:i, s:s, s:s, s:s, s:s, s:I}",
                             "v", AT_DIR_VERSION, "typename", AT_DIR_ATTEST_TYPENAME,
                             "handle", folded, "key", key_hex, "issuer", issuer_hex,
                             "expiry", (json_int_t)expiry);
    return body != NULL ? _sign(issuer_sk, AT_DIR_ATTEST_DOMAIN, body, out)
                        : AT_DIR_MALFORMED;
}

int at_dir_create_entry(const identity_t *self, const at_dir_signed_t *att,
                        int64_t seq, const char *visibility, long expiry,
                        double now, at_dir_signed_t *out)
{
    if (self == NULL || att == NULL || out == NULL || visibility == NULL)
        return AT_DIR_MALFORMED;
    const char *key = (const char *)self->signature.public_hex;
    if (at_dir_key(att) == NULL || strcmp(at_dir_key(att), key) != 0)
        return AT_DIR_MISMATCH;
    if (strcmp(visibility, AT_DIR_VISIBILITY_ANYONE) != 0
        && strcmp(visibility, AT_DIR_VISIBILITY_PUBLISHED) != 0)
        return AT_DIR_MALFORMED;
    if (expiry == 0)
        expiry = (long)now + AT_DIR_DEFAULT_TTL_SECONDS;
    if (at_dir_expiry(att) > 0 && expiry > at_dir_expiry(att))
        expiry = at_dir_expiry(att);
    char uu[UUID_STRING_LEN + 1];
    uuid_unparse_lower(self->uuid, uu);
    /* identity_t embeds public_identity_t at offset 0; the address is left
     * blank, as Python's create_entry does. */
    json_t *ident = NULL;
    if (public_identity_to_json((const public_identity_t *)self, &ident) != 0 || ident == NULL)
        return AT_DIR_MALFORMED;
    json_object_set_new(ident, "address", json_string(""));
    json_t *body = json_pack("{s:i, s:s, s:s, s:s, s:s, s:s, s:I, s:I, s:o, s:o}",
                             "v", AT_DIR_VERSION, "typename", AT_DIR_ENTRY_TYPENAME,
                             "handle", at_dir_handle(att), "uuid", uu, "key", key,
                             "visibility", visibility, "seq", (json_int_t)seq,
                             "expiry", (json_int_t)expiry, "identity", ident,
                             "attestation", at_dir_to_wire(att));
    return body != NULL ? _sign(self->signature.private, AT_DIR_ENTRY_DOMAIN, body, out)
                        : AT_DIR_MALFORMED;
}

/* -- the contact request ---------------------------------------------------- */
const char *at_dir_request_from(const at_dir_signed_t *req) { return _str(req, "from"); }
const char *at_dir_request_to(const at_dir_signed_t *req) { return _str(req, "to"); }
const char *at_dir_request_nonce(const at_dir_signed_t *req) { return _str(req, "nonce"); }

static bool _is_nonce(const char *n)
{
    if (n == NULL || strlen(n) != AT_DIR_NONCE_HEX)
        return false;
    for (const char *c = n; *c != '\0'; c++)
        if (!((*c >= '0' && *c <= '9') || (*c >= 'a' && *c <= 'f')))
            return false;
    return true;
}

int at_dir_request_verify(const at_dir_signed_t *req, double now)
{
    if (req == NULL || req->body == NULL)
        return AT_DIR_MALFORMED;
    const json_t *b = req->body;
    if (!_is_version(b, AT_DIR_REQUEST_TYPENAME))
        return AT_DIR_MALFORMED;
    json_t *relays = json_object_get(b, "relays");
    bool ok = _str(req, "from") != NULL && _str(req, "to") != NULL
        && _is_hex_key(at_dir_key(req)) && _is_handle(at_dir_handle(req))
        && _is_nonce(_str(req, "nonce")) && _positive_int(b, "expiry", 1)
        && json_is_array(relays) && json_array_size(relays) <= AT_DIR_REQUEST_MAX_RELAYS;
    size_t i;
    json_t *h;
    json_array_foreach(relays, i, h) {
        char host[AT_RELAY_HOST_LEN];
        int port = 0;
        if (!ok)
            break;
        ok = json_is_string(h)
            && net_relay_parse_hint(json_string_value(h), host, sizeof(host),
                                    &port, NULL) == 0;
    }
    if (!ok)
        return AT_DIR_MALFORMED;
    int rc = _check_sig(at_dir_key(req), AT_DIR_REQUEST_DOMAIN, req);
    if (rc != AT_DIR_OK)
        return rc;
    if (now >= (double)at_dir_expiry(req))
        return AT_DIR_EXPIRED;
    return AT_DIR_OK;
}

int at_dir_request_create(const identity_t *self, const at_dir_signed_t *entry,
                          const char *const *relays, size_t n_relays,
                          const char *nonce, long expiry, double now,
                          at_dir_signed_t *out)
{
    if (self == NULL || entry == NULL || out == NULL || at_dir_uuid(entry) == NULL
        || at_dir_handle(entry) == NULL)
        return AT_DIR_MALFORMED;
    char fresh[AT_DIR_NONCE_HEX + 1];
    if (nonce == NULL) {
        unsigned char raw[AT_DIR_NONCE_HEX / 2];
        randombytes_buf(raw, sizeof(raw));
        sodium_bin2hex(fresh, sizeof(fresh), raw, sizeof(raw));
        nonce = fresh;
    }
    if (expiry == 0)
        expiry = (long)now + AT_DIR_REQUEST_TTL_SECONDS;
    char uu[UUID_STRING_LEN + 1], to[UUID_STRING_LEN + 1];
    uuid_unparse_lower(self->uuid, uu);
    at_strlcpy(to, at_dir_uuid(entry), sizeof(to));
    for (char *c = to; *c != '\0'; c++)
        if (*c >= 'A' && *c <= 'Z')
            *c = (char)(*c - 'A' + 'a');
    json_t *rv = json_array();
    for (size_t i = 0; i < n_relays && i < AT_DIR_REQUEST_MAX_RELAYS; i++)
        json_array_append_new(rv, json_string(relays[i]));
    json_t *body = json_pack("{s:i, s:s, s:s, s:s, s:s, s:s, s:s, s:I, s:o}",
                             "v", AT_DIR_VERSION, "typename", AT_DIR_REQUEST_TYPENAME,
                             "from", uu, "key", (const char *)self->signature.public_hex,
                             "to", to, "handle", at_dir_handle(entry), "nonce", nonce,
                             "expiry", (json_int_t)expiry, "relays", rv);
    return body != NULL ? _sign(self->signature.private, AT_DIR_REQUEST_DOMAIN, body, out)
                        : AT_DIR_MALFORMED;
}

/* -- shared with contacts/device.c ------------------------------------------ */
int at_dir_sign(const unsigned char *sk, const char *domain, json_t *body,
                at_dir_signed_t *out)
{
    if (sk == NULL || domain == NULL || body == NULL || out == NULL) {
        json_decref(body);
        return AT_DIR_MALFORMED;
    }
    return _sign(sk, domain, body, out);
}

int at_dir_check_sig(const char *key_hex, const char *domain, const at_dir_signed_t *obj)
{
    if (key_hex == NULL || domain == NULL || obj == NULL || obj->body_str == NULL)
        return AT_DIR_MALFORMED;
    return _check_sig(key_hex, domain, obj);
}

bool at_dir_is_hex_key(const char *key) { return _is_hex_key(key); }
