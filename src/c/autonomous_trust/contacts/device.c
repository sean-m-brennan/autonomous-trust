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
/** @file One human, several devices (C twin of contacts/device.py). */

#include "contacts/device.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include <sodium.h>
#include <uuid/uuid.h>

#include "identity/identity_priv.h"   /* public_identity_to_json / _from_json */
#include "utilities/util.h"

static const char *const REASONS[] = {
    "", "malformed", "bad_signature", "mismatch", "unknown_operator",
    "unverified", "known", "full",
};

const char *at_device_reason(int status)
{
    int i = -status;
    return i >= 0 && i < (int)(sizeof(REASONS) / sizeof(REASONS[0])) ? REASONS[i] : "malformed";
}

static const char *_field(const at_dir_signed_t *c, const char *k)
{
    return c != NULL ? json_string_value(json_object_get(c->body, k)) : NULL;
}

const char *at_device_cert_operator(const at_dir_signed_t *cert)
{
    return _field(cert, "operator");
}

static void _uuid_lower(const public_identity_t *id, char out[UUID_STRING_LEN + 1])
{
    uuid_unparse_lower(id->uuid, out);
}

int at_device_cert_create(const unsigned char *operator_sk, const public_identity_t *id,
                          long long issued_at, at_dir_signed_t *out)
{
    if (operator_sk == NULL || id == NULL || out == NULL || issued_at < 0)
        return AT_DEVICE_MALFORMED;
    /* The public half of an ed25519 secret key is its last 32 bytes. */
    char op_hex[2 * crypto_sign_PUBLICKEYBYTES + 1];
    sodium_bin2hex(op_hex, sizeof(op_hex),
                   operator_sk + crypto_sign_SECRETKEYBYTES - crypto_sign_PUBLICKEYBYTES,
                   crypto_sign_PUBLICKEYBYTES);
    char uu[UUID_STRING_LEN + 1];
    _uuid_lower(id, uu);
    json_t *body = json_pack("{s:i, s:s, s:s, s:s, s:s, s:I}",
                             "v", AT_DEVICE_VERSION, "typename", AT_DEVICE_TYPENAME,
                             "operator", op_hex, "uuid", uu,
                             "key", (const char *)id->signature.public_hex,
                             "issued_at", (json_int_t)issued_at);
    if (body == NULL)
        return AT_DEVICE_MALFORMED;
    return at_dir_sign(operator_sk, AT_DEVICE_DOMAIN, body, out) == AT_DIR_OK
        ? AT_DEVICE_OK : AT_DEVICE_MALFORMED;
}

static bool _is_lower_uuid(const char *u)
{
    if (u == NULL || strlen(u) != UUID_STRING_LEN)
        return false;
    for (const char *c = u; *c != '\0'; c++)
        if (*c >= 'A' && *c <= 'Z')
            return false;
    return true;
}

int at_device_cert_verify(const at_dir_signed_t *cert)
{
    if (cert == NULL || cert->body == NULL)
        return AT_DEVICE_MALFORMED;
    const json_t *b = cert->body;
    const char *t = json_string_value(json_object_get(b, "typename"));
    json_t *v = json_object_get(b, "v");
    if (t == NULL || strcmp(t, AT_DEVICE_TYPENAME) != 0 || !json_is_integer(v)
        || json_integer_value(v) != AT_DEVICE_VERSION)
        return AT_DEVICE_MALFORMED;
    if (!at_dir_is_hex_key(_field(cert, "operator")) || !at_dir_is_hex_key(_field(cert, "key")))
        return AT_DEVICE_MALFORMED;
    if (!_is_lower_uuid(_field(cert, "uuid")))
        return AT_DEVICE_MALFORMED;
    json_t *at = json_object_get(b, "issued_at");
    if (!json_is_integer(at) || json_integer_value(at) < 0)
        return AT_DEVICE_MALFORMED;
    return at_dir_check_sig(_field(cert, "operator"), AT_DEVICE_DOMAIN, cert) == AT_DIR_OK
        ? AT_DEVICE_OK : AT_DEVICE_BAD_SIGNATURE;
}

bool at_device_cert_names(const at_dir_signed_t *cert, const public_identity_t *id)
{
    if (cert == NULL || id == NULL)
        return false;
    char uu[UUID_STRING_LEN + 1];
    _uuid_lower(id, uu);
    const char *cu = _field(cert, "uuid"), *ck = _field(cert, "key");
    return cu != NULL && ck != NULL && strcmp(cu, uu) == 0
        && strcmp(ck, (const char *)id->signature.public_hex) == 0;
}

int at_adopt_operator(contact_t *c, const at_dir_signed_t *cert, contacts_t *store)
{
    if (c == NULL)
        return AT_DEVICE_MALFORMED;
    int rc = at_device_cert_verify(cert);
    if (rc != AT_DEVICE_OK)
        return rc;
    if (!at_device_cert_names(cert, &c->identity))
        return AT_DEVICE_MISMATCH;
    const char *op = at_device_cert_operator(cert);
    if (c->operator_key[0] != '\0' && strcmp(c->operator_key, op) != 0)
        return AT_DEVICE_MISMATCH;
    if (store != NULL) {
        contact_t *holder = contacts_by_operator(store, op);
        if (holder != NULL && uuid_compare(holder->identity.uuid, c->identity.uuid) != 0)
            return AT_DEVICE_KNOWN;
    }
    at_strlcpy(c->operator_key, op, sizeof(c->operator_key));
    return AT_DEVICE_OK;
}

/* Append a device to @p c (no checks). 0, or -1. */
static int _append(contact_t *c, const char *uuid, json_t *identity, json_t *cert,
                   double added_at)
{
    at_contact_device_t *nd = realloc(c->devices, (c->devices_count + 1) * sizeof(*nd));
    if (nd == NULL)
        return -1;
    c->devices = nd;
    at_contact_device_t *d = &c->devices[c->devices_count++];
    memset(d, 0, sizeof(*d));
    at_strlcpy(d->uuid, uuid, sizeof(d->uuid));
    d->identity = identity;
    d->cert = cert;
    d->added_at = added_at;
    return 0;
}

static bool _lists(const contact_t *c, const char *uuid)
{
    char first[UUID_STRING_LEN + 1];
    uuid_unparse_lower(c->identity.uuid, first);
    if (strcasecmp(first, uuid) == 0)
        return true;
    for (size_t i = 0; i < c->devices_count; i++)
        if (strcasecmp(c->devices[i].uuid, uuid) == 0)
            return true;
    return false;
}

int at_link_device(contacts_t *store, const public_identity_t *id,
                   const at_dir_signed_t *cert, contact_t **out)
{
    if (out != NULL)
        *out = NULL;
    if (store == NULL || id == NULL)
        return AT_DEVICE_MALFORMED;
    int rc = at_device_cert_verify(cert);
    if (rc != AT_DEVICE_OK)
        return rc;
    if (!at_device_cert_names(cert, id))
        return AT_DEVICE_MISMATCH;
    contact_t *c = contacts_by_operator(store, at_device_cert_operator(cert));
    if (c == NULL)
        return AT_DEVICE_UNKNOWN_OPERATOR;
    char uu[UUID_STRING_LEN + 1];
    _uuid_lower(id, uu);
    if (_lists(c, uu)) {
        if (out != NULL)
            *out = c;
        return AT_DEVICE_OK;
    }
    if (contacts_get(store, uu) != NULL)
        return AT_DEVICE_KNOWN;
    if (!c->verified)
        return AT_DEVICE_UNVERIFIED;
    if (c->devices_count >= AT_CONTACT_DEVICES_MAX)
        return AT_DEVICE_FULL;
    json_t *ident = NULL;
    if (public_identity_to_json(id, &ident) != 0 || ident == NULL)
        return AT_DEVICE_MALFORMED;
    json_t *wire = at_dir_to_wire(cert);
    if (wire == NULL || _append(c, uu, ident, wire, (double)time(NULL)) != 0) {
        json_decref(ident);
        json_decref(wire);
        return AT_DEVICE_MALFORMED;
    }
    if (out != NULL)
        *out = c;
    return AT_DEVICE_OK;
}

int at_contact_device_identity(const at_contact_device_t *d, public_identity_t *out)
{
    if (d == NULL || out == NULL)
        return -1;
    memset(out, 0, sizeof(*out));
    return public_identity_from_json(d->identity, out) == 0 ? 0 : -1;
}

static double _real(const json_t *v)
{
    if (json_is_real(v))
        return json_real_value(v);
    if (json_is_integer(v))
        return (double)json_integer_value(v);
    return 0.0;
}

void at_contact_load_devices(contact_t *c, const json_t *devices)
{
    if (c == NULL || !json_is_array(devices) || c->operator_key[0] == '\0')
        return;
    size_t i;
    json_t *d;
    json_array_foreach(devices, i, d) {
        if (c->devices_count >= AT_CONTACT_DEVICES_MAX)
            break;
        public_identity_t ident;
        memset(&ident, 0, sizeof(ident));
        json_t *ij = json_object_get(d, "identity");
        if (public_identity_from_json(ij, &ident) != 0)
            continue;
        at_dir_signed_t cert;
        bool ok = at_dir_from_wire(json_object_get(d, "cert"), &cert) == AT_DIR_OK;
        char uu[UUID_STRING_LEN + 1];
        uuid_unparse_lower(ident.uuid, uu);
        ok = ok && at_device_cert_verify(&cert) == AT_DEVICE_OK
            && at_device_cert_names(&cert, &ident)
            && strcmp(at_device_cert_operator(&cert), c->operator_key) == 0
            && !_lists(c, uu);
        if (ok) {
            json_t *wire = at_dir_to_wire(&cert);
            json_t *copy = json_deep_copy(ij);
            if (wire == NULL || copy == NULL
                || _append(c, uu, copy, wire, _real(json_object_get(d, "added_at"))) != 0) {
                json_decref(wire);
                json_decref(copy);
            }
        }
        at_dir_free(&cert);
        free(ident.operator_key_binding);
    }
}
