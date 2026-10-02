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

/* An encrypted backup of the address book (C twin of first_contact/backup.py).
 * See backup.h. */

#include "first_contact/backup.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sodium.h>
#include <uuid/uuid.h>

#include "first_contact/device.h"
#include "utilities/util.h"

static const char *const REASONS[] = {
    "", "malformed", "unsupported", "bad_passphrase", "weak_passphrase",
    "bad_request", "io",
};

const char *at_backup_reason_str(int reason)
{
    if (reason < 0 || (size_t)reason >= sizeof(REASONS) / sizeof(REASONS[0]))
        return "malformed";
    return REASONS[reason];
}

static unsigned long long g_ops = AT_BACKUP_OPS_DEFAULT;
static size_t g_mem = AT_BACKUP_MEM_DEFAULT;

void at_backup_set_default_params(unsigned long long ops, size_t mem)
{
    g_ops = ops != 0 ? ops : AT_BACKUP_OPS_DEFAULT;
    g_mem = mem != 0 ? mem : AT_BACKUP_MEM_DEFAULT;
}

/* -- the passphrase ------------------------------------------------------------ */

static const char B32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

void at_backup_generate_passphrase(char out[AT_BACKUP_CODE_LEN + 1])
{
    uint8_t raw[15];
    randombytes_buf(raw, sizeof(raw));
    size_t o = 0;
    for (size_t i = 0; i < 24; i++) {
        /* Bits 5i .. 5i+4 of the 120, most significant first. */
        size_t bit = 5 * i;
        unsigned v = 0;
        for (size_t b = 0; b < 5; b++) {
            size_t at = bit + b;
            v = (v << 1) | ((raw[at / 8] >> (7 - at % 8)) & 1u);
        }
        if (i > 0 && i % 4 == 0)
            out[o++] = '-';
        out[o++] = B32[v];
    }
    out[o] = '\0';
    sodium_memzero(raw, sizeof(raw));
}

static bool _b32(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7');
}

static bool _code_shaped(const char *s)
{
    if (strlen(s) != AT_BACKUP_CODE_LEN)
        return false;
    for (size_t i = 0; i < AT_BACKUP_CODE_LEN; i++) {
        if (i % 5 == 4) {
            if (s[i] != '-' && s[i] != ' ')
                return false;
        } else if (!_b32(s[i])) {
            return false;
        }
    }
    return true;
}

void at_backup_normalize_passphrase(const char *in, char *out, size_t len)
{
    if (out == NULL || len == 0)
        return;
    at_strlcpy(out, in != NULL ? in : "", len);
    if (in == NULL || !_code_shaped(in))
        return;
    for (size_t i = 0; out[i] != '\0'; i++) {
        if (out[i] == ' ')
            out[i] = '-';
        else if (out[i] >= 'a' && out[i] <= 'z')
            out[i] = (char)(out[i] - 'a' + 'A');
    }
}

/* Characters, as Python's len(str): every byte that is not a UTF-8
 * continuation byte starts one. */
static size_t _chars(const char *s)
{
    size_t n = 0;
    for (; *s != '\0'; s++)
        if (((unsigned char)*s & 0xC0) != 0x80)
            n++;
    return n;
}

int at_backup_check_passphrase(const char *passphrase)
{
    if (passphrase == NULL || _chars(passphrase) < AT_BACKUP_PASSPHRASE_MIN)
        return AT_BACKUP_WEAK_PASSPHRASE;
    return AT_BACKUP_OK;
}

/* -- the envelope ------------------------------------------------------------ */

int at_backup_header_ad(unsigned long long ops, size_t mem, const char *salt_hex,
                        const char *nonce_hex, char *out, size_t len)
{
    int n = snprintf(out, len, "at-backup-v%d|%s|%llu|%zu|%s|%s|%s", AT_BACKUP_VERSION,
                     AT_BACKUP_KDF, ops, mem, salt_hex, AT_BACKUP_AEAD, nonce_hex);
    return (n < 0 || (size_t)n >= len) ? -1 : n;
}

static bool _params_ok(unsigned long long ops, size_t mem)
{
    return ops >= AT_BACKUP_OPS_MIN && ops <= AT_BACKUP_OPS_MAX &&
           mem >= AT_BACKUP_MEM_MIN && mem <= AT_BACKUP_MEM_MAX;
}

static int _derive(const char *passphrase, const uint8_t *salt, unsigned long long ops,
                   size_t mem, uint8_t key[AT_BACKUP_KEY_BYTES])
{
    size_t len = strlen(passphrase) + 1;
    char *norm = malloc(len);
    if (norm == NULL)
        return -1;
    at_backup_normalize_passphrase(passphrase, norm, len);
    int rc = crypto_pwhash(key, AT_BACKUP_KEY_BYTES, norm, strlen(norm), salt, ops, mem,
                           crypto_pwhash_ALG_ARGON2ID13);
    sodium_memzero(norm, len);
    free(norm);
    return rc;
}

#define AD_MAX 192

int at_backup_seal_bytes(const uint8_t *pt, size_t n, const char *passphrase,
                         unsigned long long ops, size_t mem, const uint8_t *salt_in,
                         const uint8_t *nonce_in, json_t **out)
{
    if (out != NULL)
        *out = NULL;
    if (out == NULL || (pt == NULL && n > 0))
        return AT_BACKUP_MALFORMED;
    if (at_backup_check_passphrase(passphrase) != AT_BACKUP_OK)
        return AT_BACKUP_WEAK_PASSPHRASE;
    ops = ops != 0 ? ops : g_ops;
    mem = mem != 0 ? mem : g_mem;
    if (!_params_ok(ops, mem))
        return AT_BACKUP_UNSUPPORTED;
    if (sodium_init() < 0)
        return AT_BACKUP_MALFORMED;
    uint8_t salt[AT_BACKUP_SALT_BYTES], nonce[AT_BACKUP_NONCE_BYTES];
    if (salt_in != NULL)
        memcpy(salt, salt_in, sizeof(salt));
    else
        randombytes_buf(salt, sizeof(salt));
    if (nonce_in != NULL)
        memcpy(nonce, nonce_in, sizeof(nonce));
    else
        randombytes_buf(nonce, sizeof(nonce));
    char salt_hex[2 * AT_BACKUP_SALT_BYTES + 1], nonce_hex[2 * AT_BACKUP_NONCE_BYTES + 1];
    sodium_bin2hex(salt_hex, sizeof(salt_hex), salt, sizeof(salt));
    sodium_bin2hex(nonce_hex, sizeof(nonce_hex), nonce, sizeof(nonce));
    char ad[AD_MAX];
    int ad_len = at_backup_header_ad(ops, mem, salt_hex, nonce_hex, ad, sizeof(ad));
    uint8_t key[AT_BACKUP_KEY_BYTES];
    if (ad_len < 0 || _derive(passphrase, salt, ops, mem, key) != 0)
        return AT_BACKUP_MALFORMED;
    size_t ct_len = n + AT_BACKUP_TAG_BYTES;
    uint8_t *ct = malloc(ct_len);
    size_t b64_len = sodium_base64_encoded_len(ct_len, sodium_base64_VARIANT_ORIGINAL);
    char *b64 = malloc(b64_len);
    int rc = AT_BACKUP_MALFORMED;
    unsigned long long clen = 0;
    if (ct != NULL && b64 != NULL &&
        crypto_aead_xchacha20poly1305_ietf_encrypt(ct, &clen, pt, n, (const uint8_t *)ad,
                                                   (unsigned long long)ad_len, NULL, nonce,
                                                   key) == 0) {
        sodium_bin2base64(b64, b64_len, ct, (size_t)clen, sodium_base64_VARIANT_ORIGINAL);
        json_t *o = json_object();
        if (o != NULL) {
            json_object_set_new(o, "typename", json_string(AT_BACKUP_TYPENAME));
            json_object_set_new(o, "v", json_integer(AT_BACKUP_VERSION));
            json_object_set_new(o, "kdf", json_string(AT_BACKUP_KDF));
            json_object_set_new(o, "ops", json_integer((json_int_t)ops));
            json_object_set_new(o, "mem", json_integer((json_int_t)mem));
            json_object_set_new(o, "salt", json_string(salt_hex));
            json_object_set_new(o, "aead", json_string(AT_BACKUP_AEAD));
            json_object_set_new(o, "nonce", json_string(nonce_hex));
            json_object_set_new(o, "ct", json_string(b64));
            *out = o;
            rc = AT_BACKUP_OK;
        }
    }
    sodium_memzero(key, sizeof(key));
    free(ct);
    free(b64);
    return rc;
}

/* Exactly @p n bytes of lower-case hex. */
static bool _hex(const json_t *v, uint8_t *out, size_t n)
{
    const char *s = json_string_value(v);
    if (s == NULL || strlen(s) != 2 * n)
        return false;
    for (size_t i = 0; i < 2 * n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    size_t got = 0;
    return sodium_hex2bin(out, n, s, 2 * n, NULL, &got, NULL) == 0 && got == n;
}

static bool _str_is(const json_t *obj, const char *key, const char *want)
{
    const char *s = json_string_value(json_object_get(obj, key));
    return s != NULL && strcmp(s, want) == 0;
}

int at_backup_open_bytes(const json_t *blob, const char *passphrase, uint8_t **pt,
                         size_t *n)
{
    if (pt != NULL)
        *pt = NULL;
    if (n != NULL)
        *n = 0;
    if (pt == NULL || n == NULL)
        return AT_BACKUP_MALFORMED;
    if (!json_is_object(blob) || !_str_is(blob, "typename", AT_BACKUP_TYPENAME))
        return AT_BACKUP_MALFORMED;
    const json_t *v = json_object_get(blob, "v");
    if (!json_is_integer(v) || json_integer_value(v) != AT_BACKUP_VERSION ||
        !_str_is(blob, "kdf", AT_BACKUP_KDF) || !_str_is(blob, "aead", AT_BACKUP_AEAD))
        return AT_BACKUP_UNSUPPORTED;
    const json_t *jops = json_object_get(blob, "ops"), *jmem = json_object_get(blob, "mem");
    if (!json_is_integer(jops) || !json_is_integer(jmem))
        return AT_BACKUP_MALFORMED;
    json_int_t iops = json_integer_value(jops), imem = json_integer_value(jmem);
    if (iops < (json_int_t)AT_BACKUP_OPS_MIN || iops > (json_int_t)AT_BACKUP_OPS_MAX ||
        imem < (json_int_t)AT_BACKUP_MEM_MIN || imem > (json_int_t)AT_BACKUP_MEM_MAX)
        return AT_BACKUP_UNSUPPORTED;
    unsigned long long ops = (unsigned long long)iops;
    size_t mem = (size_t)imem;
    uint8_t salt[AT_BACKUP_SALT_BYTES], nonce[AT_BACKUP_NONCE_BYTES];
    const char *ct_b64 = json_string_value(json_object_get(blob, "ct"));
    if (!_hex(json_object_get(blob, "salt"), salt, sizeof(salt)) ||
        !_hex(json_object_get(blob, "nonce"), nonce, sizeof(nonce)) || ct_b64 == NULL ||
        strlen(ct_b64) > (AT_BACKUP_CT_MAX / 3 + 1) * 4)
        return AT_BACKUP_MALFORMED;
    size_t b64_len = strlen(ct_b64);
    size_t cap = b64_len / 4 * 3 + 3;
    uint8_t *ct = malloc(cap > 0 ? cap : 1);
    if (ct == NULL)
        return AT_BACKUP_MALFORMED;
    size_t ct_len = 0;
    const char *end = NULL;
    if (sodium_base642bin(ct, cap, ct_b64, b64_len, NULL, &ct_len, &end,
                          sodium_base64_VARIANT_ORIGINAL) != 0 ||
        end != ct_b64 + b64_len) {
        free(ct);
        return AT_BACKUP_MALFORMED;
    }
    if (ct_len < AT_BACKUP_TAG_BYTES) {
        free(ct);
        return AT_BACKUP_MALFORMED;
    }
    if (passphrase == NULL || passphrase[0] == '\0') {
        free(ct);
        return AT_BACKUP_BAD_PASSPHRASE;
    }
    if (sodium_init() < 0) {
        free(ct);
        return AT_BACKUP_MALFORMED;
    }
    char ad[AD_MAX];
    int ad_len = at_backup_header_ad(ops, mem, json_string_value(json_object_get(blob, "salt")),
                                     json_string_value(json_object_get(blob, "nonce")), ad,
                                     sizeof(ad));
    uint8_t key[AT_BACKUP_KEY_BYTES];
    if (ad_len < 0 || _derive(passphrase, salt, ops, mem, key) != 0) {
        free(ct);
        return AT_BACKUP_MALFORMED;
    }
    size_t cap_pt = ct_len - AT_BACKUP_TAG_BYTES;
    uint8_t *out = malloc(cap_pt + 1);
    unsigned long long out_len = 0;
    int rc = AT_BACKUP_MALFORMED;
    if (out != NULL) {
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                out, &out_len, NULL, ct, ct_len, (const uint8_t *)ad,
                (unsigned long long)ad_len, nonce, key) == 0) {
            out[out_len] = '\0';
            *pt = out;
            *n = (size_t)out_len;
            out = NULL;
            rc = AT_BACKUP_OK;
        } else {
            rc = AT_BACKUP_BAD_PASSPHRASE;
        }
    }
    sodium_memzero(key, sizeof(key));
    free(out);
    free(ct);
    return rc;
}

int at_backup_open_text(const char *text, const char *passphrase, uint8_t **pt, size_t *n)
{
    if (pt != NULL)
        *pt = NULL;
    if (n != NULL)
        *n = 0;
    json_t *blob = text != NULL ? json_loads(text, 0, NULL) : NULL;
    if (blob == NULL)
        return AT_BACKUP_MALFORMED;
    int rc = at_backup_open_bytes(blob, passphrase, pt, n);
    json_decref(blob);
    return rc;
}

/* -- the contents ---------------------------------------------------------- */

json_t *at_backup_build_contents(const contacts_t *store, const at_siblings_t *sib,
                                 double now)
{
    json_t *book = at_sync_build(store, NULL, 0);
    json_t *o = json_object();
    if (book == NULL || o == NULL) {
        json_decref(book);
        json_decref(o);
        return NULL;
    }
    json_object_set_new(o, "typename", json_string(AT_BACKUP_CONTENTS_TYPENAME));
    json_object_set_new(o, "v", json_integer(AT_BACKUP_VERSION));
    json_object_set_new(o, "created_at", json_real(now));
    json_object_set_new(o, "contacts", book);
    if (sib != NULL && sib->count > 0) {
        json_t *s = at_siblings_to_json(sib);
        if (s != NULL)
            json_object_set_new(o, "siblings", s);
    }
    return o;
}

int at_backup_seal(const json_t *contents, const char *passphrase, char **text)
{
    if (text != NULL)
        *text = NULL;
    if (text == NULL || contents == NULL)
        return AT_BACKUP_MALFORMED;
    char *pt = json_dumps(contents, JSON_COMPACT | JSON_SORT_KEYS);
    if (pt == NULL)
        return AT_BACKUP_MALFORMED;
    json_t *blob = NULL;
    size_t pt_len = strlen(pt);
    int rc = at_backup_seal_bytes((const uint8_t *)pt, pt_len, passphrase, 0, 0, NULL, NULL,
                                  &blob);
    sodium_memzero(pt, pt_len);
    free(pt);
    if (rc != AT_BACKUP_OK)
        return rc;
    *text = json_dumps(blob, JSON_INDENT(2) | JSON_SORT_KEYS);
    json_decref(blob);
    return *text != NULL ? AT_BACKUP_OK : AT_BACKUP_MALFORMED;
}

int at_backup_open_contents(const char *text, const char *passphrase, json_t **contents)
{
    if (contents != NULL)
        *contents = NULL;
    if (contents == NULL)
        return AT_BACKUP_MALFORMED;
    uint8_t *pt = NULL;
    size_t n = 0;
    int rc = at_backup_open_text(text, passphrase, &pt, &n);
    if (rc != AT_BACKUP_OK)
        return rc;
    json_t *c = json_loadb((const char *)pt, n, 0, NULL);
    sodium_memzero(pt, n);
    free(pt);
    const json_t *v = json_object_get(c, "v");
    if (!json_is_object(c) || !_str_is(c, "typename", AT_BACKUP_CONTENTS_TYPENAME) ||
        !json_is_integer(v) || json_integer_value(v) != AT_BACKUP_VERSION ||
        !json_is_object(json_object_get(c, "contacts"))) {
        json_decref(c);
        return AT_BACKUP_MALFORMED;
    }
    *contents = c;
    return AT_BACKUP_OK;
}

int at_backup_restore(contacts_t *store, at_siblings_t *sib, const json_t *contents,
                      const at_dir_signed_t *own_cert, const char *own_uuid, double now,
                      at_sync_change_t **changes, size_t *n_changes,
                      char (**paired)[UUID_STRING_LEN + 1], size_t *n_paired)
{
    if (changes != NULL)
        *changes = NULL;
    if (n_changes != NULL)
        *n_changes = 0;
    if (paired != NULL)
        *paired = NULL;
    if (n_paired != NULL)
        *n_paired = 0;
    if (store == NULL || !json_is_object(contents))
        return AT_BACKUP_MALFORMED;
    at_siblings_t backed;
    at_siblings_from_json(json_object_get(contents, "siblings"), &backed);

    size_t cap = 1 + (sib != NULL ? sib->count : 0) + backed.count;
    const char **exclude = calloc(cap, sizeof(*exclude));
    if (exclude == NULL) {
        at_siblings_free(&backed);
        return AT_BACKUP_MALFORMED;
    }
    size_t n_ex = 0;
    if (own_uuid != NULL && own_uuid[0] != '\0')
        exclude[n_ex++] = own_uuid;
    for (size_t i = 0; sib != NULL && i < sib->count; i++)
        exclude[n_ex++] = sib->devices[i].uuid;
    for (size_t i = 0; i < backed.count; i++)
        exclude[n_ex++] = backed.devices[i].uuid;
    int merged = at_sync_merge_as(store, json_object_get(contents, "contacts"), now,
                                  exclude, n_ex, AT_PROV_BACKUP, changes, n_changes);
    free(exclude);
    if (merged != 0) {
        at_siblings_free(&backed);
        return AT_BACKUP_MALFORMED;
    }

    char (*added)[UUID_STRING_LEN + 1] = NULL;
    size_t n_added = 0;
    if (sib != NULL && own_cert != NULL && backed.count > 0)
        added = calloc(backed.count, sizeof(*added));
    for (size_t i = 0; added != NULL && i < backed.count; i++) {
        const at_contact_device_t *dev = &backed.devices[i];
        if (at_siblings_contains(sib, dev->uuid))
            continue;
        public_identity_t id;
        at_dir_signed_t cert;
        memset(&cert, 0, sizeof(cert));
        if (at_contact_device_identity(dev, &id) != 0)
            continue;
        if (at_dir_from_wire(dev->cert, &cert) == AT_DIR_OK &&
            at_siblings_add(sib, &id, &cert, own_cert) == AT_DEVICE_OK &&
            at_siblings_contains(sib, dev->uuid)) {
            const at_sibling_reach_t *r = &backed.reach[i];
            if (r->n_hints > 0) {
                const char *hints[AT_SIBLING_HINTS_MAX];
                for (size_t h = 0; h < r->n_hints; h++)
                    hints[h] = r->hints[h];
                at_siblings_set_hints(sib, dev->uuid, hints, r->n_hints);
            }
            if (r->reach_seq > 0) {
                at_sibling_reach_t *mine = at_siblings_reach(sib, dev->uuid);
                if (mine != NULL)
                    mine->reach_seq = r->reach_seq;
            }
            at_strlcpy(added[n_added++], dev->uuid, sizeof(added[0]));
        }
        at_dir_free(&cert);
        free(id.operator_key_binding);
    }
    at_siblings_free(&backed);
    if (paired != NULL && n_added > 0)
        *paired = added;
    else
        free(added);
    if (n_paired != NULL)
        *n_paired = n_added;
    return AT_BACKUP_OK;
}
