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

/* Signed reachability records. See reach.h; C twin of Python contacts/reach.py. */

#include "rendezvous/reach.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sodium.h>

#include "identity/identity_priv.h"
#include "rendezvous/net_relay.h"
#include "utilities/util.h"

void at_reach_free(at_reach_record_t *rec)
{
    if (rec == NULL)
        return;
    json_decref(rec->body);
    free(rec->body_str);
    memset(rec, 0, sizeof(*rec));
}

int at_reach_from_wire(const json_t *wire, at_reach_record_t *out)
{
    if (out == NULL)
        return AT_REACH_MALFORMED;
    memset(out, 0, sizeof(*out));
    const char *body_str = json_string_value(json_object_get((json_t *)wire, "body"));
    const char *sig = json_string_value(json_object_get((json_t *)wire, "sig"));
    if (body_str == NULL || sig == NULL || strlen(sig) >= sizeof(out->sig_hex))
        return AT_REACH_MALFORMED;
    json_t *body = json_loads(body_str, 0, NULL);
    const char *tn = json_string_value(json_object_get(body, "typename"));
    if (!json_is_object(body) || tn == NULL || strcmp(tn, AT_REACH_TYPENAME) != 0) {
        json_decref(body);
        return AT_REACH_MALFORMED;
    }
    out->body = body;
    out->body_str = strdup(body_str);
    if (out->body_str == NULL) {
        at_reach_free(out);
        return AT_REACH_MALFORMED;
    }
    at_strlcpy(out->sig_hex, sig, sizeof(out->sig_hex));
    return AT_REACH_OK;
}

int at_reach_from_text(const char *text, at_reach_record_t *out)
{
    json_t *wire = text != NULL ? json_loads(text, 0, NULL) : NULL;
    int rc = at_reach_from_wire(wire, out);
    json_decref(wire);
    return rc;
}

const char *at_reach_uuid(const at_reach_record_t *rec)
{
    return rec != NULL ? json_string_value(json_object_get(rec->body, "uuid")) : NULL;
}

const char *at_reach_key(const at_reach_record_t *rec)
{
    return rec != NULL ? json_string_value(json_object_get(rec->body, "key")) : NULL;
}

int64_t at_reach_seq(const at_reach_record_t *rec)
{
    json_t *v = rec != NULL ? json_object_get(rec->body, "seq") : NULL;
    return json_is_integer(v) ? (int64_t)json_integer_value(v) : 0;
}

long at_reach_expiry(const at_reach_record_t *rec)
{
    json_t *v = rec != NULL ? json_object_get(rec->body, "expiry") : NULL;
    return json_is_integer(v) ? (long)json_integer_value(v) : 0;
}

json_t *at_reach_relays(const at_reach_record_t *rec)
{
    json_t *v = rec != NULL ? json_object_get(rec->body, "relays") : NULL;
    return json_is_array(v) ? v : NULL;
}

json_t *at_reach_endpoints(const at_reach_record_t *rec)
{
    json_t *v = rec != NULL ? json_object_get(rec->body, "endpoints") : NULL;
    return json_is_array(v) ? v : NULL;
}

int at_reach_record_id(const at_reach_record_t *rec, char *out, size_t out_len)
{
    const char *key = at_reach_key(rec);
    return key != NULL ? net_relay_key_fingerprint(key, out, out_len) : -1;
}

int at_reach_verify(const at_reach_record_t *rec, double now)
{
    const char *key = at_reach_key(rec);
    if (rec == NULL || rec->body_str == NULL || key == NULL)
        return AT_REACH_MALFORMED;
    unsigned char pk[crypto_sign_PUBLICKEYBYTES], sig[crypto_sign_BYTES];
    size_t pkl = 0, sl = 0;
    if (sodium_hex2bin(pk, sizeof(pk), key, strlen(key), NULL, &pkl, NULL) != 0
        || pkl != sizeof(pk)
        || sodium_hex2bin(sig, sizeof(sig), rec->sig_hex, strlen(rec->sig_hex),
                          NULL, &sl, NULL) != 0
        || sl != sizeof(sig))
        return AT_REACH_BAD_SIG;
    size_t dl = strlen(AT_REACH_DOMAIN), bl = strlen(rec->body_str);
    unsigned char *msg = malloc(dl + bl);
    if (msg == NULL)
        return AT_REACH_MALFORMED;
    memcpy(msg, AT_REACH_DOMAIN, dl);
    memcpy(msg + dl, rec->body_str, bl);
    int ok = crypto_sign_verify_detached(sig, msg, dl + bl, pk);
    free(msg);
    if (ok != 0)
        return AT_REACH_BAD_SIG;
    long exp = at_reach_expiry(rec);
    if (exp != 0 && now >= (double)exp)
        return AT_REACH_EXPIRED;
    return AT_REACH_OK;
}

static char *_lower_dup(const char *s)
{
    char *d = strdup(s != NULL ? s : "");
    for (char *p = d; p != NULL && *p; p++)
        if (*p >= 'A' && *p <= 'Z')
            *p = (char)(*p - 'A' + 'a');
    return d;
}

int at_reach_create(const identity_t *self, int64_t seq,
                    const char *const *relays, size_t n_relays,
                    const char *const *endpoints, size_t n_endpoints,
                    long expiry, at_reach_record_t *out)
{
    if (self == NULL || out == NULL)
        return AT_REACH_MALFORMED;
    memset(out, 0, sizeof(*out));
    char uu[UUID_STRING_LEN + 1];
    uuid_unparse_lower(self->uuid, uu);
    char *key = _lower_dup((const char *)self->signature.public_hex);
    json_t *body = json_object();
    json_t *rv = json_array(), *ev = json_array();
    for (size_t i = 0; i < n_relays && i < AT_RELAY_MAX; i++)
        json_array_append_new(rv, json_string(relays[i]));
    for (size_t i = 0; i < n_endpoints && i < AT_REACH_MAX_ENDPOINTS; i++)
        json_array_append_new(ev, json_string(endpoints[i]));
    json_object_set_new(body, "v", json_integer(AT_REACH_VERSION));
    json_object_set_new(body, "typename", json_string(AT_REACH_TYPENAME));
    json_object_set_new(body, "uuid", json_string(uu));
    json_object_set_new(body, "key", json_string(key != NULL ? key : ""));
    json_object_set_new(body, "seq", json_integer((json_int_t)seq));
    json_object_set_new(body, "expiry", json_integer((json_int_t)expiry));
    json_object_set_new(body, "relays", rv);
    json_object_set_new(body, "endpoints", ev);
    free(key);
    /* Sorted and compact, as Python's json.dumps(sort_keys, (',', ':'),
     * ensure_ascii) -- not required (a verifier checks the bytes it is sent)
     * but it keeps the two runtimes' records alike. */
    char *body_str = json_dumps(body, JSON_COMPACT | JSON_SORT_KEYS | JSON_ENSURE_ASCII);
    if (body_str == NULL) {
        json_decref(body);
        return AT_REACH_MALFORMED;
    }
    size_t dl = strlen(AT_REACH_DOMAIN), bl = strlen(body_str);
    unsigned char *msg = malloc(dl + bl);
    unsigned char sig[crypto_sign_BYTES];
    if (msg == NULL) {
        free(body_str);
        json_decref(body);
        return AT_REACH_MALFORMED;
    }
    memcpy(msg, AT_REACH_DOMAIN, dl);
    memcpy(msg + dl, body_str, bl);
    int rc = crypto_sign_detached(sig, NULL, msg, dl + bl, self->signature.private);
    free(msg);
    if (rc != 0) {
        free(body_str);
        json_decref(body);
        return AT_REACH_MALFORMED;
    }
    out->body = body;
    out->body_str = body_str;
    sodium_bin2hex(out->sig_hex, sizeof(out->sig_hex), sig, sizeof(sig));
    return AT_REACH_OK;
}

json_t *at_reach_to_wire(const at_reach_record_t *rec)
{
    if (rec == NULL || rec->body_str == NULL)
        return NULL;
    json_t *w = json_object();
    json_object_set_new(w, "body", json_string(rec->body_str));
    json_object_set_new(w, "sig", json_string(rec->sig_hex));
    return w;
}
