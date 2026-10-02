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

/** @file This user's own other devices (C twin of first_contact/siblings.py). */

#include "first_contact/siblings.h"
#include "first_contact/device.h"
#include "identity/identity_priv.h"   /* public_identity_to_json / _from_json */
#include "utilities/util.h"           /* makedirs, at_strlcpy */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <uuid/uuid.h>

void at_siblings_init(at_siblings_t *s)
{
    if (s != NULL)
        memset(s, 0, sizeof(*s));
}

static void _clear_devices(at_siblings_t *s)
{
    for (size_t i = 0; i < s->count; i++) {
        json_decref(s->devices[i].identity);
        json_decref(s->devices[i].cert);
    }
    free(s->devices);
    free(s->reach);
    s->devices = NULL;
    s->reach = NULL;
    s->count = 0;
}

void at_siblings_free(at_siblings_t *s)
{
    if (s == NULL)
        return;
    _clear_devices(s);
    memset(s, 0, sizeof(*s));
}

static long _index(const at_siblings_t *s, const char *uuid)
{
    if (s == NULL || uuid == NULL)
        return -1;
    for (size_t i = 0; i < s->count; i++)
        if (strcmp(s->devices[i].uuid, uuid) == 0)
            return (long)i;
    return -1;
}

bool at_siblings_contains(const at_siblings_t *s, const char *uuid)
{
    return _index(s, uuid) >= 0;
}

at_sibling_reach_t *at_siblings_reach(at_siblings_t *s, const char *uuid)
{
    long i = _index(s, uuid);
    return i >= 0 ? &s->reach[i] : NULL;
}

const at_contact_device_t *at_siblings_get(const at_siblings_t *s, const char *uuid)
{
    long i = _index(s, uuid);
    return i >= 0 ? &s->devices[i] : NULL;
}

void at_siblings_set_hints(at_siblings_t *s, const char *uuid,
                           const char *const *hints, size_t n)
{
    at_sibling_reach_t *r = at_siblings_reach(s, uuid);
    if (r == NULL)
        return;
    r->n_hints = 0;
    for (size_t i = 0; i < n && r->n_hints < AT_SIBLING_HINTS_MAX; i++)
        if (hints[i] != NULL && hints[i][0] != '\0')
            at_strlcpy(r->hints[r->n_hints++], hints[i], AT_SIBLING_HINT_LEN);
}

/* Take ownership of @p identity and @p cert as a new sibling. 0, or -1. */
static int _append(at_siblings_t *s, const char *uuid, json_t *identity,
                   json_t *cert, double added_at)
{
    at_contact_device_t *nd = realloc(s->devices, (s->count + 1) * sizeof(*nd));
    if (nd == NULL)
        return -1;
    s->devices = nd;
    at_sibling_reach_t *nr = realloc(s->reach, (s->count + 1) * sizeof(*nr));
    if (nr == NULL)
        return -1;
    s->reach = nr;
    memset(&s->reach[s->count], 0, sizeof(*nr));
    at_contact_device_t *d = &s->devices[s->count++];
    memset(d, 0, sizeof(*d));
    at_strlcpy(d->uuid, uuid, sizeof(d->uuid));
    d->identity = identity;
    d->cert = cert;
    d->added_at = added_at;
    return 0;
}

int at_siblings_add(at_siblings_t *s, const public_identity_t *id,
                    const at_dir_signed_t *cert, const at_dir_signed_t *own_cert)
{
    if (s == NULL || id == NULL)
        return AT_DEVICE_MALFORMED;
    if (own_cert == NULL || at_device_cert_verify(own_cert) != AT_DEVICE_OK)
        return AT_DEVICE_UNKNOWN_OPERATOR;
    int rc = at_device_cert_verify(cert);
    if (rc != AT_DEVICE_OK)
        return rc;
    const char *own_op = at_device_cert_operator(own_cert);
    if (!at_device_cert_names(cert, id) ||
        strcmp(at_device_cert_operator(cert), own_op) != 0)
        return AT_DEVICE_MISMATCH;
    char uu[UUID_STRING_LEN + 1];
    uuid_unparse_lower(id->uuid, uu);
    const char *own_uuid = json_string_value(json_object_get(own_cert->body, "uuid"));
    if (own_uuid != NULL && strcmp(uu, own_uuid) == 0)
        return AT_DEVICE_KNOWN;
    if (strcmp(s->operator_key, own_op) != 0) {
        _clear_devices(s);
        at_strlcpy(s->operator_key, own_op, sizeof(s->operator_key));
    }
    if (at_siblings_contains(s, uu))
        return AT_DEVICE_OK;
    if (s->count >= AT_CONTACT_DEVICES_MAX)
        return AT_DEVICE_FULL;
    json_t *ident = NULL;
    if (public_identity_to_json(id, &ident) != 0 || ident == NULL)
        return AT_DEVICE_MALFORMED;
    json_t *wire = at_dir_to_wire(cert);
    if (wire == NULL || _append(s, uu, ident, wire, (double)time(NULL)) != 0) {
        json_decref(ident);
        json_decref(wire);
        return AT_DEVICE_MALFORMED;
    }
    return AT_DEVICE_OK;
}

bool at_siblings_remove(at_siblings_t *s, const char *uuid)
{
    if (s == NULL || uuid == NULL)
        return false;
    for (size_t i = 0; i < s->count; i++) {
        if (strcmp(s->devices[i].uuid, uuid) == 0) {
            json_decref(s->devices[i].identity);
            json_decref(s->devices[i].cert);
            memmove(&s->devices[i], &s->devices[i + 1],
                    (s->count - i - 1) * sizeof(s->devices[0]));
            memmove(&s->reach[i], &s->reach[i + 1],
                    (s->count - i - 1) * sizeof(s->reach[0]));
            s->count--;
            return true;
        }
    }
    return false;
}

json_t *at_siblings_to_json(const at_siblings_t *s)
{
    json_t *ds = json_array();
    for (size_t i = 0; s != NULL && i < s->count; i++) {
        json_t *d = json_pack("{s:O, s:O, s:f}", "identity", s->devices[i].identity,
                              "cert", s->devices[i].cert,
                              "added_at", s->devices[i].added_at);
        /* Only once set, as Python writes them. */
        if (s->reach[i].n_hints > 0) {
            json_t *rv = json_array();
            for (size_t h = 0; h < s->reach[i].n_hints; h++)
                json_array_append_new(rv, json_string(s->reach[i].hints[h]));
            json_object_set_new(d, "rendezvous", rv);
        }
        if (s->reach[i].reach_seq > 0)
            json_object_set_new(d, "reach_seq",
                                json_integer((json_int_t)s->reach[i].reach_seq));
        json_array_append_new(ds, d);
    }
    return json_pack("{s:s, s:i, s:s, s:o}", "typename", AT_SIBLINGS_TYPENAME,
                     "version", AT_SIBLINGS_VERSION,
                     "operator", s != NULL ? s->operator_key : "", "devices", ds);
}

static double _real(const json_t *v)
{
    if (json_is_real(v))
        return json_real_value(v);
    if (json_is_integer(v))
        return (double)json_integer_value(v);
    return 0.0;
}

void at_siblings_from_json(const json_t *obj, at_siblings_t *s)
{
    at_siblings_init(s);
    if (s == NULL || !json_is_object(obj))
        return;
    const char *tn = json_string_value(json_object_get(obj, "typename"));
    if (tn == NULL || strcmp(tn, AT_SIBLINGS_TYPENAME) != 0)
        return;
    const char *op = json_string_value(json_object_get(obj, "operator"));
    if (op == NULL || !at_dir_is_hex_key(op))
        return;
    at_strlcpy(s->operator_key, op, sizeof(s->operator_key));
    json_t *devices = json_object_get(obj, "devices");
    size_t i;
    json_t *d;
    json_array_foreach(devices, i, d) {
        if (s->count >= AT_CONTACT_DEVICES_MAX)
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
            && strcmp(at_device_cert_operator(&cert), s->operator_key) == 0
            && !at_siblings_contains(s, uu);
        if (ok) {
            json_t *wire = at_dir_to_wire(&cert);
            json_t *copy = json_deep_copy(ij);
            if (wire == NULL || copy == NULL
                || _append(s, uu, copy, wire, _real(json_object_get(d, "added_at"))) != 0) {
                json_decref(wire);
                json_decref(copy);
            } else {
                at_sibling_reach_t *r = &s->reach[s->count - 1];
                json_t *rv = json_object_get(d, "rendezvous");
                for (size_t h = 0; json_is_array(rv) && h < json_array_size(rv)
                                   && r->n_hints < AT_SIBLING_HINTS_MAX; h++) {
                    const char *hint = json_string_value(json_array_get(rv, h));
                    if (hint != NULL && hint[0] != '\0')
                        at_strlcpy(r->hints[r->n_hints++], hint, AT_SIBLING_HINT_LEN);
                }
                json_t *seq = json_object_get(d, "reach_seq");
                if (json_is_integer(seq) && json_integer_value(seq) > 0)
                    r->reach_seq = (int64_t)json_integer_value(seq);
            }
        }
        at_dir_free(&cert);
        free(ident.operator_key_binding);
    }
}

static int _path(const char *data_dir, char *out, size_t out_len)
{
    int n = snprintf(out, out_len, "%s/%s", data_dir, AT_SIBLINGS_FILENAME);
    return (n > 0 && (size_t)n < out_len) ? 0 : -1;
}

void at_siblings_load(const char *data_dir, at_siblings_t *s)
{
    at_siblings_init(s);
    char path[4096];
    if (data_dir == NULL || _path(data_dir, path, sizeof(path)) != 0)
        return;
    json_error_t err;
    json_t *root = json_load_file(path, 0, &err);
    if (root == NULL)
        return;
    at_siblings_from_json(root, s);
    json_decref(root);
}

int at_siblings_save(const at_siblings_t *s, const char *data_dir)
{
    if (s == NULL || data_dir == NULL)
        return -1;
    char dir[4096];
    at_strlcpy(dir, data_dir, sizeof(dir));
    if (makedirs(dir, 0755) != 0)
        return -1;
    char path[4096];
    if (_path(data_dir, path, sizeof(path)) != 0)
        return -1;
    json_t *root = at_siblings_to_json(s);
    if (root == NULL)
        return -1;
    /* Atomic, as contacts_save: a temp beside the target, then rename. */
    char tmp[4096 + 16];
    snprintf(tmp, sizeof(tmp), "%s.tmp%d", path, (int)getpid());
    int rc = json_dump_file(root, tmp, JSON_INDENT(2) | JSON_SORT_KEYS);
    json_decref(root);
    if (rc != 0 || rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}
