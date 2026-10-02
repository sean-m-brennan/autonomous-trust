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

/** @file The durable, user-owned contacts store (C twin of first_contact/store.py).
 *
 *  Persists <data_dir>/contacts.cfg.json in the DRY canonical form so a store
 *  written by either runtime loads in the other. Standalone (not registered in
 *  the DEFINE_CONFIGURATION table) and never auto-pruned, like the reputation
 *  store. */

#include "first_contact/contacts.h"
#include "first_contact/device.h"
#include "first_contact/directory.h"
#include "identity/identity_priv.h"   /* public_identity_to_json / _from_json */
#include "utilities/util.h"           /* makedirs */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include <jansson.h>
#include <uuid/uuid.h>

/* ------------------------------------------------------------------------- */
/* Store lifetime + membership                                                */
/* ------------------------------------------------------------------------- */

void contacts_init(contacts_t *store)
{
    if (store != NULL)
        memset(store, 0, sizeof(*store));
}

void contacts_free(contacts_t *store)
{
    if (store == NULL)
        return;
    for (size_t i = 0; i < store->count; i++)
        contact_free(&store->items[i]);
    free(store->items);
    free(store->tombstones);
    memset(store, 0, sizeof(*store));
}

size_t contacts_count(const contacts_t *store)
{
    return store != NULL ? store->count : 0;
}

static int _grow(contacts_t *s)
{
    if (s->count < s->cap)
        return 0;
    size_t ncap = s->cap ? s->cap * 2 : 4;
    contact_t *ni = realloc(s->items, ncap * sizeof(contact_t));
    if (ni == NULL)
        return -1;
    s->items = ni;
    s->cap = ncap;
    return 0;
}

static contact_t *_find(contacts_t *s, const char *uuid)
{
    char u[UUID_STRING_LEN + 1];
    for (size_t i = 0; i < s->count; i++) {
        uuid_unparse(s->items[i].identity.uuid, u);
        if (strcmp(u, uuid) == 0)
            return &s->items[i];
    }
    return NULL;
}

/* ------------------------------------------------------------------------- */
/* Tombstones (Phase 4, first_contact/sync.h)                                      */
/* ------------------------------------------------------------------------- */

bool at_is_lower_uuid(const char *v)
{
    if (v == NULL || strlen(v) != UUID_STRING_LEN)
        return false;
    for (const char *p = v; *p; p++)
        if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || *p == '-'))
            return false;
    return true;
}

static at_tombstone_t *_tomb(const contacts_t *s, const char *uuid)
{
    for (size_t i = 0; i < s->tombstones_count; i++)
        if (strcmp(s->tombstones[i].uuid, uuid) == 0)
            return &s->tombstones[i];
    return NULL;
}

double contacts_tombstone(const contacts_t *store, const char *uuid)
{
    if (store == NULL || uuid == NULL)
        return -1.0;
    at_tombstone_t *t = _tomb(store, uuid);
    return t != NULL ? t->at : -1.0;
}

int contacts_set_tombstone(contacts_t *store, const char *uuid, double at)
{
    if (store == NULL || !at_is_lower_uuid(uuid))
        return -1;
    at_tombstone_t *t = _tomb(store, uuid);
    if (t != NULL) {
        if (at > t->at)
            t->at = at;
        return 0;
    }
    if (store->tombstones_count == store->tombstones_cap) {
        size_t ncap = store->tombstones_cap ? store->tombstones_cap * 2 : 4;
        at_tombstone_t *nt = realloc(store->tombstones, ncap * sizeof(*nt));
        if (nt == NULL)
            return -1;
        store->tombstones = nt;
        store->tombstones_cap = ncap;
    }
    t = &store->tombstones[store->tombstones_count++];
    at_strlcpy(t->uuid, uuid, sizeof(t->uuid));
    t->at = at;
    return 0;
}

static void _drop_tombstone(contacts_t *s, const char *uuid)
{
    at_tombstone_t *t = _tomb(s, uuid);
    if (t == NULL)
        return;
    size_t i = (size_t)(t - s->tombstones);
    memmove(&s->tombstones[i], &s->tombstones[i + 1],
            (s->tombstones_count - i - 1) * sizeof(*t));
    s->tombstones_count--;
}

/* Move an already-owned contact into the store (replace-by-uuid or append).
 * Takes ownership of *c (its heap fields). */
static int _place_move(contacts_t *s, contact_t *c)
{
    char uuid_s[UUID_STRING_LEN + 1];
    uuid_unparse(c->identity.uuid, uuid_s);
    contact_t *existing = _find(s, uuid_s);
    _drop_tombstone(s, uuid_s);
    if (existing != NULL) {
        contact_free(existing);
        *existing = *c;
        return 0;
    }
    if (_grow(s) != 0) {
        contact_free(c);
        return -1;
    }
    s->items[s->count++] = *c;
    return 0;
}

static int _deep_copy(contact_t *dst, const contact_t *src)
{
    *dst = *src;
    dst->rendezvous = NULL;
    dst->rendezvous_count = 0;
    if (src->rendezvous_count > 0) {
        dst->rendezvous = calloc(src->rendezvous_count, sizeof(char *));
        if (dst->rendezvous == NULL)
            return -1;
        for (size_t i = 0; i < src->rendezvous_count; i++)
            dst->rendezvous[dst->rendezvous_count++] = strdup(src->rendezvous[i]);
    }
    dst->devices = NULL;
    dst->devices_count = 0;
    if (src->devices_count > 0) {
        dst->devices = calloc(src->devices_count, sizeof(at_contact_device_t));
        if (dst->devices == NULL)
            return -1;
        for (size_t i = 0; i < src->devices_count; i++) {
            dst->devices[i] = src->devices[i];
            json_incref(dst->devices[i].identity);
            json_incref(dst->devices[i].cert);
        }
        dst->devices_count = src->devices_count;
    }
    if (src->identity.operator_key_binding != NULL &&
        src->identity.operator_key_binding_len > 0) {
        dst->identity.operator_key_binding =
            malloc(src->identity.operator_key_binding_len);
        if (dst->identity.operator_key_binding != NULL)
            memcpy(dst->identity.operator_key_binding,
                   src->identity.operator_key_binding,
                   src->identity.operator_key_binding_len);
    } else {
        dst->identity.operator_key_binding = NULL;
        dst->identity.operator_key_binding_len = 0;
    }
    return 0;
}

int contacts_add(contacts_t *store, const contact_t *c)
{
    if (store == NULL || c == NULL)
        return -1;
    contact_t copy;
    if (_deep_copy(&copy, c) != 0)
        return -1;
    return _place_move(store, &copy);
}

contact_t *contacts_get_first(contacts_t *store, const char *uuid)
{
    if (store == NULL || uuid == NULL)
        return NULL;
    return _find(store, uuid);
}

contact_t *contacts_get(contacts_t *store, const char *uuid)
{
    if (store == NULL || uuid == NULL)
        return NULL;
    contact_t *c = _find(store, uuid);
    for (size_t i = 0; i < store->count && c == NULL; i++)
        for (size_t d = 0; d < store->items[i].devices_count && c == NULL; d++)
            if (strcasecmp(store->items[i].devices[d].uuid, uuid) == 0)
                c = &store->items[i];
    return c;
}

contact_t *contacts_by_operator(contacts_t *store, const char *operator_key)
{
    if (store == NULL || operator_key == NULL || operator_key[0] == '\0')
        return NULL;
    for (size_t i = 0; i < store->count; i++)
        if (strcmp(store->items[i].operator_key, operator_key) == 0)
            return &store->items[i];
    return NULL;
}

contact_t *contacts_by_petname(contacts_t *store, const char *petname)
{
    if (store == NULL || petname == NULL)
        return NULL;
    for (size_t i = 0; i < store->count; i++)
        if (strcmp(store->items[i].petname, petname) == 0)
            return &store->items[i];
    return NULL;
}

bool contacts_remove(contacts_t *store, const char *uuid)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return contacts_remove_at(store, uuid,
                              (double)ts.tv_sec + (double)ts.tv_nsec / 1e9);
}

bool contacts_remove_at(contacts_t *store, const char *uuid, double at)
{
    if (store == NULL || uuid == NULL)
        return false;
    char u[UUID_STRING_LEN + 1];
    for (size_t i = 0; i < store->count; i++) {
        uuid_unparse(store->items[i].identity.uuid, u);
        if (strcmp(u, uuid) == 0) {
            double v = contact_version(&store->items[i]);
            contacts_set_tombstone(store, u, at > v ? at : v);
            contact_free(&store->items[i]);
            /* compact: move the tail down one */
            memmove(&store->items[i], &store->items[i + 1],
                    (store->count - i - 1) * sizeof(contact_t));
            store->count--;
            return true;
        }
    }
    return false;
}

/* ------------------------------------------------------------------------- */
/* Canonical JSON <-> struct                                                  */
/* ------------------------------------------------------------------------- */

int contact_to_json(const contact_t *c, json_t **obj_out)
{
    if (c == NULL || obj_out == NULL)
        return -1;
    json_t *id = NULL;
    if (public_identity_to_json(&c->identity, &id) != 0)
        return -1;
    json_t *o = json_object();
    json_object_set_new(o, "identity", id);
    json_object_set_new(o, "petname", json_string(c->petname));
    json_object_set_new(o, "verified", json_boolean(c->verified));
    json_object_set_new(o, "provenance",
                        json_string(at_provenance_str(c->provenance)));
    json_object_set_new(o, "trust_seed", json_real(c->trust_seed));
    json_t *rv = json_array();
    for (size_t i = 0; i < c->rendezvous_count; i++)
        json_array_append_new(rv, json_string(c->rendezvous[i]));
    json_object_set_new(o, "rendezvous", rv);
    json_object_set_new(o, "nonce", json_string(c->nonce));
    json_object_set_new(o, "added_at", json_real(c->added_at));
    json_object_set_new(o, "verified_at", json_real(c->verified_at));
    /* Only once set, as Python does, so a store with no record applied is the
     * same file either runtime wrote before records existed. */
    if (c->reach_seq > 0)
        json_object_set_new(o, "reach_seq", json_integer((json_int_t)c->reach_seq));
    /* Likewise only once there is something to say (Phase 4). */
    if (c->operator_key[0] != '\0')
        json_object_set_new(o, "operator_key", json_string(c->operator_key));
    if (c->devices_count > 0) {
        json_t *ds = json_array();
        for (size_t i = 0; i < c->devices_count; i++)
            json_array_append_new(ds, json_pack("{s:O, s:O, s:f}",
                                                "identity", c->devices[i].identity,
                                                "cert", c->devices[i].cert,
                                                "added_at", c->devices[i].added_at));
        json_object_set_new(o, "devices", ds);
    }
    if (c->updated_at > 0.0)
        json_object_set_new(o, "updated_at", json_real(c->updated_at));
    *obj_out = o;
    return 0;
}

static at_provenance_t _provenance_from_str(const char *s)
{
    if (s != NULL && strcmp(s, "in_person") == 0)
        return AT_PROV_IN_PERSON;
    if (s != NULL && strcmp(s, "directory") == 0)
        return AT_PROV_DIRECTORY;
    if (s != NULL && strcmp(s, "sibling") == 0)
        return AT_PROV_SIBLING;
    if (s != NULL && strcmp(s, "area") == 0)
        return AT_PROV_AREA;
    if (s != NULL && strcmp(s, "backup") == 0)
        return AT_PROV_BACKUP;
    return AT_PROV_TOKEN;
}

static double _real(const json_t *o, const char *k)
{
    json_t *v = json_object_get((json_t *)o, k);
    if (json_is_real(v))
        return json_real_value(v);
    if (json_is_integer(v))
        return (double)json_integer_value(v);
    return 0.0;
}

int contact_from_json(const json_t *obj, contact_t *out)
{
    if (obj == NULL || out == NULL)
        return -1;
    memset(out, 0, sizeof(*out));
    if (public_identity_from_json(json_object_get((json_t *)obj, "identity"),
                                  &out->identity) != 0)
        return -1;

    const char *petname = json_string_value(
        json_object_get((json_t *)obj, "petname"));
    if (petname != NULL)
        at_strlcpy(out->petname, petname, sizeof(out->petname));
    out->verified = json_is_true(json_object_get((json_t *)obj, "verified"));
    out->provenance = _provenance_from_str(
        json_string_value(json_object_get((json_t *)obj, "provenance")));
    out->trust_seed = _real(obj, "trust_seed");
    const char *nonce = json_string_value(
        json_object_get((json_t *)obj, "nonce"));
    if (nonce != NULL)
        at_strlcpy(out->nonce, nonce, sizeof(out->nonce));
    out->added_at = _real(obj, "added_at");
    out->verified_at = _real(obj, "verified_at");
    out->updated_at = _real(obj, "updated_at");
    if (!(out->updated_at >= 0.0))
        out->updated_at = 0.0;
    json_t *rs = json_object_get((json_t *)obj, "reach_seq");
    out->reach_seq = json_is_integer(rs) ? (int64_t)json_integer_value(rs) : 0;

    const char *op = json_string_value(json_object_get((json_t *)obj, "operator_key"));
    if (op != NULL && at_dir_is_hex_key(op))
        at_strlcpy(out->operator_key, op, sizeof(out->operator_key));
    at_contact_load_devices(out, json_object_get((json_t *)obj, "devices"));

    json_t *rv = json_object_get((json_t *)obj, "rendezvous");
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
    return 0;
}

int contacts_to_json(const contacts_t *store, json_t **obj_out)
{
    if (store == NULL || obj_out == NULL)
        return -1;
    json_t *root = json_object();
    json_object_set_new(root, "typename", json_string(AT_CONTACTS_TYPENAME));
    json_object_set_new(root, "version", json_integer(AT_CONTACTS_VERSION));
    json_t *cs = json_object();
    char uuid_s[UUID_STRING_LEN + 1];
    for (size_t i = 0; i < store->count; i++) {
        json_t *cj = NULL;
        if (contact_to_json(&store->items[i], &cj) != 0) {
            json_decref(root);
            json_decref(cs);
            return -1;
        }
        uuid_unparse(store->items[i].identity.uuid, uuid_s);
        json_object_set_new(cs, uuid_s, cj);
    }
    json_object_set_new(root, "contacts", cs);
    /* Only once something was removed, so an older store stays
     * byte-identical. */
    if (store->tombstones_count > 0) {
        json_t *ts = json_object();
        for (size_t i = 0; i < store->tombstones_count; i++)
            json_object_set_new(ts, store->tombstones[i].uuid,
                                json_real(store->tombstones[i].at));
        json_object_set_new(root, "tombstones", ts);
    }
    *obj_out = root;
    return 0;
}

int contacts_from_json(const json_t *obj, contacts_t *store)
{
    contacts_init(store);
    if (!json_is_object(obj))
        return -1;
    json_t *cs = json_object_get((json_t *)obj, "contacts");
    if (!json_is_object(cs))
        return 0;   /* empty store is legal */
    const char *key;
    json_t *val;
    json_object_foreach(cs, key, val) {
        (void)key;   /* key by the contact's OWN uuid, not the map key */
        contact_t c;
        if (contact_from_json(val, &c) == 0)
            _place_move(store, &c);
    }
    /* Only well-formed tombstones, and none for a contact that is here. */
    json_t *ts = json_object_get((json_t *)obj, "tombstones");
    if (json_is_object(ts)) {
        json_object_foreach(ts, key, val) {
            if (!(json_is_real(val) || json_is_integer(val)))
                continue;
            double at = json_is_real(val) ? json_real_value(val)
                                          : (double)json_integer_value(val);
            if (at >= 0.0 && at_is_lower_uuid(key) && _find(store, key) == NULL)
                contacts_set_tombstone(store, key, at);
        }
    }
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Persistence                                                                */
/* ------------------------------------------------------------------------- */

static int _default_path(const char *data_dir, char *out, size_t out_len)
{
    int n = snprintf(out, out_len, "%s/%s", data_dir, AT_CONTACTS_FILENAME);
    return (n > 0 && (size_t)n < out_len) ? 0 : -1;
}

int contacts_load(const char *data_dir, contacts_t *store)
{
    contacts_init(store);
    if (data_dir == NULL)
        return -1;
    char path[4096];
    if (_default_path(data_dir, path, sizeof(path)) != 0)
        return -1;
    if (access(path, F_OK) != 0)
        return 0;   /* no file yet -> empty store, not an error */
    json_error_t err;
    json_t *root = json_load_file(path, 0, &err);
    if (root == NULL)
        return -1;
    int rc = contacts_from_json(root, store);
    json_decref(root);
    return rc;
}

int contacts_save(const contacts_t *store, const char *data_dir)
{
    if (store == NULL || data_dir == NULL)
        return -1;
    char dir[4096];
    at_strlcpy(dir, data_dir, sizeof(dir));
    if (makedirs(dir, 0755) != 0)
        return -1;

    char path[4096];
    if (_default_path(data_dir, path, sizeof(path)) != 0)
        return -1;

    json_t *root = NULL;
    if (contacts_to_json(store, &root) != 0)
        return -1;

    /* Atomic write: dump to a temp sibling, then rename over the target so a
     * concurrent reader (or a crash) never sees a torn contacts.cfg.json.
     * rename(2) is atomic within a filesystem, and the temp sits beside the
     * target so they are always on the same one. */
    char tmp[4096 + 16];
    snprintf(tmp, sizeof(tmp), "%s.tmp%d", path, (int)getpid());
    int rc = json_dump_file(root, tmp, JSON_INDENT(2) | JSON_SORT_KEYS);
    json_decref(root);
    if (rc != 0) {
        unlink(tmp);
        return -1;
    }
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}
