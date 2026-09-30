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

/** @file One address book across a user's devices (C twin of
 *  contacts/sync.py). Every step mirrors the Python merge in order. */

#include "contacts/sync.h"
#include "utilities/util.h"   /* at_strlcpy */

#include <stdlib.h>
#include <string.h>

#include <uuid/uuid.h>

/** Hints kept on a contact after a merge: first_contact's
 *  AT_FC_MAX_RENDEZVOUS_HINTS, Python's MAX_RENDEZVOUS_HINTS. */
#define SYNC_HINTS_MAX 4

const char *at_sync_action_str(at_sync_action_t a)
{
    switch (a) {
    case AT_SYNC_ADDED:
        return "added";
    case AT_SYNC_UPDATED:
        return "updated";
    case AT_SYNC_REMOVED:
        return "removed";
    case AT_SYNC_TOMBSTONE:
        return "tombstone";
    default:
        return "";
    }
}

static bool _wanted(const char *uuid, const char *const *uuids, size_t n)
{
    if (uuids == NULL)
        return true;
    for (size_t i = 0; i < n; i++)
        if (uuids[i] != NULL && strcmp(uuids[i], uuid) == 0)
            return true;
    return false;
}

json_t *at_sync_build(const contacts_t *store, const char *const *uuids, size_t n)
{
    if (store == NULL)
        return NULL;
    json_t *cs = json_object();
    char u[UUID_STRING_LEN + 1];
    for (size_t i = 0; i < store->count; i++) {
        uuid_unparse_lower(store->items[i].identity.uuid, u);
        if (!_wanted(u, uuids, n))
            continue;
        json_t *cj = NULL;
        if (contact_to_json(&store->items[i], &cj) == 0)
            json_object_set_new(cs, u, cj);
    }
    json_t *ts = json_object();
    for (size_t i = 0; i < store->tombstones_count; i++)
        if (_wanted(store->tombstones[i].uuid, uuids, n))
            json_object_set_new(ts, store->tombstones[i].uuid,
                                json_real(store->tombstones[i].at));
    return json_pack("{s:i, s:s, s:o, s:o}", "v", AT_SYNC_VERSION,
                     "typename", AT_SYNC_TYPENAME, "contacts", cs, "tombstones", ts);
}

/* --- the change list ------------------------------------------------------ */

typedef struct {
    at_sync_change_t *items;
    size_t count;
    bool oom;
} changes_t;

static void _note(changes_t *ch, const char *uuid, at_sync_action_t a)
{
    for (size_t i = 0; i < ch->count; i++) {
        if (strcmp(ch->items[i].uuid, uuid) == 0) {
            ch->items[i].action = a;
            return;
        }
    }
    at_sync_change_t *n = realloc(ch->items, (ch->count + 1) * sizeof(*n));
    if (n == NULL) {
        ch->oom = true;
        return;
    }
    ch->items = n;
    at_strlcpy(ch->items[ch->count].uuid, uuid, sizeof(ch->items[0].uuid));
    ch->items[ch->count++].action = a;
}

static int _cmp_change(const void *a, const void *b)
{
    return strcmp(((const at_sync_change_t *)a)->uuid,
                  ((const at_sync_change_t *)b)->uuid);
}

/* --- helpers --------------------------------------------------------------- */

static int _cmp_str(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* An object's keys, sorted (Python iterates sorted(...)). Borrowed; free the
 * array only. */
static const char **_sorted_keys(const json_t *obj, size_t *n)
{
    *n = json_object_size(obj);
    const char **keys = calloc(*n ? *n : 1, sizeof(char *));
    if (keys == NULL) {
        *n = 0;
        return NULL;
    }
    size_t i = 0;
    const char *k;
    json_t *v;
    json_object_foreach((json_t *)obj, k, v) {
        (void)v;
        keys[i++] = k;
    }
    qsort(keys, *n, sizeof(char *), _cmp_str);
    return keys;
}

static bool _time(const json_t *v, double *out)
{
    double t;
    if (json_is_real(v))
        t = json_real_value(v);
    else if (json_is_integer(v))
        t = (double)json_integer_value(v);
    else
        return false;
    if (!(t >= 0.0))
        return false;
    *out = t;
    return true;
}

static double _clamp(double t, double now)
{
    return t > now + AT_SYNC_CLOCK_SKEW ? now : t;
}

static void _uuid_of(const contact_t *c, char out[UUID_STRING_LEN + 1])
{
    uuid_unparse_lower(c->identity.uuid, out);
}

/* The contact's device uuids, sorted and joined by ','. malloc'd. */
static char *_joined_devices(const contact_t *c)
{
    const char **u = calloc(c->devices_count ? c->devices_count : 1, sizeof(char *));
    char *out = calloc(c->devices_count * (UUID_STRING_LEN + 1) + 1, 1);
    if (u == NULL || out == NULL) {
        free(u);
        free(out);
        return NULL;
    }
    for (size_t i = 0; i < c->devices_count; i++)
        u[i] = c->devices[i].uuid;
    qsort(u, c->devices_count, sizeof(char *), _cmp_str);
    for (size_t i = 0; i < c->devices_count; i++) {
        if (i > 0)
            strcat(out, ",");
        strcat(out, u[i]);
    }
    free(u);
    return out;
}

/* Python's _tie_key(a) vs _tie_key(b): <0, 0, >0. */
static int _tie_cmp(const contact_t *a, const contact_t *b)
{
    if (a->verified != b->verified)
        return a->verified ? 1 : -1;
    if (a->trust_seed < b->trust_seed)
        return -1;
    if (a->trust_seed > b->trust_seed)
        return 1;
    int r = strcmp(a->petname, b->petname);
    if (r != 0)
        return r;
    r = strcmp(a->operator_key, b->operator_key);
    if (r != 0)
        return r;
    char *da = _joined_devices(a), *db = _joined_devices(b);
    r = (da != NULL && db != NULL) ? strcmp(da, db) : 0;
    free(da);
    free(db);
    if (r != 0)
        return r;
    return strcmp(a->nonce, b->nonce);
}

static bool _newer(const contact_t *remote, const contact_t *local)
{
    double rv = contact_version(remote), lv = contact_version(local);
    if (rv > lv)
        return true;
    if (rv < lv)
        return false;
    return _tie_cmp(remote, local) > 0;
}

static bool _lists_device(const contact_t *c, const char *uuid)
{
    char first[UUID_STRING_LEN + 1];
    _uuid_of(c, first);
    if (strcmp(first, uuid) == 0)
        return true;
    for (size_t i = 0; i < c->devices_count; i++)
        if (strcmp(c->devices[i].uuid, uuid) == 0)
            return true;
    return false;
}

/* Fold into @p winner what @p loser has gained that it lacks. Whether it
 * changed. */
static bool _absorb(contact_t *winner, const contact_t *loser)
{
    bool changed = false;
    if (loser->verified && !winner->verified) {
        winner->verified = true;
        winner->verified_at = loser->verified_at;
        winner->trust_seed = loser->trust_seed;
        changed = true;
    }
    if (loser->operator_key[0] != '\0' && winner->operator_key[0] == '\0') {
        at_strlcpy(winner->operator_key, loser->operator_key,
                   sizeof(winner->operator_key));
        changed = true;
    }
    if (strcmp(loser->operator_key, winner->operator_key) == 0) {
        for (size_t i = 0; i < loser->devices_count; i++) {
            const at_contact_device_t *d = &loser->devices[i];
            if (_lists_device(winner, d->uuid) ||
                winner->devices_count >= AT_CONTACT_DEVICES_MAX)
                continue;
            at_contact_device_t *nd = realloc(winner->devices,
                                              (winner->devices_count + 1) * sizeof(*nd));
            if (nd == NULL)
                break;
            winner->devices = nd;
            nd[winner->devices_count] = *d;
            json_incref(d->identity);
            json_incref(d->cert);
            winner->devices_count++;
            changed = true;
        }
    }
    return changed;
}

static bool _excluded(const char *uuid, const char *const *exclude, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (exclude[i] != NULL && strcmp(exclude[i], uuid) == 0)
            return true;
    return false;
}

/* Whether @p u is filed under a contact other than the one at @p uuid. */
static bool _held_elsewhere(contacts_t *store, const char *u, const char *uuid)
{
    contact_t *holder = contacts_get(store, u);
    if (holder == NULL)
        return false;
    char hu[UUID_STRING_LEN + 1];
    _uuid_of(holder, hu);
    return strcmp(hu, uuid) != 0;
}

static bool _conflicts(contacts_t *store, const contact_t *c,
                       const char *const *exclude, size_t n_exclude)
{
    char uuid[UUID_STRING_LEN + 1];
    _uuid_of(c, uuid);
    if (_excluded(uuid, exclude, n_exclude) || _held_elsewhere(store, uuid, uuid))
        return true;
    for (size_t i = 0; i < c->devices_count; i++)
        if (_excluded(c->devices[i].uuid, exclude, n_exclude) ||
            _held_elsewhere(store, c->devices[i].uuid, uuid))
            return true;
    if (c->operator_key[0] != '\0') {
        contact_t *holder = contacts_by_operator(store, c->operator_key);
        if (holder != NULL) {
            char hu[UUID_STRING_LEN + 1];
            _uuid_of(holder, hu);
            if (strcmp(hu, uuid) != 0)
                return true;
        }
    }
    return false;
}

static bool _has_hint(char **list, size_t n, const char *h)
{
    for (size_t i = 0; i < n; i++)
        if (strcmp(list[i], h) == 0)
            return true;
    return false;
}

/* Replace @p c's hints with @p first's then its own, deduplicated, at most
 * SYNC_HINTS_MAX (Python _merge_hints(local, remote)). */
static void _merge_hints(contact_t *c, const contact_t *first)
{
    char **out = calloc(SYNC_HINTS_MAX, sizeof(char *));
    if (out == NULL)
        return;
    size_t n = 0;
    const contact_t *srcs[2] = {first, c};
    for (int s = 0; s < 2; s++)
        for (size_t i = 0; i < srcs[s]->rendezvous_count && n < SYNC_HINTS_MAX; i++) {
            const char *h = srcs[s]->rendezvous[i];
            if (h != NULL && h[0] != '\0' && !_has_hint(out, n, h))
                out[n++] = strdup(h);
        }
    for (size_t i = 0; i < c->rendezvous_count; i++)
        free(c->rendezvous[i]);
    free(c->rendezvous);
    c->rendezvous = out;
    c->rendezvous_count = n;
}

static void _clamp_contact(contact_t *c, double now)
{
    c->added_at = _clamp(c->added_at, now);
    c->verified_at = _clamp(c->verified_at, now);
    c->updated_at = _clamp(c->updated_at, now);
}

/* A deep copy of @p c through its canonical form (Python's
 * Contact.from_canonical(c.to_canonical())). 0, or -1. */
static int _copy(const contact_t *c, contact_t *out)
{
    json_t *j = NULL;
    if (contact_to_json(c, &j) != 0)
        return -1;
    int rc = contact_from_json(j, out);
    json_decref(j);
    return rc;
}

/* --- merge ----------------------------------------------------------------- */

int at_sync_merge(contacts_t *store, const json_t *payload, double now,
                  const char *const *exclude, size_t n_exclude,
                  at_sync_change_t **changes_out, size_t *n_changes)
{
    if (changes_out != NULL)
        *changes_out = NULL;
    if (n_changes != NULL)
        *n_changes = 0;
    if (store == NULL || !json_is_object(payload))
        return -1;
    const char *tn = json_string_value(json_object_get(payload, "typename"));
    json_t *v = json_object_get(payload, "v");
    if (tn == NULL || strcmp(tn, AT_SYNC_TYPENAME) != 0 || !json_is_integer(v) ||
        json_integer_value(v) != AT_SYNC_VERSION)
        return -1;
    json_t *contacts = json_object_get(payload, "contacts");
    json_t *tombstones = json_object_get(payload, "tombstones");
    if ((contacts != NULL && !json_is_object(contacts)) ||
        (tombstones != NULL && !json_is_object(tombstones)))
        return -1;

    changes_t ch = {0};
    size_t n;
    const char **keys;

    if (tombstones != NULL && (keys = _sorted_keys(tombstones, &n)) != NULL) {
        for (size_t k = 0; k < n; k++) {
            const char *uuid = keys[k];
            double at;
            if (!_time(json_object_get(tombstones, uuid), &at) || !at_is_lower_uuid(uuid))
                continue;
            at = _clamp(at, now);
            contact_t *local = contacts_get_first(store, uuid);
            if (local != NULL) {
                if (at >= contact_version(local)) {
                    contacts_remove_at(store, uuid, at);
                    _note(&ch, uuid, AT_SYNC_REMOVED);
                }
            } else if (at > contacts_tombstone(store, uuid)) {
                contacts_set_tombstone(store, uuid, at);
                _note(&ch, uuid, AT_SYNC_TOMBSTONE);
            }
        }
        free(keys);
    }

    if (contacts != NULL && (keys = _sorted_keys(contacts, &n)) != NULL) {
        for (size_t k = 0; k < n; k++) {
            contact_t remote;
            if (contact_from_json(json_object_get(contacts, keys[k]), &remote) != 0)
                continue;
            char uuid[UUID_STRING_LEN + 1];
            _uuid_of(&remote, uuid);
            if (strcmp(uuid, keys[k]) != 0) {
                contact_free(&remote);
                continue;
            }
            _clamp_contact(&remote, now);
            if (contacts_tombstone(store, uuid) >= contact_version(&remote) ||
                _conflicts(store, &remote, exclude, n_exclude)) {
                contact_free(&remote);
                continue;
            }
            contact_t *local = contacts_get_first(store, uuid);
            if (local == NULL) {
                remote.provenance = AT_PROV_SIBLING;
                if (contacts_add(store, &remote) == 0)
                    _note(&ch, uuid, AT_SYNC_ADDED);
            } else if (_newer(&remote, local)) {
                _absorb(&remote, local);
                remote.provenance = local->provenance;
                if (local->reach_seq > remote.reach_seq)
                    remote.reach_seq = local->reach_seq;
                _merge_hints(&remote, local);
                if (!_conflicts(store, &remote, exclude, n_exclude) &&
                    contacts_add(store, &remote) == 0)
                    _note(&ch, uuid, AT_SYNC_UPDATED);
            } else {
                /* Ours stays, gaining what the older copy has that ours lacks. */
                contact_t mine;
                if (_copy(local, &mine) == 0) {
                    if (_absorb(&mine, &remote) &&
                        !_conflicts(store, &mine, exclude, n_exclude) &&
                        contacts_add(store, &mine) == 0)
                        _note(&ch, uuid, AT_SYNC_UPDATED);
                    contact_free(&mine);
                }
            }
            contact_free(&remote);
        }
        free(keys);
    }

    if (ch.count > 1)
        qsort(ch.items, ch.count, sizeof(ch.items[0]), _cmp_change);
    if (changes_out != NULL)
        *changes_out = ch.items;
    else
        free(ch.items);
    if (n_changes != NULL)
        *n_changes = ch.count;
    return 0;
}
