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

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "first_contact/net_registry.h"
#include "config/configuration.h"
#include "first_contact/directory.h"
#include "utilities/logger.h"
#include "utilities/util.h"

#define AT_REGISTRY_MAX_CLIENTS 1024

typedef struct {
    char handle[AT_DIR_HANDLE_MAX + 1];
    at_dir_signed_t entry;
} reg_entry_t;

typedef struct {
    char uuid[UUID_STR_LEN + 1];
    double tokens;
    double last;
} reg_bucket_t;

struct net_registry_s {
    pthread_mutex_t lock;
    char issuers[AT_REGISTRY_MAX_ISSUERS][2 * 32 + 1];
    size_t n_issuers;
    int rate;
    reg_entry_t *entries;
    size_t n_entries;
    reg_bucket_t buckets[AT_REGISTRY_MAX_CLIENTS];
    size_t n_buckets;
    net_relay_distrust_fn distrusted;
    void *distrust_arg;
    double (*monotonic)(void);
    double (*wallclock)(void);
};

static double _monotonic(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static double _wallclock(void)
{
    return (double)time(NULL);
}

static bool _flag_on(const char *name)
{
    const char *v = getenv(name);
    if (v == NULL)
        return false;
    while (*v == ' ' || *v == '\t')
        v++;
    char word[8] = {0};
    size_t n = 0;
    while (v[n] != '\0' && v[n] != ' ' && v[n] != '\t' && v[n] != '\n' && n < sizeof(word) - 1) {
        word[n] = (char)(v[n] >= 'A' && v[n] <= 'Z' ? v[n] + 32 : v[n]);
        n++;
    }
    return strcmp(word, "1") == 0 || strcmp(word, "true") == 0
        || strcmp(word, "yes") == 0 || strcmp(word, "on") == 0;
}

bool net_registry_enabled(void)
{
    return _flag_on("AT_REGISTRY");
}

int net_registry_rate(void)
{
    const char *v = getenv(AT_REGISTRY_RATE_ENV);
    if (v == NULL || *v == '\0')
        return AT_REGISTRY_DEFAULT_RATE;
    char *end = NULL;
    long r = strtol(v, &end, 10);
    while (end != NULL && (*end == ' ' || *end == '\t' || *end == '\n'))
        end++;
    if (end == NULL || *end != '\0' || r <= 0 || r > 1000000)
        return AT_REGISTRY_DEFAULT_RATE;
    return (int)r;
}

static bool _is_hex_key(const char *k)
{
    if (k == NULL || strlen(k) != 64)
        return false;
    for (const char *c = k; *c != '\0'; c++)
        if (!((*c >= '0' && *c <= '9') || (*c >= 'a' && *c <= 'f') || (*c >= 'A' && *c <= 'F')))
            return false;
    return true;
}

size_t net_registry_load_issuers(const char *path, char out[][2 * 32 + 1], size_t max)
{
    char def[CFG_PATH_LEN + 64];
    if (path == NULL) {
        char dir[CFG_PATH_LEN + 1] = {0};
        if (get_cfg_dir(dir, sizeof(dir)) <= 0)
            return 0;
        snprintf(def, sizeof(def), "%s/%s", dir, AT_REGISTRY_ISSUERS_FILE);
        path = def;
    }
    json_error_t err;
    json_t *root = json_load_file(path, 0, &err);
    if (root == NULL) {
        log_warn(NULL, "Registry: cannot read %s (%s); no entry can be filed\n",
                 path, err.text);
        return 0;
    }
    json_t *arr = json_object_get(root, "issuers");
    size_t n = 0, bad = 0, i;
    json_t *item;
    json_array_foreach(arr, i, item) {
        const char *k = json_string_value(item);
        if (!_is_hex_key(k)) {
            bad++;
            continue;
        }
        char low[65];
        for (size_t j = 0; j < 64; j++)
            low[j] = (char)(k[j] >= 'A' && k[j] <= 'F' ? k[j] + 32 : k[j]);
        low[64] = '\0';
        bool dup = false;
        for (size_t j = 0; j < n && !dup; j++)
            dup = strcmp(out[j], low) == 0;
        if (!dup && n < max)
            memcpy(out[n++], low, sizeof(low));
    }
    if (bad > 0)
        log_warn(NULL, "Registry: %s lists %zu entries that are not hex keys; skipped\n",
                 path, bad);
    json_decref(root);
    return n;
}

net_registry_t *net_registry_new(const char *const *issuers, size_t n_issuers, int rate)
{
    net_registry_t *reg = calloc(1, sizeof(*reg));
    if (reg == NULL)
        return NULL;
    pthread_mutex_init(&reg->lock, NULL);
    for (size_t i = 0; i < n_issuers && reg->n_issuers < AT_REGISTRY_MAX_ISSUERS; i++)
        if (_is_hex_key(issuers[i]))
            at_strlcpy(reg->issuers[reg->n_issuers++], issuers[i], sizeof(reg->issuers[0]));
    reg->rate = rate > 0 ? rate : AT_REGISTRY_DEFAULT_RATE;
    reg->monotonic = _monotonic;
    reg->wallclock = _wallclock;
    return reg;
}

void net_registry_free(net_registry_t *reg)
{
    if (reg == NULL)
        return;
    for (size_t i = 0; i < reg->n_entries; i++)
        at_dir_free(&reg->entries[i].entry);
    free(reg->entries);
    pthread_mutex_destroy(&reg->lock);
    free(reg);
}

void net_registry_set_distrust(net_registry_t *reg, net_relay_distrust_fn fn, void *arg)
{
    if (reg == NULL)
        return;
    pthread_mutex_lock(&reg->lock);
    reg->distrusted = fn;
    reg->distrust_arg = arg;
    pthread_mutex_unlock(&reg->lock);
}

void net_registry_set_clocks(net_registry_t *reg, double (*monotonic)(void),
                             double (*wallclock)(void))
{
    if (reg == NULL)
        return;
    reg->monotonic = monotonic != NULL ? monotonic : _monotonic;
    reg->wallclock = wallclock != NULL ? wallclock : _wallclock;
}

static json_t *_reply(const char *op, const char *handle)
{
    return json_pack("{s:s, s:s}", "op", op, "handle", handle != NULL ? handle : "");
}

static json_t *_refused(const char *handle, const char *reason)
{
    json_t *r = _reply("dir_refused", handle);
    json_object_set_new(r, "reason", json_string(reason));
    return r;
}

static const char *_REASONS[] = {"", "malformed", "bad_signature", "expired",
                                 "untrusted", "mismatch"};

static bool _expired(const at_dir_signed_t *e, double now)
{
    json_t *v = json_object_get(e->body, "expiry");
    return !json_is_integer(v) || now >= (double)json_integer_value(v);
}

static reg_entry_t *_find_locked(net_registry_t *reg, const char *handle)
{
    for (size_t i = 0; i < reg->n_entries; i++)
        if (strcmp(reg->entries[i].handle, handle) == 0)
            return &reg->entries[i];
    return NULL;
}

static void _remove_locked(net_registry_t *reg, reg_entry_t *e)
{
    at_dir_free(&e->entry);
    size_t i = (size_t)(e - reg->entries);
    memmove(&reg->entries[i], &reg->entries[i + 1],
            (reg->n_entries - i - 1) * sizeof(reg->entries[0]));
    reg->n_entries--;
}

static void _evict_locked(net_registry_t *reg)
{
    double now = reg->wallclock();
    for (size_t i = reg->n_entries; i-- > 0;)
        if (_expired(&reg->entries[i].entry, now))
            _remove_locked(reg, &reg->entries[i]);
    if (reg->n_entries >= AT_REGISTRY_MAX_ENTRIES) {
        size_t soonest = 0;
        for (size_t i = 1; i < reg->n_entries; i++)
            if (at_dir_expiry(&reg->entries[i].entry) < at_dir_expiry(&reg->entries[soonest].entry))
                soonest = i;
        _remove_locked(reg, &reg->entries[soonest]);
    }
}

json_t *net_registry_publish(net_registry_t *reg, const char *uuid, const char *pubkey,
                             const json_t *wire)
{
    at_dir_signed_t entry;
    if (at_dir_from_wire(wire, &entry) != AT_DIR_OK)
        return _refused("", "malformed");
    const char *h = at_dir_handle(&entry);
    char handle[AT_DIR_HANDLE_MAX + 1] = {0};
    if (h != NULL)
        at_strlcpy(handle, h, sizeof(handle));
    const char *trusted[AT_REGISTRY_MAX_ISSUERS];
    for (size_t i = 0; i < reg->n_issuers; i++)
        trusted[i] = reg->issuers[i];
    int rc = at_dir_entry_verify(&entry, trusted, reg->n_issuers, reg->wallclock());
    if (rc != AT_DIR_OK) {
        at_dir_free(&entry);
        return _refused(handle, _REASONS[-rc]);
    }
    /* Only the holder files: the entry is signed by the key the registrant
     * proved, for the uuid it registered. */
    if (strcmp(at_dir_key(&entry), pubkey) != 0 || strcasecmp(at_dir_uuid(&entry), uuid) != 0) {
        at_dir_free(&entry);
        return _refused(handle, "not_holder");
    }
    int64_t seq = at_dir_seq(&entry);
    pthread_mutex_lock(&reg->lock);
    reg_entry_t *held = _find_locked(reg, handle);
    json_t *reply = NULL;
    if (held != NULL && strcmp(at_dir_key(&held->entry), at_dir_key(&entry)) != 0
        && !_expired(&held->entry, reg->wallclock())) {
        reply = _refused(handle, "taken");
    } else if (held != NULL && strcmp(at_dir_key(&held->entry), at_dir_key(&entry)) == 0) {
        if (seq == at_dir_seq(&held->entry)
            && strcmp(entry.body_str, held->entry.body_str) == 0)
            reply = json_pack("{s:s, s:s, s:I}", "op", "dir_published", "handle", handle,
                              "seq", (json_int_t)seq);
        else if (seq <= at_dir_seq(&held->entry))
            reply = _refused(handle, "stale");
    }
    if (reply != NULL) {
        pthread_mutex_unlock(&reg->lock);
        at_dir_free(&entry);
        return reply;
    }
    if (held != NULL) {
        at_dir_free(&held->entry);
        held->entry = entry;           /* move */
    } else {
        if (reg->n_entries >= AT_REGISTRY_MAX_ENTRIES)
            _evict_locked(reg);
        reg_entry_t *grown = realloc(reg->entries, (reg->n_entries + 1) * sizeof(*grown));
        if (grown == NULL) {
            pthread_mutex_unlock(&reg->lock);
            at_dir_free(&entry);
            return _refused(handle, "malformed");
        }
        reg->entries = grown;
        at_strlcpy(reg->entries[reg->n_entries].handle, handle, sizeof(grown->handle));
        reg->entries[reg->n_entries++].entry = entry;   /* move */
    }
    pthread_mutex_unlock(&reg->lock);
    log_info(NULL, "Registry: %.8s filed %s (seq %lld)\n", uuid, handle, (long long)seq);
    return json_pack("{s:s, s:s, s:I}", "op", "dir_published", "handle", handle,
                     "seq", (json_int_t)seq);
}

json_t *net_registry_withdraw(net_registry_t *reg, const char *uuid, const char *pubkey,
                              const char *handle)
{
    char folded[AT_DIR_HANDLE_MAX + 1] = {0};
    if (at_dir_normalize_handle(handle, folded, sizeof(folded)) != 0)
        folded[0] = '\0';
    pthread_mutex_lock(&reg->lock);
    reg_entry_t *held = folded[0] != '\0' ? _find_locked(reg, folded) : NULL;
    if (held != NULL && strcmp(at_dir_key(&held->entry), pubkey) == 0
        && strcasecmp(at_dir_uuid(&held->entry), uuid) == 0)
        _remove_locked(reg, held);
    pthread_mutex_unlock(&reg->lock);
    return _reply("dir_withdrawn", folded);
}

static bool _take_token_locked(net_registry_t *reg, const char *uuid)
{
    double now = reg->monotonic();
    reg_bucket_t *b = NULL;
    for (size_t i = 0; i < reg->n_buckets && b == NULL; i++)
        if (strcmp(reg->buckets[i].uuid, uuid) == 0)
            b = &reg->buckets[i];
    if (b == NULL) {
        size_t slot = reg->n_buckets < AT_REGISTRY_MAX_CLIENTS ? reg->n_buckets++ : 0;
        if (slot == 0 && reg->n_buckets == AT_REGISTRY_MAX_CLIENTS) {
            /* Full: reuse the least recently seen bucket. */
            for (size_t i = 1; i < reg->n_buckets; i++)
                if (reg->buckets[i].last < reg->buckets[slot].last)
                    slot = i;
        }
        b = &reg->buckets[slot];
        at_strlcpy(b->uuid, uuid, sizeof(b->uuid));
        b->tokens = (double)reg->rate;
        b->last = now;
    }
    double tokens = b->tokens + (now - b->last) * (double)reg->rate / 60.0;
    if (tokens > (double)reg->rate)
        tokens = (double)reg->rate;
    b->last = now;
    if (tokens < 1.0) {
        b->tokens = tokens;
        return false;
    }
    b->tokens = tokens - 1.0;
    return true;
}

json_t *net_registry_lookup(net_registry_t *reg, const char *uuid, const char *handle)
{
    char folded[AT_DIR_HANDLE_MAX + 1] = {0};
    if (at_dir_normalize_handle(handle, folded, sizeof(folded)) != 0)
        folded[0] = '\0';
    pthread_mutex_lock(&reg->lock);
    if (!_take_token_locked(reg, uuid)) {
        pthread_mutex_unlock(&reg->lock);
        return _reply("dir_limited", folded);
    }
    reg_entry_t *held = folded[0] != '\0' ? _find_locked(reg, folded) : NULL;
    json_t *wire = NULL;
    char holder_uuid[UUID_STR_LEN + 1] = {0}, holder_key[65] = {0};
    if (held != NULL) {
        bool visible = true;
        const char *vis = at_dir_visibility(&held->entry);
        if (vis != NULL && strcmp(vis, AT_DIR_VISIBILITY_PUBLISHED) == 0) {
            visible = false;
            for (size_t i = 0; i < reg->n_entries && !visible; i++)
                visible = strcasecmp(at_dir_uuid(&reg->entries[i].entry), uuid) == 0;
        }
        if (visible && !_expired(&held->entry, reg->wallclock())) {
            wire = at_dir_to_wire(&held->entry);
            at_strlcpy(holder_uuid, at_dir_uuid(&held->entry), sizeof(holder_uuid));
            at_strlcpy(holder_key, at_dir_key(&held->entry), sizeof(holder_key));
        }
    }
    net_relay_distrust_fn fn = reg->distrusted;
    void *arg = reg->distrust_arg;
    pthread_mutex_unlock(&reg->lock);
    if (wire != NULL && fn != NULL && fn(arg, holder_uuid, holder_key)) {
        json_decref(wire);
        wire = NULL;
    }
    json_t *r = _reply("dir_entry", folded);
    json_object_set_new(r, "entry", wire != NULL ? wire : json_null());
    return r;
}
