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

#include <dirent.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>

#include "rendezvous/net_relay_rosters.h"
#include "config/configuration.h"
#include "config/discover.h"
#include "utilities/logger.h"
#include "utilities/util.h"

static bool _is_key_hex(const char *s)
{
    if (s == NULL || strlen(s) != AT_RELAY_ROSTER_KEY_HEX)
        return false;
    for (const char *c = s; *c != '\0'; c++)
        if (!((*c >= '0' && *c <= '9') || (*c >= 'a' && *c <= 'f')))
            return false;
    return true;
}

static bool _pinned(const net_relay_roster_issuers_t *issuers, const char *key)
{
    for (size_t i = 0; issuers != NULL && i < issuers->n; i++)
        if (strcmp(issuers->keys[i], key) == 0)
            return true;
    return false;
}

/* The roster's `areas` into @p out, aligned with @p list's entries (the
 * body's `relays`, in order). 0, or -1 when present and not what a roster
 * allows. Mirrors Python relay_rosters._areas. */
static int _areas(const json_t *body, const net_relay_seed_list_t *list,
                  net_relay_roster_areas_t *out)
{
    if (out != NULL)
        memset(out, 0, sizeof(*out));
    json_t *areas = json_object_get(body, "areas");
    if (areas == NULL)
        return 0;
    if (!json_is_object(areas))
        return -1;
    json_t *relays = json_object_get(body, "relays");
    const char *hint;
    json_t *listed;
    json_object_foreach(areas, hint, listed) {
        size_t at = list->n;
        for (size_t i = 0; i < json_array_size(relays) && i < list->n && at == list->n; i++) {
            const char *r = json_string_value(json_array_get(relays, i));
            if (r != NULL && strcmp(r, hint) == 0)
                at = i;
        }
        if (at == list->n || !json_is_array(listed) || json_array_size(listed) == 0
            || json_array_size(listed) > AT_RELAY_ROSTER_AREAS_MAX)
            return -1;
        size_t i;
        json_t *a;
        json_array_foreach(listed, i, a) {
            if (!net_relay_is_area(json_string_value(a)))
                return -1;
            if (out != NULL)
                snprintf(out->areas[at][i], sizeof(out->areas[at][i]), "%s",
                         json_string_value(a));
        }
        if (out != NULL)
            out->n[at] = json_array_size(listed);
    }
    return 0;
}

int net_relay_roster_verify(const char *text, const net_relay_roster_issuers_t *issuers,
                            char *issuer_out, long long *seq, net_relay_seed_list_t *out)
{
    return net_relay_roster_verify_areas(text, issuers, issuer_out, seq, out, NULL);
}

int net_relay_roster_verify_areas(const char *text, const net_relay_roster_issuers_t *issuers,
                                  char *issuer_out, long long *seq, net_relay_seed_list_t *out,
                                  net_relay_roster_areas_t *areas)
{
    if (out == NULL)
        return -1;
    out->n = 0;
    json_t *wire = NULL;
    const char *body_str = NULL, *sig_hex = NULL;
    json_t *body = net_relay_signed_split(text, &wire, &body_str, &sig_hex);
    const char *issuer = json_string_value(json_object_get(body, "issuer"));
    const char *type = json_string_value(json_object_get(body, "typename"));
    json_t *v = json_object_get(body, "v");
    json_t *s = json_object_get(body, "seq");
    int rc = -1;
    if (body != NULL && _is_key_hex(issuer) && _pinned(issuers, issuer)
        && net_relay_signed_check(issuer, AT_RELAY_ROSTER_DOMAIN, body_str, sig_hex) == 0
        && type != NULL && strcmp(type, AT_RELAY_ROSTER_TYPENAME) == 0
        && json_is_integer(v) && json_integer_value(v) == AT_RELAY_ROSTER_VERSION
        && json_is_integer(s) && json_integer_value(s) >= 1
        && net_relay_signed_hints(body, "relays", out) == 0) {
        rc = 0;
        /* A community vouches for relays by key: an unpinned entry refuses all. */
        for (size_t i = 0; i < out->n; i++)
            if (!out->pins[i].set)
                rc = -1;
        if (rc == 0 && _areas(body, out, areas) != 0)
            rc = -1;
        if (rc == 0) {
            if (issuer_out != NULL)
                snprintf(issuer_out, AT_RELAY_ROSTER_KEY_HEX + 1, "%s", issuer);
            if (seq != NULL)
                *seq = (long long)json_integer_value(s);
        }
    }
    if (rc != 0)
        out->n = 0;
    json_decref(body);
    json_decref(wire);
    return rc;
}

static void _pin_issuer(net_relay_roster_issuers_t *out, const char *raw, size_t len)
{
    char key[AT_RELAY_ROSTER_KEY_HEX + 8] = {0};
    while (len > 0 && (*raw == ' ' || *raw == '\t')) {
        raw++;
        len--;
    }
    while (len > 0 && (raw[len - 1] == ' ' || raw[len - 1] == '\t' || raw[len - 1] == '\n'))
        len--;
    if (len == 0)
        return;
    if (len >= sizeof(key)) {
        log_warn(NULL, "Relay rosters: an issuer is not a hex ed25519 key; skipped\n");
        return;
    }
    for (size_t i = 0; i < len; i++)
        key[i] = (char)(raw[i] >= 'A' && raw[i] <= 'Z' ? raw[i] + 32 : raw[i]);
    if (!_is_key_hex(key)) {
        log_warn(NULL, "Relay rosters: issuer '%s' is not a hex ed25519 key; skipped\n", key);
        return;
    }
    if (_pinned(out, key) || out->n >= AT_RELAY_ROSTER_ISSUERS_MAX)
        return;
    snprintf(out->keys[out->n++], AT_RELAY_ROSTER_KEY_HEX + 1, "%s", key);
}

int net_relay_rosters_issuers_path(char *out, size_t out_len)
{
    char dir[CFG_PATH_LEN + 1] = {0};
    if (get_cfg_dir(dir, sizeof(dir)) <= 0)
        return -1;
    int n = snprintf(out, out_len, "%s/%s", dir, AT_RELAY_ROSTER_ISSUERS_FILE);
    return (n <= 0 || (size_t)n >= out_len) ? -1 : 0;
}

size_t net_relay_rosters_pinned(net_relay_roster_issuers_t *out)
{
    if (out == NULL)
        return 0;
    out->n = 0;
    const char *env = getenv(AT_RELAY_ROSTER_ISSUERS_ENV);
    for (const char *p = env; p != NULL && *p != '\0';) {
        const char *comma = strchr(p, ',');
        size_t len = comma != NULL ? (size_t)(comma - p) : strlen(p);
        _pin_issuer(out, p, len);
        if (comma == NULL)
            break;
        p = comma + 1;
    }
    char path[CFG_PATH_LEN + 64];
    char *text = net_relay_rosters_issuers_path(path, sizeof(path)) == 0
        ? net_relay_signed_read(path) : NULL;
    if (text != NULL) {
        json_t *doc = json_loads(text, 0, NULL);
        json_t *arr = json_object_get(doc, "issuers");
        if (!json_is_array(arr)) {
            log_warn(NULL, "Relay rosters: %s ignored (issuers is not a list)\n", path);
        } else {
            size_t i;
            json_t *item;
            json_array_foreach(arr, i, item) {
                const char *k = json_string_value(item);
                if (k != NULL)
                    _pin_issuer(out, k, strlen(k));
                else
                    log_warn(NULL, "Relay rosters: a non-string issuer in %s; skipped\n", path);
            }
        }
        json_decref(doc);
        free(text);
    }
    return out->n;
}

int net_relay_rosters_dir(char *out, size_t out_len)
{
    const char *env = getenv(AT_RELAY_ROSTERS_ENV);
    while (env != NULL && (*env == ' ' || *env == '\t'))
        env++;
    int n;
    if (env != NULL && env[0] != '\0') {
        n = snprintf(out, out_len, "%s", env);
        while (n > 0 && (out[n - 1] == ' ' || out[n - 1] == '\t' || out[n - 1] == '\n'))
            out[--n] = '\0';
    } else {
        char dir[CFG_PATH_LEN + 1] = {0};
        if (get_cfg_dir(dir, sizeof(dir)) <= 0)
            return -1;
        n = snprintf(out, out_len, "%s/%s", dir, AT_RELAY_ROSTERS_DIR);
    }
    return (n <= 0 || (size_t)n >= out_len) ? -1 : 0;
}

static int _cmp_names(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

size_t net_relay_rosters_files(char names[][256], size_t max)
{
    char dir[CFG_PATH_LEN + 64];
    if (net_relay_rosters_dir(dir, sizeof(dir)) != 0)
        return 0;
    DIR *d = opendir(dir);
    if (d == NULL)
        return 0;
    /* Collect every match, sort, then keep the first `max`: the cut must fall
     * on the same names Python keeps, which readdir order would not give. */
    size_t cap = 64, n = 0;
    char (*all)[256] = malloc(cap * sizeof(*all));
    size_t ext = strlen(CFG_FILE_EXT);
    struct dirent *e;
    while (all != NULL && (e = readdir(d)) != NULL) {
        size_t len = strlen(e->d_name);
        if (len <= ext || len >= 256 || strcmp(e->d_name + len - ext, CFG_FILE_EXT) != 0)
            continue;
        if (n == cap) {
            char (*grown)[256] = realloc(all, 2 * cap * sizeof(*all));
            if (grown == NULL)
                break;
            all = grown;
            cap *= 2;
        }
        snprintf(all[n++], 256, "%s", e->d_name);
    }
    closedir(d);
    if (all == NULL)
        return 0;
    qsort(all, n, sizeof(*all), _cmp_names);
    if (n > max)
        n = max;
    memcpy(names, all, n * sizeof(*all));
    free(all);
    return n;
}

typedef struct {
    bool have;
    long long seq;
    char path[CFG_PATH_LEN + 320];
    net_relay_seed_list_t list;
    net_relay_roster_areas_t areas;
} _best_t;

static void _save_seen(json_t *seen)
{
    char dir[CFG_PATH_LEN + 1] = {0}, path[CFG_PATH_LEN + 64], tmp[CFG_PATH_LEN + 80];
    if (get_data_dir(dir, sizeof(dir)) > 0)
        (void)makedirs(dir, 0755);
    bool saved = net_relay_signed_data_path(AT_RELAY_ROSTERS_SEEN_FILE, path, sizeof(path)) == 0
        && (size_t)snprintf(tmp, sizeof(tmp), "%s.tmp", path) < sizeof(tmp)
        && json_dump_file(seen, tmp, JSON_COMPACT | JSON_SORT_KEYS) == 0
        && rename(tmp, path) == 0;
    if (!saved)
        log_warn(NULL, "Relay rosters: cannot record seqs in %s\n", dir);
}

static const net_relay_area_provider_t *area_provider = NULL;

void net_relay_rosters_set_area_provider(const net_relay_area_provider_t *p)
{
    area_provider = p;
}

size_t net_relay_rosters_listed_buckets(char out[][8], size_t max)
{
    return area_provider != NULL ? area_provider->listed_buckets(out, max) : 0;
}

int net_relay_rosters_area_state_path(char *out, size_t len)
{
    return area_provider != NULL ? area_provider->state_path(out, len) : -1;
}

static bool _is_geohash_char(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'b' && c <= 'z' && c != 'i' && c != 'l'
                                      && c != 'o');
}

int net_relay_area_normalize(const char *in, char *out, size_t out_len, size_t min_len,
                             size_t max_len)
{
    if (in == NULL || out == NULL)
        return -1;
    size_t n = strlen(in);
    if (n < min_len || n > max_len || out_len < n + 1)
        return -1;
    for (size_t i = 0; i < n; i++) {
        char c = in[i];
        if (c >= 'A' && c <= 'Z')
            c = (char)(c - 'A' + 'a');
        if (!_is_geohash_char(c))
            return -1;
        out[i] = c;
    }
    out[n] = '\0';
    return 0;
}

bool net_relay_is_area(const char *in)
{
    char folded[AT_RELAY_AREA_MAX + 2];
    return net_relay_area_normalize(in, folded, sizeof(folded), AT_RELAY_AREA_MIN,
                                    AT_RELAY_AREA_MAX) == 0
        && strcmp(folded, in) == 0;
}

size_t net_relay_rosters_load(net_relay_ep_t *out, net_relay_pin_t *pins, size_t max)
{
    char buckets[16][8];
    size_t nb = net_relay_rosters_listed_buckets(buckets, 16);
    const char *ptrs[16];
    for (size_t i = 0; i < nb; i++)
        ptrs[i] = buckets[i];
    return net_relay_rosters_load_near(out, pins, max, ptrs, nb);
}

size_t net_relay_rosters_load_near(net_relay_ep_t *out, net_relay_pin_t *pins, size_t max,
                                   const char *const *buckets, size_t n_buckets)
{
    if (out == NULL || max == 0)
        return 0;
    if (max > AT_RELAY_MAX)
        max = AT_RELAY_MAX;
    net_relay_roster_issuers_t issuers;
    if (net_relay_rosters_pinned(&issuers) == 0)
        return 0;
    _best_t *best = calloc(issuers.n, sizeof(*best));
    net_relay_seed_list_t *list = calloc(1, sizeof(*list));
    char (*names)[256] = calloc(AT_RELAY_ROSTER_FILES_MAX, sizeof(*names));
    if (best == NULL || list == NULL || names == NULL) {
        free(best);
        free(list);
        free(names);
        return 0;
    }
    char dir[CFG_PATH_LEN + 64];
    size_t nf = net_relay_rosters_dir(dir, sizeof(dir)) == 0
        ? net_relay_rosters_files(names, AT_RELAY_ROSTER_FILES_MAX) : 0;
    for (size_t f = 0; f < nf; f++) {
        char path[CFG_PATH_LEN + 320];
        snprintf(path, sizeof(path), "%s/%s", dir, names[f]);
        char *text = net_relay_signed_read(path);
        if (text == NULL)
            continue;
        char issuer[AT_RELAY_ROSTER_KEY_HEX + 1] = {0};
        long long seq = 0;
        net_relay_roster_areas_t *areas = calloc(1, sizeof(*areas));
        if (areas == NULL || net_relay_roster_verify_areas(text, &issuers, issuer, &seq, list,
                                                           areas) != 0) {
            log_warn(NULL, "Relay rosters: %s refused: not a validly signed roster "
                     "from a pinned issuer\n", path);
        } else {
            for (size_t i = 0; i < issuers.n; i++) {
                if (strcmp(issuers.keys[i], issuer) != 0)
                    continue;
                if (!best[i].have || seq > best[i].seq) {
                    best[i].have = true;
                    best[i].seq = seq;
                    snprintf(best[i].path, sizeof(best[i].path), "%s", path);
                    best[i].list = *list;
                    best[i].areas = *areas;
                }
            }
        }
        free(areas);
        free(text);
    }

    char seen_path[CFG_PATH_LEN + 64];
    json_t *seen = net_relay_signed_data_path(AT_RELAY_ROSTERS_SEEN_FILE, seen_path,
                                              sizeof(seen_path)) == 0
        ? json_load_file(seen_path, 0, NULL) : NULL;
    if (!json_is_object(seen)) {
        json_decref(seen);
        seen = json_object();
    }
    bool raised = false;
    /* Every relay first, one per endpoint, then hubs for our own buckets to
     * the front (stable), THEN the cap: Python's order exactly. */
    size_t cap = AT_RELAY_SEEDS_MAX, n = 0;
    net_relay_ep_t *all = calloc(cap, sizeof(*all));
    net_relay_pin_t *all_pins = calloc(cap, sizeof(*all_pins));
    bool *near = calloc(cap, sizeof(*near));
    if (all == NULL || all_pins == NULL || near == NULL)
        cap = 0;
    for (size_t i = 0; i < issuers.n; i++) {
        if (!best[i].have)
            continue;
        json_t *f = json_object_get(seen, issuers.keys[i]);
        long long floor = json_is_integer(f) ? (long long)json_integer_value(f) : 0;
        if (best[i].seq < floor) {
            log_warn(NULL, "Relay rosters: %s is seq %lld from issuer %.16s…, older than "
                     "the seq %lld this node already accepted; refused\n",
                     best[i].path, best[i].seq, issuers.keys[i], floor);
            continue;
        }
        if (best[i].seq > floor) {
            json_object_set_new(seen, issuers.keys[i], json_integer((json_int_t)best[i].seq));
            raised = true;
        }
        for (size_t j = 0; j < best[i].list.n && n < cap; j++) {
            bool dup = false;
            for (size_t k = 0; k < n && !dup; k++)
                dup = all[k].port == best[i].list.eps[j].port
                   && strcmp(all[k].host, best[i].list.eps[j].host) == 0;
            if (dup)
                continue;
            bool is_near = false;
            for (size_t a = 0; a < best[i].areas.n[j] && !is_near; a++)
                for (size_t b = 0; b < n_buckets && !is_near; b++)
                    is_near = buckets[b] != NULL
                        && strncmp(buckets[b], best[i].areas.areas[j][a],
                                   strlen(best[i].areas.areas[j][a])) == 0;
            near[n] = is_near;
            all_pins[n] = best[i].list.pins[j];
            all[n++] = best[i].list.eps[j];
        }
    }
    if (raised)
        _save_seen(seen);
    size_t kept = 0;
    for (int pass = 0; pass < 2; pass++)
        for (size_t k = 0; k < n && kept < max; k++)
            if (near[k] == (pass == 0)) {
                if (pins != NULL)
                    pins[kept] = all_pins[k];
                out[kept++] = all[k];
            }
    n = kept;
    free(all);
    free(all_pins);
    free(near);
    json_decref(seen);
    free(best);
    free(list);
    free(names);
    return n;
}

/* The issuers file with @p issuer pinned or not. true when it changed. */
static bool _set_issuer(const char *issuer, bool pinned)
{
    char path[CFG_PATH_LEN + 64];
    if (net_relay_rosters_issuers_path(path, sizeof(path)) != 0)
        return false;
    char *text = net_relay_signed_read(path);
    json_t *doc = text != NULL ? json_loads(text, 0, NULL) : NULL;
    free(text);
    json_t *old = json_object_get(doc, "issuers");
    json_t *listed = json_array();
    bool had = false;
    size_t i;
    json_t *item;
    json_array_foreach(old, i, item) {
        const char *k = json_string_value(item);
        if (k == NULL)
            continue;
        char low[AT_RELAY_ROSTER_KEY_HEX + 1];
        snprintf(low, sizeof(low), "%s", k);
        for (char *c = low; *c != '\0'; c++)
            if (*c >= 'A' && *c <= 'Z')
                *c = (char)(*c + 32);
        if (strcmp(low, issuer) == 0) {
            had = true;
            if (!pinned)
                continue;
        }
        json_array_append_new(listed, json_string(low));
    }
    json_decref(doc);
    if (pinned && !had)
        json_array_append_new(listed, json_string(issuer));
    bool changed = had != pinned;
    if (changed) {
        char dir[CFG_PATH_LEN + 1] = {0}, tmp[CFG_PATH_LEN + 80];
        if (get_cfg_dir(dir, sizeof(dir)) > 0)
            (void)makedirs(dir, 0755);
        json_t *out = json_pack("{s:o}", "issuers", listed);
        listed = NULL;
        bool ok = out != NULL && (size_t)snprintf(tmp, sizeof(tmp), "%s.tmp", path) < sizeof(tmp)
            && json_dump_file(out, tmp, JSON_COMPACT) == 0 && rename(tmp, path) == 0;
        if (!ok)
            log_warn(NULL, "Relay rosters: cannot write %s\n", path);
        json_decref(out);
    }
    json_decref(listed);
    return changed;
}

static int _installed_path(const char *issuer, char *out, size_t out_len)
{
    char dir[CFG_PATH_LEN + 64];
    if (net_relay_rosters_dir(dir, sizeof(dir)) != 0)
        return -1;
    int n = snprintf(out, out_len, "%s/%.32s%s", dir, issuer, CFG_FILE_EXT);
    return (n <= 0 || (size_t)n >= out_len) ? -1 : 0;
}

int net_relay_rosters_install(const char *text, char *issuer_out, long long *seq_out)
{
    json_t *wire = NULL;
    const char *body_str = NULL, *sig_hex = NULL;
    json_t *body = net_relay_signed_split(text, &wire, &body_str, &sig_hex);
    const char *issuer = json_string_value(json_object_get(body, "issuer"));
    net_relay_roster_issuers_t self = {0};
    if (_is_key_hex(issuer)) {
        self.n = 1;
        snprintf(self.keys[0], sizeof(self.keys[0]), "%s", issuer);
    }
    net_relay_seed_list_t *list = calloc(1, sizeof(*list));
    char key[AT_RELAY_ROSTER_KEY_HEX + 1] = {0};
    long long seq = 0;
    int rc = list != NULL && self.n == 1
        && net_relay_roster_verify_areas(text, &self, key, &seq, list, NULL) == 0 ? 0 : -1;
    free(list);
    json_decref(body);
    json_decref(wire);
    if (rc != 0)
        return -1;
    char seen_path[CFG_PATH_LEN + 64];
    json_t *seen = net_relay_signed_data_path(AT_RELAY_ROSTERS_SEEN_FILE, seen_path,
                                              sizeof(seen_path)) == 0
        ? json_load_file(seen_path, 0, NULL) : NULL;
    json_t *f = json_object_get(seen, key);
    long long floor = json_is_integer(f) ? (long long)json_integer_value(f) : 0;
    json_decref(seen);
    if (seq < floor)
        return -2;
    char dir[CFG_PATH_LEN + 64], path[CFG_PATH_LEN + 160], tmp[CFG_PATH_LEN + 176];
    if (net_relay_rosters_dir(dir, sizeof(dir)) != 0 || _installed_path(key, path, sizeof(path)) != 0
        || (size_t)snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= sizeof(tmp))
        return -3;
    (void)makedirs(dir, 0755);
    FILE *fp = fopen(tmp, "w");
    bool ok = fp != NULL && fputs(text, fp) >= 0;
    if (fp != NULL && fclose(fp) != 0)
        ok = false;
    if (!ok || rename(tmp, path) != 0) {
        remove(tmp);
        return -3;
    }
    (void)_set_issuer(key, true);
    if (issuer_out != NULL)
        snprintf(issuer_out, AT_RELAY_ROSTER_KEY_HEX + 1, "%s", key);
    if (seq_out != NULL)
        *seq_out = seq;
    return 0;
}

int net_relay_rosters_remove(const char *issuer)
{
    char key[AT_RELAY_ROSTER_KEY_HEX + 1];
    if (issuer == NULL || strlen(issuer) != AT_RELAY_ROSTER_KEY_HEX)
        return -1;
    for (size_t i = 0; i <= AT_RELAY_ROSTER_KEY_HEX; i++)
        key[i] = (char)(issuer[i] >= 'A' && issuer[i] <= 'Z' ? issuer[i] + 32 : issuer[i]);
    if (!_is_key_hex(key))
        return -1;
    char path[CFG_PATH_LEN + 160];
    bool had = _installed_path(key, path, sizeof(path)) == 0 && remove(path) == 0;
    bool unpinned = _set_issuer(key, false);
    return had || unpinned ? 1 : 0;
}
