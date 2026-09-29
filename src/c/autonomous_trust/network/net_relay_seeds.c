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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>
#include <sodium.h>

#include "net_relay_seeds.h"
#include "config/configuration.h"
#include "utilities/logger.h"
#include "utilities/util.h"

static char g_release_key[2 * crypto_sign_PUBLICKEYBYTES + 1] = AT_RELAY_SEEDS_RELEASE_KEY;

void net_relay_seeds_set_release_key(const char *release_key_hex)
{
    snprintf(g_release_key, sizeof(g_release_key), "%s",
             release_key_hex != NULL ? release_key_hex : AT_RELAY_SEEDS_RELEASE_KEY);
}

/* {body, sig} -> the parsed body (new reference) and borrowed strings, or NULL. */
static json_t *_split(const char *text, json_t **wire_out, const char **body_str,
                      const char **sig_hex)
{
    json_t *wire = text != NULL ? json_loads(text, 0, NULL) : NULL;
    *wire_out = wire;
    *body_str = json_string_value(json_object_get(wire, "body"));
    *sig_hex = json_string_value(json_object_get(wire, "sig"));
    if (*body_str == NULL || *sig_hex == NULL)
        return NULL;
    json_t *body = json_loads(*body_str, 0, NULL);
    if (!json_is_object(body)) {
        json_decref(body);
        return NULL;
    }
    return body;
}

static int _check_sig(const char *key_hex, const char *domain, const char *body_str,
                      const char *sig_hex)
{
    unsigned char pk[crypto_sign_PUBLICKEYBYTES], sig[crypto_sign_BYTES];
    size_t pkl = 0, sl = 0;
    if (key_hex == NULL
        || sodium_hex2bin(pk, sizeof(pk), key_hex, strlen(key_hex), NULL, &pkl, NULL) != 0
        || pkl != sizeof(pk)
        || sodium_hex2bin(sig, sizeof(sig), sig_hex, strlen(sig_hex), NULL, &sl, NULL) != 0
        || sl != sizeof(sig))
        return -1;
    size_t dl = strlen(domain), bl = strlen(body_str);
    unsigned char *msg = malloc(dl + bl);
    if (msg == NULL)
        return -1;
    memcpy(msg, domain, dl);
    memcpy(msg + dl, body_str, bl);
    int ok = crypto_sign_verify_detached(sig, msg, dl + bl, pk);
    free(msg);
    return ok == 0 ? 0 : -1;
}

/* A missing field is empty; anything but a list of hints refuses the file. */
static int _hints(const json_t *body, const char *field, net_relay_seed_list_t *out)
{
    out->n = 0;
    json_t *arr = json_object_get(body, field);
    if (arr == NULL)
        return 0;
    if (!json_is_array(arr) || json_array_size(arr) > AT_RELAY_SEEDS_MAX)
        return -1;
    size_t i;
    json_t *item;
    json_array_foreach(arr, i, item) {
        const char *s = json_string_value(item);
        if (s == NULL
            || net_relay_parse_hint(s, out->eps[i].host, sizeof(out->eps[i].host),
                                    &out->eps[i].port, &out->pins[i]) != 0)
            return -1;
        out->n = i + 1;
    }
    return 0;
}

static bool _is_version(const json_t *body, const char *typename)
{
    const char *t = json_string_value(json_object_get(body, "typename"));
    json_t *v = json_object_get(body, "v");
    return t != NULL && strcmp(t, typename) == 0 && json_is_integer(v)
        && json_integer_value(v) == AT_RELAY_SEEDS_VERSION;
}

int net_relay_seeds_verify(const char *text, const char *release_key_hex,
                           long long *seq, net_relay_seed_list_t *out)
{
    if (out != NULL)
        out->n = 0;
    if (release_key_hex == NULL || release_key_hex[0] == '\0' || out == NULL)
        return -1;
    json_t *wire = NULL;
    const char *body_str = NULL, *sig_hex = NULL;
    json_t *body = _split(text, &wire, &body_str, &sig_hex);
    int rc = -1;
    json_t *s = json_object_get(body, "seq");
    if (body != NULL
        && _check_sig(release_key_hex, AT_RELAY_SEEDS_DOMAIN, body_str, sig_hex) == 0
        && _is_version(body, AT_RELAY_SEEDS_TYPENAME)
        && json_is_integer(s) && json_integer_value(s) >= 1
        && _hints(body, "relays", out) == 0) {
        if (seq != NULL)
            *seq = (long long)json_integer_value(s);
        rc = 0;
    }
    if (rc != 0)
        out->n = 0;
    json_decref(body);
    json_decref(wire);
    return rc;
}

int net_relay_seeds_verify_local(const char *text, const char *node_key_hex,
                                 net_relay_seed_list_t *adds,
                                 net_relay_seed_list_t *removes)
{
    if (adds == NULL || removes == NULL)
        return -1;
    adds->n = removes->n = 0;
    if (node_key_hex == NULL || node_key_hex[0] == '\0')
        return -1;
    json_t *wire = NULL;
    const char *body_str = NULL, *sig_hex = NULL;
    json_t *body = _split(text, &wire, &body_str, &sig_hex);
    int rc = body != NULL
        && _check_sig(node_key_hex, AT_RELAY_SEEDS_LOCAL_DOMAIN, body_str, sig_hex) == 0
        && _is_version(body, AT_RELAY_SEEDS_LOCAL_TYPENAME)
        && _hints(body, "add", adds) == 0
        && _hints(body, "remove", removes) == 0 ? 0 : -1;
    if (rc != 0)
        adds->n = removes->n = 0;
    json_decref(body);
    json_decref(wire);
    return rc;
}

static bool _has(const net_relay_ep_t *eps, size_t n, const net_relay_ep_t *ep)
{
    for (size_t i = 0; i < n; i++)
        if (eps[i].port == ep->port && strcmp(eps[i].host, ep->host) == 0)
            return true;
    return false;
}

size_t net_relay_seeds_merge(const net_relay_seed_list_t *shipped,
                             const net_relay_seed_list_t *adds,
                             const net_relay_seed_list_t *removes,
                             net_relay_ep_t *out, net_relay_pin_t *pins, size_t max)
{
    if (out == NULL)
        return 0;
    if (max > AT_RELAY_MAX)
        max = AT_RELAY_MAX;
    size_t n = 0;
    const net_relay_seed_list_t *sides[2] = {adds, shipped};
    for (int s = 0; s < 2; s++) {
        const net_relay_seed_list_t *l = sides[s];
        for (size_t i = 0; l != NULL && i < l->n && n < max; i++) {
            if (s == 1 && removes != NULL && _has(removes->eps, removes->n, &l->eps[i]))
                continue;
            if (_has(out, n, &l->eps[i]))
                continue;
            if (pins != NULL)
                pins[n] = l->pins[i];
            out[n++] = l->eps[i];
        }
    }
    return n;
}

static char *_read(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL)
        return NULL;
    char *buf = NULL;
    long len = -1;
    if (fseek(f, 0, SEEK_END) == 0 && (len = ftell(f)) >= 0 && fseek(f, 0, SEEK_SET) == 0
        && (buf = malloc((size_t)len + 1)) != NULL) {
        if (fread(buf, 1, (size_t)len, f) != (size_t)len) {
            free(buf);
            buf = NULL;
        } else {
            buf[len] = '\0';
        }
    }
    fclose(f);
    return buf;
}

int net_relay_seeds_path(char *out, size_t out_len)
{
    const char *env = getenv(AT_RELAY_SEEDS_ENV);
    while (env != NULL && (*env == ' ' || *env == '\t'))
        env++;
    int n;
    if (env != NULL && env[0] != '\0') {
        n = snprintf(out, out_len, "%s", env);
        /* Trim, as Python strips. */
        while (n > 0 && (out[n - 1] == ' ' || out[n - 1] == '\t' || out[n - 1] == '\n'))
            out[--n] = '\0';
    } else {
        char dir[CFG_PATH_LEN + 1] = {0};
        if (get_cfg_dir(dir, sizeof(dir)) <= 0)
            return -1;
        n = snprintf(out, out_len, "%s/%s", dir, AT_RELAY_SEEDS_FILE);
    }
    return (n <= 0 || (size_t)n >= out_len) ? -1 : 0;
}

int net_relay_seeds_node_key(char *out, size_t out_len)
{
    char dir[CFG_PATH_LEN + 1] = {0}, path[CFG_PATH_LEN + 64];
    if (out_len < 2 * crypto_sign_PUBLICKEYBYTES + 1 || get_cfg_dir(dir, sizeof(dir)) <= 0
        || (size_t)snprintf(path, sizeof(path), "%s/identity.cfg.json", dir) >= sizeof(path))
        return -1;
    json_t *ident = json_load_file(path, 0, NULL);
    const char *seed_hex = json_string_value(
        json_object_get(json_object_get(ident, "signature"), "hex_seed"));
    unsigned char seed[crypto_sign_SEEDBYTES], pk[crypto_sign_PUBLICKEYBYTES],
                  sk[crypto_sign_SECRETKEYBYTES];
    size_t sl = 0;
    int rc = seed_hex != NULL
        && sodium_hex2bin(seed, sizeof(seed), seed_hex, strlen(seed_hex), NULL, &sl, NULL) == 0
        && sl == sizeof(seed)
        && crypto_sign_seed_keypair(pk, sk, seed) == 0 ? 0 : -1;
    json_decref(ident);
    sodium_memzero(seed, sizeof(seed));
    sodium_memzero(sk, sizeof(sk));
    if (rc == 0)
        sodium_bin2hex(out, out_len, pk, sizeof(pk));
    return rc;
}

static int _data_path(const char *name, char *out, size_t out_len)
{
    char dir[CFG_PATH_LEN + 1] = {0};
    if (get_data_dir(dir, sizeof(dir)) <= 0)
        return -1;
    int n = snprintf(out, out_len, "%s/%s", dir, name);
    return (n < 0 || (size_t)n >= out_len) ? -1 : 0;
}

static long long _seen_seq(void)
{
    char path[CFG_PATH_LEN + 64];
    if (_data_path(AT_RELAY_SEEDS_SEEN_FILE, path, sizeof(path)) != 0)
        return 0;
    json_t *st = json_load_file(path, 0, NULL);
    json_t *s = json_object_get(st, "seq");
    long long seq = json_is_integer(s) ? (long long)json_integer_value(s) : 0;
    json_decref(st);
    return seq;
}

static void _raise_seen(long long seq)
{
    char dir[CFG_PATH_LEN + 1] = {0}, path[CFG_PATH_LEN + 64], tmp[CFG_PATH_LEN + 80];
    if (get_data_dir(dir, sizeof(dir)) > 0)
        (void)makedirs(dir, 0755);
    json_t *st = json_object();
    json_object_set_new(st, "seq", json_integer((json_int_t)seq));
    bool saved = _data_path(AT_RELAY_SEEDS_SEEN_FILE, path, sizeof(path)) == 0
        && (size_t)snprintf(tmp, sizeof(tmp), "%s.tmp", path) < sizeof(tmp)
        && json_dump_file(st, tmp, JSON_COMPACT) == 0
        && rename(tmp, path) == 0;
    json_decref(st);
    if (!saved)
        log_warn(NULL, "Relay seeds: cannot record seq %lld in %s\n", seq, dir);
}

size_t net_relay_seeds_load(const char *release_key_hex, net_relay_ep_t *out,
                            net_relay_pin_t *pins, size_t max)
{
    const char *key = release_key_hex != NULL ? release_key_hex : g_release_key;
    net_relay_seed_list_t *lists = calloc(3, sizeof(*lists));
    if (lists == NULL || out == NULL) {
        free(lists);
        return 0;
    }
    net_relay_seed_list_t *shipped = &lists[0], *adds = &lists[1], *removes = &lists[2];

    char path[CFG_PATH_LEN + 64];
    char *text = net_relay_seeds_path(path, sizeof(path)) == 0 ? _read(path) : NULL;
    if (text != NULL) {
        long long seq = 0;
        if (key[0] == '\0') {
            log_warn(NULL, "Relay seeds: %s refused: no release key is configured\n", path);
        } else if (net_relay_seeds_verify(text, key, &seq, shipped) != 0) {
            log_warn(NULL, "Relay seeds: %s refused: not a validly signed seed list\n", path);
        } else {
            long long floor = _seen_seq();
            if (seq < floor) {
                log_warn(NULL, "Relay seeds: %s is seq %lld, older than the seq %lld "
                         "this node already accepted; refused\n", path, seq, floor);
                shipped->n = 0;
            } else if (seq > floor) {
                _raise_seen(seq);
            }
        }
        free(text);
    }

    text = _data_path(AT_RELAY_SEEDS_LOCAL_FILE, path, sizeof(path)) == 0 ? _read(path) : NULL;
    if (text != NULL) {
        char node_key[2 * crypto_sign_PUBLICKEYBYTES + 1] = {0};
        (void)net_relay_seeds_node_key(node_key, sizeof(node_key));
        if (net_relay_seeds_verify_local(text, node_key, adds, removes) != 0)
            log_warn(NULL, "Relay seeds: local edits %s refused: not validly signed "
                     "by this node's key\n", path);
        free(text);
    }
    size_t n = net_relay_seeds_merge(shipped, adds, removes, out, pins, max);
    free(lists);
    return n;
}

const char *net_relay_seeds_release_key(void)
{
    return g_release_key;
}
