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

/* The rendezvous relay. See net_relay.h for the protocol. */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <jansson.h>
#include <sodium.h>

#include "net_relay.h"
#include "net_relay_seeds.h"
#include "net_relay_rosters.h"
#include "net_registry.h"
#include "net_hub.h"
#include "contacts/area_card.h"
#include "config/configuration.h"
#include "contacts/reach.h"
#include "identity/identity_priv.h"
#include "utilities/socket_helpers.h"
#include "utilities/util.h"

bool net_relay_enabled(void)
{
    const char *v = getenv("AT_RELAY");
    return v != NULL && (strcmp(v, "1") == 0 || strcasecmp(v, "true") == 0
                         || strcasecmp(v, "yes") == 0 || strcasecmp(v, "on") == 0);
}

int net_relay_port(void)
{
    const char *v = getenv("AT_RELAY_PORT");
    int p = (v != NULL && v[0] != '\0') ? atoi(v) : 0;
    return (p > 0 && p < 65536) ? p : AT_RELAY_DEFAULT_PORT;
}

int net_relay_parse_endpoint(const char *text, char *host, size_t host_len,
                             int *port)
{
    if (host == NULL || host_len == 0 || port == NULL)
        return -1;
    host[0] = '\0';
    if (text == NULL)
        return -1;
    const char *s = text;
    size_t slen = strlen(AT_RELAY_SCHEME);
    if (strncmp(s, AT_RELAY_SCHEME, slen) == 0)
        s += slen;
    const char *at = strchr(s, '@');
    if (at != NULL)
        s = at + 1;         /* a pin; net_relay_parse_hint reads it */
    char buf[256];
    if (at_strlcpy(buf, s, sizeof(buf)) >= sizeof(buf))
        return -1;
    size_t n = strlen(buf);
    while (n > 0 && buf[n - 1] == '/')
        buf[--n] = '\0';
    char *h, *p;
    if (buf[0] == '[') {
        char *close = strchr(buf, ']');
        if (close == NULL || close[1] != ':')
            return -1;
        *close = '\0';
        h = buf + 1;
        p = close + 2;
    } else {
        char *colon = strrchr(buf, ':');
        if (colon == NULL)
            return -1;
        *colon = '\0';
        h = buf;
        p = colon + 1;
    }
    char *end = NULL;
    long v = strtol(p, &end, 10);
    if (h[0] == '\0' || p[0] == '\0' || end == NULL || *end != '\0'
        || v <= 0 || v >= 65536)
        return -1;
    if (at_strlcpy(host, h, host_len) >= host_len) {
        host[0] = '\0';
        return -1;
    }
    *port = (int)v;
    return 0;
}

int net_relay_key_fingerprint(const char *pubkey_hex, char *out, size_t out_len)
{
    unsigned char raw[64];
    size_t raw_len = 0;
    unsigned char digest[crypto_hash_sha256_BYTES];
    if (pubkey_hex == NULL || out == NULL || out_len < AT_RELAY_FP_BYTES * 2 + 1
        || sodium_hex2bin(raw, sizeof(raw), pubkey_hex, strlen(pubkey_hex),
                          NULL, &raw_len, NULL) != 0 || raw_len == 0)
        return -1;
    crypto_hash_sha256(digest, raw, raw_len);
    sodium_bin2hex(out, out_len, digest, AT_RELAY_FP_BYTES);
    return 0;
}

static bool _is_hex_lower(const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return false;
    return s[n] == '\0';
}

int net_relay_parse_hint(const char *text, char *host, size_t host_len,
                         int *port, net_relay_pin_t *pin)
{
    if (pin != NULL)
        memset(pin, 0, sizeof(*pin));
    if (text == NULL)
        return -1;
    const char *s = text;
    size_t slen = strlen(AT_RELAY_SCHEME);
    if (strncmp(s, AT_RELAY_SCHEME, slen) == 0)
        s += slen;
    const char *at = strchr(s, '@');
    if (at != NULL) {
        char head[UUID_STR_LEN + AT_RELAY_FP_BYTES * 2 + 8];
        size_t hl = (size_t)(at - s);
        if (hl >= sizeof(head))
            return -1;
        memcpy(head, s, hl);
        head[hl] = '\0';
        for (char *q = head; *q; q++)
            if (*q >= 'A' && *q <= 'Z')
                *q = (char)(*q - 'A' + 'a');
        char *colon = strchr(head, ':');
        uuid_t u;
        if (colon == NULL)
            return -1;
        *colon = '\0';
        const char *fp = colon + 1;
        if (uuid_parse(head, u) != 0 || strlen(fp) != AT_RELAY_FP_BYTES * 2
            || !_is_hex_lower(fp, AT_RELAY_FP_BYTES * 2))
            return -1;
        if (pin != NULL) {
            pin->set = true;
            uuid_unparse_lower(u, pin->uuid);
            at_strlcpy(pin->fp, fp, sizeof(pin->fp));
        }
    }
    if (net_relay_parse_endpoint(text, host, host_len, port) != 0) {
        if (pin != NULL)
            memset(pin, 0, sizeof(*pin));
        return -1;
    }
    return 0;
}

int net_relay_hint_for_pinned(const char *host, int port,
                              const net_relay_pin_t *pin, char *out,
                              size_t out_len)
{
    if (host == NULL || out == NULL)
        return -1;
    char prefix[UUID_STR_LEN + AT_RELAY_FP_BYTES * 2 + 4] = "";
    if (pin != NULL && pin->set)
        snprintf(prefix, sizeof(prefix), "%s:%s@", pin->uuid, pin->fp);
    int n = strchr(host, ':') != NULL
          ? snprintf(out, out_len, "%s%s[%s]:%d", AT_RELAY_SCHEME, prefix, host, port)
          : snprintf(out, out_len, "%s%s%s:%d", AT_RELAY_SCHEME, prefix, host, port);
    return (n < 0 || (size_t)n >= out_len) ? -1 : 0;
}

size_t net_relay_own_list(net_relay_ep_t *out, size_t max)
{
    return net_relay_own_hints(out, NULL, max);
}

/* The seed list's files, stamped, so it is re-read (and a refusal re-logged)
 * only when one of them changes. Mirrors Python relay._seed_hints. */
#define AT_RELAY_SEED_STAMPS 4
typedef struct {
    char path[CFG_PATH_LEN + 64 + 256];   /* a roster dir plus a file name */
    bool exists;
    struct timespec mtime;
    off_t size;
} _seed_stamp_t;

static struct {
    pthread_mutex_t lock;
    bool valid;
    _seed_stamp_t stamp[AT_RELAY_SEED_STAMPS];
    char key[2 * crypto_sign_PUBLICKEYBYTES + 1];
    size_t n;
    net_relay_ep_t eps[AT_RELAY_MAX];
    net_relay_pin_t pins[AT_RELAY_MAX];
} g_seed_cache = { .lock = PTHREAD_MUTEX_INITIALIZER };

static void _seed_stamp(_seed_stamp_t *st)
{
    char data_dir[CFG_PATH_LEN + 1] = {0}, cfg_dir[CFG_PATH_LEN + 1] = {0};
    memset(st, 0, AT_RELAY_SEED_STAMPS * sizeof(*st));
    (void)get_data_dir(data_dir, sizeof(data_dir));
    (void)get_cfg_dir(cfg_dir, sizeof(cfg_dir));
    (void)net_relay_seeds_path(st[0].path, sizeof(st[0].path));
    snprintf(st[1].path, sizeof(st[1].path), "%s/%s", data_dir, AT_RELAY_SEEDS_LOCAL_FILE);
    snprintf(st[2].path, sizeof(st[2].path), "%s/%s", data_dir, AT_RELAY_SEEDS_SEEN_FILE);
    snprintf(st[3].path, sizeof(st[3].path), "%s/identity.cfg.json", cfg_dir);
    for (int i = 0; i < AT_RELAY_SEED_STAMPS; i++) {
        struct stat sb;
        if (st[i].path[0] != '\0' && stat(st[i].path, &sb) == 0) {
            st[i].exists = true;
            st[i].mtime = sb.st_mtim;
            st[i].size = sb.st_size;
        }
    }
}

static bool _seed_flag_on(void)
{
    const char *v = getenv("AT_FIRST_CONTACT");
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

/* With AT_USE_RELAY unset or empty and first contact on, the signed seed list
 * stands in: an operator's explicit choice always wins, and off means off. */
static size_t _seed_hints(net_relay_ep_t *out, net_relay_pin_t *pins, size_t max)
{
    if (!_seed_flag_on())
        return 0;
    _seed_stamp_t now[AT_RELAY_SEED_STAMPS];
    pthread_mutex_lock(&g_seed_cache.lock);
    _seed_stamp(now);
    const char *key = net_relay_seeds_release_key();
    if (!g_seed_cache.valid || strcmp(g_seed_cache.key, key) != 0
        || memcmp(now, g_seed_cache.stamp, sizeof(now)) != 0) {
        g_seed_cache.n = net_relay_seeds_load(NULL, g_seed_cache.eps, g_seed_cache.pins,
                                              AT_RELAY_MAX);
        /* Stamped AFTER the load: raising the seq floor rewrites a stamped file. */
        _seed_stamp(g_seed_cache.stamp);
        snprintf(g_seed_cache.key, sizeof(g_seed_cache.key), "%s", key);
        g_seed_cache.valid = true;
    }
    size_t n = g_seed_cache.n < max ? g_seed_cache.n : max;
    memcpy(out, g_seed_cache.eps, n * sizeof(*out));
    if (pins != NULL)
        memcpy(pins, g_seed_cache.pins, n * sizeof(*pins));
    pthread_mutex_unlock(&g_seed_cache.lock);
    return n;
}

/* The pinned communities' roster files, stamped as the seed list's are.
 * Mirrors Python relay._roster_hints. */
#define AT_RELAY_ROSTER_STAMPS (AT_RELAY_ROSTER_FILES_MAX + 4)
static struct {
    pthread_mutex_t lock;
    bool valid;
    _seed_stamp_t stamp[AT_RELAY_ROSTER_STAMPS];
    char issuers_env[AT_RELAY_ROSTER_ISSUERS_MAX * (AT_RELAY_ROSTER_KEY_HEX + 2) + 1];
    size_t n;
    net_relay_ep_t eps[AT_RELAY_MAX];
    net_relay_pin_t pins[AT_RELAY_MAX];
} g_roster_cache = { .lock = PTHREAD_MUTEX_INITIALIZER };

static void _roster_stamp(_seed_stamp_t *st)
{
    char data_dir[CFG_PATH_LEN + 1] = {0}, dir[CFG_PATH_LEN + 64] = {0};
    memset(st, 0, AT_RELAY_ROSTER_STAMPS * sizeof(*st));
    (void)get_data_dir(data_dir, sizeof(data_dir));
    (void)net_relay_rosters_dir(dir, sizeof(dir));
    snprintf(st[0].path, sizeof(st[0].path), "%s", dir);
    (void)net_relay_rosters_issuers_path(st[1].path, sizeof(st[1].path));
    snprintf(st[2].path, sizeof(st[2].path), "%s/%s", data_dir, AT_RELAY_ROSTERS_SEEN_FILE);
    /* Our own listings: a hub for one of their buckets is registered first. */
    snprintf(st[3].path, sizeof(st[3].path), "%s/%s", data_dir, AT_AREA_STATE_FILENAME);
    char (*names)[256] = calloc(AT_RELAY_ROSTER_FILES_MAX, sizeof(*names));
    size_t nf = names != NULL ? net_relay_rosters_files(names, AT_RELAY_ROSTER_FILES_MAX) : 0;
    for (size_t i = 0; i < nf; i++)
        snprintf(st[4 + i].path, sizeof(st[4 + i].path), "%s/%s", dir, names[i]);
    free(names);
    for (int i = 0; i < AT_RELAY_ROSTER_STAMPS; i++) {
        struct stat sb;
        if (st[i].path[0] != '\0' && stat(st[i].path, &sb) == 0) {
            st[i].exists = true;
            st[i].mtime = sb.st_mtim;
            st[i].size = sb.st_size;
        }
    }
}

/* With AT_USE_RELAY unset or empty and first contact on, the relays of the
 * communities this node pinned stand in ahead of the seed list. */
static size_t _roster_hints(net_relay_ep_t *out, net_relay_pin_t *pins, size_t max)
{
    if (!_seed_flag_on())
        return 0;
    _seed_stamp_t *now = calloc(AT_RELAY_ROSTER_STAMPS, sizeof(*now));
    if (now == NULL)
        return 0;
    const char *env = getenv(AT_RELAY_ROSTER_ISSUERS_ENV);
    char env_now[sizeof(g_roster_cache.issuers_env)];
    snprintf(env_now, sizeof(env_now), "%s", env != NULL ? env : "");
    pthread_mutex_lock(&g_roster_cache.lock);
    _roster_stamp(now);
    if (!g_roster_cache.valid || strcmp(g_roster_cache.issuers_env, env_now) != 0
        || memcmp(now, g_roster_cache.stamp, AT_RELAY_ROSTER_STAMPS * sizeof(*now)) != 0) {
        g_roster_cache.n = net_relay_rosters_load(g_roster_cache.eps, g_roster_cache.pins,
                                                  AT_RELAY_MAX);
        /* Stamped AFTER the load: raising a seq floor rewrites a stamped file. */
        _roster_stamp(g_roster_cache.stamp);
        snprintf(g_roster_cache.issuers_env, sizeof(g_roster_cache.issuers_env), "%s", env_now);
        g_roster_cache.valid = true;
    }
    size_t n = g_roster_cache.n < max ? g_roster_cache.n : max;
    memcpy(out, g_roster_cache.eps, n * sizeof(*out));
    if (pins != NULL)
        memcpy(pins, g_roster_cache.pins, n * sizeof(*pins));
    pthread_mutex_unlock(&g_roster_cache.lock);
    free(now);
    return n;
}

/* Rosters first, then the seed entries they lack, one per endpoint. */
static size_t _community_hints(net_relay_ep_t *out, net_relay_pin_t *pins, size_t max)
{
    size_t n = _roster_hints(out, pins, max);
    net_relay_ep_t seeds[AT_RELAY_MAX];
    net_relay_pin_t seed_pins[AT_RELAY_MAX];
    size_t ns = _seed_hints(seeds, seed_pins, AT_RELAY_MAX);
    for (size_t i = 0; i < ns && n < max; i++) {
        bool dup = false;
        for (size_t k = 0; k < n && !dup; k++)
            dup = out[k].port == seeds[i].port && strcmp(out[k].host, seeds[i].host) == 0;
        if (dup)
            continue;
        if (pins != NULL)
            pins[n] = seed_pins[i];
        out[n++] = seeds[i];
    }
    return n;
}

size_t net_relay_own_hints(net_relay_ep_t *out, net_relay_pin_t *pins, size_t max)
{
    const char *env = getenv("AT_USE_RELAY");
    if (out == NULL || max == 0)
        return 0;
    if (max > AT_RELAY_MAX)
        max = AT_RELAY_MAX;
    bool blank = true;
    for (const char *c = env; c != NULL && *c != '\0' && blank; c++)
        blank = *c == ' ' || *c == '\t' || *c == '\n' || *c == '\r';
    if (blank)
        return _community_hints(out, pins, max);
    size_t n = 0;
    const char *p = env;
    while (*p != '\0' && n < max) {
        const char *comma = strchr(p, ',');
        size_t len = comma != NULL ? (size_t)(comma - p) : strlen(p);
        char item[256];
        if (len < sizeof(item)) {
            memcpy(item, p, len);
            item[len] = '\0';
            /* Trim, as Python's parse_endpoint strips. */
            char *s = item;
            while (*s == ' ' || *s == '\t')
                s++;
            size_t sl = strlen(s);
            while (sl > 0 && (s[sl - 1] == ' ' || s[sl - 1] == '\t'))
                s[--sl] = '\0';
            net_relay_ep_t ep;
            net_relay_pin_t pin;
            if (s[0] != '\0'
                && net_relay_parse_hint(s, ep.host, sizeof(ep.host), &ep.port,
                                        &pin) == 0) {
                bool dup = false;
                for (size_t i = 0; i < n && !dup; i++)
                    dup = out[i].port == ep.port && strcmp(out[i].host, ep.host) == 0;
                if (!dup) {
                    if (pins != NULL)
                        pins[n] = pin;
                    out[n++] = ep;
                }
            }
        }
        if (comma == NULL)
            break;
        p = comma + 1;
    }
    return n;
}

int net_relay_own(char *host, size_t host_len, int *port)
{
    net_relay_ep_t eps[AT_RELAY_MAX];
    if (host != NULL && host_len > 0)
        host[0] = '\0';
    if (host == NULL || port == NULL || net_relay_own_list(eps, AT_RELAY_MAX) == 0
        || at_strlcpy(host, eps[0].host, host_len) >= host_len)
        return -1;
    *port = eps[0].port;
    return 0;
}

int net_relay_hint_for(const char *host, int port, char *out, size_t out_len)
{
    return net_relay_hint_for_pinned(host, port, NULL, out, out_len);
}

/* ---- framing ------------------------------------------------------------ */

static int _send_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    while (len > 0) {
        ssize_t w = at_send_eintr(fd, p, len, MSG_NOSIGNAL);
        if (w <= 0)
            return -1;
        p += w;
        len -= (size_t)w;
    }
    return 0;
}

static int _recv_all(int fd, void *buf, size_t len)
{
    uint8_t *p = buf;
    while (len > 0) {
        ssize_t r = at_recv_eintr(fd, p, len, 0);
        if (r <= 0)
            return -1;
        p += r;
        len -= (size_t)r;
    }
    return 0;
}

int net_relay_send_json(int fd, const char *json_text)
{
    size_t len = strlen(json_text);
    if (len > AT_RELAY_MAX_FRAME)
        return -1;
    uint8_t hdr[4] = { (uint8_t)(len >> 24), (uint8_t)(len >> 16),
                       (uint8_t)(len >> 8), (uint8_t)len };
    if (_send_all(fd, hdr, 4) != 0)
        return -1;
    return _send_all(fd, json_text, len);
}

char *net_relay_recv_json(int fd)
{
    uint8_t hdr[4];
    if (_recv_all(fd, hdr, 4) != 0)
        return NULL;
    uint32_t len = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16)
                 | ((uint32_t)hdr[2] << 8) | hdr[3];
    if (len > AT_RELAY_MAX_FRAME)
        return NULL;
    char *out = malloc((size_t)len + 1);
    if (out == NULL)
        return NULL;
    if (_recv_all(fd, out, len) != 0) {
        free(out);
        return NULL;
    }
    out[len] = '\0';
    return out;
}

static int _send_obj(int fd, json_t *obj)
{
    char *text = json_dumps(obj, JSON_COMPACT);
    json_decref(obj);
    if (text == NULL)
        return -1;
    int rc = net_relay_send_json(fd, text);
    free(text);
    return rc;
}

static json_t *_recv_obj(int fd)
{
    char *text = net_relay_recv_json(fd);
    if (text == NULL)
        return NULL;
    json_error_t err;
    json_t *obj = json_loads(text, 0, &err);
    free(text);
    if (obj != NULL && !json_is_object(obj)) {
        json_decref(obj);
        return NULL;
    }
    return obj;
}

static int _registration_text(const char *nonce, const char *uuid, char *out,
                              size_t out_len)
{
    int n = snprintf(out, out_len, "%s|%s|%s", AT_RELAY_DOMAIN, nonce, uuid);
    return (n < 0 || (size_t)n >= out_len) ? -1 : 0;
}

/* What a relay signs to prove itself: bound to the client's fresh nonce (so
 * unreplayable) and to both uuids. "relay|" keeps it from ever verifying as a
 * client's registration text. Mirrors Python relay.relay_proof_text. */
static int _relay_proof_text(const char *client_nonce, const char *nonce,
                             const char *relay_uuid, const char *client_uuid,
                             char *out, size_t out_len)
{
    int n = snprintf(out, out_len, "%s|relay|%s|%s|%s|%s", AT_RELAY_DOMAIN,
                     client_nonce, nonce, relay_uuid, client_uuid);
    return (n < 0 || (size_t)n >= out_len) ? -1 : 0;
}

static void _lower(char *s)
{
    for (; s != NULL && *s != '\0'; s++)
        if (*s >= 'A' && *s <= 'Z')
            *s = (char)(*s - 'A' + 'a');
}

/* ---- the relay ---------------------------------------------------------- */

#define AT_RELAY_MAX_CLIENTS 256

typedef struct {
    char uuid[UUID_STR_LEN + 1];
    int fd;
    pthread_mutex_t *send_lock;     /* heap; owned by the connection */
} relay_entry_t;

struct net_relay_server_s {
    int fd;
    int port;
    bool stopped;
    logger_t *logger;
    pthread_t accept_thread;
    pthread_mutex_t lock;
    relay_entry_t entries[AT_RELAY_MAX_CLIENTS];
    size_t count;
    const identity_t *self;         /* proves the relay; NULL = no proof */
    net_relay_distrust_fn distrusted;
    void *distrust_arg;
    /* Reachability records filed here (contacts/reach.h), by record id. */
    struct relay_record_s *records;
    size_t n_records;
    /* A directory registry (net_registry.h), or NULL: dir_* ops refused. */
    net_registry_t *registry;
    /* An area hub (net_hub.h), or NULL: hub_* ops refused. */
    net_hub_t *hub;
};

typedef struct relay_record_s {
    char id[AT_RELAY_FP_BYTES * 2 + 1];
    at_reach_record_t rec;
} relay_record_t;

typedef struct {
    net_relay_server_t *srv;
    int fd;
} relay_conn_arg_t;

static void _server_write(net_relay_server_t *srv, int fd, json_t *obj)
{
    pthread_mutex_t *lk = NULL;
    pthread_mutex_lock(&srv->lock);
    for (size_t i = 0; i < srv->count; i++)
        if (srv->entries[i].fd == fd)
            lk = srv->entries[i].send_lock;
    pthread_mutex_unlock(&srv->lock);
    if (lk != NULL)
        pthread_mutex_lock(lk);
    (void)_send_obj(fd, obj);
    if (lk != NULL)
        pthread_mutex_unlock(lk);
}

/* Run the challenge; the proven uuid into @p out, or -1. */
static int _server_register(net_relay_server_t *srv, int fd, char *out,
                            size_t out_len, char *pub_out, size_t pub_len)
{
    json_t *hello = _recv_obj(fd);
    if (hello == NULL)
        return -1;      /* unreadable or oversized: no reply, as Python */
    const char *op = json_string_value(json_object_get(hello, "op"));
    const char *uuid = json_string_value(json_object_get(hello, "uuid"));
    const char *pub = json_string_value(json_object_get(hello, "pubkey"));
    const char *cn = json_string_value(json_object_get(hello, "nonce"));
    char client_nonce[65] = "";
    if (cn != NULL && strlen(cn) < sizeof(client_nonce))
        at_strlcpy(client_nonce, cn, sizeof(client_nonce));
    char pub_l[crypto_sign_PUBLICKEYBYTES * 2 + 1] = "";
    if (pub != NULL && strlen(pub) < sizeof(pub_l)) {
        at_strlcpy(pub_l, pub, sizeof(pub_l));
        _lower(pub_l);
    }
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    size_t pk_len = 0;
    uuid_t parsed;
    if (op == NULL || strcmp(op, "hello") != 0 || uuid == NULL || pub == NULL
        || uuid_parse(uuid, parsed) != 0
        || sodium_hex2bin(pk, sizeof(pk), pub, strlen(pub), NULL, &pk_len, NULL) != 0
        || pk_len != sizeof(pk)) {
        json_decref(hello);
        json_t *e = json_object();
        json_object_set_new(e, "op", json_string("error"));
        json_object_set_new(e, "reason", json_string("expected hello"));
        (void)_send_obj(fd, e);
        return -1;
    }
    char uuid_l[UUID_STR_LEN + 1];
    uuid_unparse_lower(parsed, uuid_l);
    json_decref(hello);

    unsigned char raw[16];
    char nonce[33];
    randombytes_buf(raw, sizeof(raw));
    sodium_bin2hex(nonce, sizeof(nonce), raw, sizeof(raw));
    json_t *ch = json_object();
    json_object_set_new(ch, "op", json_string("challenge"));
    json_object_set_new(ch, "nonce", json_string(nonce));
    const identity_t *self = srv->self;
    if (self != NULL && client_nonce[0] != '\0') {
        char me[UUID_STR_LEN + 1], proof[256];
        unsigned char psig[crypto_sign_BYTES];
        char psig_hex[crypto_sign_BYTES * 2 + 1];
        uuid_unparse_lower(self->uuid, me);
        if (_relay_proof_text(client_nonce, nonce, me, uuid_l, proof,
                              sizeof(proof)) == 0
            && crypto_sign_detached(psig, NULL, (const unsigned char *)proof,
                                    strlen(proof), self->signature.private) == 0) {
            sodium_bin2hex(psig_hex, sizeof(psig_hex), psig, sizeof(psig));
            json_object_set_new(ch, "relay_uuid", json_string(me));
            json_object_set_new(ch, "relay_pubkey",
                                json_string((const char *)self->signature.public_hex));
            json_object_set_new(ch, "relay_sig", json_string(psig_hex));
        }
    }
    if (_send_obj(fd, ch) != 0)
        return -1;

    json_t *reg = _recv_obj(fd);
    const char *sig_hex = json_string_value(json_object_get(reg, "sig"));
    unsigned char sig[crypto_sign_BYTES];
    size_t sig_len = 0;
    char text[160];
    bool ok = sig_hex != NULL
        && sodium_hex2bin(sig, sizeof(sig), sig_hex, strlen(sig_hex), NULL,
                          &sig_len, NULL) == 0
        && sig_len == sizeof(sig)
        && _registration_text(nonce, uuid_l, text, sizeof(text)) == 0
        && crypto_sign_verify_detached(sig, (const unsigned char *)text,
                                       strlen(text), pk) == 0;
    json_decref(reg);
    if (!ok) {
        log_warn(srv->logger, "Relay: registration for %.8s refused: bad "
                 "signature\n", uuid_l);
        json_t *e = json_object();
        json_object_set_new(e, "op", json_string("error"));
        json_object_set_new(e, "reason", json_string("bad signature"));
        (void)_send_obj(fd, e);
        return -1;
    }
    if (srv->distrusted != NULL
        && srv->distrusted(srv->distrust_arg, uuid_l, pub_l)) {
        log_warn(srv->logger, "Relay: registration for %.8s refused: "
                 "distrusted\n", uuid_l);
        json_t *e = json_object();
        json_object_set_new(e, "op", json_string("error"));
        json_object_set_new(e, "reason", json_string("distrusted"));
        (void)_send_obj(fd, e);
        return -1;
    }
    at_strlcpy(out, uuid_l, out_len);
    at_strlcpy(pub_out, pub_l, pub_len);
    return 0;
}

/* Store @p uuid's own record (@p wire) and answer. Only the holder files its
 * own record: the registrant proved @p pub, and the record must be signed by
 * that key, for that uuid. Mirrors Python RelayServer._publish. */
static json_t *_server_publish(net_relay_server_t *srv, const char *uuid,
                               const char *pub, const json_t *wire)
{
    json_t *ans = json_object();
    at_reach_record_t rec;
    const char *why = NULL;
    if (at_reach_from_wire(wire, &rec) != AT_REACH_OK) {
        why = "malformed reachability record";
    } else {
        int v = at_reach_verify(&rec, (double)time(NULL));
        const char *ru = at_reach_uuid(&rec), *rk = at_reach_key(&rec);
        if (v == AT_REACH_BAD_SIG)
            why = "signature does not match the record key";
        else if (v == AT_REACH_EXPIRED)
            why = "record has expired";
        else if (v != AT_REACH_OK || ru == NULL || rk == NULL
                 || strcasecmp(ru, uuid) != 0 || strcasecmp(rk, pub) != 0)
            why = "not your record";
    }
    char id[AT_RELAY_FP_BYTES * 2 + 1];
    if (why == NULL && at_reach_record_id(&rec, id, sizeof(id)) != 0)
        why = "record key is not hex";
    if (why != NULL) {
        at_reach_free(&rec);
        json_object_set_new(ans, "op", json_string("refused"));
        json_object_set_new(ans, "reason", json_string(why));
        return ans;
    }
    int64_t seq = at_reach_seq(&rec);
    pthread_mutex_lock(&srv->lock);
    relay_record_t *slot = NULL;
    for (size_t i = 0; i < srv->n_records && slot == NULL; i++)
        if (strcmp(srv->records[i].id, id) == 0)
            slot = &srv->records[i];
    char reason[96] = "";
    bool stored = false;
    if (slot != NULL) {
        int64_t held = at_reach_seq(&slot->rec);
        if (seq == held && strcmp(slot->rec.body_str, rec.body_str) == 0) {
            stored = true;          /* the same record again: a refile */
            at_reach_free(&rec);
        } else if (seq <= held) {
            snprintf(reason, sizeof(reason), "stale (seq %lld <= %lld)",
                     (long long)seq, (long long)held);
            at_reach_free(&rec);
        } else {
            at_reach_free(&slot->rec);
            slot->rec = rec;
            stored = true;
        }
    } else {
        if (srv->records == NULL)
            srv->records = calloc(AT_RELAY_MAX_RECORDS, sizeof(*srv->records));
        if (srv->records != NULL && srv->n_records == AT_RELAY_MAX_RECORDS) {
            /* Full: drop the soonest to expire (an expired one first). */
            size_t victim = 0;
            for (size_t i = 1; i < srv->n_records; i++) {
                long e = at_reach_expiry(&srv->records[i].rec);
                long v = at_reach_expiry(&srv->records[victim].rec);
                if (e != 0 && (v == 0 || e < v))
                    victim = i;
            }
            at_reach_free(&srv->records[victim].rec);
            srv->records[victim] = srv->records[--srv->n_records];
        }
        if (srv->records != NULL) {
            relay_record_t *r = &srv->records[srv->n_records++];
            at_strlcpy(r->id, id, sizeof(r->id));
            r->rec = rec;
            stored = true;
        } else {
            at_reach_free(&rec);
            snprintf(reason, sizeof(reason), "out of memory");
        }
    }
    pthread_mutex_unlock(&srv->lock);
    if (stored) {
        json_object_set_new(ans, "op", json_string("published"));
        json_object_set_new(ans, "seq", json_integer((json_int_t)seq));
    } else {
        json_object_set_new(ans, "op", json_string("refused"));
        json_object_set_new(ans, "reason", json_string(reason));
    }
    return ans;
}

static json_t *_server_lookup(net_relay_server_t *srv, const char *rid)
{
    char id[AT_RELAY_FP_BYTES * 2 + 1] = "";
    if (rid != NULL)
        at_strlcpy(id, rid, sizeof(id));
    _lower(id);
    json_t *ans = json_object();
    json_object_set_new(ans, "op", json_string("record"));
    json_object_set_new(ans, "id", json_string(id));
    json_t *wire = NULL;
    double now = (double)time(NULL);
    pthread_mutex_lock(&srv->lock);
    for (size_t i = 0; i < srv->n_records && wire == NULL; i++) {
        if (strcmp(srv->records[i].id, id) != 0)
            continue;
        long exp = at_reach_expiry(&srv->records[i].rec);
        if (exp == 0 || now < (double)exp)
            wire = at_reach_to_wire(&srv->records[i].rec);
    }
    pthread_mutex_unlock(&srv->lock);
    json_object_set_new(ans, "record", wire != NULL ? wire : json_null());
    return ans;
}

static void _server_drop(net_relay_server_t *srv, int fd)
{
    pthread_mutex_t *lk = NULL;
    pthread_mutex_lock(&srv->lock);
    for (size_t i = 0; i < srv->count; i++) {
        if (srv->entries[i].fd != fd)
            continue;
        lk = srv->entries[i].send_lock;
        srv->entries[i] = srv->entries[--srv->count];
        break;
    }
    pthread_mutex_unlock(&srv->lock);
    if (lk != NULL) {
        pthread_mutex_destroy(lk);
        free(lk);
    }
}

/* A registry op from registrant @p uuid. The reply (new reference). Mirrors
 * Python RelayServer._directory. */
static json_t *_server_directory(net_relay_server_t *srv, const char *uuid,
                                 const char *pub, const char *op, const json_t *req)
{
    const char *h = json_string_value(json_object_get(req, "handle"));
    const char *handle = h != NULL ? h : "";
    pthread_mutex_lock(&srv->lock);
    net_registry_t *reg = srv->registry;
    pthread_mutex_unlock(&srv->lock);
    const char *reason = NULL;
    if (reg == NULL)
        reason = "not_registry";
    else if (strcmp(op, "dir_publish") == 0)
        return net_registry_publish(reg, uuid, pub, json_object_get(req, "entry"));
    else if (strcmp(op, "dir_withdraw") == 0)
        return net_registry_withdraw(reg, uuid, pub, handle);
    else if (strcmp(op, "dir_lookup") == 0)
        return net_registry_lookup(reg, uuid, handle);
    else
        reason = "unknown_op";
    return json_pack("{s:s, s:s, s:s}", "op", "dir_refused", "handle", handle,
                     "reason", reason);
}

/* A hub op from registrant @p uuid. The reply (new reference). Mirrors
 * Python RelayServer._area_hub. */
static json_t *_server_hub(net_relay_server_t *srv, const char *uuid, const char *pub,
                           const char *op, const json_t *req)
{
    const char *a = json_string_value(json_object_get(req, "area"));
    const char *area = a != NULL ? a : "";
    pthread_mutex_lock(&srv->lock);
    net_hub_t *hub = srv->hub;
    pthread_mutex_unlock(&srv->lock);
    const char *reason = NULL;
    if (hub == NULL)
        reason = "not_hub";
    else if (strcmp(op, "hub_publish") == 0)
        return net_hub_publish(hub, uuid, pub, json_object_get(req, "card"));
    else if (strcmp(op, "hub_withdraw") == 0)
        return net_hub_withdraw(hub, uuid, pub, area);
    else if (strcmp(op, "hub_lookup") == 0)
        return net_hub_lookup(hub, uuid, area);
    else
        reason = "unknown_op";
    return json_pack("{s:s, s:s, s:s}", "op", "hub_refused", "area", area, "reason", reason);
}

static void *_server_conn(void *arg)
{
    relay_conn_arg_t a = *(relay_conn_arg_t *)arg;
    free(arg);
    net_relay_server_t *srv = a.srv;
    int fd = a.fd;
    char uuid[UUID_STR_LEN + 1] = {0};
    char pub[crypto_sign_PUBLICKEYBYTES * 2 + 1] = {0};

    /* Bounded while registering; blocking once registered, since a registered
     * client may say nothing for as long as it likes. */
    (void)at_set_rcvtimeo(fd, AT_RELAY_HANDSHAKE_TIMEOUT_MS, srv->logger);
    if (_server_register(srv, fd, uuid, sizeof(uuid), pub, sizeof(pub)) != 0) {
        close(fd);
        return NULL;
    }
    (void)at_set_rcvtimeo(fd, 0, srv->logger);

    int old_fd = -1;
    pthread_mutex_lock(&srv->lock);
    size_t i;
    for (i = 0; i < srv->count; i++)
        if (strcmp(srv->entries[i].uuid, uuid) == 0)
            break;
    if (i < srv->count) {
        old_fd = srv->entries[i].fd;        /* a reconnect: newer wins */
    } else if (srv->count < AT_RELAY_MAX_CLIENTS) {
        i = srv->count++;
        srv->entries[i].send_lock = NULL;
    } else {
        pthread_mutex_unlock(&srv->lock);
        close(fd);
        return NULL;
    }
    at_strlcpy(srv->entries[i].uuid, uuid, sizeof(srv->entries[i].uuid));
    srv->entries[i].fd = fd;
    if (srv->entries[i].send_lock == NULL) {
        srv->entries[i].send_lock = malloc(sizeof(pthread_mutex_t));
        if (srv->entries[i].send_lock != NULL)
            pthread_mutex_init(srv->entries[i].send_lock, NULL);
    }
    pthread_mutex_unlock(&srv->lock);
    if (old_fd >= 0)
        shutdown(old_fd, SHUT_RDWR);   /* its thread sees EOF and exits */

    json_t *ok = json_object();
    json_object_set_new(ok, "op", json_string("registered"));
    _server_write(srv, fd, ok);
    log_info(srv->logger, "Relay: %.8s registered\n", uuid);

    for (;;) {
        json_t *req = _recv_obj(fd);
        if (req == NULL)
            break;
        const char *op = json_string_value(json_object_get(req, "op"));
        if (op != NULL && strcmp(op, "publish") == 0) {
            _server_write(srv, fd, _server_publish(srv, uuid, pub,
                                                   json_object_get(req, "record")));
            json_decref(req);
            continue;
        }
        if (op != NULL && strcmp(op, "lookup") == 0) {
            _server_write(srv, fd, _server_lookup(
                srv, json_string_value(json_object_get(req, "id"))));
            json_decref(req);
            continue;
        }
        if (op != NULL && strncmp(op, "dir_", 4) == 0) {
            _server_write(srv, fd, _server_directory(srv, uuid, pub, op, req));
            json_decref(req);
            continue;
        }
        if (op != NULL && strncmp(op, "hub_", 4) == 0) {
            _server_write(srv, fd, _server_hub(srv, uuid, pub, op, req));
            json_decref(req);
            continue;
        }
        const char *to = json_string_value(json_object_get(req, "to"));
        json_t *frame = json_object_get(req, "frame");
        if (op == NULL || strcmp(op, "send") != 0 || to == NULL
            || !json_is_string(frame)) {
            json_decref(req);
            continue;
        }
        char to_l[UUID_STR_LEN + 1];
        at_strlcpy(to_l, to, sizeof(to_l));
        _lower(to_l);
        int target = -1;
        pthread_mutex_lock(&srv->lock);
        for (size_t k = 0; k < srv->count; k++)
            if (strcmp(srv->entries[k].uuid, to_l) == 0)
                target = srv->entries[k].fd;
        pthread_mutex_unlock(&srv->lock);
        if (target < 0) {
            json_t *u = json_object();
            json_object_set_new(u, "op", json_string("unreachable"));
            json_object_set_new(u, "to", json_string(to_l));
            _server_write(srv, fd, u);
        } else {
            /* `from` is OURS: the sender's proven registration, never
             * anything the frame claims. */
            json_t *d = json_object();
            json_object_set_new(d, "op", json_string("deliver"));
            json_object_set_new(d, "from", json_string(uuid));
            json_object_set(d, "frame", frame);
            _server_write(srv, target, d);
        }
        json_decref(req);
    }
    /* Only drop the entry if it is still ours (a reconnect replaced the fd). */
    pthread_mutex_lock(&srv->lock);
    bool mine = false;
    for (size_t k = 0; k < srv->count; k++)
        if (srv->entries[k].fd == fd)
            mine = true;
    pthread_mutex_unlock(&srv->lock);
    if (mine)
        _server_drop(srv, fd);
    close(fd);
    return NULL;
}

static void *_server_accept(void *arg)
{
    net_relay_server_t *srv = arg;
    while (!srv->stopped) {
        struct pollfd pfd = { .fd = srv->fd, .events = POLLIN };
        int pr = at_poll_eintr(&pfd, 1, 200);
        if (pr <= 0)
            continue;
        int fd = accept(srv->fd, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == ECONNABORTED)
                continue;
            if (srv->stopped)
                break;
            continue;
        }
        relay_conn_arg_t *a = malloc(sizeof(*a));
        pthread_t t;
        if (a == NULL) {
            close(fd);
            continue;
        }
        a->srv = srv;
        a->fd = fd;
        if (pthread_create(&t, NULL, _server_conn, a) != 0) {
            free(a);
            close(fd);
            continue;
        }
        pthread_detach(t);
    }
    return NULL;
}

net_relay_server_t *net_relay_server_start(const char *host, int port,
                                           logger_t *logger)
{
    if (sodium_init() < 0)
        return NULL;
    net_relay_server_t *srv = calloc(1, sizeof(*srv));
    if (srv == NULL)
        return NULL;
    srv->logger = logger;
    pthread_mutex_init(&srv->lock, NULL);
    struct addrinfo hints = { .ai_socktype = SOCK_STREAM, .ai_flags = AI_PASSIVE
                                                                   | AI_NUMERICHOST };
    struct addrinfo *res = NULL;
    char port_s[8];
    snprintf(port_s, sizeof(port_s), "%d", port);
    if (getaddrinfo(host, port_s, &hints, &res) != 0 || res == NULL) {
        free(srv);
        return NULL;
    }
    srv->fd = socket(res->ai_family, SOCK_STREAM, 0);
    int one = 1;
    if (srv->fd < 0
        || setsockopt(srv->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0
        || bind(srv->fd, res->ai_addr, res->ai_addrlen) != 0
        || listen(srv->fd, 64) != 0) {
        if (srv->fd >= 0)
            close(srv->fd);
        freeaddrinfo(res);
        free(srv);
        return NULL;
    }
    freeaddrinfo(res);
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    getsockname(srv->fd, (struct sockaddr *)&ss, &sl);
    srv->port = ntohs(ss.ss_family == AF_INET6
                      ? ((struct sockaddr_in6 *)&ss)->sin6_port
                      : ((struct sockaddr_in *)&ss)->sin_port);
    if (pthread_create(&srv->accept_thread, NULL, _server_accept, srv) != 0) {
        close(srv->fd);
        free(srv);
        return NULL;
    }
    log_info(logger, "Relay: serving on %s:%d\n", host, srv->port);
    return srv;
}

void net_relay_server_set_identity(net_relay_server_t *srv, const identity_t *self)
{
    if (srv == NULL)
        return;
    pthread_mutex_lock(&srv->lock);
    srv->self = self;
    pthread_mutex_unlock(&srv->lock);
}

void net_relay_server_set_registry(net_relay_server_t *srv, net_registry_t *reg)
{
    if (srv == NULL)
        return;
    pthread_mutex_lock(&srv->lock);
    srv->registry = reg;
    pthread_mutex_unlock(&srv->lock);
}

void net_relay_server_set_hub(net_relay_server_t *srv, net_hub_t *hub)
{
    if (srv == NULL)
        return;
    pthread_mutex_lock(&srv->lock);
    srv->hub = hub;
    pthread_mutex_unlock(&srv->lock);
}

void net_relay_server_set_distrust(net_relay_server_t *srv,
                                   net_relay_distrust_fn fn, void *arg)
{
    if (srv == NULL)
        return;
    pthread_mutex_lock(&srv->lock);
    srv->distrusted = fn;
    srv->distrust_arg = arg;
    pthread_mutex_unlock(&srv->lock);
}

void net_relay_server_evict(net_relay_server_t *srv, const char *uuid)
{
    if (srv == NULL || uuid == NULL)
        return;
    int fd = -1;
    pthread_mutex_lock(&srv->lock);
    for (size_t i = 0; i < srv->count && fd < 0; i++)
        if (strcasecmp(srv->entries[i].uuid, uuid) == 0)
            fd = srv->entries[i].fd;
    pthread_mutex_unlock(&srv->lock);
    if (fd >= 0) {
        /* The connection's own thread, blocked in recv, wakes on the shutdown
         * and drops the entry and the fd itself. */
        log_info(srv->logger, "Relay: evicted %.8s (distrusted)\n", uuid);
        shutdown(fd, SHUT_RDWR);
    }
}

int net_relay_server_port(const net_relay_server_t *srv)
{
    return srv != NULL ? srv->port : -1;
}

bool net_relay_server_has(net_relay_server_t *srv, const char *uuid)
{
    if (srv == NULL || uuid == NULL)
        return false;
    bool found = false;
    pthread_mutex_lock(&srv->lock);
    for (size_t i = 0; i < srv->count && !found; i++)
        found = strcasecmp(srv->entries[i].uuid, uuid) == 0;
    pthread_mutex_unlock(&srv->lock);
    return found;
}

void net_relay_server_stop(net_relay_server_t *srv)
{
    if (srv != NULL) {
        pthread_mutex_lock(&srv->lock);
        for (size_t i = 0; i < srv->n_records; i++)
            at_reach_free(&srv->records[i].rec);
        free(srv->records);
        srv->records = NULL;
        srv->n_records = 0;
        pthread_mutex_unlock(&srv->lock);
    }
    if (srv == NULL)
        return;
    srv->stopped = true;
    pthread_join(srv->accept_thread, NULL);
    close(srv->fd);
    pthread_mutex_lock(&srv->lock);
    for (size_t i = 0; i < srv->count; i++)
        shutdown(srv->entries[i].fd, SHUT_RDWR);
    pthread_mutex_unlock(&srv->lock);
    /* Connection threads are detached and clean up after themselves; the
     * server struct is deliberately leaked so a late one never touches freed
     * memory. A relay stops once, at shutdown. */
}

/* ---- a node's link to a relay ------------------------------------------- */

#define AT_RELAY_UNREACHABLE_MAX 32

struct net_relay_client_s {
    char host[AT_RELAY_HOST_LEN];
    int port;
    const identity_t *self;
    net_relay_deliver_fn deliver;
    void *arg;
    logger_t *logger;
    pthread_mutex_t lock;
    int fd;                         /* -1 when not connected */
    net_relay_unreachable_fn on_unreachable;
    void *unreachable_arg;
    net_relay_pin_t pin;            /* who must answer; unset = anyone */
    net_relay_distrust_fn distrusted;
    void *distrust_arg;
    net_relay_record_fn on_record;
    void *record_arg;
    net_relay_dir_fn on_dir;
    void *dir_arg;
    net_relay_hub_fn on_hub;
    void *hub_arg;
    net_relay_pin_t proven;         /* who answered at the last connect */
    char proven_key[crypto_sign_PUBLICKEYBYTES * 2 + 1];
    char refused[160];
    char unreachable[AT_RELAY_UNREACHABLE_MAX][UUID_STR_LEN + 1];
    size_t n_unreachable;
};

net_relay_client_t *net_relay_client_new(const char *host, int port,
                                         const identity_t *self,
                                         net_relay_deliver_fn deliver, void *arg,
                                         logger_t *logger)
{
    if (host == NULL || self == NULL || sodium_init() < 0)
        return NULL;
    net_relay_client_t *c = calloc(1, sizeof(*c));
    if (c == NULL)
        return NULL;
    if (at_strlcpy(c->host, host, sizeof(c->host)) >= sizeof(c->host)) {
        free(c);
        return NULL;
    }
    c->port = port;
    c->self = self;
    c->deliver = deliver;
    c->arg = arg;
    c->logger = logger;
    c->fd = -1;
    pthread_mutex_init(&c->lock, NULL);
    return c;
}

void net_relay_client_on_unreachable(net_relay_client_t *c,
                                     net_relay_unreachable_fn fn, void *arg)
{
    if (c == NULL)
        return;
    pthread_mutex_lock(&c->lock);
    c->on_unreachable = fn;
    c->unreachable_arg = arg;
    pthread_mutex_unlock(&c->lock);
}

void net_relay_client_set_pin(net_relay_client_t *c, const net_relay_pin_t *pin)
{
    if (c == NULL)
        return;
    pthread_mutex_lock(&c->lock);
    if (pin != NULL && pin->set)
        c->pin = *pin;
    else
        memset(&c->pin, 0, sizeof(c->pin));
    pthread_mutex_unlock(&c->lock);
}

void net_relay_client_set_distrust(net_relay_client_t *c,
                                   net_relay_distrust_fn fn, void *arg)
{
    if (c == NULL)
        return;
    pthread_mutex_lock(&c->lock);
    c->distrusted = fn;
    c->distrust_arg = arg;
    pthread_mutex_unlock(&c->lock);
}

bool net_relay_client_proven(net_relay_client_t *c, net_relay_pin_t *out,
                             char *key_hex, size_t key_len)
{
    if (c == NULL)
        return false;
    pthread_mutex_lock(&c->lock);
    bool set = c->proven.set;
    if (out != NULL)
        *out = c->proven;
    if (key_hex != NULL && key_len > 0)
        at_strlcpy(key_hex, c->proven_key, key_len);
    pthread_mutex_unlock(&c->lock);
    return set;
}

void net_relay_client_refused(net_relay_client_t *c, char *out, size_t out_len)
{
    if (out == NULL || out_len == 0)
        return;
    out[0] = '\0';
    if (c == NULL)
        return;
    pthread_mutex_lock(&c->lock);
    at_strlcpy(out, c->refused, out_len);
    pthread_mutex_unlock(&c->lock);
}

void net_relay_client_on_record(net_relay_client_t *c, net_relay_record_fn fn,
                                void *arg)
{
    if (c == NULL)
        return;
    pthread_mutex_lock(&c->lock);
    c->on_record = fn;
    c->record_arg = arg;
    pthread_mutex_unlock(&c->lock);
}

/* One request frame, connecting first if needed. */
static int _client_request(net_relay_client_t *c, json_t *req)
{
    if (c == NULL || req == NULL || net_relay_client_connect(c) != 0) {
        json_decref(req);
        return -1;
    }
    pthread_mutex_lock(&c->lock);
    int fd = c->fd;
    int rc = fd >= 0 ? _send_obj(fd, req) : -1;     /* _send_obj frees req */
    if (fd < 0)
        json_decref(req);
    pthread_mutex_unlock(&c->lock);
    return rc;
}

int net_relay_client_publish(net_relay_client_t *c, const json_t *wire)
{
    if (wire == NULL)
        return -1;
    json_t *req = json_object();
    json_object_set_new(req, "op", json_string("publish"));
    json_object_set(req, "record", (json_t *)wire);
    return _client_request(c, req);
}

void net_relay_client_on_dir(net_relay_client_t *c, net_relay_dir_fn fn, void *arg)
{
    if (c == NULL)
        return;
    pthread_mutex_lock(&c->lock);
    c->on_dir = fn;
    c->dir_arg = arg;
    pthread_mutex_unlock(&c->lock);
}

int net_relay_client_dir_publish(net_relay_client_t *c, const json_t *entry)
{
    if (entry == NULL)
        return -1;
    json_t *req = json_object();
    json_object_set_new(req, "op", json_string("dir_publish"));
    json_object_set(req, "entry", (json_t *)entry);
    return _client_request(c, req);
}

int net_relay_client_dir_withdraw(net_relay_client_t *c, const char *handle)
{
    if (handle == NULL)
        return -1;
    return _client_request(c, json_pack("{s:s, s:s}", "op", "dir_withdraw",
                                        "handle", handle));
}

int net_relay_client_dir_lookup(net_relay_client_t *c, const char *handle)
{
    if (handle == NULL)
        return -1;
    return _client_request(c, json_pack("{s:s, s:s}", "op", "dir_lookup",
                                        "handle", handle));
}

void net_relay_client_on_hub(net_relay_client_t *c, net_relay_hub_fn fn, void *arg)
{
    if (c == NULL)
        return;
    pthread_mutex_lock(&c->lock);
    c->on_hub = fn;
    c->hub_arg = arg;
    pthread_mutex_unlock(&c->lock);
}

int net_relay_client_hub_publish(net_relay_client_t *c, const json_t *card)
{
    if (card == NULL)
        return -1;
    json_t *req = json_object();
    json_object_set_new(req, "op", json_string("hub_publish"));
    json_object_set(req, "card", (json_t *)card);
    return _client_request(c, req);
}

int net_relay_client_hub_withdraw(net_relay_client_t *c, const char *area)
{
    if (area == NULL)
        return -1;
    return _client_request(c, json_pack("{s:s, s:s}", "op", "hub_withdraw", "area", area));
}

int net_relay_client_hub_lookup(net_relay_client_t *c, const char *area)
{
    if (area == NULL)
        return -1;
    return _client_request(c, json_pack("{s:s, s:s}", "op", "hub_lookup", "area", area));
}

int net_relay_client_lookup(net_relay_client_t *c, const char *rid)
{
    if (rid == NULL)
        return -1;
    json_t *req = json_object();
    json_object_set_new(req, "op", json_string("lookup"));
    json_object_set_new(req, "id", json_string(rid));
    return _client_request(c, req);
}

void net_relay_client_close(net_relay_client_t *c)
{
    if (c == NULL)
        return;
    pthread_mutex_lock(&c->lock);
    int fd = c->fd;
    pthread_mutex_unlock(&c->lock);
    if (fd >= 0)
        shutdown(fd, SHUT_RDWR);      /* the reader marks it down */
}

/* Check the relay's proof in @p ch against our pin and distrust gate. 0 with
 * @p proven / @p key filled (proven->set false: no proof offered), or -1 with
 * @p why set. Caller holds c->lock. */
static int _client_check_relay(net_relay_client_t *c, json_t *ch,
                               const char *client_nonce, const char *my_uuid,
                               net_relay_pin_t *proven, char *key, size_t key_len,
                               char *why, size_t why_len)
{
    memset(proven, 0, sizeof(*proven));
    key[0] = '\0';
    const char *ruuid = json_string_value(json_object_get(ch, "relay_uuid"));
    const char *rkey = json_string_value(json_object_get(ch, "relay_pubkey"));
    const char *rsig = json_string_value(json_object_get(ch, "relay_sig"));
    const char *nonce = json_string_value(json_object_get(ch, "nonce"));
    if (ruuid != NULL) {
        unsigned char pk[crypto_sign_PUBLICKEYBYTES], sig[crypto_sign_BYTES];
        size_t pkl = 0, sl = 0;
        char proof[256];
        uuid_t u;
        bool ok = rkey != NULL && rsig != NULL && nonce != NULL
            && uuid_parse(ruuid, u) == 0
            && sodium_hex2bin(pk, sizeof(pk), rkey, strlen(rkey), NULL, &pkl, NULL) == 0
            && pkl == sizeof(pk)
            && sodium_hex2bin(sig, sizeof(sig), rsig, strlen(rsig), NULL, &sl, NULL) == 0
            && sl == sizeof(sig);
        if (ok) {
            /* The text carries the uuid exactly as the relay sent it (both
             * runtimes send it lower-case, as they sign it). */
            ok = _relay_proof_text(client_nonce, nonce, ruuid, my_uuid, proof,
                                   sizeof(proof)) == 0
                 && crypto_sign_verify_detached(sig, (const unsigned char *)proof,
                                                strlen(proof), pk) == 0;
        }
        if (!ok) {
            snprintf(why, why_len, "its proof of identity does not verify");
            return -1;
        }
        proven->set = true;
        uuid_unparse_lower(u, proven->uuid);
        at_strlcpy(key, rkey, key_len);
        _lower(key);
        if (net_relay_key_fingerprint(key, proven->fp, sizeof(proven->fp)) != 0) {
            snprintf(why, why_len, "its key is not hex");
            return -1;
        }
    }
    if (c->pin.set) {
        if (!proven->set) {
            snprintf(why, why_len, "offered no proof of identity, and the link "
                     "names relay %.8s", c->pin.uuid);
            return -1;
        }
        if (strcmp(proven->uuid, c->pin.uuid) != 0
            || strcmp(proven->fp, c->pin.fp) != 0) {
            snprintf(why, why_len, "is not the relay the link names (expected "
                     "%.8s, proved %.8s with another key)", c->pin.uuid,
                     proven->uuid);
            return -1;
        }
    }
    if (proven->set && c->distrusted != NULL
        && c->distrusted(c->distrust_arg, proven->uuid, key)) {
        snprintf(why, why_len, "(%.8s) is distrusted", proven->uuid);
        return -1;
    }
    return 0;
}

bool net_relay_client_connected(net_relay_client_t *c)
{
    if (c == NULL)
        return false;
    pthread_mutex_lock(&c->lock);
    bool up = c->fd >= 0;
    pthread_mutex_unlock(&c->lock);
    return up;
}

typedef struct {
    net_relay_client_t *c;
    int fd;
} relay_reader_arg_t;

static void _client_mark_down(net_relay_client_t *c, int fd)
{
    pthread_mutex_lock(&c->lock);
    if (c->fd == fd)
        c->fd = -1;
    pthread_mutex_unlock(&c->lock);
    close(fd);
}

static void *_client_reader(void *arg)
{
    relay_reader_arg_t a = *(relay_reader_arg_t *)arg;
    free(arg);
    net_relay_client_t *c = a.c;
    for (;;) {
        json_t *msg = _recv_obj(a.fd);
        if (msg == NULL)
            break;
        const char *op = json_string_value(json_object_get(msg, "op"));
        if (op != NULL && strcmp(op, "deliver") == 0) {
            const char *from = json_string_value(json_object_get(msg, "from"));
            const char *b64 = json_string_value(json_object_get(msg, "frame"));
            size_t cap = b64 != NULL ? strlen(b64) : 0;
            uint8_t *frame = cap > 0 ? malloc(cap) : NULL;
            size_t flen = 0;
            if (from != NULL && frame != NULL
                && sodium_base642bin(frame, cap, b64, cap, NULL, &flen, NULL,
                                     sodium_base64_VARIANT_ORIGINAL) == 0
                && c->deliver != NULL) {
                char from_l[UUID_STR_LEN + 1];
                at_strlcpy(from_l, from, sizeof(from_l));
                _lower(from_l);
                c->deliver(c->arg, from_l, frame, flen, c->host, c->port);
            }
            free(frame);
        } else if (op != NULL && strcmp(op, "record") == 0) {
            const char *rid = json_string_value(json_object_get(msg, "id"));
            json_t *wire = json_object_get(msg, "record");
            pthread_mutex_lock(&c->lock);
            net_relay_record_fn fn = c->on_record;
            void *fn_arg = c->record_arg;
            pthread_mutex_unlock(&c->lock);
            if (fn != NULL && rid != NULL)
                fn(fn_arg, rid, json_is_object(wire) ? wire : NULL);
        } else if (op != NULL && strncmp(op, "dir_", 4) == 0) {
            if (strcmp(op, "dir_refused") == 0)
                log_warn(c->logger, "Relay %s:%d refused directory %s: %s\n", c->host,
                         c->port, json_string_value(json_object_get(msg, "handle")),
                         json_string_value(json_object_get(msg, "reason")));
            pthread_mutex_lock(&c->lock);
            net_relay_dir_fn fn = c->on_dir;
            void *fn_arg = c->dir_arg;
            pthread_mutex_unlock(&c->lock);
            if (fn != NULL)
                fn(fn_arg, msg, c->host, c->port);
        } else if (op != NULL && strncmp(op, "hub_", 4) == 0) {
            const char *why = json_string_value(json_object_get(msg, "reason"));
            if (strcmp(op, "hub_refused") == 0 && (why == NULL || strcmp(why, "not_hub") != 0))
                log_warn(c->logger, "Relay %s:%d refused area card %s: %s\n", c->host,
                         c->port, json_string_value(json_object_get(msg, "area")), why);
            pthread_mutex_lock(&c->lock);
            net_relay_hub_fn fn = c->on_hub;
            void *fn_arg = c->hub_arg;
            pthread_mutex_unlock(&c->lock);
            if (fn != NULL)
                fn(fn_arg, msg, c->host, c->port);
        } else if (op != NULL && strcmp(op, "published") == 0) {
            log_info(c->logger, "Relay %s:%d holds our reachability record "
                     "(seq %lld)\n", c->host, c->port,
                     (long long)json_integer_value(json_object_get(msg, "seq")));
        } else if (op != NULL && strcmp(op, "refused") == 0) {
            log_warn(c->logger, "Relay %s:%d refused our reachability record: "
                     "%s\n", c->host, c->port,
                     json_string_value(json_object_get(msg, "reason")));
        } else if (op != NULL && strcmp(op, "unreachable") == 0) {
            const char *to = json_string_value(json_object_get(msg, "to"));
            if (to != NULL) {
                pthread_mutex_lock(&c->lock);
                size_t slot = c->n_unreachable % AT_RELAY_UNREACHABLE_MAX;
                at_strlcpy(c->unreachable[slot], to, sizeof(c->unreachable[slot]));
                _lower(c->unreachable[slot]);
                c->n_unreachable++;
                char to_l[UUID_STR_LEN + 1];
                at_strlcpy(to_l, c->unreachable[slot], sizeof(to_l));
                net_relay_unreachable_fn fn = c->on_unreachable;
                void *fn_arg = c->unreachable_arg;
                pthread_mutex_unlock(&c->lock);
                log_info(c->logger, "Relay %s:%d cannot reach %.8s (not "
                         "registered there)\n", c->host, c->port, to);
                if (fn != NULL)
                    fn(fn_arg, to_l, c->host, c->port);
            }
        }
        json_decref(msg);
    }
    _client_mark_down(c, a.fd);
    return NULL;
}

static int _client_dial(net_relay_client_t *c)
{
    struct addrinfo hints = { .ai_socktype = SOCK_STREAM };
    struct addrinfo *res = NULL;
    char port_s[8];
    snprintf(port_s, sizeof(port_s), "%d", c->port);
    if (getaddrinfo(c->host, port_s, &hints, &res) != 0 || res == NULL)
        return -1;
    int fd = socket(res->ai_family, SOCK_STREAM, 0);
    if (fd >= 0) {
        (void)at_set_rcvtimeo(fd, AT_RELAY_HANDSHAKE_TIMEOUT_MS, c->logger);
        (void)at_set_sndtimeo(fd, AT_RELAY_HANDSHAKE_TIMEOUT_MS, c->logger);
        if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
            close(fd);
            fd = -1;
        }
    }
    freeaddrinfo(res);
    return fd;
}

int net_relay_client_connect(net_relay_client_t *c)
{
    if (c == NULL)
        return -1;
    pthread_mutex_lock(&c->lock);
    if (c->fd >= 0) {
        pthread_mutex_unlock(&c->lock);
        return 0;
    }
    int fd = _client_dial(c);
    if (fd < 0) {
        pthread_mutex_unlock(&c->lock);
        return -1;
    }
    char uuid[UUID_STR_LEN + 1];
    uuid_unparse_lower(c->self->uuid, uuid);
    json_t *hello = json_object();
    json_object_set_new(hello, "op", json_string("hello"));
    json_object_set_new(hello, "uuid", json_string(uuid));
    json_object_set_new(hello, "pubkey",
                        json_string((const char *)c->self->signature.public_hex));
    unsigned char cn_raw[16];
    char client_nonce[33];
    randombytes_buf(cn_raw, sizeof(cn_raw));
    sodium_bin2hex(client_nonce, sizeof(client_nonce), cn_raw, sizeof(cn_raw));
    json_object_set_new(hello, "nonce", json_string(client_nonce));
    int rc = -1;
    json_t *ch = NULL, *ans = NULL;
    net_relay_pin_t proven;
    char proven_key[sizeof(c->proven_key)];
    char why[sizeof(c->refused)] = "";
    memset(&proven, 0, sizeof(proven));
    proven_key[0] = '\0';
    if (_send_obj(fd, hello) == 0 && (ch = _recv_obj(fd)) != NULL) {
        const char *op = json_string_value(json_object_get(ch, "op"));
        const char *nonce = json_string_value(json_object_get(ch, "nonce"));
        char text[160];
        unsigned char sig[crypto_sign_BYTES];
        char sig_hex[crypto_sign_BYTES * 2 + 1];
        if (op != NULL && strcmp(op, "challenge") == 0 && nonce != NULL
            && _client_check_relay(c, ch, client_nonce, uuid, &proven, proven_key,
                                   sizeof(proven_key), why, sizeof(why)) == 0
            && _registration_text(nonce, uuid, text, sizeof(text)) == 0
            && crypto_sign_detached(sig, NULL, (const unsigned char *)text,
                                    strlen(text), c->self->signature.private) == 0) {
            sodium_bin2hex(sig_hex, sizeof(sig_hex), sig, sizeof(sig));
            json_t *reg = json_object();
            json_object_set_new(reg, "op", json_string("register"));
            json_object_set_new(reg, "sig", json_string(sig_hex));
            if (_send_obj(fd, reg) == 0 && (ans = _recv_obj(fd)) != NULL) {
                const char *aop = json_string_value(json_object_get(ans, "op"));
                if (aop != NULL && strcmp(aop, "registered") == 0)
                    rc = 0;
            }
        }
    }
    json_decref(ch);
    json_decref(ans);
    if (rc != 0) {
        close(fd);
        at_strlcpy(c->refused, why, sizeof(c->refused));
        pthread_mutex_unlock(&c->lock);
        if (why[0] != '\0')
            log_warn(c->logger, "Relay: %s:%d refused: relay %s\n",
                     c->host, c->port, why);
        else
            log_warn(c->logger, "Relay: registration with %s:%d failed\n",
                     c->host, c->port);
        return -1;
    }
    (void)at_set_rcvtimeo(fd, 0, c->logger);
    c->fd = fd;
    c->proven = proven;
    at_strlcpy(c->proven_key, proven_key, sizeof(c->proven_key));
    c->refused[0] = '\0';
    pthread_mutex_unlock(&c->lock);

    relay_reader_arg_t *a = malloc(sizeof(*a));
    pthread_t t;
    if (a == NULL) {
        _client_mark_down(c, fd);
        return -1;
    }
    a->c = c;
    a->fd = fd;
    if (pthread_create(&t, NULL, _client_reader, a) != 0) {
        free(a);
        _client_mark_down(c, fd);
        return -1;
    }
    pthread_detach(t);
    if (proven.set)
        log_info(c->logger, "Relay: registered with %s:%d (relay %.8s, proven)\n",
                 c->host, c->port, proven.uuid);
    else
        log_info(c->logger, "Relay: registered with %s:%d (relay "
                 "unauthenticated)\n", c->host, c->port);
    return 0;
}

int net_relay_client_send(net_relay_client_t *c, const uuid_t to,
                          const uint8_t *frame, size_t len)
{
    if (c == NULL || frame == NULL || net_relay_client_connect(c) != 0)
        return -1;
    size_t b64_cap = sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL);
    char *b64 = malloc(b64_cap);
    if (b64 == NULL)
        return -1;
    sodium_bin2base64(b64, b64_cap, frame, len, sodium_base64_VARIANT_ORIGINAL);
    char to_s[UUID_STR_LEN + 1];
    uuid_unparse_lower(to, to_s);
    json_t *req = json_object();
    json_object_set_new(req, "op", json_string("send"));
    json_object_set_new(req, "to", json_string(to_s));
    json_object_set_new(req, "frame", json_string(b64));
    free(b64);
    pthread_mutex_lock(&c->lock);
    int fd = c->fd;
    int rc = fd >= 0 ? _send_obj(fd, req) : (json_decref(req), -1);
    if (rc != 0 && fd >= 0 && c->fd == fd) {
        c->fd = -1;
        shutdown(fd, SHUT_RDWR);       /* the reader closes it */
    }
    pthread_mutex_unlock(&c->lock);
    return rc;
}

bool net_relay_client_was_unreachable(net_relay_client_t *c, const char *uuid)
{
    if (c == NULL || uuid == NULL)
        return false;
    bool found = false;
    pthread_mutex_lock(&c->lock);
    size_t n = c->n_unreachable < AT_RELAY_UNREACHABLE_MAX
             ? c->n_unreachable : AT_RELAY_UNREACHABLE_MAX;
    for (size_t i = 0; i < n && !found; i++)
        found = strcasecmp(c->unreachable[i], uuid) == 0;
    pthread_mutex_unlock(&c->lock);
    return found;
}

void net_relay_client_free(net_relay_client_t *c)
{
    if (c == NULL)
        return;
    pthread_mutex_lock(&c->lock);
    int fd = c->fd;
    c->fd = -1;
    pthread_mutex_unlock(&c->lock);
    if (fd >= 0)
        shutdown(fd, SHUT_RDWR);
    /* The reader thread may still hold `c` for a moment; like the server, a
     * client is freed only at shutdown, so it is left for process exit. */
}
