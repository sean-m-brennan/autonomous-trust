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

#include "first_contact/net_hub.h"
#include "utilities/logger.h"
#include "utilities/util.h"

#define AT_HUB_MAX_CLIENTS 1024

typedef struct {
    char area[AT_AREA_MAX + 1];
    char uuid[UUID_STR_LEN + 1];
    at_dir_signed_t card;
} hub_card_t;

typedef struct {
    char uuid[UUID_STR_LEN + 1];
    double tokens;
    double last;
} hub_bucket_t;

struct net_hub_s {
    pthread_mutex_t lock;
    char areas[AT_HUB_MAX_AREAS][AT_AREA_MAX + 1];
    size_t n_areas;
    int rate;
    hub_card_t *cards;
    size_t n_cards;
    hub_bucket_t buckets[AT_HUB_MAX_CLIENTS];
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

bool net_hub_enabled(void)
{
    const char *v = getenv("AT_HUB");
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

int net_hub_rate(void)
{
    const char *v = getenv(AT_HUB_RATE_ENV);
    if (v == NULL || *v == '\0')
        return AT_HUB_DEFAULT_RATE;
    char *end = NULL;
    long r = strtol(v, &end, 10);
    while (end != NULL && (*end == ' ' || *end == '\t' || *end == '\n'))
        end++;
    if (end == NULL || *end != '\0' || r <= 0 || r > 1000000)
        return AT_HUB_DEFAULT_RATE;
    return (int)r;
}

size_t net_hub_areas(char out[][AT_AREA_MAX + 1], size_t max)
{
    const char *env = getenv(AT_HUB_AREAS_ENV);
    size_t n = 0;
    if (env == NULL)
        return 0;
    if (max > AT_HUB_MAX_AREAS)
        max = AT_HUB_MAX_AREAS;
    const char *p = env;
    while (*p != '\0' && n < max) {
        const char *comma = strchr(p, ',');
        size_t len = comma != NULL ? (size_t)(comma - p) : strlen(p);
        while (len > 0 && (*p == ' ' || *p == '\t')) {
            p++;
            len--;
        }
        while (len > 0 && (p[len - 1] == ' ' || p[len - 1] == '\t' || p[len - 1] == '\n'))
            len--;
        char part[16], area[AT_AREA_MAX + 1];
        if (len < sizeof(part)) {
            memcpy(part, p, len);
            part[len] = '\0';
            if (at_area_normalize(part, area, sizeof(area), AT_AREA_MIN, AT_AREA_MAX) == 0) {
                bool dup = false;
                for (size_t i = 0; i < n && !dup; i++)
                    dup = strcmp(out[i], area) == 0;
                if (!dup)
                    at_strlcpy(out[n++], area, sizeof(out[0]));
            }
        }
        if (comma == NULL)
            break;
        p = comma + 1;
    }
    return n;
}

net_hub_t *net_hub_new(const char *const *areas, size_t n_areas, int rate)
{
    net_hub_t *hub = calloc(1, sizeof(*hub));
    if (hub == NULL)
        return NULL;
    pthread_mutex_init(&hub->lock, NULL);
    for (size_t i = 0; i < n_areas && hub->n_areas < AT_HUB_MAX_AREAS; i++)
        if (at_area_is_area(areas[i]))
            at_strlcpy(hub->areas[hub->n_areas++], areas[i], sizeof(hub->areas[0]));
    hub->rate = rate > 0 ? rate : AT_HUB_DEFAULT_RATE;
    hub->monotonic = _monotonic;
    hub->wallclock = _wallclock;
    return hub;
}

void net_hub_free(net_hub_t *hub)
{
    if (hub == NULL)
        return;
    for (size_t i = 0; i < hub->n_cards; i++)
        at_dir_free(&hub->cards[i].card);
    free(hub->cards);
    pthread_mutex_destroy(&hub->lock);
    free(hub);
}

void net_hub_set_distrust(net_hub_t *hub, net_relay_distrust_fn fn, void *arg)
{
    if (hub == NULL)
        return;
    pthread_mutex_lock(&hub->lock);
    hub->distrusted = fn;
    hub->distrust_arg = arg;
    pthread_mutex_unlock(&hub->lock);
}

void net_hub_set_clocks(net_hub_t *hub, double (*monotonic)(void), double (*wallclock)(void))
{
    if (hub == NULL)
        return;
    hub->monotonic = monotonic != NULL ? monotonic : _monotonic;
    hub->wallclock = wallclock != NULL ? wallclock : _wallclock;
}

static json_t *_reply(const char *op, const char *area)
{
    return json_pack("{s:s, s:s}", "op", op, "area", area != NULL ? area : "");
}

static json_t *_refused(const char *area, const char *reason)
{
    json_t *r = _reply("hub_refused", area);
    json_object_set_new(r, "reason", json_string(reason));
    return r;
}

static const char *_REASONS[] = {"", "malformed", "bad_signature", "expired",
                                 "untrusted", "mismatch"};

static bool _expired(const at_dir_signed_t *c, double now)
{
    json_t *v = json_object_get(c->body, "expiry");
    return !json_is_integer(v) || now >= (double)json_integer_value(v);
}

static bool _serves(const net_hub_t *hub, const char *area)
{
    for (size_t i = 0; i < hub->n_areas; i++)
        if (strcmp(hub->areas[i], area) == 0)
            return true;
    return false;
}

static hub_card_t *_find_locked(net_hub_t *hub, const char *area, const char *uuid)
{
    for (size_t i = 0; i < hub->n_cards; i++)
        if (strcmp(hub->cards[i].area, area) == 0 && strcmp(hub->cards[i].uuid, uuid) == 0)
            return &hub->cards[i];
    return NULL;
}

static void _remove_locked(net_hub_t *hub, size_t i)
{
    at_dir_free(&hub->cards[i].card);
    memmove(&hub->cards[i], &hub->cards[i + 1], (hub->n_cards - i - 1) * sizeof(hub->cards[0]));
    hub->n_cards--;
}

static void _evict_locked(net_hub_t *hub, double now)
{
    for (size_t i = hub->n_cards; i-- > 0;)
        if (_expired(&hub->cards[i].card, now))
            _remove_locked(hub, i);
}

static size_t _count_locked(const net_hub_t *hub, const char *area)
{
    size_t n = 0;
    for (size_t i = 0; i < hub->n_cards; i++)
        n += strcmp(hub->cards[i].area, area) == 0;
    return n;
}

json_t *net_hub_publish(net_hub_t *hub, const char *uuid, const char *pubkey,
                        const json_t *wire)
{
    at_dir_signed_t card;
    if (at_dir_from_wire(wire, &card) != AT_DIR_OK)
        return _refused("", "malformed");
    double now = hub->wallclock();
    int rc = at_area_card_verify(&card, now);
    if (rc != AT_DIR_OK) {
        /* The area as the card gives it, whatever it is, as Python's reply. */
        json_t *r = _refused(at_area_card_area(&card), _REASONS[-rc]);
        at_dir_free(&card);
        return r;
    }
    char area[AT_AREA_MAX + 1];
    at_strlcpy(area, at_area_card_area(&card), sizeof(area));    /* verified: fits */
    if (!_serves(hub, area)) {
        at_dir_free(&card);
        return _refused(area, "area");
    }
    if ((double)at_dir_expiry(&card) > now + AT_AREA_MAX_TTL_SECONDS) {
        at_dir_free(&card);
        return _refused(area, "expiry");
    }
    /* Only the holder files: the card is signed by the key the registrant
     * proved, for the uuid it registered. */
    if (strcmp(at_dir_key(&card), pubkey) != 0 || strcasecmp(at_dir_uuid(&card), uuid) != 0) {
        at_dir_free(&card);
        return _refused(area, "not_holder");
    }
    char holder[UUID_STR_LEN + 1];
    at_strlcpy(holder, uuid, sizeof(holder));
    int64_t seq = at_dir_seq(&card);
    pthread_mutex_lock(&hub->lock);
    hub_card_t *held = _find_locked(hub, area, holder);
    json_t *reply = NULL;
    if (held != NULL) {
        if (seq == at_dir_seq(&held->card) && strcmp(card.body_str, held->card.body_str) == 0)
            reply = json_pack("{s:s, s:s, s:I}", "op", "hub_published", "area", area,
                              "seq", (json_int_t)seq);
        else if (seq <= at_dir_seq(&held->card))
            reply = _refused(area, "stale");
    } else {
        _evict_locked(hub, now);
        if (_count_locked(hub, area) >= AT_HUB_MAX_PER_AREA || hub->n_cards >= AT_HUB_MAX_CARDS)
            reply = _refused(area, "full");
    }
    if (reply != NULL) {
        pthread_mutex_unlock(&hub->lock);
        at_dir_free(&card);
        return reply;
    }
    if (held != NULL) {
        at_dir_free(&held->card);
        held->card = card;             /* move */
    } else {
        hub_card_t *grown = realloc(hub->cards, (hub->n_cards + 1) * sizeof(*grown));
        if (grown == NULL) {
            pthread_mutex_unlock(&hub->lock);
            at_dir_free(&card);
            return _refused(area, "full");
        }
        hub->cards = grown;
        hub_card_t *slot = &hub->cards[hub->n_cards++];
        at_strlcpy(slot->area, area, sizeof(slot->area));
        at_strlcpy(slot->uuid, holder, sizeof(slot->uuid));
        slot->card = card;             /* move */
    }
    pthread_mutex_unlock(&hub->lock);
    log_info(NULL, "Hub: %.8s listed in %s (seq %lld)\n", uuid, area, (long long)seq);
    return json_pack("{s:s, s:s, s:I}", "op", "hub_published", "area", area,
                     "seq", (json_int_t)seq);
}

json_t *net_hub_withdraw(net_hub_t *hub, const char *uuid, const char *pubkey,
                         const char *area)
{
    char folded[AT_AREA_MAX + 1] = {0};
    if (at_area_normalize(area, folded, sizeof(folded), AT_AREA_MIN, AT_AREA_MAX) != 0)
        folded[0] = '\0';
    pthread_mutex_lock(&hub->lock);
    hub_card_t *held = folded[0] != '\0' ? _find_locked(hub, folded, uuid) : NULL;
    if (held != NULL && strcmp(at_dir_key(&held->card), pubkey) == 0)
        _remove_locked(hub, (size_t)(held - hub->cards));
    pthread_mutex_unlock(&hub->lock);
    return _reply("hub_withdrawn", folded);
}

static bool _take_token_locked(net_hub_t *hub, const char *uuid)
{
    double now = hub->monotonic();
    hub_bucket_t *b = NULL;
    for (size_t i = 0; i < hub->n_buckets && b == NULL; i++)
        if (strcmp(hub->buckets[i].uuid, uuid) == 0)
            b = &hub->buckets[i];
    if (b == NULL) {
        size_t slot = hub->n_buckets < AT_HUB_MAX_CLIENTS ? hub->n_buckets++ : 0;
        if (slot == 0 && hub->n_buckets == AT_HUB_MAX_CLIENTS) {
            /* Full: reuse the least recently seen bucket. */
            for (size_t i = 1; i < hub->n_buckets; i++)
                if (hub->buckets[i].last < hub->buckets[slot].last)
                    slot = i;
        }
        b = &hub->buckets[slot];
        at_strlcpy(b->uuid, uuid, sizeof(b->uuid));
        b->tokens = (double)hub->rate;
        b->last = now;
    }
    double tokens = b->tokens + (now - b->last) * (double)hub->rate / 60.0;
    if (tokens > (double)hub->rate)
        tokens = (double)hub->rate;
    b->last = now;
    if (tokens < 1.0) {
        b->tokens = tokens;
        return false;
    }
    b->tokens = tokens - 1.0;
    return true;
}

typedef struct {
    long expiry;
    char uuid[UUID_STR_LEN + 1];
    char key[65];
    json_t *wire;
} hub_hit_t;

/* Freshest first; uuid breaks a tie, as Python's sort key (-expiry, uuid). */
static int _by_freshness(const void *x, const void *y)
{
    const hub_hit_t *a = x, *b = y;
    if (a->expiry != b->expiry)
        return a->expiry > b->expiry ? -1 : 1;
    return strcmp(a->uuid, b->uuid);
}

json_t *net_hub_lookup(net_hub_t *hub, const char *uuid, const char *area)
{
    char folded[AT_AREA_MAX + 1] = {0};
    if (at_area_normalize(area, folded, sizeof(folded), AT_AREA_MIN, AT_AREA_MAX) != 0)
        folded[0] = '\0';
    pthread_mutex_lock(&hub->lock);
    if (!_take_token_locked(hub, uuid)) {
        pthread_mutex_unlock(&hub->lock);
        return _reply("hub_limited", folded);
    }
    double now = hub->wallclock();
    hub_card_t *mine = folded[0] != '\0' ? _find_locked(hub, folded, uuid) : NULL;
    hub_hit_t *hits = NULL;
    size_t n = 0;
    if (mine != NULL && !_expired(&mine->card, now)) {
        hits = calloc(hub->n_cards > 0 ? hub->n_cards : 1, sizeof(*hits));
        for (size_t i = 0; hits != NULL && i < hub->n_cards; i++) {
            hub_card_t *c = &hub->cards[i];
            if (strcmp(c->area, folded) != 0 || strcmp(c->uuid, uuid) == 0
                || _expired(&c->card, now))
                continue;
            hits[n].expiry = at_dir_expiry(&c->card);
            at_strlcpy(hits[n].uuid, c->uuid, sizeof(hits[n].uuid));
            at_strlcpy(hits[n].key, at_dir_key(&c->card), sizeof(hits[n].key));
            hits[n].wire = at_dir_to_wire(&c->card);
            n++;
        }
    }
    net_relay_distrust_fn fn = hub->distrusted;
    void *arg = hub->distrust_arg;
    pthread_mutex_unlock(&hub->lock);
    /* Distrust is asked outside the lock, as the registry's is. */
    size_t kept = 0;
    for (size_t i = 0; i < n; i++) {
        if (fn != NULL && fn(arg, hits[i].uuid, hits[i].key)) {
            json_decref(hits[i].wire);
            continue;
        }
        hits[kept++] = hits[i];
    }
    if (kept > 1)
        qsort(hits, kept, sizeof(*hits), _by_freshness);
    json_t *cards = json_array();
    for (size_t i = 0; i < kept; i++) {
        if (i < AT_HUB_LOOKUP_MAX && hits[i].wire != NULL)
            json_array_append_new(cards, hits[i].wire);
        else
            json_decref(hits[i].wire);
    }
    free(hits);
    json_t *r = _reply("hub_cards", folded);
    json_object_set_new(r, "cards", cards);
    return r;
}
