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
#include <stdlib.h>
#include <string.h>

#include "identity/identity.h"   /* DEFAULT_MAX_PEERS */
#include "network/net_presence.h"

/* One tracked peer. `since` is when it joined the tracker: a peer is never
 * absent, and never owed a heartbeat, before it has been on the roster for the
 * respective interval. */
typedef struct {
    uuid_t uuid;
    double since;
    double last_heard;   /* 0 = nothing heard yet */
    double last_sent;    /* 0 = nothing sent yet */
    bool   absent;
} presence_entry_t;

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static presence_entry_t g_entries[DEFAULT_MAX_PEERS];
static size_t g_count;
static double g_heartbeat_sec = NET_PRESENCE_HEARTBEAT_DEFAULT_SEC;
static double g_absent_sec = NET_PRESENCE_ABSENT_DEFAULT_SEC;

static double _env_seconds(const char *name, double fallback)
{
    const char *raw = getenv(name);
    if (raw == NULL || raw[0] == '\0')
        return fallback;
    char *end = NULL;
    double v = strtod(raw, &end);
    if (end == raw || *end != '\0' || !(v > 0.0))
        return fallback;
    return v;
}

void net_presence_configure(double heartbeat_sec, double absent_sec)
{
    pthread_mutex_lock(&g_lock);
    g_heartbeat_sec = heartbeat_sec > 0.0
        ? heartbeat_sec : NET_PRESENCE_HEARTBEAT_DEFAULT_SEC;
    g_absent_sec = absent_sec > 0.0 ? absent_sec : NET_PRESENCE_ABSENT_DEFAULT_SEC;
    /* Absent means "missed the heartbeats it owed us", so the threshold below
     * one heartbeat would mark an idle but healthy peer absent between two
     * presence frames. */
    if (g_absent_sec < g_heartbeat_sec)
        g_absent_sec = g_heartbeat_sec;
    g_count = 0;
    memset(g_entries, 0, sizeof(g_entries));
    pthread_mutex_unlock(&g_lock);
}

void net_presence_init(void)
{
    net_presence_configure(
        _env_seconds("AT_PRESENCE_HEARTBEAT_SEC", NET_PRESENCE_HEARTBEAT_DEFAULT_SEC),
        _env_seconds("AT_PRESENCE_ABSENT_SEC", NET_PRESENCE_ABSENT_DEFAULT_SEC));
}

double net_presence_heartbeat_sec(void)
{
    pthread_mutex_lock(&g_lock);
    double v = g_heartbeat_sec;
    pthread_mutex_unlock(&g_lock);
    return v;
}

double net_presence_absent_sec(void)
{
    pthread_mutex_lock(&g_lock);
    double v = g_absent_sec;
    pthread_mutex_unlock(&g_lock);
    return v;
}

/* Caller holds g_lock. */
static presence_entry_t *_find_locked(const uuid_t peer)
{
    for (size_t i = 0; i < g_count; i++)
        if (uuid_compare(g_entries[i].uuid, peer) == 0)
            return &g_entries[i];
    return NULL;
}

void net_presence_heard(const uuid_t peer, double now)
{
    if (peer == NULL || uuid_is_null(peer))
        return;
    pthread_mutex_lock(&g_lock);
    presence_entry_t *e = _find_locked(peer);
    /* Only peers the tick has put on the roster. A frame from an address we
     * have not admitted yet is not evidence about a member. */
    if (e != NULL && now > e->last_heard)
        e->last_heard = now;
    pthread_mutex_unlock(&g_lock);
}

void net_presence_sent(const uuid_t peer, double now)
{
    pthread_mutex_lock(&g_lock);
    if (peer == NULL) {
        for (size_t i = 0; i < g_count; i++)
            if (now > g_entries[i].last_sent)
                g_entries[i].last_sent = now;
    } else {
        presence_entry_t *e = _find_locked(peer);
        if (e != NULL && now > e->last_sent)
            e->last_sent = now;
    }
    pthread_mutex_unlock(&g_lock);
}

static bool _on_roster(const uuid_t *roster, size_t n, const uuid_t peer)
{
    for (size_t i = 0; i < n; i++)
        if (uuid_compare(roster[i], peer) == 0)
            return true;
    return false;
}

bool net_presence_tick(const uuid_t *roster, size_t n, double now,
                       net_presence_change_t *out, size_t out_max,
                       size_t *n_out)
{
    size_t changes = 0;
    bool heartbeat_due = false;
    pthread_mutex_lock(&g_lock);

    /* Forget peers that left the roster, compacting in place. */
    size_t kept = 0;
    for (size_t i = 0; i < g_count; i++) {
        if (roster != NULL && _on_roster(roster, n, g_entries[i].uuid)) {
            if (kept != i)
                g_entries[kept] = g_entries[i];
            kept++;
        }
    }
    g_count = kept;

    for (size_t r = 0; roster != NULL && r < n; r++) {
        presence_entry_t *e = _find_locked(roster[r]);
        if (e == NULL) {
            if (g_count >= DEFAULT_MAX_PEERS || uuid_is_null(roster[r]))
                continue;
            e = &g_entries[g_count++];
            memset(e, 0, sizeof(*e));
            uuid_copy(e->uuid, roster[r]);
            e->since = now;
        }
        /* Silence is measured from the later of joining the tracker and the
         * last frame heard, so a new peer gets the full grace. */
        double heard_ref = e->last_heard > e->since ? e->last_heard : e->since;
        bool absent = (now - heard_ref) > g_absent_sec;
        if (absent != e->absent) {
            e->absent = absent;
            if (out != NULL && changes < out_max) {
                uuid_copy(out[changes].peer_uuid, e->uuid);
                out[changes].present = !absent;
                out[changes].last_heard = e->last_heard;
            }
            changes++;
        }
        double sent_ref = e->last_sent > e->since ? e->last_sent : e->since;
        if ((now - sent_ref) >= g_heartbeat_sec)
            heartbeat_due = true;
    }
    pthread_mutex_unlock(&g_lock);
    if (n_out != NULL)
        *n_out = changes < out_max ? changes : out_max;
    return heartbeat_due;
}

size_t net_presence_snapshot(const uuid_t *roster, size_t n,
                             net_presence_change_t *out, size_t out_max)
{
    if (roster == NULL || out == NULL)
        return 0;
    size_t written = 0;
    pthread_mutex_lock(&g_lock);
    for (size_t r = 0; r < n && written < out_max; r++) {
        presence_entry_t *e = _find_locked(roster[r]);
        uuid_copy(out[written].peer_uuid, roster[r]);
        out[written].present = e == NULL || !e->absent;
        out[written].last_heard = e == NULL ? 0.0 : e->last_heard;
        written++;
    }
    pthread_mutex_unlock(&g_lock);
    return written;
}
