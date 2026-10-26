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
#include <string.h>
#include <time.h>

#include "network/net_liveness.h"

typedef struct {
    uuid_t uuid;
    double last;
    bool used;
} liveness_entry_t;

static liveness_entry_t g_entries[NET_LIVENESS_MAX];
static double g_start;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

double net_liveness_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

void net_liveness_reset(double start)
{
    pthread_mutex_lock(&g_lock);
    memset(g_entries, 0, sizeof(g_entries));
    g_start = start;
    pthread_mutex_unlock(&g_lock);
}

void net_liveness_heard(const uuid_t peer, double now)
{
    if (peer == NULL || uuid_is_null(peer))
        return;
    pthread_mutex_lock(&g_lock);
    liveness_entry_t *slot = NULL, *free_slot = NULL, *oldest = NULL;
    for (size_t i = 0; i < NET_LIVENESS_MAX; i++) {
        liveness_entry_t *e = &g_entries[i];
        if (!e->used) {
            if (free_slot == NULL)
                free_slot = e;
            continue;
        }
        if (uuid_compare(e->uuid, peer) == 0) {
            slot = e;
            break;
        }
        if (oldest == NULL || e->last < oldest->last)
            oldest = e;
    }
    if (slot == NULL) {
        slot = free_slot != NULL ? free_slot : oldest;
        uuid_copy(slot->uuid, peer);
        slot->used = true;
        slot->last = now;
    } else if (now > slot->last) {
        slot->last = now;
    }
    pthread_mutex_unlock(&g_lock);
}

double net_liveness_quiet_for(const uuid_t peer, double now)
{
    pthread_mutex_lock(&g_lock);
    double since = g_start;
    for (size_t i = 0; peer != NULL && i < NET_LIVENESS_MAX; i++)
        if (g_entries[i].used && uuid_compare(g_entries[i].uuid, peer) == 0) {
            since = g_entries[i].last;
            break;
        }
    pthread_mutex_unlock(&g_lock);
    double q = now - since;
    return q > 0.0 ? q : 0.0;
}
