/********************
 *  Copyright 2025 Sean M. Brennan and contributors
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

#include <stddef.h>
#include <stdio.h>

#include <jansson.h>

#include "config/configuration.h"
#include "structures/data.h"
#include "structures/map.h"
#include "utilities/exception.h"
#include "utilities/timeout.h"

int at_timeout_apply_scale(int base_ms, int max_rtt_ms, int multiplier)
{
    if (multiplier <= 0)       multiplier  = AT_TIMEOUT_DEFAULT_MULTIPLIER;
    if (max_rtt_ms < 0)        max_rtt_ms  = 0;
    /* long arithmetic avoids 32-bit overflow for multi-minute DTN links. */
    long scaled = (long)max_rtt_ms * (long)multiplier;
    if (scaled < (long)base_ms) return base_ms;
    if (scaled > (long)0x7FFFFFFF) return 0x7FFFFFFF;
    return (int)scaled;
}

/* Read the timeouts config from proc->configs if registered; else NULL. */
static const timeouts_config_t *get_timeouts_cfg(const process_t *proc)
{
    if (proc == NULL || proc->configs == NULL) return NULL;
    data_t *dat = NULL;
    /* map_get's signature doesn't declare const-correctness for lookups;
     * cast through to preserve the const on @p proc here, and stage the
     * key in a non-const char buffer since map_key_t is `char *`. */
    char key[16];
    snprintf(key, sizeof(key), "timeouts");
    if (map_get((map_t *)proc->configs, key, &dat) != 0 || dat == NULL)
        return NULL;
    config_t *cfg = NULL;
    if (data_object_ptr(dat, (void **)&cfg) != 0 || cfg == NULL) return NULL;
    return (const timeouts_config_t *)cfg->data_struct;
}

/* Walk peer_rtt_ms[] under the protocol read lock; return the max, or
 * AT_TIMEOUT_DEFAULT_RTT_MS if every slot is zero (unknown). */
static int max_peer_rtt_ms(const process_t *proc)
{
    if (proc == NULL) return AT_TIMEOUT_DEFAULT_RTT_MS;
    peers_read_lock(proc);
    int max_rtt = 0;
    for (size_t i = 0; i < proc->protocol.num_peers; i++) {
        int r = proc->protocol.peer_rtt_ms[i];
        if (r > max_rtt) max_rtt = r;
    }
    peers_read_unlock(proc);
    return max_rtt > 0 ? max_rtt : AT_TIMEOUT_DEFAULT_RTT_MS;
}

int at_timeout_scale_ms(int base_ms, const process_t *proc)
{
    int multiplier = AT_TIMEOUT_DEFAULT_MULTIPLIER;
    int rtt_ms;

    const timeouts_config_t *tc = get_timeouts_cfg(proc);
    if (tc != NULL && tc->multiplier > 0)
        multiplier = tc->multiplier;

    if (tc != NULL && tc->forced_rtt_ms > 0)
        rtt_ms = tc->forced_rtt_ms;
    else
        rtt_ms = max_peer_rtt_ms(proc);

    return at_timeout_apply_scale(base_ms, rtt_ms, multiplier);
}

/* ---------- JSON serialization ---------- */

int timeouts_to_json(const void *data_struct, json_t **obj_ptr)
{
    const timeouts_config_t *cfg = data_struct;
    json_t *obj = json_object();
    if (obj == NULL) return EXCEPTION(ENOMEM);
    json_object_set_new(obj, "typename",      json_string("timeouts"));
    json_object_set_new(obj, "multiplier",    json_integer(cfg->multiplier));
    json_object_set_new(obj, "forced_rtt_ms", json_integer(cfg->forced_rtt_ms));
    *obj_ptr = obj;
    return 0;
}

int timeouts_from_json(const json_t *obj, void *data_struct)
{
    timeouts_config_t *cfg = data_struct;
    cfg->multiplier    = 0;
    cfg->forced_rtt_ms = 0;

    const json_t *jm = json_object_get(obj, "multiplier");
    if (json_is_integer(jm)) cfg->multiplier = (int)json_integer_value(jm);

    const json_t *jr = json_object_get(obj, "forced_rtt_ms");
    if (json_is_integer(jr)) cfg->forced_rtt_ms = (int)json_integer_value(jr);

    return 0;
}

DECLARE_CONFIGURATION(timeouts, sizeof(timeouts_config_t), timeouts_to_json, timeouts_from_json);
