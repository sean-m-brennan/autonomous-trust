/********************
 *  Copyright 2024 TekFive, Inc., Sean M. Brennan, and contributors
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

#include <string.h>

#include "peers.h"
#include "structures/map_priv.h"
#include "config/configuration.h"


int peers_to_json(const void *data_struct, json_t **obj_ptr)
{
    const peers_t *peers = data_struct;
    *obj_ptr = json_object();
    json_t *obj = *obj_ptr;
    if (obj == NULL)
        return EXCEPTION(ENOMEM);

    json_t *hierarchy = json_array();
    for (int i=0; i < LEVELS; i++) {
        json_t *hierarchy_lvl;
        map_to_json(&peers->hierarchy[i], &hierarchy_lvl);
        json_array_append_new(hierarchy, hierarchy_lvl);
    }
    json_object_set_new(obj, "hierarchy", hierarchy);

    json_t *valuation = json_array();
    for (int i=0; i < VALUES; i++) {
        json_t *valuation_lvl;
        map_to_json(&peers->valuations[i], &valuation_lvl);
        json_array_append_new(valuation, valuation_lvl);
    }
    json_object_set_new(obj, "valuation", valuation);
    return 0;
}

int peers_from_json(const json_t *obj, void *data_struct)
{
    peers_t *peers = data_struct;
    json_t *hierarchy = json_object_get(obj, "hierarchy");
    for (int i=0; i < LEVELS; i++) {
        json_t *hierarchy_lvl = json_array_get(hierarchy, i);
        map_from_json(hierarchy_lvl, &peers->hierarchy[i]);
    }
    json_t *valuation = json_object_get(obj, "valuation");
    for (int i=0; i < VALUES; i++) {
        json_t *valuation_lvl = json_array_get(valuation, i);
        map_from_json(valuation_lvl, &peers->valuations[i]);
    }
    return 0;
}

DECLARE_CONFIGURATION(peers, sizeof(peers_t), peers_to_json, peers_from_json);


/****************************
 * Peer helper methods
 ****************************/

/* Internal: extract public_identity_t pointer from map value (stored as bytes) */
static const public_identity_t *_peer_from_data(data_t *value)
{
    bytes_t bytes = NULL;
    if (data_bytes_ptr(value, &bytes) == 0)
        return (const public_identity_t *)bytes;
    return NULL;
}

/* Iteration is not under a lock because every in-tree caller reaches this
 * through the identity-process message dispatcher, which serialises handler
 * invocations.  If peers_t ever becomes visible to a second thread, add a
 * reader/writer lock here and in peers_find_by_address below. */
const public_identity_t *peers_find_by_uuid(peers_t *peers, const uuid_t uuid)
{
    for (int lvl = 0; lvl < LEVELS; lvl++)
    {
        map_key_t key;
        data_t *value;
        map_entries_for_each(&peers->hierarchy[lvl], key, value)
            const public_identity_t *peer = _peer_from_data(value);
            if (peer != NULL && uuid_compare(peer->uuid, uuid) == 0)
                return peer;
        map_end_for_each
    }
    return NULL;
}

/* Frama-C: skipped — [solver-timeout] array iteration preconditions */
const public_identity_t *peers_find_by_address(peers_t *peers, const char *address)
{
    /* Strip CIDR suffix if present (mirrors Python behavior) */
    char addr_buf[ADDR_LEN + 1];
    const char *slash = strchr(address, '/');
    if (slash != NULL)
    {
        size_t len = (size_t)(slash - address);
        if (len > ADDR_LEN)
            len = ADDR_LEN;
        memcpy(addr_buf, address, len);
        addr_buf[len] = '\0';
        address = addr_buf;
    }

    for (int lvl = 0; lvl < LEVELS; lvl++)
    {
        map_key_t key;
        data_t *value;
        map_entries_for_each(&peers->hierarchy[lvl], key, value)
            const public_identity_t *peer = _peer_from_data(value);
            if (peer != NULL && strcmp(peer->address, address) == 0)
                return peer;
        map_end_for_each
    }
    return NULL;
}

int peers_find_top_n(peers_t *peers, int n, const public_identity_t **out, int *out_count)
{
    int count = 0;
    for (int vlvl = 0; vlvl < VALUES && count < n; vlvl++)
    {
        map_key_t key;
        data_t *value;
        map_entries_for_each(&peers->valuations[vlvl], key, value)
            if (count >= n)
                break;
            const public_identity_t *peer = _peer_from_data(value);
            if (peer != NULL)
                out[count++] = peer;
        map_end_for_each
    }
    *out_count = count;
    return 0;
}

int peers_add(peers_t *peers, const public_identity_t *who, int level)
{
    if (level < 0)
        level = PEERS_MID_LEVEL;
    if (level >= LEVELS)
        return EINVAL;

    map_key_t nick = (map_key_t)who->nickname;

    /* Store as bytes in hierarchy map (keyed by nickname, matching Python _index_by) */
    data_t *val = bytes_data((bytes_t)who, sizeof(public_identity_t));
    if (val == NULL)
        return ENOMEM;
    int err = map_set(&peers->hierarchy[level], nick, val);
    if (err != 0)
        return err;

    /* Also store in lowest valuation level */
    data_t *val2 = bytes_data((bytes_t)who, sizeof(public_identity_t));
    if (val2 == NULL)
        return ENOMEM;
    return map_set(&peers->valuations[VALUES - 1], nick, val2);
}

/* Frama-C: skipped — [solver-timeout] smrt_ptr/array container preconditions */
int peers_delete(peers_t *peers, const public_identity_t *who)
{
    map_key_t nick = (map_key_t)who->nickname;

    /* Remove from hierarchy (search all levels) */
    for (int lvl = 0; lvl < LEVELS; lvl++)
    {
        data_t *val = NULL;
        if (map_get(&peers->hierarchy[lvl], nick, &val) == 0)
        {
            map_remove(&peers->hierarchy[lvl], nick);
            break;
        }
    }

    /* Remove from valuation (search all levels) */
    for (int vlvl = 0; vlvl < VALUES; vlvl++)
    {
        data_t *val = NULL;
        if (map_get(&peers->valuations[vlvl], nick, &val) == 0)
        {
            map_remove(&peers->valuations[vlvl], nick);
            break;
        }
    }

    return 0;
}

/* Frama-C: skipped — [solver-timeout] smrt_ptr/array container preconditions */
int peers_promote(peers_t *peers, const public_identity_t *who)
{
    map_key_t nick = (map_key_t)who->nickname;

    for (int vlvl = 0; vlvl < VALUES; vlvl++)
    {
        data_t *val = NULL;
        if (map_get(&peers->valuations[vlvl], nick, &val) == 0)
        {
            if (vlvl > 0)
            {
                /* Move up one valuation level */
                map_set(&peers->valuations[vlvl - 1], nick, val);
                map_remove(&peers->valuations[vlvl], nick);
            }
            return 0;
        }
    }

    /* Not found in any valuation level; add at lowest (matches Python fallback) */
    data_t *val = bytes_data((bytes_t)who, sizeof(public_identity_t));
    if (val == NULL)
        return ENOMEM;
    return map_set(&peers->valuations[VALUES - 1], nick, val);
}

/* Frama-C: skipped — [solver-timeout] smrt_ptr/array container preconditions */
int peers_demote(peers_t *peers, const public_identity_t *who)
{
    map_key_t nick = (map_key_t)who->nickname;

    for (int vlvl = 0; vlvl < VALUES; vlvl++)
    {
        data_t *val = NULL;
        if (map_get(&peers->valuations[vlvl], nick, &val) == 0)
        {
            if (vlvl < VALUES - 1)
            {
                /* Move down one valuation level */
                map_set(&peers->valuations[vlvl + 1], nick, val);
            }
            else
            {
                /* At lowest level: evict entirely (matches Python behavior) */
                peers_delete(peers, who);
                return 0;
            }
            map_remove(&peers->valuations[vlvl], nick);
            return 0;
        }
    }
    return 0;
}

int peers_count(peers_t *peers)
{
    int count = 0;
    for (int lvl = 0; lvl < LEVELS; lvl++)
        count += (int)map_size(&peers->hierarchy[lvl]);
    return count;
}

void peers_free(peers_t *peers)
{
    if (peers == NULL)
        return;
    for (int i = 0; i < LEVELS; i++)
        map_free(&peers->hierarchy[i]);
    for (int i = 0; i < VALUES; i++)
        map_free(&peers->valuations[i]);
}
