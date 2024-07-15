/********************
 *  Copyright 2024 TekFive, Inc. and contributors
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
