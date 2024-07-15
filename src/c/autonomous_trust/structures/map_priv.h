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

#ifndef MAP_PRIV_H
#define MAP_PRIV_H

#include <stddef.h>

#include <sodium.h>
#include <jansson.h>

#include "map.h"
#include "array_priv.h"
#include "structures/map.pb-c.h"

struct map_s
{
    smrt_ptr_t;
    map_item_t *items;
    size_t length;
    size_t capacity;
    array_t keys;
    unsigned char hashkey[crypto_shorthash_KEYBYTES];
};


int map_sync_out(map_t *map, AutonomousTrust__Core__Protobuf__Structures__DataMap *dmap);

void map_proto_free(AutonomousTrust__Core__Protobuf__Structures__DataMap *dmap);

int map_sync_in(AutonomousTrust__Core__Protobuf__Structures__DataMap *dmap, map_t *map);

int map_to_json(const void *data_struct, json_t **obj_ptr);

int map_from_json(const json_t *obj, void *data_struct);

#endif  // MAP_PRIV_H
