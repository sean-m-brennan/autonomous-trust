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

#ifndef PEERS_H
#define PEERS_H

#include "structures/map_priv.h"

#define LEVELS 3
#define VALUES 10

typedef struct {
    map_t hierarchy[LEVELS];
    map_t valuations[VALUES];
} peers_t;

int peers_to_json(const void *data_struct, json_t **obj_ptr);
int peers_from_json(const json_t *obj, void *data_struct);

#endif  // PEERS_H
