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

#ifndef ARRAY_PRIV_H
#define ARRAY_PRIV_H

#include <stddef.h>
#include <stdbool.h>

#include <jansson.h>

#include "array.h"
#include "data_priv.h"
#include "structures/data.pb-c.h"

struct array_s
{
    smrt_ptr_t;
    size_t size;
    data_t **array;
};

int array_sync_out(array_t *array, AutonomousTrust__Core__Protobuf__Structures__Data **parr, size_t *n);

void array_proto_free(AutonomousTrust__Core__Protobuf__Structures__Data **parr);

int array_sync_in(AutonomousTrust__Core__Protobuf__Structures__Data **parr, size_t n, array_t *array);

int array_to_json(const void *data_struct, json_t **obj_ptr);

int array_from_json(const json_t *obj, void *data_struct);

#endif  // ARRAY_PRIV_H
