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

#ifndef DATA_PRIV_H
#define DATA_PRIV_H

#include <jansson.h>

#include "data.h"
#include "structures/data.pb-c.h"

int data_sync_out(data_t *data, AutonomousTrust__Core__Protobuf__Structures__Data *pdata);

void data_proto_free(AutonomousTrust__Core__Protobuf__Structures__Data *pdata);

int data_sync_in(AutonomousTrust__Core__Protobuf__Structures__Data *pdata, data_t *data);

int data_to_json(const void *data_struct, json_t **obj_ptr);

int data_from_json(const json_t *obj, void *data_struct);


#define EDAT_SER_OBJ 216
DECLARE_ERROR(EDAT_SER_OBJ, "Serializing arbitrary data objects not allowed")

#define EDAT_DSER_OBJ 217
DECLARE_ERROR(EDAT_DSER_OBJ, "De-serializing arbitrary data objects not allowed")

#endif  // DATA_PRIV_H
