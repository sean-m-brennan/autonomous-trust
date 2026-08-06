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
 ********************/
#ifndef MSG_TYPES_PRIV_H
#define MSG_TYPES_PRIV_H

#include <jansson.h>

#include "structures/map.h"
#include "structures/data.h"
#include "structures/array.h"

#include "utilities/msg_types.h"

int generic_msg_to_proto(generic_msg_t *msg, void **data, size_t *data_len);
int proto_to_generic_msg(void *data, size_t data_len, generic_msg_t *msg);

int net_msg_to_proto(const net_msg_t *msg, void **data_ptr, size_t *data_len_ptr);
int proto_to_net_msg(uint8_t *data, size_t len, net_msg_t *net_msg);

int net_msg_pack_json(net_msg_t *msg, json_t *json);
int net_msg_unpack_json(const net_msg_t *msg, json_t **json);

#endif  /* MSG_TYPES_PRIV_H */
