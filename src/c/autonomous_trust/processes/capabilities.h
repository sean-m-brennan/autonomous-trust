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

#ifndef CAPABILITIES_H
#define CAPABILITIES_H

#include <stdbool.h>
#include <stdarg.h>

#include "structures/map.h"

#define MAX_CAPABILITIES 128 // # processes beyond required core

#define CAP_NAMELEN PROC_NAME_LEN

#define MAX_ARGS 10

typedef struct capability_s capability_t;

int capability_init(capability_t *capability);

capability_t *find_capability(const char *name);

#define DECLARE_CAPABILITY(config_name, data_size, struct_to_json, struct_from_json)

#define QUOTE(x) #x

/**
 * @brief Local capabilities are discovered at compile time
 *
 */
#define DEFINE_CAPABILITY(cap_name, func, args, arg_num)                          \
    void __attribute__((constructor)) CONCAT(register_capability_, __COUNTER__)() \
    {                                                                             \
        capability_init(&capability_table[capability_table_size]);                \
        capability_table[capability_table_size].name = QUOTE(cap_name);           \
        capability_table[capability_table_size].function = func;                  \
        capability_table[capability_table_size].args = args;                      \
        capability_table[capability_table_size].arg_num = arg_num;                \
        capability_table[capability_table_size].local = true;                     \
        capability_table_size++;                                                  \
    }

// FIXME to/from json for configuration of peer capabilities (local capabilities are in the code)

// FIXME build my own peer capability list for tx

#endif  // CAPABILITIES_H
