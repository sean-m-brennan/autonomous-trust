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

#ifndef CONFIGURATION_H
#define CONFIGURATION_H

#include <stdio.h>

#include <jansson.h>

#include "utilities/exception.h"
#include "utilities/logger.h"
#include "structures/map.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Paths to config files cannot exceed this length
 * 
 */
#define CFG_PATH_LEN 256
#define CFG_NAME_SIZE 64

/**
 * @brief Get the config directory
 *
 * @param path char[CFG_PATH_LEN]
 * @return int
 */
/*@
  requires \valid(path + (0 .. CFG_PATH_LEN - 1));
  assigns path[0 .. CFG_PATH_LEN - 1];
  ensures \result >= 0 || \result < 0;
*/
int get_cfg_dir(char path[]);

/**
 * @brief Get the data directory
 *
 * @param path char[CFG_PATH_LEN]
 * @return int
 */
/*@
  requires \valid(path + (0 .. CFG_PATH_LEN - 1));
  assigns path[0 .. CFG_PATH_LEN - 1];
  ensures \result >= 0 || \result < 0;
*/
int get_data_dir(char path[]);

/**
 * @brief
 *
 */
typedef struct
{
    const char *name;
    int (*to_json)(const void *data_struct, json_t **obj_ptr);
    int (*from_json)(const json_t *obj, void *data_struct);
    size_t data_len;
    void *data_struct;
} config_t;

#ifndef CONFIG_IMPL
extern config_t configuration_table[];
extern size_t configuration_table_size;
#endif

#define DECLARE_CONFIGURATION(config_name, data_size, struct_to_json, struct_from_json)

#define QUOTE(x) #x

#define _CONCAT_NEXT(x, y) x##y
#define CONCAT(x, y) _CONCAT_NEXT(x, y)

/**
 * @brief 
 * 
 */
#define DEFINE_CONFIGURATION(cfg_name, to, from, len, struct_ptr)                    \
    void __attribute__((constructor)) CONCAT(register_configuration_, __COUNTER__)() \
    {                                                                                \
        configuration_table[configuration_table_size].name = QUOTE(cfg_name);        \
        configuration_table[configuration_table_size].to_json = to;                  \
        configuration_table[configuration_table_size].from_json = from;              \
        configuration_table[configuration_table_size].data_len = len;                \
        configuration_table[configuration_table_size].data_struct = struct_ptr;      \
        configuration_table_size++;                                                  \
    }

/**
 * @brief
 *
 * @param filename
 * @param data_struct
 * @return int
 */
/*@
  requires filename != \null && \valid_read(filename);
  requires data_struct != \null && \valid(data_struct);
  assigns *((char *)data_struct);
  behavior success:
    ensures \result == 0;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int read_config_file(const char *filename, void *data_struct);

/**
 * @brief
 *
 * @param config
 * @param data_struct
 * @param filename
 * @return int
 */
/*@
  requires \valid(config);
  requires data_struct != \null && \valid_read(data_struct);
  requires filename != \null && \valid_read(filename);
  assigns \nothing;
  behavior success:
    ensures \result == 0;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int write_config_file(const config_t *config, const void *data_struct, const char *filename);

/*@
  requires name != \null && \valid_read(name);
  assigns \nothing;
  ensures \result == \null || \valid(\result);
*/
config_t *find_configuration(const char *name);

/*@
  requires filepath == \null || \valid_read(filepath);
  requires \valid(config);
  assigns *config;
  behavior null_path:
    assumes filepath == \null;
    ensures \result != 0;
  behavior success:
    assumes filepath != \null;
    ensures \result == 0 ==> *config != \null;
  disjoint behaviors;
*/
int load_config(char *filepath, config_t **config, char *cfg_name, logger_t *logger);

/*@
  requires cfg_dir != \null && \valid_read(cfg_dir);
  requires \valid(configs);
  assigns *configs;
  ensures \result >= 0 || \result == -1;
*/
int load_all_configs(char *cfg_dir, map_t *configs, logger_t *logger);

/**
 * @brief
 *
 */
#define ECFG_NOIMPL 206
DECLARE_ERROR(ECFG_NOIMPL, "No config implementation registered for the given name");

/**
 * @brief
 *
 */
#define ECFG_BADFMT 207
DECLARE_ERROR(ECFG_BADFMT, "Configuration incorrectly formatted")

#ifdef __cplusplus
} // extern "C"
#endif

#endif  // CONFIGURATION_H
