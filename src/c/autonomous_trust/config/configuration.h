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

/** @addtogroup public_api
 *  @{
 */

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
 * @brief On-disk serialization mode for configuration files.
 *
 * Wire values match Python's `SerializeMode` enum
 * (`core/_python/config/configuration.py:52`) so a `AT_SERIALIZE_MODE`
 * env var set against either implementation picks the same path.
 * - @ref AT_SERIALIZE_PROTO  — binary `.cfg.pb` via protobuf-c.
 * - @ref AT_SERIALIZE_JSON   — pretty `.cfg.json` via jansson (default).
 * - @ref AT_SERIALIZE_PJSON  — `.cfg.json` extension but protobuf-derived
 *                              JSON shape; treated identically to JSON
 *                              by the C reader (jansson handles both).
 */
typedef enum {
    AT_SERIALIZE_PROTO = 1,
    AT_SERIALIZE_JSON  = 2,
    AT_SERIALIZE_PJSON = 3,
} at_serialize_mode_t;

/**
 * @brief Read the active serialize mode from the `AT_SERIALIZE_MODE`
 *        env var (cached after first call). Defaults to
 *        @ref AT_SERIALIZE_JSON when unset or unparseable.
 */
at_serialize_mode_t at_serialize_mode_current(void);

/**
 * @brief Return the file extension for @p mode (`".cfg.pb"` or
 *        `".cfg.json"`). Returns a static string; do not free.
 */
const char *at_serialize_mode_file_ext(at_serialize_mode_t mode);

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
 * @brief Registration entry for a named configuration section.
 *
 * One entry per config section registered via DEFINE_CONFIGURATION(). The
 * @c to_json / @c from_json callbacks marshal between the section's C
 * struct and its on-disk JSON representation.
 */
typedef struct
{
    const char *name;                                                      /**< Section name (JSON key). */
    int (*to_json)(const void *data_struct, json_t **obj_ptr);             /**< Serialize @c data_struct → JSON. */
    int (*from_json)(const json_t *obj, void *data_struct);                /**< Parse JSON → @c data_struct. */
    size_t data_len;                                                       /**< Size of the backing struct in bytes. */
    void *data_struct;                                                     /**< Pointer to the backing struct. */
    /** Optional: serialize @c data_struct → packed protobuf bytes. NULL
     *  means the config has no proto serializer yet — write_config_file
     *  in PROTO mode falls back to the JSON path with a one-time warning.
     *  Caller frees @c *buf_out. */
    int (*to_proto)(const void *data_struct, void **buf_out, size_t *len_out);
    /** Optional: parse packed protobuf bytes → @c data_struct. NULL
     *  means the config has no proto deserializer yet. */
    int (*from_proto)(const void *buf, size_t len, void *data_struct);
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
 * @brief Register a named configuration section at program startup.
 *
 * Emits a `__attribute__((constructor))` function that appends an entry to
 * @c configuration_table before main() runs. Use once per config section
 * in the translation unit that owns the backing struct.
 *
 * @param cfg_name    Unquoted identifier used as the JSON section name.
 * @param to          @c to_json callback (see @ref config_t).
 * @param from        @c from_json callback.
 * @param len         @c sizeof the backing struct.
 * @param struct_ptr  Address of the backing struct instance.
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
 * @brief Load a single config file into the provided struct.
 *
 * Looks up the matching registered @ref config_t by the file's section name
 * and invokes its @c from_json callback.
 *
 * @param[in]  filename     Absolute or cfg-relative path to the JSON file.
 * @param[out] data_struct  Struct matching the section's registered layout.
 * @return 0 on success, non-zero on I/O, parse, or dispatch failure.
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
 * @brief Write a struct back to its on-disk JSON config file.
 *
 * @param[in] config       Registration entry identifying the section.
 * @param[in] data_struct  Populated struct matching @p config->data_struct layout.
 * @param[in] filename     Destination path.
 * @return 0 on success, non-zero on I/O or serialization failure.
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
 * @brief Error: no config implementation registered for the given name.
 */
#define ECFG_NOIMPL 206
DECLARE_ERROR(ECFG_NOIMPL, "No config implementation registered for the given name");

/**
 * @brief Error: configuration file is malformed.
 */
#define ECFG_BADFMT 207
DECLARE_ERROR(ECFG_BADFMT, "Configuration incorrectly formatted")

#ifdef __cplusplus
} // extern "C"
#endif


/** @} */ /* end of public_api */

#endif  // CONFIGURATION_H
