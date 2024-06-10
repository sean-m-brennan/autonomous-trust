#ifndef CONFIGURATION_H
#define CONFIGURATION_H

#include <stdio.h>

#include <jansson.h>

#include "utilities/exception.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Paths to config files cannot exceed this length
 * 
 */
#define CFG_PATH_LEN 256

/**
 * @brief Get the config directory
 *
 * @param path char[CFG_PATH_LEN]
 * @return int
 */
int get_cfg_dir(char path[]);

/**
 * @brief Get the data directory
 *
 * @param path char[CFG_PATH_LEN]
 * @return int
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
int read_config_file(const char *filename, void *data_struct);

/**
 * @brief
 *
 * @param config
 * @param data_struct
 * @param filename
 * @return int
 */
int write_config_file(const config_t *config, const void *data_struct, const char *filename);

/**
 * @brief
 *
 */
#define ECFG_NOIMPL 170

DECLARE_ERROR(ECFG_NOIMPL, "No config implementation registered for the given name");

/**
 * @brief
 *
 */
#define ECFG_BADFMT 171

DECLARE_ERROR(ECFG_BADFMT, "Configuration incorrectly formatted")

#ifdef __cplusplus
} // extern "C"
#endif

#endif  // CONFIGURATION_H
