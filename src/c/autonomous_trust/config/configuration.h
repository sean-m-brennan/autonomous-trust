#ifndef CONFIGURATION_H
#define CONFIGURATION_H

#include <stdio.h>

#include <jansson.h>

#include "structures/array.h"
#include "utilities/exception.h"

#define CFG_PATH_LEN 256

/**
 * @brief Get the config directory
 *
 * @param path char[256]
 * @return int
 */
int get_cfg_dir(char path[]);

/**
 * @brief Get the data directory
 *
 * @param path char[256]
 * @return int
 */
int get_data_dir(char path[]);

// #ifndef PUBLIC_INTERFACE

/**
 * @brief
 *
 * @param path
 * @return int
 */
int num_config_files(char path[]);

/**
 * @brief
 *
 * @param dir
 * @param paths
 * @return int
 */
int all_config_files(char dir[], array_t *paths);

/**
 * @brief Configuration names cannot exceed this many characters
 *
 */
#define CFG_NAME_SIZE 128

/**
 * @brief
 *
 * @param path_in
 * @param path_out
 * @return int
 */
int config_absolute_path(const char *path_in, char *path_out);

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
 * @param name
 * @return config_t*
 */
config_t *find_configuration(const char *name) __attribute__((used));

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

// #endif // !PUBLIC_INTERFACE

#endif  // CONFIGURATION_H
