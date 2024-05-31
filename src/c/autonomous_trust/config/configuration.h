#ifndef CONFIGURATION_H
#define CONFIGURATION_H

#include <stdio.h>

#include <jansson.h>

#include "serialization.h"

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

#ifndef PUBLIC_INTERFACE

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
int all_config_files(char dir[], char **paths);


/**
 * @brief Configuration names cannot exceed this many characters
 * 
 */
#define CFG_NAME_SIZE 128

/**
 * @brief
 *
 */
typedef struct
{
    char name[CFG_NAME_SIZE];
    void *data_struct;
    int (*to_json)(const void *data_struct, json_t **obj_ptr);
    int (*from_json)(const json_t *obj, void *data_struct);
} config_t;

#define QUOTE(str) #str

/**
 * @brief
 *
 */
#define DECLARE_CONFIGURATION(config_name, struct_to_json, struct_from_json) \
    static config_t ptr_##config_name                                        \
        __attribute((used, section("configuration_table"))) = {              \
            .name = QUOTE(config_name),                                      \
            .to_json = struct_to_json,                                       \
            .from_json = struct_from_json,                                   \
    }

/**
 * @brief 
 * 
 * @param name 
 * @return config_t* 
 */
config_t *find_configuration(const char *name);

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

/**
 * @brief
 *
 */
#define ECFG_BADFMT 171

#endif // !PUBLIC_INTERFACE

#endif // CONFIGURATION_H