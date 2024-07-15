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

#define _DEFAULT_SOURCE
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdbool.h>

#include <jansson.h>

#define CONFIG_IMPL

#include "configuration_priv.h"
#include "structures/array.h"
#include "utilities/exception.h"
#include "utilities/logger.h"
#include "utilities/util.h"
#include "structures/map.h"
#include "config_table_priv.h"

#define MAX_CONFIGS 64

static const char *required_configs[] = {
    "subsystems", "network", "identity",
    //"negotitation, "reputation"
};
static const int num_req_cfgs = 3;

const char ROOT_ENV_VAR[] = "AUTONOMOUS_TRUST_ROOT";

const char CFG_PATH[] = "etc/at";

const char DATA_PATH[] = "var/at";

const char *rootDir()
{
    const char *root = getenv(ROOT_ENV_VAR);
    if (root == NULL)
        root = "";
    return root;
}

int get_cfg_dir(char path[])
{
    return snprintf(path, 255, "%s/%s", rootDir(), CFG_PATH);
}

int get_data_dir(char path[])
{
    return snprintf(path, 255, "%s/%s", rootDir(), DATA_PATH);
}

config_t *find_configuration(const char *name)
{
    for (int i = 0; i < configuration_table_size; i++)
    {
        config_t *entry = &configuration_table[i];
        if (strncmp(entry->name, name, strlen(name)) == 0)
            return entry;
    }
    return NULL;
}

int num_config_files(char path[])
{
    DIR *d = opendir(path);
    if (d == NULL)
        return SYS_EXCEPTION();
    int i = 0;
    while (true)
    {
        struct dirent *de = readdir(d);
        if (de == NULL)
            break;
        i++;
    }
    return i;
}

int all_config_files(char dir[], array_t *paths)
{
    DIR *d = opendir(dir);
    if (d == NULL)
        return SYS_EXCEPTION();
    int i = 0;
    while (true)
    {
        struct dirent *de = readdir(d);
        if (de == NULL)
            break;
        if (de->d_type == DT_REG || de->d_type == DT_UNKNOWN)
        {
            char *dot = strchr(de->d_name, '.');
            if (dot && (!strcmp(dot, ".cfg.jsn") || !strcmp(dot, ".cfg.json")))
            {
                char *path = malloc(CFG_PATH_LEN + 1);
                if (path == NULL)
                    return SYS_EXCEPTION();
                strncpy(path, de->d_name, CFG_PATH_LEN);
                data_t *str_dat = string_data(path, strlen(path));
                int err = array_append(paths, str_dat);
                if (err != 0)
                    return err;
                i++;
            }
        }
    }
    closedir(d);
    return 0;
}

int config_absolute_path(const char *path_in, char *path_out)
{
    char cfg_dir[CFG_PATH_LEN + 1];
    get_cfg_dir(cfg_dir); // FIXME error checking?
    if (strncmp(path_in, cfg_dir, strlen(cfg_dir)) != 0)
    {
        int remain = snprintf(path_out, 255, "%s/%s", cfg_dir, path_in);
        if (remain < 0)
            return -1; // FIXME set error?
    }
    return 0;
}

int read_config_file(const char *filename, void *data_struct)
{
    char typename[CFG_NAME_SIZE + 1] = {0};
    json_t *root = json_load_file(filename, 0, NULL);
    if (root == NULL || !json_is_object(root))
        return EXCEPTION(ECFG_BADFMT);  // FIXME 'network'

    json_t *name_obj = json_object_get(root, "typename");
    if (name_obj == NULL || !json_is_string(name_obj))
    {
        json_decref(root);
        return EXCEPTION(ECFG_BADFMT);
    }
    strncpy(typename, json_string_value(name_obj), CFG_NAME_SIZE - 1);
    json_decref(name_obj);

    config_t *cfg = find_configuration(typename);
    if (cfg == NULL)
        return EXCEPTION(ECFG_NOIMPL);

    int err = cfg->from_json(root, data_struct);
    json_decref(root); // frees created tree
    return err;
}

int write_config_file(const config_t *cfg_obj, const void *data_struct, const char *filename)
{
    json_t *root;
    int err = cfg_obj->to_json(data_struct, &root);
    if (err != 0)
        return err;

    err = json_dump_file(root, filename, 0);
    if (err != 0)
        return EXCEPTION(EJSN_DUMP); // ECFG_BADFMT);

    json_decref(root); // frees created tree
    return 0;
}

int load_all_configs(char *cfg_dir, map_t *configs, logger_t *logger)
{
    // read all other config files (peers, group, etc)
    if (map_init(configs) != 0)
    {
        log_exception(logger);
        return -1;
    }
    array_t config_files = {0};
    if (array_init(&config_files) != 0)
    {
        log_exception(logger);
        return -1;
    }
    if (all_config_files(cfg_dir, &config_files) != 0)
    {
        log_exception(logger);
        return -1;
    }
    int num_err = 0;
    int required = num_req_cfgs - 1;  // process tracker already loaded

    for (size_t i = 0; i < array_size(&config_files); i++)
    {
        data_t *str_dat;
        if (array_get(&config_files, i, &str_dat) != 0)
        {
            log_exception(logger);
            num_err++;
            continue;
        }
        char *filepath;
        if (data_string_ptr(str_dat, &filepath) != 0)
        {
            log_exception(logger);
            num_err++;
            continue;
        }

        config_t *config;
        char cfg_name[CFG_NAME_SIZE + 1] = {0};
        if (load_config(filepath, &config, cfg_name, logger) < 0)
            return -1;

        for (int j = 0; j < num_req_cfgs; j++)
        {
            if (strncmp(cfg_name, required_configs[j], CFG_NAME_SIZE) == 0)
            {
                required--;
                break;
            }
        }
        data_t *ds = object_ptr_data(config, sizeof(config_t));
        if (map_set(configs, cfg_name, ds) != 0)
        {
            log_exception(logger);
            num_err++;
        }
    }
    if (required > 0)
        log_error(logger, "%d required configurations not found\n", required);
    return num_err;
}

int load_config(char *filepath, config_t **config_ptr, char *cfg_name, logger_t *logger)
{
    if (filepath == NULL)
    {
        return EXCEPTION(EINVAL);
    }
    char abspath[CFG_PATH_LEN + 1];
    if (config_absolute_path(filepath, abspath) != 0)
    {
        return -1;
    }
    char *filename = strrchr(filepath, '/');
    if (filename == NULL)
        filename = filepath;

    if (strncmp(filename, default_tracker_filename, CFG_PATH_LEN) == 0)
        return 0; // skip tracker cfg, already loaded
    char *ext = strchr(filename, '.');
    int extlen = 0;
    if (ext != NULL)
        extlen = strlen(ext);
    char cfg_name_stack[CFG_NAME_SIZE + 1] = {0};
    if (cfg_name == NULL)
        cfg_name = cfg_name_stack;
    strncpy(cfg_name, filename, min(CFG_PATH_LEN - 1, strlen(filename) - extlen));
    *config_ptr = find_configuration(cfg_name);
    config_t *config = *config_ptr;
    if (config == NULL)
    {
        log_error(logger, "No config for %s\n", cfg_name);
        return -1;
    }
    config->data_struct = smrt_create(config->data_len); // FIXME needs freed
    if (config->data_struct == NULL)
        return EXCEPTION(ENOMEM);
    if (read_config_file(abspath, config->data_struct) != 0)
    {
        log_exception_extra(logger, " for config named '%s'\n", cfg_name);
        return -1;
    }
    return 0;
}