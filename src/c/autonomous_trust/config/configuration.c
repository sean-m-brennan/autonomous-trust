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
#include "utilities/util.h"
#include "config_table_priv.h"

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
    for (int i=0; i<configuration_table_size; i++) {
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
    while (true) {
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
    while (true) {
        struct dirent *de = readdir(d);
        if (de == NULL)
            break;
        if (de->d_type == DT_REG || de->d_type == DT_UNKNOWN) {
            char *dot = strchr(de->d_name, '.');
            if (dot && (!strcmp(dot, ".cfg.jsn") || !strcmp(dot, ".cfg.json"))) {
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
    char cfg_dir[CFG_PATH_LEN];
    get_cfg_dir(cfg_dir);  // FIXME error checking?
    if (strncmp(path_in, cfg_dir, strlen(cfg_dir)) != 0) {
        int remain = snprintf(path_out, 255, "%s/%s", cfg_dir, path_in);
        if (remain < 0)
            return -1;  // FIXME set error?
    }
    return 0;
}

int read_config_file(const char *filename, void *data_struct)
{
    char typename[CFG_NAME_SIZE] = {0};
    json_t *root = json_load_file(filename, 0, NULL);
    if (root == NULL || !json_is_object(root))
        return EXCEPTION(ECFG_BADFMT);

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
    json_decref(root);  // frees created tree
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
        return EXCEPTION(EJSN_DUMP);//ECFG_BADFMT);

    json_decref(root);  // frees created tree
    return 0;
}
