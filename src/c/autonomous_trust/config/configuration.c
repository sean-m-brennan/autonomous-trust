#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <dirent.h>
#include <stdbool.h>

#include <jansson.h>

#include "configuration.h"
#include "serialization.h"

const char ROOT_ENV_VAR[] = "AUTONOMOUS_TRUST_ROOT";

const char CFG_PATH[] = "etc/at";

const char DATA_PATH[] = "var/at";

extern config_t __start_configuration_table;
extern config_t __stop_configuration_table;

char *rootDir()
{
    char *root = getenv(ROOT_ENV_VAR);
    if (root == NULL)
        root = "/";
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

__attribute__((used)) config_t *find_configuration(const char *name)
{
    for (config_t *entry = &__start_configuration_table; entry != &__stop_configuration_table; ++entry)
    {
        if (strncmp(entry->name, name, strlen(name) == 0))
            return entry;
    }
    return NULL;
}

int num_config_files(char path[])
{
    DIR *d = opendir(path);
    if (d == NULL)
        return -1;
    int i = 0;
    while (true) {
        struct dirent *de = readdir(d);
        if (de == NULL)
            break;
        i++;
    }
    return i;
}

int all_config_files(char dir[], char **paths)
{
    DIR *d = opendir(dir);
    if (d == NULL)
        return ENOENT;
    int i = 0;
    while (true) {
        struct dirent *de = readdir(d);
        if (de == NULL)
            break;
        if (de->d_type == DT_REG) {
            char *dot = strrchr(de->d_name, '.');
            if (dot && (!strcmp(dot, ".jsn") || !strcmp(dot, ".json"))) {
                strncpy(paths[i], de->d_name, 256);
                i++;
            }
        }
    }
    closedir(d);
    return 0;
}

int read_config_file(const char *filename, void *data_struct)
{
    file_mapping_t mapping;
    ssize_t data_err = readable_file_mapping(filename, &mapping);
    if (data_err != 0)
        return data_err;

    char typename[CFG_NAME_SIZE] = {0};
    json_t *root = json_loadb((const char *)mapping.data, mapping.data_len, 0, NULL);
    if (root == NULL || !json_is_object(root)) {
        demap_file(&mapping);
        return ECFG_BADFMT;
    }
    json_t *name_obj = json_object_get(root, "typename");
    if (name_obj == NULL || !json_is_string(name_obj))
    {
        free(root);
        demap_file(&mapping);
        return ECFG_BADFMT;
    }
    strncpy(typename, json_string_value(name_obj), CFG_NAME_SIZE - 1);
    json_decref(name_obj);
    demap_file(&mapping);

    config_t *cfg = find_configuration(typename);
    if (cfg == NULL)
        return ECFG_NOIMPL;

    int err = cfg->from_json(root, data_struct);
    json_decref(root);  // frees created tree
    return err;
}

int write_config_file(const config_t *cfg_obj, const void *data_struct, const char *filename)
{
    file_mapping_t mapping;
    int err = writeable_file_mapping(filename, &mapping);
    if (err != 0)
        return err;

    json_t *root;
    err = cfg_obj->to_json(data_struct, &root);
    if (err != 0)
        return err;
    err = json_dumpb(root, (char*)mapping.data, mapping.data_len, 0);
    json_decref(root);  // frees created tree
    return err;
}
