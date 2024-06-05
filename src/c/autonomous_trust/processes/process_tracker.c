#include <errno.h>

#include <jansson.h>

#include "processes/process_tracker_priv.h"
#include "config/configuration.h"
#include "process_table.h"


const char *default_tracker_filename = "subsystems.cfg.json";


handler_ptr_t find_process(const char *name)
{
    for (int i=0; i<process_table_size; i++)
    {
        proc_map_t *entry = &process_table[i];
        if (strncmp(entry->name, name, strlen(name)) == 0)
            return entry->runner;
    }
    return NULL;
}

int find_process_name(const handler_ptr_t handler, char **name)
{
    if (handler == NULL)
        return EINVAL;
    //for (proc_map_t *entry = &__start_process_table; entry != &__stop_process_table; ++entry)
    for (int i=0; i<process_table_size; i++)
    {
        proc_map_t *entry = &process_table[i];
        if (entry->runner == handler)
            *name = entry->name;
    }
    return 0;
}

int tracker_init(logger_t *logger, tracker_t *tracker)
{
    tracker->logger = logger;
    tracker->alloc = false;
    return map_create(&tracker->registry);
}

int tracker_create(logger_t *logger, tracker_t **tracker_ptr)
{
    *tracker_ptr = calloc(1, sizeof(tracker_t));
    if (*tracker_ptr == NULL)
        return ENOMEM;
    tracker_t *tracker = *tracker_ptr;
    int err = tracker_init(logger, tracker);
    if (err != 0)
        free(tracker);
    tracker->alloc = true;
    return err;
}

int tracker_to_json(const void *data_struct, json_t **obj_ptr)
{
    tracker_t *tracker = (tracker_t *)data_struct;
    *obj_ptr = json_object();
    json_t *top_obj = *obj_ptr;
    if (top_obj == NULL)
        return ENOMEM;
    
    json_t *array_obj = json_array();
    array_t *keys = map_keys(tracker->registry);
    for (int i = 0; i < array_size(keys); i++)
    {
        json_t *obj = json_object();
        if (obj == NULL) {
            json_decref(array_obj);
            json_decref(top_obj);
            return ENOMEM;
        }
        data_t key_dat;
        array_get(keys, i, &key_dat);
        map_key_t key = key_dat.str;
        data_t value;
        map_get(tracker->registry, key, &value);
        json_t *val_str = json_string(value.str);
        if (val_str == NULL)
        {
            json_decref(obj);
            json_decref(array_obj);
            json_decref(top_obj);
            return ENOMEM;
        }
        json_object_set(obj, key, val_str);
        json_array_append(array_obj, obj);
        free(val_str);
    }
    json_object_set(top_obj, "subsystems", array_obj);
    return 0;
}

int tracker_from_json(const json_t *obj, void *data_struct)
{
    tracker_t *tracker = (tracker_t *)data_struct;
    const char *key;
    json_t *value;

    json_t *array_obj = json_object_get(obj, "subsystems");
    if (array_obj == NULL || !json_is_array(array_obj))
        return ECFG_BADFMT;

    json_object_foreach((json_t *)array_obj, key, value)
    {
        const char *val_str = json_string_value(value);
        if (val_str == NULL)
            return ECFG_BADFMT;

        data_t val_dat = sdat((char*)val_str);
        int err = map_set(tracker->registry, (char *)key, &val_dat);
        if (err != 0)
            return err;
    }
    return 0;
}

DECLARE_CONFIGURATION(process_tracker, sizeof(tracker_t), tracker_to_json, tracker_from_json);

int tracker_from_file(const char *filename, logger_t *logger, tracker_t **tracker_ptr)
{
    int err = tracker_create(logger, tracker_ptr);
    if (err != 0)
        return err;
    tracker_t *tracker = *tracker_ptr;

    return read_config_file(filename, tracker); // FIXME error logging?
}

int tracker_config(char config_file[])
{
    get_cfg_dir(config_file);
    strcat(config_file, "/");
    int len = strlen(config_file);
    strncpy(config_file + len, default_tracker_filename, 255 - len);
    return len;
}

int tracker_register_subsystem(const tracker_t *tracker, const char *name, const handler_ptr_t handler)
{
    // TODO processes plus what else?
    data_t h_dat = odat(handler);
    return map_set(tracker->registry, (char *)name, &h_dat);
}

int tracker_to_file(const tracker_t *tracker, const char *filename)
{
    config_t cfg = {
        .name = "process_tracker",
        .to_json = tracker_to_json,
        .from_json = tracker_from_json};
    return write_config_file(&cfg, tracker, filename);
}

void tracker_free(tracker_t *tracker)
{
    if (tracker != NULL)
    {
        if (tracker->registry != NULL)
            map_free(tracker->registry);
        if (tracker->alloc)
            free(tracker);
    }
}
