#include <errno.h>

#include <jansson.h>

#include "processes/process_tracker_priv.h"
#include "config/configuration_priv.h"
#include "utilities/util.h"
#include "utilities/exception.h"
#include "process_table_priv.h"

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

char *find_process_name(const handler_ptr_t handler)
{
    if (handler == NULL)
        return NULL;
    for (int i=0; i<process_table_size; i++)
    {
        proc_map_t *entry = &process_table[i];
        if (entry->runner == handler)
            return (char*)entry->name;
    }
    return NULL;
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
        return EXCEPTION(ENOMEM);
    tracker_t *tracker = *tracker_ptr;
    int err = tracker_init(logger, tracker);
    if (err != 0) {
        free(tracker);
        return err;
    }
    tracker->alloc = true;
    return err;
}

int tracker_to_json(const void *data_struct, json_t **obj_ptr)
{
    tracker_t *tracker = (tracker_t *)data_struct;
    *obj_ptr = json_object();
    json_t *top_obj = *obj_ptr;
    if (top_obj == NULL)
        return EXCEPTION(ENOMEM);

    json_t *name_str = json_string("process_tracker");
    if (name_str == NULL) {
        json_decref(top_obj);
        return EXCEPTION(ENOMEM);
    }
    int err = json_object_set_new(top_obj, "typename", name_str);
    if (err != 0)
        return EXCEPTION(EJSN_OBJ_SET);
    
    json_t *array_obj = json_array();
    if (array_obj == NULL) {
        json_decref(top_obj);
        return EXCEPTION(ENOMEM);
    }
    array_t *keys = map_keys(tracker->registry);
    for (int i = 0; i < array_size(keys); i++)
    {
        json_t *obj = json_object();
        if (obj == NULL) {
            json_decref(array_obj);
            json_decref(top_obj);
            return EXCEPTION(ENOMEM);
        }
        // key is type, name is impl, runner is func
        data_t *key_dat;
        err = array_get(keys, i, &key_dat);
        if (err != 0)
            return err;
        map_key_t key;
        data_string_ptr(key_dat, &key);
        data_t *value;
        err = map_get(tracker->registry, key, &value);
        if (err != 0)
            return err;
        char *str_val;
        data_string_ptr(value, &str_val);
        json_t *val_str = json_string(str_val);
        if (val_str == NULL)
        {
            json_decref(obj);
            json_decref(array_obj);
            json_decref(top_obj);
            return EXCEPTION(ENOMEM);
        }
        err = json_object_set_new(obj, key, val_str);
        if (err != 0)
            return EXCEPTION(EJSN_OBJ_SET);
        err = json_array_append_new(array_obj, obj);
        if (err != 0)
            return EXCEPTION(EJSN_ARR_APP);
    }
    err = json_object_set_new(top_obj, "subsystems", array_obj);
    if (err != 0)
        EXCEPTION(EJSN_OBJ_SET);
    return err;
}

int tracker_from_json(const json_t *obj, void *data_struct)
{
    tracker_t *tracker = (tracker_t *)data_struct;

    json_t *array_obj = json_object_get(obj, "subsystems");
    if (array_obj == NULL || !json_is_array(array_obj))
        return EXCEPTION(ECFG_BADFMT);

    size_t index = 0;
    json_t *arr_value = NULL;
    json_array_foreach(array_obj, index, arr_value)
    {
        if (!json_is_object(arr_value))
            return EXCEPTION(ECFG_BADFMT);
        const char *key = NULL;
        json_t *value = NULL;
        const char *val_str = NULL;
        json_object_foreach(arr_value, key, value)
        {
            val_str = json_string_value(value);
            if (val_str == NULL)
                return EXCEPTION(ECFG_BADFMT);
            break;
        }
        if (val_str == NULL)
            return -1; //FIXME which error?
        json_incref(value);
        data_t *val_dat = string_data((char*)val_str, strlen(val_str));
        if (val_dat == NULL)
            return EXCEPTION(ENOMEM);
        int err = map_set(tracker->registry, (char *)key, val_dat);
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

    return read_config_file(filename, tracker);
}

int tracker_config(char config_file[])
{
    get_cfg_dir(config_file);
    strcat(config_file, "/");
    int len = strlen(config_file);
    strncpy(config_file + len, default_tracker_filename, CFG_PATH_LEN - len);
    return len;
}

int tracker_register_subsystem(const tracker_t *tracker, const char *name, const char *impl)
{
    data_t *impl_dat = string_data((char*)impl, strlen(impl));
    if (impl_dat == NULL)
        return EXCEPTION(ENOMEM);
    return map_set(tracker->registry, (char*)name, impl_dat);
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
