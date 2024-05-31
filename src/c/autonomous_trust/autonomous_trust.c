#include <stdio.h>
#include <stdbool.h>
#include <errno.h>

#include "utilities/message.h"
#include "utilities/logger.h"
#include "config/sighandler.h"
#include "config/processes.h"
#include "structures/array.h"
#include "structures/map.h"
#include "autonomous_trust.h"

void reread_configs() { /* do nothing */ }

void user1_handler() { /* do nothing */ }

void user2_handler() { /* do nothing */ }

int run_autonomous_trust(msgq_key_t q_in, msgq_key_t q_out,
                         void *capabilities, size_t cap_len, // FIXME from config file?
                         log_level_t log_level, char log_file[])
{
    // FIXME pass in/register capabilities
    int error = 0;
    char cfg_dir[256] = {0};
    get_cfg_dir(cfg_dir);
    char data_dir[256] = {0};
    get_data_dir(data_dir);

    daemonize(data_dir, 0);
    char *name = "AutonomousTrust";
    logger_t logger;
    logger_init(&logger, log_level, log_file);
    log_info(&logger, "\nYou are using\033[94m AutonomousTrust\033[00m v%s from\033[96m TekFive\033[00m.\n", VERSION);

    tracker_t *tracker;
    char tracker_cfg[256];
    tracker_config(tracker_cfg);
    tracker_from_file(tracker_cfg, &logger, &tracker);

    map_t *configs;
    map_create(&configs);
    int count = num_config_files(cfg_dir);
    char **config_files = calloc(count, 256);
    all_config_files(cfg_dir, config_files);
    for (int i = 0; i < count * 256; i += 256)
    {
        char *filepath = config_files[i];
        char *filename = strrchr(filepath, '/');
        if (strncmp(filename, default_tracker_filename, 256) == 0)
            continue;
        char cfg_name[256];
        char *ext = strrchr(filename, '.');
        strncpy(cfg_name, filename, strlen(filename) - strlen(ext));
        config_t *config = find_configuration(cfg_name);
        void *data_struct = config->data_struct;
        read_config_file(filepath, data_struct);
        map_set(configs, cfg_name, data_struct);
    }

    map_t *queues;
    map_create(&queues);
    map_t *signals;
    map_create(&signals);
    array_t *process_names = map_keys(tracker->registry);
    int idx;
    array_data_t name_val;
    int p = 0;
    array_for_each(process_names, idx, name_val) char *name = (char *)name_val;
        msgq_key_t *mk = malloc(sizeof(msgq_key_t));
        *mk = ftok(tracker_cfg, p++);
        map_set(queues, name, mk);
        mk = malloc(sizeof(int));
        *mk = ftok(tracker_cfg, p++);
        map_set(signals, name, mk);
    array_end_for_each()

    map_key_t key;
    map_data_t run_val;
    array_t *keys;
    map_entries_for_each(tracker->registry, key, run_val)
        handler_ptr_t runner = (handler_ptr_t)run_val;
        log_info(&logger, "%s:  Starting %s ...", name, key);
        process_t proc;
        process_init(&proc, key, configs, tracker, &logger, NULL);
        msgq_key_t signal = *(int *)map_get(signals, key);
        runner(&proc, queues, signal); // spawn process
    map_end_for_each()
    msgq_key_t *mk = malloc(sizeof(msgq_key_t));
    if (mk == NULL)
    {
        error = ENOMEM;
        goto signal_quit;
    }
    *mk = q_in;
    map_set(queues, "extern_in", mk);
    mk = malloc(sizeof(msgq_key_t));
    *mk = q_out;
    map_set(queues, "extern_out", mk);

    map_t *signal_ids;
    map_create(&signal_ids);
    int *int_val;
    map_entries_for_each(signals, key, int_val)
        msgq_key_t mk = *int_val;
        msgq_key_t *mp = malloc(sizeof(msgq_key_t));
        if (mp == NULL)
        {
            error = ENOMEM;
            goto cleanup;
        }
        *mp = msgq_create(mk);
        map_set(signal_ids, key, mp);
    map_end_for_each()
    map_t *queue_ids;
    map_create(&queue_ids);
    map_entries_for_each(queues, key, int_val)
        msgq_key_t mk = *int_val;
        msgq_key_t *mp = malloc(sizeof(msgq_key_t));
        *mp = msgq_create(mk);
        map_set(queue_ids, key, mp);
    map_end_for_each()

        log_info(&logger, "%s:                                          Ready.", name);

    while (!stop_process)
    {
        // monitor processes
        // handle messages (extern)
        // handle results (intern)
        // tasking
        // sleep
        break;
    }

signal_quit:
    int *q_val;
    signal_buf_t sig = {SIGNAL, {"quit", -1}};
    map_entries_for_each(signal_ids, key, q_val) if (*q_val != 0)
        msgsnd(*q_val, &sig, sizeof(signal_buf_t), 0);
    map_end_for_each()
    
cleanup:
    map_free(queue_ids);
    map_free(signal_ids);
    map_free(queues);
    map_free(signals);

    return error;
}
