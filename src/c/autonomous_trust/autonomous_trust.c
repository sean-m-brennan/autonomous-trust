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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "version.h"
#include "utilities/message.h"
#include "utilities/logger.h"
#include "config/sighandler.h"
#include "config/configuration_priv.h"
#include "processes/processes.h"
#include "processes/process_tracker.h"
#include "structures/array_priv.h"
#include "structures/map_priv.h"
#include "config/protobuf_shutdown.h"

#define PROC_NAMELEN 16

#define MAX_CONFIGS 64


void reread_configs() { /* do nothing */ }

void user1_handler() { /* do nothing */ }

void user2_handler() { /* do nothing */ }

int set_process_name(const char *name_in)
{
    char name[PROC_NAMELEN] = {0};
    strncpy(name, name_in, PROC_NAMELEN-1);
    pthread_t tid = pthread_self();
    return pthread_setname_np(tid, name);
}


int run_autonomous_trust(msgq_key_t q_in, msgq_key_t q_out,
                         void *capabilities, size_t cap_len, // FIXME from config file?
                         log_level_t log_level, char log_file[])
{
    // FIXME pass in/register capabilities
    const long cadence = 500000L; // microseconds
    int error = 0;
    char cfg_dir[256] = {0};
    get_cfg_dir(cfg_dir);
    char data_dir[256] = {0};
    get_data_dir(data_dir);

    int fd1 = 0;
    int fd2 = 0;
    int flags = 0;
    if (log_file == NULL)
        flags |= NO_STDERR_REDIRECT;
    if (false) {
    int pid = daemonize(data_dir, flags, &fd1, &fd2);
    if (pid != 0)
        return pid;
    }

    const char *name = "AutonomousTrust";
    logger_t logger;
    logger_init(&logger, log_level, log_file);
    log_info(&logger, "You are using\033[94m AutonomousTrust\033[00m v%s from\033[96m TekFive\033[00m.\n", VERSION);
    if (set_process_name(name) < 0)
        log_error(&logger, "%s: Setting title failed: %s\n", name, strerror(errno));

    // setup tracker which loads process implementations to run
    tracker_t tracker;
    tracker_init(&logger, &tracker);
    char tracker_cfg[CFG_PATH_LEN + 1];
    tracker_config(tracker_cfg);
    read_config_file(tracker_cfg, &tracker);

    // read all other config files (peers, group, etc)
    map_t *configs = NULL;
    map_create(&configs);
    array_t config_files = {0};
    array_init(&config_files);
    all_config_files(cfg_dir, &config_files);

    for (size_t i = 0; i < array_size(&config_files); i++)
    {
        data_t *str_dat;
        array_get(&config_files, i, &str_dat);
        char *filepath;
        int err = data_string_ptr(str_dat, &filepath);
        if (err != 0)
            continue;
        if (filepath == NULL)
            continue;
        char abspath[256];
        err = config_absolute_path(filepath, abspath);
        if (err != 0)
            continue;
        char *filename = strrchr(filepath, '/');
        if (filename == NULL)
            filename = filepath;

        if (strncmp(filename, default_tracker_filename, 256) == 0)
            continue;
        char cfg_name[256] = {0};
        char *ext = strchr(filename, '.');
        int extlen = 0;
        if (ext != NULL)
            extlen = strlen(ext);
        strncpy(cfg_name, filename, strlen(filename) - extlen);
        config_t *config = find_configuration(cfg_name);
        if (config == NULL) {
            log_error(&logger, "No config for %s\n", cfg_name);
            continue;
        }
        config->data_struct = malloc(config->data_len);
        if (config->data_struct == NULL)
            return ENOMEM;
        read_config_file(abspath, config->data_struct);  // FIXME error handling
        data_t *ds = object_ptr_data(config, sizeof(config_t));
        map_set(configs, cfg_name, ds);
    }

    // master lists of messaging/signalling queue keys (for passing to procs, not the queues themselves)
    map_t q_keys;
    map_init(&q_keys);
    map_t s_keys;
    map_init(&s_keys);
    array_t *process_names = map_keys(tracker.registry);
    size_t idx;
    data_t *name_val;
    int p = 0;
    array_for_each(process_names, idx, name_val)
        char *pname;
        data_string_ptr(name_val, &pname);  // FIXME
        msgq_key_t mk = ftok(tracker_cfg, p++);
        data_t *mk_dat = integer_data(mk);
        map_set(&q_keys, (char*)name, mk_dat);
        msgq_key_t mks = ftok(tracker_cfg, p++);
        data_t *mks_dat = integer_data(mks);
        map_set(&s_keys, (char*)name, mks_dat);
    array_end_for_each

    // spawn processes per tracker config
    map_key_t key = NULL;
    data_t *impl_val = NULL;
    map_t procs;
    map_init(&procs);
    map_entries_for_each(tracker.registry, key, impl_val)  // FIXME wrong
        char *impl;
        data_string_ptr(impl_val, &impl);  // FIXME this is null
        handler_ptr_t runner = find_process(impl);
        if (runner == NULL) {
            log_error(&logger, "Invalid runner for %s\n", key);
            continue;
        }
        
        log_info(&logger, "%s:  Starting %s:%s ...\n", name, key, impl);
        process_t proc;
        process_init(&proc, key, configs, &tracker, &logger, NULL);
        data_t *sig_dat;
        map_get(&s_keys, key, &sig_dat);
        int sig;
        data_integer(sig_dat, &sig);
        pid_t pid = runner(&proc, &q_keys, sig);

        // record pids for monitoring
        char pid_str[32] = {0};
        snprintf(pid_str, 31, "%d", pid);
        data_t *key_val = string_data(key, strlen(key));
        map_set(&procs, pid_str, key_val);
    map_end_for_each

    // message queue keys from the parent process
    data_t *mk_in_dat = integer_data(q_in);
    map_set(&q_keys, (char*)"extern_in", mk_in_dat);
    data_t *mk_out_dat = integer_data(q_out);
    map_set(&q_keys, (char*)"extern_out", mk_out_dat);

    // create all message queues/signals from keys (since all processes are spawned)
    map_t signals;
    map_t queues;
    map_t *both[] = { &signals, &queues };
    for (int i=0; i<2; i++) {
        map_t *map = both[i];
        map_init(map);

        map_key_t mkey;
        data_t *int_val;
        map_entries_for_each(map, mkey, int_val)
            msgq_key_t mk;
            data_integer(int_val, &mk);  // FIXME error check
            msgq_key_t mp = msgq_create(mk);
            data_t *mp_dat = integer_data(mp);
            map_set(&signals, key, mp_dat);  // FIXME error check
        map_end_for_each
    }

    log_info(&logger, "%s:                                          Ready.\n", name);
    size_t active = map_size(&procs);
    array_t unhandled_msgs;
    array_init(&unhandled_msgs);
    while (!stop_process)
    {
        // monitor processes for premature termination
        data_t *str_val;
        map_entries_for_each(&procs, key, str_val)
            pid_t pid = atoi(key);
            char *pname;
            data_string_ptr(str_val, &pname);
            int status;
            waitpid(pid, &status, WNOHANG);
            bool terminated = false;
            if (WIFEXITED(status)) {
                terminated = true;
                log_info(&logger, "%s: Process %s exited normally with status %d\n", name, pname, WEXITSTATUS(status));
            }
            if (WIFSIGNALED(status)) {
                terminated = true;
                log_error(&logger, "%s: Process %s terminated by signal %d\n", name, pname, strsignal(WTERMSIG(status)));
            }
            if (WIFSTOPPED(status))
                log_warn(&logger, "%s: Process %s stopped by signal %d\n", name, pname, strsignal(WSTOPSIG(status)));
            if (WIFCONTINUED(status))
                log_warn(&logger, "%s: Process %s continued by signal SIGCONT\n", name, pname);
            if (terminated)
                active--;
        map_end_for_each

        if (active <= 0) {
            log_info(&logger, "%s: No remaining processes, exiting.\n", name);
            break;
        }

        // check for extern messages
        msgq_buf_t task_msg;
        queue_id_t extern_in = fetch_msgq(&queues, "extern_in");
        ssize_t err = msgrcv(extern_in, &task_msg, sizeof(message_t), 0, IPC_NOWAIT);
        if (err == -1)
        {
            if (errno != ENOMSG)
                log_error(&logger, "Messaging error: %s\n", strerror(errno));
        } else {
            // FIXME handling tasking from extern
            // parse task
            // send task to proper process
        }

        bool do_send = false;
        msgq_buf_t result_msg;
        data_t *int_val = NULL;
        // FIXME get results from internal procs
        map_entries_for_each(&queues, key, int_val)
            queue_id_t qid;
            data_integer(int_val, &qid);
            ssize_t merror = msgrcv(qid, &result_msg, sizeof(message_t), 0, IPC_NOWAIT);
            if (merror == -1)
            {
                if (errno != ENOMSG)
                    log_error(&logger, "Messaging error: %s\n", strerror(errno));
            } else {
                data_t *msg_dat = object_ptr_data(&result_msg, sizeof(message_t));  // FIXME malloc
                array_append(&unhandled_msgs, msg_dat);
            }
        map_end_for_each

        array_t extern_msgs;
        array_init(&extern_msgs);
        int index;
        data_t *msg_dat;
        array_for_each(&unhandled_msgs, index, msg_dat)
            // FIXME handle msg
            array_remove(&unhandled_msgs, msg_dat);
            if (false) {
                array_append(&extern_msgs, msg_dat);
                do_send = true;
            }
        array_end_for_each

        if (do_send)
        {
            queue_id_t extern_out = fetch_msgq(&queues, "extern_out");
            err = msgsnd(extern_out, &result_msg, sizeof(message_t), result_msg.mtype);
            if (err != 0)
                log_error(&logger, "Messaging error: %s\n", strerror(errno));
        }

        usleep(cadence);
    }
    log_debug(&logger, "%s: Shutdown.\n", name);

//signal_quit:
    log_debug(&logger, "Send sig quit\n"); // FIXME
    data_t *q_val;
    signal_buf_t sig = { .mtype = SIGNAL, .info = { .signal = {0}, .sig = -1 } };
    strncpy(sig.info.signal, sig_quit, 31);
    map_entries_for_each(&signals, key, q_val)
        int q;
        data_integer(q_val, &q);
        if (q != 0)
            msgsnd(q, &sig, sizeof(signal_buf_t), 0);
    map_end_for_each

//cleanup:
    log_debug(&logger, "Free\n"); // FIXME
    map_free(&signals);
    map_free(&queues);
    map_free(&s_keys);
    map_free(&q_keys);
    tracker_free(&tracker);
    if (fd1 > 0)
        close(fd1);
    if (fd2 > 0)
        close(fd2);
    shutdown_protobuf_library();

    return error;
}
