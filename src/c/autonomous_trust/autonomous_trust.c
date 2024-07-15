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
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <signal.h>

#include "version.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"
#include "utilities/logger.h"
#include "utilities/sighandler.h"
#include "config/configuration_priv.h"
#include "processes/processes.h"
#include "processes/process_tracker_priv.h"
#include "structures/array_priv.h"
#include "structures/map_priv.h"
#include "utilities/protobuf_shutdown.h"
#include "network/network.h"


void reread_configs() { /* do nothing */ }

void user1_handler() { /* do nothing */ }

void user2_handler() { /* do nothing */ }


int register_queues(tracker_t *tracker, const char *main, directory_t *queues, directory_t *signals, logger_t *logger)
{
    // setup tracker which loads process implementations to run
    if (tracker_init(logger, tracker) != 0)
    {
        log_exception(logger);
        return -1;
    }
    char tracker_cfg[CFG_PATH_LEN + 1];
    if (tracker_config(tracker_cfg) < 0)
    {
        log_exception(logger);
        return -1;
    }
    if (read_config_file(tracker_cfg, tracker) != 0)
    {
        log_exception(logger);
        return -1;
    }

    // master lists of messaging/signalling queue keys
    if (array_init(queues) != 0)
    {
        log_exception(logger);
        return -1;
    }
    if (array_init(signals) != 0)
    {
        log_exception(logger);
        return -1;
    }
    array_t *process_names = map_keys(tracker->registry);
    size_t idx;
    data_t *name_val;
    int num_err = 0;

    if (array_copy(process_names, queues) != 0)
    {
        log_exception(logger);
        return -1;
    }

    // also a queue for the main interface process (i.e. this one)
    data_t *key_dat = string_data((char *)main, strlen(main));
    if (array_append(queues, key_dat) != 0)
    {
        log_exception(logger);
        num_err++;
    }

    array_for_each(process_names, idx, name_val) char *pname;
    if (data_string_ptr(name_val, &pname) != 0)
    {
        log_exception(logger);
        num_err++;
        continue;
    }

    char sname[SIG_NAME_LEN + 1];
    process_name_to_signal(pname, sname);
    data_t *s_dat = string_data(sname, sizeof(sname));
    if (array_append(signals, s_dat) != 0)
    {
        log_exception(logger);
        num_err++;
        continue;
    }
    array_end_for_each return num_err;
}


int run_autonomous_trust(char *q_in, char *q_out,
                         capability_t *capabilities, size_t cap_len, // FIXME from config file?
                         log_level_t log_level, char log_file[])
{
    // FIXME pass in/register capabilities
    const long cadence = 500000L; // microseconds
    int error = 0;
    char cfg_dir[CFG_PATH_LEN + 1] = {0};
    get_cfg_dir(cfg_dir);
    char data_dir[CFG_PATH_LEN + 1] = {0};
    get_data_dir(data_dir);

    int fd1 = 0;
    int fd2 = 0;
    int flags = 0;
    if (log_file == NULL)
        flags |= NO_STDERR_REDIRECT;
    int err = daemonize(data_dir, flags, &fd1, &fd2);
    if (err != 0)
        return err;

    const char *name = "AutonomousTrust";
    logger_t logger = {0};
    logger_init(&logger, log_level, log_file); // FIXME quit if logger fails?
    log_info(&logger, "You are using\033[94m AutonomousTrust\033[00m v%s from\033[96m TekFive\033[00m.\n", VERSION);
    if (set_process_name(name) < 0)
        log_exception(&logger);
    init_sig_handling(&logger);
    log_debug(&logger, "AT pid %d\n", getpid());

    map_t configs = {0};
    int ret = load_all_configs(cfg_dir, &configs, &logger);
    if (ret < 0)
        return ret;
    if (ret > 0)
        ; // FIXME handle partial errors ('required' list?)

    tracker_t tracker = {0};
    directory_t queues = {0};
    directory_t signals = {0};
    ret = register_queues(&tracker, name, &queues, &signals, &logger);
    if (ret < 0)
        return ret;
    if (ret > 0)
        ; // FIXME handle partial errors

    // spawn processes per tracker config
    map_key_t key = NULL;
    data_t *impl_val = NULL;
    map_t procs;
    if (map_init(&procs) != 0)
    {
        log_exception(&logger);
        return -1;
    }
    int num_err = 0;
    map_entries_for_each(tracker.registry, key, impl_val)
    {
        char *impl;
        if (data_string_ptr(impl_val, &impl) != 0)
        {
            log_exception(&logger);
            num_err++;
            continue;
        }
        handler_ptr_t runner = find_process(impl);
        if (runner == NULL)
        {
            log_error(&logger, "Invalid runner for %s (%s)\n", key, impl);
            continue;
        }

        log_info(&logger, "%s:  Starting %s:%s ...\n", name, key, impl);
        if (start_process(key, runner, &configs, &tracker, &procs, &queues, &logger))
        {
            log_exception_extra(&logger, " for process %s:%s\n", name, key);
            num_err++;
        }
    }
    map_end_for_each
    // FIXME deal with partials

    queue_t my_q = {0};
    if (messaging_init(name, &my_q) != 0)
        log_exception(&logger);
    messaging_assign(&my_q);
    queue_t extern_q = {0};
    if (messaging_init(q_in, &extern_q) != 0)
        log_exception(&logger);

    log_info(&logger, "%s:                                          Ready.\n", name);
    size_t active = map_size(&procs);
    array_t unhandled_msgs;
    if (array_init(&unhandled_msgs) != 0)
        log_exception(&logger);
    sleep(3); // FIXME
    while (!stop_process)
    {
        // monitor processes for early termination
        data_t *str_val = NULL;
        map_entries_for_each(&procs, key, str_val)
        {
            pid_t pid = atoi(key);
            err = kill(pid, 0);
            if (err == 0)
                continue;
            if (err == -1)
            {
                if (errno == ESRCH)
                {
                    if (restart_process(pid, key, &procs, &queues, &logger))
                    {
                        log_exception_extra(&logger, " (key = '%s')\n", key);  // FIXME No such key in the map (EMAP_NOKEY)
                        // FIXME quit trying?
                    }
                }
                else
                {
                    SYS_EXCEPTION();
                    log_exception(&logger);
                    continue;
                }
            }
        }
        map_end_for_each

            if (active <= 0)
        {
            log_info(&logger, "%s: No remaining processes, exiting.\n", name);
            break;
        }

        // check for extern messages
        generic_msg_t task_msg = {0};
        ret = messaging_recv_on(&extern_q, &task_msg, NULL, false);
        if (ret == -1)
            log_exception(&logger);
        else if (ret == 0)
        {
            if (task_msg.type != TASK)
            {
                /*error*/
            }
            else
            {
                // FIXME handling tasking from extern
                // parse task
                // send task to proper process
            }
        }

        // get results from internal procs
        generic_msg_t result_msg = {0};
        ret = messaging_recv(&result_msg);
        if (ret == -1)
            log_exception(&logger);
        else if (ret == 0)
        {
            // FIXME convert to struct?
            data_t *msg_dat = object_ptr_data(&result_msg.info, message_size(result_msg.type));
            if (array_append(&unhandled_msgs, msg_dat) != 0)
                log_exception(&logger);
        }

        array_t extern_msgs = {0};
        if (array_init(&extern_msgs) != 0)
            log_exception(&logger);
        bool do_send = false;
        int index;
        data_t *msg_dat;
        array_for_each(&unhandled_msgs, index, msg_dat)
        {
            // FIXME handle msg
            if (array_remove(&unhandled_msgs, msg_dat) != 0)
                log_exception(&logger);
            if (false)
            { // FIXME
                if (array_append(&extern_msgs, msg_dat) != 0)
                    log_exception(&logger);
                do_send = true;
            }
        }
        array_end_for_each

            if (do_send)
        {
            if (messaging_send("extern_out", result_msg.type, &result_msg, false) != 0)
                log_exception(&logger);
        }

        if (usleep(cadence) == -1)
        {
            if (errno != EINTR) {
                SYS_EXCEPTION();
                log_exception(&logger);
            }
        }
    }
    log_debug(&logger, "%s: Shutdown.\n", name);

    // signal_quit:
    log_debug(&logger, "Send sig quit\n"); // FIXME
    data_t *k_val = NULL;
    int index = 0;
    generic_msg_t sig = {.type = SIGNAL, .info.signal = {.descr = {0}, .sig = -1}};
    strncpy(sig.info.signal.descr, sig_quit, 31);
    array_for_each(&signals, index, k_val)
    {
        char *skey;
        if (data_string_ptr(k_val, &skey) != 0) {
            log_exception(&logger);
            continue;
        }
        if (messaging_send(skey, SIGNAL, &sig, true) < 0)  // FIXME ECONNREFUSED
            log_exception_extra(&logger, " signalling %d - %s\n", index, skey);
    }
    array_end_for_each

        // cleanup:
        log_debug(&logger, "Shutdown\n"); // FIXME
    array_free(&signals);
    array_free(&queues);
    tracker_free(&tracker);
    if (fd1 > 0)
        close(fd1);
    if (fd2 > 0)
        close(fd2);
    shutdown_protobuf_library();

    return error;
}
