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

#ifndef PROCESSES_H
#define PROCESSES_H

#include "utilities/message.h"
#include "config/configuration.h"
#include "identity/identity_priv.h"
#include "process_tracker_priv.h"
#include "utilities/util.h"

struct process_s
{
    char name[PROC_NAME_LEN+1];  // category of process, i.e. identity, network, ...
    char impl[PROC_NAME_LEN+1];  // identifier of implementing function
    config_t conf;
    map_t *configs;
    tracker_t *subsystems;
    array_t *dependencies;
    logger_t *logger;
    int flags;
    struct timeval start;
    handler_ptr_t runner;
    struct
    {
        map_t *handlers;
        group_t group;
        public_identity_t peers[MAX_PEERS];
        size_t num_peers;
        map_t *peer_capabilities;
        int phase;
        array_t *unhandled_messages;
    } protocol;
};

#define SIG_NAME_LEN PROC_NAME_LEN + 2

void process_name_to_signal(const char *name, char *sig);

int set_process_name(const char *name_in);

typedef char* queue_id_t;
typedef array_t directory_t;

#ifndef PROCESSES_IMPL
extern const char *sig_quit;
#endif

#define NO_UMASK 0x01
#define NO_CHDIR 0x02
#define NO_CLOSE_FILES 0x04
#define NO_STDOUT_REDIRECT 0x08
#define NO_STDERR_REDIRECT 0x10

/**
 * @brief Initialize a process (config, etc)
 *
 * @param proc
 * @param name
 * @param proc_name
 * @param configurations
 * @param subsystems
 * @param dependencies
 * @param log_level
 * @return int
 */
int process_init(process_t *proc, char *name, handler_ptr_t runner, map_t *configurations, tracker_t *subsystems, logger_t *logger, array_t *dependencies);

int start_process(char *pname, handler_ptr_t runner, map_t *configs, tracker_t *tracker,
                  map_t *procs, directory_t *queues, logger_t *logger);

int restart_process(pid_t orig, char *pname, map_t *procs, directory_t *queues, logger_t *logger);


/**
 * @brief 
 * 
 * @param data_dir 
 * @param flags 
 * @param fd1 
 * @param fd2 
 * @return int 
 */
int daemonize(char *data_dir, int flags, int *fd1, int *fd2);

/**
 * @brief 
 * 
 * @param proc 
 * @param func_name 
 * @param handler 
 * @return int 
 */
int process_register_handler(const process_t *proc, char *func_name, handler_ptr_t handler);

/**
 * @brief See handler_ptr_t
 *
 * @param proc
 * @param queues
 * @param signal
 * @return int
 */
int process_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger);

void process_free(process_t *proc);

#endif  // PROCESSES_H
