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

struct process_s
{
    char name[PROC_NAMELEN];  // category of process, i.e. identity, network, ...
    char impl[PROC_NAMELEN];  // identifier of implementing function
    config_t conf;
    map_t *configs;
    tracker_t *subsystems;
    array_t *dependencies;
    logger_t *logger;
    int flags;
    struct timeval start;
    struct
    {
        map_t *handlers;
        group_t group;
        public_identity_t peers[MAX_PEERS];
        // FIXME from configs
        // capabilities
        // peer capabilities
        int phase;
        array_t *unhandled_messages;
    } protocol;
};

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
int process_init(process_t *proc, char *name, map_t *configurations, tracker_t *subsystems, logger_t *logger, array_t *dependencies);

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
int process_run(const process_t *proc, map_t *queues, int signal, logger_t *logger);

void process_free(process_t *proc);

#endif  // PROCESSES_H
