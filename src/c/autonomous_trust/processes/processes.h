/********************
 *  Copyright 2025 Sean M. Brennan and contributors
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

#include <sys/time.h>

#include "utilities/message.h"
#include "config/configuration.h"
#include "identity/identity_priv.h"
#include "process_tracker_priv.h"
#include "utilities/util.h"

struct process_s
{
    smrt_ptr_t;
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
        public_identity_t peers[DEFAULT_MAX_PEERS];
        size_t num_peers;
        map_t *peer_capabilities;
        int phase;
        array_t *unhandled_messages;
    } protocol;
};

#define SIG_NAME_LEN PROC_NAME_LEN + 2

/*@
  requires name != \null && \valid_read(name);
  requires \valid(sig + (0 .. SIG_NAME_LEN));
  assigns sig[0 .. SIG_NAME_LEN];
*/
void process_name_to_signal(const char *name, char *sig);

/*@
  requires name_in != \null && \valid_read(name_in);
  assigns \nothing;
  behavior success:
    ensures \result == 0;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
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
/*@
  requires \valid(proc);
  requires name != \null && \valid_read(name);
  requires \valid(configurations);
  assigns proc->name[0 .. PROC_NAME_LEN],
          proc->conf, proc->configs, proc->subsystems,
          proc->logger, proc->dependencies, proc->runner,
          proc->protocol.handlers;
  behavior success:
    ensures \result == 0;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
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
/*@
  requires \valid(proc);
  requires func_name != \null && \valid_read(func_name);
  assigns proc->protocol.handlers;
  ensures \result == 0 || \result != 0;
*/
int process_register_handler(const process_t *proc, char *func_name, handler_ptr_t handler);

#ifndef PROCESSES_IMPL
extern const long cadence;
#endif

/*@
  requires \valid(proc);
  requires \valid(sig_q);
  assigns \nothing;
  ensures \result == \true || \result == \false;
*/
bool keep_running(const process_t *proc, queue_t *sig_q, logger_t *logger);

/*@
  requires \valid(proc);
  assigns \nothing;
*/
void sleep_until(const process_t *proc, long how_long);

/*@
  requires \valid(proc);
  requires \valid(msg);
  assigns proc->protocol.group, proc->protocol.peers[0 .. DEFAULT_MAX_PEERS - 1],
          proc->protocol.num_peers;
  ensures \result == \true || \result == \false;
*/
bool run_message_handlers(process_t *proc, directory_t *queues, long msgtype, generic_msg_t *msg);

/**
 * @brief Context for split process setup/loop lifecycle
 */
typedef struct
{
    queue_t my_q;
    queue_t sig_q;
    int fd1;
    int fd2;
} process_ctx_t;

/**
 * @brief Daemonize and initialize messaging. Call before process_loop().
 */
/*@
  requires \valid(proc);
  requires signal != \null && \valid_read(signal);
  requires \valid(ctx);
  assigns ctx->my_q, ctx->sig_q, ctx->fd1, ctx->fd2;
  behavior success:
    ensures \result == 0;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int process_setup(process_t *proc, queue_id_t signal, logger_t *logger,
                  process_ctx_t *ctx);

/**
 * @brief Run the message-handling loop. Call after process_setup().
 */
/*@
  requires \valid(proc);
  requires \valid(ctx);
  assigns \nothing;
  ensures \result == 0;
*/
int process_loop(process_t *proc, directory_t *queues, logger_t *logger,
                 process_ctx_t *ctx);

/**
 * @brief Combined setup + loop (convenience for simple processes).
 */
/*@
  requires \valid(proc);
  requires signal != \null && \valid_read(signal);
  assigns \nothing;
  ensures \result == 0 || \result != 0;
*/
int process_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger);

/*@
  requires proc == \null || \valid(proc);
  frees proc;
*/
void process_free(process_t *proc);

#endif  // PROCESSES_H
