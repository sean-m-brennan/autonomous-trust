#ifndef PROCESSES_H
#define PROCESSES_H

#include "utilities/message.h"
#include "config/configuration.h"
#include "processes/process_tracker.h"


struct process_s
{
    char impl[256]; // FIXME python class
    char name[256];
    //char cfg_name[256];  // FIXME ???
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
        // FIXME from configs
        // peers
        // group
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
int process_run(const process_t *proc, map_t *queues, msgq_key_t signal);

void process_free(process_t *proc);

#endif  // PROCESSES_H
