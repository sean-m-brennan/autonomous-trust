#ifndef PROCESSES_H
#define PROCESSES_H

#include <sys/msg.h>
#include <sys/time.h>

#include "structures/structures.h"
#include "config/configuration.h"
#include "utilities/logger.h"
#include "utilities/message.h"

typedef struct {
    map_t *registry;
    logger_t *logger;
} tracker_t;

#ifndef PROCESSES_IMPL
extern const char *default_tracker_filename;
#endif

typedef struct process_s process_t;

typedef int (*handler_ptr_t)(const process_t *proc, map_t *queues, msgq_key_t signal);

typedef struct
{
    char *name;
    handler_ptr_t runner;
} proc_map_t;



/**
 * @brief All potential process runners *must* be declared using this macro. The name must be unique.
 * 
 */
#define DECLARE_PROCESS(proc_name, run_func)              \
    static proc_map_t ptr_##proc_name                     \
        __attribute((used, section("process_table"))) = { \
            .name = proc_name,                            \
            .runner = run_func,                           \
    }

/**
 * @brief Allocate a process tracker
 * 
 * @param logger 
 * @param tracker_ptr 
 * @return int 
 */
int tracker_create(logger_t *logger, tracker_t **tracker_ptr);

/**
 * @brief Load a process tracker from file
 * 
 * @param filename 
 * @param logger 
 * @param tracker_ptr 
 * @return int 
 */
int tracker_from_file(const char *filename, logger_t *logger, tracker_t **tracker_ptr);

/**
 * @brief 
 * 
 * @param config_file 
 * @return int 
 */
int tracker_config(char config_file[]);

/**
 * @brief Register a subsystem process
 * 
 * @param tracker 
 * @param name 
 * @param handler 
 * @return int 
 */
int tracker_register_subsystem(const tracker_t *tracker, const char *name, const handler_ptr_t handler);

/**
 * @brief Save a process tracker to file
 * 
 * @param tracker 
 * @param filename 
 * @return int 
 */
int tracker_to_file(const tracker_t *tracker, const char *filename);

/**
 * @brief Free a previously allocated process tracker
 * 
 * @param tracker 
 */
void tracker_free(tracker_t *tracker);

/**
 * @brief Error code: process not found in process table (see DECLARE_PROCESS)
 * 
 */
#define EPROC_NF 170


/*************************/

struct process_s
{
    char impl[256]; // FIXME python class
    char name[256];
    //char cfg_name[256];  // FIXME ???
    // configuration_t conf;
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
    } protocol;
};

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
 * @return int 
 */
int daemonize(char *data_dir, int flags);

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

#endif // PROCESSES_H