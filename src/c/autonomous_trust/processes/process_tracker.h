#ifndef PROCESS_TRACKER_H
#define PROCESS_TRACKER_H

#include "structures/structures.h"
#include "utilities/logger.h"
#include "utilities/message.h"
#include "config/configuration.h"

typedef struct
{
    map_t *registry;
    logger_t *logger;
    bool alloc;
} tracker_t;

#ifndef PROCESSES_IMPL
extern const char *default_tracker_filename;
#endif

typedef struct process_s process_t;  // FIXME why is this defined here?

typedef int (*handler_ptr_t)(const process_t *proc, map_t *queues, msgq_key_t signal);

typedef struct
{
    char *name;
    handler_ptr_t runner;
} proc_map_t;

#define DECLARE_PROCESS(proc_name, run_func)

/**
 * @brief Initialize existing tracker
 *
 * @param logger
 * @param tracker
 * @return int
 */
int tracker_init(logger_t *logger, tracker_t *tracker);

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


#endif // PROCESS_TRACKER_H
