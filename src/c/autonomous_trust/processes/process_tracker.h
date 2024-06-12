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

#ifndef PROCESS_TRACKER_H
#define PROCESS_TRACKER_H

#include "structures/map.h"
#include "utilities/logger.h"
#include "utilities/message.h"
#include "config/configuration.h"

typedef struct
{
    map_t *registry;
    logger_t *logger;
    bool alloc;
} tracker_t;

typedef struct process_s process_t; // FIXME why is this defined here?

typedef int (*handler_ptr_t)(const process_t *proc, map_t *queues, int signal, logger_t *logger);

typedef struct
{
    const char *type;
    const char *name;
    handler_ptr_t runner;
} proc_map_t;

#ifndef PROCESSES_IMPL
extern const char *default_tracker_filename;

extern proc_map_t process_table[];
extern size_t process_table_size;
#endif

#define DECLARE_PROCESS(type, proc_name, run_func)

#define DEFINE_PROCESS(t, n, r)                                                \
    void __attribute__((constructor)) CONCAT(register_process_, __COUNTER__)() \
    {                                                                          \
        process_table[process_table_size].type = QUOTE(t);                     \
        process_table[process_table_size].name = QUOTE(n);                     \
        process_table[process_table_size].runner = r;                          \
        process_table_size++;                                                  \
    }

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
 * @param name Type of process
 * @param impl Name of implementation
 * @return int
 */
int tracker_register_subsystem(const tracker_t *tracker, const char *name, const char *impl);

/**
 * @brief
 *
 * @param name
 * @return handler_ptr_t
 */
handler_ptr_t find_process(const char *name);

/**
 * @brief
 *
 * @param handler
 * @return char*
 */
char *find_process_name(const handler_ptr_t handler);

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

DECLARE_ERROR(EPROC_NF, "Process not found in process table");

#endif  // PROCESS_TRACKER_H
