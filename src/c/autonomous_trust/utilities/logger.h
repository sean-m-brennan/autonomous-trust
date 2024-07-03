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

#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "structures/datetime.h"
#include "exception.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    DEBUG = 1,
    INFO,
    WARNING,
    ERROR,
    CRITICAL
} log_level_t;

typedef struct {
    log_level_t max_level;
    char file_name[MAX_FILENAME+1];
    FILE *file;
    bool term;
    bool local_time;
    time_resolution_t resolution;
} logger_t;


/**
 * @brief Initialize a logger. Many simultaneous instances supported per process. Time resolution in milliseconds.
 *
 * @param logger Logger instance (existing).
 * @param level Log level.
 * @param filename Path to the log file.
 * 
 * @return int Success (0) or error code
 */
int logger_init(logger_t *logger, log_level_t max_level, const char *log_file);

/**
 * @brief Initialize a logger, specifying time resolution.
 * 
 * @param logger Logger instance (existing).
 * @param max_level Log level.
 * @param log_file Path to the log file.
 * @param res Time resolution (in milli-, micro-, or nanoseconds).
 * @return int Success (0) or error code
 */
int logger_init_time_res(logger_t *logger, log_level_t max_level, const char *log_file, time_resolution_t res);

/**
 * @brief Initialize a logger that outputs local time instead of UTC.
 * 
 * @param logger Logger instance (existing).
 * @param max_level Log level.
 * @param log_file Path to the log file.
 * 
 * @return int Success (0) or error code
 */
int logger_init_local_time(logger_t *logger, log_level_t max_level, const char *log_file);

/**
 * @brief Initialize a logger that outputs local time instead of UTC, specifying time resolution.
 * 
 * @param logger Logger instance (existing).
 * @param max_level Log level.
 * @param log_file Path to the log file.
 * @param res Time resolution (in milli-, micro-, or nanoseconds).
 * @return int Success (0) or error code
 */
int logger_init_local_time_res(logger_t *logger, log_level_t max_level, const char *log_file, time_resolution_t res);

/**
 * @brief Internal, use log_xxx() macros.
 * @details Write a formatted string to the log file at the given log level.
 *
 * @param level Log level.
 * @param frmt Format message.
 * @param ... Variable arguments.
 */
void _logging(logger_t *logger, log_level_t level, const char *srcfile, const size_t line, const char *fmt, ...);

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#define log_debug(logger, ...) _logging(logger, DEBUG, __FILENAME__, __LINE__, __VA_ARGS__)
#define log_info(logger, ...)  _logging(logger, INFO, __FILENAME__, __LINE__, __VA_ARGS__)
#define log_warn(logger, ...)  _logging(logger, WARNING, __FILENAME__, __LINE__, __VA_ARGS__)
#define log_error(logger, ...) _logging(logger, ERROR, __FILENAME__, __LINE__, __VA_ARGS__)
#define log_critical(logger, ...) _logging(logger, CRITICAL, __FILENAME__, __LINE__, __VA_ARGS__)

void _log_exception(logger_t *logger, const char *srcfile, const size_t line);

#define log_exception(logger) _log_exception(logger, __FILENAME__, __LINE__)

void _log_exception_extra(logger_t *logger, const char *srcfile, const size_t line, const char *fmt, ...);

#define log_exception_extra(logger, ...) _log_exception_extra(logger, __FILENAME__, __LINE__, __VA_ARGS__)

/**
 * @brief Close the given logger
 * 
 * @param logger 
 */
void logger_close(logger_t *logger);

#ifdef __cplusplus
} // extern "C"
#endif

#endif  // LOGGER_H
