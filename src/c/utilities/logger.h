#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "../structures/datetime.h"

typedef enum {
    DEBUG = 0,
    INFO,
    WARNING,
    ERROR,
    CRITICAL
} log_level_t;

typedef struct {
    log_level_t max_level;
    char file_name[256];
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
 * @brief Write a formatted string to the log file at the given log level.
 *
 * @param level Log level.
 * @param frmt Format message.
 * @param ... Variable arguments.
 */
void logging(logger_t *logger, log_level_t level, const char *srcfile, const size_t line, const char *fmt, ...);

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#define log_debug(logger, format, ...) logging(logger, DEBUG, __FILENAME__, __LINE__, format, __VA_ARGS__)
#define log_info(logger, format, ...)  logging(logger, INFO, __FILENAME__, __LINE__, format, __VA_ARGS__)
#define log_warn(logger, format, ...)  logging(logger, WARNING, __FILENAME__, __LINE__, format, __VA_ARGS__)
#define log_error(logger, format, ...) logging(logger, ERROR, __FILENAME__, __LINE__, format, __VA_ARGS__)
#define log_critical(logger, format, ...) logging(logger, CRITICAL, __FILENAME__, __LINE__, format, __VA_ARGS__)

/**
 * @brief Close the given logger
 * 
 * @param logger 
 */
void logger_close(logger_t *logger);

#endif // LOGGER_H
