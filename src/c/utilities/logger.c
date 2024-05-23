#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <stdbool.h>

#include "logger.h"
#include "util.h"
#include "../structures/datetime.h"

static const char* log_level_strings[] = {
    " [DEBUG]    ",
    " [INFO]     ",
    " [WARNING]  ",
    " [ERROR]    ",
    " [CRITICAL] ",
};

const char* colors[] = {
    TERM_BLUE,
    TERM_GREEN,
    TERM_YELLOW,
    TERM_RED,
    TERM_PURPLE,
};

int logger_init_time_res(logger_t *logger, log_level_t max_level, const char *log_file, time_resolution_t res) {
    logger->max_level = max_level;
    logger->term = true;
    logger->local_time = false;
    logger->resolution = res;
    bzero(logger->file_name, 256);
    if (log_file == NULL)
        logger->file = stderr;
    else {
        strncpy(logger->file_name, log_file, 255);
        logger->file = fopen(logger->file_name, "a");
        if (logger->file == NULL)
            return errno;
        logger->term = false;
    }
    return 0;
}

inline int logger_init(logger_t *logger, log_level_t max_level, const char *log_file) {
    return logger_init_time_res(logger, max_level, log_file, MILLISECONDS);
}

int logger_init_local_time_res(logger_t *logger, log_level_t max_level, const char *log_file, time_resolution_t res) {
    int err = logger_init_time_res(logger, max_level, log_file, res);
    if (err != 0)
        return err;
    logger->local_time = true;
    return 0;
}

inline int logger_init_local_time(logger_t *logger, log_level_t max_level, const char *log_file) {
    return logger_init_local_time_res(logger, max_level, log_file, MILLISECONDS);
}


void logging(logger_t *logger, log_level_t level, const char *srcfile, const size_t line, const char *fmt, ...) {
    if (level < logger->max_level)
        return;

    datetime_t now;
    datetime_now(false, &now);
    char datetime[512] = {0};
    datetime_strftime_res(&now, iso8601_format, logger->resolution, datetime, 512);
    fprintf(logger->file, "%s", datetime); 

    if (logger->term)
        fprintf(logger->file, "%s%-10s%s", colors[level], log_level_strings[level], TERM_RESET);
    else
        fprintf(logger->file, "%-10s", log_level_strings[level]);

    fprintf(logger->file, "%s: line %lu: ", srcfile, line);
    va_list argp;
    va_start(argp, fmt);
    vfprintf(logger->file, fmt, argp);
    va_end(argp);    
    fprintf(logger->file, "\n");
}
