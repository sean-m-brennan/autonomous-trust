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

#define _XOPEN_SOURCE 700
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "logger.h"
#include "util.h"
#include "error_table_priv.h"
#include "structures/datetime.h"

#define LOGGER_IMPLEMENTATION

logger_t root_logger = {
    .max_level = DEBUG,
    .term = true,
    .local_time = false,
    .resolution = MILLISECONDS,
    .file_name = {0},
    .file = NULL,
};

static const char *log_level_strings[] = {
    "",
    " [DEBUG]    ",
    " [INFO]     ",
    " [WARNING]  ",
    " [ERROR]    ",
    " [CRITICAL] ",
};

const char *colors[] = {
    "",
    TERM_BLUE,
    TERM_GREEN,
    TERM_YELLOW,
    TERM_RED,
    TERM_PURPLE,
};

int logger_init_time_res(logger_t *logger, log_level_t max_level, const char *log_file, time_resolution_t res)
{
    logger->max_level = max_level;
    logger->term = true;
    logger->local_time = false;
    logger->resolution = res;
    memset(logger->file_name, 0, sizeof(logger->file_name));
    if (log_file == NULL)
        logger->file = stderr;
    else
    {
        strncpy(logger->file_name, log_file, 255);
        logger->file = fopen(logger->file_name, "a");
        if (logger->file == NULL)
            return SYS_EXCEPTION();
        logger->term = false;
    }
    return 0;
}

inline int logger_init(logger_t *logger, log_level_t max_level, const char *log_file)
{
    return logger_init_time_res(logger, max_level, log_file, MILLISECONDS);
}

int logger_init_local_time_res(logger_t *logger, log_level_t max_level, const char *log_file, time_resolution_t res)
{
    int err = logger_init_time_res(logger, max_level, log_file, res);
    if (err != 0)
        return err;
    logger->local_time = true;
    return 0;
}

inline int logger_init_local_time(logger_t *logger, log_level_t max_level, const char *log_file)
{
    return logger_init_local_time_res(logger, max_level, log_file, MILLISECONDS);
}

void _logging(logger_t *logger_ptr, log_level_t level, const char *srcfile, const size_t line, const char *fmt, ...)
{
    logger_t *logger = logger_ptr;
    if (logger_ptr == NULL)
        logger = &root_logger;

    if (level < logger->max_level)
        return;
    if (logger->file == NULL)
        logger->file = stderr;

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
}

const char *_custom_errstr(int num)
{
    for (int i = 0; i < error_table_size; i++)
    {
        exception_info_t *entry = &error_table[i];
        if (entry->errnum == num)
            return entry->description;
    }
    return NULL;
}

void log_exception(logger_t *logger)
{
    // FIXME allow for additional formatted char* info
    const char *err_descr = _custom_errstr(_exception.errnum);
    int gai_max = -1;
    int gai_min = -11;
    if (_exception.errnum >= gai_min && _exception.errnum <= gai_max)
        err_descr = gai_strerror(_exception.errnum);
    if (err_descr == NULL)
        err_descr = strerror(_exception.errnum);
    _logging(logger, ERROR, _exception.file, _exception.line, "%s\n", err_descr);
}
