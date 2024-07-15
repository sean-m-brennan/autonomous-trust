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

#define ERR_INFO_FMT "%s (%s)"
#define ERR_INFO_LEN (1024 + 64 + 3)

#define ORIGIN_FMT "\tfrom %s, line %ld\n"
#define ORIGIN_LEN (MAX_FILENAME + MAX_INT_STR + 14)

extern exception_t _exception;

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

void _vlogging(logger_t *logger_ptr, log_level_t level, const char *srcfile, const size_t line, const char *fmt, va_list argp)
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
    char datetime[MAX_DT_STR+1] = {0};
    datetime_strftime_res(&now, iso8601_format, logger->resolution, datetime, MAX_DT_STR);
    fprintf(logger->file, "%s", datetime);

    if (logger->term)
        fprintf(logger->file, "%s%-10s%s", colors[level], log_level_strings[level], TERM_RESET);
    else
        fprintf(logger->file, "%-10s", log_level_strings[level]);

    fprintf(logger->file, "%s: line %lu: ", srcfile, line);

    vfprintf(logger->file, fmt, argp);
}

void _logging(logger_t *logger_ptr, log_level_t level, const char *srcfile, const size_t line, const char *fmt, ...)
{
    va_list argp;
    va_start(argp, fmt);
    _vlogging(logger_ptr, level, srcfile, line, fmt, argp);
    va_end(argp);
}


const char *_custom_errstr(int num)
{
    for (int i = 0; i < error_table_size; i++)
    {
        exception_info_t *entry = &error_table[i];
        if (entry->errnum == num)
            return entry->errstr;
    }
    return NULL;
}

const char *_custom_errdescr(int num)
{
    for (int i = 0; i < error_table_size; i++)
    {
        exception_info_t *entry = &error_table[i];
        if (entry->errnum == num)
            return entry->description;
    }
    return NULL;
}


void _log_exception(logger_t *logger, const char *srcfile, const size_t line)
{
    _log_exception_extra(logger, srcfile, line, "\n");
}

void _log_exception_extra(logger_t *logger, const char *srcfile, const size_t line, const char *fmt, ...)
{
    if (_exception.errnum == 0) {
        _logging(logger, ERROR, "?", -1, "Incorrect exception flagging (unexpected return value)\n");
        return;
    }

    const char *err_descr = _custom_errdescr(_exception.errnum);
    const char *err_str = _custom_errstr(_exception.errnum);
    int gai_max = -1;
    int gai_min = -11;
    if (_exception.errnum >= gai_min && _exception.errnum <= gai_max)
        err_descr = gai_strerror(_exception.errnum);
    if (err_descr == NULL)
        err_descr = strerror(_exception.errnum);
    if (err_str == NULL)
        err_str = _get_err_str(_exception.errnum);

    char err_info[ERR_INFO_LEN+1];
    snprintf(err_info, ERR_INFO_LEN, ERR_INFO_FMT, err_descr, err_str);
    bool add_stack = false;
    char *addtnl = (char*)"";
    if (strcmp(srcfile, _exception.file) != 0 || line != _exception.line) {
        add_stack = true;
        addtnl = malloc(ORIGIN_LEN+1);
        snprintf(addtnl, ORIGIN_LEN, ORIGIN_FMT, srcfile, line);
    }
    char *format = malloc(strlen(err_info) + strlen(fmt) + strlen(addtnl) + 1);
    strcpy(format, err_info);
    strcat(format, fmt);
    if (add_stack)
        strcat(format, addtnl);

    va_list argp;
    va_start(argp, fmt);
    _vlogging(logger, ERROR, _exception.file, _exception.line, format, argp);
    va_end(argp);
    _set_exception(0, 0, "");  // clear
    free(format);
    if (add_stack)
        free(addtnl);
}
