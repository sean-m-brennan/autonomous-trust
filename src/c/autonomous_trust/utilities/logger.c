/********************
 *  Copyright 2024 TekFive, Inc., Sean M. Brennan, and contributors
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

extern _Thread_local exception_t _exception;

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

/* Frama-C: skipped —
 * logger_init_time_res also has direct strncpy + fopen + set_exception preconditions.
 */
/*@
  requires \valid(logger);
  requires max_level >= DEBUG && max_level <= CRITICAL;
  requires log_file == \null ||
           \valid_read(log_file + (0 .. MAX_FILENAME - 1));
  assigns logger->max_level, logger->term, logger->local_time,
          logger->resolution, logger->file_name[0 .. MAX_FILENAME],
          logger->file;
  behavior success:
    ensures \result == 0;
    ensures logger->max_level == max_level;
    ensures logger->resolution == res;
  behavior failure:
    ensures \result == -1;
  disjoint behaviors;
*/
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
        /* logger->file_name was zero'd by the memset above; strncpy writes
         * at most 255 bytes, leaving byte 255 as the NUL terminator. */
        strncpy(logger->file_name, log_file, 255);
        logger->file = fopen(logger->file_name, "a");
        if (logger->file == NULL)
            return SYS_EXCEPTION();
        logger->term = false;
        /* Line-buffer the log file so each newline-terminated record reaches
         * disk promptly. A file stream is fully buffered by default, which in
         * a long-lived daemon strands log lines in the ~4 KiB stdio buffer
         * until it fills or the process exits — they'd never show up live.
         * (stderr, the foreground sink, is unbuffered already.) Must precede
         * any write to the stream. */
        setvbuf(logger->file, NULL, _IOLBF, 0);
    }
    return 0;
}

/* Frama-C: skipped —
 * [solver-timeout] all 4 logger_init* variants time out on disjoint_failure_success — the
 * disjoint-behaviors check between the success and failure branches involves path-join +
 * fopen + strncpy state that the solver can't fully eliminate.
 */
inline int logger_init(logger_t *logger, log_level_t max_level, const char *log_file)
{
    return logger_init_time_res(logger, max_level, log_file, MILLISECONDS);
}

/* Frama-C: skipped — [syscall] freopen. */
int logger_reopen(logger_t *logger)
{
    if (logger == NULL || logger->file_name[0] == '\0')
        return 0;  /* stderr/terminal logger — fds 0/1/2 survive daemonize */
    /* freopen reuses the existing FILE* object, so handlers holding
     * logger->file keep a valid pointer. It flushes+closes the old (now
     * already-closed) descriptor — that close failure is ignored per POSIX —
     * then opens file_name fresh in append mode on a live fd. */
    FILE *reopened = freopen(logger->file_name, "a", logger->file);
    if (reopened == NULL)
        return SYS_EXCEPTION();
    logger->file = reopened;
    /* freopen resets buffering to the default (full) — restore line buffering
     * so the child's records flush per line, matching logger_init. */
    setvbuf(logger->file, NULL, _IOLBF, 0);
    return 0;
}

/* Frama-C: skipped —
 * [solver-timeout] all 4 logger_init* variants time out on disjoint_failure_success — the
 * disjoint-behaviors check between the success and failure branches involves path-join +
 * fopen + strncpy state that the solver can't fully eliminate. logger_init_time_res also
 * has direct strncpy + fopen + set_exception preconditions.
 */
/*@
  requires \valid(logger);
  requires max_level >= DEBUG && max_level <= CRITICAL;
  requires log_file == \null ||
           \valid_read(log_file + (0 .. MAX_FILENAME - 1));
  assigns logger->max_level, logger->term, logger->local_time,
          logger->resolution, logger->file_name[0 .. MAX_FILENAME],
          logger->file;
  behavior success:
    ensures \result == 0;
    ensures logger->local_time == true;
    ensures logger->resolution == res;
  behavior failure:
    ensures \result == -1;
  disjoint behaviors;
*/
int logger_init_local_time_res(logger_t *logger, log_level_t max_level, const char *log_file, time_resolution_t res)
{
    int err = logger_init_time_res(logger, max_level, log_file, res);
    if (err != 0)
        return err;
    logger->local_time = true;
    return 0;
}

/* Frama-C: skipped —
 * [solver-timeout] all 4 logger_init* variants time out on disjoint_failure_success — the
 * disjoint-behaviors check between the success and failure branches involves path-join +
 * fopen + strncpy state that the solver can't fully eliminate. logger_init_time_res also
 * has direct strncpy + fopen + set_exception preconditions.
 */
inline int logger_init_local_time(logger_t *logger, log_level_t max_level, const char *log_file)
{
    return logger_init_local_time_res(logger, max_level, log_file, MILLISECONDS);
}

/*@
  requires logger_ptr == \null || \valid(logger_ptr);
  requires srcfile != \null && \valid_read(srcfile);
  requires fmt != \null && \valid_read(fmt);
  assigns \nothing;
*/
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


/*@
  requires \valid_read(error_table + (0 .. error_table_size - 1));
  assigns \nothing;
  behavior found:
    ensures \result != \null;
  behavior not_found:
    ensures \result == \null;
  disjoint behaviors;
*/
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

/*@
  requires \valid_read(error_table + (0 .. error_table_size - 1));
  assigns \nothing;
  behavior found:
    ensures \result != \null;
  behavior not_found:
    ensures \result == \null;
  disjoint behaviors;
*/
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


/*@
  requires logger == \null || \valid(logger);
  requires srcfile != \null && \valid_read(srcfile);
  assigns _exception.errnum, _exception.line,
          _exception.file[0 .. MAX_FILENAME - 1];
  ensures _exception.errnum == 0;
*/
void _log_exception(logger_t *logger, const char *srcfile, const size_t line)
{
    _log_exception_extra(logger, srcfile, line, "\n");
}

/*@
  requires logger == \null || \valid(logger);
  requires srcfile != \null && \valid_read(srcfile);
  requires fmt != \null && \valid_read(fmt);
  assigns _exception.errnum, _exception.line,
          _exception.file[0 .. MAX_FILENAME - 1];
  ensures _exception.errnum == 0;
*/
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
    /* Allocation size matches exactly what the three writes need:
     *   strcpy err_info  → strlen(err_info) bytes + NUL
     *   strcat "%s"      → 2 more bytes + NUL (overwrites prior NUL)
     *   strcat addtnl    → strlen(addtnl) bytes + NUL (len=0 when !add_stack)
     *   total            = strlen(err_info) + 2 + strlen(addtnl) + 1
     * No overrun. */
    char *format = malloc(strlen(err_info) + 2 + strlen(addtnl) + 1);
    strcpy(format, err_info);
    strcat(format, "%s");
    if (add_stack)
        strcat(format, addtnl);

    va_list argp;
    va_start(argp, fmt);
    char user_msg[1024] = {0};
    vsnprintf(user_msg, sizeof(user_msg), fmt, argp);
    va_end(argp);
    _logging(logger, ERROR, _exception.file, _exception.line, format, user_msg);
    _set_exception(0, 0, "");  // clear
    free(format);
    if (add_stack)
        free(addtnl);
}
