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

#ifndef EXCEPTION_H
#define EXCEPTION_H

#include <stddef.h>
#include <errno.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define MAX_FILENAME 256
#define MAX_INT_STR 11

    typedef struct
    {
        int errnum;
        const char* errstr;
        const char *description;
    } exception_info_t;

    typedef struct
    {
        int errnum;
        size_t line;
        char file[MAX_FILENAME + 1];
    } exception_t;

#ifndef EXCEPTION_IMPL
    extern exception_t _exception;
    const char *_get_err_str(int err);

    extern exception_info_t error_table[];
    extern size_t error_table_size;
#endif

/**
 * @brief Internal, use the SYS_EXCEPTION() or EXCEPTION() macros.
 * @details Similar to errno, set the current exception for later logging.
 *
 * @param err
 * @param line
 * @param file
 * @return int
 */
int _set_exception(int err, size_t line, const char *file);

/**
 * @brief Save information related to an errno error for later logging.
 *
 */
#define SYS_EXCEPTION() _set_exception(errno, __LINE__, __FILE__)

/**
 * @brief Save indformation related to an arbitrary error for later logging.
 *
 */
#define EXCEPTION(err) _set_exception(err, __LINE__, __FILE__)

#define DECLARE_ERROR(num, descr) // Nullifies internal use; ignore

/**
 * @brief Custom errors
 * @details Code that uses the library can define custom errors for use with SYS_EXCEPTION/EXCEPTION macros and log_exception().
 *
 */
#define DEFINE_ERROR(num, descr)                           \
    void __attribute__((constructor)) register_err_##num() \
    {                                                      \
        error_table[error_table_size].errnum = num;        \
        error_table[error_table_size].errstr = #num;       \
        error_table[error_table_size].description = descr; \
        error_table_size++;                                \
    }

#ifdef __cplusplus
} // extern "C"
#endif

#endif // EXCEPTION_H
