/********************
 *  Copyright 2025 Sean M. Brennan and contributors
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

#ifndef UTIL_H
#define UTIL_H

/** @addtogroup internal_utilities
 *  @{
 */

#include <sys/types.h>

#include "exception.h"
#include "compiler.h"

#if defined __GNUC__ && !defined __FRAMAC__
#define IGNORE_GCC_DIAGNOSTIC(which) \
    _Pragma("GCC diagnostic push")   \
        _Pragma(_GCC_DIAGNOSTIC(which))

#define _IGNORE_GCC_DIAGNOSTIC_1(which) IGNORE_GCC_DIAGNOSTIC(which)
#define _IGNORE_GCC_DIAGNOSTIC_0(which)

#define IGNORE_GCC_VER_DIAGNOSTIC(version, which)   \
    _GCC_VER_COND(_IGNORE_GCC_DIAGNOSTIC_, version) \
    (which)

#define END_IGNORE_GCC_DIAGNOSTIC _Pragma("GCC diagnostic pop")
#else
#define IGNORE_GCC_DIAGNOSTIC(x)
#define IGNORE_GCC_VER_DIAGNOSTIC(v, x)
#define END_IGNORE_GCC_DIAGNOSTIC
#endif

#define TERM_RESET "\x1B[0m"
#define TERM_RED "\x1B[31m"
#define TERM_GREEN "\x1B[32m"
#define TERM_YELLOW "\x1B[33m"
#define TERM_BLUE "\x1B[34m"
#define TERM_PURPLE "\x1B[35m"

/** @brief Return the lesser of @p a and @p b. */
long min(long a, long b);

/** @brief Return the greater of @p a and @p b. */
long max(long a, long b);

/**
 * @brief Remove every occurrence of @p sub from @p str in place.
 *
 * @param[in,out] str  NUL-terminated string; modified in place.
 * @param[in]     sub  Substring to delete.
 * @return @p str for chaining.
 */
char *strremove(char *str, const char *sub);

/**
 * @brief Ensure every component of @p path exists as a directory (`mkdir -p`).
 *
 * @param[in] path  Directory path (may contain multiple missing components).
 * @param[in] mode  Permission bits for newly created directories.
 * @return 0 on success, -1 with @c errno set on failure.
 */
int makedirs(char *path, mode_t mode);

/**
 * @brief Join a directory and suffix with '/'.  Returns total length
 *        written (excluding NUL) on success, -1 on overflow.
 *        On overflow dest[0] is set to '\0'.
 */
/*@
  requires destlen > 0;
  requires \valid(dest + (0 .. destlen - 1));
  requires dir != \null;
  requires suffix != \null;
  assigns dest[0 .. destlen - 1];
  ensures \result >= -1;
*/
int path_join(char *dest, size_t destlen,
                 const char *dir, const char *suffix);

/**
 * @brief Test whether two floats are within @p epsilon of each other.
 *
 * @return Non-zero when the absolute difference is below @p epsilon.
 */
int compare_float_precision(float f1, float f2, float epsilon);

/** @brief Convenience wrapper calling compare_float_precision() with @c 1e-5. */
#define compare_float(f1, f2) \
    compare_float_precision(f1, f2, 0.00001)

/**
 * @brief Test whether two doubles are within @p epsilon of each other.
 *
 * @return Non-zero when the absolute difference is below @p epsilon.
 */
int compare_double_precision(double f1, double f2, double epsilon);

/** @brief Convenience wrapper calling compare_double_precision() with @c 1e-5. */
#define compare_double(f1, f2) \
    compare_double_precision(f1, f2, 0.00001)

#define PROC_NAME_LEN 64

/********************/
// json errors

#define EJSN_OBJ_SET 201
DECLARE_ERROR(EJSN_OBJ_SET, "JSON error when adding an element to an object");

#define EJSN_ARR_APP 202
DECLARE_ERROR(EJSN_ARR_APP, "JSON error when appending to an array");

#define EJSN_DUMP 203
DECLARE_ERROR(EJSN_DUMP, "JSON error dumping to string/file/etc.");


/** @} */ /* end of internal_utilities */

#endif // UTIL_H
