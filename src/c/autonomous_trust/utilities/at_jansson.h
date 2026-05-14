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

#ifndef AT_JANSSON_H
#define AT_JANSSON_H

/** @addtogroup internal_utilities
 *  @{
 *
 *  Defensive jansson wrappers. Closes BUGS.md "unchecked jansson
 *  return values" recurring theme by giving the codebase a single,
 *  audited spelling for the two recurring bug shapes:
 *
 *    1. `json_object()` returning NULL on allocator failure.
 *       Use `at_json_object_or_log()` instead of bare `json_object()`
 *       when the caller plans to fail-fast.
 *
 *    2. `json_string_value(json_object_get(j, k))` returning NULL when
 *       the key is missing or the value isn't a string.
 *       Use `AT_JSON_STRING(j, k, dst)` for safe bounded copy into a
 *       char array, or `at_json_string_copy()` for an explicit length.
 *
 *  All helpers are NULL-safe on @p obj — passing NULL yields the
 *  documented "missing key" outcome (no copy / no read).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <jansson.h>

#include "logger.h"

/**
 * @brief Allocate a fresh JSON object. On allocator failure logs to
 *        @p logger (when non-NULL) and returns NULL.
 *
 * @param logger Optional logger; NULL silences the failure message.
 * @param site   Short label included in the log message (file:fn or
 *               module:purpose). May be NULL.
 * @return New json_t* (reference count 1) or NULL on failure.
 */
json_t *at_json_object_or_log(logger_t *logger, const char *site);

/**
 * @brief Copy a string-valued JSON field into @p dst, NUL-terminated.
 *
 * Reads `json_object_get(obj, key)` and, if it is a string, copies up to
 * @p dst_len - 1 bytes into @p dst followed by '\0'. Tolerates @p obj
 * being NULL, the key being missing, or the value being a non-string —
 * in those cases @p dst is unchanged and -1 is returned. The original
 * default (e.g. zero-initialised buffer) therefore stays intact.
 *
 * @return 0 on successful copy, -1 if the field is missing / non-string
 *         / @p dst_len < 1.
 */
int at_json_string_copy(const json_t *obj, const char *key,
                        char *dst, size_t dst_len);

/**
 * @brief Convenience macro for fixed char-buffer destinations.
 *
 * Auto-derives the size with @c sizeof(dst); only valid for actual char
 * arrays, not char pointers.
 */
#define AT_JSON_STRING(obj, key, dst) \
    at_json_string_copy((obj), (key), (dst), sizeof(dst))

/**
 * @brief Heap-duplicate a string-valued JSON field.
 *
 * On success stores a malloc'd copy in `*dst_ptr` and returns 0. On
 * any failure (missing key, wrong type, malloc fail) `*dst_ptr` is set
 * to NULL and -1 is returned.
 */
int at_json_string_dup(const json_t *obj, const char *key, char **dst_ptr);

/**
 * @brief Read a string-valued JSON field as a borrowed pointer.
 *
 * @return Internal jansson string pointer (valid while @p obj is
 *         alive), or NULL on missing/non-string. The pointer is owned
 *         by the JSON tree — DO NOT free.
 */
const char *at_json_string_peek(const json_t *obj, const char *key);

/**
 * @brief Read an integer-valued JSON field.
 *
 * @return 0 on success (writes to @p dst); -1 if missing or non-integer
 *         (@p dst untouched).
 */
int at_json_integer(const json_t *obj, const char *key, int64_t *dst);

/**
 * @brief Read a boolean-valued JSON field.
 *
 * @return 0 on success (writes to @p dst); -1 if missing or non-boolean
 *         (@p dst untouched).
 */
int at_json_boolean(const json_t *obj, const char *key, bool *dst);

/** @} */ /* end of internal_utilities */

#endif /* AT_JANSSON_H */
