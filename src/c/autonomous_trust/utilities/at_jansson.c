/********************
 *  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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

#include "at_jansson.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

json_t *at_json_object_or_log(logger_t *logger, const char *site)
{
    /* Intentionally bypasses the logger framework so this helper has
     * no link-time dependency on logger.c — callers may compile it
     * into stand-alone test executables that don't pull in the full
     * library. The @p logger parameter is reserved for a future
     * variant; ignored today. */
    (void)logger;
    json_t *j = json_object();
    if (j == NULL)
        fprintf(stderr, "jansson: json_object() returned NULL (%s)\n",
                site != NULL ? site : "<unknown>");
    return j;
}

int at_json_string_copy(const json_t *obj, const char *key,
                        char *dst, size_t dst_len)
{
    if (dst == NULL || dst_len < 1)
        return -1;
    if (obj == NULL || key == NULL)
        return -1;
    json_t *v = json_object_get(obj, key);
    if (v == NULL || !json_is_string(v))
        return -1;
    const char *s = json_string_value(v);
    if (s == NULL)
        return -1;
    /* NUL-terminated bounded copy. */
    size_t n = strnlen(s, dst_len - 1);
    memcpy(dst, s, n);
    dst[n] = '\0';
    return 0;
}

int at_json_string_dup(const json_t *obj, const char *key, char **dst_ptr)
{
    if (dst_ptr == NULL)
        return -1;
    *dst_ptr = NULL;
    if (obj == NULL || key == NULL)
        return -1;
    json_t *v = json_object_get(obj, key);
    if (v == NULL || !json_is_string(v))
        return -1;
    const char *s = json_string_value(v);
    if (s == NULL)
        return -1;
    size_t len = strlen(s);
    char *copy = malloc(len + 1);
    if (copy == NULL)
        return -1;
    memcpy(copy, s, len + 1);
    *dst_ptr = copy;
    return 0;
}

const char *at_json_string_peek(const json_t *obj, const char *key)
{
    if (obj == NULL || key == NULL)
        return NULL;
    json_t *v = json_object_get(obj, key);
    if (v == NULL || !json_is_string(v))
        return NULL;
    return json_string_value(v);
}

int at_json_integer(const json_t *obj, const char *key, int64_t *dst)
{
    if (dst == NULL || obj == NULL || key == NULL)
        return -1;
    json_t *v = json_object_get(obj, key);
    if (v == NULL || !json_is_integer(v))
        return -1;
    *dst = (int64_t)json_integer_value(v);
    return 0;
}

int at_json_boolean(const json_t *obj, const char *key, bool *dst)
{
    if (dst == NULL || obj == NULL || key == NULL)
        return -1;
    json_t *v = json_object_get(obj, key);
    if (v == NULL || !json_is_boolean(v))
        return -1;
    *dst = json_is_true(v);
    return 0;
}
