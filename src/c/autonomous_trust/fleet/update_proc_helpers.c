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

/**
 * update_proc_helpers.c — pure, dependency-free helper functions for update_proc.
 *
 * Kept in a separate translation unit so that unit tests can link only
 * update_proc_helpers.c + update_selftest.c without pulling in the full
 * process/messaging infrastructure that update_proc.c depends upon.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <jansson.h>

#include "fleet/update_proc.h"

/* ------------------------------------------------------------------ */
/* State file I/O                                                      */
/* ------------------------------------------------------------------ */

int update_state_write(const char *data_dir, const update_state_t *state)
{
    /* Ensure <data_dir>/update/ exists */
    char dir_path[512];
    snprintf(dir_path, sizeof(dir_path), "%s/update", data_dir);

    struct stat st;
    if (stat(dir_path, &st) != 0) {
        if (mkdir(dir_path, 0755) != 0 && errno != EEXIST)
            return -1;
    }

    /* Build JSON object with all 7 fields */
    json_t *root = json_object();
    if (!root)
        return -1;

    json_object_set_new(root, "state",       json_string(state->state));
    json_object_set_new(root, "version",     json_string(state->version));
    json_object_set_new(root, "hash_hex",    json_string(state->hash_hex));
    json_object_set_new(root, "backup_path", json_string(state->backup_path));
    json_object_set_new(root, "binary_path", json_string(state->binary_path));
    json_object_set_new(root, "timestamp",   json_integer(state->timestamp));
    json_object_set_new(root, "attempt",     json_integer(state->attempt));
    json_object_set_new(root, "type",        json_string(state->type));

    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s/update/state.json", data_dir);

    int ret = json_dump_file(root, file_path, JSON_INDENT(2));
    json_decref(root);
    return ret;
}

int update_state_read(const char *data_dir, update_state_t *state)
{
    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s/update/state.json", data_dir);

    json_error_t err;
    json_t *root = json_load_file(file_path, 0, &err);
    if (!root)
        return -1;

    const char *s;

    s = json_string_value(json_object_get(root, "state"));
    if (s) strncpy(state->state, s, sizeof(state->state) - 1);
    state->state[sizeof(state->state) - 1] = '\0';

    s = json_string_value(json_object_get(root, "version"));
    if (s) strncpy(state->version, s, sizeof(state->version) - 1);
    state->version[sizeof(state->version) - 1] = '\0';

    s = json_string_value(json_object_get(root, "hash_hex"));
    if (s) strncpy(state->hash_hex, s, sizeof(state->hash_hex) - 1);
    state->hash_hex[sizeof(state->hash_hex) - 1] = '\0';

    s = json_string_value(json_object_get(root, "backup_path"));
    if (s) strncpy(state->backup_path, s, sizeof(state->backup_path) - 1);
    state->backup_path[sizeof(state->backup_path) - 1] = '\0';

    s = json_string_value(json_object_get(root, "binary_path"));
    if (s) strncpy(state->binary_path, s, sizeof(state->binary_path) - 1);
    state->binary_path[sizeof(state->binary_path) - 1] = '\0';

    state->timestamp = (long)json_integer_value(json_object_get(root, "timestamp"));
    state->attempt   = (int)json_integer_value(json_object_get(root, "attempt"));

    s = json_string_value(json_object_get(root, "type"));
    if (s) strncpy(state->type, s, sizeof(state->type) - 1);
    state->type[sizeof(state->type) - 1] = '\0';

    json_decref(root);
    return 0;
}

int update_state_delete(const char *data_dir)
{
    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s/update/state.json", data_dir);

    if (unlink(file_path) != 0) {
        if (errno == ENOENT)
            return 0;  /* already absent is fine */
        return -1;
    }
    return 0;
}

bool update_state_exists(const char *data_dir)
{
    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s/update/state.json", data_dir);

    struct stat st;
    return stat(file_path, &st) == 0;
}

bool update_should_abort(const update_state_t *state)
{
    return state->attempt > 1;
}

/* ------------------------------------------------------------------ */
/* Path helpers                                                        */
/* ------------------------------------------------------------------ */

int update_staging_dir(const char *data_dir, char *buf, size_t buflen)
{
    return snprintf(buf, buflen, "%s/update", data_dir) < (int)buflen ? 0 : -1;
}

int update_staging_path(const char *data_dir, char *buf, size_t buflen)
{
    return snprintf(buf, buflen, "%s/update/at_demo.new", data_dir) < (int)buflen ? 0 : -1;
}

int update_backup_path(const char *data_dir, char *buf, size_t buflen)
{
    return snprintf(buf, buflen, "%s/update/at_demo.backup", data_dir) < (int)buflen ? 0 : -1;
}

int update_current_binary_path(char *buf, size_t buflen)
{
    ssize_t len = readlink("/proc/self/exe", buf, buflen - 1);
    if (len < 0)
        return -1;
    buf[len] = '\0';
    return 0;
}
