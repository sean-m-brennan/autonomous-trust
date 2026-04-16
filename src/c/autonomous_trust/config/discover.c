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

#include <string.h>
#include <libgen.h>

#include "discover.h"

/* Frama-C: skipped — [syscall] basename(3) + string manipulation */
int get_cfg_type(const char *path, char *type_out, size_t type_len)
{
    if (path == NULL || type_out == NULL || type_len == 0)
        return -1;

    /* get basename */
    char path_copy[512];
    strncpy(path_copy, path, sizeof(path_copy) - 1);
    path_copy[sizeof(path_copy) - 1] = '\0';
    const char *base = basename(path_copy);

    /* check for .cfg.json suffix and strip it */
    size_t base_len = strlen(base);
    size_t ext_len = strlen(CFG_FILE_EXT);
    if (base_len > ext_len &&
        strcmp(base + base_len - ext_len, CFG_FILE_EXT) == 0)
    {
        size_t name_len = base_len - ext_len;
        if (name_len >= type_len)
            name_len = type_len - 1;
        memcpy(type_out, base, name_len);
        type_out[name_len] = '\0';
    }
    else
    {
        strncpy(type_out, base, type_len - 1);
        type_out[type_len - 1] = '\0';
    }
    return 0;
}
