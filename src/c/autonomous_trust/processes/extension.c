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

#include <stdio.h>
#include <string.h>

#include "processes/extension.h"
#include "utilities/logger.h"

/* Filled by constructors before main(), then read-only, so unlocked -- as
 * utilities/msg_registry.c. */
static const at_extension_t *_extensions[AT_EXTENSION_MAX];
static size_t _extensions_len = 0;

int at_extension_register(const at_extension_t *ext)
{
    if (ext == NULL || ext->name == NULL || ext->name[0] == '\0')
    {
        fprintf(stderr, "at_extension_register: refusing an unnamed extension\n");
        return -1;
    }
    for (size_t i = 0; i < _extensions_len; i++)
        if (strcmp(_extensions[i]->name, ext->name) == 0)
        {
            fprintf(stderr, "at_extension_register: refusing %s: already registered\n",
                    ext->name);
            return -1;
        }
    if (_extensions_len >= AT_EXTENSION_MAX)
    {
        fprintf(stderr, "at_extension_register: refusing %s: registry full\n", ext->name);
        return -2;
    }
    _extensions[_extensions_len++] = ext;
    return 0;
}

int at_extensions_register_handlers(process_t *proc, const char *proc_name)
{
    if (proc == NULL || proc_name == NULL)
        return -1;
    int failed = 0;
    for (size_t i = 0; i < _extensions_len; i++)
    {
        const at_extension_t *ext = _extensions[i];
        if (ext->register_handlers == NULL)
            continue;
        if (ext->enabled != NULL && !ext->enabled())
            continue;
        if (ext->register_handlers(proc, proc_name) != 0)
        {
            log_warn(proc->logger, "%s: extension %s failed to register its handlers\n",
                     proc_name, ext->name);
            failed++;
        }
    }
    return failed;
}

void at_extensions_reset(void)
{
    for (size_t i = 0; i < _extensions_len; i++)
        if (_extensions[i]->reset != NULL)
            _extensions[i]->reset();
}

size_t at_extension_count(void)
{
    return _extensions_len;
}
