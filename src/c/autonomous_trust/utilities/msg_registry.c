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

#include "msg_registry.h"
#include "msg_types_priv.h"

/* Filled by constructors before main(), then read-only. Nothing registers
 * after startup, so no lock: a lock here would be taken on every IPC hop to
 * guard writes that have all already happened. */
static struct {
    long id;
    const at_msg_vtable_t *vt;
} _registry[AT_MSG_TYPE_REGISTRY_MAX];
static size_t _registry_len = 0;

/* Logged to stderr, not through the logger: registration runs from
 * constructors, before any logger exists, and a refusal there is otherwise
 * invisible -- the feature just silently stops receiving its messages. */
static int _refuse(long id, const char *name, const char *why)
{
    fprintf(stderr, "at_msg_type_register: refusing %ld (%s): %s\n",
            id, name != NULL ? name : "?", why);
    return -1;
}

/* Frama-C: skipped — [func-ptr] vtable pointers stored for later dispatch */
int at_msg_type_register(long id, const at_msg_vtable_t *vt)
{
    if (id < AT_MSG_TYPE_EXT_MIN || id > AT_MSG_TYPE_EXT_MAX)
        return _refuse(id, vt != NULL ? vt->name : NULL, "id outside the extension ranges");
    if (vt == NULL || vt->name == NULL || vt->name[0] == '\0')
        return _refuse(id, NULL, "no name");
    if (vt->size == 0 || vt->size > AT_MSG_PAYLOAD_MAX)
        return _refuse(id, vt->name, "payload size is 0 or exceeds AT_MSG_PAYLOAD_MAX");
    if ((vt->to_proto == NULL) != (vt->from_proto == NULL))
        return _refuse(id, vt->name, "to_proto and from_proto must both be set or both NULL");
    if (message_type_core_by_name(vt->name) != (message_type_t)-1)
        return _refuse(id, vt->name, "name is a core type's");
    for (size_t i = 0; i < _registry_len; i++)
    {
        if (_registry[i].id == id)
            return _refuse(id, vt->name, "id already registered");
        if (strcmp(_registry[i].vt->name, vt->name) == 0)
            return _refuse(id, vt->name, "name already registered");
    }
    if (_registry_len >= AT_MSG_TYPE_REGISTRY_MAX)
    {
        _refuse(id, vt->name, "registry full (AT_MSG_TYPE_REGISTRY_MAX)");
        return -2;
    }
    _registry[_registry_len].id = id;
    _registry[_registry_len].vt = vt;
    _registry_len++;
    return 0;
}

const at_msg_vtable_t *at_msg_type_lookup(long id)
{
    if (id < AT_MSG_TYPE_EXT_MIN)
        return NULL;
    for (size_t i = 0; i < _registry_len; i++)
        if (_registry[i].id == id)
            return _registry[i].vt;
    return NULL;
}

long at_msg_type_by_name(const char *name)
{
    if (name == NULL)
        return -1;
    for (size_t i = 0; i < _registry_len; i++)
        if (strcmp(_registry[i].vt->name, name) == 0)
            return _registry[i].id;
    return -1;
}

size_t at_msg_type_count(void)
{
    return _registry_len;
}

long at_msg_type_id_at(size_t i)
{
    return i < _registry_len ? _registry[i].id : -1;
}

static struct {
    const char *verb;
    const char *target;
} _verbs[AT_APP_VERB_REGISTRY_MAX];
static size_t _verbs_len = 0;

int at_app_verb_register(const char *verb, const char *target)
{
    if (verb == NULL || verb[0] == '\0' || target == NULL || target[0] == '\0')
    {
        fprintf(stderr, "at_app_verb_register: refusing an empty verb or target\n");
        return -1;
    }
    if (at_app_verb_target(verb) != NULL)
    {
        fprintf(stderr, "at_app_verb_register: refusing %s: already registered\n", verb);
        return -1;
    }
    if (_verbs_len >= AT_APP_VERB_REGISTRY_MAX)
    {
        fprintf(stderr, "at_app_verb_register: refusing %s: registry full\n", verb);
        return -2;
    }
    _verbs[_verbs_len].verb = verb;
    _verbs[_verbs_len].target = target;
    _verbs_len++;
    return 0;
}

const char *at_app_verb_target(const char *verb)
{
    if (verb == NULL)
        return NULL;
    for (size_t i = 0; i < _verbs_len; i++)
        if (strcmp(_verbs[i].verb, verb) == 0)
            return _verbs[i].target;
    return NULL;
}
