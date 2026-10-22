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

#include "negotiation/neg_ext.h"

/* Filled by constructors before main(), then read-only, so unlocked -- as
 * processes/extension.c. */
static const neg_tier_cap_t *caps[NEG_TIER_CAP_MAX];
static size_t n_caps = 0;

int neg_tier_cap_register(const neg_tier_cap_t *cap)
{
    if (cap == NULL || cap->name == NULL || cap->name[0] == '\0'
        || cap->cap == NULL) {
        fprintf(stderr, "neg_tier_cap_register: refusing an unnamed cap\n");
        return -1;
    }
    if (neg_tier_cap_present(cap->name)) {
        fprintf(stderr, "neg_tier_cap_register: refusing %s: already registered\n",
                cap->name);
        return -1;
    }
    if (n_caps >= NEG_TIER_CAP_MAX) {
        fprintf(stderr, "neg_tier_cap_register: refusing %s: registry full\n",
                cap->name);
        return -1;
    }
    caps[n_caps++] = cap;
    return 0;
}

bool neg_tier_cap_present(const char *name)
{
    if (name == NULL)
        return false;
    for (size_t i = 0; i < n_caps; i++)
        if (strcmp(caps[i]->name, name) == 0)
            return true;
    return false;
}

int neg_ext_capped_tier(const process_t *proc, const unsigned char *peer, int tier)
{
    for (size_t i = 0; i < n_caps; i++) {
        int capped = caps[i]->cap(proc, peer, tier);
        if (capped < tier)
            tier = capped;      /* a cap only lowers */
    }
    return tier;
}

/* ---- Live replication's result hook ----------------------------------- */

static const neg_result_hook_t *result_hook;

int neg_result_hook_register(const neg_result_hook_t *hook)
{
    if (hook == NULL || hook->name == NULL || hook->name[0] == '\0') {
        fprintf(stderr, "neg_result_hook_register: refusing an unnamed hook\n");
        return -1;
    }
    if (result_hook != NULL) {
        fprintf(stderr, "neg_result_hook_register: refusing %s: %s is registered\n",
                hook->name, result_hook->name);
        return -1;
    }
    result_hook = hook;
    return 0;
}

neg_result_verdict_t neg_ext_on_result(const process_t *proc,
                                       const neg_result_info_t *info)
{
    if (result_hook == NULL || result_hook->on_result == NULL)
        return NEG_RESULT_LEAVE;
    return result_hook->on_result(proc, info);
}

void neg_ext_periodic(const process_t *proc)
{
    if (result_hook != NULL && result_hook->periodic != NULL)
        result_hook->periodic(proc);
}
