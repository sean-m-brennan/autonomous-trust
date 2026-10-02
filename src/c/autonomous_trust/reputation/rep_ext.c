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

#include "reputation/rep_ext.h"

/* Filled by constructors before main(), then read-only, so unlocked -- as
 * processes/extension.c. */
static const rep_seed_provider_t *providers[REP_SEED_PROVIDER_MAX];
static size_t n_providers = 0;

int rep_seed_provider_register(const rep_seed_provider_t *p)
{
    if (p == NULL || p->name == NULL || p->name[0] == '\0' || p->seeds == NULL) {
        fprintf(stderr, "rep_seed_provider_register: refusing an unnamed provider\n");
        return -1;
    }
    if (rep_seed_provider_present(p->name)) {
        fprintf(stderr, "rep_seed_provider_register: refusing %s: already "
                "registered\n", p->name);
        return -1;
    }
    if (n_providers >= REP_SEED_PROVIDER_MAX) {
        fprintf(stderr, "rep_seed_provider_register: refusing %s: registry full\n",
                p->name);
        return -1;
    }
    providers[n_providers++] = p;
    return 0;
}

bool rep_seed_provider_present(const char *name)
{
    if (name == NULL)
        return false;
    for (size_t i = 0; i < n_providers; i++)
        if (strcmp(providers[i]->name, name) == 0)
            return true;
    return false;
}

size_t rep_seed_providers(const rep_seed_provider_t **out, size_t max)
{
    size_t n = n_providers < max ? n_providers : max;
    for (size_t i = 0; i < n; i++)
        out[i] = providers[i];
    return n;
}
