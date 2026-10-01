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

/** @file The 1:1 contact record (C twin of contacts/contact.py). */

#include "contacts/contacts.h"

#include <stdlib.h>
#include <time.h>

const char *at_provenance_str(at_provenance_t p)
{
    switch (p) {
    case AT_PROV_IN_PERSON:
        return "in_person";
    case AT_PROV_TOKEN:
        return "token";
    case AT_PROV_DIRECTORY:
        return "directory";
    case AT_PROV_SIBLING:
        return "sibling";
    case AT_PROV_AREA:
        return "area";
    case AT_PROV_BACKUP:
        return "backup";
    default:
        return "token";
    }
}

void contact_mark_verified(contact_t *c, double seed)
{
    if (c == NULL)
        return;
    c->verified = true;
    /* Stamp once. verified_at is epoch seconds (never negative); 0 is the
     * "not yet verified" sentinel. Use <= to satisfy -Werror=float-equal (the
     * host build) rather than an == against 0.0. */
    if (c->verified_at <= 0.0)
        c->verified_at = (double)time(NULL);
    c->trust_seed = seed;
}

double contact_version(const contact_t *c)
{
    if (c == NULL)
        return 0.0;
    double v = c->added_at;
    if (c->verified_at > v)
        v = c->verified_at;
    if (c->updated_at > v)
        v = c->updated_at;
    return v;
}

void contact_touch(contact_t *c, double now)
{
    if (c == NULL)
        return;
    if (now < 0.0) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        now = (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
    }
    double v = contact_version(c);
    c->updated_at = now > v ? now : v;
}

void contact_free(contact_t *c)
{
    if (c == NULL)
        return;
    for (size_t i = 0; i < c->devices_count; i++) {
        json_decref(c->devices[i].identity);
        json_decref(c->devices[i].cert);
    }
    free(c->devices);
    c->devices = NULL;
    c->devices_count = 0;
    if (c->rendezvous != NULL) {
        for (size_t i = 0; i < c->rendezvous_count; i++)
            free(c->rendezvous[i]);
        free(c->rendezvous);
        c->rendezvous = NULL;
        c->rendezvous_count = 0;
    }
    /* The embedded public identity may own an operator_key_binding heap buffer
     * (public_identity_from_json mallocs it when present). Our invitation
     * identities never carry one, but free defensively for real callers. */
    if (c->identity.operator_key_binding != NULL) {
        free(c->identity.operator_key_binding);
        c->identity.operator_key_binding = NULL;
        c->identity.operator_key_binding_len = 0;
    }
}
