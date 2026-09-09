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

void contact_free(contact_t *c)
{
    if (c == NULL)
        return;
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
