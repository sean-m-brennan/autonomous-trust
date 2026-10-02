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

#ifndef AT_CONTACTS_SIBLINGS_H
#define AT_CONTACTS_SIBLINGS_H

/**
 * @file siblings.h
 * @brief This user's own other devices (FIRST_CONTACT_PLAN Phase 4, live
 * pairing). C twin of Python first_contact/siblings.py: same file, same checks in
 * the same order, same refusal reasons.
 *
 * A sibling is another node whose device cert names the same operator key as
 * this node's own cert (first_contact/device.h). Siblings share one address book
 * (first_contact/sync.h), so they are kept apart from it, in
 * <data_dir>/siblings.cfg.json:
 *
 *     {typename: "siblings", version: 1, operator: <hex>,
 *      devices: [{identity, cert, added_at, rendezvous?, reach_seq?}]}
 *
 * and never appear as contacts. On load a device is kept only if its cert
 * still verifies for its identity under the stored operator key.
 */

#include <stdbool.h>
#include <stddef.h>

#include <jansson.h>

#include "first_contact/contacts.h"
#include "first_contact/directory.h"

#define AT_SIBLINGS_TYPENAME "siblings"
#define AT_SIBLINGS_VERSION 1
#define AT_SIBLINGS_FILENAME "siblings.cfg.json"
/** Hints kept per sibling (first_contact's AT_FC_MAX_RENDEZVOUS_HINTS). */
#define AT_SIBLING_HINTS_MAX 4
#define AT_SIBLING_HINT_LEN 384

/** Where a sibling was last reached, as a contact keeps it: hints most recent
 *  first, and the highest reachability-record seq applied. Stored only once
 *  set. */
typedef struct {
    char hints[AT_SIBLING_HINTS_MAX][AT_SIBLING_HINT_LEN];
    size_t n_hints;
    int64_t reach_seq;
} at_sibling_reach_t;

typedef struct {
    char operator_key[AT_OPERATOR_KEY_HEX_LEN + 1];   /* "" until paired */
    at_contact_device_t *devices;                     /* owned */
    at_sibling_reach_t *reach;                        /* owned; one per device */
    size_t count;
} at_siblings_t;

void at_siblings_init(at_siblings_t *s);
void at_siblings_free(at_siblings_t *s);

/** Whether @p uuid is one of the siblings. */
bool at_siblings_contains(const at_siblings_t *s, const char *uuid);

/** Pair with the node @p id, whose device cert is @p cert; @p own_cert is
 *  this node's (NULL when it has none). An at_device_status_t:
 *  AT_DEVICE_UNKNOWN_OPERATOR (no cert of our own), MALFORMED /
 *  BAD_SIGNATURE (@p cert is no good), MISMATCH (it does not name @p id, or
 *  names another operator than ours), KNOWN (@p id is this node), FULL
 *  (already AT_CONTACT_DEVICES_MAX). Pairing a known sibling again is OK. A
 *  new operator on our own cert starts the list over. */
int at_siblings_add(at_siblings_t *s, const public_identity_t *id,
                    const at_dir_signed_t *cert, const at_dir_signed_t *own_cert);

/** The sibling @p uuid's reach state, or NULL. */
at_sibling_reach_t *at_siblings_reach(at_siblings_t *s, const char *uuid);
/** The sibling @p uuid's device record, or NULL. */
const at_contact_device_t *at_siblings_get(const at_siblings_t *s, const char *uuid);
/** Replace @p uuid's hints with @p hints (non-empty, at most
 *  AT_SIBLING_HINTS_MAX kept). */
void at_siblings_set_hints(at_siblings_t *s, const char *uuid,
                           const char *const *hints, size_t n);

/** Drop the sibling @p uuid; whether there was one. */
bool at_siblings_remove(at_siblings_t *s, const char *uuid);

/** Canonical JSON (new reference). */
json_t *at_siblings_to_json(const at_siblings_t *s);
/** Fill @p s (initialised here) from @p obj, keeping only the devices that
 *  verify under its operator key. Anything not a siblings file = none. */
void at_siblings_from_json(const json_t *obj, at_siblings_t *s);

/** Load <data_dir>/siblings.cfg.json; no file or an unreadable one = none. */
void at_siblings_load(const char *data_dir, at_siblings_t *s);
/** Write it atomically, creating @p data_dir. 0, or -1. */
int at_siblings_save(const at_siblings_t *s, const char *data_dir);

#endif /* AT_CONTACTS_SIBLINGS_H */
