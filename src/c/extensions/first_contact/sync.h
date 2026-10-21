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

#ifndef AT_CONTACTS_SYNC_H
#define AT_CONTACTS_SYNC_H

/**
 * @file sync.h
 * @brief One user's address book kept the same on all their devices
 * (FIRST_CONTACT_PLAN Phase 4, live pairing). C twin of Python
 * first_contact/sync.py: same payload, same rules, same order.
 *
 *     {v: 1, typename: "at-contacts-sync",
 *      contacts:   {uuid: <contact canonical form>},
 *      tombstones: {uuid: removed_at}}
 *
 * at_sync_merge folds one into the local store, contact by contact, the newer
 * edit winning (contact_version: the latest of added_at, verified_at,
 * updated_at). A tombstone beats any record of its uuid no newer than it.
 * A remote time more than AT_SYNC_CLOCK_SKEW past ours is taken as now. Equal
 * versions go to the larger tie key (verified, trust_seed, petname,
 * operator_key, sorted device uuids, nonce). What only ever grows --
 * verification, the operator key, devices under it -- is folded from the
 * losing copy into the winner. A contact new here arrives as
 * AT_PROV_SIBLING; one already here keeps its provenance, the higher
 * reach_seq, and both hint lists.
 */

#include <stdbool.h>
#include <stddef.h>

#include <jansson.h>

#include "first_contact/contacts.h"

#define AT_SYNC_TYPENAME "at-contacts-sync"
#define AT_SYNC_VERSION 1
/** How far past our clock a remote time may be before it is taken as now. */
#define AT_SYNC_CLOCK_SKEW 300.0

typedef enum {
    AT_SYNC_ADDED = 1,
    AT_SYNC_UPDATED,
    AT_SYNC_REMOVED,
    /** A removal of a contact this device never had, kept to pass on. */
    AT_SYNC_TOMBSTONE,
} at_sync_action_t;

typedef struct {
    char uuid[UUID_STRING_LEN + 1];
    at_sync_action_t action;
} at_sync_change_t;

/** "added" / "updated" / "removed" / "tombstone". */
const char *at_sync_action_str(at_sync_action_t a);

/** The payload for @p store: every contact and tombstone when @p uuids is
 *  NULL, else only those filed under the @p n uuids (a delta). New
 *  reference, or NULL. */
json_t *at_sync_build(const contacts_t *store, const char *const *uuids, size_t n);

/** Fold @p payload into @p store at time @p now. @p exclude (n_exclude
 *  uuids: this node and its siblings) are never taken as contacts. The
 *  changes, in uuid order, go to *changes_out (malloc'd, may be NULL when
 *  there are none) and their number to *n_changes; none = nothing to save.
 *  0, or -1 when @p payload is not a sync payload (the store untouched). A
 *  malformed record inside one is skipped. */
int at_sync_merge(contacts_t *store, const json_t *payload, double now,
                  const char *const *exclude, size_t n_exclude,
                  at_sync_change_t **changes_out, size_t *n_changes);

/** at_sync_merge, a contact new here getting @p provenance instead of
 *  AT_PROV_SIBLING (AT_PROV_BACKUP for a restore, first_contact/backup.h). */
int at_sync_merge_as(contacts_t *store, const json_t *payload, double now,
                     const char *const *exclude, size_t n_exclude,
                     at_provenance_t provenance,
                     at_sync_change_t **changes_out, size_t *n_changes);

#endif /* AT_CONTACTS_SYNC_H */
