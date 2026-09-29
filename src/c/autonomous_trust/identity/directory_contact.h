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

/** @file Finding someone by handle, and asking to become their contact
 *  (FIRST_CONTACT_PLAN Phase 3). C twin of Python
 *  identity/directory_contact.py; part of first contact, so registered by
 *  at_first_contact_register and off unless `AT_FIRST_CONTACT` is on.
 *
 *  Alice publishes an issuer-attested entry at her registries
 *  (app_directory_publish); Bob looks the handle up (app_directory_lookup) and
 *  checks the entry himself; Bob asks (app_first_contact_request), sending a
 *  signed first_contact_request through the registry's relay; Alice's node
 *  checks it and hands it to HER APP, which alone decides
 *  (app_first_contact_accept / _decline); on accept her node sends a
 *  single-use invitation in a first_contact_accept, which Bob's node takes
 *  only for a request it has outstanding, signed by the entry's key, and then
 *  runs the ordinary hello. Both record an unverified contact of directory
 *  provenance.
 *
 *  In memory, bar our own entries (<data_dir>/directory.cfg.json, so each
 *  entry's seq only rises and entries are refiled after a restart).
 */
#ifndef AUTONOMOUS_TRUST_IDENTITY_DIRECTORY_CONTACT_H
#define AUTONOMOUS_TRUST_IDENTITY_DIRECTORY_CONTACT_H

#include <stdbool.h>

#include "processes/processes.h"
#include "utilities/msg_types.h"

/** Most requests held for the app, one per sender. Same as Python's. */
#define AT_DIR_REQUESTS_IN_MAX 32
/** Most looked-up entries remembered for a request, and for how long. */
#define AT_DIR_FOUND_MAX 64
#define AT_DIR_FOUND_TTL_SECONDS 600
/** How long the invitation an accept carries is good for. */
#define AT_DIR_ACCEPT_INVITATION_TTL 600
#define AT_DIR_STATE_FILENAME "directory.cfg.json"

/** Register the directory handlers on @p proc (from at_first_contact_register). */
void at_dir_contact_register(process_t *proc);
/** At startup: hand every unexpired entry of ours to the network to refile.
 *  @return how many. Mirrors Python restore_entries. */
int at_dir_contact_restore_entries(process_t *proc);
/** True iff @p nonce is an invitation we minted to answer an accept, so the
 *  hello it brings records a directory-provenance contact. */
bool at_dir_contact_is_invite(const char *nonce);
/** Forget every request, lookup and found entry (a restart, or a test). */
void at_dir_contact_reset(void);
/** How many requests are held for the app now. Process-wide: a conformance
 *  observable (Python len(proc._dir_in)). */
size_t at_dir_contact_held_count(void);
/** The nonce of our outstanding request to @p holder_uuid into @p out, or ""
 *  if there is none. For the conformance harness, which must echo it. */
void at_dir_contact_outstanding_nonce(const char *holder_uuid, char *out, size_t len);

bool handle_dir_app_publish(const process_t *proc, directory_t *queues, generic_msg_t *msg);
bool handle_dir_app_withdraw(const process_t *proc, directory_t *queues, generic_msg_t *msg);
bool handle_dir_app_lookup(const process_t *proc, directory_t *queues, generic_msg_t *msg);
bool handle_dir_app_request(const process_t *proc, directory_t *queues, generic_msg_t *msg);
bool handle_dir_app_accept(const process_t *proc, directory_t *queues, generic_msg_t *msg);
bool handle_dir_app_decline(const process_t *proc, directory_t *queues, generic_msg_t *msg);
bool handle_dir_result(const process_t *proc, directory_t *queues, generic_msg_t *msg);
bool handle_dir_status(const process_t *proc, directory_t *queues, generic_msg_t *msg);
bool handle_dir_contact_request(const process_t *proc, directory_t *queues, generic_msg_t *msg);
bool handle_dir_contact_accept(const process_t *proc, directory_t *queues, generic_msg_t *msg);

#endif /* AUTONOMOUS_TRUST_IDENTITY_DIRECTORY_CONTACT_H */
