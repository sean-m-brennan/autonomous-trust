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

/** @file Pairing one's own devices, and keeping their address books the same
 *  (FIRST_CONTACT_PLAN Phase 4, live pairing, the wire half). C twin of
 *  Python identity/sibling_sync.py; part of first contact, so registered by
 *  at_first_contact_register and off unless `AT_FIRST_CONTACT` is on.
 *
 *  Pairing: the old device mints an invitation whose signed body carries
 *  `purpose: "pair"`; the new device redeems it and the two run the usual
 *  hello / hello_ack, recording no contact. Each pushes its device cert,
 *  sealed; on the other's, at_siblings_add decides. A match writes
 *  siblings.cfg.json and emits AT_APP_EVENT_FC_SIBLING_PAIRED; anything else
 *  (no cert, another operator, nothing within AT_SIBLING_PAIR_WAIT_SECONDS)
 *  drops the direct peer and emits REFUSED with AT_FC_REASON_NOT_SIBLING.
 *
 *  Sync: siblings swap sealed `contacts_sync` payloads (contacts/sync.h) --
 *  the whole book after pairing and at startup (asking one reply, `reply:
 *  true`), and what changed after each local edit. Only a sibling's payload
 *  is taken, and a change it brings has a local edit's effect: an added
 *  contact is admitted and routed, a removed one's peers dropped, and the
 *  app hears CONTACT / REMOVED with origin AT_FC_ORIGIN_SIBLING.
 */
#ifndef AUTONOMOUS_TRUST_IDENTITY_SIBLING_SYNC_H
#define AUTONOMOUS_TRUST_IDENTITY_SIBLING_SYNC_H

#include <stdbool.h>
#include <stddef.h>

#include <jansson.h>

#include "at_first_contact.h"
#include "contacts/reach.h"
#include "identity/identity.h"
#include "processes/processes.h"
#include "utilities/msg_types.h"

/** How long a pair handshake waits for the other side's device cert. Python
 *  sibling_sync.PAIR_WAIT_SECONDS. */
#define AT_SIBLING_PAIR_WAIT_SECONDS 120

/** Register the sibling handlers on @p proc (from at_first_contact_register). */
void at_sibling_sync_register(process_t *proc);
/** Drop pending pair handshakes and the change tracking (tests). */
void at_sibling_sync_reset(void);

/** Whether this node has a device cert of its own to pair under. */
bool at_sibling_can_pair(const process_t *proc);
/** A pair handshake with @p peer is done: wait for its cert (refusing older
 *  handshakes past their wait first), and send ours. @p hints: where it was
 *  reached. */
void at_sibling_begin(const process_t *proc, directory_t *queues,
                      const public_identity_t *peer, const char *ref,
                      at_fc_role_t role, const char *const *hints, size_t n_hints);
/** End a pair handshake that did not make two siblings: drop the peer (when
 *  @p drop) and emit REFUSED / NOT_SIBLING. */
void at_sibling_refuse(const process_t *proc, directory_t *queues,
                       const public_identity_t *peer, const char *ref,
                       at_fc_role_t role, bool drop);
/** A device cert (@p cert, {body, sig}) from @p sender: true if it answered a
 *  pair handshake and has been dealt with, false to handle it as a
 *  contact's. */
bool at_sibling_on_device_cert(const process_t *proc, directory_t *queues,
                               const public_identity_t *sender, const json_t *cert);
/** Refuse every pair handshake whose cert never came by @p now. @return how
 *  many. */
int at_sibling_expire(const process_t *proc, directory_t *queues, double now);

/** After a local edit: what changed since the last push, to every sibling
 *  that is a peer. @return how many sent. */
int at_sibling_push_changes(const process_t *proc);
/** The whole address book to @p only (NULL: every sibling that is a peer);
 *  @p reply asks each to answer once with its own. @return how many sent. */
int at_sibling_send_full(const process_t *proc, const public_identity_t *only,
                         bool reply);
/** At startup: start change tracking, re-admit and route every sibling, send
 *  each our record, and swap books. @return how many siblings. */
int at_sibling_restore(process_t *proc);
/** A reachability record: if it is a sibling's, keep its newer hints and
 *  return true (refused or applied); false when it is not a sibling's. */
bool at_sibling_apply_record(const process_t *proc, const at_reach_record_t *rec);
/** Whether @p uuid (lower case) is in siblings.cfg.json, re-read only when
 *  the file changes. For the tier cap. */
bool at_sibling_is(const char *uuid);

bool handle_contacts_sync(const process_t *proc, directory_t *queues, generic_msg_t *msg);
bool handle_app_sibling_list(const process_t *proc, directory_t *queues, generic_msg_t *msg);
bool handle_app_sibling_remove(const process_t *proc, directory_t *queues,
                               generic_msg_t *msg);

#endif /* AUTONOMOUS_TRUST_IDENTITY_SIBLING_SYNC_H */
