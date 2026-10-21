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

/** @file Finding people nearby at an area hub. C twin of Python
 *  first_contact/area_contact.py; part of first contact, so registered by
 *  at_first_contact_register and off unless `AT_FIRST_CONTACT` is on.
 *  The app lists us in an area (app_area_publish): we sign an area card
 *  (first_contact/area_card.h), save it (<data_dir>/area.cfg.json, so its seq only
 *  rises and we stay listed across a restart) and hand it to the network to
 *  file at each of our relays; a fresh card is issued past half its life. A
 *  lookup (app_area_lookup) asks every relay, and each card any hub answers
 *  with is checked HERE. A person found may be asked to become a contact
 *  through directory_contact's flow (app_first_contact_request with @c area
 *  and @c peer_uuid), which a node shows its app only for an area it is
 *  listed in. Installing a community's relay roster is rendezvous's
 *  (rendezvous/at_rendezvous.h).
 */
#ifndef AUTONOMOUS_TRUST_IDENTITY_AREA_CONTACT_H
#define AUTONOMOUS_TRUST_IDENTITY_AREA_CONTACT_H

#include <stdbool.h>
#include <stddef.h>

#include "first_contact/directory.h"
#include "processes/processes.h"
#include "utilities/msg_types.h"

/** Most people a lookup is remembered for, and for how long. Same as Python's. */
#define AT_AREA_FOUND_MAX 256
#define AT_AREA_FOUND_TTL_SECONDS 600
/** Most areas one node lists itself in. Same as Python's LISTED_MAX. */
#define AT_AREA_LISTED_MAX 4

/** Register the area handlers on @p proc (from at_first_contact_register). */
void at_area_contact_register(process_t *proc);
/** Refile every listing, issuing a fresh card for any past half its life. At
 *  startup and from the periodic resync. @return how many were handed to the
 *  network. Mirrors Python refresh. */
int at_area_contact_refresh(const process_t *proc);
/** True iff we are listed in @p area now (a card is held, not withdrawn). */
bool at_area_contact_listed(const char *area);
/** The card of @p uuid, found in @p area within AT_AREA_FOUND_TTL_SECONDS and
 *  still unexpired, into @p card (a copy; free it) and the relay it came from
 *  into @p relay. Mirrors Python found_card. */
bool at_area_contact_found(const char *uuid, const char *area, at_dir_signed_t *card,
                           char *relay, size_t relay_len);
/** Remember / ask whether @p nonce is an invitation minted to answer an area
 *  request, so the hello it brings records an area-provenance contact. */
void at_area_contact_note_invite(const char *nonce);
bool at_area_contact_is_invite(const char *nonce);
/** Forget every lookup and invite (a restart, or a test). */
void at_area_contact_reset(void);

/** The handlers at_area_contact_register installs (the conformance harness
 *  drives them directly, as it does directory_contact's). */
bool handle_area_app_publish(const process_t *proc, directory_t *queues, generic_msg_t *msg);
bool handle_area_app_withdraw(const process_t *proc, directory_t *queues, generic_msg_t *msg);
bool handle_area_app_lookup(const process_t *proc, directory_t *queues, generic_msg_t *msg);
bool handle_area_hub_result(const process_t *proc, directory_t *queues, generic_msg_t *msg);
bool handle_area_hub_status(const process_t *proc, directory_t *queues, generic_msg_t *msg);

#endif /* AUTONOMOUS_TRUST_IDENTITY_AREA_CONTACT_H */
