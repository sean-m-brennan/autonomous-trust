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
/** @file One human, several devices, on the wire (FIRST_CONTACT_PLAN Phase 4,
 *  slice 1b). C twin of Python identity/device_contact.py; part of first
 *  contact, so registered by at_first_contact_register and off unless
 *  `AT_FIRST_CONTACT` is on.
 *
 *  Our own device cert (<cfg_dir>/device_cert.cfg.json, written by the
 *  operator's tools/device_cert.py) goes SEALED to each contact once we are
 *  peers (`device_cert`), so the contact learns our operator key. A node with a
 *  cert announces itself at startup, PLAINTEXT, to every contact in its store
 *  (`device_announce`); the contact files it under the matching verified
 *  contact (contacts/device.h), admits it as a direct peer and tells its app
 *  (AT_APP_EVENT_FC_DEVICE_LINKED). Nothing is sent back either way.
 */
#ifndef AUTONOMOUS_TRUST_IDENTITY_DEVICE_CONTACT_H
#define AUTONOMOUS_TRUST_IDENTITY_DEVICE_CONTACT_H

#include <stdbool.h>

#include "contacts/contacts.h"
#include "contacts/directory.h"
#include "identity/identity.h"
#include "processes/processes.h"
#include "utilities/msg_types.h"

#define AT_DEVICE_CERT_FILENAME "device_cert.cfg.json"

/** Register the device handlers on @p proc (from at_first_contact_register). */
void at_device_contact_register(process_t *proc);
/** This node's device cert into @p out: 0, or -1 when none is installed, it
 *  does not verify, or it names another node (logged). at_dir_free it. */
int at_device_own_cert(const process_t *proc, at_dir_signed_t *out);
/** Push our device cert, sealed, to @p only (NULL: every device of every
 *  contact that is a peer now). @return how many were sent. */
int at_device_push_own_cert(const process_t *proc, const public_identity_t *only);
/** Announce this node, plaintext, to every device of every contact in the
 *  store. @return how many were sent (0 without a cert). */
int at_device_announce(const process_t *proc);
/** Announce this node to every device of @p c only (a contact a sibling just
 *  gave us). @return how many were sent. */
int at_device_announce_contact(const process_t *proc, const contact_t *c);

bool handle_device_cert(const process_t *proc, directory_t *queues, generic_msg_t *msg);
bool handle_device_announce(const process_t *proc, directory_t *queues, generic_msg_t *msg);

#endif /* AUTONOMOUS_TRUST_IDENTITY_DEVICE_CONTACT_H */
