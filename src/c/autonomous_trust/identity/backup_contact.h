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

/** @file An encrypted backup of the address book, through the node
 *  (FIRST_CONTACT_PLAN Phase 4, recovery). C twin of Python
 *  identity/backup_contact.py; part of first contact, so registered by
 *  at_first_contact_register and off unless `AT_FIRST_CONTACT` is on.
 *
 *  app_backup_export {ref, path, passphrase | generate: true} seals the book
 *  and the sibling list (contacts/backup.h) into @c path, atomically, mode
 *  0600, and answers AT_APP_EVENT_BACKUP_WRITTEN (with the made passphrase
 *  when asked to make one). app_backup_import {ref, path, passphrase} merges
 *  it in -- the side effects of an address book from a sibling, with origin
 *  AT_FC_ORIGIN_BACKUP -- and answers BACKUP_RESTORED. Refusals are
 *  BACKUP_REFUSED with a reason. The node never handles the operator key: a
 *  backup carrying one (tools/backup.py) restores its book here and leaves the
 *  key to that tool.
 */
#ifndef AUTONOMOUS_TRUST_IDENTITY_BACKUP_CONTACT_H
#define AUTONOMOUS_TRUST_IDENTITY_BACKUP_CONTACT_H

#include <stdbool.h>

#include "processes/processes.h"
#include "utilities/msg_types.h"

/** Register the backup handlers on @p proc (from at_first_contact_register). */
void at_backup_contact_register(process_t *proc);

bool handle_app_backup_export(const process_t *proc, directory_t *queues,
                              generic_msg_t *msg);
bool handle_app_backup_import(const process_t *proc, directory_t *queues,
                              generic_msg_t *msg);

#endif /* AUTONOMOUS_TRUST_IDENTITY_BACKUP_CONTACT_H */
