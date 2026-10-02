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

/** @file What first_contact.c shares with directory_contact.c: internal to the
 *  identity process, not part of any public or FFI surface. (Deliberately not
 *  named first_contact_priv.h: a <module>_priv.h changes the generated
 *  process-table include.) */
#ifndef AUTONOMOUS_TRUST_IDENTITY_FC_SHARED_H
#define AUTONOMOUS_TRUST_IDENTITY_FC_SHARED_H

#include <stdbool.h>
#include <stddef.h>

#include <jansson.h>
#include <uuid/uuid.h>

#include "first_contact/at_first_contact.h"
#include "first_contact/contacts.h"
#include "identity/identity.h"
#include "rendezvous/net_relay.h"
#include "processes/processes.h"
#include "utilities/msg_types.h"

/** An envelope carrying a sender identity (a non-zero uuid). */
bool at_fc_has_sender(const public_identity_t *who);
/** Free what a public identity copy owns (its operator binding). */
void at_fc_free_public(public_identity_t *p);
/** The app request's JSON object, or NULL. Caller decrefs. */
json_t *at_fc_app_payload(net_msg_t *nmsg);
/** The request's ref ("" when absent), or NULL when it does not fit. */
const char *at_fc_app_ref(const json_t *req);
/** An invitation minted for our app, reported under @p ref when redeemed. */
void at_fc_remember_minted(const char *nonce, const char *ref);
/** A fresh invitation nonce (upper-case hex, as Python's). */
void at_fc_new_nonce(char out[33]);
/** The first-contact HELLO_SENT event, role initiator. */
void at_fc_emit_hello_sent(const process_t *proc, const char *ref,
                           const public_identity_t *peer);
/** Our own relays as hints, pinned to who they proved to be. @return how many. */
size_t at_fc_own_hints(char out[][AT_RELAY_HOST_LEN + 96], size_t max);
/** Push our reachability record, sealed, to @p only (NULL: every contact
 *  that is a peer now). */
void at_fc_push_own_record(const process_t *proc, const public_identity_t *only);
/** The DEVICE_LINKED contact event: @p device filed under @p c. */
void at_fc_emit_device_linked(const process_t *proc, const contact_t *c,
                              const uuid_t device);
/** The same, answering the app request tagged @p ref (an address-book list). */
void at_fc_emit_device_linked_ref(const process_t *proc, const char *ref,
                                  const contact_t *c, const uuid_t device);
/** Tell the network to reach @p uuid through @p hints (relay:// hints). */
void at_fc_send_route_hints(const uuid_t uuid, const char *const *hints, size_t n);
/** A first-contact event (at_app_first_contact_t payload). */
void at_fc_emit_event(const process_t *proc, int32_t kind, const char *ref,
                      const public_identity_t *peer, at_fc_reason_t reason,
                      at_fc_role_t role);
/** An address-book event for @p c, with @p origin (AT_FC_ORIGIN_*). */
void at_fc_emit_contact(const process_t *proc, int32_t kind, const char *ref,
                        const contact_t *c, bool dropped, int32_t origin);
/** A sibling event (at_app_contact_t payload): @p uuid, @p nickname and
 *  @p added_at may be NULL / 0. */
void at_fc_emit_sibling(const process_t *proc, int32_t kind, const char *ref,
                        const char *uuid, const char *nickname, double added_at,
                        bool dropped, int32_t count);

#endif /* AUTONOMOUS_TRUST_IDENTITY_FC_SHARED_H */
