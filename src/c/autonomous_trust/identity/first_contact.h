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

/** @file The live 1:1 first-contact handshake (C twin of Python
 *  `identity/first_contact.py`).
 *
 *  OPTIONAL and off by default: nothing here runs unless the node opts in with
 *  the `AT_FIRST_CONTACT` environment flag, so a default deployment registers
 *  no handlers and behaves exactly as before. Kept as its own translation unit
 *  (rather than folded into the 7k-line id_proc.c) for the same reason Python
 *  keeps it out of idprocess.py: the feature is a self-contained add-on.
 *
 *  The flow (doc/architecture/first-contact.md, §4.0/§4.1):
 *
 *    1. Alice mints a signed invitation carrying her endpoint (at_create_
 *       invitation) and shares the link out of band.
 *    2. Bob redeems it (the offline contacts slice) and calls
 *       @ref at_first_contact_initiate, which sends `first_contact_hello` to
 *       Alice's endpoint on the OPEN unencrypted channel -- unencrypted
 *       because Alice does not know Bob yet. The hello carries Bob's identity
 *       (on the envelope) and the invitation blob as his ticket.
 *    3. Alice's @ref handle_first_contact_hello validates the ticket -- HER
 *       signature, not expired, and the nonce not already spent (invitations
 *       are SINGLE-USE) -- then admits Bob as a DIRECT peer and replies
 *       `first_contact_hello_ack`.
 *    4. Bob's @ref handle_first_contact_hello_ack admits Alice in turn. Both
 *       now hold each other's keys, so the encrypted point-to-point channel
 *       and reputation work.
 *
 *  "Direct peer" is narrower than group admission: admission goes through
 *  @ref identity_admit_direct_peer, which records the peer (visibility,
 *  reputation, P2P attribution) but never propagates the group key and never
 *  inserts into the group identity history -- a contact is not a group member.
 *  The contact stays unverified until the out-of-band safety-number compare
 *  (at_verify_contact, contacts/contacts.h).
 */
#ifndef AUTONOMOUS_TRUST_IDENTITY_FIRST_CONTACT_H
#define AUTONOMOUS_TRUST_IDENTITY_FIRST_CONTACT_H

#include <stdbool.h>
#include <stddef.h>

#include "processes/processes.h"
#include "utilities/msg_types.h"
#include "utilities/msg_registry.h"
#include "at_first_contact.h"
#include "contacts/contacts.h"

/* The two wire verbs. DEFINED beside the rest of the identity verb table in
 * id_proc.c -- that file is the one place that owns these strings, so drift
 * against Python's IdentityProtocol stays visible in a single screen -- and
 * declared here because this module is what sends and receives them.
 * Mirrors Python IdentityProtocol.hello / .hello_ack. */
extern char ID_FC_HELLO[];
extern char ID_FC_HELLO_ACK[];
extern char ID_FC_REQUEST[];
extern char ID_FC_ACCEPT[];
extern char ID_FC_DEVICE_CERT[];
extern char ID_FC_DEVICE_ANNOUNCE[];

/** The app-bound event: one message type carrying all four outcomes, its
 *  public kind beside the flat payload. Registered (app_bound) in
 *  first_contact_app.c, so the main loop forwards it to the app and
 *  at_app_events_poll decodes it. Local IPC only; no wire form. */
#define FIRST_CONTACT_EVENT ((message_type_t)(AT_MSG_TYPE_FC_MIN + 0))

typedef struct {
    int32_t kind;                   /* AT_APP_EVENT_FC_* */
    at_app_first_contact_t data;
} fc_event_msg_t;

/** The address-book answers, a second app-bound type for the second payload
 *  shape (kinds AT_APP_EVENT_FC_CONTACT..REMOVED). */
#define FIRST_CONTACT_CONTACT_EVENT ((message_type_t)(AT_MSG_TYPE_FC_MIN + 1))

typedef struct {
    int32_t kind;
    at_app_contact_t data;
} fc_contact_msg_t;

/** The directory answers, a third app-bound type (kinds AT_APP_EVENT_DIR_*). */
#define FIRST_CONTACT_DIRECTORY_EVENT ((message_type_t)(AT_MSG_TYPE_FC_MIN + 2))

typedef struct {
    int32_t kind;
    at_app_directory_t data;
} fc_directory_msg_t;

/** The area answers, a fourth app-bound type (kinds AT_APP_EVENT_AREA_* and
 *  AT_APP_EVENT_ROSTER_*). */
#define FIRST_CONTACT_AREA_EVENT ((message_type_t)(AT_MSG_TYPE_FC_MIN + 3))

typedef struct {
    int32_t kind;
    at_app_area_t data;
} fc_area_msg_t;

/** The backup answers, a fifth app-bound type (kinds AT_APP_EVENT_BACKUP_*). */
#define FIRST_CONTACT_BACKUP_EVENT ((message_type_t)(AT_MSG_TYPE_FC_MIN + 4))

typedef struct {
    int32_t kind;
    at_app_backup_t data;
} fc_backup_msg_t;

/** Environment flag naming. The feature is opt-in; absent/empty means OFF.
 *  Mirrors Python first_contact._FLAG. */
#define AT_FIRST_CONTACT_ENV "AT_FIRST_CONTACT"

/** Durable single-use guard, written beside the rest of AT's config.
 *  Mirrors Python SpentNonces.FILENAME + Configuration.file_ext. */
#define AT_FC_NONCE_FILENAME "first_contact_nonces.cfg.json"
#define AT_FC_NONCE_TYPENAME "first_contact_nonces"
#define AT_FC_NONCE_VERSION 1

/** The highest trust tier an UNVERIFIED contact may use when it asks this node
 *  to run a capability: tier 1, communication (doc/architecture/trust-tiers.md).
 *  Same value as Python's first_contact.UNVERIFIED_TIER_CAP. */
#define AT_FC_UNVERIFIED_TIER_CAP 1

/** The tier @p peer may USE when it asks @p proc (any core process) to run a
 *  capability: @p tier, or @ref AT_FC_UNVERIFIED_TIER_CAP for a peer that is
 *  not a VERIFIED contact. Own-group members are never capped. A child-group
 *  member is capped only while on record as an unverified contact; any other
 *  peer is capped with no record too (a missing record counts as unverified).
 *  Nothing is capped while first contact is off. Mirrors Python
 *  first_contact.capped_tier. */
int at_first_contact_capped_tier(const process_t *proc, const unsigned char *peer,
                                 int tier);

/** Reconnect every saved contact at startup: re-admit each as a direct peer
 *  and route it through its recorded relays, then this node's own. A no-op
 *  while first contact is off. Runs from identity's run_start. @return how
 *  many contacts. Mirrors Python first_contact.restore_contacts. */
int at_first_contact_restore_contacts(process_t *proc);

/** The network process's NET_FN_RELAY_IDENTITY: one of our own relays proved
 *  who it is, so the links we mint pin it. Local only. */
bool handle_first_contact_relay_identity(const process_t *proc, directory_t *queues,
                                         generic_msg_t *msg);

/** A contact's signed reachability record (contacts/reach.h), pushed by the
 *  contact or handed on by our network process from a relay lookup. */
bool handle_first_contact_reach_record(const process_t *proc, directory_t *queues,
                                       generic_msg_t *msg);
/** Issue our own record if what it states changed (or it is past half its
 *  life), push it to contacts that are peers, and hand it to the network to
 *  file at our relays. */
void at_first_contact_refresh_own_record(const process_t *proc);

/** An app-minted invitation's lifetime when the request names none. Mirrors
 *  Python contacts.invitation.DEFAULT_TTL_SECONDS (a week). */
#define AT_FC_DEFAULT_TTL_SECONDS (7L * 24 * 3600)

/** True iff first contact is opted in via `AT_FIRST_CONTACT`. Accepts the same
 *  spellings as Python: 1/true/yes/on, case-insensitive. */
bool at_first_contact_enabled(void);

/** Register the two handlers on @p proc. Called from
 *  identity_register_handlers ONLY when @ref at_first_contact_enabled -- a
 *  default node registers nothing here. Also primes the durable spent-nonce
 *  guard, so a restart cannot let a redeemer re-present a still-unexpired
 *  invitation. */
int at_first_contact_register(process_t *proc);

/** Inviter side: honor a valid, single-use invitation WE minted, admit the
 *  sender as a direct peer, and acknowledge. Always returns true (a bad
 *  ticket is dropped, never fatal), mirroring Python handle_hello. */
bool handle_first_contact_hello(const process_t *proc, directory_t *queues,
                                generic_msg_t *msg);

/** Initiator side: the inviter accepted; admit them as a direct peer so the
 *  channel is live both ways (we already hold their key from the invitation).
 *  Mirrors Python handle_hello_ack. */
bool handle_first_contact_hello_ack(const process_t *proc, directory_t *queues,
                                    generic_msg_t *msg);

/** Initiator side: reach the inviter named in @p blob and open the handshake.
 *
 *  @param blob     the invitation link/blob (`at+contact:`-prefixed or bare).
 *  @param endpoint override the reachable host; NULL defaults to the
 *                  invitation's first rendezvous hint, then the inviter's
 *                  advertised address. Only the host is used -- Phase 1
 *                  assumes the shared comm port (cross-port waits on the
 *                  rendezvous relay layer).
 *  @param out      optional; receives the inviter's public identity (the
 *                  caller owns any operator_key_binding on it).
 *  @return 0 on success, an at_invite_status_t on a bad invitation, -1 otherwise.
 *  Mirrors Python first_contact.initiate. */
int at_first_contact_initiate(const process_t *proc, directory_t *queues,
                              const char *blob, const char *endpoint,
                              public_identity_t *out);

/** @ref at_first_contact_initiate, tagged with the app's @p ref (NULL = none),
 *  which the ESTABLISHED event echoes.
 *
 *  Both record the hello as PENDING for @ref AT_FC_PENDING_TTL_SECONDS: the
 *  inviter's ack is honored only while it is, only with the nonce of the
 *  ticket presented, and only when signed by the key that ticket carried.
 *  Mirrors Python first_contact.initiate(..., ref=). */
int at_first_contact_initiate_ref(const process_t *proc, directory_t *queues,
                                  const char *blob, const char *endpoint,
                                  const char *ref, public_identity_t *out);

/** @ref at_first_contact_initiate_ref, recording the contact the ack brings
 *  with @p provenance (AT_PROV_DIRECTORY for a directory contact's accept). */
int at_first_contact_initiate_prov(const process_t *proc, directory_t *queues,
                                   const char *blob, const char *endpoint,
                                   const char *ref, at_provenance_t provenance,
                                   public_identity_t *out);

/** The app asked this node to mint an invitation (AT_APP_FC_INVITE).
 *  Mirrors Python handle_app_invite. */
bool handle_first_contact_app_invite(const process_t *proc, directory_t *queues,
                                     generic_msg_t *msg);

/** The app handed this node a friend's invitation (AT_APP_FC_INITIATE).
 *  Mirrors Python handle_app_initiate. */
bool handle_first_contact_app_initiate(const process_t *proc,
                                       directory_t *queues, generic_msg_t *msg);

/** The address-book verbs (AT_APP_FC_SAFETY_NUMBER .. AT_APP_FC_REMOVE).
 *  Mirror Python handle_app_safety_number / _verify / _list / _rename /
 *  _remove. */
bool handle_first_contact_app_safety_number(const process_t *proc,
                                            directory_t *queues,
                                            generic_msg_t *msg);
bool handle_first_contact_app_verify(const process_t *proc, directory_t *queues,
                                     generic_msg_t *msg);
bool handle_first_contact_app_list(const process_t *proc, directory_t *queues,
                                   generic_msg_t *msg);
bool handle_first_contact_app_rename(const process_t *proc, directory_t *queues,
                                     generic_msg_t *msg);
bool handle_first_contact_app_remove(const process_t *proc, directory_t *queues,
                                     generic_msg_t *msg);

/** Reduce a rendezvous hint or advertised address to a bare host, writing it
 *  into @p out (cleared on any failure). Returns 0 on success, -1 on a NULL
 *  argument or when the host does not FIT.
 *
 *  Strips a `/path` tail and a trailing `:port`. Getting this right for IPv6 is
 *  why it is a named, tested function rather than two lines inline: a
 *  bracketless IPv6 literal cannot express a port (the colons are part of the
 *  address), so the `strrchr(raw, ':')` this replaced turned `fe80::1` into
 *  `fe80:` -- a well-formed address silently mangled into an unroutable one
 *  that still looks like an address.
 *
 *      10.0.0.1              -> 10.0.0.1
 *      10.0.0.1:9000         -> 10.0.0.1
 *      fe80::1               -> fe80::1           (no port is expressible)
 *      2001:db8::1%eth0      -> 2001:db8::1%eth0
 *      [fe80::1]             -> fe80::1
 *      [fe80::1]:9000        -> fe80::1
 *      relay.example:9000/x  -> relay.example
 *
 *  An unterminated bracket (`[fe80::1`) yields everything after the `[`: a best
 *  effort on malformed input, defined only so this and Python's
 *  `endpoint_host` agree on it.
 *
 *  TRUNCATION IS A FAILURE, not a shortening -- @p out is cleared and -1
 *  returned, following cidr_split (network/network.c): half an address still
 *  looks like an address, so clipping turns a local mistake into an
 *  apparently-unreachable peer. Callers pass an ADDR_LEN-sized buffer, and
 *  ADDR_LEN is 45 (`ADDR_LEN + 1` == IPV6_ADDR_LEN == INET6_ADDRSTRLEN), so
 *  every numeric address of either family now fits -- a full uncompressed IPv6
 *  literal included. The refusal branch survives for what does NOT fit: a
 *  scoped literal (`fe80::1%eth0`, which the transport's inet_pton rejects
 *  anyway) or a DNS name. This is the one place the C twin diverges from
 *  Python's `endpoint_host`, which has no length bound at all. */
int at_first_contact_endpoint_host(const char *raw, char *out, size_t out_len);

/* --- test / harness seams (mirrors identity_reset_state) ----------------- */

/** True iff @p nonce has already been honored by this node. Exposed so the
 *  conformance adapter can assert the durable single-use guard directly. */
bool at_first_contact_nonce_spent(const char *nonce);

/** Drop the in-memory spent-nonce guard and forget where it was loaded from,
 *  so the next handler call reloads from the CURRENT data dir. Also forgets
 *  every pending hello and every minted ref, which live only in memory. Models
 *  a restart, and keeps one scenario's state out of the next one. */
void at_first_contact_reset(void);

/** Keeps first contact's extension registration (processes/extension.h) in a
 *  static link: it is a constructor in first_contact.c, which a static link
 *  drops unless something references the object. No-op at run time. */
void at_first_contact_link(void);

/** The same for first_contact_app.c (the event type and its decoder), which
 *  at_first_contact_link pulls in. */
void at_first_contact_app_link(void);

#endif /* AUTONOMOUS_TRUST_IDENTITY_FIRST_CONTACT_H */
