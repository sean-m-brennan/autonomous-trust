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

/* The two wire verbs. DEFINED beside the rest of the identity verb table in
 * id_proc.c -- that file is the one place that owns these strings, so drift
 * against Python's IdentityProtocol stays visible in a single screen -- and
 * declared here because this module is what sends and receives them.
 * Mirrors Python IdentityProtocol.hello / .hello_ack. */
extern char ID_FC_HELLO[];
extern char ID_FC_HELLO_ACK[];

/** Environment flag naming. The feature is opt-in; absent/empty means OFF.
 *  Mirrors Python first_contact._FLAG. */
#define AT_FIRST_CONTACT_ENV "AT_FIRST_CONTACT"

/** Durable single-use guard, written beside the rest of AT's config.
 *  Mirrors Python SpentNonces.FILENAME + Configuration.file_ext. */
#define AT_FC_NONCE_FILENAME "first_contact_nonces.cfg.json"
#define AT_FC_NONCE_TYPENAME "first_contact_nonces"
#define AT_FC_NONCE_VERSION 1

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
 *  so the next handler call reloads from the CURRENT data dir. Models a
 *  restart, and keeps one scenario's nonces out of the next one. */
void at_first_contact_reset(void);

#endif /* AUTONOMOUS_TRUST_IDENTITY_FIRST_CONTACT_H */
