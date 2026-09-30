/********************
 *  Copyright 2024 TekFive, Inc., Sean M. Brennan, and contributors
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

#ifndef NET_PROC_PRIV_H
#define NET_PROC_PRIV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <uuid/uuid.h>

#include "processes/processes.h"
#include "network/net_transport.h"
#include "network/net_relay.h"
#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "utilities/logger.h"

int network_udp_ip4_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger);

int network_udp_ip6_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger);

int network_tcp_ip4_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger);

int network_tcp_ip6_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger);

/* Shared runner selected by transport name; used by per-transport process
 * declarations, and by extension transports' DEFINE_PROCESS runners (DTN,
 * src/c/extensions/dtn/). */
int network_run_by_name(const char *impl_name, process_t *proc,
                        directory_t *queues, queue_id_t signal,
                        logger_t *logger);

/**
 * @brief State shared by a network process's three receiver threads.
 *
 * Exposed here (rather than being a private struct in net_proc.c) so
 * tests can drive the inbound handlers directly without bringing up
 * real sockets + daemonize()'d processes. See test/net_proc_relay_test.c.
 */
typedef struct {
    const net_transport_t *transport;
    net_transport_ctx_t   *ctx;
    process_t             *proc;
    directory_t           *queues;
    logger_t              *logger;
    network_config_t      *net_cfg;
    identity_t            *myself;
    bool                  *stop;

    /** Optional pointer to the transport's extra-config struct (e.g.
     *  hybrid_config_t for hybrid_net). NULL for transports that don't
     *  use one, or when the matching config entry is absent. Read by the
     *  gateway's group forward (libat_gateway) to reach
     *  hybrid_config_t::group_routes. */
    const void            *transport_cfg;
} net_thread_ctx_t;

/**
 * @brief Process one inbound PEER-channel frame.
 *
 * Extracted from peer_receiver_thread's loop body so integration tests
 * can drive the handler with crafted bytes. @p buf / @p nbytes must
 * already have been returned by transport->recv; @p from_addr is the
 * sender's transport address as that transport reports it (IP for
 * UDP/TCP, EID for DTN, gateway-IP for a forwarded frame).
 *
 * Consumes @p buf: the handler does NOT free it; the caller retains
 * ownership (matching the thread-loop contract where the thread frees
 * after the handler returns).
 */
void handle_inbound_peer(net_thread_ctx_t *ctx,
                         uint8_t *buf, size_t nbytes,
                         const char *from_addr);

/** @brief Process one frame a rendezvous relay delivered (net_relay.h),
 *  attributed by @p from_uuid -- the sender the RELAY vouched for -- rather
 *  than by an address. A known peer takes the ordinary peer path; from a
 *  stranger only plaintext is read, and only if its envelope names the same
 *  sender. The caller keeps @p buf. */
void handle_inbound_relayed(net_thread_ctx_t *ctx, const uint8_t *buf,
                            size_t nbytes, const char *from_uuid);

/** @brief Identity's relay_route {uuid, relay}: reach that peer through that
 *  relay. Refused (-1) from the wire -- a peer must not reroute this node's
 *  traffic -- and when unusable; 0 when the route is set. */
int net_handle_relay_route(net_msg_t *nmsg, logger_t *logger);

/** @brief True iff @p peer is routed through a relay (tests). */
bool net_relay_has_route(const uuid_t peer);
/** @brief @p peer's relays, active first, into @p out (tests). @return how many. */
size_t net_relay_route_endpoints(const uuid_t peer, net_relay_ep_t *out,
                                 size_t max);
/** @brief Forget every relay route (tests). */
void net_relay_reset_routes(void);

/** @brief Send @p buf to @p peer through its active relay, failing over down
 *  its route when one cannot be reached. 0 sent; -1 no relay reached it; 1 the
 *  peer has no relay route (send it directly). */
int net_relay_send_to_peer(const uuid_t peer, const uint8_t *buf, size_t len);
/** @brief Queue a relay's "unreachable" answer, as a client's reader does. */
void net_relay_note_unreachable(const char *host, int port, const char *to_uuid);
/** @brief Fail over and resend for each queued "unreachable". Run by the loop. */
void net_relay_drain_unreachable(void);
/** @brief Resend frames every relay refused whose retry is due. Run by the loop. */
void net_relay_retry_refused(void);
/** @brief Seconds before a refused frame is retried (tests shorten it). */
void net_relay_set_retry_sec(int sec);
/** @brief Reputation cut @p uuid off (@p excluded) or readmitted it: gates it
 *  as a relay client and as a relay, by uuid and by the key we hold for it. */
void net_relay_note_exclusion(const char *uuid, bool excluded);
/** @brief The relay gate: is @p uuid (proven to hold @p pubkey_hex)
 *  distrusted? See net_proc.c. */
bool net_relay_is_distrusted(const char *uuid, const char *pubkey_hex);
/** @brief Identity's reach_publish {body, sig}: our own reachability record,
 *  filed at our relays now and at each registration. Refused from the wire. */
int net_handle_reach_publish(net_msg_t *nmsg, logger_t *logger);
/** @brief Hand relay lookup answers to identity. Run by the loop. */
void net_relay_drain_records(void);

/** @brief The directory (net_registry.h), identity's local IPC: file our entry
 *  ({entry}) at our relays now and at each registration; withdraw it
 *  ({handle}); look a handle up at every relay we are registered at
 *  ({handle}). Each refused from the wire. Mirror Python
 *  NetworkProcess.handle_dir_*. */
int net_handle_dir_publish(net_msg_t *nmsg, logger_t *logger);
int net_handle_dir_withdraw(net_msg_t *nmsg, logger_t *logger);
int net_handle_dir_lookup(net_msg_t *nmsg, logger_t *logger);
/** @brief A registry's answer, as a relay client's on_dir (the reader thread);
 *  queued for @ref net_relay_drain_dir. Tests call it directly. */
void net_relay_dir_answer(void *arg, const json_t *msg, const char *host, int port);
/** @brief Hand registry answers to identity: a lookup's ONE outcome (the first
 *  entry found, or null once every relay asked has answered or 10 s passed)
 *  and the registry's word on our publish or withdraw. Run by the loop. */
void net_relay_drain_dir(void);
/** @brief Tests: make every lookup in flight @p seconds older. */
void net_relay_dir_age_lookups(double seconds);
/** @brief Stands in for the relay clients' dir_* requests (tests): each goes
 *  to @p fn (op "dir_publish" | "dir_withdraw" | "dir_lookup"), for each of
 *  our own relays as if connected. NULL restores. */
typedef int (*net_relay_test_dir_fn)(const char *host, int port, const char *op,
                                     const char *handle, const json_t *entry);
void net_relay_set_test_dir(net_relay_test_dir_fn fn);

/** @brief Area hubs (net_hub.h), identity's local IPC: file our card ({card})
 *  at our relays now and at each registration; withdraw it ({area}); ask every
 *  relay we are registered at who is listed in an area ({area}). Each refused
 *  from the wire. Mirror Python NetworkProcess.handle_hub_*. */
int net_handle_hub_publish(net_msg_t *nmsg, logger_t *logger);
int net_handle_hub_withdraw(net_msg_t *nmsg, logger_t *logger);
int net_handle_hub_lookup(net_msg_t *nmsg, logger_t *logger);
/** @brief A hub's answer, as a relay client's on_hub (the reader thread);
 *  queued for @ref net_relay_drain_hub. Tests call it directly. */
void net_relay_hub_answer(void *arg, const json_t *msg, const char *host, int port);
/** @brief Hand hub answers to identity: a lookup's ONE outcome (every card
 *  any relay asked held, once each has answered or 10 s passed) and a hub's
 *  word on our publish or withdraw (a relay that is no hub is not reported).
 *  Run by the loop. */
void net_relay_drain_hub(void);
/** @brief Tests: make every area lookup in flight @p seconds older. */
void net_relay_hub_age_lookups(double seconds);
/** @brief Stands in for the relay clients' hub_* requests (tests), as
 *  net_relay_set_test_dir does for dir_*: op "hub_publish" | "hub_withdraw" |
 *  "hub_lookup", @p area, and @p card for a publish. NULL restores. */
typedef int (*net_relay_test_hub_fn)(const char *host, int port, const char *op,
                                     const char *area, const json_t *card);
void net_relay_set_test_hub(net_relay_test_hub_fn fn);
/** Seconds an area lookup waits for its relays. Same as Python HUB_LOOKUP_TIMEOUT. */
#define NET_HUB_LOOKUP_TIMEOUT_SEC 10.0
#define NET_HUB_MAX_LOOKUPS 8

/** Seconds a lookup waits for its relays. Same as Python DIR_LOOKUP_TIMEOUT. */
#define NET_DIR_LOOKUP_TIMEOUT_SEC 10.0
#define NET_DIR_MAX_LOOKUPS 32
#define NET_DIR_MAX_ASKED 16
typedef struct {
    bool used;
    char handle[128 + 1];
    net_relay_ep_t asked[NET_DIR_MAX_ASKED];
    bool answered[NET_DIR_MAX_ASKED];
    size_t n_asked;
    bool limited;
    double since;
} net_dir_lookup_t;

/** @brief Stands in for the relay clients (tests): every relayed send goes to
 *  @p fn instead, which returns 0 when the relay "took" it. NULL restores. */
typedef int (*net_relay_test_send_fn)(const char *host, int port,
                                      const uuid_t to, const uint8_t *buf,
                                      size_t len);
void net_relay_set_test_sender(net_relay_test_send_fn fn);
/** @brief The process whose peers[] the relay gate consults when there is no
 *  network context (tests). */
void net_relay_set_test_proc(const process_t *proc);

/** @brief Process one inbound BROADCAST-channel frame. See @ref handle_inbound_peer. */
void handle_inbound_broadcast(net_thread_ctx_t *ctx,
                              uint8_t *buf, size_t nbytes,
                              const char *from_addr);

/** @brief Process one inbound GROUP-channel frame. See @ref handle_inbound_peer. */
void handle_inbound_group(net_thread_ctx_t *ctx,
                          uint8_t *buf, size_t nbytes,
                          const char *from_addr);

/**
 * @brief The registered peer whose identity uuid is @p uuid, or NULL.
 *
 * For a frame whose originator is named in the frame (the routing envelope)
 * rather than by the transport address, which may be a gateway's. The
 * pointer stays valid: peers[] is append-only and never reallocated.
 */
const public_identity_t *net_find_peer_by_uuid(const process_t *proc, const uuid_t uuid);

/* ---- Test-only hooks for the deferred-message retry path ----
 * These let tests observe and reset the module-local `deferred_messages`
 * ring without exposing the struct itself. They are safe to call in
 * production but have no legitimate non-test use. */

/** @brief Number of entries currently pending retry. */
size_t net_proc_test_deferred_count(void);

/** @brief Reset the deferred ring to empty. Tests call this before
 *         exercising defer behavior so they don't inherit sibling
 *         tests' residue. */
void net_proc_test_reset_deferred(void);

/** @brief True iff the deferred entry at @p idx would be retried for
 *         @p new_peer under the current match rules (envelope src_uuid
 *         if present, else from_addr). Returns false if @p idx is out
 *         of range. */
bool net_proc_test_deferred_matches_peer(size_t idx,
                                         const public_identity_t *new_peer);

/** @brief Defer a (non-envelope) message — populate the queue without a
 *         live socket. */
void net_proc_test_defer(const uint8_t *data, size_t len, const char *from_addr);

/** @brief Backdate every queued entry by @p secs, so a test can simulate
 *         time passing and trigger age-out without sleeping. */
void net_proc_test_backdate_deferred(int64_t secs);

/** @brief Run the age-out sweep now; returns the number of surviving entries. */
size_t net_proc_test_sweep_stale(void);

/* ---- Test-only hooks for the pest / annoy-limit path ----
 * A tunable that never reaches its comparison is decorative, which is the
 * failure mode doc/architecture/networking.md is about. These let a test drive the counter
 * and observe the blacklist promotion without a live socket. */

/** @brief Clear the pest counters and the blacklist. */
void net_proc_test_reset_pests(void);

/** @brief Record one annoyance from @p address, exactly as the receive path
 *         does; promotes to the blacklist past the resolved annoy limit. */
void net_proc_test_track_annoy(const char *address);

/** @brief True iff @p address is currently blacklisted (its traffic is
 *         dropped before any further processing). */
bool net_proc_test_is_rejected(const char *address);

/* ---- Test-only: route_to_process capture ----
 * Tests for AT_DISCOVERY_CROSS_CLUSTER observe whether a forwarded
 * broadcast preserved the wire payload's self-reported from_whom.address
 * or clobbered it with the gateway's transport address. */

/** @brief Clear the capture buffer. Call before exercising a handler so
 *         stale residue from a prior test doesn't confuse assertions. */
void net_proc_test_reset_last_routed_from_addr(void);

/** @brief Copy the most recent address observed by route_to_process into
 *         @p out (NUL-terminated, truncated to @p outlen). Empty string
 *         if no call has happened since the last reset. */
void net_proc_test_get_last_routed_from_addr(char *out, size_t outlen);

/* ---- ping_at refusal (divergence: C implements no PingAT) ----
 * The outbound drain answers the `ping_at` selector with an explicit refusal
 * instead of performing one. Exposed here (not in network.h) so a test can
 * assert the reply's selector and body without standing up a whole network
 * process; it is not public API. */

/** @brief Post `{"error":"unsupported", ...}` on the NET_FN_PING_AT selector to
 *         @p return_to. Local IPC only — never a wire message.
 *  @return 0 when the refusal was posted, non-zero on alloc/send failure. */
int refuse_ping_at_unsupported(const char *target_addr, const char *return_to,
                            logger_t *logger);

#endif  // NET_PROC_PRIV_H
