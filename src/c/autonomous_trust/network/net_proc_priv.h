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
#include "network/net_message.h"   /* net_wire_msg_t */
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

/** @brief Process one inbound BROADCAST-channel frame. See @ref handle_inbound_peer. */
void handle_inbound_broadcast(net_thread_ctx_t *ctx,
                              uint8_t *buf, size_t nbytes,
                              const char *from_addr);

/** @brief Process one inbound GROUP-channel frame. See @ref handle_inbound_peer. */
void handle_inbound_group(net_thread_ctx_t *ctx,
                          uint8_t *buf, size_t nbytes,
                          const char *from_addr);

/** How many group frames that did not open are held for a key change, and for
 *  how long (seconds) before one is dropped if no new key arrives. */
#define NET_HELD_GROUP_FRAMES 16
#define NET_HELD_GROUP_FRAME_SEC 10

/** Try again every held group frame whose key differs from the one installed
 *  now; one that still does not open is dropped. Drops frames held longer than
 *  NET_HELD_GROUP_FRAME_SEC. The group receiver calls it every poll; returns
 *  how many were retried. */
size_t net_retry_held_group_frames(net_thread_ctx_t *ctx);

/** Test seams: how many group frames are held; forget them all. */
size_t net_held_group_frame_count(void);
void net_held_group_frames_reset(void);

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

/** @brief route_to_process (the hand-off of every inbound wire frame to its
 *         sibling process), for a test that drives it with a refusing
 *         messaging hook (ISSUES §2.14). Not public API. Routes as a frame
 *         from a peer we hold (NET_PATH_PEER). */
int net_proc_test_route_to_process(const net_wire_msg_t *wmsg, process_t *proc,
                                   logger_t *logger);

/** The receive path an inbound wire frame came in on. It decides which verbs
 *  route_to_process lets through (ISSUES §2.17): a stranger's paths carry only
 *  what a node says before it shares a key with us. */
typedef enum {
    NET_PATH_PEER,           /* decrypted from a peer we hold, or replayed after
                              * its admission */
    NET_PATH_PLAIN_KNOWN,    /* plaintext from a peer we hold (allowlisted at
                              * try_unencrypted_from_known_peer) */
    NET_PATH_STRANGER,       /* plaintext from an address we cannot place */
    NET_PATH_RELAY_STRANGER, /* relayed from a uuid we do not hold */
    NET_PATH_BROADCAST,      /* the broadcast (discovery) channel */
    NET_PATH_GROUP,          /* group-encrypted, from a peer we hold */
} net_route_path_t;

/** route_to_process's return when the frame's verb is not let in on its path
 *  (the frame is dropped, not routed). */
#define NET_ROUTE_REFUSED 1

/** @brief Whether a wire frame for @p process / @p function may be routed when
 *         it came in on @p path. Never an `app_*` verb (those are the local
 *         app's commands and never travel), never a command to the network
 *         process except a remote stats_req, and on a stranger's or the
 *         broadcast path only the plaintext / broadcast verbs. @p why, when
 *         not NULL, is set to a static reason on refusal. */
bool net_wire_verb_admitted(const char *process, const char *function,
                            net_route_path_t path, const char **why);

/** @brief route_to_process for @p wmsg as if it came in on @p path. Returns
 *         NET_ROUTE_REFUSED when the verb is not let in there. Not public
 *         API. */
int net_proc_test_route_on_path(const net_wire_msg_t *wmsg, process_t *proc,
                                logger_t *logger, net_route_path_t path);

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
