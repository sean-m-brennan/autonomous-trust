/********************
 *  Copyright 2025 Sean M. Brennan and contributors
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
#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "utilities/logger.h"

int network_udp_ip4_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger);

int network_udp_ip6_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger);

int network_tcp_ip4_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger);

int network_tcp_ip6_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger);

/* Shared runner selected by transport name; used by per-transport process
 * declarations (including the dtn_bp entry when AT_NET_DTN is enabled). */
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

/** @brief Process one inbound BROADCAST-channel frame. See @ref handle_inbound_peer. */
void handle_inbound_broadcast(net_thread_ctx_t *ctx,
                              uint8_t *buf, size_t nbytes,
                              const char *from_addr);

/** @brief Process one inbound GROUP-channel frame. See @ref handle_inbound_peer. */
void handle_inbound_group(net_thread_ctx_t *ctx,
                          uint8_t *buf, size_t nbytes,
                          const char *from_addr);

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

#endif  // NET_PROC_PRIV_H
