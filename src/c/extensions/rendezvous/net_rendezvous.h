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

#ifndef NET_RENDEZVOUS_H
#define NET_RENDEZVOUS_H

/**
 * @file net_rendezvous.h
 * @brief Rendezvous in the network process: the local verbs it owns, its
 *        relay routes, and what it offers a feature that rides its relays
 *        (FEATURE_SPLIT_PLAN Phase 7, R1 and R2).
 *
 * First contact plugs two services into the relay this way: the directory
 * registry ("dir_" ops) and the area hub ("hub_" ops). A service registers one
 * @ref net_rdv_service_t. Rendezvous then
 *
 *  - attaches its answer handler to every relay client it holds, for the ops
 *    starting with its prefix (net_relay_client_on_op);
 *  - calls @c own_registered each time we register at one of our OWN relays,
 *    so the service refiles what it holds there (a relay keeps it in memory);
 *  - calls @c server_started once our relay server is up ($AT_RELAY), so the
 *    service plugs in its server ops (net_relay_server_add_op);
 *  - calls @c reset from net_relay_reset_routes (tests).
 *
 * The service reaches the relays through @ref net_rendezvous_clients and
 * net_relay_client_request, and asks the relay gate through
 * net_relay_is_distrusted. Filled before main(), then read-only, so unlocked,
 * as the other registries. Mirrors Python rendezvous's RelayService.
 */

#include <stdbool.h>
#include <stddef.h>

#include <uuid/uuid.h>

#include "network/net_proc_priv.h"
#include "rendezvous/net_relay.h"

/* -- the local verbs rendezvous owns (FEATURE_SPLIT_PLAN Phase 7b) -------- */
/* Local IPC from identity: reach peer {uuid} through relay {relay}
 * ("host:port"), learned from a first-contact invitation's hint. Mirrors
 * Python Network.relay_route. See rendezvous/net_relay.h. */
extern char NET_FN_RELAY_ROUTE[];
/** network -> identity, local IPC: an own relay proved who it is. */
extern char NET_FN_RELAY_IDENTITY[];
/** network -> identity, local IPC: a known peer is talking to us through a
 *  relay ({uuid}), first in this run or through another relay than before.
 *  First contact answers a contact with our reachability record. Mirrors
 *  Python Network.relay_peer. */
extern char NET_FN_RELAY_PEER[];
/** identity -> network, local IPC: our own reachability record to publish. */
extern char NET_FN_REACH_PUBLISH[];

/* -- the network process's relay state (rdv_net.c) ------------------------- */
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

/** @brief Stands in for the relay clients (tests): every relayed send goes to
 *  @p fn instead, which returns 0 when the relay "took" it. NULL restores. */
typedef int (*net_relay_test_send_fn)(const char *host, int port,
                                      const uuid_t to, const uint8_t *buf,
                                      size_t len);
void net_relay_set_test_sender(net_relay_test_send_fn fn);
/** @brief The process whose peers[] the relay gate consults when there is no
 *  network context (tests). */
void net_relay_set_test_proc(const process_t *proc);

/* -- services riding the relays (R1, R2) ----------------------------------- */
/** Most services the relay carries. */
#define NET_RDV_SERVICES_MAX 4

/** One service riding the relays. Every member but @c name may be NULL. */
typedef struct {
    /** Unique; for logs. */
    const char *name;
    /** Its ops' family prefix ("dir_"). */
    const char *prefix;
    /** An answer to one of its ops, on the client's reader thread. */
    net_relay_op_fn on_answer;
    void *answer_arg;
    /** We registered at our own relay @p ep (client @p c). */
    void (*own_registered)(const net_relay_ep_t *ep, net_relay_client_t *c);
    /** Our relay server is up. */
    void (*server_started)(net_relay_server_t *srv, net_thread_ctx_t *ctx);
    /** Drop the service's network-process state (tests). */
    void (*reset)(void);
} net_rdv_service_t;

/** Register @p svc (static storage). @return 0; -1 bad, duplicate or full. */
int net_rendezvous_service_register(const net_rdv_service_t *svc);

/** The relays an op can go to now: every connected client, or only those at
 *  our own relays when @p own_only. At most @p max into @p eps / @p cs.
 *  @return how many. */
size_t net_rendezvous_clients(bool own_only, net_relay_ep_t *eps,
                              net_relay_client_t **cs, size_t max);

/** Register @p svc at load time. */
#define NET_RDV_SERVICE_REGISTER(tag, svc)                                        \
    static void __attribute__((constructor)) net_rdv_service_register_##tag(void) \
    {                                                                             \
        (void)net_rendezvous_service_register(svc);                               \
    }

#endif /* NET_RENDEZVOUS_H */
