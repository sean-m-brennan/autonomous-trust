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

#ifndef FC_NET_H
#define FC_NET_H

/**
 * @file fc_net.h
 * @brief First contact in the network process: the directory and area-hub
 *        clients, and the registry and hub a relay serves for it.
 *
 * FEATURE_SPLIT_PLAN Phase 7, R1/R2. Both ride the rendezvous relays as
 * services (network/net_rendezvous.h): their ops reach the relays through
 * net_relay_client_request, their answers come back through the service's
 * answer handler, and our relay serves the registry ("dir_") and the hub
 * ("hub_") through net_relay_server_add_op. Identity's local verbs reach this
 * module through first contact's network extension (network/net_ext.h).
 */

#include <stdbool.h>
#include <stddef.h>

#include <jansson.h>

#include "first_contact/area_card.h"
#include "network/net_message.h"
#include "utilities/msg_types.h"
#include "rendezvous/net_relay.h"
#include "utilities/logger.h"

/** identity -> network, local IPC: the directory. Mirror: Python Network.dir_*. */
extern char NET_FN_DIR_PUBLISH[];
extern char NET_FN_DIR_WITHDRAW[];
extern char NET_FN_DIR_LOOKUP[];
/** network -> identity, local IPC: a lookup's outcome, and a registry's answer
 *  to our publish or withdraw. Mirror: Python FirstContactProtocol.dir_result /
 *  dir_status. */
extern char NET_ID_DIR_RESULT[];
extern char NET_ID_DIR_STATUS[];
/** identity -> network, local IPC: area hubs. Mirror: Python Network.hub_*. */
extern char NET_FN_HUB_PUBLISH[];
extern char NET_FN_HUB_WITHDRAW[];
extern char NET_FN_HUB_LOOKUP[];
/** network -> identity, local IPC: an area lookup's outcome, and a hub's answer
 *  to our publish or withdraw. Mirror: Python FirstContactProtocol.hub_result /
 *  hub_status. */
extern char NET_ID_HUB_RESULT[];
extern char NET_ID_HUB_STATUS[];

/** @brief The directory (net_registry.h), identity's local IPC: file our entry
 *  ({entry}) at our relays now and at each registration; withdraw it
 *  ({handle}); look a handle up at every relay we are registered at
 *  ({handle}). Each refused from the wire. Mirror Python
 *  first contact's handle_dir_*. */
int fc_net_dir_publish(net_msg_t *nmsg, logger_t *logger);
int fc_net_dir_withdraw(net_msg_t *nmsg, logger_t *logger);
int fc_net_dir_lookup(net_msg_t *nmsg, logger_t *logger);
/** @brief A registry's answer, as a relay client's "dir_" answer (the reader thread);
 *  queued for @ref fc_net_drain_dir. Tests call it directly. */
void fc_net_dir_answer(void *arg, const json_t *msg, const char *host, int port);
/** @brief Hand registry answers to identity: a lookup's ONE outcome (the first
 *  entry found, or null once every relay asked has answered or 10 s passed)
 *  and the registry's word on our publish or withdraw. Run by the loop. */
void fc_net_drain_dir(void);
/** @brief Tests: make every lookup in flight @p seconds older. */
void fc_net_dir_age_lookups(double seconds);
/** @brief Stands in for the relay clients' dir_* requests (tests): each goes
 *  to @p fn (op "dir_publish" | "dir_withdraw" | "dir_lookup"), for each of
 *  our own relays as if connected. NULL restores. */
typedef int (*fc_net_test_dir_fn)(const char *host, int port, const char *op,
                                     const char *handle, const json_t *entry);
void fc_net_set_test_dir(fc_net_test_dir_fn fn);

/** @brief Area hubs (net_hub.h), identity's local IPC: file our card ({card})
 *  at our relays now and at each registration; withdraw it ({area}); ask every
 *  relay we are registered at who is listed in an area ({area}). Each refused
 *  from the wire. Mirror Python NetworkProcess.handle_hub_*. */
int fc_net_hub_publish(net_msg_t *nmsg, logger_t *logger);
int fc_net_hub_withdraw(net_msg_t *nmsg, logger_t *logger);
int fc_net_hub_lookup(net_msg_t *nmsg, logger_t *logger);
/** @brief A hub's answer, as a relay client's "hub_" answer (the reader thread);
 *  queued for @ref fc_net_drain_hub. Tests call it directly. */
void fc_net_hub_answer(void *arg, const json_t *msg, const char *host, int port);
/** @brief Hand hub answers to identity: a lookup's ONE outcome (every card
 *  any relay asked held, once each has answered or 10 s passed) and a hub's
 *  word on our publish or withdraw (a relay that is no hub is not reported).
 *  Run by the loop. */
void fc_net_drain_hub(void);
/** @brief Tests: make every area lookup in flight @p seconds older. */
void fc_net_hub_age_lookups(double seconds);
/** @brief Stands in for the relay clients' hub_* requests (tests), as
 *  fc_net_set_test_dir does for dir_*: op "hub_publish" | "hub_withdraw" |
 *  "hub_lookup", @p area, and @p card for a publish. NULL restores. */
typedef int (*fc_net_test_hub_fn)(const char *host, int port, const char *op,
                                     const char *area, const json_t *card);
void fc_net_set_test_hub(fc_net_test_hub_fn fn);
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
} fc_net_dir_lookup_t;


/** @brief Serve the directory with @p reg (NULL: refuse it, not_registry) and
 *  the area hub with @p hub (NULL: not_hub) on relay server @p srv, as our
 *  relay does once it starts. Tests call them directly. */
struct net_registry_s;
struct net_hub_s;
void fc_net_serve_registry(net_relay_server_t *srv, struct net_registry_s *reg);
void fc_net_serve_hub(net_relay_server_t *srv, struct net_hub_s *hub);

#endif /* FC_NET_H */
