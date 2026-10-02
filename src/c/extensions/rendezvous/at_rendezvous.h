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

/**
 * @file at_rendezvous.h
 * @brief Rendezvous's part of the flat app ABI (libat_rendezvous): trusting a
 *        community's relay roster, and the events that answer it.
 *
 * FEATURE_SPLIT_PLAN Phase 7b, D10. The two verbs used to be first contact's;
 * they keep their names, and their events keep kinds 1028-1030 inside first
 * contact's reserved range, so nothing an app already handles renumbers. They
 * are identity handlers that rendezvous registers, as every app verb targets
 * identity. The events ride rendezvous's own message type (AT_MSG_TYPE_RDV_MIN,
 * utilities/msg_registry.h). Python's twin is autonomous_trust.rendezvous's
 * roster module.
 */

#ifndef AT_RENDEZVOUS_PUBLIC_H
#define AT_RENDEZVOUS_PUBLIC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "app_events.h"

#ifdef __cplusplus
extern "C" {
#endif

/** The roster app verbs. Local IPC only: the node refuses either one arriving
 *  from the wire. Same strings as Python's. */
#define AT_APP_ROSTER_INSTALL  "app_relay_roster_install"
#define AT_APP_ROSTER_REMOVE   "app_relay_roster_remove"

/* The roster events: payload @ref at_app_roster_t, read with
 * @ref at_rendezvous_roster_event. */
#define AT_APP_EVENT_ROSTER_INSTALLED    1028  /**< @c issuer, @c seq */
#define AT_APP_EVENT_ROSTER_REFUSED      1029  /**< @c reason: bad_request | invalid | stale */
#define AT_APP_EVENT_ROSTER_REMOVED      1030  /**< @c issuer; @c count 1 if one was there */

/** @c ref buffer: the app's own correlation string, at most 63 bytes. */
#define AT_RDV_REF_LEN 64
/** @c issuer buffer: a hex ed25519 key and a NUL. */
#define AT_RDV_ISSUER_LEN 65
/** @c reason buffer. */
#define AT_RDV_REASON_LEN 32

/** One roster outcome. Every field is written on every event; those a kind
 *  does not use are zero. */
typedef struct {
    char    ref[AT_RDV_REF_LEN];
    /** INSTALLED / REMOVED: the community key the roster is signed by. */
    char    issuer[AT_RDV_ISSUER_LEN];
    /** REFUSED: why. */
    char    reason[AT_RDV_REASON_LEN];
    /** INSTALLED: the roster's sequence number. */
    int64_t seq;
    /** REMOVED: 1 if one was installed. */
    int32_t count;
} at_app_roster_t;

AT_APP_STATIC_ASSERT(sizeof(at_app_roster_t) <= AT_APP_EVENT_PAYLOAD_MAX,
                     "at_app_roster_t fits the app event payload");

/** @brief The roster payload of @p ev, or NULL unless @p ev is one of the
 *  AT_APP_EVENT_ROSTER_* kinds. */
const at_app_roster_t *at_rendezvous_roster_event(const at_app_event_t *ev);

/** @brief Trust a community's relay roster (@p roster, the file's {body, sig}
 *  JSON): pin its issuer and file it. Answered by ROSTER_INSTALLED or
 *  ROSTER_REFUSED under @p ref. 0 sent; AT_APP_NOT_READY when the node has
 *  not bound @p q_out yet; -1 otherwise. */
int at_app_relay_roster_install(at_app_events_t *handle, const char *q_out,
                                const char *ref, const char *roster);
/** @brief Stop trusting @p issuer's roster (hex key). Answered by
 *  ROSTER_REMOVED or ROSTER_REFUSED. Returns as at_app_relay_roster_install. */
int at_app_relay_roster_remove(at_app_events_t *handle, const char *q_out,
                               const char *ref, const char *issuer);

/** @brief Keeps rendezvous's registrations in a static link. A consumer that
 *  links at_rendezvous_static without --whole-archive calls it once. */
void at_rendezvous_link(void);

#ifdef __cplusplus
}
#endif

#endif /* AT_RENDEZVOUS_PUBLIC_H */
