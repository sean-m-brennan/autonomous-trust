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
 * @file at_fleet.h
 * @brief Fleet's part of the flat app ABI (libat_fleet): proposing a software
 *        update, and hearing that the cohort accepted one.
 *
 * FEATURE_SPLIT_PLAN Phase 8. An app holds no private key, so it sends the
 * proposal's fields unsigned; the node builds the proposal, signs it with its
 * own identity key, names itself the signer and puts it to the cohort's vote.
 * An acceptance comes back as kind AT_APP_EVENT_FLEET_UPDATE_ACCEPTED, from
 * fleet's own message type (FLEET_UPDATE_ACCEPTED, 2100). Fleet's kinds are
 * the block 1100-1109.
 */

#ifndef AT_FLEET_PUBLIC_H
#define AT_FLEET_PUBLIC_H

#include <stdint.h>

#include "app_events.h"

#ifdef __cplusplus
extern "C" {
#endif

/** The app's verb (local IPC only; the node refuses it from the wire). */
#define AT_APP_FLEET_PROPOSE "app_fleet_propose"

/** The cohort accepted a proposal: payload @ref at_app_fleet_accepted_t, read
 *  with @ref at_fleet_accepted_event. */
#define AT_APP_EVENT_FLEET_UPDATE_ACCEPTED 1100

/** One accepted proposal: which one. (Fleet does not count the votes where it
 *  announces the acceptance, so no tally is carried.) */
typedef struct {
    uint8_t proposal_uuid[AT_APP_UUID_LEN];
} at_app_fleet_accepted_t;

AT_APP_STATIC_ASSERT(sizeof(at_app_fleet_accepted_t) <= AT_APP_EVENT_PAYLOAD_MAX,
                     "at_app_fleet_accepted_t fits the app event payload");

/** @brief The acceptance in @p ev, or NULL unless @p ev is
 *  AT_APP_EVENT_FLEET_UPDATE_ACCEPTED. */
const at_app_fleet_accepted_t *at_fleet_accepted_event(const at_app_event_t *ev);

/** @brief Propose an update: @p version (at most 64 bytes), @p artifact_hash
 *  (the artifact's 32-byte hash as 64 hex characters), @p target_arch (at most
 *  16 bytes; NULL for "unknown"), and the lowest reputation a voter must hold
 *  of this node for the proposal to pass. The node signs it as itself.
 *  @return 0 sent; AT_APP_NOT_READY when the node has not bound @p q_out yet;
 *  -1 otherwise (a malformed field is refused here, before anything is sent). */
int at_app_fleet_propose(at_app_events_t *handle, const char *q_out, const char *version,
                         const char *artifact_hash, const char *target_arch,
                         double min_proposer_reputation);

#ifdef __cplusplus
}
#endif

#endif /* AT_FLEET_PUBLIC_H */
