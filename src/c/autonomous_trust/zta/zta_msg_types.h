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

#ifndef ZTA_MSG_TYPES_H
#define ZTA_MSG_TYPES_H

/** @addtogroup internal_utilities
 *  @{
 */

/**
 * @file zta_msg_types.h
 * @brief The ZTA feature's IPC message types and payload.
 *
 * Registered with the core at load (utilities/msg_registry.h), the pattern
 * every feature's types follow. Payload rides
 * `generic_msg_t.info.payload`, read with AT_MSG_EXT(msg, zta_event_msg_t).
 */

#include "utilities/msg_types.h"

/* ZTA message ids (reserved range AT_MSG_TYPE_ZTA_MIN..MAX); typed constants. */
/** Peer credential revocation notice. */
#define ZTA_REVOCATION_ALERT    ((message_type_t)(AT_MSG_TYPE_ZTA_MIN + 0))
/** Outcome of a deferred ZTA verification. */
#define ZTA_VERIFICATION_RESULT ((message_type_t)(AT_MSG_TYPE_ZTA_MIN + 1))

typedef struct {
    uuid_t peer_uuid;
    uuid_t voucher_uuid;            /* Identity of the peer that performed verification */
    uint8_t credential_hash[32];
    int status;                     /* zta_status_t cast to int */
    char reason[64];
} zta_event_msg_t;

/** @brief Pull the ZTA type registrations into a static link; see
 *  @ref AT_MSG_TYPE_REGISTER. */
void at_zta_msg_types_link(void);

/** @} */ /* end of internal_utilities */

#endif  // ZTA_MSG_TYPES_H
