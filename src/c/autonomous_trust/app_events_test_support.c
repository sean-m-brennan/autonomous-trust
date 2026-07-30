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
 * @file
 * @brief The daemon's side of the app-facing wire, in flat form. See the header
 *        for why this exists and why it sanitizes nothing.
 */

#include <string.h>

#include "app_events_test_support.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"

int at_app_test_emit_peer(const char *q_name,
                          const uint8_t peer_uuid[AT_APP_UUID_LEN],
                          const uint8_t signing_pubkey[AT_APP_SIGNING_KEY_LEN],
                          int32_t rank,
                          bool operator_bound,
                          double operator_attested_at,
                          const uint8_t operator_pubkey[AT_APP_SIGNING_KEY_LEN])
{
    if (q_name == NULL || q_name[0] == '\0' || peer_uuid == NULL
        || signing_pubkey == NULL)
        return -1;

    generic_msg_t msg = {0};
    msg.type = PEER_OBSERVED;
    msg.size = sizeof(peer_observed_msg_t);
    memcpy(msg.info.peer_observed.peer_uuid, peer_uuid, AT_APP_UUID_LEN);
    memcpy(msg.info.peer_observed.signing_pubkey, signing_pubkey,
           AT_APP_SIGNING_KEY_LEN);
    msg.info.peer_observed.rank = rank;
    msg.info.peer_observed.operator_bound = operator_bound;
    /* Verbatim, including a stamp on an unbound node: the real emitter zeroes
     * that, and a helper that copied the emitter could not be used to test a
     * consumer's own gating of it. */
    msg.info.peer_observed.operator_attested_at = operator_attested_at;
    /* Verbatim for the same reason, and NULL is how a caller says "no
     * guardian": the message was zeroed above, so absence needs no flag. A
     * key sent with operator_bound false is exactly the case a consumer's
     * gating has to be provable against, so this helper must be able to
     * produce it. */
    if (operator_pubkey != NULL)
        memcpy(msg.info.peer_observed.operator_pubkey, operator_pubkey,
               AT_APP_SIGNING_KEY_LEN);

    /* Non-blocking, like every app-bound send: a full queue is the caller's
     * problem to see, not something to hang on. */
    return messaging_send(q_name, PEER_OBSERVED, &msg, false) == 0 ? 0 : -1;
}

int at_app_test_emit_reputation(const char *q_name,
                               const uint8_t peer_uuid[AT_APP_UUID_LEN],
                               double score,
                               bool rated)
{
    if (q_name == NULL || q_name[0] == '\0' || peer_uuid == NULL)
        return -1;

    generic_msg_t msg = {0};
    msg.type = PEER_REPUTATION;
    msg.size = sizeof(peer_reputation_msg_t);
    memcpy(msg.info.peer_reputation.peer_uuid, peer_uuid, AT_APP_UUID_LEN);
    /* Also verbatim: a consumer must be testable for believing a score it was
     * explicitly told carries no information. */
    msg.info.peer_reputation.score = score;
    msg.info.peer_reputation.rated = rated;

    return messaging_send(q_name, PEER_REPUTATION, &msg, false) == 0 ? 0 : -1;
}
