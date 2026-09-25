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

/* The flat app-event ABI's layout (ABI v2, FEATURE_SPLIT_PLAN §3.2).
 *
 * Built in EVERY config, because that is the claim: at_app_event_t used to
 * be 104 B in a core build and several KB in a social one, so a foreign
 * mirror (the ethne en-at crate, the Agora shim) was right for exactly one
 * build. The numbers asserted here are the ones those mirrors hard-code. */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stddef.h>
#include <string.h>

#include "autonomous_trust/app_events.h"
#include "autonomous_trust/app_events_registry.h"

DEFINE_TEST(test_app_event_layout_is_build_independent)
{
    ck_assert_int_eq((int)at_app_abi_version(), AT_APP_ABI_VERSION);
    ck_assert_int_eq((int)AT_APP_ABI_VERSION, 2);
    ck_assert_int_eq((int)sizeof(at_app_event_t), 8 + AT_APP_EVENT_PAYLOAD_MAX);
    ck_assert_int_eq((int)offsetof(at_app_event_t, data), 8);
    /* The formerly social-only peer fields are always there. */
    at_app_event_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.data.peer.in_group = true;
    ev.data.peer.blocked = true;
    ck_assert(ev.data.peer.in_group && ev.data.peer.blocked);
    /* No decoder for a core type or an unregistered one. */
    ck_assert(at_app_event_decoder_lookup(PEER_OBSERVED) == NULL);
    ck_assert(at_app_event_decoder_lookup(AT_MSG_TYPE_FLEET_MAX) == NULL);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_core_arm_offsets_are_pinned)
{
    /* The offsets the en-at Rust mirror asserts (source.rs). */
    ck_assert_int_eq((int)offsetof(at_app_peer_t, rank), 48);
    ck_assert_int_eq((int)offsetof(at_app_peer_t, operator_attested_at), 56);
    ck_assert_int_eq((int)offsetof(at_app_peer_t, operator_pubkey), 64);
    ck_assert_int_eq((int)offsetof(at_app_peer_t, in_group), 96);
    ck_assert_int_eq((int)offsetof(at_app_peer_t, blocked), 97);
    ck_assert_int_eq((int)sizeof(at_app_peer_t), 104);
    ck_assert_int_eq((int)offsetof(at_app_reputation_t, score), 16);
    ck_assert_int_eq((int)offsetof(at_app_reputation_t, rated), 24);
    ck_assert_int_eq((int)offsetof(at_app_reputation_t, effective_tier), 28);
    ck_assert_int_eq((int)offsetof(at_app_reputation_t, standing_ceiling), 32);
    ck_assert_int_eq((int)sizeof(at_app_reputation_t), 40);
    ck_assert_int_eq((int)sizeof(at_app_rtt_t), 20);
}
END_TEST_DEFINITION()

RUN_TESTS(App_Abi, test_app_event_layout_is_build_independent,
          test_core_arm_offsets_are_pinned)
