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
 * @brief Inject synthetic app-facing events, for testing a consumer of
 *        @ref app_events.h across a language boundary.
 *
 * # Why this exists
 *
 * A foreign consumer (the `ethne` Rust adapter, via its `at-ffi` feature) can
 * *receive* app-facing events through the flat ABI without knowing anything
 * about AT's internals. It cannot *send* one: emitting a `PEER_OBSERVED` means
 * constructing a @c generic_msg_t, and that is a tagged union whose layout
 * depends on `public_identity_t`, `group_t`, `net_msg_t` and the ZTA build flag
 * — precisely what @ref app_events.h exists so nobody mirrors. Without a flat
 * emitter, such a consumer can verify that it binds a queue and that its struct
 * layouts agree, but never that a decoded event survives the trip. That was a
 * real hole: the ethne decoder was complete and tested with **no event having
 * crossed the boundary** (2026-07-30).
 *
 * These are the daemon's side of the wire, in flat form, so a consumer's test
 * can play daemon.
 *
 * # This forges events, deliberately
 *
 * Anything able to call this could already write to the queue's unix socket
 * directly, so it grants no capability that a local process lacked — but it is
 * still a forgery tool and is named accordingly. It belongs in tests and
 * integration harnesses. Nothing in AT calls it. The same reasoning as
 * @ref messaging_set_test_hook, which is likewise a test seam living in a normal
 * header.
 *
 * # Values pass through unsanitized
 *
 * In particular an attendance stamp is **not** zeroed when @c operator_bound is
 * false, though the real emitter does zero it
 * (`identity_emit_peer_observed`). A helper that sanitized could not be used to
 * test a consumer's own gating of that field, which is one of the things a
 * consumer most needs to test.
 *
 * @see doc/architecture/app-peer-carrier.md
 */

#ifndef AT_APP_EVENTS_TEST_SUPPORT_H
#define AT_APP_EVENTS_TEST_SUPPORT_H

#include <stdbool.h>
#include <stdint.h>

#include "autonomous_trust/app_events.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Send a synthetic @c PEER_OBSERVED to a queue, as the daemon would.
 *
 * @warning **The calling process must already have an assigned queue**, which
 * @ref at_app_events_open provides (it calls `messaging_assign`). Sends go out
 * through it. Called with no queue assigned this returns -1 rather than
 * pretending to send. A consumer that opened queue `"q"` may emit *to* `"q"`,
 * looping a synthetic event back to itself over the real socket — which is the
 * cheapest end-to-end test of a decoder.
 *
 * @param[in] q_name        Target queue: the name the consumer bound.
 * @param[in] peer_uuid     @ref AT_APP_UUID_LEN bytes.
 * @param[in] signing_pubkey @ref AT_APP_SIGNING_KEY_LEN bytes.
 * @param[in] rank          AT topology rank.
 * @param[in] operator_bound Whether a human guardian was verified.
 * @param[in] operator_attested_at Epoch seconds; passed through verbatim,
 *                          including when @p operator_bound is false.
 * @param[in] operator_pubkey The guardian's ed25519 public key, @ref
 *                          AT_APP_SIGNING_KEY_LEN bytes, or NULL for the
 *                          ordinary "no guardian advertised" case. Also
 *                          verbatim — pass a key with @p operator_bound false
 *                          to test that a consumer refuses it.
 * @return 0 on success, -1 on failure (no assigned queue, bad argument, or the
 *         target queue is not bound).
 */
int at_app_test_emit_peer(const char *q_name,
                          const uint8_t peer_uuid[AT_APP_UUID_LEN],
                          const uint8_t signing_pubkey[AT_APP_SIGNING_KEY_LEN],
                          int32_t rank,
                          bool operator_bound,
                          double operator_attested_at,
                          const uint8_t operator_pubkey[AT_APP_SIGNING_KEY_LEN]);

/**
 * @brief Send a synthetic @c PEER_REPUTATION to a queue, as the daemon would.
 *
 * Same queue precondition as @ref at_app_test_emit_peer. @p score passes through
 * even when @p rated is false, so a consumer can be tested for believing a score
 * it was told carries no information.
 *
 * @param[in] q_name    Target queue.
 * @param[in] peer_uuid @ref AT_APP_UUID_LEN bytes. The join key: a consumer pairs
 *                      this with the uuid of a @c PEER_OBSERVED.
 * @param[in] score     AT's absolute [0.0, 1.0] score.
 * @param[in] rated     False means AT holds no rating and @p score is noise.
 * @return 0 on success, -1 on failure.
 */
int at_app_test_emit_reputation(const char *q_name,
                                const uint8_t peer_uuid[AT_APP_UUID_LEN],
                                double score,
                                bool rated);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* AT_APP_EVENTS_TEST_SUPPORT_H */
