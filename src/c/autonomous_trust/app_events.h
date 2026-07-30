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
 * app_events.h — the flat app-facing event ABI.
 *
 * A stable, minimal surface over the peer carrier, for consumers outside C
 * (the ethne adapter binds it via `extern "C"`). It exists so a foreign
 * consumer does not have to reproduce @ref generic_msg_t: that is a tagged
 * union whose size and member offsets depend on `public_identity_t`,
 * `group_t`, `net_msg_t` and the ZTA build flag, so a hand-written mirror of
 * it in another language would be a silent-corruption hazard the first time
 * any of those changed. Everything here is fixed-width and self-contained.
 *
 * Only the app-facing subset crosses. Internal traffic stays internal.
 *
 * Usage:
 *   at_app_events_t *ev = at_app_events_open("at_to_extern");
 *   at_app_events_request_roster(ev, "extern_to_at");   // optional; RETRY
 *   at_app_event_t batch[32];
 *   int n = at_app_events_poll(ev, batch, 32);          // non-blocking
 *   ...
 *   at_app_events_close(ev);
 *
 * See doc/architecture/app-peer-carrier.md.
 */

#ifndef AT_APP_EVENTS_H
#define AT_APP_EVENTS_H

/** @addtogroup public_api
 *  @{
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Length of an ed25519 signing public key. Spelled out rather than pulled
 *  from libsodium so this header stands alone for a foreign binding. */
#define AT_APP_SIGNING_KEY_LEN 32
/** Length of a UUID in bytes. */
#define AT_APP_UUID_LEN 16

/** Discriminates @ref at_app_event_t. Values are frozen: a consumer compiled
 *  against an older header must keep decoding what it already understood, so
 *  new kinds are only ever appended. */
typedef enum {
    AT_APP_EVENT_NONE = 0,
    /** A peer as this node observes it (@c peer). */
    AT_APP_EVENT_PEER_OBSERVED = 1,
    /** A peer's earned reputation (@c reputation). */
    AT_APP_EVENT_PEER_REPUTATION = 2
} at_app_event_kind_t;

/** One observed peer. Mirrors `peer_observed_msg_t` in flat, fixed-width form. */
typedef struct {
    uint8_t peer_uuid[AT_APP_UUID_LEN];
    uint8_t signing_pubkey[AT_APP_SIGNING_KEY_LEN];
    int32_t rank;
    /** This node has a human guardian, verified by OUR receiver against the
     *  distinct operator anchor — never the peer's own claim. */
    bool    operator_bound;
    /** Epoch seconds of the last verified operator session; 0 = nobody
     *  attending, or could not confirm. Zero whenever @c operator_bound is
     *  false. Grade this against your own clock: it is a stamp, not a state,
     *  and a bound node with nobody at the keyboard for a week is normal. */
    double  operator_attested_at;
} at_app_peer_t;

/** One peer's earned reputation. Mirrors `peer_reputation_msg_t`. */
typedef struct {
    uint8_t peer_uuid[AT_APP_UUID_LEN];
    /** AT's absolute [0.0, 1.0] score. Do not read unless @c rated. */
    double  score;
    /** False means AT holds no rating for this peer and @c score carries no
     *  information. An unrated peer would otherwise be indistinguishable
     *  from one genuinely rated at AT's neutral prior. */
    bool    rated;
} at_app_reputation_t;

/** A decoded app-facing event. */
typedef struct {
    at_app_event_kind_t kind;
    union {
        at_app_peer_t       peer;
        at_app_reputation_t reputation;
    } data;
} at_app_event_t;

/** Opaque handle; owns the bound queue. */
typedef struct at_app_events_s at_app_events_t;

/**
 * @brief Bind the AT -> app queue and start receiving.
 *
 * @param[in] q_in  Queue name the daemon sends to — the same string passed as
 *                  `q_in` in @ref at_node_config_t. Binding any other name
 *                  receives nothing.
 * @return Handle, or NULL on failure (the name is already bound, or the
 *         socket path is unavailable).
 */
at_app_events_t *at_app_events_open(const char *q_in);

/**
 * @brief Borrow the queue this process already bound, instead of binding one.
 *
 * For a host that called @ref at_node_start, which binds `q_in` itself: two
 * binders of one name would fight over the same socket path (the second
 * unlinks the first's). Use this in that case and @ref at_app_events_open
 * when nothing else has bound the queue — e.g. a consumer attaching to an
 * already-running daemon it does not own.
 *
 * @return Handle, or NULL on allocation failure. Closing it leaves the
 *         borrowed queue open.
 */
at_app_events_t *at_app_events_open_existing(void);

/**
 * @brief Drain whatever has arrived since the last call. Never blocks.
 *
 * @param[in]  handle  From @ref at_app_events_open.
 * @param[out] out     Caller's buffer, filled with up to @p max events.
 * @param[in]  max     Capacity of @p out.
 * @return Number of events written (0 if nothing arrived), or -1 on error.
 *         Messages that are not app-facing events are skipped, not returned.
 */
int at_app_events_poll(at_app_events_t *handle, at_app_event_t *out, size_t max);

/**
 * @brief Ask AT to re-emit its current peer view.
 *
 * The carrier is otherwise event-driven, so a consumer that attached after
 * the node admitted its peers sees nothing until something changes. Call this
 * after opening, and again whenever a fresh full view is wanted.
 *
 * @warning **Retry until it returns 0 — a single call at startup loses a
 * race.** Nothing waits for the daemon to be ready: `at_node_start` forks it
 * and returns, so until AT's identity and reputation processes have bound their
 * queues there is no recipient and the request is dropped. This function is
 * caller-driven by design, so the retry is the host's: call it on each pass of
 * whatever loop the host already runs until it succeeds. `src/c/example.c` and
 * `examples/demo/src/at_demo.c` both show the shape.
 *
 * @param[in] handle From @ref at_app_events_open.
 * @param[in] q_out  Queue name the daemon receives on — the same string
 *                   passed as `q_out` in @ref at_node_config_t.
 * @return 0 on success, -1 on failure.
 */
int at_app_events_request_roster(at_app_events_t *handle, const char *q_out);

/** @brief Close the queue and release the handle. NULL-safe. */
void at_app_events_close(at_app_events_t *handle);

#ifdef __cplusplus
}
#endif

/** @} */ /* end of public_api */

#endif /* AT_APP_EVENTS_H */
