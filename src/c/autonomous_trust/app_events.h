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
 * This header is the CORE's half and is the same in every build. A feature
 * adds its own kinds in its own header -- the Agora social feature's are in
 * at_agora.h -- carried in @ref at_app_event_t's fixed-size payload arm.
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

/** Returned instead of -1 when the daemon exists but has not bound its queue
 *  yet, so a caller can retry rather than treat a normal cold start as an error.
 *  Distinct from -1 because a forked daemon takes ~170-210 ms to become reachable and
 *  every send before that failed identically to a genuine fault. */
#define AT_APP_NOT_READY (-2)

/** Discriminates @ref at_app_event_t. Values are frozen: a consumer compiled
 *  against an older header must keep decoding what it already understood, so
 *  new kinds are only ever appended. */
typedef enum {
    AT_APP_EVENT_NONE = 0,
    /** A peer as this node observes it (@c peer). */
    AT_APP_EVENT_PEER_OBSERVED = 1,
    /** A peer's earned reputation (@c reputation). */
    AT_APP_EVENT_PEER_REPUTATION = 2,
    /** A peer's latest round-trip time (@c rtt). A network-latency proximity
     *  proxy, in milliseconds — NOT a geographic distance. */
    AT_APP_EVENT_PEER_RTT = 3,
    /* Kinds 4..15 are the Agora social feature's -- at_agora.h, with their
     * payloads and accessors. Reserved so nobody collides with them:
     *   0..99      core, and Agora's 4..15 grandfathered (Agora appends 16..99)
     *   100..199   future core kinds
     *   1000..     further features, one block each (doc/architecture/extensions.md)
     * Values are frozen across ALL of these: only ever append. */
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
    /** WHICH human, when the node opted in: the guardian's ed25519 public key,
     *  or all-zero for "not advertised". A non-zero key here means THIS node
     *  verified a binding signed by that operator's own credential and naming
     *  this peer — never a peer's unbacked claim.
     *
     *  **All-zero is the normal case and carries no judgement.** Naming a
     *  guardian is opt-in on the far side: one key per operator, stable across
     *  the nodes that human guards, which links them — a real cost AT does not
     *  impose. A consumer that requires a guardian (ethne's chartered
     *  node->guardian edge) is applying its own rule, and must treat absence as
     *  "unguarded machine", not as an error.
     *
     *  Zero whenever @c operator_bound is false, for the same reason the stamp
     *  is: a guardian identity on a node with no verified human is a
     *  contradiction. */
    uint8_t operator_pubkey[AT_APP_SIGNING_KEY_LEN];
    /** True iff this peer shares OUR group (its address is in our group's
     *  address_map). The app surfaces it as an "in your group" indicator,
     *  distinct from an explicit connection edge. Appended LAST. Always present
     *  (ABI v2), false when the core is built without the social feature. */
    bool    in_group;
    /** True iff this peer is LOCALLY BLOCKED on this node (Phase 4 P4.1).
     *
     *  Identity's own state, reported by identity. Compose it with
     *  @ref at_app_reputation_t::effective_tier exactly as the core does: a
     *  blocked peer's effective tier is 0 whatever they have earned.
     *
     *  Before P4.1 a block emitted nothing at all, so the app could not see
     *  one — it re-derives tier from the score, and a block leaves the score
     *  untouched. Appended LAST; always present, false without the social feature. */
    bool    blocked;
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
    /** The trust tier this score yields AFTER any standing ceiling, 0..4
     *  (Phase 4 P4.1).
     *
     *  This header has said since Increment 3 that the app derives tier from
     *  reputation, and it still may — but only reputation knows about a
     *  CEILING, and a ceiling is not a function of the score. A peer bounded
     *  by an authority reads as an ordinary score with a tier the app cannot
     *  compute, so the tier reputation actually used crosses here. */
    int32_t effective_tier;
    /** The ceiling in force on this peer, or a NEGATIVE sentinel for none.
     *
     *  Lets the app tell "low because they have earned little" from "bounded
     *  by a community decision" — different things to show a person.
     *
     *  @warning A consumer that memsets its event and forgets to write this
     *  reports 0.0, which reads as "floored at zero". It must be written
     *  explicitly on every path. */
    double  standing_ceiling;
} at_app_reputation_t;

/** One peer's latest round-trip time. Mirrors `peer_rtt_update_msg_t`. */
typedef struct {
    uint8_t peer_uuid[AT_APP_UUID_LEN];
    /** Latest RTT estimate in milliseconds. 0 means unknown / not yet
     *  measured (net_proc's fast-LAN default) — read it as "unknown", never as
     *  "0 ms". A network-latency proxy for proximity, not a geographic distance. */
    int32_t rtt_ms;
} at_app_rtt_t;


/** Bytes of @ref at_app_event_t's opaque payload arm. A feature's event (e.g.
 *  the Agora kinds in at_agora.h) is carried there and read through that
 *  feature's accessors. Fixed so that the event is ONE size in every build
 *  and a foreign mirror never depends on which features the core was built
 *  with. Changing it is an app-ABI change: bump @ref AT_APP_ABI_VERSION. */
#define AT_APP_EVENT_PAYLOAD_MAX 8192

/** The app ABI's version, bumped on any change to a struct or constant a
 *  foreign mirror hard-codes. 1 was the unversioned layout whose size swung
 *  with AT_SOCIAL (104 B vs several KB); 2 is the fixed-size event, with
 *  @ref at_app_peer_t's social fields always present. Check it against
 *  @ref at_app_abi_version at load. */
#define AT_APP_ABI_VERSION 2

#ifdef __cplusplus
#define AT_APP_ALIGN8 alignas(8)
#define AT_APP_STATIC_ASSERT static_assert
#else
#define AT_APP_ALIGN8 _Alignas(8)
#define AT_APP_STATIC_ASSERT _Static_assert
#endif

/** A decoded app-facing event.
 *
 *  @c kind is an @ref at_app_event_kind_t for the core's kinds and a
 *  feature's own constant otherwise (at_agora.h), so it is a plain
 *  fixed-width integer rather than the enum type. */
typedef struct {
    int32_t kind;
    union {
        at_app_peer_t       peer;
        at_app_reputation_t reputation;
        at_app_rtt_t        rtt;
        /** A feature's event; read it through that feature's accessors. */
        AT_APP_ALIGN8 uint8_t payload[AT_APP_EVENT_PAYLOAD_MAX];
    } data;
} at_app_event_t;

/* Pinned so a mirror in another language can assert the same numbers. */
AT_APP_STATIC_ASSERT(sizeof(at_app_event_t) == 8 + AT_APP_EVENT_PAYLOAD_MAX,
                     "at_app_event_t is 8 + AT_APP_EVENT_PAYLOAD_MAX bytes");
AT_APP_STATIC_ASSERT(offsetof(at_app_event_t, data) == 8,
                     "at_app_event_t.data is at offset 8");

/** @brief The @ref AT_APP_ABI_VERSION this library was built with. A consumer
 *  built against a different header must refuse to read events. */
uint32_t at_app_abi_version(void);

/** Opaque handle; owns the bound queue. */
typedef struct at_app_events_s at_app_events_t;

/**
 * @brief Bind the AT -> app queue and start receiving.
 *
 * @param[in] q_in  Queue name the daemon sends to — the same string passed as
 *                  `q_in` in @ref at_node_config_t. Binding any other name
 *                  receives nothing. At most 63 bytes, the length the messaging
 *                  layer keeps; a longer name is refused rather than shortened,
 *                  since a shortened name is another name.
 * @return Handle, or NULL on failure (the name is empty or too long, already
 *         bound, or the socket path is unavailable).
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
 * @warning **Then keep asking — a successful send is not a useful answer.** A
 * pull reports what AT knows *now*, and a node that has not finished discovery
 * knows nothing: measured on a cold 3-node cohort, the first successful pull
 * returned 0 peers 23 seconds before the first admission. A consumer that pulls
 * once at startup will conclude AT has no peers, and will never observe an
 * unrated peer, since `rated == false` crosses on the pull alone. Re-pull
 * periodically, or whenever a fresh full view is wanted. Repeats are cheap and
 * safe: the feed is upsert-only, so a restated observation costs one message.
 * (A pull can also return nothing because the reputation process has not
 * finished initializing, which is the same lesson.)
 *
 * @param[in] handle From @ref at_app_events_open.
 * @param[in] q_out  Queue name the daemon receives on — the same string
 *                   passed as `q_out` in @ref at_node_config_t. Same 63-byte
 *                   limit, refused the same way.
 * @return 0 on success, @ref AT_APP_NOT_READY if nothing is bound at @p q_out
 *         yet, -1 on any other failure.
 *
 * @note The not-ready case used to be indistinguishable from a real failure, so a
 *       caller could only guess which it was — and a cold daemon takes ~170-210 ms to
 *       bind, so it is the common one. See @ref at_app_node_ready.
 */
int at_app_events_request_roster(at_app_events_t *handle, const char *q_out);


/**
 * @brief Hand the core an AUTHORITY FINDING about a peer's standing (P4.1).
 *
 * Sends @ref AT_APP_PEER_STANDING with {"peer", "standing", "ceiling",
 * "source", "reason"}; identity validates it and republishes it to reputation
 * as a @ref PEER_STANDING, which BOUNDS what that peer may hold.
 *
 * A ceiling, never a score. The caller has decided something AT's [0, 1] scale
 * cannot express — a community expelled this member — and a scalar penalty has
 * no representation on that scale; the predecessor of this mechanism tried one
 * and it was discarded at the boundary. @ref AT_ETHNE_EXPEL_CEILING is the
 * bound an expulsion carries.
 *
 * @p standing is "proved", "capped" or "failed". "proved" means REINSTATED and
 * lifts only THIS source's ceiling — one authority never clears another's.
 * @p ceiling is in [0, 1], or negative for "no bound". @p source names the
 * authority and may not be @ref PEER_STANDING_SOURCE_ZTA: an app cannot know
 * what a credential authority proved, so claiming to speak as one is refused.
 *
 * The core verifies NOTHING about the finding itself — an Ethne expulsion is
 * proved by co-signatures inside a record it cannot parse. What it trusts is
 * that this arrived on the local app queue.
 *
 * @return 0 on success, @ref AT_APP_NOT_READY if @p q_out is not bound, -1 on
 *         a bad argument (including an off-scale ceiling or a ZTA source).
 */
int at_app_events_peer_standing(at_app_events_t *handle, const char *q_out,
                                const uint8_t peer_uuid[AT_APP_UUID_LEN],
                                const char *standing, double ceiling,
                                const char *source, const char *reason);

/** @brief Close the queue and release the handle. NULL-safe. */
void at_app_events_close(at_app_events_t *handle);

#ifdef __cplusplus
}
#endif

/** @} */ /* end of public_api */

#endif /* AT_APP_EVENTS_H */
