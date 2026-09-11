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
/** Max geohash length carried across the app boundary. The app shares a
 *  ~5-char geohash (~5km "neighborhood" bucket); the buffer allows finer later
 *  without an ABI change. MUST match AT_GEOHASH_MAX_LEN in msg_types.h. */
#define AT_APP_GEOHASH_LEN 12
/** Max bytes of the compact profile JSON carried across the app boundary
 *  (Increment 3). MUST match AT_PROFILE_JSON_LEN in msg_types.h,
 *  AT_PROFILE_JSON_MAX in identity/profile.h, and AGORA_PROFILE_JSON_MAX in the
 *  shim / cohort ctypes. */
#define AT_APP_PROFILE_JSON_LEN 2560
/** Max bytes of a DM body carried across the app boundary (Increment 6). MUST
 *  match AT_DM_TEXT_LEN (msg_types.h), AT_DM_TEXT_MAX (identity/dm.h), and
 *  AGORA_DM_TEXT_MAX in the shim / cohort ctypes. */
#define AT_APP_DM_TEXT_LEN 1024

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
    /** A peer's shared coarse position (@c position), as an opt-in geohash
     *  bucket. Empty geohash = the peer shared none (the default). The consumer
     *  computes geographic distance from its own opted-in bucket. */
    AT_APP_EVENT_PEER_POSITION = 4,
    /** A peer's shared agora.profile (@c profile), as compact field JSON. The
     *  core already bound-validated and signature-verified it before emitting;
     *  an empty profile_json = the peer shared none (the default). */
    AT_APP_EVENT_PEER_PROFILE = 5,
    /** An inbound connection ASK from a peer (@c connection; Increment 5). The
     *  peer requested an explicit connection; @c connection.state is pending_in.
     *  The app surfaces an accept/decline affordance. */
    AT_APP_EVENT_CONNECTION_REQUEST = 6,
    /** This node's connection edge-state toward a peer changed (@c connection;
     *  Increment 5): none=0, pending_out=1, pending_in=2, connected=3,
     *  declined=4. A connection is EXPLICIT and separate from reputation; the
     *  app derives trust tier from reputation, not from this. */
    AT_APP_EVENT_CONNECTION_STATE = 7,
    /** A directed text message received from a peer (@c dm; Increment 6). A DM
     *  is a single directed, ENCRYPTED peer→peer message; crypto_box already
     *  authenticated the sender, so @c dm.peer_uuid is trustworthy. Delivered on
     *  arrival — a live stream, never replayed as roster state. */
    AT_APP_EVENT_DM = 8
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

/** One peer's latest round-trip time. Mirrors `peer_rtt_update_msg_t`. */
typedef struct {
    uint8_t peer_uuid[AT_APP_UUID_LEN];
    /** Latest RTT estimate in milliseconds. 0 means unknown / not yet
     *  measured (net_proc's fast-LAN default) — read it as "unknown", never as
     *  "0 ms". A network-latency proxy for proximity, not a geographic distance. */
    int32_t rtt_ms;
} at_app_rtt_t;

/** One peer's shared coarse position. Mirrors `peer_position_msg_t`. */
typedef struct {
    uint8_t peer_uuid[AT_APP_UUID_LEN];
    /** NUL-terminated geohash bucket the peer opted to share; empty string ""
     *  means the peer shared none (opted out) — the ordinary, default case.
     *  Opaque and untrusted; the consumer decodes it to compute distance from
     *  its own opted-in bucket. */
    char    geohash[AT_APP_GEOHASH_LEN + 1];
} at_app_position_t;

/** One peer's shared agora.profile. Mirrors `peer_profile_msg_t`. */
typedef struct {
    uint8_t peer_uuid[AT_APP_UUID_LEN];
    /** NUL-terminated compact JSON object of the peer's profile fields; empty
     *  string "" means the peer shared none (opted out). The core already
     *  bound-validated the fields and verified the peer's Ed25519 signature, so
     *  the consumer may trust this without re-checking; the signature does not
     *  cross. */
    char    profile_json[AT_APP_PROFILE_JSON_LEN + 1];
} at_app_profile_t;

/** One connection edge event toward a peer (Increment 5). Mirrors
 *  `peer_connection_msg_t`. Carried by both AT_APP_EVENT_CONNECTION_REQUEST
 *  (an inbound ask; @c state == 2 pending_in) and AT_APP_EVENT_CONNECTION_STATE
 *  (any edge transition). @c state: none=0, pending_out=1, pending_in=2,
 *  connected=3, declined=4. NO trust tier here — the app derives that from
 *  reputation; a connection is an explicit, separate axis. */
typedef struct {
    uint8_t peer_uuid[AT_APP_UUID_LEN];
    int32_t state;
} at_app_connection_t;

/** One directed text message received from a peer (Increment 6). @c peer_uuid is
 *  the SENDER (crypto_box authenticated it, so it is trustworthy); @c seq is the
 *  sender's freshness sequence; @c ts the sender's send time (epoch seconds);
 *  @c text the NUL-terminated body, bound-truncated to AT_APP_DM_TEXT_LEN bytes.
 *  Carried by AT_APP_EVENT_DM. A live stream — delivered on arrival, not roster
 *  state. */
typedef struct {
    uint8_t peer_uuid[AT_APP_UUID_LEN];
    int64_t seq;
    double  ts;
    char    text[AT_APP_DM_TEXT_LEN + 1];
} at_app_dm_t;

/** A decoded app-facing event. */
typedef struct {
    at_app_event_kind_t kind;
    union {
        at_app_peer_t       peer;
        at_app_reputation_t reputation;
        at_app_rtt_t        rtt;
        at_app_position_t   position;
        at_app_profile_t    profile;
        at_app_connection_t connection;
        at_app_dm_t         dm;
    } data;
} at_app_event_t;

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
 * @brief Set (or clear) THIS node's own opt-in coarse position.
 *
 * Sends the app→AT `AT_APP_SET_POSITION` verb on @p q_out (same queue as the
 * roster request). @p geohash is the operator's chosen bucket; NULL or "" opts
 * out (clears it). STRICTLY OPT-IN: until this is called with a non-empty
 * geohash, the node advertises and answers nothing geographic.
 *
 * @return 0 on success, @ref AT_APP_NOT_READY if @p q_out is not bound yet,
 *         -1 on any other failure.
 */
int at_app_events_set_position(at_app_events_t *handle, const char *q_out,
                               const char *geohash);

/**
 * @brief Set (or clear) THIS node's own opt-in agora.profile (Increment 3).
 *
 * Sends the app→AT `AT_APP_SET_PROFILE` verb on @p q_out. @p profile_json is a
 * JSON object of the profile fields ({display_name, handle, bio, avatar_ref,
 * links}); NULL or "" clears the profile (opts out). The identity process
 * truncates each field to its bound and shares the result, signed, only with
 * admitted peers that ask.
 *
 * @return 0 on success, @ref AT_APP_NOT_READY if @p q_out is not bound yet,
 *         -1 on any other failure (including malformed @p profile_json).
 */
int at_app_events_set_profile(at_app_events_t *handle, const char *q_out,
                              const char *profile_json);

/**
 * @brief Request an explicit connection to a peer (Increment 5).
 *
 * Sends the app→AT `AT_APP_CONNECT_REQUEST` verb on @p q_out. @p peer_uuid is
 * the 16-byte identity of the peer to connect to. The identity process sets our
 * edge to pending_out and sends a directed encrypted peer_connection_request;
 * an AT_APP_EVENT_CONNECTION_STATE(pending_out) is emitted back. A connection is
 * EXPLICIT and revocable, and SEPARATE from reputation.
 *
 * @return 0 on success, @ref AT_APP_NOT_READY if @p q_out is not bound yet,
 *         -1 on any other failure.
 */
int at_app_events_connect_request(at_app_events_t *handle, const char *q_out,
                                  const uint8_t peer_uuid[AT_APP_UUID_LEN]);

/**
 * @brief Respond to an inbound connection request (Increment 5).
 *
 * Sends the app→AT `AT_APP_CONNECT_RESPOND` verb on @p q_out. @p peer_uuid is
 * the requester's 16-byte identity; @p accept true connects, false declines. The
 * identity process sets our edge accordingly and sends a directed encrypted,
 * SIGNED peer_connection_response; an AT_APP_EVENT_CONNECTION_STATE is emitted
 * back.
 *
 * @return 0 on success, @ref AT_APP_NOT_READY if @p q_out is not bound yet,
 *         -1 on any other failure.
 */
int at_app_events_connect_respond(at_app_events_t *handle, const char *q_out,
                                  const uint8_t peer_uuid[AT_APP_UUID_LEN],
                                  bool accept);

/**
 * @brief Send a directed text message to a peer (Increment 6).
 *
 * Sends the app→AT `AT_APP_SEND_DM` verb on @p q_out. @p peer_uuid is the
 * recipient's 16-byte identity; @p text is the message body (truncated to
 * AT_APP_DM_TEXT_LEN bytes). The identity process sends a directed encrypted
 * peer_dm carrying {text, seq, ts} to that peer. The core does NOT echo the
 * outgoing message back — the app echoes it locally.
 *
 * @return 0 on success, @ref AT_APP_NOT_READY if @p q_out is not bound yet,
 *         -1 on any other failure.
 */
int at_app_events_send_dm(at_app_events_t *handle, const char *q_out,
                          const uint8_t peer_uuid[AT_APP_UUID_LEN],
                          const char *text);

/** @brief Close the queue and release the handle. NULL-safe. */
void at_app_events_close(at_app_events_t *handle);

#ifdef __cplusplus
}
#endif

/** @} */ /* end of public_api */

#endif /* AT_APP_EVENTS_H */
