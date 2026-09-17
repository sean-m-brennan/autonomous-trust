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
#ifdef AT_SOCIAL_ENABLED
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
/** Max bytes of a feed-post body carried across the app boundary (Increment 7).
 *  MUST match AT_POST_BODY_LEN (msg_types.h), AT_POST_BODY_MAX (identity/post.h),
 *  and AGORA_POST_BODY_MAX in the shim / cohort ctypes. */
#define AT_APP_POST_BODY_LEN 4096
/** Length of a post content id (blake2b-256 lowercase hex). MUST match
 *  AT_POST_ID_LEN (msg_types.h), AT_POST_ID_HEX_LEN (identity/post.h), and
 *  AGORA_POST_ID_MAX in the shim / cohort ctypes. */
#define AT_APP_POST_ID_LEN 64

/** Max bytes of the opaque Ethne page bundle carried on a business ad (Phase 3
 *  P3.2). MUST match AT_BUSINESS_BUNDLE_MAX in identity/business_ad.h,
 *  AT_BUSINESS_BUNDLE_LEN in msg_types.h, and AGORA_BUSINESS_BUNDLE_MAX in the
 *  shim / cohort ctypes. */
#define AT_APP_BUSINESS_BUNDLE_LEN 3072

/** Max bytes of a polity DID. MUST match AT_BUSINESS_DID_MAX / AT_BUSINESS_DID_LEN
 *  and AGORA_BUSINESS_DID_MAX. */
#define AT_APP_BUSINESS_DID_LEN 95

/** Ad content id: blake2b-256 as lowercase hex. MUST match
 *  AT_BUSINESS_AD_ID_HEX_LEN / AT_BUSINESS_AD_ID_LEN and AGORA_BUSINESS_AD_ID_MAX. */
#define AT_APP_BUSINESS_AD_ID_LEN 64

/** A business advertising its OWN page, rather than a customer rating it. MUST
 *  match AT_BUSINESS_SAT_SELF in identity/business_ad.h. */
#define AT_APP_BUSINESS_SAT_SELF 0xFF

/** Max hex characters of a detached exchange's exported canonical bytes (Phase 3
 *  P3.3), so half this many bytes of CBOR. MUST match AT_COSIGN_BYTES_MAX in
 *  identity/cosign.h, AT_COSIGN_BYTES_LEN in msg_types.h, COSIGN_BYTES_HEX_MAX
 *  in the agora ethne_ffi crate, and AGORA_COSIGN_BYTES_MAX in the shim / cohort
 *  ctypes.
 *
 *  MEASURED against real exchanges: a membership admission is 666 hex, a
 *  guardian designation carrying an observation 2142 for a small polity and 4192
 *  for a majority of thirty staff with a long rationale. The evidence is what
 *  grows it — roughly 372 hex per extra reading — so an exchange cites an
 *  observation scoped to the member concerned, and the authoring side refuses an
 *  oversized one outright rather than letting it truncate. */
#define AT_APP_COSIGN_BYTES_LEN 6144
/** Max bytes of a polity DID or a signer's did:key. MUST match AT_COSIGN_DID_MAX
 *  (identity/cosign.h), AT_COSIGN_DID_LEN (msg_types.h) and AGORA_COSIGN_DID_MAX. */
#define AT_APP_COSIGN_DID_LEN 95
/** Exchange content id, "b3:" + 64 lowercase hex. MUST match AT_COSIGN_CID_MAX
 *  (identity/cosign.h), AT_COSIGN_CID_LEN (msg_types.h) and AGORA_COSIGN_CID_MAX. */
#define AT_APP_COSIGN_CID_LEN 67
/** An Ed25519 signature as lowercase hex. MUST match AT_COSIGN_SIG_MAX
 *  (identity/cosign.h), AT_COSIGN_SIG_LEN (msg_types.h) and AGORA_COSIGN_SIG_MAX. */
#define AT_APP_COSIGN_SIG_LEN 128
/** A record-class or op token. MUST match AT_COSIGN_TOKEN_MAX
 *  (identity/cosign.h), AT_COSIGN_TOKEN_LEN (msg_types.h) and AGORA_COSIGN_TOKEN_MAX. */
#define AT_APP_COSIGN_TOKEN_LEN 15
#endif /* AT_SOCIAL_ENABLED */

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
#ifdef AT_SOCIAL_ENABLED
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
    AT_APP_EVENT_DM = 8,
    /** A signed feed post received over the group channel (@c post; Increment 7).
     *  The core verified the author's Ed25519 signature, tier-gated it against
     *  this node's view of the author's tier, and content-id-deduped it before
     *  emitting; @c post.author_uuid is the signature-bound author. Distributed
     *  by encrypted group multicast and gossip-forwarded a bounded number of
     *  hops — a live stream, never replayed as roster state. */
    AT_APP_EVENT_POST = 9,
    /** A peer reacted to one of THIS node's posts (@c reaction; Increment 8). A
     *  reaction is a single directed, ENCRYPTED reactor→author message; crypto_box
     *  authenticated the reactor, so @c reaction.peer_uuid is trustworthy. It is
     *  the return signal a fire-and-forget post lacks, and it accrues reputation
     *  for both peers. Delivered on arrival — a live stream. */
    AT_APP_EVENT_REACTION = 10,

    /** The coarse distance BAND to a CONNECTED peer (@c proximity; Phase 2),
     *  learned by a private-proximity probe. Carries only the band (near / mid /
     *  far), never coordinates — the exact position never crosses this boundary.
     *  Emitted for both sides of a probe once tags are exchanged. */
    AT_APP_EVENT_PROXIMITY = 11,

    /** A signed business ad — one opaque, self-verifying Ethne page bundle plus
     *  the advertiser's declared satisfaction (Phase 3 P3.2, @ref
     *  at_app_business_ad_t). The advertiser is either the business itself or
     *  one of its CUSTOMERS re-advertising from cache in the first person;
     *  nobody else carries a page, so what reaches you came through people who
     *  actually patronize the place. */
    AT_APP_EVENT_BUSINESS_AD = 12,

    /** A peer asks THIS node to co-sign one staff-roll or guardianship record
     *  (Phase 3 P3.3, @ref at_app_cosign_request_t). The keys never travel; the
     *  record does. What it commits to, in words, is NOT carried — derive it on
     *  this node from @c bytes, which is what will actually be signed. */
    AT_APP_EVENT_COSIGN_REQUEST = 13,

    /** A signer returns their detached signature over an exchange THIS node is
     *  authoring (Phase 3 P3.3, @ref at_app_cosign_sig_t). Check it against the
     *  payload before appending — the core neither did nor could. */
    AT_APP_EVENT_COSIGN_SIGNATURE = 14
#endif /* AT_SOCIAL_ENABLED */
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
#ifdef AT_SOCIAL_ENABLED
    /** True iff this peer shares OUR group (its address is in our group's
     *  address_map). The app surfaces it as an "in your group" indicator,
     *  distinct from an explicit connection edge. Appended LAST; social builds
     *  only, so a non-social consumer's field offsets are unchanged. */
    bool    in_group;
#endif /* AT_SOCIAL_ENABLED */
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

#ifdef AT_SOCIAL_ENABLED
/** One peer's shared coarse position. Mirrors `peer_position_msg_t`. */
typedef struct {
    uint8_t peer_uuid[AT_APP_UUID_LEN];
    /** NUL-terminated geohash bucket the peer opted to share; empty string ""
     *  means the peer shared none (opted out) — the ordinary, default case.
     *  Opaque and untrusted; the consumer decodes it to compute distance from
     *  its own opted-in bucket. */
    char    geohash[AT_APP_GEOHASH_LEN + 1];
} at_app_position_t;

/** The coarse distance BAND to a CONNECTED peer (Phase 2). Mirrors
 *  `peer_proximity_msg_t`. No coordinates — only the band. */
typedef struct {
    uint8_t peer_uuid[AT_APP_UUID_LEN];
    /** 0 = unknown (a side had no exact position), 1 = near (~1 km), 2 = mid
     *  (~5 km), 3 = far. Matches at_prox_band_t. */
    int32_t band;
} at_app_proximity_t;

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

/** One signed feed post received over the group channel (Increment 7).
 *  @c author_uuid is the SIGNATURE-BOUND author (the core verified the Ed25519
 *  signature over the canonical form, so it is trustworthy even though the post
 *  was gossip-relayed by other peers); @c post_id is the blake2b content-address
 *  (the dedup/merge key); @c seq the author's post sequence; @c ts the author's
 *  post time (epoch seconds); @c required_tier the audience floor (0..4);
 *  @c body the NUL-terminated body, bound-truncated to AT_APP_POST_BODY_LEN
 *  bytes. Carried by AT_APP_EVENT_POST. A live stream — delivered on arrival,
 *  not roster state. */
typedef struct {
    uint8_t author_uuid[AT_APP_UUID_LEN];
    char    post_id[AT_APP_POST_ID_LEN + 1];
    int64_t seq;
    double  ts;
    int32_t required_tier;
    char    body[AT_APP_POST_BODY_LEN + 1];
} at_app_post_t;

/** One reaction to one of THIS node's posts (Increment 8). @c peer_uuid is the
 *  REACTOR (crypto_box-authenticated, so trustworthy); @c post_id is the
 *  content-id of the post reacted to; @c seq the reactor's freshness sequence;
 *  @c ts the reactor's send time (epoch seconds). Carried by AT_APP_EVENT_REACTION.
 *  A live stream — delivered on arrival, not roster state. */
typedef struct {
    uint8_t peer_uuid[AT_APP_UUID_LEN];
    char    post_id[AT_APP_POST_ID_LEN + 1];
    int64_t seq;
    double  ts;
} at_app_reaction_t;

/** One signed business ad (Phase 3 P3.2). @c advertiser_uuid is the
 *  SIGNATURE-BOUND advertiser — the business's own node, or a CUSTOMER speaking
 *  for it in the first person (an ad is never relayed, only re-advertised, so
 *  this is always someone vouching with their own key). @c polity is the
 *  business's Ethne DID; @c ad_id the blake2b content-address (the dedup key);
 *  @c satisfaction the advertiser's 0..4 rating, or @ref AT_APP_BUSINESS_SAT_SELF
 *  when the business is advertising itself; @c seq the page version; @c ts the
 *  advertiser's send time (epoch seconds).
 *
 *  @c bundle is the OPAQUE Ethne page artifact. The core did NOT verify it — it
 *  cannot, it holds no Ethne — so the APP must, via the self-contained bundle
 *  verifier (polity root -> envoy -> page) before showing or trusting the page.
 *  What the core DID verify is the ad's Ed25519 signature: that this advertiser
 *  really vouched for these exact page bytes at this satisfaction.
 *
 *  Carried by AT_APP_EVENT_BUSINESS_AD. A live stream — delivered on arrival,
 *  not roster state. */
typedef struct {
    uint8_t advertiser_uuid[AT_APP_UUID_LEN];
    char    polity[AT_APP_BUSINESS_DID_LEN + 1];
    char    ad_id[AT_APP_BUSINESS_AD_ID_LEN + 1];
    int32_t satisfaction;
    int64_t seq;
    double  ts;
    char    bundle[AT_APP_BUSINESS_BUNDLE_LEN + 1];
} at_app_business_ad_t;

/** One peer's ask that this node co-sign a record (Phase 3 P3.3).
 *
 *  A staff roll act — admitting, expelling, designating a machine, moving or
 *  releasing its guardian — is decided by several people who are not at the same
 *  keyboard. Their PRIVATE KEYS DO NOT TRAVEL: the record's canonical bytes do,
 *  each signer signs them where their key already lives, and the authoring node
 *  reassembles the signatures.
 *
 *  @c requester_uuid is crypto_box-authenticated, so an ask cannot be put in
 *  somebody else's mouth. @c record is "membership" or "guardian", @c op the act
 *  within it, @c polity the Ethne DID, @c cid the exchange's content address,
 *  and @c bytes the exported canonical CBOR as lowercase hex.
 *
 *  @c bytes is OPAQUE and NOT verified by the core — it holds no Ethne, exactly
 *  as it holds no verifier for a page bundle. What the core did check is the
 *  shape: a known op, and an even-length lowercase-hex payload within bounds.
 *
 *  **No description is carried, deliberately.** Derive what these bytes commit
 *  to on THIS node (`ethne_describe`) and show the operator that. If the asking
 *  node supplied the wording too, it would choose both what you sign and what
 *  you are told you are signing — a friendly sentence over hostile bytes, with a
 *  real signature on the end. Recompute @c cid from @c bytes while you are
 *  there; it is carried for reference, never as proof.
 *
 *  Carried by AT_APP_EVENT_COSIGN_REQUEST. A live stream — delivered on
 *  arrival, not roster state. */
typedef struct {
    uint8_t requester_uuid[AT_APP_UUID_LEN];
    char    record[AT_APP_COSIGN_TOKEN_LEN + 1];
    char    op[AT_APP_COSIGN_TOKEN_LEN + 1];
    char    polity[AT_APP_COSIGN_DID_LEN + 1];
    char    cid[AT_APP_COSIGN_CID_LEN + 1];
    int64_t seq;
    double  ts;
    char    bytes[AT_APP_COSIGN_BYTES_LEN + 1];
} at_app_cosign_request_t;

/** One signer's detached signature, returned to the authoring node (Phase 3
 *  P3.3). @c signer_uuid is crypto_box-authenticated; @c cid names the exchange;
 *  @c signer_did is the signing did:key, which EMBEDS its public key, so no
 *  registry is needed to check the signature; @c sig is the detached Ed25519
 *  signature over the exported bytes, as lowercase hex.
 *
 *  The core did not verify @c sig and could not — it does not hold the payload.
 *  Verification belongs to the assembling node, which refuses a wrong key or a
 *  tampered payload before anything is appended.
 *
 *  Carried by AT_APP_EVENT_COSIGN_SIGNATURE. A live stream. */
typedef struct {
    uint8_t signer_uuid[AT_APP_UUID_LEN];
    char    cid[AT_APP_COSIGN_CID_LEN + 1];
    char    signer_did[AT_APP_COSIGN_DID_LEN + 1];
    char    sig[AT_APP_COSIGN_SIG_LEN + 1];
    int64_t seq;
    double  ts;
} at_app_cosign_sig_t;
#endif /* AT_SOCIAL_ENABLED */

/** A decoded app-facing event. */
typedef struct {
    at_app_event_kind_t kind;
    union {
        at_app_peer_t       peer;
        at_app_reputation_t reputation;
        at_app_rtt_t        rtt;
#ifdef AT_SOCIAL_ENABLED
        at_app_position_t   position;
        at_app_profile_t    profile;
        at_app_connection_t connection;
        at_app_dm_t         dm;
        at_app_post_t       post;
        at_app_reaction_t   reaction;
        at_app_proximity_t  proximity;
        at_app_business_ad_t business_ad;
        at_app_cosign_request_t cosign_request;
        at_app_cosign_sig_t cosign_sig;
#endif /* AT_SOCIAL_ENABLED */
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

#ifdef AT_SOCIAL_ENABLED
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
 * @brief Pull a fresh operator-attendance attestation from a peer NOW (Phase 2,
 *        presence).
 *
 * Sends the app→AT `AT_APP_REQUEST_ATTEND` verb on @p q_out. @p peer_uuid is the
 * peer to probe. The identity process issues a nonce-fresh operator_attest_query
 * to that peer and, on the response, updates the peer's operator_attested_at and
 * re-emits an AT_APP_EVENT_PEER_OBSERVED so the app's presence indicator
 * refreshes. Fire-and-forget: no direct return event, the refresh rides the
 * next peer-observed.
 *
 * @return 0 on success, @ref AT_APP_NOT_READY if @p q_out is not bound yet,
 *         -1 on any other failure.
 */
int at_app_events_request_attend(at_app_events_t *handle, const char *q_out,
                                 const uint8_t peer_uuid[AT_APP_UUID_LEN]);

/**
 * @brief Set or clear THIS node's opt-in EXACT position (Phase 2, private
 *        proximity).
 *
 * Sends the app→AT `AT_APP_SET_EXACT_POSITION` verb on @p q_out. When @p opt_in
 * is true the (@p lat, @p lon) degrees are stored; when false the exact position
 * is cleared (opt out). The identity process keeps it LOCAL-ONLY and never
 * advertises it — it feeds only the pairwise proximity probe.
 *
 * @return 0 on success, @ref AT_APP_NOT_READY if @p q_out is not bound yet,
 *         -1 on any other failure.
 */
int at_app_events_set_exact_position(at_app_events_t *handle, const char *q_out,
                                     bool opt_in, double lat, double lon);

/**
 * @brief Run a private-proximity probe against a CONNECTED peer (Phase 2).
 *
 * Sends the app→AT `AT_APP_REQUEST_PROXIMITY` verb on @p q_out. @p peer_uuid is
 * the connected peer. The identity process exchanges pairwise-keyed grid tags so
 * both sides learn only a coarse distance BAND (an AT_APP_EVENT_PROXIMITY),
 * never coordinates. Fire-and-forget: the band rides a later proximity event.
 *
 * @return 0 on success, @ref AT_APP_NOT_READY if @p q_out is not bound yet,
 *         -1 on any other failure.
 */
int at_app_events_request_proximity(at_app_events_t *handle, const char *q_out,
                                    const uint8_t peer_uuid[AT_APP_UUID_LEN]);

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

/**
 * @brief Publish a feed post to the local group (Increment 7).
 *
 * Sends the app→AT `AT_APP_PUBLISH_POST` verb on @p q_out. @p body is the post
 * body (truncated to AT_APP_POST_BODY_LEN bytes); @p required_tier is the
 * audience floor (0..4) — a reader delivers the post only when its own view of
 * this node's tier meets it. The identity process signs the post with this
 * node's Ed25519 key, group-encrypts it, and multicasts it on the group channel;
 * inbound copies are verified, tier-gated, content-id-deduped and gossip-
 * forwarded a bounded number of hops. The core does NOT echo the outgoing post
 * back — the app echoes it locally.
 *
 * @return 0 on success, @ref AT_APP_NOT_READY if @p q_out is not bound yet,
 *         -1 on any other failure.
 */
int at_app_events_publish_post(at_app_events_t *handle, const char *q_out,
                               const char *body, int required_tier);

/**
 * @brief Publish THIS node's own business page (Phase 3 P3.2).
 *
 * Sends the app→AT `AT_APP_ADVERTISE_BUSINESS` verb on @p q_out with
 * {"polity", "bundle", "seq"}; identity signs the canonical ad with this node's
 * Ed25519 key, marks it as the business's own (@ref AT_APP_BUSINESS_SAT_SELF),
 * and group-multicasts it. @p bundle is the OPAQUE, self-verifying Ethne page
 * artifact the app built through Ethne — the core never parses it.
 *
 * Reach comes from customers, not from this call: the business's own ad travels
 * one group, and it is each CUSTOMER's re-advertisement (see
 * @ref at_app_events_set_customer) that carries the page further.
 *
 * @return 0 on success, @ref AT_APP_NOT_READY if @p q_out is not bound, -1 otherwise.
 */
int at_app_events_advertise_business(at_app_events_t *handle, const char *q_out,
                                     const char *polity_did, const char *bundle,
                                     int64_t seq);

/**
 * @brief Declare, update or clear THIS node's CUSTOMER edge to a business
 * (Phase 3 P3.2).
 *
 * Sends the app→AT `AT_APP_SET_CUSTOMER` verb on @p q_out with
 * {"polity", "satisfaction", "bundle", "seq"}. A customer edge is what
 * authorizes this node to CARRY a business's page: on set, identity caches the
 * bundle and immediately advertises it in the FIRST PERSON — signed with this
 * node's key, carrying this node's satisfaction — and does so again whenever a
 * fresh ad for that business arrives. Nobody else relays a page, so a business's
 * reach is exactly the sum of its customers' voices.
 *
 * @param satisfaction 0..4, or NEGATIVE to clear the edge. Clearing is how an
 *        unhappy customer withdraws: this node simply goes quiet about the
 *        business. No negative is ever published, so there is nothing to
 *        brigade with.
 * @param bundle The page to carry, or NULL/"" to carry the page this node has
 *        already learned (so a person can become a customer straight from a page
 *        that reached them through someone else).
 * @return 0 on success, @ref AT_APP_NOT_READY if @p q_out is not bound, -1 otherwise.
 */
int at_app_events_set_customer(at_app_events_t *handle, const char *q_out,
                               const char *polity_did, int satisfaction,
                               const char *bundle, int64_t seq);

/**
 * @brief React to a peer's post (Increment 8). Sends AT_APP_REACT_POST with
 * {"author", "post_id"}; identity delivers a directed encrypted reaction to the
 * author and both peers accrue reputation for the engagement.
 * @return 0 on success, @ref AT_APP_NOT_READY if @p q_out is not bound, -1 otherwise.
 */
int at_app_events_react_post(at_app_events_t *handle, const char *q_out,
                             const uint8_t author_uuid[AT_APP_UUID_LEN],
                             const char *post_id);

/**
 * @brief Locally block a peer (Increment 8). Sends AT_APP_BLOCK with {"peer"};
 * identity clamps the peer's effective trust tier to 0 for this node only. Purely
 * local — no wire traffic, no reputation transaction.
 * @return 0 on success, @ref AT_APP_NOT_READY if @p q_out is not bound, -1 otherwise.
 */
int at_app_events_block(at_app_events_t *handle, const char *q_out,
                        const uint8_t peer_uuid[AT_APP_UUID_LEN]);

/**
 * @brief Ask named peers to co-sign one record (Phase 3 P3.3).
 *
 * Sends the app→AT `AT_APP_REQUEST_COSIGN` verb on @p q_out with
 * {"peers", "record", "op", "polity", "cid", "bytes"}; identity sends each named
 * peer a directed ENCRYPTED `peer_cosign_request`, and each of them answers with
 * @ref at_app_events_return_cosign. No private key moves: that is the whole
 * point of exporting the bytes rather than gathering the keys.
 *
 * @p bytes is the exchange's canonical CBOR as lowercase hex, and it must be
 * reproduced EXACTLY — the signatures are over these bytes, so anything that
 * truncates or re-encodes them produces signatures over nothing. An oversized
 * exchange is refused rather than shortened; keep the cited observation scoped
 * to the member concerned (see @ref AT_APP_COSIGN_BYTES_LEN).
 *
 * The core carries the payload and verifies nothing about it, and it carries NO
 * description: each signer's own node derives what the bytes commit to. Do not
 * add one here — a wording chosen by the asking node is how a human comes to
 * sign something other than what they were shown.
 *
 * @param[in] peer_uuids  @p n_peers × 16-byte identities to ask.
 * @return 0 on success, @ref AT_APP_NOT_READY if @p q_out is not bound, -1 on
 *         any other failure (including a malformed op or non-hex @p bytes).
 */
int at_app_events_request_cosign(at_app_events_t *handle, const char *q_out,
                                 const uint8_t *peer_uuids, size_t n_peers,
                                 const char *record, const char *op,
                                 const char *polity_did, const char *cid,
                                 const char *bytes);

/**
 * @brief Return this node's detached signature to the authoring peer (Phase 3
 * P3.3).
 *
 * Sends the app→AT `AT_APP_RETURN_COSIGN` verb on @p q_out with
 * {"peer", "cid", "signer", "sig"}; identity sends the requester a directed
 * ENCRYPTED `peer_cosign_sig`. @p signer_did is this signer's did:key (it embeds
 * the public key, so the assembling node needs no registry) and @p sig_hex the
 * detached Ed25519 signature over the exported bytes.
 *
 * Sign only after deriving, on this node, what those bytes actually commit to.
 *
 * @return 0 on success, @ref AT_APP_NOT_READY if @p q_out is not bound, -1 otherwise.
 */
int at_app_events_return_cosign(at_app_events_t *handle, const char *q_out,
                                const uint8_t peer_uuid[AT_APP_UUID_LEN],
                                const char *cid, const char *signer_did,
                                const char *sig_hex);
#endif /* AT_SOCIAL_ENABLED */

/** @brief Close the queue and release the handle. NULL-safe. */
void at_app_events_close(at_app_events_t *handle);

#ifdef __cplusplus
}
#endif

/** @} */ /* end of public_api */

#endif /* AT_APP_EVENTS_H */
