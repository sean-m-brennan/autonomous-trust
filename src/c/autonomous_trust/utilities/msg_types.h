/********************
 *  Copyright 2024 TekFive, Inc., Sean M. Brennan, and contributors
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

#ifndef MSG_TYPES_H
#define MSG_TYPES_H

/** @addtogroup internal_utilities
 *  @{
 */

#include <stdint.h>

#include "identity/identity.h"
#include "identity/group.h"
#include "identity/peers.h"
#include "processes/capabilities.h"
#include "reputation/tx_channel.h"
#include "negotiation/task.h"
#include "utilities/util.h"

/**
 * @brief Tags discriminating the payload carried by @ref generic_msg_t.
 */
typedef enum {
    SIGNAL = 1,              /**< Process-control signal (@ref signal_t). */
    GROUP,                   /**< Group announcement / rekey. */
    PEER,                    /**< Peer identity advertisement. */
    PEER_CAPABILITIES,       /**< Peer capability matrix. */
    TASK,                    /**< New task assignment. */
    NET_MESSAGE,             /**< Generic network message (@ref net_msg_t). */
    TASK_STATUS,             /**< Task status update. */
    TASK_RESULT,             /**< Task completion payload. */
    TRANSACTION_SCORE,       /**< Reputation transaction score. */
    UPDATE_PROPOSAL,         /**< Fleet update proposal. */
    UPDATE_VOTE,             /**< Vote on an update proposal. */
    UPDATE_ACCEPTED,         /**< Announcement that an update was accepted. */
    PEER_RTT_UPDATE,         /**< Net-proc → sibling processes: peer RTT telemetry. Local IPC only — not part of identity.proto / public_identity_t network serialization. */
    PEER_OBSERVED,           /**< Identity → app: one observed peer (@ref peer_observed_msg_t). Local IPC only. */
    PEER_REPUTATION,         /**< Reputation → app: one peer's earned score (@ref peer_reputation_msg_t). Local IPC only. */
    CHILD_GROUP,             /**< Identity → sibling processes: one cohort this node GATEWAYS, beyond its primary group. Local IPC only. Carries a @ref group_t like @ref GROUP, but must never land in `protocol.group` — the reputation process keeps a separate chain per child group, and clobbering the primary slot would merge a subtree into it. Mirrors Python's ChildGroupSet (see gateway-reputation-tree.md, doc/architecture/gateway-reputation-tree.md). */
    PEER_RTT_OBSERVED,       /**< Net-proc → app: one peer's latest RTT (ms). Local IPC only. Reuses @ref peer_rtt_update_msg_t; distinct from @ref PEER_RTT_UPDATE (which stays net-proc → sibling processes). */
#ifdef AT_SOCIAL_ENABLED
    PEER_POSITION_OBSERVED,  /**< Identity → app: one peer's shared coarse position (opt-in geohash, @ref peer_position_msg_t). Local IPC only. */
    PEER_PROFILE_OBSERVED,   /**< Identity → app: one peer's shared agora.profile (opt-in, signature-verified, @ref peer_profile_msg_t). Local IPC only. */
    PEER_CONNECTION_REQUEST_OBSERVED, /**< Identity → app: an inbound connection ASK from a peer (Increment 5, @ref peer_connection_msg_t). Local IPC only. */
    PEER_CONNECTION_STATE_OBSERVED,   /**< Identity → app: our connection edge-state toward a peer changed (Increment 5, @ref peer_connection_msg_t). Local IPC only. */
    PEER_DM_OBSERVED,        /**< Identity → app: a directed text message received from a peer (Increment 6, @ref peer_dm_msg_t). Local IPC only. Live stream — delivered on arrival, never roster state. */
    PEER_POST_OBSERVED,      /**< Identity → app: a signed feed post received over the group channel (Increment 7, @ref peer_post_msg_t). Local IPC only. Signature-verified, tier-gated and content-id-deduped before emit. */
    PEER_REACTION_OBSERVED,  /**< Identity → app: a peer reacted to one of our posts (Increment 8, @ref peer_reaction_msg_t). Local IPC only. Live stream — delivered on arrival. */
    PEER_PROXIMITY_OBSERVED, /**< Identity → app: the coarse distance BAND to a CONNECTED peer, learned by a private-proximity probe (Phase 2, @ref peer_proximity_msg_t). Local IPC only. No coordinates — only the band. */
    PEER_BUSINESS_AD_OBSERVED, /**< Identity → app: a signed business ad — one opaque Ethne page bundle plus the advertiser's satisfaction (Phase 3 P3.2, @ref peer_business_ad_msg_t). Local IPC only. Signature-verified and content-id-deduped before emit; the BUNDLE is verified app-side, never by the core. */
    PEER_COSIGN_REQUEST_OBSERVED, /**< Identity → app: a peer asks this node to co-sign a staff-roll or guardianship record (Phase 3 P3.3, @ref peer_cosign_request_msg_t). Local IPC only. The core shape-checks the ask and carries the exported bytes; it holds no Ethne, so it verifies nothing about WHAT is being signed — and it never carries the wording, which the signer's own node derives from the bytes. */
    PEER_COSIGN_SIG_OBSERVED, /**< Identity → app: a signer returns their detached signature over an exchange this node is authoring (Phase 3 P3.3, @ref peer_cosign_sig_msg_t). Local IPC only. The signature is checked against the payload by the ASSEMBLING node, not by the core. */
#endif /* AT_SOCIAL_ENABLED */
#ifdef AT_ZTA_ENABLED
    ZTA_REVOCATION_ALERT,    /**< Peer credential revocation notice. */
    ZTA_VERIFICATION_RESULT, /**< Outcome of a deferred ZTA verification. */
    ZTA_STANDING             /**< Identity → reputation: what ZTA proved about a peer (@ref zta_standing_msg_t). Local IPC only. Mirrors Python's ZtaStanding (doc/architecture/zta-integration.md). */
#endif
} message_type_t;

/**
 * @brief Network message wrapper
 * @details Network messages are strictly between net_proc and other processes, 
 *          and always in packed protobuf format.
 * 
 */
typedef struct
{
    char process[PROC_NAME_LEN+1];
    char *function;
    /* Heap-allocated payload + explicit length. Wire-side cap is
     * `NET_MSG_MAX_DATA = 1 MB` (see `net_message.h:31`); the
     * transport rejects oversized envelopes before they reach this
     * struct, so callers can treat `len` as already-bounded. */
    uint8_t *obj;
    size_t len;
    public_identity_t to_whom;
    public_identity_t from_whom;
    /* Sender topology rank carried on the envelope (mirrors Python's
     * from_whom._rank riding the wire). public_identity_t drops rank, so the
     * envelope carries it alongside; net_proc route_to_process copies it in
     * from the wire, and the identity process captures it into peer_ranks at
     * admission for rank-based child-gateway discovery. Default 0 (unknown).
     * See doc/architecture/gateway-reputation-tree.md. */
    int from_rank;
    bool encrypt;
    /* Route this message as an encrypted GROUP MULTICAST on NET_CHAN_GROUP
     * (Increment 7) rather than a directed peer send or an open broadcast. The
     * identity process sets this for a feed post; net_proc maps it to
     * RECIPIENT_GROUP. Serialized across the IPC hop by net_msg_to_proto /
     * proto_to_net_msg (absent/false on the wire = the historical peer/broadcast
     * behavior). */
#ifdef AT_SOCIAL_ENABLED
    bool group_multicast;
#endif /* AT_SOCIAL_ENABLED */
    char return_to[PROC_NAME_LEN+1];
    /* 32-char hex (UUID4 without dashes) + NUL — must match
     * NET_TRACE_ID_LEN in network/net_message.h. Carried across the IPC
     * hop between net_proc and sibling processes so probes_trace_msg
     * stays correlated end-to-end. Empty string means "not set"; the
     * wire serializer mints one in that case. */
    char trace_id[33];
    /* Signature-verification result carried from net_message_from_wire
     * across the IPC hop. Mirrors Python Message.verified
     * (network/message.py:72). Without this field the wire layer's
     * verification result is silently dropped at route_to_process, so
     * downstream handlers (e.g. reputation/handle_transaction) can't
     * reject unsigned/spoofed Paxos consensus messages — a parity
     * gap with Python's repprocess.handle_transaction:390 /
     * handle_accepted:439. has_signature distinguishes "no signature
     * supplied" from "signature present but failed verify"; both
     * leave verified=false but only the latter is a security event. */
    bool verified;
    bool has_signature;
} net_msg_t;

typedef enum {
    TASK_STATUS_RUNNING = 1,
    TASK_STATUS_SLEEPING,
    TASK_STATUS_ZOMBIE,
    TASK_STATUS_STOPPED,
    TASK_STATUS_DEAD,
    TASK_STATUS_PENDING,
    TASK_STATUS_UNKNOWN
} task_status_val_t;

typedef struct {
    uuid_t task_uuid;
    uuid_t requestor_uuid;
    task_status_val_t status;
} task_status_msg_t;

typedef struct {
    uuid_t task_uuid;
    uuid_t requestor_uuid;
    uint8_t *result_data;
    size_t result_len;
} task_result_msg_t;

typedef struct {
    uuid_t task_uuid;
    /* The peer this score is ABOUT (the SUBJECT), not the proposer: the
     * reputation process fills our own identity in for that. Zero == not
     * attributable to a single peer, which is the honest answer for a fan-out.
     * IPC-only by construction -- this struct never crosses the wire, and the
     * paxos payload that does carries no subject -- which is what makes
     * R+D.md §12.8's "locally-produced evidence only" rule structural: a score
     * off the wire has nobody to accuse whatever channel it claims. */
    uuid_t peer_uuid;
    double score;
    /* Name of the Capability that produced this score, so the reputation
     * process can resolve its transaction_weight (mirrors Python
     * TransactionScore.capability_name). Empty string == unknown/legacy →
     * weight 1. Carried verbatim by the whole-struct memcpy in
     * msg_types.c (TRANSACTION_SCORE ser/de), so no field-wise packing. */
    char capability_name[CAP_NAMELEN + 1];
    /* Which evidence channel this score came from (R+D.md §12.8), so an app
     * submitting a physics refutation or a certificate verdict can say so
     * rather than handing AT a bare number. Empty string == absent ->
     * TX_CHANNEL_TASK_OUTCOME, which is what every pre-channel submitter
     * meant. An unknown spelling is refused at the reputation process
     * boundary, not silently graded. Carried verbatim by the whole-struct
     * memcpy in msg_types.c (TRANSACTION_SCORE ser/de), so no field-wise
     * packing. Mirrors Python TransactionScore.channel. */
    char channel[TX_CHANNEL_NAMELEN + 1];
    /* The learned multiplier on this score's EMA weight (R+D.md §12.5): the
     * subject peer's prequential record on this capability, measured by the
     * negotiation process that observed the forecast and carried to the
     * reputation process that applies the weight. Mirrors Python
     * TransactionScore.competence.
     *
     * Zero or negative == absent -> 1.0, the authored transaction_weight
     * verbatim, which is what every producer predating this field meant (and
     * what a zeroed struct says). Local-only by exactly the construction that
     * makes `peer_uuid` above local-only: this struct never crosses the wire.
     * That is not tidiness -- a peer that could stamp its own competence
     * would hold a lever on every EMA it appears in, the same reason §12.8's
     * channel weight applies to locally-produced evidence only.
     *
     * Carried verbatim by the whole-struct memcpy in msg_types.c
     * (TRANSACTION_SCORE ser/de), so no field-wise packing. */
    double competence;
} tx_score_msg_t;

typedef struct {
    uuid_t proposal_uuid;
    uuid_t voter_uuid;
    bool accept;
} update_vote_msg_t;

typedef struct {
    uuid_t proposal_uuid;
    int accept_count;
    int reject_count;
} update_accepted_msg_t;

/**
 * @brief Net-proc → sibling processes: latest per-peer RTT estimate.
 *
 * Emitted after net_proc stores @c peer_rtt_ms[idx] for a new or
 * re-measured peer. Carries (peer uuid, rtt_ms) so sibling processes
 * can look up the peer in their own @c peers[] and update the matching
 * @c peer_rtt_ms[] slot. Local IPC only — not serialized via
 * identity.proto on the network transport.
 */
typedef struct {
    uuid_t  peer_uuid;
    int32_t rtt_ms;
} peer_rtt_update_msg_t;

/**
 * @brief AT → app: one peer as this node currently observes it.
 *
 * Half of the app-facing peer carrier; @ref peer_reputation_msg_t is the
 * other half. The split follows process ownership rather than the consumer's
 * convenience: the identity process holds the peer table, the ranks and the
 * operator signals, while earned reputation lives in the reputation process.
 * Neither reaches into the other; the consumer joins the two on @c peer_uuid.
 *
 * Local IPC only — not part of identity.proto or `public_identity_t` network
 * serialization (same standing as @ref peer_rtt_update_msg_t).
 *
 * See doc/architecture/app-peer-carrier.md.
 */
typedef struct {
    uuid_t   peer_uuid;
    /** ed25519 signing public key (`public_identity_t.signature.public`).
     *  Identity for a consumer: it is what a `did:key` embeds, so no
     *  registry is needed to name this peer outside AT. */
    uint8_t  signing_pubkey[crypto_sign_PUBLICKEYBYTES];
    /** Topology rank (one-hop reachability via gateways), from the identity
     *  process's `peer_ranks` seam; 0 = unknown. NOT a trust tier. */
    int32_t  rank;
    /** Durable: this node has a human guardian, and OUR receiver verified
     *  their credential against the distinct operator anchor. Never the
     *  peer's own claim. */
    bool     operator_bound;
    /** Live: epoch seconds of the last verified operator session, 0 = nobody
     *  attending (or could not confirm — for a guardian edge those are the
     *  same operational answer). Meaningless without a clock to compare
     *  against, so it is carried raw and graded by the consumer, never
     *  reduced to a bool here. Read together with @c operator_bound and
     *  never for it: a bound node with nobody at the keyboard for a week is
     *  a normal state, not an error.
     *  See doc/architecture/operator-attended.md. */
    double   operator_attested_at;
    /** WHICH human, when the peer opted in: the guardian's ed25519 public
     *  key, all-zero for "not advertised". Non-zero only when OUR receiver
     *  verified a binding signed by that operator's credential and naming
     *  this peer — the stored key IS the verification, so there is no second
     *  flag here to disagree with it.
     *
     *  All-zero is the ordinary case and says nothing bad about the peer:
     *  naming a guardian is opt-in, and one key per operator links that
     *  human's nodes to each other, which is a real cost AT does not impose.
     *  Zeroed whenever @c operator_bound is false, for the same reason the
     *  stamp is. */
    uint8_t  operator_pubkey[crypto_sign_PUBLICKEYBYTES];
#ifdef AT_SOCIAL_ENABLED
    /** True iff this peer's address is a current member of OUR group's
     *  address_map — i.e. we and the peer are in the same group. The social app
     *  surfaces it as an "in your group" indicator, distinct from an explicit
     *  connection edge. Appended LAST; social builds only. */
    bool     in_group;
#endif /* AT_SOCIAL_ENABLED */
} peer_observed_msg_t;

/**
 * @brief AT → app: one peer's earned reputation.
 *
 * @c rated is the load-bearing field. AT's scale is anchored by fixed
 * constants (PREREP_NEUTRAL, COMM_CUTOFF, the tier floors) rather than
 * normalized across the peer population, so @c score crosses as-is — but a
 * peer AT has never scored reads as exactly PREREP_NEUTRAL, which is also a
 * score a peer can genuinely earn. Collapsing those two would let a consumer
 * treat "no information" as a real, mid-range rating. @c rated separates
 * them: false means @c score carries no information and must not be read.
 *
 * Local IPC only.
 */
typedef struct {
    uuid_t peer_uuid;
    /** AT's absolute [0.0, 1.0] score. Meaningless unless @c rated. */
    double score;
    /** True iff AT holds an actual rating for this peer. */
    bool   rated;
} peer_reputation_msg_t;

#ifdef AT_SOCIAL_ENABLED
/* Max geohash length carried across the AT->app boundary. The app shares a
 * ~5-char geohash (the ~5km "neighborhood" bucket); the buffer allows finer
 * precision later without an ABI change. MUST match AT_APP_GEOHASH_LEN in
 * app_events.h. */
#define AT_GEOHASH_MAX_LEN 12

/**
 * @brief AT → app: one peer's shared coarse position, as an opt-in geohash
 * bucket. Half of the geographic-distance feature (Increment 2); the app
 * computes distance from its own opted-in bucket. An empty @c geohash means the
 * peer shared none (opted out) — the ordinary, default case. Treat the geohash
 * as opaque and untrusted peer input. Local IPC only — the on-wire exchange is
 * the directed peer_position_query/response, not this message.
 */
typedef struct {
    uuid_t peer_uuid;
    /** NUL-terminated geohash; "" = none / opted out. */
    char   geohash[AT_GEOHASH_MAX_LEN + 1];
} peer_position_msg_t;

/*
 * A private-proximity result (Phase 2): the coarse distance BAND to one
 * CONNECTED peer, learned by exchanging pairwise-keyed grid tags. Carries NO
 * coordinates — only the band (see at_prox_band_t: 0 unknown, 1 near, 2 mid,
 * 3 far). Local IPC only; the on-wire exchange is the directed encrypted
 * peer_proximity_probe/reply, not this message.
 */
typedef struct {
    uuid_t peer_uuid;
    int    band; /**< at_prox_band_t */
} peer_proximity_msg_t;

/* Max bytes of the compact profile JSON carried across the AT->app boundary
 * (the sanitized field object; the signature stays in the core). MUST match
 * AT_PROFILE_JSON_MAX in identity/profile.h and AT_APP_PROFILE_JSON_LEN in
 * app_events.h. */
#define AT_PROFILE_JSON_LEN 2560

/**
 * @brief AT → app: one peer's shared agora.profile, as compact field JSON
 * (Increment 3). Emitted only AFTER the core has bound-validated the fields and
 * verified the peer's Ed25519 signature, so the app receives already-trusted
 * data; the signature itself does not cross. An empty @c profile_json means the
 * peer shared none (opted out). Local IPC only — the on-wire exchange is the
 * directed, signed peer_profile_query/response, not this message.
 */
typedef struct {
    uuid_t peer_uuid;
    /** NUL-terminated compact JSON object of profile fields; "" = none. */
    char   profile_json[AT_PROFILE_JSON_LEN + 1];
} peer_profile_msg_t;

/**
 * @brief AT → app: a connection edge event toward one peer (Increment 5).
 *
 * Carries the peer's uuid and this node's local edge state toward it
 * (@ref at_conn_state_t cast to int): none=0, pending_out=1, pending_in=2,
 * connected=3, declined=4. Used for BOTH @ref PEER_CONNECTION_REQUEST_OBSERVED
 * (an inbound ask; @c state is pending_in) and @ref PEER_CONNECTION_STATE_OBSERVED
 * (any edge transition). A connection is EXPLICIT and separate from reputation.
 * Local IPC only — the on-wire exchange is the directed peer_connection_request
 * / signed peer_connection_response, not this message.
 */
typedef struct {
    uuid_t  peer_uuid;
    int32_t state;   /**< @ref at_conn_state_t cast to int. */
} peer_connection_msg_t;

/* Max bytes of a DM body carried across the AT->app boundary (Increment 6).
 * MUST match AT_DM_TEXT_MAX in identity/dm.h, AT_APP_DM_TEXT_LEN in app_events.h,
 * and AGORA_DM_TEXT_MAX in the shim / cohort ctypes. */
#define AT_DM_TEXT_LEN 1024

/**
 * @brief AT → app: one directed text message received from a peer (Increment 6).
 *
 * A DM is a single directed, ENCRYPTED peer→peer message; crypto_box already
 * authenticates the sender, so no extra signature is needed and the sender uuid
 * is trustworthy. @c seq is the sender's freshness sequence (a replayed/stale
 * seq is dropped before this is emitted); @c ts is the sender's send time (epoch
 * seconds). @c text is bound-truncated to @ref AT_DM_TEXT_LEN bytes. Local IPC
 * only, and a LIVE STREAM — delivered on arrival, never replayed as roster
 * state. The on-wire form is the directed encrypted peer_dm verb, not this
 * message.
 */
typedef struct {
    uuid_t  peer_uuid;   /**< The SENDER's uuid. */
    int64_t seq;         /**< The sender's freshness sequence. */
    double  ts;          /**< The sender's send time (epoch seconds). */
    /** NUL-terminated message body, bound-truncated to AT_DM_TEXT_LEN bytes. */
    char    text[AT_DM_TEXT_LEN + 1];
} peer_dm_msg_t;

/* Max bytes of a post body carried across the AT->app boundary (Increment 7).
 * MUST match AT_POST_BODY_MAX in identity/post.h, AT_APP_POST_BODY_LEN in
 * app_events.h, and AGORA_POST_BODY_MAX in the shim / cohort ctypes. */
#define AT_POST_BODY_LEN 4096
/* Content id: blake2b-256 digest as lowercase hex (32 bytes -> 64 chars). MUST
 * match AT_POST_ID_HEX_LEN in identity/post.h, AT_APP_POST_ID_LEN in
 * app_events.h, and AGORA_POST_ID_MAX in the shim / cohort ctypes. */
#define AT_POST_ID_LEN 64

/**
 * @brief AT → app: one signed feed post received over the group channel
 * (Increment 7).
 *
 * A post is a signed, content-addressed feed item distributed by encrypted group
 * multicast and gossip-forwarded a bounded number of hops. @c peer_uuid is the
 * AUTHOR (bound by the Ed25519 signature the core verified before emitting, NOT
 * by the wire envelope). @c post_id is the blake2b content-address of the
 * canonical form — the dedup/merge key. @c seq is the author's post sequence,
 * @c ts the author's post time (epoch seconds), @c required_tier the audience
 * floor (0..4). @c body is bound-truncated to @ref AT_POST_BODY_LEN bytes. Local
 * IPC only; the on-wire form is the group-encrypted peer_post verb, not this
 * message.
 */
typedef struct {
    uuid_t  peer_uuid;   /**< The AUTHOR's uuid (signature-bound). */
    /** NUL-terminated blake2b content id (lowercase hex). */
    char    post_id[AT_POST_ID_LEN + 1];
    int64_t seq;         /**< The author's post sequence. */
    double  ts;          /**< The author's post time (epoch seconds). */
    int32_t required_tier; /**< Audience floor 0..4. */
    /** NUL-terminated post body, bound-truncated to AT_POST_BODY_LEN bytes. */
    char    body[AT_POST_BODY_LEN + 1];
} peer_post_msg_t;

/**
 * @brief AT → app: one reaction to one of OUR posts, received from a peer
 * (Increment 8).
 *
 * A reaction is a single directed, ENCRYPTED reactor→author message; crypto_box
 * authenticates the reactor, so no extra signature is needed and @c peer_uuid (the
 * REACTOR) is trustworthy. @c post_id is the content-id of the post reacted to.
 * @c seq is the reactor's freshness sequence (a stale/replayed seq is dropped
 * before this is emitted); @c ts is the reactor's send time. Local IPC only; the
 * on-wire form is the directed encrypted peer_reaction verb, not this message.
 */
typedef struct {
    uuid_t  peer_uuid;   /**< The REACTOR's uuid. */
    /** NUL-terminated content id of the post reacted to (lowercase hex). */
    char    post_id[AT_POST_ID_LEN + 1];
    int64_t seq;         /**< The reactor's freshness sequence. */
    double  ts;          /**< The reactor's send time (epoch seconds). */
} peer_reaction_msg_t;

/* Max bytes of the opaque Ethne page bundle carried across the AT->app boundary
 * (Phase 3 P3.2). MUST match AT_BUSINESS_BUNDLE_MAX in identity/business_ad.h,
 * AT_APP_BUSINESS_BUNDLE_LEN in app_events.h, and AGORA_BUSINESS_BUNDLE_MAX in
 * the shim / cohort ctypes. */
#define AT_BUSINESS_BUNDLE_LEN 3072
/* Max bytes of a polity DID. MUST match AT_BUSINESS_DID_MAX in
 * identity/business_ad.h, AT_APP_BUSINESS_DID_LEN in app_events.h, and
 * AGORA_BUSINESS_DID_MAX in the shim / cohort ctypes. */
#define AT_BUSINESS_DID_LEN 95
/* Ad content id: blake2b-256 digest as lowercase hex (32 bytes -> 64 chars).
 * MUST match AT_BUSINESS_AD_ID_HEX_LEN in identity/business_ad.h,
 * AT_APP_BUSINESS_AD_ID_LEN in app_events.h, and AGORA_BUSINESS_AD_ID_MAX in the
 * shim / cohort ctypes. */
#define AT_BUSINESS_AD_ID_LEN 64

/**
 * @brief AT → app: one signed business ad received over the group channel
 * (Phase 3 P3.2, "businesses near me").
 *
 * @c peer_uuid is the ADVERTISER — bound by the Ed25519 signature the core
 * verified before emitting, NOT by the wire envelope — and is either the
 * business's own node or a CUSTOMER re-advertising from its cache in the first
 * person. There is no relay and no hop count: only customers carry a page, and
 * they always speak for themselves (see identity/business_ad.h).
 *
 * @c polity is the business's Ethne DID (the page store's key), @c satisfaction
 * the advertiser's declared 0..4 rating or @ref AT_BUSINESS_SAT_SELF for the
 * business's own ad, @c seq the page version, @c ts the advertiser's send time.
 * @c ad_id is the blake2b content-address of the canonical form — the dedup key.
 *
 * @c bundle is the OPAQUE, self-verifying Ethne page artifact ({page,delegation}
 * proving polity-root → envoy → page). The core never parses it; the APP
 * verifies it. Local IPC only; the on-wire form is the group-encrypted
 * peer_business_ad verb, not this message.
 */
typedef struct {
    uuid_t  peer_uuid;   /**< The ADVERTISER's uuid (signature-bound). */
    /** NUL-terminated polity DID — the business this ad is for. */
    char    polity[AT_BUSINESS_DID_LEN + 1];
    /** NUL-terminated blake2b ad content id (lowercase hex). */
    char    ad_id[AT_BUSINESS_AD_ID_LEN + 1];
    int32_t satisfaction; /**< 0..4, or AT_BUSINESS_SAT_SELF (255) for the business's own ad. */
    int64_t seq;         /**< The page version the advertiser is carrying. */
    double  ts;          /**< The advertiser's send time (epoch seconds). */
    /** NUL-terminated opaque Ethne bundle, bound-truncated to AT_BUSINESS_BUNDLE_LEN. */
    char    bundle[AT_BUSINESS_BUNDLE_LEN + 1];
} peer_business_ad_msg_t;

/* Max hex characters of a detached exchange's exported canonical bytes (Phase 3
 * P3.3). MUST match AT_COSIGN_BYTES_MAX in identity/cosign.h,
 * AT_APP_COSIGN_BYTES_LEN in app_events.h, COSIGN_BYTES_HEX_MAX in the agora
 * ethne_ffi crate, and AGORA_COSIGN_BYTES_MAX in the shim / cohort ctypes. */
#define AT_COSIGN_BYTES_LEN 6144
/* Max bytes of a polity DID, or of a signer's did:key. MUST match
 * AT_COSIGN_DID_MAX in identity/cosign.h, AT_APP_COSIGN_DID_LEN in
 * app_events.h, and AGORA_COSIGN_DID_MAX in the shim / cohort ctypes. */
#define AT_COSIGN_DID_LEN 95
/* Exchange content id as Ethne prints it: "b3:" + 64 lowercase hex. MUST match
 * AT_COSIGN_CID_MAX in identity/cosign.h, AT_APP_COSIGN_CID_LEN in
 * app_events.h, and AGORA_COSIGN_CID_MAX in the shim / cohort ctypes. */
#define AT_COSIGN_CID_LEN 67
/* An Ed25519 signature as lowercase hex (64 bytes -> 128 chars). MUST match
 * AT_COSIGN_SIG_MAX in identity/cosign.h, AT_APP_COSIGN_SIG_LEN in
 * app_events.h, and AGORA_COSIGN_SIG_MAX in the shim / cohort ctypes. */
#define AT_COSIGN_SIG_LEN 128
/* A record-class or op token ("membership", "guardian", "designate", …). MUST
 * match AT_COSIGN_TOKEN_MAX in identity/cosign.h, AT_APP_COSIGN_TOKEN_LEN in
 * app_events.h, and AGORA_COSIGN_TOKEN_MAX in the shim / cohort ctypes. */
#define AT_COSIGN_TOKEN_LEN 15

/**
 * @brief AT → app: a peer asks this node to co-sign one record (Phase 3 P3.3).
 *
 * A staff roll act is decided by several people who are not at the same
 * keyboard, and their KEYS DO NOT TRAVEL. The record does: one node exports its
 * canonical bytes, each required signer signs those exact bytes on their own
 * node, and the authoring node reassembles the signatures.
 *
 * @c peer_uuid is the REQUESTER, bound by crypto_box on the directed encrypted
 * envelope — nobody can put an ask in somebody else's mouth. @c record is
 * "membership" or "guardian" and @c op the act within it; @c polity the Ethne
 * DID; @c cid the exchange's content address; @c bytes the exported canonical
 * CBOR as lowercase hex.
 *
 * **The core verifies nothing about what is being signed**, exactly as it
 * verifies nothing about a business page bundle: it holds no Ethne. It bounds
 * and shape-checks the fields (known op, even-length lowercase hex) so a
 * malformed ask is refused rather than carried.
 *
 * **No description travels.** What the record commits to, in words, is derived
 * on the SIGNER's node from these bytes. Carrying the wording would let the
 * asking node choose both what you sign and what you are told you are signing.
 *
 * Local IPC only; the on-wire form is the directed encrypted peer_cosign_request
 * verb, not this message.
 */
typedef struct {
    uuid_t  peer_uuid;   /**< The REQUESTER's uuid (crypto_box-authenticated). */
    /** NUL-terminated record class: "membership" or "guardian". */
    char    record[AT_COSIGN_TOKEN_LEN + 1];
    /** NUL-terminated op: admit/expel, or designate/rotate/release. */
    char    op[AT_COSIGN_TOKEN_LEN + 1];
    /** NUL-terminated polity DID this record belongs to. */
    char    polity[AT_COSIGN_DID_LEN + 1];
    /** NUL-terminated exchange content id ("b3:<hex>"), NOT recomputed here. */
    char    cid[AT_COSIGN_CID_LEN + 1];
    int64_t seq;         /**< The requester's freshness sequence. */
    double  ts;          /**< The requester's send time (epoch seconds). */
    /** NUL-terminated exported canonical bytes, lowercase hex. Opaque. */
    char    bytes[AT_COSIGN_BYTES_LEN + 1];
} peer_cosign_request_msg_t;

/**
 * @brief AT → app: a signer returns their detached signature (Phase 3 P3.3).
 *
 * @c peer_uuid is the returning peer (crypto_box-authenticated). @c cid names
 * the exchange, @c signer the signing did:key — which EMBEDS its public key, so
 * the assembling node needs no registry to check the signature — and @c sig the
 * detached Ed25519 signature over the exported bytes, as lowercase hex.
 *
 * The core does not check the signature, and could not: it does not hold the
 * payload. Verification happens where it belongs, on the ASSEMBLING node, which
 * refuses a wrong key or a tampered payload before anything is appended.
 *
 * Local IPC only; the on-wire form is the directed encrypted peer_cosign_sig
 * verb, not this message.
 */
typedef struct {
    uuid_t  peer_uuid;   /**< The SIGNER's uuid (crypto_box-authenticated). */
    /** NUL-terminated exchange content id this signature is for. */
    char    cid[AT_COSIGN_CID_LEN + 1];
    /** NUL-terminated signer did:key (embeds the public key). */
    char    signer[AT_COSIGN_DID_LEN + 1];
    /** NUL-terminated detached Ed25519 signature, lowercase hex. */
    char    sig[AT_COSIGN_SIG_LEN + 1];
    int64_t seq;         /**< The signer's freshness sequence. */
    double  ts;          /**< The signer's send time (epoch seconds). */
} peer_cosign_sig_msg_t;
#endif /* AT_SOCIAL_ENABLED */

#define SIGNAL_LEN 32

typedef struct
{
    char descr[SIGNAL_LEN+1];
    int sig;
} signal_t;

#ifdef AT_ZTA_ENABLED
typedef struct {
    uuid_t peer_uuid;
    uuid_t voucher_uuid;            /* Identity of the peer that performed verification */
    uint8_t credential_hash[32];
    int status;                     /* zta_status_t cast to int */
    char reason[64];
} zta_event_msg_t;

/**
 * @brief What ZTA proved (or failed to prove) about a peer.
 *
 * Mirrors Python's `STANDING_*` in `identity/zta_standing.py`; the three
 * values are the distinctions the reputation process can act on, deliberately
 * NOT the six-valued @ref zta_status_t (the verifier's own status rides along
 * in `reason` for the operator log). doc/architecture/zta-integration.md.
 */
typedef enum {
    ZTA_STANDING_PROVED = 0, /**< Verified against a configured anchor AND bound to this identity. No ceiling; anchors the unwind. */
    ZTA_STANDING_CAPPED,     /**< Admitted but unproved (DDIL/deferred, or a chained-but-unbound credential under `binding_mode: prefer`). Carries the ceiling. */
    ZTA_STANDING_FAILED      /**< Affirmative post-admission failure: REVOKED / EXPIRED / REJECTED at re-verification. Unwinds and demotes. */
} zta_standing_t;

/**
 * @brief Identity → reputation: one peer's ZTA standing. Local IPC only.
 *
 * The verdict is discovered by the identity process (it owns admission and the
 * verifier) but the thing it must bound, reputation, lives in another process;
 * this is that hand-off. Nothing here is peer-supplied — it is this node's own
 * finding — so a peer cannot forge itself a ceiling of 1.0 by claiming one.
 *
 * Why a ceiling and not a score: a ZTA verdict is an authority finding about
 * whether an identity is who it claims, not the outcome of an interaction with
 * it, and AT's [0, 1] scale (doc/architecture/reputation.md) has no representation for a penalty. The
 * predecessor of this message tried to send one as `score = -0.8` on a
 * TRANSACTION_SCORE and was discarded at the boundary twice over — once for
 * the zero task_uuid sentinel, once for being off-scale — so a revoked
 * credential cost a peer exactly nothing.
 */
typedef struct {
    uuid_t peer_uuid;
    int32_t standing;    /**< @ref zta_standing_t cast to int. */
    double ceiling;      /**< Highest reputation this peer may hold while unproved; < 0 means "no bound". */
    char reason[64];
} zta_standing_msg_t;

/** @brief Sentinel for @ref zta_standing_msg_t::ceiling meaning "no bound". */
#define ZTA_NO_CEILING (-1.0)
#endif

/**
 * @brief Tagged union carrying any message the IPC layer understands.
 *
 * The @c type field (a @ref message_type_t cast to @c long for ABI stability
 * with the message queue) selects which member of @c info is live. Use
 * @ref message_size to learn the serialized size for a given @c type.
 */
typedef struct
{
    long type;      /**< @ref message_type_t tag. */
    size_t size;    /**< Payload size in bytes (populated by senders). */
    union {
        signal_t signal;
        group_t group;
        public_identity_t peer;
        peer_capabilities_matrix_t peer_capabilities;
        task_t task;
        net_msg_t net_msg;  // FIXME specific protocols instead
        task_status_msg_t task_status;
        task_result_msg_t task_result;
        tx_score_msg_t tx_score;
        update_vote_msg_t update_vote;
        update_accepted_msg_t update_accepted;
        peer_rtt_update_msg_t peer_rtt_update;
        peer_observed_msg_t peer_observed;
        peer_reputation_msg_t peer_reputation;
#ifdef AT_SOCIAL_ENABLED
        peer_position_msg_t peer_position;
        peer_profile_msg_t peer_profile;
        peer_connection_msg_t peer_connection;
        peer_dm_msg_t peer_dm;
        peer_post_msg_t peer_post;
        peer_reaction_msg_t peer_reaction;
        peer_proximity_msg_t peer_proximity;
        peer_business_ad_msg_t peer_business_ad;
        peer_cosign_request_msg_t peer_cosign_request;
        peer_cosign_sig_msg_t peer_cosign_sig;
#endif /* AT_SOCIAL_ENABLED */
#ifdef AT_ZTA_ENABLED
        zta_event_msg_t zta_event;
        zta_standing_msg_t zta_standing;
#endif
    } info;         /**< Discriminated-union payload keyed by @c type. */
} generic_msg_t;

/**
 * @brief Return the @c sizeof the struct associated with @p type.
 *
 * Used to size buffers for the message queue. Returns 0 for unknown types.
 */
/*@
  assigns \nothing;
  ensures \result >= 0;
*/
size_t message_size(message_type_t type);



/** @} */ /* end of internal_utilities */

#endif  // MSG_TYPES_H
