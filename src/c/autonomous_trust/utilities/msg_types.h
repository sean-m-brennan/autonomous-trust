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

#include <stddef.h>
#include <stdint.h>

#include "identity/identity.h"
#include "identity/group.h"
#include "identity/peers.h"
#include "processes/capabilities.h"
#include "reputation/tx_channel.h"
#include "negotiation/task.h"
#include "utilities/util.h"
#include "utilities/msg_registry.h"

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
    PEER_STANDING,           /**< An authority → reputation: a BOUND on what a peer may hold, not an interaction outcome (@ref peer_standing_msg_t). Local IPC only. Was ZTA_STANDING, and ZTA is still a producer — but so is an Ethne expulsion reaching the core through the app (Phase 4 P4.1), so the mechanism outlives the one authority that first needed it. */
    PEER_REMOVED             /**< Identity → sibling processes: drop one peer from peers[] (@ref peer_removed_msg_t). The inverse of @ref PEER, which only ever appended. Local IPC only. Sent when the user removes a first-contact (direct) peer; a cohort member is never removed this way. */
    /* Core ids stop below AT_MSG_TYPE_EXT_MIN (msg_registry.h). A FEATURE's
     * types -- social (Agora's libat_social), ZTA
     * (zta/zta_msg_types.h) -- are registered at load in their own reserved
     * range. None of these numbers is on any wire: IPC carries the NAME
     * (message_type_to_string), so appending here renumbers nothing a peer,
     * an app, or the Python twin can see. */
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
     * struct, so callers can treat `len` as already-bounded.
     *
     * OWNERSHIP: a plain malloc buffer, NOT a smrt allocation -- never
     * smrt_deref it (the payload bytes sit where a smrt header would, so the
     * "refcount" is JSON text). Whoever filled it frees it: a sender with
     * net_msg_free_obj() once its last messaging_send returns (the send
     * serializes; it does not take the buffer), a receiver with
     * messaging_recv_release(). */
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
    bool group_multicast;
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

/** Free @p msg's payload (see net_msg_t.obj) and clear obj/len. NULL-safe.
 *  For a message this code packed and has finished sending; a received
 *  message is released whole with messaging_recv_release(). */
void net_msg_free_obj(net_msg_t *msg);

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
    /** True iff this peer's address is a current member of OUR group's
     *  address_map — i.e. we and the peer are in the same group. The social app
     *  surfaces it as an "in your group" indicator, distinct from an explicit
     *  connection edge. Appended LAST. Always present so the struct is one size in
     *  every build; false without libat_social. */
    bool     in_group;
    /** True iff this peer is LOCALLY BLOCKED on this node (Phase 4 P4.1).
     *
     *  Identity's own state, reported by identity — which is why it rides here
     *  and not on @ref peer_reputation_msg_t. The app composes the two exactly
     *  as identity_get_peer_tier does: an effective tier is the reputation
     *  tier unless the peer is blocked, in which case it is 0.
     *
     *  Without this the block is INVISIBLE to the app. handle_app_block emitted
     *  nothing at all before P4.1, and the app re-derives tier from the score
     *  (tie_strength.dart mirrors the floors), so a core-side block left the
     *  score unchanged, the derived tier unchanged, and the peer ranked exactly
     *  as before. Appended LAST. Always present (see @c in_group); false
     *  without libat_social. */
    bool     blocked;
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
    /** The trust tier this score yields AFTER any standing ceiling, 0..4
     *  (Phase 4 P4.1).
     *
     *  app_events.h has said since Increment 3 that the app derives tier from
     *  reputation, and it still may — but only reputation knows about a
     *  CEILING, which is not a function of the score at all. A peer bounded by
     *  an authority reads as a perfectly ordinary score with a tier the app
     *  cannot compute. So the tier reputation actually used crosses here, and
     *  the app's own floors become a fallback for a core that predates P4.1. */
    int32_t effective_tier;
    /** The ceiling in force on this peer, or a negative sentinel for none.
     *
     *  Carried beside the tier so the app can distinguish "low because they
     *  have earned little" from "bounded by a community decision", which are
     *  different things to show a person. @ref PEER_NO_CEILING is the
     *  sentinel — and it MUST be written explicitly, because every consumer
     *  memsets its event before filling it and an unwritten 0.0 would read as
     *  "floored at zero". */
    double standing_ceiling;
} peer_reputation_msg_t;


#define SIGNAL_LEN 32

typedef struct
{
    char descr[SIGNAL_LEN+1];
    int sig;
} signal_t;


/**
 * @brief What an authority proved (or failed to prove) about a peer.
 *
 * Mirrors Python's `STANDING_*` in `identity/peer_standing.py`; the three
 * values are the distinctions the reputation process can act on, deliberately
 * NOT the six-valued @ref zta_status_t (a verifier's own status rides along
 * in `reason` for the operator log). doc/architecture/zta-integration.md.
 *
 * ALWAYS COMPILED, unlike the ZTA machinery that first needed it: an Ethne
 * expulsion is the second authority to reach this, and it arrives through the
 * app on a build with AT_ZTA off (Phase 4 P4.1). The values are explicit and
 * start at 0 so lifting them out of `#ifdef AT_ZTA_ENABLED` renumbered nothing.
 */
typedef enum {
    PEER_STANDING_PROVED = 0, /**< Verified against a configured anchor AND bound to this identity. No ceiling; anchors the unwind. From the app, this means REINSTATED. */
    PEER_STANDING_CAPPED,     /**< Admitted but unproved (DDIL/deferred, or a chained-but-unbound credential under `binding_mode: prefer`). Carries the ceiling. */
    PEER_STANDING_FAILED      /**< Affirmative post-admission failure: REVOKED / EXPIRED / REJECTED at re-verification, or an expulsion. Unwinds and demotes. */
} peer_standing_t;

/**
 * @brief An authority → reputation: one peer's standing. Local IPC only.
 *
 * The verdict is discovered by the identity process (it owns admission, the
 * verifier, and the app boundary) but the thing it must bound, reputation,
 * lives in another process; this is that hand-off. Nothing here is
 * peer-supplied — it is this node's own finding, or one its operator's app
 * handed it over the local queue — so a peer cannot forge itself a ceiling of
 * 1.0 by claiming one.
 *
 * Why a ceiling and not a score: an authority finding is about whether an
 * identity is who or what it claims, not the outcome of an interaction with
 * it, and AT's [0, 1] scale (doc/architecture/reputation.md) has no
 * representation for a penalty. The predecessor of this message tried to send
 * one as `score = -0.8` on a TRANSACTION_SCORE and was discarded at the
 * boundary twice over — once for the zero task_uuid sentinel, once for being
 * off-scale — so a revoked credential cost a peer exactly nothing.
 */
/** @brief Storage bound for a standing source name, sized past the longest
 *  spelling below with room for another. Fields are `[PEER_STANDING_SOURCE_LEN
 *  + 1]` for the terminator, matching TX_CHANNEL_NAMELEN's convention. */
#define PEER_STANDING_SOURCE_LEN 15

/** A credential authority: ZTA proved, could not prove, or disproved an
 *  identity (doc/architecture/zta-integration.md). */
#define PEER_STANDING_SOURCE_ZTA   "zta"

/** A governance authority: an Ethne polity expelled a member, or reinstated
 *  one (Phase 4 P4.1). The finding is decided in the app — the core holds no
 *  Ethne and verifies nothing about it — and arrives over the local app queue. */
#define PEER_STANDING_SOURCE_ETHNE "ethne"

/** The full closed set, iterated by @ref peer_standing_source_valid and by the
 *  effective-ceiling reduction in rep_proc.c. Mirrored by Python's
 *  STANDING_SOURCES. */
#define PEER_STANDING_SOURCE_ALL \
    PEER_STANDING_SOURCE_ZTA, \
    PEER_STANDING_SOURCE_ETHNE

/** True iff @p source is exactly one of the closed set's spellings.
 *
 *  NULL and "" are NOT valid here — they are *absent*, which is a different
 *  question from *invalid*; normalize absence with
 *  @ref peer_standing_source_or_default first. Byte-exact and case-sensitive,
 *  for the reason @ref tx_channel_valid gives: a set that quietly accepts
 *  near-misses stops being closed. */
static inline bool peer_standing_source_valid(const char *source)
{
    if (source == NULL || source[0] == '\0')
        return false;
    static const char *const all[] = { PEER_STANDING_SOURCE_ALL };
    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++)
        if (strcmp(source, all[i]) == 0)
            return true;
    return false;
}

/** @p source if it is set at all, else the default.
 *
 *  Absence normalizes to ZTA because ZTA was the only producer before there
 *  was a source field at all, so an unset source is by construction a ZTA
 *  finding from a caller that predates Phase 4 P4.1. */
static inline const char *peer_standing_source_or_default(const char *source)
{
    return (source != NULL && source[0] != '\0') ? source
                                                 : PEER_STANDING_SOURCE_ZTA;
}

typedef struct {
    uuid_t peer_uuid;
    int32_t standing;    /**< @ref peer_standing_t cast to int. */
    double ceiling;      /**< Highest reputation this peer may hold while unproved; < 0 means "no bound". */
    char reason[64];
    /** Which authority is speaking — one of @ref PEER_STANDING_SOURCE_ALL.
     *
     *  Ceilings are kept PER SOURCE and reduced by MINIMUM, because two
     *  authorities may bound the same peer for unrelated reasons and neither
     *  may clear the other's finding: a ZTA re-verification proving a
     *  certificate says nothing about whether a community expelled the person
     *  holding it. A single-valued ceiling would let whichever authority spoke
     *  last silently overwrite the other. */
    char source[PEER_STANDING_SOURCE_LEN + 1];
} peer_standing_msg_t;

/** @brief Payload of @ref PEER_REMOVED: which peer every process forgets. */
typedef struct {
    uuid_t peer_uuid;
} peer_removed_msg_t;

/** @brief Sentinel for @ref peer_standing_msg_t::ceiling meaning "no bound". */
#define PEER_NO_CEILING (-1.0)

/** @brief The bound an Ethne expulsion places on a former member (Phase 4 P4.1).
 *
 *  BELOW the tier-1 floor (0.50), so every tier-gated capability and every
 *  tier-gated feed closes; ABOVE `COMM_CUTOFF` (0.10), so the peer is NOT cut
 *  off at the network layer — "revocation as a reputation event, not a hard
 *  cut" (SOCIAL_APP_PLAN.md:481). They can still be spoken to, and they can
 *  still re-earn once the community lifts the bound.
 *
 *  The same number ZTA's default revocation already lands on: `zta_policy`'s
 *  `revocation_reputation_penalty` defaults to 0.8 and zta_process.c turns that
 *  into `ceiling = 1.0 - penalty`. Two authority findings, one bound, which is
 *  the point of there being one standing mechanism.
 *
 *  NOT comparable to `AT_SOCIAL_NEG_SCORE` (0.30), despite the numbers looking
 *  alike: that is one DATUM folded into a slow EMA, which good behaviour
 *  outweighs over time. This is a hard BOUND that no amount of good behaviour
 *  lifts.
 *
 *  Filed here rather than in libat_social's social_tx.h (Agora), where the
 *  other social constants live, because this verb is core and always
 *  compiled. */
#define AT_ETHNE_EXPEL_CEILING 0.20

/**
 * @brief Tagged union carrying any message the IPC layer understands.
 *
 * The @c type field selects which member of @c info is live: a core
 * @ref message_type_t names its arm; a type a feature registered
 * (msg_registry.h) lives in @c payload and is read with @ref AT_MSG_EXT. Use
 * @ref message_size to learn the payload size for a given @c type.
 *
 * `info` is exactly @ref AT_MSG_PAYLOAD_MAX bytes in every build, so the
 * struct's size no longer depends on which features are compiled in.
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
        peer_standing_msg_t peer_standing;
        peer_removed_msg_t peer_removed;
        /** A registered (extension) type's payload -- see msg_registry.h. */
        _Alignas(max_align_t) uint8_t payload[AT_MSG_PAYLOAD_MAX];
    } info;         /**< Discriminated-union payload keyed by @c type. */
} generic_msg_t;

_Static_assert(sizeof(((generic_msg_t *)0)->info) == AT_MSG_PAYLOAD_MAX,
               "a core arm of generic_msg_t.info outgrew AT_MSG_PAYLOAD_MAX");

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

/**
 * @brief Return a static, human-readable name for @p type.
 *
 * For logging only. Returns the empty string for types outside the enum.
 */
/*@
  assigns \nothing;
  ensures \result != \null;
*/
char *message_type_to_string(message_type_t type);



/** @} */ /* end of internal_utilities */

#endif  // MSG_TYPES_H
