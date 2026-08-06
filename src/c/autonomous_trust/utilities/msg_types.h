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
#ifdef AT_ZTA_ENABLED
    ZTA_REVOCATION_ALERT,    /**< Peer credential revocation notice. */
    ZTA_VERIFICATION_RESULT  /**< Outcome of a deferred ZTA verification. */
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
    uuid_t peer_uuid;
    double score;
    /* Name of the Capability that produced this score, so the reputation
     * process can resolve its transaction_weight (mirrors Python
     * TransactionScore.capability_name). Empty string == unknown/legacy →
     * weight 1. Carried verbatim by the whole-struct memcpy in
     * msg_types.c (TRANSACTION_SCORE ser/de), so no field-wise packing. */
    char capability_name[CAP_NAMELEN + 1];
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
#ifdef AT_ZTA_ENABLED
        zta_event_msg_t zta_event;
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
