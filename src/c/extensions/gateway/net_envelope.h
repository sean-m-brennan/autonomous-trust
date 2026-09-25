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

#ifndef NET_ENVELOPE_H
#define NET_ENVELOPE_H

/**
 * @file net_envelope.h
 * @brief Plaintext forwarding envelope for AT wire frames (at-over-dtn.md §4.3).
 *
 * The envelope prepends routing metadata to the existing encrypted payload
 * so a gateway node can forward frames between network legs (e.g., UDP
 * cluster → DTN bridge → UDP cluster) WITHOUT decrypting the inner
 * payload. End-to-end confidentiality is preserved: only the final peer
 * (or the receiving group) can decrypt the payload; gateways see only
 * the routing header.
 *
 * Wire layout (36-byte header + payload):
 * @code
 *   offset   field        size  meaning
 *   ------   ----------   ----  -------
 *     0      version      u8    must equal NET_ENV_VERSION (currently 0x01)
 *     1      type         u8    NET_ENV_TYPE_{PEER,BROADCAST,GROUP}
 *     2      flags        u8    bitfield (NET_ENV_FLAG_*)
 *     3      hop_count    u8    incremented by each gateway; capped at NET_ENV_MAX_HOPS
 *     4      dst_uuid     16B   final recipient UUID (NIL for broadcast; group UUID for group)
 *    20      src_uuid     16B   original sender UUID — unchanged through forwards
 *    36      payload      ...   inner AT frame (nonce+ciphertext, or raw bytes for broadcast)
 * @endcode
 *
 * Hop-count guard: a gateway that receives an envelope must bump
 * hop_count before re-transmitting; if hop_count would exceed
 * NET_ENV_MAX_HOPS, the frame is dropped rather than forwarded. This
 * bounds loops if operators misconfigure a gateway mesh.
 *
 * Gated by the AT_NET_ENVELOPE CMake option. When OFF (default), net_proc
 * sends and receives frames without this header, matching pre-2b behavior.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <uuid/uuid.h>

#define NET_ENV_VERSION     0x01
#define NET_ENV_MAX_HOPS    8
#define NET_ENV_HEADER_LEN  36

/** Envelope wraps one of AT's three logical channels. Mirrors net_channel_t
 *  semantically but is a distinct wire-level enum so the envelope is
 *  self-describing even when decoded in isolation. */
typedef enum {
    NET_ENV_TYPE_UNKNOWN   = 0,
    NET_ENV_TYPE_PEER      = 1,  /**< Encrypted unicast; dst_uuid = target peer. */
    NET_ENV_TYPE_BROADCAST = 2,  /**< Discovery broadcast; dst_uuid = NIL. */
    NET_ENV_TYPE_GROUP     = 3,  /**< Encrypted group multicast; dst_uuid = group UUID. */
} net_env_type_t;

/** Bit 0: this frame has been forwarded by at least one gateway. Useful for
 *  telemetry and for receivers to distinguish first-delivery from relay. */
#define NET_ENV_FLAG_FORWARDED 0x01

typedef struct {
    uint8_t        version;
    net_env_type_t type;
    uint8_t        flags;
    uint8_t        hop_count;
    uuid_t         dst_uuid;
    uuid_t         src_uuid;
} net_envelope_t;

/**
 * @brief Pack a header + payload into a contiguous output frame.
 *
 * @param env             Header fields to serialize (must be non-NULL).
 * @param payload         Inner payload bytes (may be NULL iff payload_len == 0).
 * @param payload_len     Length of @p payload in bytes.
 * @param out_frame       Output buffer (must be at least
 *                        NET_ENV_HEADER_LEN + payload_len bytes).
 * @param out_frame_cap   Capacity of @p out_frame in bytes.
 * @param out_frame_len   On success, receives the total frame length.
 * @return 0 on success, -1 on NULL args, oversize frame, or insufficient
 *         buffer capacity.
 */
/*@
  requires \valid_read(env);
  requires \valid_read(env->dst_uuid + (0 .. 15));
  requires \valid_read(env->src_uuid + (0 .. 15));
  requires \valid(out_frame + (0 .. out_frame_cap - 1));
  requires \valid(out_frame_len);
  requires payload_len == 0 || \valid_read(payload + (0 .. payload_len - 1));
  requires out_frame_cap >= NET_ENV_HEADER_LEN + payload_len;
  requires \separated(out_frame + (0 .. out_frame_cap - 1), env->dst_uuid + (0 .. 15));
  requires \separated(out_frame + (0 .. out_frame_cap - 1), env->src_uuid + (0 .. 15));
  requires payload_len == 0 ||
           \separated(out_frame + (0 .. out_frame_cap - 1),
                      payload + (0 .. payload_len - 1));
  requires \separated(out_frame_len, out_frame + (0 .. out_frame_cap - 1));
  assigns out_frame[0 .. NET_ENV_HEADER_LEN + payload_len - 1];
  assigns *out_frame_len;
  ensures \result == 0 || \result == -1;
  ensures \result == 0 ==> *out_frame_len == NET_ENV_HEADER_LEN + payload_len;
*/
int net_envelope_pack(const net_envelope_t *env,
                      const uint8_t *payload, size_t payload_len,
                      uint8_t *out_frame, size_t out_frame_cap,
                      size_t *out_frame_len);

/**
 * @brief Unpack a wire frame's header and locate its payload.
 *
 * @p *payload_out points INTO @p frame (not a copy); the caller must not
 * free it and must not use it beyond @p frame's lifetime.
 *
 * @param frame            Incoming frame bytes.
 * @param frame_len        Length of @p frame in bytes.
 * @param env_out          Receives parsed header fields.
 * @param payload_out      Receives a pointer to the payload inside @p frame.
 * @param payload_len_out  Receives the payload length in bytes.
 * @return 0 on success, -1 if @p frame_len is too short, version is
 *         unrecognized, or any argument is NULL.
 */
/*@
  requires frame_len == 0 || \valid_read(frame + (0 .. frame_len - 1));
  requires \valid(env_out);
  requires \valid(env_out->dst_uuid + (0 .. 15));
  requires \valid(env_out->src_uuid + (0 .. 15));
  requires \valid(payload_out);
  requires \valid(payload_len_out);
  requires frame_len < NET_ENV_HEADER_LEN ||
           \separated(env_out, frame + (0 .. frame_len - 1));
  requires frame_len < NET_ENV_HEADER_LEN ||
           \separated(env_out->dst_uuid + (0 .. 15), frame + (0 .. frame_len - 1));
  requires frame_len < NET_ENV_HEADER_LEN ||
           \separated(env_out->src_uuid + (0 .. 15), frame + (0 .. frame_len - 1));
  requires \separated(env_out, payload_out, payload_len_out);
  assigns *env_out;
  assigns env_out->dst_uuid[0 .. 15];
  assigns env_out->src_uuid[0 .. 15];
  assigns *payload_out;
  assigns *payload_len_out;
  ensures \result == 0 || \result == -1;
  ensures \result == 0 ==> frame_len >= NET_ENV_HEADER_LEN;
  ensures \result == 0 ==> *payload_len_out == frame_len - NET_ENV_HEADER_LEN;
*/
int net_envelope_unpack(const uint8_t *frame, size_t frame_len,
                        net_envelope_t *env_out,
                        const uint8_t **payload_out,
                        size_t *payload_len_out);

/**
 * @brief Copy a fresh envelope header over an existing frame in place,
 *        preserving the payload bytes that follow.
 *
 * Convenience helper for the gateway forwarding path: after deciding to
 * relay a frame, the gateway increments hop_count (and sets the
 * FORWARDED flag), then calls this to rewrite only the 36 header bytes
 * back into the frame buffer without re-copying the entire payload.
 *
 * @param env         New header fields.
 * @param frame       Frame buffer whose first NET_ENV_HEADER_LEN bytes
 *                    will be overwritten.
 * @param frame_len   Length of @p frame in bytes (must be >= NET_ENV_HEADER_LEN).
 * @return 0 on success, -1 on NULL args or undersized frame.
 */
/*@
  requires \valid_read(env);
  requires \valid_read(env->dst_uuid + (0 .. 15));
  requires \valid_read(env->src_uuid + (0 .. 15));
  requires \valid(frame + (0 .. frame_len - 1));
  requires frame_len >= NET_ENV_HEADER_LEN;
  requires \separated(frame + (0 .. frame_len - 1), env->dst_uuid + (0 .. 15));
  requires \separated(frame + (0 .. frame_len - 1), env->src_uuid + (0 .. 15));
  assigns frame[0 .. NET_ENV_HEADER_LEN - 1];
  ensures \result == 0 || \result == -1;
*/
int net_envelope_rewrite_header(const net_envelope_t *env,
                                uint8_t *frame, size_t frame_len);

/**
 * @brief True iff @p uuid is the all-zero (NIL) UUID.
 *
 * Broadcast envelopes carry dst_uuid = NIL. Receivers compare against
 * this to distinguish broadcast from unicast routing.
 */
/*@
  requires \valid_read(uuid + (0 .. 15));
  assigns \nothing;
*/
bool net_envelope_is_nil_uuid(const uuid_t uuid);

/** Disposition a receiver should apply to an unpacked envelope. */
typedef enum {
    NET_ENV_DISPOSITION_LOCAL   = 0, /**< Payload is for this node; decrypt/deliver. */
    NET_ENV_DISPOSITION_FORWARD = 1, /**< Relay via the other transport leg. */
    NET_ENV_DISPOSITION_DROP    = 2, /**< Drop — not ours, not forwardable. */
} net_env_disposition_t;

/**
 * @brief Pure protocol helper: decide what to do with an envelope.
 *
 * PEER: local iff @p env->dst_uuid == @p my_uuid; forward iff
 * @p am_gateway && hop_count < @ref NET_ENV_MAX_HOPS; otherwise drop.
 *
 * BROADCAST: always LOCAL. A gateway may ADDITIONALLY relay a broadcast
 * to its other legs — that decision is exposed by
 * @ref net_envelope_should_forward_broadcast, which the caller combines
 * with a node-local dedup table (to prevent loops) and a rate-limit
 * counter (to bound amplification).
 *
 * GROUP: local iff @p my_group_uuid is non-NIL AND equals @p env->dst_uuid;
 * otherwise drop. Cross-group forwarding requires group-routing state not
 * available at this layer.
 *
 * No peer-registry lookup is performed; the caller does that only on the
 * FORWARD path using @p env->dst_uuid.
 *
 * @param env              Unpacked envelope header.
 * @param my_uuid          This node's identity UUID.
 * @param my_group_uuid    This node's group UUID, or NIL if not joined.
 *                         May be NULL (treated as NIL).
 * @param am_gateway       True iff this node is operating as a gateway.
 */
/*@
  requires env == \null || \valid_read(env);
  requires env == \null || \valid_read(env->dst_uuid + (0 .. 15));
  requires \valid_read(my_uuid + (0 .. 15));
  requires my_group_uuid == \null || \valid_read(my_group_uuid + (0 .. 15));
  assigns \nothing;
  ensures \result == NET_ENV_DISPOSITION_LOCAL ||
          \result == NET_ENV_DISPOSITION_FORWARD ||
          \result == NET_ENV_DISPOSITION_DROP;
*/
net_env_disposition_t net_envelope_disposition(const net_envelope_t *env,
                                               const uuid_t my_uuid,
                                               const uuid_t my_group_uuid,
                                               bool am_gateway);

/**
 * @brief Pure predicate: may a gateway relay this BROADCAST envelope to
 *        its other legs?
 *
 * Returns true iff @p env is a BROADCAST, @p am_gateway is true, and
 * hop_count is strictly below @ref NET_ENV_MAX_HOPS. The caller is still
 * responsible for (a) avoiding re-forwarding the same fingerprint within a
 * node-local dedup window and (b) enforcing any rate limit it wishes to
 * apply — this function only captures the protocol-level gate.
 *
 * For PEER / GROUP / UNKNOWN envelopes the function always returns false;
 * forwarding for those types is handled via
 * @ref net_envelope_disposition.
 */
/*@
  requires env == \null || \valid_read(env);
  assigns \nothing;
*/
bool net_envelope_should_forward_broadcast(const net_envelope_t *env,
                                           bool am_gateway);

/**
 * @brief Compute a stable 64-bit fingerprint for broadcast-relay dedup.
 *
 * The fingerprint is an FNV-1a-64 hash over the envelope's src_uuid
 * concatenated with the inner payload bytes. hop_count and flags are
 * intentionally excluded so the same logical broadcast hashes identically
 * before and after a gateway rewrites the header. dst_uuid is NIL for
 * broadcasts and contributes nothing, so it is omitted.
 *
 * @param env          Unpacked envelope header (must be non-NULL).
 * @param payload      Payload bytes that followed the header on the wire;
 *                     may be NULL iff @p payload_len == 0.
 * @param payload_len  Length of @p payload in bytes.
 * @return The 64-bit fingerprint, or 0 if @p env is NULL (callers should
 *         treat 0 as "do not dedup" — a real fingerprint of empty input
 *         is the FNV offset basis, which is non-zero).
 */
/*@
  requires env == \null || \valid_read(env);
  requires env == \null || \valid_read(env->src_uuid + (0 .. 15));
  requires payload_len == 0 || \valid_read(payload + (0 .. payload_len - 1));
  assigns \nothing;
  ensures env == \null ==> \result == 0;
*/
uint64_t net_envelope_broadcast_fingerprint(const net_envelope_t *env,
                                            const uint8_t *payload,
                                            size_t payload_len);

/**
 * @brief Pure predicate: may a gateway relay this GROUP envelope to a
 *        configured forwarding leg?
 *
 * Returns true iff @p env is a GROUP type, @p am_gateway is true, the
 * destination UUID is non-NIL (i.e., a real group), and hop_count is
 * strictly below @ref NET_ENV_MAX_HOPS. The caller is responsible for
 * consulting the group-routing table (see hybrid_group_route_lookup) to
 * decide WHICH leg receives the forward, and for dedup bookkeeping.
 *
 * For PEER / BROADCAST / UNKNOWN envelopes the function always returns
 * false; forwarding for those types is handled elsewhere
 * (net_envelope_disposition for PEER, net_envelope_should_forward_broadcast
 * for BROADCAST).
 */
/*@
  requires env == \null || \valid_read(env);
  requires env == \null || \valid_read(env->dst_uuid + (0 .. 15));
  assigns \nothing;
*/
bool net_envelope_should_forward_group(const net_envelope_t *env,
                                       bool am_gateway);

/**
 * @brief Compute a stable 64-bit fingerprint for group-relay dedup.
 *
 * FNV-1a-64 over src_uuid || dst_uuid || payload. Unlike the broadcast
 * fingerprint, dst_uuid participates because group envelopes are
 * destination-discriminated: two GROUP frames that share source and
 * payload but target different groups must NOT dedup together. hop_count
 * and flags are intentionally excluded so the same logical frame hashes
 * identically before and after a gateway rewrites the header.
 *
 * @param env          Unpacked envelope header (must be non-NULL).
 * @param payload      Payload bytes that followed the header on the wire;
 *                     may be NULL iff @p payload_len == 0.
 * @param payload_len  Length of @p payload in bytes.
 * @return The 64-bit fingerprint, or 0 if @p env is NULL (callers should
 *         treat 0 as "do not dedup" — a real fingerprint of empty input
 *         is the FNV offset basis, which is non-zero).
 */
/*@
  requires env == \null || \valid_read(env);
  requires env == \null || \valid_read(env->src_uuid + (0 .. 15));
  requires env == \null || \valid_read(env->dst_uuid + (0 .. 15));
  requires payload_len == 0 || \valid_read(payload + (0 .. payload_len - 1));
  assigns \nothing;
  ensures env == \null ==> \result == 0;
*/
uint64_t net_envelope_group_fingerprint(const net_envelope_t *env,
                                        const uint8_t *payload,
                                        size_t payload_len);

#endif /* NET_ENVELOPE_H */
