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
 * @file connection.h
 * @brief agora connection edge-state model and the Ed25519 signing/verification
 *        of a connection RESPONSE (AT "with-distance" Increment 5).
 *
 * A "connection" is an EXPLICIT, revocable, bilateral edge between two nodes,
 * kept SEPARATE from reputation (reputation is earned; a connection is chosen).
 * The edge has five states from each node's local viewpoint:
 *
 *   none=0  no edge; pending_out=1  we asked; pending_in=2  they asked us;
 *   connected=3  mutually connected; declined=4  the ask was declined.
 *
 * The flow is user-initiated: an app CONNECT verb sets our edge pending_out and
 * sends a directed encrypted `peer_connection_request`; the peer's app RESPONDs,
 * which sends a directed encrypted, SIGNED `peer_connection_response`. Only the
 * response is signed — it is the leg that changes the requester's state to a
 * durable connected/declined, so it carries a detached Ed25519 signature the
 * requester verifies against the accepter's signing key before acting.
 *
 * SIGNING (the cross-language crux): the response signature covers a CANONICAL,
 * framing-only serialization BOTH runtimes produce identically (no JSON, whose
 * whitespace/key-order diverge):
 *
 *   canonical = requester_uuid[16] || accepter_uuid[16]
 *             || u8(decision) || u64le(seq)
 *   where decision = 1 (accept) or 0 (decline).
 *
 * Both uuids are in the canonical form so a signed response is bound to the
 * specific ordered pair and cannot be re-attributed on relay; `seq` binds it to
 * the accepter's freshness sequence so a captured response cannot be replayed.
 * MUST stay in lockstep with Python connection_canonical() in capabilities.py.
 */

#ifndef AUTONOMOUS_TRUST_IDENTITY_CONNECTION_H
#define AUTONOMOUS_TRUST_IDENTITY_CONNECTION_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <uuid/uuid.h>
#include <sodium.h>

/* Edge states, from THIS node's local viewpoint. Frozen small integers: they
 * cross the app boundary as at_app_connection_t.state and are asserted by the
 * conformance `connection_state` key, so their values are stable. */
typedef enum
{
    AT_CONN_NONE        = 0,
    AT_CONN_PENDING_OUT = 1,   /* we asked them */
    AT_CONN_PENDING_IN  = 2,   /* they asked us */
    AT_CONN_CONNECTED   = 3,
    AT_CONN_DECLINED    = 4
} at_conn_state_t;

/* Detached Ed25519 signature as lowercase hex (crypto_sign_BYTES * 2 + NUL). */
#define AT_CONNECTION_SIG_HEX_LEN (crypto_sign_BYTES * 2)

/* Fixed size of the canonical signing buffer: 16 + 16 + 1 + 8. */
#define AT_CONNECTION_CANON_LEN (16 + 16 + 1 + 8)

/* Write the canonical signing bytes for a connection response into @p out.
 * Returns the number of bytes written (AT_CONNECTION_CANON_LEN), or (size_t)-1
 * if it would exceed @p outcap. THE cross-language contract — see the header. */
size_t at_connection_canonical(const uuid_t requester_uuid,
                               const uuid_t accepter_uuid,
                               uint8_t decision, uint64_t seq,
                               uint8_t *out, size_t outcap);

/* Sign the canonical (requester, accepter, decision, seq) with the accepter's
 * Ed25519 secret key @p sk; write the detached signature as lowercase hex
 * (AT_CONNECTION_SIG_HEX_LEN + NUL) into @p sig_hex_out. Returns 0 on success. */
int at_connection_sign(const unsigned char sk[crypto_sign_SECRETKEYBYTES],
                       const uuid_t requester_uuid, const uuid_t accepter_uuid,
                       uint8_t decision, uint64_t seq, char *sig_hex_out);

/* Verify @p sig_hex (lowercase hex detached signature) over the canonical bytes
 * of (requester, accepter, decision, seq) against the accepter's Ed25519 public
 * key @p pk. Returns true iff the signature is valid. */
bool at_connection_verify(const unsigned char pk[crypto_sign_PUBLICKEYBYTES],
                          const uuid_t requester_uuid, const uuid_t accepter_uuid,
                          uint8_t decision, uint64_t seq, const char *sig_hex);

#endif /* AUTONOMOUS_TRUST_IDENTITY_CONNECTION_H */
