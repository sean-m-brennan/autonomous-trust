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

#ifndef NET_WIRE_FORMAT_H
#define NET_WIRE_FORMAT_H

/** @addtogroup internal_network
 *  @{
 */

/* Deliberately a LEAF header: no includes, so both `network/net_message.h`
 * (which encodes and decodes the two forms) and `identity/group.h` (which
 * CARRIES the choice) can name the type without either pulling the other in.
 * The alternative -- putting the enum in net_message.h -- would drag the whole
 * wire-message struct into every consumer of a group. */

/**
 * @brief Which encoding an inter-host envelope rides in (doc/architecture/network-wire-format.md).
 *
 * Values match Python's `NetWireFormat` and the `identity.proto`
 * `NetWireFormat` enum, and @ref NET_WIRE_JSON is 0 so that a zeroed struct,
 * an absent proto field and an unprovisioned group all mean the format every
 * AT node can read.
 *
 * NOT chosen per message and NOT negotiated per peer: it is a property of the
 * GROUP (@c group_t::wire_format), because a cohort in which two members
 * disagree cannot talk at all. Traffic outside any group -- discovery,
 * pre-admission -- is @ref NET_WIRE_JSON unconditionally, which is what keeps a
 * proto cohort joinable by any node. Detecting a peer's format is deliberately
 * absent; see doc/architecture/network-wire-format.md for the security questions that keep it so.
 */
typedef enum {
    NET_WIRE_JSON  = 0, /**< The JSON envelope (net_message_to_wire). */
    NET_WIRE_PROTO = 1, /**< Packed `network/net_message.proto`, magic-prefixed. */
} net_wire_format_t;

/**
 * @brief The one byte that prefixes every packed protobuf envelope.
 *
 * A JSON envelope always begins '{' (0x7B), so one byte decides which parser a
 * frame is even eligible for -- and a receiver refuses a frame in a format it
 * does not speak WITHOUT running the other parser over peer-supplied bytes,
 * which is the property that makes carrying two formats acceptable while
 * detection stays unimplemented. Doubles as the envelope version slot: an
 * incompatible future proto envelope takes 0xAC and is distinguishable rather
 * than guessed.
 *
 * Must match Python's `NET_WIRE_PROTO_MAGIC` (config/configuration.py).
 */
#define NET_WIRE_PROTO_MAGIC 0xABu

/**
 * @brief Human-readable name of a wire format ("json" / "proto"), for logs and
 *        for the group JSON wire form. Returns a static string; do not free.
 */
/*@
  assigns \nothing;
  ensures \result != \null;
*/
const char *net_wire_format_name(net_wire_format_t fmt);

/**
 * @brief Parse a wire-format name as the group JSON form writes it.
 *
 * An unrecognized or NULL name resolves to @ref NET_WIRE_JSON rather than
 * failing: a group config is provisioned data, and a typo in this field has a
 * safe reading (the format every node can read). Same discipline as the ZTA
 * policy's binding_mode falling back to `require`.
 */
/*@
  assigns \nothing;
*/
net_wire_format_t net_wire_format_from_name(const char *name);

/** @} */ /* end of internal_network */

#endif  /* NET_WIRE_FORMAT_H */
