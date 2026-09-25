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

#ifndef DTN_EID_H
#define DTN_EID_H

/**
 * @file dtn_eid.h
 * @brief Endpoint Identifier helpers for the AT DTN transport.
 *
 * Scheme (per at-over-dtn.md §2.1):
 *   dtn://at-<uuid-prefix>/          -- node EID
 *   dtn://at-<uuid-prefix>/<service> -- service EID (identity, reputation, ...)
 *   dtn://at-group-<hash>/~bcast     -- group broadcast EID
 *
 * AT channel → EID service mapping:
 *   NET_CHAN_PEER      -> .../peer
 *   NET_CHAN_BROADCAST -> .../bcast (on group-bcast node)
 *   NET_CHAN_GROUP     -> .../group (on group-bcast node, BPSec-protected)
 */

#include <stddef.h>
#include <uuid/uuid.h>

#define DTN_EID_MAX 127  /**< Fits any AT-generated EID comfortably. */

#define DTN_CHAN_PEER_SUFFIX   "/peer"
#define DTN_CHAN_BCAST_SUFFIX  "/bcast"
#define DTN_CHAN_GROUP_SUFFIX  "/group"

/**
 * @brief Build a node EID from a UUID.
 * @param uuid   Node UUID.
 * @param out    Buffer of at least DTN_EID_MAX+1 bytes.
 * @return length written on success, -1 on truncation.
 */
int dtn_eid_from_uuid(const uuid_t uuid, char *out, size_t out_len);

/**
 * @brief Append a service suffix to a node EID to form a service EID.
 * @param base_eid  Node EID (e.g., "dtn://at-abcd/").
 * @param service   Service suffix including leading '/' (e.g., "/peer").
 * @param out       Buffer of at least DTN_EID_MAX+1 bytes.
 * @return length written on success, -1 on truncation.
 */
int dtn_eid_for_service(const char *base_eid, const char *service,
                        char *out, size_t out_len);

/**
 * @brief Group-broadcast EID for an AT group.
 *
 * Derives a stable EID from the first 8 bytes of @p group_hash.
 * @param group_hash  Group identity hash (e.g., from group.c's shared-key hash).
 * @param hash_len    Length of @p group_hash (>= 8 required).
 * @param out         Buffer of at least DTN_EID_MAX+1 bytes.
 * @return length on success, -1 on truncation or short hash.
 */
int dtn_eid_for_group(const unsigned char *group_hash, size_t hash_len,
                      char *out, size_t out_len);

#endif /* DTN_EID_H */
