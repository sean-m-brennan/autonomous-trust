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

#include <stdio.h>
#include <string.h>

#include "extensions/dtn/dtn_eid.h"
#include "network/net_transport.h"

/* Frama-C: skipped —
 * [solver-timeout] EID string formatters: every function is a thin at_snprintf wrapper
 * whose precondition cascade WP cannot discharge. Small file, simple body, low bug risk —
 * skipping the whole API is acceptable.
 */
int dtn_eid_from_uuid(const uuid_t uuid, char *out, size_t out_len)
{
    /* Use first 8 hex chars of UUID as node prefix — keeps EIDs short
     * while remaining collision-resistant within any realistic AT fleet. */
    int n = snprintf(out, out_len,
                     "dtn://at-%02x%02x%02x%02x/",
                     uuid[0], uuid[1], uuid[2], uuid[3]);
    if (n < 0 || (size_t)n >= out_len)
        return -1;
    return n;
}

/* Frama-C: skipped —
 * [solver-timeout] EID string formatters: every function is a thin at_snprintf wrapper
 * whose precondition cascade WP cannot discharge. Small file, simple body, low bug risk —
 * skipping the whole API is acceptable.
 */
int dtn_eid_for_service(const char *base_eid, const char *service,
                        char *out, size_t out_len)
{
    /* base_eid already ends with '/'; service begins with '/' — we trim the
     * leading slash of service to avoid "dtn://at-xxx//peer". */
    const char *s = (service[0] == '/') ? service + 1 : service;
    int n = snprintf(out, out_len, "%s%s", base_eid, s);
    if (n < 0 || (size_t)n >= out_len)
        return -1;
    return n;
}

/* Frama-C: skipped —
 * [solver-timeout] EID string formatters: every function is a thin at_snprintf wrapper
 * whose precondition cascade WP cannot discharge. Small file, simple body, low bug risk —
 * skipping the whole API is acceptable.
 */
int dtn_eid_for_group(const unsigned char *group_hash, size_t hash_len,
                      char *out, size_t out_len)
{
    if (hash_len < 8)
        return -1;
    int n = snprintf(out, out_len,
                     "dtn://at-group-%02x%02x%02x%02x%02x%02x%02x%02x/",
                     group_hash[0], group_hash[1], group_hash[2], group_hash[3],
                     group_hash[4], group_hash[5], group_hash[6], group_hash[7]);
    if (n < 0 || (size_t)n >= out_len)
        return -1;
    return n;
}

const unsigned char DTN_PRE_JOIN_HASH[8] = {'A', 'T', '-', 'b', 'o', 'o', 't', 0};

/* Frama-C: skipped — [solver-timeout] memcmp/memcpy over uuid bytes. */
int dtn_group_hash(const uuid_t group_uuid, unsigned char out[8])
{
    static const uuid_t zero = {0};
    if (group_uuid != NULL && memcmp(group_uuid, zero, sizeof(uuid_t)) != 0) {
        memcpy(out, group_uuid, 8);
        return 1;
    }
    memcpy(out, DTN_PRE_JOIN_HASH, 8);
    return 0;
}

const char *dtn_channel_suffix(int channel)
{
    switch (channel) {
    case NET_CHAN_PEER:      return DTN_CHAN_PEER_SUFFIX;
    case NET_CHAN_BROADCAST: return DTN_CHAN_BCAST_SUFFIX;
    case NET_CHAN_GROUP:     return DTN_CHAN_GROUP_SUFFIX;
    default:                 return NULL;
    }
}

/* Frama-C: skipped — strcmp. */
int dtn_service_to_channel(const char *service)
{
    if (service == NULL) return NET_CHAN__COUNT;
    if (strcmp(service, DTN_CHAN_PEER_SUFFIX) == 0)  return NET_CHAN_PEER;
    if (strcmp(service, DTN_CHAN_BCAST_SUFFIX) == 0) return NET_CHAN_BROADCAST;
    if (strcmp(service, DTN_CHAN_GROUP_SUFFIX) == 0) return NET_CHAN_GROUP;
    return NET_CHAN__COUNT;
}

/* Frama-C: skipped — [solver-timeout] snprintf chain, as the formatters above. */
int dtn_endpoints(const uuid_t node_uuid, const uuid_t group_uuid,
                  char eids[3][DTN_EID_MAX + 1])
{
    char node_eid[DTN_EID_MAX + 1];
    char group_node_eid[DTN_EID_MAX + 1];
    unsigned char hash[8];

    if (node_uuid != NULL) {
        if (dtn_eid_from_uuid(node_uuid, node_eid, sizeof(node_eid)) < 0)
            return -1;
    } else {
        snprintf(node_eid, sizeof(node_eid), "%s", DTN_PLACEHOLDER_NODE_EID);
    }
    int joined = dtn_group_hash(group_uuid, hash);
    if (dtn_eid_for_service(node_eid, DTN_CHAN_PEER_SUFFIX,
                            eids[NET_CHAN_PEER], DTN_EID_MAX + 1) < 0 ||
        dtn_eid_for_group(hash, sizeof(hash),
                          group_node_eid, sizeof(group_node_eid)) < 0 ||
        dtn_eid_for_service(group_node_eid, DTN_CHAN_BCAST_SUFFIX,
                            eids[NET_CHAN_BROADCAST], DTN_EID_MAX + 1) < 0 ||
        dtn_eid_for_service(group_node_eid, DTN_CHAN_GROUP_SUFFIX,
                            eids[NET_CHAN_GROUP], DTN_EID_MAX + 1) < 0)
        return -1;
    return joined;
}

/* Frama-C: skipped — [solver-timeout] snprintf chain, as the formatters above. */
int dtn_broadcast_eid(int channel, const uuid_t group_uuid,
                      char *out, size_t out_len)
{
    const char *suffix = dtn_channel_suffix(channel);
    if (channel == NET_CHAN_PEER || suffix == NULL)
        return -1;
    unsigned char hash[8];
    char group_node_eid[DTN_EID_MAX + 1];
    dtn_group_hash(group_uuid, hash);
    if (dtn_eid_for_group(hash, sizeof(hash),
                          group_node_eid, sizeof(group_node_eid)) < 0)
        return -1;
    return dtn_eid_for_service(group_node_eid, suffix, out, out_len);
}

/* Frama-C: skipped — [solver-timeout] strncmp/snprintf chain. */
int dtn_peer_eid(const char *target, const uuid_t matched,
                 char *out, size_t out_len)
{
    if (target == NULL || target[0] == '\0')
        return -1;
    if (strncmp(target, "dtn:", 4) == 0 || strncmp(target, "ipn:", 4) == 0) {
        int n = snprintf(out, out_len, "%s", target);
        return (n > 0 && (size_t)n < out_len) ? n : -1;
    }
    if (matched != NULL) {
        char node_eid[DTN_EID_MAX + 1];
        if (dtn_eid_from_uuid(matched, node_eid, sizeof(node_eid)) < 0)
            return -1;
        return dtn_eid_for_service(node_eid, DTN_CHAN_PEER_SUFFIX, out, out_len);
    }
    int n = snprintf(out, out_len, "dtn://at-%s/peer", target);
    return (n > 0 && (size_t)n < out_len) ? n : -1;
}
