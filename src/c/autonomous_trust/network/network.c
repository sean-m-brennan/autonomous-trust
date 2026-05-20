/********************
 *  Copyright 2025 Sean M. Brennan and contributors
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

#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>

#include <jansson.h>

#include "network.h"
#include "utilities/at_jansson.h"
#include "utilities/exception.h"
#include "config/configuration.h"
#include "utilities/util.h"

/* Design note — protobuf wire path for inter-host network messages.
 *
 * Inter-host network messages currently ride the JSON wire format in
 * `network/net_message.c::net_message_to_wire`. A protobuf wire path is
 * structurally enabled by `at_serialize_mode_current()` + per-mode
 * dispatch already in `config/configuration.c`; applying the same shape
 * here is straightforward in C but requires four coordinated pieces:
 *
 *   1. A `network/net_message.proto` schema for `net_wire_msg_t`
 *      (process, function, data bytes, encrypt, trace_id, from_whom,
 *      to_whom, signature). Codegen lands in `src/c/build/...` via the
 *      existing CMake protobuf-c plumbing.
 *   2. `net_message_to_wire_proto` / `net_message_from_wire_proto`
 *      siblings of the JSON path. Signature canonicalization (the
 *      "<process>|<function>|<base64(data)>" pre-image in
 *      net_message.c:98-119) MUST stay byte-identical to Python; the
 *      proto path signs the same canonical string, only the envelope
 *      changes.
 *   3. Dispatch by `at_serialize_mode_current()` at the top of
 *      `net_message_to_wire` (read side branches on a one-byte magic
 *      prefix to support mixed-mode peers during migration).
 *   4. The Python side adds the matching `to_wire_proto` /
 *      `from_wire_proto` paths in `core/_python/network/net_message.py`
 *      and the conformance corpus gains a `--wire-mode=proto` variant.
 *
 * Until items 1 and 4 ship together, JSON remains the only safe wire
 * format — a one-sided switch would silently break interop. */


/* Frama-C: skipped — [inet] inet_pton with network byte order */
int cidr_split(char * cidr, char *addr, char *mask)
{
    if (addr == NULL)
        return EXCEPTION(EINVAL);
    char *saveptr = NULL;
    char *cidr_dup = strdup(cidr);
    if (cidr_dup == NULL)
        return EXCEPTION(ENOMEM);
    char *a = strtok_r(cidr_dup, "/", &saveptr);
    if (a == NULL)
        return EXCEPTION(EINVAL);  // empty string
    /* Callers pass addr[IPV4_ADDR_LEN] (16 bytes) and mask[3]; use snprintf
     * to guarantee NUL termination and deterministic truncation. */
    snprintf(addr, IPV4_ADDR_LEN, "%s", a);
    if (mask != NULL) {
        char *m = strtok_r(NULL, "/", &saveptr);
        if (m != NULL)
            snprintf(mask, 3, "%s", m);
        // missing slash is acceptable
    }
    free(cidr_dup);
    return 0;
}

/* Frama-C: skipped — [inet] inet_pton IPv4 conversion */
int cidr4_to_ip4_binary(char *cidr, uint32_t *ip, uint8_t *mask)
{
    char addr[IPV4_ADDR_LEN] = {0};
    char mask_str[3] = {0};
    if (cidr_split(cidr, addr, mask_str) < 0)
        return -1;
    struct in_addr addr_struct = {0};
    if (inet_pton(AF_INET, addr, &addr_struct) < 0)
        return SYS_EXCEPTION();
    *ip = addr_struct.s_addr;
    *mask = atoi(mask_str);
    if (*mask > 32)
        return EXCEPTION(ENET_INVALID_MASK);
    return 0;
}

/* Frama-C: skipped — [inet] inet_ntop IPv4 conversion */
int ip4_binary_to_addr(uint32_t ip, char *addr)
{
    struct in_addr addr_struct = {0};
    addr_struct.s_addr = ip;
    if (inet_ntop(AF_INET, &addr_struct, addr, INET_ADDRSTRLEN) == NULL)
        return SYS_EXCEPTION();
    return 0;
}

/* Frama-C: skipped — [inet] bitwise CIDR mask calculation */
int cidr4_to_broadcast(char *cidr, char *bcast_addr)
{
    uint32_t ip = 0;
    uint8_t prefix = 0;
    if (cidr4_to_ip4_binary(cidr, &ip, &prefix) < 0)
        return -1;
    /* Convert CIDR prefix length to network-byte-order bitmask */
    uint32_t host_mask = (prefix == 0) ? 0 : ~((1U << (32 - prefix)) - 1);
    uint32_t net_mask = htonl(host_mask);
    uint32_t bcast = (ip & net_mask) | ~net_mask;
    return ip4_binary_to_addr(bcast, bcast_addr);
}

/* Frama-C: skipped — [inet] inet_pton IPv6 conversion */
int cidr6_to_ip6_binary(char *cidr, uint128_t *ip, uint8_t *mask)
{
    char addr[IPV6_ADDR_LEN] = {0};
    char mask_str[4] = {0};
    if (cidr_split(cidr, addr, mask_str) < 0)
        return -1;
    struct in6_addr addr_struct = {0};
    if (inet_pton(AF_INET6, addr, &addr_struct) < 0)
        return SYS_EXCEPTION();
    memcpy(ip, &addr_struct.s6_addr, sizeof(uint128_t));  // keep in host order (internal only)
    *mask = atoi(mask_str);
    if (*mask > 128)
        return EXCEPTION(ENET_INVALID_MASK);
    return 0;
}

/* Frama-C: skipped — [inet] inet_ntop IPv6 conversion */
int ip6_binary_to_addr(uint128_t ip, char *addr)
{
    struct in6_addr addr_struct;
    memcpy(&addr_struct.s6_addr, &ip, sizeof(uint128_t));
    if (inet_ntop(AF_INET6, &addr_struct, addr, INET6_ADDRSTRLEN) == NULL)
        return SYS_EXCEPTION();
    return 0;
}

/* Frama-C: skipped — [serialization] jansson JSON serialization */
int network_to_json(const void *data_struct, json_t **obj_ptr)
{
    const network_config_t *net = data_struct;
    *obj_ptr = json_object();
    json_t *obj = *obj_ptr;
    if (obj == NULL)
        return EXCEPTION(ENOMEM);

    int err = json_object_set_new(obj, "typename", json_string("network"));
    if (err != 0)
        return EXCEPTION(EJSN_OBJ_SET);
        
    json_object_set_new(obj, "port", json_integer(net->port));
    json_object_set_new(obj, "ip4_cidr", json_string((char *)net->ip4_cidr));
    json_object_set_new(obj, "ip6_cidr", json_string((char *)net->ip6_cidr));
    json_object_set_new(obj, "mcast4_addr", json_string((char *)net->mcast4_addr));
    json_object_set_new(obj, "mcast6_addr", json_string((char *)net->mcast6_addr));
    json_object_set_new(obj, "mac_addr", json_string((char *)net->mac_address));
    return 0;
}

/* Frama-C: skipped — [serialization] jansson JSON deserialization */
int network_from_json(const json_t *obj, void *data_struct)
{
    network_config_t *net = data_struct;
    net->port = json_integer_value(json_object_get(obj, "port"));
    AT_JSON_STRING(obj, "ip4_cidr",    net->ip4_cidr);
    AT_JSON_STRING(obj, "ip6_cidr",    net->ip6_cidr);
    AT_JSON_STRING(obj, "mcast4_addr", net->mcast4_addr);
    AT_JSON_STRING(obj, "mcast6_addr", net->mcast6_addr);
    AT_JSON_STRING(obj, "mac_addr",    net->mac_address);
    return 0;
}

DECLARE_CONFIGURATION(network, sizeof(network_config_t), network_to_json, network_from_json);
