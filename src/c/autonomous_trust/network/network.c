/********************
 *  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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
int cidr_split(char *cidr, char *addr, size_t addr_len,
               char *mask, size_t mask_len)
{
    if (addr == NULL || addr_len == 0)
        return EXCEPTION(EINVAL);
    char *saveptr = NULL;
    char *cidr_dup = strdup(cidr);
    if (cidr_dup == NULL)
        return EXCEPTION(ENOMEM);
    char *a = strtok_r(cidr_dup, "/", &saveptr);
    if (a == NULL) {
        free(cidr_dup);  /* the early return used to leak this */
        return EXCEPTION(EINVAL);  // empty string
    }
    /* snprintf for guaranteed NUL termination, but its return value is the
     * length it WANTED, so it also detects truncation. The lengths come from the
     * caller: a hard-coded IPV4_ADDR_LEN silently mangled every IPv6 address,
     * and widening it would have overflowed the 16-byte IPv4 callers. */
    int need = snprintf(addr, addr_len, "%s", a);
    if (need < 0 || (size_t)need >= addr_len) {
        /* Clear rather than leave the partial write: callers that ignore the
         * return code (net_proc.c's my_address is void) must not go on to use a
         * truncated address as if it were theirs -- that is a self-filter that
         * silently stops matching. An empty string fails loudly at the next use. */
        addr[0] = '\0';
        free(cidr_dup);
        return EXCEPTION(ENET_ADDR_TOO_LONG);
    }
    if (mask != NULL) {
        char *m = strtok_r(NULL, "/", &saveptr);
        if (m != NULL) {
            if (mask_len == 0) {
                free(cidr_dup);
                return EXCEPTION(EINVAL);
            }
            /* An IPv6 prefix is up to 3 digits, so a 3-byte buffer truncated
             * "128" to "12" -- and 12 passes the family sanity check downstream,
             * which is what made this silent rather than loud. */
            need = snprintf(mask, mask_len, "%s", m);
            if (need < 0 || (size_t)need >= mask_len) {
                mask[0] = '\0';
                addr[0] = '\0';  /* neither half is usable on its own */
                free(cidr_dup);
                return EXCEPTION(ENET_ADDR_TOO_LONG);
            }
        }
        // missing slash is acceptable
    }
    free(cidr_dup);
    return 0;
}

/* Frama-C: skipped — [inet] inet_pton IPv4 conversion */
int cidr4_to_ip4_binary(char *cidr, uint32_t *ip, uint8_t *mask)
{
    char addr[IPV4_ADDR_LEN] = {0};
    /* 4 bytes, not 3: a 3-digit prefix must be REPRESENTABLE so that an
     * out-of-range one ("10.0.0.1/128") reports ENET_INVALID_MASK below rather
     * than being truncated to a plausible-looking "12". */
    char mask_str[4] = {0};
    if (cidr_split(cidr, addr, sizeof(addr), mask_str, sizeof(mask_str)) < 0)
        return -1;
    struct in_addr addr_struct = {0};
    /* inet_pton returns 1 on success, 0 on a MALFORMED address, -1 only on a bad
     * family. The old `< 0` therefore accepted garbage silently, which is what
     * hid the truncation above. */
    if (inet_pton(AF_INET, addr, &addr_struct) != 1)
        return EXCEPTION(EINVAL);
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
    if (cidr_split(cidr, addr, sizeof(addr), mask_str, sizeof(mask_str)) < 0)
        return -1;
    struct in6_addr addr_struct = {0};
    /* See the note in cidr4_to_ip4_binary: 0 means malformed, and `< 0` never
     * caught it. */
    if (inet_pton(AF_INET6, addr, &addr_struct) != 1)
        return EXCEPTION(EINVAL);
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
        
    /* Omit an unset port rather than recording a literal 0. The config layer
     * always wins in net_port_resolve(), so a `"port": 0` would read back as
     * "no choice made" anyway — and a config file should state only what was
     * actually chosen, leaving AT_COMM_PORT and the compile-time default free
     * to apply. network_from_json() reads a missing key as 0 already
     * (json_integer_value(NULL) == 0), so the round trip is unchanged. */
    if (net->port != 0)
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
