/********************
 *  Copyright 2024 TekFive, Inc. and contributors
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
#include "utilities/exception.h"
#include "config/configuration.h"
#include "utilities/util.h"

// FIXME protobuf between hosts


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
    strncpy(addr, a, IPV4_ADDR_LEN);
    if (mask != NULL) {
        char *m = strtok_r(NULL, "/", &saveptr);
        if (m != NULL)
            strncpy(mask, m, 3);
        // missing slash is acceptable
    }
    free(cidr_dup);
    return 0;
}

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
        return EXCEPTION(EINVAL);  // FIXME custom?
    return 0;
}

int ip4_binary_to_addr(uint32_t ip, char *addr)
{
    struct in_addr addr_struct = {0};
    addr_struct.s_addr = ip;
    if (inet_ntop(AF_INET, &addr_struct, addr, INET_ADDRSTRLEN))
        return SYS_EXCEPTION();
    return 0;
}

int cidr4_to_broadcast(char *cidr, char *bcast_addr)
{
    uint32_t ip;
    uint8_t mask;
    if (cidr4_to_ip4_binary(cidr, &ip, &mask) < 0)
        return -1;
    uint32_t net = ip & mask;
    uint32_t bcast = net | ~mask;
    return ip4_binary_to_addr(bcast, bcast_addr);
}

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
        return EXCEPTION(EINVAL);  // FIXME custom?
    return 0;
}

int ip6_binary_to_addr(uint128_t ip, char *addr)
{
    struct in6_addr addr_struct;
    memcpy(&addr_struct.s6_addr, &ip, sizeof(uint128_t));
    if (inet_ntop(AF_INET6, &addr_struct, addr, INET6_ADDRSTRLEN))
        return SYS_EXCEPTION();
    return 0;
}

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
        
    json_object_set(obj, "port", json_integer(net->port));
    json_object_set(obj, "ip4_cidr", json_string((char *)net->ip4_cidr));
    json_object_set(obj, "ip6_cidr", json_string((char *)net->ip6_cidr));
    json_object_set(obj, "mcast4_addr", json_string((char *)net->mcast4_addr));
    json_object_set(obj, "mcast6_addr", json_string((char *)net->mcast6_addr));
    json_object_set(obj, "mac_addr", json_string((char *)net->mac_address));
    return 0;
}

int network_from_json(const json_t *obj, void *data_struct)
{
    network_config_t *net = data_struct;
    net->port = json_integer_value(json_object_get(obj, "port"));
    strncpy(net->ip4_cidr, (char *)json_string_value(json_object_get(obj, "ip4_cidr")), CIDR4_LEN);
    strncpy(net->ip6_cidr, (char *)json_string_value(json_object_get(obj, "ip6_cidr")), CIDR6_LEN);
    strncpy(net->mcast4_addr, (char *)json_string_value(json_object_get(obj, "mcast4_addr")), IPV4_ADDR_LEN);
    strncpy(net->mcast6_addr, (char *)json_string_value(json_object_get(obj, "mcast6_addr")), IPV6_ADDR_LEN);
    strncpy(net->mac_address, (char *)json_string_value(json_object_get(obj, "mac_addr")), MAC_ADDR_LEN);
    return 0;
}

DECLARE_CONFIGURATION(network, sizeof(network_config_t), network_to_json, network_from_json);
