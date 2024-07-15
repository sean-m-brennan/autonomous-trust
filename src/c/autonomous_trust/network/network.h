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

#ifndef NETWORK_H
#define NETWORK_H

#include <stdint.h>
#include "utilities/allocation.h"

#define COMM_PORT 27787
#define PING_RCV_PORT (COMM_PORT + 2)
#define PING_SND_PORT (PING_RCV_PORT + 1)
#define NTP_PORT (COMM_PORT + 4)

#define IPV4_ADDR_LEN 16
#define CIDR4_LEN (IPV4_ADDR_LEN + 3)
#define IPV6_ADDR_LEN 46
#define CIDR6_LEN (IPV6_ADDR_LEN + 4)
#define MAC_ADDR_LEN 17

typedef struct
{
    smrt_ptr_t;
    /* data from json */
    int port;
    char mac_address[MAC_ADDR_LEN + 1];
    char ip4_cidr[CIDR4_LEN + 1];
    char mcast4_addr[IPV4_ADDR_LEN + 1];
    char ip6_cidr[CIDR6_LEN + 1];
    char mcast6_addr[IPV6_ADDR_LEN + 1];
} network_config_t;

int cidr_split(char * cidr, char *addr, char *mask);

int cidr4_to_ip4_binary(char *cidr, uint32_t *ip, uint8_t *mask);
int ip4_binary_to_addr(uint32_t ip, char *addr);
int cidr4_to_broadcast(char *cidr, char *bcast_addr);

typedef unsigned __int128 uint128_t;
int cidr6_to_ip6_binary(char *cidr, uint128_t *ip, uint8_t *mask);
int ip6_binary_to_addr(uint128_t ip, char *addr);

int network_to_json(const void *data_struct, json_t **obj_ptr);
int network_from_json(const json_t *obj, void *data_struct);

#endif  // NETWORK_H
