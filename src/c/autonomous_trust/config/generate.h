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

#ifndef GENERATE_H
#define GENERATE_H

#include "network/network.h"
#include "identity/identity.h"
#include "utilities/exception.h"

/****************************
 * Network interface discovery
 ****************************/

typedef struct {
    char ip4_addr[IPV4_ADDR_LEN + 1];
    char ip4_cidr[CIDR4_LEN + 1];
    char ip6_addr[IPV6_ADDR_LEN + 1];
    char ip6_cidr[CIDR6_LEN + 1];
    char mac_addr[MAC_ADDR_LEN + 1];
    char if_name[16];
} net_iface_t;

/**
 * Discover network interfaces via getifaddrs().
 * Skips loopback. Returns first non-loopback interface.
 */
int discover_network(net_iface_t *iface);

/****************************
 * Configuration generators
 ****************************/

/**
 * Generate identity config: create keypair, write to cfg_dir.
 */
int generate_identity(const char *fullname, const char *cfg_dir);

/**
 * Generate network.cfg.json from discovered interface.
 */
int generate_network_config(const char *cfg_dir);

/**
 * Non-interactive wrapper: generate both identity and network config
 * with random name.
 */
int random_config(const char *cfg_dir);

/****************************
 * Error codes
 ****************************/

#define EGEN_NOIF 260
DECLARE_ERROR(EGEN_NOIF, "No suitable network interface found");

#endif  /* GENERATE_H */
