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

/** @addtogroup internal_config
 *  @{
 */

#include "network/network.h"
#include "identity/identity.h"
#include "utilities/exception.h"

#ifndef IF_NAMESIZE
#define IF_NAMESIZE 16
#endif

/****************************
 * Network interface info
 ****************************/

/**
 * @brief Snapshot of a network interface's IPv4/IPv6 addresses and MAC.
 */
typedef struct {
    char ip4_addr[IPV4_ADDR_LEN + 1];  /**< Dotted-decimal IPv4 address (may be empty). */
    char ip4_cidr[CIDR4_LEN + 1];      /**< IPv4 address with `/prefix` suffix. */
    char ip6_addr[IPV6_ADDR_LEN + 1];  /**< Colon-hex IPv6 address (may be empty). */
    char ip6_cidr[CIDR6_LEN + 1];      /**< IPv6 address with `/prefix` suffix. */
    char mac_addr[MAC_ADDR_LEN + 1];   /**< MAC address as `xx:xx:xx:xx:xx:xx`. */
    char if_name[IF_NAMESIZE];         /**< Kernel interface name (e.g. `eth0`). */
} net_iface_t;

/****************************
 * Error codes
 ****************************/

/** @brief Error: no suitable network interface was found. */
#define EGEN_NOIF 220
DECLARE_ERROR(EGEN_NOIF, "No suitable network interface found");

/****************************
 * API
 ****************************/

/**
 * @brief Probe the system for a suitable network interface and populate @p iface.
 *
 * Skips loopback and down interfaces; prefers interfaces with a routable
 * IPv4 address.
 *
 * @param[out] iface  Receives the selected interface's addressing info.
 * @return 0 on success, @ref EGEN_NOIF if no candidate exists.
 */
int discover_network(net_iface_t *iface);

/**
 * @brief Create a fresh identity (keypairs + UUID) and write it to disk.
 *
 * @param[in] fullname  Human-readable name to embed in the identity.
 * @param[in] cfg_dir   Directory where @c identity.json should be written.
 * @return 0 on success, non-zero on keygen or I/O failure.
 */
int generate_identity(const char *fullname, const char *cfg_dir);

/**
 * @brief Run discover_network() and write the result to @c cfg_dir/network.json.
 *
 * @param[in] cfg_dir  Config directory to write into.
 * @return 0 on success, non-zero on failure.
 */
int generate_network_config(const char *cfg_dir);

/**
 * @brief Write default subsystem configurations to @c cfg_dir.
 *
 * Populates each registered @ref config_t section with its defaults so the
 * daemon can start on first boot.
 *
 * @param[in] cfg_dir  Config directory to write into.
 * @return 0 on success, non-zero on failure.
 */
int generate_subsystems_config(const char *cfg_dir);

/**
 * @brief Generate a complete random configuration (identity + network +
 *        subsystems) under @p cfg_dir.
 *
 * Intended for test/demo bring-up where no pre-existing config exists.
 *
 * @param[in] cfg_dir  Config directory to write into.
 * @return 0 on success, non-zero on failure.
 */
int random_config(const char *cfg_dir);


/** @} */ /* end of internal_config */

#endif  /* GENERATE_H */
