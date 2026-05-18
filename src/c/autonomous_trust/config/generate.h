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

#include <stdbool.h>

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
 * The active transport's @c net_proto (looked up via the @c AT_TRANSPORT
 * env var, default `udp_net_4`) picks the address family — IPv4, IPv6,
 * or MAC. Mirrors Python `generate.generate_identity` (generate.py:57).
 *
 * @param[in] fullname  Human-readable name to embed in the identity.
 * @param[in] cfg_dir   Directory where @c identity.json should be written.
 * @param[in] preserve  When true, skip writes if the target file already
 *                      exists (parity with Python `preserve=True`).
 * @param[in] defaults  Currently a no-op on the C side (kept for signature
 *                      parity with Python; the C generator already runs
 *                      non-interactively).
 * @return 0 on success, non-zero on keygen or I/O failure.
 */
int generate_identity(const char *fullname, const char *cfg_dir,
                      bool preserve, bool defaults);

/**
 * @brief Run discover_network() and write the result to @c cfg_dir/network.json.
 *
 * @param[in] cfg_dir   Config directory to write into.
 * @param[in] preserve  When true, leave an existing @c network.cfg.json
 *                      file alone.
 * @return 0 on success, non-zero on failure.
 */
int generate_network_config(const char *cfg_dir, bool preserve);

/**
 * @brief Write default subsystem configurations to @c cfg_dir.
 *
 * Populates each registered @ref config_t section with its defaults so the
 * daemon can start on first boot. The `network` subsystem's implementation
 * name is taken from the @c AT_TRANSPORT env var (default `udp_net_4`).
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
 * Identity-name selection (in priority order):
 *   1. @c AT_PEER_NAME env var, if set;
 *   2. seed-indexed @c _names[] entry if @p seed_str is non-NULL OR
 *      @c AT_PEER_SEED env var is set (mirrors Python `_names[idx]`);
 *   3. UUID-derived `agent-XXXXXXXX` fallback.
 *
 * @param[in] cfg_dir   Config directory to write into.
 * @param[in] seed_str  Optional seed string. Integer-parseable strings are
 *                      used directly; otherwise the per-char-ord sum is
 *                      hashed in (same as Python). NULL falls back to
 *                      @c AT_PEER_SEED, then to the UUID branch.
 * @return 0 on success, non-zero on failure.
 */
int random_config(const char *cfg_dir, const char *seed_str);

/**
 * @brief Generic worker-config bootstrap — writes a zero-initialized
 *        default for the registered config @p proc_name.
 *
 * Counterpart to Python `generate_worker_config(cfg_dir, proc_name,
 * cfg_class, defaults=True)` (generate.py:194). Python's reflective
 * auto-prompt path (using `inspect.getfullargspec`) is *not* ported —
 * C lacks runtime signature introspection. The C variant covers only
 * the `defaults=True` slice: it allocates a buffer of @c data_len from
 * the registered @ref config_t, writes it via @ref write_config_file
 * with the mode-aware extension, and exits.
 *
 * Production code already uses dedicated `generate_identity` /
 * `generate_network_config` / `generate_subsystems_config` for the
 * three configs that need non-zero defaults. Use this helper for
 * additional zero-init configs (zta_policy, timeouts, etc.) that
 * just need a placeholder file on first boot.
 *
 * @param[in] cfg_dir    Config directory to write into.
 * @param[in] proc_name  Registered config section name (matches the
 *                       string in @ref DECLARE_CONFIGURATION).
 * @return 0 on success or "already exists"; non-zero if @p proc_name is
 *         not registered or the write fails.
 */
int generate_worker_config(const char *cfg_dir, const char *proc_name);


/** @} */ /* end of internal_config */

#endif  /* GENERATE_H */
