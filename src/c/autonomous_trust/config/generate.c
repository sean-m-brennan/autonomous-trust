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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <jansson.h>
#include <uuid/uuid.h>

#include "config/generate.h"
#include "config/configuration.h"
#include "network/network.h"
#include "network/net_transport.h"
#include "processes/process_tracker.h"
#include "utilities/util.h"

DEFINE_ERROR(EGEN_NOIF, "No suitable network interface found");

/* Seed-indexed identity names (mirrors Python generate.py:34-45). Used
 * when AT_PEER_NAME is unset but a seed is available — gives parity
 * with Python's randomize=True path. */
static const char *const _names[] = {
    "j.h.watson@tekfive.com",
    "a.hastings@tekfive.com",
    "a.goodwin@tekfive.com",
    "j.may@tekfive.com",
    "a.bryant@tekfive.com",
    "t.beresford@tekfive.com",
    "n.charles@tekfive.com",
    "d.selby@tekfive.com",
    "m.archer@tekfive.com",
    "r.lewis@tekfive.com",
};
static const size_t _names_count = sizeof(_names) / sizeof(_names[0]);

/* Resolve the active transport name. Mirrors Python's `communications`
 * env override (system.py:49). Falls back to the long-standing default. */
static const char *default_transport_name(void)
{
    const char *t = getenv("AT_TRANSPORT");
    if (t != NULL && t[0] != '\0')
        return t;
    return "udp_net_4";
}

/* Convert Python's `int(seed) or sum(ord(c) for c in seed)` into C.
 * Returns the parsed seed value, or a per-char hash when the string
 * isn't pure-integer. Negative inputs are mapped to their absolute
 * value so `% _names_count` is well-defined. */
static unsigned int parse_seed(const char *seed_str)
{
    if (seed_str == NULL || seed_str[0] == '\0') return 0;
    char *end = NULL;
    long v = strtol(seed_str, &end, 10);
    if (end != NULL && *end == '\0') {
        if (v < 0) v = -v;
        return (unsigned int)v;
    }
    unsigned int sum = 0;
    for (const char *p = seed_str; *p != '\0'; p++)
        sum += (unsigned int)(unsigned char)*p;
    return sum;
}

/****************************
 * Bootstrap config reader
 * Reads node_address and subnet from bootstrap/bootstrap.cfg.json if present.
 ****************************/

/* Frama-C: skipped — [solver-timeout] JSON file read preconditions */
static int read_bootstrap(const char *cfg_dir, char *addr_out, size_t addr_len,
                          char *subnet_out, size_t subnet_len)
{
    char path[CFG_PATH_LEN + 1];
    snprintf(path, sizeof(path), "%s/bootstrap/bootstrap.cfg.json", cfg_dir);

    json_error_t err;
    json_t *root = json_load_file(path, 0, &err);
    if (root == NULL)
        return -1;

    const char *addr = json_string_value(json_object_get(root, "node_address"));
    const char *sub  = json_string_value(json_object_get(root, "subnet"));

    if (addr == NULL || addr[0] == '\0')
    {
        json_decref(root);
        return -1;
    }

    strncpy(addr_out, addr, addr_len - 1);
    addr_out[addr_len - 1] = '\0';

    if (sub != NULL && subnet_out != NULL)
    {
        strncpy(subnet_out, sub, subnet_len - 1);
        subnet_out[subnet_len - 1] = '\0';
    }

    json_decref(root);
    return 0;
}

/****************************
 * Network interface discovery
 ****************************/

/* Frama-C: skipped — [solver-timeout] inet/network struct init preconditions */
static void fill_ipv4(net_iface_t *iface, struct ifaddrs *ifa,
                      const char *override_ip)
{
    struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;

    /* Use the bootstrap-provided IP if given, otherwise the interface's own */
    if (override_ip != NULL && override_ip[0] != '\0')
        strncpy(iface->ip4_addr, override_ip, IPV4_ADDR_LEN);
    else
        inet_ntop(AF_INET, &sa->sin_addr, iface->ip4_addr, IPV4_ADDR_LEN);

    if (ifa->ifa_netmask != NULL)
    {
        struct sockaddr_in *nm = (struct sockaddr_in *)ifa->ifa_netmask;
        uint32_t mask = ntohl(nm->sin_addr.s_addr);
        int bits = 0;
        while (mask & 0x80000000) { bits++; mask <<= 1; }
        /* Format into a scratch buffer larger than any possible input, then
         * copy the exact prefix that fits (silences -Wformat-truncation,
         * which is pessimistic about the %d range). */
        char cidr_buf[64];
        int n = snprintf(cidr_buf, sizeof(cidr_buf), "%s/%d", iface->ip4_addr, bits);
        if (n > 0 && (size_t)n < sizeof(iface->ip4_cidr))
            memcpy(iface->ip4_cidr, cidr_buf, (size_t)n + 1);
        else
            iface->ip4_cidr[0] = '\0';
    }

    snprintf(iface->if_name, sizeof(iface->if_name), "%s", ifa->ifa_name);
}

/**
 * Discover network interface.  When preferred_ip is non-NULL, select the
 * interface whose subnet contains that address (and use it as our IP).
 * Falls back to the first non-loopback IPv4 interface.
 */
/* Frama-C: skipped — [solver-timeout] network interface enumeration */
static int discover_network_for(net_iface_t *iface, const char *preferred_ip)
{
    memset(iface, 0, sizeof(net_iface_t));

    struct ifaddrs *ifaddr = NULL;
    if (getifaddrs(&ifaddr) == -1)
        return SYS_EXCEPTION();

    /* Parse preferred IP for subnet matching */
    uint32_t pref_addr = 0;
    if (preferred_ip != NULL && preferred_ip[0] != '\0')
    {
        struct in_addr pa;
        if (inet_pton(AF_INET, preferred_ip, &pa) == 1)
            pref_addr = ntohl(pa.s_addr);
    }

    bool found_ip4 = false;
    struct ifaddrs *fallback_ifa = NULL;  /* first non-loopback IPv4 */

    for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
            continue;
        if (ifa->ifa_flags & IFF_LOOPBACK)
            continue;

        int family = ifa->ifa_addr->sa_family;

        if (family == AF_INET)
        {
            if (fallback_ifa == NULL)
                fallback_ifa = ifa;

            /* If we have a preferred IP, check if this interface's subnet matches */
            if (pref_addr != 0 && ifa->ifa_netmask != NULL)
            {
                struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
                struct sockaddr_in *nm = (struct sockaddr_in *)ifa->ifa_netmask;
                uint32_t if_net  = ntohl(sa->sin_addr.s_addr) & ntohl(nm->sin_addr.s_addr);
                uint32_t pref_net = pref_addr & ntohl(nm->sin_addr.s_addr);
                if (if_net == pref_net)
                {
                    fill_ipv4(iface, ifa, preferred_ip);
                    found_ip4 = true;
                    break;  /* preferred match — stop looking */
                }
            }
        }
        else if (family == AF_INET6)
        {
            struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)ifa->ifa_addr;
            inet_ntop(AF_INET6, &sa6->sin6_addr, iface->ip6_addr, IPV6_ADDR_LEN);

            if (ifa->ifa_netmask != NULL)
            {
                struct sockaddr_in6 *nm6 = (struct sockaddr_in6 *)ifa->ifa_netmask;
                int bits = 0;
                for (int i = 0; i < 16; i++)
                {
                    uint8_t byte = nm6->sin6_addr.s6_addr[i];
                    while (byte & 0x80)
                    {
                        bits++;
                        byte <<= 1;
                    }
                    if (byte != 0) break;
                }
                {
                    char cidr_buf[128];
                    int n = snprintf(cidr_buf, sizeof(cidr_buf),
                                     "%s/%d", iface->ip6_addr, bits);
                    if (n > 0 && (size_t)n < sizeof(iface->ip6_cidr))
                        memcpy(iface->ip6_cidr, cidr_buf, (size_t)n + 1);
                    else
                        iface->ip6_cidr[0] = '\0';
                }
            }
        }
    }

    /* Fall back to first non-loopback IPv4 if preferred match wasn't found */
    if (!found_ip4 && fallback_ifa != NULL)
    {
        fill_ipv4(iface, fallback_ifa, NULL);
        found_ip4 = true;
    }

    /* Get MAC address via ioctl */
    if (found_ip4)
    {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock >= 0)
        {
            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            snprintf(ifr.ifr_name, IFNAMSIZ, "%s", iface->if_name);
            if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0)
            {
                unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
                snprintf(iface->mac_addr, MAC_ADDR_LEN + 1,
                         "%02x:%02x:%02x:%02x:%02x:%02x",
                         mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            }
            close(sock);
        }
    }

    freeifaddrs(ifaddr);

    if (!found_ip4)
        return EXCEPTION(EGEN_NOIF);

    return 0;
}

int discover_network(net_iface_t *iface)
{
    return discover_network_for(iface, NULL);
}

/****************************
 * Identity generation
 ****************************/

/* Frama-C: skipped — [solver-timeout] identity creation + JSON file write */
int generate_identity(const char *fullname, const char *cfg_dir,
                      bool preserve, bool defaults)
{
    (void)defaults;  /* parity-only — C generator already runs non-interactively */

    char filepath[CFG_PATH_LEN + 1];
    /* File extension follows AT_SERIALIZE_MODE — Python generate.py
     * builds `cfg_dir + CfgIds.identity + Configuration.file_ext`. */
    char fname[CFG_NAME_SIZE + 16];
    snprintf(fname, sizeof(fname), "identity%s",
             at_serialize_mode_file_ext(at_serialize_mode_current()));
    if (path_join(filepath, sizeof(filepath), cfg_dir, fname) < 0)
        return -1;

    /* preserve: skip if the identity file already exists. Mirrors Python
     * generate.py:121 (`not os.path.exists(ident_file) or not preserve`). */
    if (preserve) {
        struct stat st;
        if (stat(filepath, &st) == 0)
            return 0;
    }

    uuid_t uuid;
    uuid_generate(uuid);

    /* Check bootstrap for a provisioned address */
    char bootstrap_addr[IPV4_ADDR_LEN + 1] = {0};
    read_bootstrap(cfg_dir, bootstrap_addr, sizeof(bootstrap_addr), NULL, 0);

    /* Discover the right interface (preferring bootstrap subnet) */
    net_iface_t iface;
    char address[ADDR_LEN + 1] = {0};
    int disc = discover_network_for(&iface, bootstrap_addr[0] ? bootstrap_addr : NULL);

    /* Address-family selection: ask the active transport which family it
     * speaks. Mirrors Python generate.py:80-85 (`proto_cls.net_proto`). */
    const net_transport_t *active = net_transport_find(default_transport_name());
    network_protocol_t fam = (active != NULL) ? active->net_proto : NETPROTO_IPV4;

    /* Manual byte-copy with explicit truncation — ADDR_LEN (32) is shorter
     * than IPV6_ADDR_LEN (46), so a long IPv6 address may truncate. The
     * compiler's -Wformat-truncation / -Wstringop-truncation can't see
     * that truncation is intentional here, so we copy bytes and NUL-
     * terminate by hand. Widening `public_identity_t.address` is a
     * separate (L4-class) wire-format change. */
    const char *src = NULL;
    if (disc == 0) {
        switch (fam) {
        case NETPROTO_IPV6:
            src = (iface.ip6_addr[0] != '\0') ? iface.ip6_addr : iface.ip4_addr;
            break;
        case NETPROTO_MAC:
            src = iface.mac_addr;
            break;
        case NETPROTO_IPV4:
        case NETPROTO_NONE:
        default:
            src = iface.ip4_addr;
            break;
        }
    } else {
        src = "127.0.0.1";
    }
    size_t copy_len = strlen(src);
    if (copy_len > ADDR_LEN) copy_len = ADDR_LEN;
    memcpy(address, src, copy_len);
    address[copy_len] = '\0';

    identity_t *ident = NULL;
    int err = identity_create(&uuid, address, (char *)fullname, NULL, NULL, &ident);
    if (err != 0)
        return err;

    config_t *cfg = find_configuration("identity");
    if (cfg == NULL)
    {
        identity_free(ident);
        return -1;
    }
    err = write_config_file(cfg, ident, filepath);
    identity_free(ident);

    return err;
}

/****************************
 * Network config generation
 ****************************/

/* Frama-C: skipped — [solver-timeout] network config + JSON file write */
int generate_network_config(const char *cfg_dir, bool preserve)
{
    char filepath[CFG_PATH_LEN + 1];
    char fname[CFG_NAME_SIZE + 16];
    snprintf(fname, sizeof(fname), "network%s",
             at_serialize_mode_file_ext(at_serialize_mode_current()));
    if (path_join(filepath, sizeof(filepath), cfg_dir, fname) < 0)
        return -1;

    if (preserve) {
        struct stat st;
        if (stat(filepath, &st) == 0)
            return 0;
    }

    /* Check bootstrap for a provisioned address */
    char bootstrap_addr[IPV4_ADDR_LEN + 1] = {0};
    read_bootstrap(cfg_dir, bootstrap_addr, sizeof(bootstrap_addr), NULL, 0);

    net_iface_t iface;
    int err = discover_network_for(&iface, bootstrap_addr[0] ? bootstrap_addr : NULL);
    if (err != 0)
        return err;

    network_config_t net_cfg = {0};
    net_cfg.port = COMM_PORT;
    snprintf(net_cfg.mac_address, sizeof(net_cfg.mac_address), "%s", iface.mac_addr);
    snprintf(net_cfg.ip4_cidr, sizeof(net_cfg.ip4_cidr), "%s", iface.ip4_cidr);
    snprintf(net_cfg.ip6_cidr, sizeof(net_cfg.ip6_cidr), "%s", iface.ip6_cidr);
    /* default multicast groups; user may override in cfg file */
    snprintf(net_cfg.mcast4_addr, sizeof(net_cfg.mcast4_addr), "%s", DEFAULT_MCAST4_ADDR);
    snprintf(net_cfg.mcast6_addr, sizeof(net_cfg.mcast6_addr), "%s", DEFAULT_MCAST6_ADDR);

    config_t *cfg = find_configuration("network");
    if (cfg == NULL)
        return -1;
    return write_config_file(cfg, &net_cfg, filepath);
}

/****************************
 * Subsystems config generation
 ****************************/

int generate_subsystems_config(const char *cfg_dir)
{
    logger_t logger;
    int err = logger_init(&logger, WARNING, NULL);
    if (err != 0)
        return err;

    tracker_t tracker;
    err = tracker_init(&logger, &tracker);
    if (err != 0)
        return err;

    err = tracker_register_subsystem(&tracker, "network", default_transport_name());
    if (err != 0)
        return err;
    err = tracker_register_subsystem(&tracker, "identity", "id_proc");
    if (err != 0)
        return err;
    err = tracker_register_subsystem(&tracker, "negotiation", "neg_proc");
    if (err != 0)
        return err;
    err = tracker_register_subsystem(&tracker, "reputation", "rep_proc");
    if (err != 0)
        return err;
    err = tracker_register_subsystem(&tracker, "fleet", "fleet_proc");
    if (err != 0)
        return err;
    err = tracker_register_subsystem(&tracker, "artifact", "artifact_proc");
    if (err != 0)
        return err;
    err = tracker_register_subsystem(&tracker, "update", "update_proc");
    if (err != 0)
        return err;
    err = tracker_register_subsystem(&tracker, "config", "config_proc");
    if (err != 0)
        return err;

    char filepath[CFG_PATH_LEN + 1];
    if (path_join(filepath, sizeof(filepath), cfg_dir, default_tracker_filename) < 0)
        return -1;

    return tracker_to_file(&tracker, filepath);
}

/****************************
 * Non-interactive wrapper
 ****************************/

int random_config(const char *cfg_dir, const char *seed_str)
{
    char fullname[NAME_LEN + 1];

    /* Identity-name selection priority (mirrors Python generate.py:87-107
     * plus the seed-indexed _names path the C side previously skipped).
     *   1. AT_PEER_NAME env (operator override — multi-agent compose).
     *   2. seed-indexed _names[] entry when a seed is available.
     *   3. UUID-derived `agent-XXXXXXXX` fallback.
     *
     * Seed source: explicit seed_str argument wins; falls back to the
     * AT_PEER_SEED env var (parity with how Python's __main__.py wires
     * a CLI --ident through random_config(base, ident)). */
    const char *peer_name = getenv("AT_PEER_NAME");
    if (peer_name != NULL && peer_name[0] != '\0') {
        strncpy(fullname, peer_name, NAME_LEN);
        fullname[NAME_LEN] = '\0';
    } else {
        const char *seed_src = seed_str;
        if (seed_src == NULL || seed_src[0] == '\0')
            seed_src = getenv("AT_PEER_SEED");
        if (seed_src != NULL && seed_src[0] != '\0') {
            unsigned int seed = parse_seed(seed_src);
            const char *picked = _names[seed % _names_count];
            strncpy(fullname, picked, NAME_LEN);
            fullname[NAME_LEN] = '\0';
        } else {
            uuid_t name_uuid;
            uuid_generate(name_uuid);
            char name_str[UUID_STRING_LEN + 1];
            uuid_unparse_lower(name_uuid, name_str);
            snprintf(fullname, NAME_LEN, "agent-%.*s", 8, name_str);
        }
    }

    /* preserve=true so existing keys / network / subsystem files survive
     * an idempotent re-run. Regenerating identity would mint new keys
     * and break peer relationships. Mirrors Python random_config which
     * only writes when the cfg_dir is empty. */
    int err = generate_identity(fullname, cfg_dir, /*preserve=*/true,
                                /*defaults=*/true);
    if (err != 0)
        return err;

    err = generate_network_config(cfg_dir, /*preserve=*/true);
    if (err != 0)
        return err;

    return generate_subsystems_config(cfg_dir);
}

/* Defaults-only counterpart to Python's reflective generate_worker_config.
 * See header for the parity rationale (no C-side `inspect` analog). */
int generate_worker_config(const char *cfg_dir, const char *proc_name)
{
    if (cfg_dir == NULL || proc_name == NULL)
        return EXCEPTION(EINVAL);

    config_t *cfg = find_configuration(proc_name);
    if (cfg == NULL)
        return EXCEPTION(ECFG_NOIMPL);

    /* Build the destination path using the active serialize mode's
     * extension — Python's equivalent does
     * `proc_name + Configuration.file_ext`. */
    char fname[CFG_NAME_SIZE + 16];
    snprintf(fname, sizeof(fname), "%s%s", proc_name,
             at_serialize_mode_file_ext(at_serialize_mode_current()));
    char filepath[CFG_PATH_LEN + 1];
    if (path_join(filepath, sizeof(filepath), cfg_dir, fname) < 0)
        return -1;

    /* Idempotent — Python's `not os.path.exists(cfg_file)` guard. */
    struct stat st;
    if (stat(filepath, &st) == 0)
        return 0;

    /* Zero-initialized backing struct ⇒ "all defaults" wire form.
     * Configs whose to_json/to_proto require non-zero invariants set
     * their own constructors via the dedicated `generate_*_config()`
     * helpers (network/identity/subsystems). */
    void *data = calloc(1, cfg->data_len);
    if (data == NULL)
        return SYS_EXCEPTION();
    int err = write_config_file(cfg, data, filepath);
    free(data);
    return err;
}
