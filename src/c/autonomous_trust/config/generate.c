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
#include "processes/process_tracker.h"
#include "utilities/util.h"

DEFINE_ERROR(EGEN_NOIF, "No suitable network interface found");

/****************************
 * Bootstrap config reader
 * Reads node_address and subnet from bootstrap/bootstrap.cfg.json if present.
 ****************************/

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
        char cidr_buf[64];
        snprintf(cidr_buf, sizeof(cidr_buf), "%s/%d", iface->ip4_addr, bits);
        strncpy(iface->ip4_cidr, cidr_buf, CIDR4_LEN);
    }

    strncpy(iface->if_name, ifa->ifa_name, sizeof(iface->if_name) - 1);
}

/**
 * Discover network interface.  When preferred_ip is non-NULL, select the
 * interface whose subnet contains that address (and use it as our IP).
 * Falls back to the first non-loopback IPv4 interface.
 */
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
                    snprintf(cidr_buf, sizeof(cidr_buf), "%s/%d", iface->ip6_addr, bits);
                    strncpy(iface->ip6_cidr, cidr_buf, CIDR6_LEN);
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
            strncpy(ifr.ifr_name, iface->if_name, IFNAMSIZ - 1);
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

int generate_identity(const char *fullname, const char *cfg_dir)
{
    uuid_t uuid;
    uuid_generate(uuid);

    /* Check bootstrap for a provisioned address */
    char bootstrap_addr[IPV4_ADDR_LEN + 1] = {0};
    read_bootstrap(cfg_dir, bootstrap_addr, sizeof(bootstrap_addr), NULL, 0);

    /* Discover the right interface (preferring bootstrap subnet) */
    net_iface_t iface;
    char address[ADDR_LEN + 1] = {0};
    if (discover_network_for(&iface, bootstrap_addr[0] ? bootstrap_addr : NULL) == 0)
        strncpy(address, iface.ip4_addr, ADDR_LEN);
    else
        strncpy(address, "127.0.0.1", ADDR_LEN);

    identity_t *ident = NULL;
    int err = identity_create(&uuid, address, (char *)fullname, NULL, NULL, &ident);
    if (err != 0)
        return err;

    char filepath[CFG_PATH_LEN + 1];
    snprintf(filepath, CFG_PATH_LEN, "%s/identity.cfg.json", cfg_dir);

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

int generate_network_config(const char *cfg_dir)
{
    /* Check bootstrap for a provisioned address */
    char bootstrap_addr[IPV4_ADDR_LEN + 1] = {0};
    read_bootstrap(cfg_dir, bootstrap_addr, sizeof(bootstrap_addr), NULL, 0);

    net_iface_t iface;
    int err = discover_network_for(&iface, bootstrap_addr[0] ? bootstrap_addr : NULL);
    if (err != 0)
        return err;

    network_config_t net_cfg = {0};
    net_cfg.port = COMM_PORT;
    strncpy(net_cfg.mac_address, iface.mac_addr, MAC_ADDR_LEN);
    strncpy(net_cfg.ip4_cidr, iface.ip4_cidr, CIDR4_LEN);
    strncpy(net_cfg.ip6_cidr, iface.ip6_cidr, CIDR6_LEN);
    /* mcast addresses left empty */

    char filepath[CFG_PATH_LEN + 1];
    snprintf(filepath, CFG_PATH_LEN, "%s/network.cfg.json", cfg_dir);

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

    err = tracker_register_subsystem(&tracker, "network", "udp_net_4");
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
    snprintf(filepath, CFG_PATH_LEN, "%s/%s", cfg_dir, default_tracker_filename);

    return tracker_to_file(&tracker, filepath);
}

/****************************
 * Non-interactive wrapper
 ****************************/

int random_config(const char *cfg_dir)
{
    /* Only generate identity if it doesn't already exist.
     * Regenerating would create new keys, breaking existing peer
     * relationships (peers still hold the old public key). */
    char id_path[CFG_PATH_LEN + 1];
    snprintf(id_path, sizeof(id_path), "%s/identity.cfg.json", cfg_dir);
    struct stat st;
    if (stat(id_path, &st) != 0)
    {
        uuid_t name_uuid;
        uuid_generate(name_uuid);
        char name_str[UUID_STRING_LEN + 1];
        uuid_unparse_lower(name_uuid, name_str);

        char fullname[NAME_LEN + 1];
        snprintf(fullname, NAME_LEN, "agent-%.*s", 8, name_str);

        int err = generate_identity(fullname, cfg_dir);
        if (err != 0)
            return err;
    }

    int err = generate_network_config(cfg_dir);
    if (err != 0)
        return err;

    return generate_subsystems_config(cfg_dir);
}
