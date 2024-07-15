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

#define _XOPEN_SOURCE 700
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/exception.h"
#include "utilities/logger.h"
#include "network.h"

const bool use_mcast = false;

typedef struct
{
    int domain;
    int type;
    int protocol;
} socket_t;

typedef struct
{
    int level;
    int optname;
    const void *optval;
    socklen_t optlen;
} sock_opts_t;

typedef struct
{
    int recv_ptp;
    int recv_grp;
    int recv_cast;
} recvrs_t;

int _send(socket_t *cfg, char *msg, char *host, int port)
{
    // int sock = socket(cfg->domain, cfg->type, cfg->protocol);
    //  encode
    //  connect
    //  send all
    return 0;
}

void network_shutdown(recvrs_t *socks)
{
    if (socks->recv_cast > 0)
        close(socks->recv_cast);
    if (socks->recv_grp > 0)
        close(socks->recv_grp);
    if (socks->recv_ptp > 0)
        close(socks->recv_ptp);
}

int network_run(socket_t *cfg, process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger, bool ipv6)
{
    recvrs_t socks = {0};
    int backlog = 5;
    network_config_t *net_cfg = (network_config_t *)proc->conf.data_struct;
    int one = 1;

    char *address = NULL;
    if (ipv6) {
        char ipv6_addr[IPV6_ADDR_LEN];
        cidr_split(net_cfg->ip6_cidr, ipv6_addr, NULL);
        address = ipv6_addr;
    } else {
        char ipv4_addr[IPV4_ADDR_LEN];
        cidr_split(net_cfg->ip4_cidr, ipv4_addr, NULL);
        address = ipv4_addr;
    }

    struct addrinfo *res;
    struct addrinfo hints = {0};
    hints.ai_family = cfg->domain;
    hints.ai_socktype = cfg->type;
    if (address == NULL)
        hints.ai_flags = AI_PASSIVE;

    int port_num = net_cfg->port;
    if (port_num == 0)
        port_num = COMM_PORT;
    int grp_port = port_num + 1;
    char port_str[32] = {0};
    snprintf(port_str, 31, "%d", port_num);
    char grp_port_str[32] = {0};
    snprintf(grp_port_str, 31, "%d", grp_port);

    int err = getaddrinfo(address, port_str, &hints, &res);
    if (err != 0)
    {
        if (err == EAI_SYSTEM)
        {
            SYS_EXCEPTION();
            log_exception(logger);
            return -1;
        }
        EXCEPTION(err);
        log_exception(logger);
        return -1;
    }
    socks.recv_ptp = socket(cfg->domain, cfg->type, cfg->protocol);
    if (socks.recv_ptp == -1)
    {
        SYS_EXCEPTION();
        log_exception(logger);
        return -1;
    }
    err = setsockopt(socks.recv_ptp, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));
    if (err != 0)
    {
        network_shutdown(&socks);
        SYS_EXCEPTION();
        log_exception(logger);
        return -1;
    }
    err = bind(socks.recv_ptp, res->ai_addr, res->ai_addrlen);  // FIXME EADDRNOTAVAIL
    if (err != 0)
    {
        network_shutdown(&socks);
        SYS_EXCEPTION();
        log_exception(logger);
        return -1;
    }
    if (SOCK_STREAM == cfg->type) {
        err = listen(socks.recv_ptp, backlog);
        if (err != 0)
        {
            network_shutdown(&socks);
            SYS_EXCEPTION();
            log_exception(logger);
            return -1;
        }
    }
    freeaddrinfo(res);

    err = getaddrinfo(address, grp_port_str, &hints, &res);
    if (err != 0)
    {
        network_shutdown(&socks);
        if (err == EAI_SYSTEM)
        {
            SYS_EXCEPTION();
            log_exception(logger);
            return -1;
        }
        EXCEPTION(err);
        log_exception(logger);
        return -1;
    }
    socks.recv_grp = socket(cfg->domain, cfg->type, cfg->protocol);
    if (socks.recv_grp == -1)
    {
        network_shutdown(&socks);
        SYS_EXCEPTION();
        log_exception(logger);
        return -1;
    }
    err = setsockopt(socks.recv_grp, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));
    if (err != 0)
    {
        network_shutdown(&socks);
        SYS_EXCEPTION();
        log_exception(logger);
        return -1;
    }
    // FIXME different port?
    err = bind(socks.recv_grp, res->ai_addr, res->ai_addrlen);
    if (err != 0)
    {
        network_shutdown(&socks);
        SYS_EXCEPTION();
        log_exception(logger);
        return -1;
    }
    if (SOCK_STREAM == cfg->type) {
        err = listen(socks.recv_grp, backlog);
        if (err != 0)
        {
            network_shutdown(&socks);
            SYS_EXCEPTION();
            log_exception(logger);
            return -1;
        }
    }
    freeaddrinfo(res);

    if (use_mcast)
    {
        char *mcast_address = NULL;
        if (ipv6)
            mcast_address = net_cfg->mcast6_addr;
        else
            mcast_address = net_cfg->mcast4_addr;

        err = getaddrinfo(mcast_address, port_str, &hints, &res);
        if (err != 0)
        {
            network_shutdown(&socks);
            if (err == EAI_SYSTEM)
            {
                SYS_EXCEPTION();
                log_exception(logger);
                return -1;
            }
            EXCEPTION(err);
            log_exception(logger);
            return -1;
        }
        // size_t packet_size = 65527;
        // int mcast_ttl = 2;
        // sock_opts_t send_opts = { .level = IPPROTO_IP, .optname = IP_MULTICAST_TTL, .optval = &mcast_ttl, .optlen = sizeof(int) };
        socks.recv_cast = socket(cfg->domain, SOCK_DGRAM, IPPROTO_UDP);
        if (socks.recv_cast == -1)
        {
            network_shutdown(&socks);
            SYS_EXCEPTION();
            log_exception(logger);
            return -1;
        }
        err = setsockopt(socks.recv_cast, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));
        if (err != 0)
        {
            network_shutdown(&socks);
            SYS_EXCEPTION();
            log_exception(logger);
            return -1;
        }
        err = bind(socks.recv_cast, res->ai_addr, res->ai_addrlen);
        if (err != 0)
        {
            network_shutdown(&socks);
            SYS_EXCEPTION();
            log_exception(logger);
            return -1;
        }
        // setsockopt(IPPROTO_IP, IP_ADD_MEMBERSHIP, req);
        freeaddrinfo(res);
    }
    else
    {
        if (ipv6)
        {
            log_error(logger, "IPv6 Anycast not implemented\n");
            return EXCEPTION(EINVAL);
        }

        char bcast_address[IPV4_ADDR_LEN];
        cidr4_to_broadcast(net_cfg->ip4_cidr, bcast_address);
        err = getaddrinfo(bcast_address, port_str, &hints, &res);
        if (err != 0)
        {
            network_shutdown(&socks);
            if (err == EAI_SYSTEM)
            {
                SYS_EXCEPTION();
                log_exception(logger);
            }
            EXCEPTION(err);
            log_exception(logger);
            return -1;
        }
        // size_t packet_size = 65507;
        // sock_opts_t send_opts = { .level = SOL_SOCKET, .optname = SO_BROADCAST, .optval = &one, .optlen = sizeof(int) };
        socks.recv_cast = socket(cfg->domain, SOCK_DGRAM, IPPROTO_UDP);
        if (socks.recv_cast == -1)
        {
            network_shutdown(&socks);
            SYS_EXCEPTION();
            log_exception(logger);
            return -1;
        }
        err = setsockopt(socks.recv_cast, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));
        if (err != 0)
        {
            network_shutdown(&socks);
            SYS_EXCEPTION();
            log_exception(logger);
            return -1;
        }
        err = bind(socks.recv_cast, res->ai_addr, res->ai_addrlen);
        if (err != 0)
        {
            network_shutdown(&socks);
            SYS_EXCEPTION();
            log_exception(logger);
            return -1;
        }
        freeaddrinfo(res);
    }

    // register handlers for intern msgs
    return process_run(proc, queues, signal, logger);
}

/**********/

int network_udp_ip4_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger)
{
    socket_t cfg = {.domain = AF_INET, .type = SOCK_DGRAM, .protocol = IPPROTO_UDP};
    return network_run(&cfg, proc, queues, signal, logger, false);
}
DECLARE_PROCESS(network, udp_net_4, network_udp_ip4_run);

int network_udp_ip6_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger)
{
    socket_t cfg = {.domain = AF_INET6, .type = SOCK_DGRAM, .protocol = IPPROTO_UDP};
    return network_run(&cfg, proc, queues, signal, logger, true);
}
DECLARE_PROCESS(network, udp_net_6, network_udp_ip6_run);

int network_tcp_ip4_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger)
{
    socket_t cfg = {.domain = AF_INET, .type = SOCK_STREAM, .protocol = 0};
    return network_run(&cfg, proc, queues, signal, logger, false);
}
DECLARE_PROCESS(network, tcp_net_4, network_tcp_ip4_run);

int network_tcp_ip6_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger)
{
    socket_t cfg = {.domain = AF_INET6, .type = SOCK_STREAM, .protocol = 0};
    return network_run(&cfg, proc, queues, signal, logger, true);
}
DECLARE_PROCESS(network, tcp_net_6, network_tcp_ip6_run);
