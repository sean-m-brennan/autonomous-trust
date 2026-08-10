/********************
 *  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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

/**
 * @file net_transport_ip.c
 * @brief Bind/mcast helpers shared between UDP and TCP socket transports.
 */

#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "net_transport_priv.h"
#include "utilities/exception.h"

/* Frama-C: skipped — [syscall] inet_pton + bind/setsockopt stubs. */
int net_transport_ip_bind_source(int sock, const char *address, int domain,
                                 bool stream, logger_t *logger)
{
    /* Nothing to pin: no address, or a wildcard, which is what an unbound
     * socket already does. Not an error. */
    if (address == NULL || address[0] == '\0' ||
        strcmp(address, "0.0.0.0") == 0 || strcmp(address, "::") == 0)
        return -1;

    if (stream) {
#ifdef IP_BIND_ADDRESS_NO_PORT
        int one = 1;
        /* Best effort: correctness does not depend on it, only port headroom. */
        (void)setsockopt(sock, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT,
                         &one, sizeof(one));
#endif
    }

    /* inet_pton rather than getaddrinfo: this runs on every send, and the
     * address is already a numeric literal derived from the config. NOTE: no
     * SO_REUSEADDR here, deliberately -- see the header comment. Port 0 lets
     * the kernel autobind. */
    int err;
    if (domain == AF_INET6) {
        struct sockaddr_in6 src = {0};
        src.sin6_family = AF_INET6;
        src.sin6_port = 0;
        if (inet_pton(AF_INET6, address, &src.sin6_addr) != 1)
            return -1;
        err = bind(sock, (struct sockaddr *)&src, sizeof(src));
    } else {
        struct sockaddr_in src = {0};
        src.sin_family = AF_INET;
        src.sin_port = 0;
        if (inet_pton(AF_INET, address, &src.sin_addr) != 1)
            return -1;
        err = bind(sock, (struct sockaddr *)&src, sizeof(src));
    }
    if (err != 0) {
        /* Warn once per process, not once per send. */
        static bool warned = false;
        if (!warned) {
            warned = true;
            log_warn(logger, "Could not bind source address %s (%s); sending "
                     "unbound, so peers may fail to attribute these messages\n",
                     address, strerror(errno));
        }
        return -1;
    }
    return 0;
}

/* Frama-C: skipped —
 * [syscall] net_transport_ip_bind: getaddrinfo loop + bind/setsockopt + 6x set_exception
 * precondition cascade.
 */
int net_transport_ip_bind(const socket_cfg_t *cfg, const char *address,
                          int port, bool listen_sock, bool reuse, int *out_fd,
                          logger_t *logger)
{
    struct addrinfo hints = {0};
    hints.ai_family = cfg->domain;
    hints.ai_socktype = cfg->type;
    if (address == NULL)
        hints.ai_flags = AI_PASSIVE;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo *res = NULL;
    int err = getaddrinfo(address, port_str, &hints, &res);
    if (err != 0)
    {
        if (err == EAI_SYSTEM) {
            SYS_EXCEPTION();
        } else {
            EXCEPTION(err);
        }
        log_exception(logger);
        return -1;
    }

    int sock = socket(cfg->domain, cfg->type, cfg->protocol);
    if (sock == -1)
    {
        freeaddrinfo(res);
        SYS_EXCEPTION();
        log_exception(logger);
        return -1;
    }

    /* Per-socket, deliberately — see the @p reuse contract in the header. Set
     * on this socket, the option is also what would let a SECOND node bind the
     * identical addr:port and take delivery of every datagram, so the unicast
     * recv sockets opt out and get EADDRINUSE instead. */
    if (reuse)
    {
        int one = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0)
        {
            close(sock);
            freeaddrinfo(res);
            SYS_EXCEPTION();
            log_exception(logger);
            return -1;
        }
    }

    if (bind(sock, res->ai_addr, res->ai_addrlen) != 0)
    {
        /* Saved before close()/freeaddrinfo()/log_error, any of which may set
         * errno on their own; the reported cause has to be the bind's. */
        int bind_errno = errno;
        /* Name the likely cause: without SO_REUSEADDR this is how a second
         * node sharing one base and one address now announces itself, and a
         * bare "Address already in use" does not say which knob to move. */
        if (bind_errno == EADDRINUSE)
            log_error(logger,
                      "Cannot bind %s:%d -- already held, most likely by "
                      "another AT node on this address. Give each co-located "
                      "node a distinct base port (config net_cfg.port, or "
                      "AT_COMM_PORT).\n",
                      address ? address : "*", port);
        close(sock);
        freeaddrinfo(res);
        EXCEPTION(bind_errno);
        log_exception(logger);
        return -1;
    }

    if (listen_sock && cfg->type == SOCK_STREAM)
    {
        if (listen(sock, 5) != 0)
        {
            close(sock);
            freeaddrinfo(res);
            SYS_EXCEPTION();
            log_exception(logger);
            return -1;
        }
    }

    freeaddrinfo(res);
    *out_fd = sock;
    return 0;
}

/* Frama-C: skipped —
 * [syscall] net_transport_ip_join_mcast: setsockopt + at_memcpy +
 * getaddrinfo/freeaddrinfo + set_exception cascade (IPv4 and IPv6 branches both hit
 * setsockopt).
 */
int net_transport_ip_join_mcast(int sock, bool ipv6, const char *mcast_address,
                                int port, logger_t *logger)
{
    struct addrinfo hints = {0};
    hints.ai_family = ipv6 ? AF_INET6 : AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo *res = NULL;
    int err = getaddrinfo(mcast_address, port_str, &hints, &res);
    if (err != 0)
    {
        if (err == EAI_SYSTEM) {
            SYS_EXCEPTION();
        } else {
            EXCEPTION(err);
        }
        log_exception(logger);
        return -1;
    }

    if (ipv6) {
        struct ipv6_mreq mreq6;
        memcpy(&mreq6.ipv6mr_multiaddr,
               &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr,
               sizeof(mreq6.ipv6mr_multiaddr));
        mreq6.ipv6mr_interface = 0;
        err = setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP,
                         &mreq6, sizeof(mreq6));
    } else {
        struct ip_mreq mreq4;
        mreq4.imr_multiaddr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
        mreq4.imr_interface.s_addr = htonl(INADDR_ANY);
        err = setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                         &mreq4, sizeof(mreq4));
    }

    freeaddrinfo(res);
    if (err != 0)
    {
        SYS_EXCEPTION();
        log_exception(logger);
        return -1;
    }
    return 0;
}
