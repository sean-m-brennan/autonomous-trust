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

#include "socket_helpers.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdbool.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>

/* Frama-C: skipped — these are pass-through wrappers over POSIX
 * send/recv/sendto/recvfrom/setsockopt syscalls; the WP-usable specs
 * for the underlying syscalls do not exist. */

ssize_t at_send_eintr(int sock, const void *buf, size_t len, int flags)
{
    for (;;) {
        ssize_t n = send(sock, buf, len, flags);
        if (n < 0 && errno == EINTR)
            continue;
        return n;
    }
}

int at_poll_eintr(struct pollfd *fds, nfds_t nfds, int timeout_ms)
{
    for (;;) {
        int n = poll(fds, nfds, timeout_ms);
        if (n < 0 && errno == EINTR)
            continue;
        return n;
    }
}

ssize_t at_recv_eintr(int sock, void *buf, size_t len, int flags)
{
    for (;;) {
        ssize_t n = recv(sock, buf, len, flags);
        if (n < 0 && errno == EINTR)
            continue;
        return n;
    }
}

ssize_t at_sendto_eintr(int sock, const void *buf, size_t len, int flags,
                        const struct sockaddr *dest, socklen_t dest_len)
{
    for (;;) {
        ssize_t n = sendto(sock, buf, len, flags, dest, dest_len);
        if (n < 0 && errno == EINTR)
            continue;
        return n;
    }
}

ssize_t at_recvfrom_eintr(int sock, void *buf, size_t len, int flags,
                          struct sockaddr *src, socklen_t *src_len)
{
    for (;;) {
        ssize_t n = recvfrom(sock, buf, len, flags, src, src_len);
        if (n < 0 && errno == EINTR)
            continue;
        return n;
    }
}

static int set_timeo(int sock, int level, int optname, int timeout_ms,
                     const char *which, logger_t *logger)
{
    if (timeout_ms < 0)
        timeout_ms = 0;
    struct timeval tv = {
        .tv_sec  = timeout_ms / 1000,
        .tv_usec = (timeout_ms % 1000) * 1000,
    };
    if (setsockopt(sock, level, optname, &tv, sizeof(tv)) != 0) {
        int saved = errno;
        if (logger != NULL)
            log_warn(logger, "setsockopt(%s) failed: %s\n",
                     which, strerror(saved));
        errno = saved;
        return -1;
    }
    return 0;
}

int at_set_rcvtimeo(int sock, int timeout_ms, logger_t *logger)
{
    return set_timeo(sock, SOL_SOCKET, SO_RCVTIMEO, timeout_ms,
                     "SO_RCVTIMEO", logger);
}

int at_set_sndtimeo(int sock, int timeout_ms, logger_t *logger)
{
    return set_timeo(sock, SOL_SOCKET, SO_SNDTIMEO, timeout_ms,
                     "SO_SNDTIMEO", logger);
}

int at_socket_nosigpipe(int sock)
{
#ifdef SO_NOSIGPIPE
    int one = 1;
    return setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#else
    (void)sock;
    return 0;
#endif
}

int at_socket_close(int sock)
{
#ifdef _WIN32
    return closesocket((SOCKET)sock) == 0 ? 0 : -1;
#else
    return close(sock);
#endif
}

int at_socket_set_nonblock(int sock)
{
#ifdef _WIN32
    u_long on = 1;
    return ioctlsocket((SOCKET)sock, FIONBIO, &on) == 0 ? 0 : -1;
#else
    int fl = fcntl(sock, F_GETFL, 0);
    if (fl < 0)
        return -1;
    return fcntl(sock, F_SETFL, fl | O_NONBLOCK);
#endif
}

int at_socket_listener_opts(int sock)
{
    int one = 1;
#ifdef _WIN32
    return setsockopt(sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &one, sizeof(one));
#else
    return setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#endif
}

/* Strict dotted quad: four decimal octets, 0-255, no leading zeros. */
static bool _ipv4_strict(const char *s, const char *end)
{
    int octets = 0;
    while (s < end)
    {
        const char *start = s;
        int v = 0;
        while (s < end && isdigit((unsigned char)*s))
            v = v * 10 + (*s++ - '0');
        size_t len = (size_t)(s - start);
        if (len == 0 || len > 3 || v > 255 || (len > 1 && *start == '0'))
            return false;
        if (++octets > 4)
            return false;
        if (s < end && *s++ != '.')
            return false;
        if (s == end && s[-1] == '.')
            return false;
    }
    return octets == 4;
}

int at_inet_pton(int af, const char *src, void *dst)
{
    if (src == NULL)
        return 0;
    if (af == AF_INET && !_ipv4_strict(src, src + strlen(src)))
        return 0;
    if (af == AF_INET6)
    {
        /* An embedded IPv4 tail ("::ffff:10.0.0.1") follows the last colon */
        const char *colon = strrchr(src, ':');
        if (colon != NULL && strchr(colon, '.') != NULL &&
            !_ipv4_strict(colon + 1, src + strlen(src)))
            return 0;
    }
    return inet_pton(af, src, dst);
}
