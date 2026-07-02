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

#include <errno.h>
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
