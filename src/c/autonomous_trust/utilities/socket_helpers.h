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

#ifndef AT_SOCKET_HELPERS_H
#define AT_SOCKET_HELPERS_H

/** @addtogroup internal_utilities
 *  @{
 *
 *  Thin wrappers around send/recv/sendto/recvfrom that retry on EINTR
 *  and around setsockopt(SO_*TIMEO) that return an explicit error.
 *  Closes BUGS.md "socket EINTR + missing timeouts" recurring theme.
 *
 *  Semantics:
 *   - EINTR retries are transparent: the syscall is reissued and the
 *     caller never observes EINTR. Any other errno (including
 *     EAGAIN/EWOULDBLOCK from a configured timeout) propagates.
 *   - Length and address arguments are pass-through. No partial-write
 *     accumulation is done here; TCP callers that need send_all
 *     semantics should layer their own loop on top of @ref at_send_eintr.
 *   - setsockopt wrappers return 0 / -1 (errno set on failure) and emit
 *     a warning to @p logger when the syscall fails. A logger of NULL is
 *     accepted; in that case the warning is suppressed.
 */

#include <poll.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "logger.h"

/* Darwin has no MSG_NOSIGNAL: a socket opts out of SIGPIPE once, with
 * SO_NOSIGPIPE (@ref at_socket_nosigpipe), and the per-send flag is a no-op. */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

/**
 * @brief send(2) with transparent EINTR retry.
 * @return Bytes sent, or -1 with @c errno set on non-EINTR error.
 */
ssize_t at_send_eintr(int sock, const void *buf, size_t len, int flags);

/**
 * @brief recv(2) with transparent EINTR retry.
 * @return Bytes received (may be 0 on orderly shutdown), or -1 with
 *         @c errno set on non-EINTR error.
 */
ssize_t at_recv_eintr(int sock, void *buf, size_t len, int flags);

/**
 * @brief sendto(2) with transparent EINTR retry.
 * @return Bytes sent, or -1 with @c errno set on non-EINTR error.
 */
ssize_t at_sendto_eintr(int sock, const void *buf, size_t len, int flags,
                        const struct sockaddr *dest, socklen_t dest_len);

/**
 * @brief recvfrom(2) with transparent EINTR retry.
 * @return Bytes received (may be 0), or -1 with @c errno set on non-EINTR error.
 */
ssize_t at_recvfrom_eintr(int sock, void *buf, size_t len, int flags,
                          struct sockaddr *src, socklen_t *src_len);

/**
 * @brief Set @c SO_RCVTIMEO with explicit return-value checking.
 *
 * @param sock        Socket file descriptor.
 * @param timeout_ms  Timeout in milliseconds. 0 disables the timeout
 *                    (sets {0,0}); negative values are clamped to 0.
 * @param logger      Optional logger for the failure path; may be NULL.
 * @return 0 on success, -1 with @c errno set on failure.
 */
int at_set_rcvtimeo(int sock, int timeout_ms, logger_t *logger);

/**
 * @brief Set @c SO_SNDTIMEO with explicit return-value checking.
 *
 * @param sock        Socket file descriptor.
 * @param timeout_ms  Timeout in milliseconds. 0 disables the timeout
 *                    (sets {0,0}); negative values are clamped to 0.
 * @param logger      Optional logger for the failure path; may be NULL.
 * @return 0 on success, -1 with @c errno set on failure.
 */
int at_set_sndtimeo(int sock, int timeout_ms, logger_t *logger);

/**
 * @brief poll(2) with transparent EINTR retry.
 *
 * The timeout is NOT recomputed across a retry: a signal-interrupted poll
 * restarts with the full timeout, so the worst case is (signals + 1) ×
 * @p timeout_ms. Callers here poll with either 0 or the receive-poll
 * tunable, both short, and none of them use poll as a clock.
 *
 * @param fds         Descriptor set, as poll(2).
 * @param nfds        Number of entries in @p fds.
 * @param timeout_ms  Milliseconds to wait; 0 returns immediately, negative
 *                    blocks indefinitely (as poll(2)).
 * @return Number of ready descriptors (0 on timeout), or -1 with @c errno
 *         set on non-EINTR error.
 */
int at_poll_eintr(struct pollfd *fds, nfds_t nfds, int timeout_ms);

/**
 * @brief Keep a write to a reset stream socket from raising SIGPIPE.
 *
 * Sets @c SO_NOSIGPIPE where the platform has it (Darwin, the BSDs), whose
 * sends cannot carry MSG_NOSIGNAL; elsewhere a no-op, since MSG_NOSIGNAL is
 * the per-send equivalent there. Call it on every connected or accepted
 * stream socket.
 *
 * @return 0 on success or when there is nothing to set, -1 with @c errno set.
 */
int at_socket_nosigpipe(int sock);

/**
 * @brief Close a socket: close(2) on POSIX, closesocket on Windows, where a
 *        socket is not a file descriptor and close() would leak it.
 */
int at_socket_close(int sock);

/**
 * @brief Put a socket in non-blocking mode (O_NONBLOCK; FIONBIO on Windows).
 * @return 0 on success, -1 with @c errno set.
 */
int at_socket_set_nonblock(int sock);

/**
 * @brief Ready a listening socket to bind: SO_REUSEADDR on POSIX, so a restart
 *        can bind while old connections sit in TIME_WAIT; SO_EXCLUSIVEADDRUSE on
 *        Windows, where SO_REUSEADDR would instead let another socket bind the
 *        same port and take this server's connections.
 * @return 0 on success, -1 with @c errno set.
 */
int at_socket_listener_opts(int sock);

/**
 * @brief inet_pton, with glibc's strictness on every libc.
 *
 * glibc (and Python's ipaddress) refuse an IPv4 octet with a leading zero,
 * because inet_aton would read "010" as octal 8; uClibc-ng's inet_pton takes
 * it as decimal 10. A node on such a libc would then accept, and route on, an
 * address the rest of the fleet rejects. This rejects it everywhere, in a
 * plain IPv4 address and in the dotted tail of an IPv6 one.
 *
 * @return As inet_pton: 1 on success, 0 if @p src does not parse, -1 for a
 *         bad @p af.
 */
int at_inet_pton(int af, const char *src, void *dst);

/** @} */ /* end of internal_utilities */

#endif /* AT_SOCKET_HELPERS_H */
