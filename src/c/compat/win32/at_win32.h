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

#ifndef AT_WIN32_H
#define AT_WIN32_H

/* The POSIX that AT's C is written against, on Windows (MinGW-w64, UCRT).
 *
 * Force-included into every Windows translation unit (CMakeLists.txt), so the
 * sources keep their POSIX spelling. The headers beside this one stand in for
 * the POSIX headers MinGW lacks (sys/socket.h, poll.h, uuid/uuid.h, ...) and
 * all lead here.
 *
 * The socket calls are thin wrappers that leave Winsock's error in errno, as
 * POSIX does, so every `errno == EAGAIN` and its kin keeps meaning what it
 * means on Linux, and that emulate the per-call MSG_DONTWAIT Winsock lacks.
 * A socket is closed with at_socket_close (utilities/socket_helpers.h): on
 * Windows it is not a file descriptor. */

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
/* wingdi.h #defines ERROR, which is one of AT's log levels. */
#ifndef NOGDI
#define NOGDI
#endif
#ifndef _CRT_RAND_S
#define _CRT_RAND_S        /* rand_s, for mkdtemp (win32.c) */
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00   /* AF_UNIX sockets need Windows 10 1803+ */
#endif

/* windows.h and winsock2.h typedef names AT uses for its own (the data type
 * tags UINT, INT, FLOAT and BOOL; the GROUP message type; libuuid's uuid_t).
 * Their typedefs are made under other names here, and every Windows header AT
 * needs is included now, under that rename: one that came in later would find
 * UINT no longer a type. */
/* BOOL has its own opt-out: minwindef.h then uses WINBOOL, through a BOOL
 * macro undefined again below. */
#define _NO_BOOL_TYPEDEF
#define UINT   at_w32_UINT
#define INT    at_w32_INT
#define FLOAT  at_w32_FLOAT
#define GROUP  at_w32_GROUP
#define uuid_t at_w32_uuid_t
#include <winsock2.h>
#include <ws2tcpip.h>
#include <afunix.h>
#include <windows.h>
/* minwindef.h pops BOOL back to undefined; iphlpapi.h's mprapi.h still spells it. */
#define BOOL WINBOOL
#include <iphlpapi.h>
#undef BOOL
#undef UINT
#undef INT
#undef FLOAT
#undef BOOL
#undef GROUP
#undef uuid_t

#include <direct.h>
#include <errno.h>
#include <io.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

/* What windows.h leaves defined that AT's names collide with. */
#undef DELETE
#undef OPTIONAL
#undef IN
#undef OUT
#undef interface
#undef small
#undef near
#undef far

#ifdef __cplusplus
extern "C" {
#endif

/* ---- errno from Winsock -------------------------------------------------- */

static inline int at_w32_wsa_errno(int wsa)
{
    switch (wsa)
    {
    /* EAGAIN, not EWOULDBLOCK: the UCRT gives them different values, and AT
     * (like most POSIX code, where they are equal) tests EAGAIN. */
    case WSAEWOULDBLOCK:    return EAGAIN;
    case WSAEINPROGRESS:    return EINPROGRESS;
    case WSAEALREADY:       return EALREADY;
    case WSAEINTR:          return EINTR;
    case WSAEBADF:          return EBADF;
    case WSAEACCES:         return EACCES;
    case WSAEFAULT:         return EFAULT;
    case WSAEINVAL:         return EINVAL;
    case WSAEMFILE:         return EMFILE;
    case WSAENOTSOCK:       return ENOTSOCK;
    case WSAEDESTADDRREQ:   return EDESTADDRREQ;
    case WSAEMSGSIZE:       return EMSGSIZE;
    case WSAEPROTOTYPE:     return EPROTOTYPE;
    case WSAENOPROTOOPT:    return ENOPROTOOPT;
    case WSAEPROTONOSUPPORT:return EPROTONOSUPPORT;
    case WSAEOPNOTSUPP:     return EOPNOTSUPP;
    case WSAEAFNOSUPPORT:   return EAFNOSUPPORT;
    case WSAEADDRINUSE:     return EADDRINUSE;
    case WSAEADDRNOTAVAIL:  return EADDRNOTAVAIL;
    case WSAENETDOWN:       return ENETDOWN;
    case WSAENETUNREACH:    return ENETUNREACH;
    case WSAENETRESET:      return ENETRESET;
    case WSAECONNABORTED:   return ECONNABORTED;
    case WSAECONNRESET:     return ECONNRESET;
    case WSAENOBUFS:        return ENOBUFS;
    case WSAEISCONN:        return EISCONN;
    case WSAENOTCONN:       return ENOTCONN;
    case WSAETIMEDOUT:      return ETIMEDOUT;
    case WSAECONNREFUSED:   return ECONNREFUSED;
    case WSAEHOSTUNREACH:   return EHOSTUNREACH;
    case WSAESHUTDOWN:      return EPIPE;
    default:                return EIO;
    }
}

static inline void at_w32_set_errno(void)
{
    errno = at_w32_wsa_errno(WSAGetLastError());
}

/* ---- types and names POSIX has and MinGW does not ----------------------- */

typedef long suseconds_t;

#ifndef EAI_SYSTEM
#define EAI_SYSTEM (-11)   /* never returned by Winsock's getaddrinfo */
#endif

static inline struct tm *gmtime_r(const time_t *t, struct tm *out)
{
    return gmtime_s(out, t) == 0 ? out : NULL;
}

static inline struct tm *localtime_r(const time_t *t, struct tm *out)
{
    return localtime_s(out, t) == 0 ? out : NULL;
}

/* ---- flags POSIX has and Winsock does not -------------------------------- */

/* Not a Winsock flag: the wrappers strip it and poll first instead. */
#define MSG_DONTWAIT 0x40000000
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0         /* no SIGPIPE on Windows */
#endif
#ifndef SHUT_RDWR
#define SHUT_RD   SD_RECEIVE
#define SHUT_WR   SD_SEND
#define SHUT_RDWR SD_BOTH
#endif

typedef ULONG nfds_t;

/* True when a socket can take a read (POLLIN) or write (POLLOUT) now. */
static inline int at_w32_ready(SOCKET s, short events)
{
    WSAPOLLFD p = {.fd = s, .events = events, .revents = 0};
    int r = WSAPoll(&p, 1, 0);
    return r > 0;
}

/* ---- the wrappers (defined before the macros that route calls here) ------ */

static inline int at_w32_socket(int domain, int type, int protocol)
{
    SOCKET s = socket(domain, type, protocol);
    if (s == INVALID_SOCKET)
    {
        at_w32_set_errno();
        return -1;
    }
    /* Windows socket handles fit in 32 bits; AT keeps them in an int. */
    return (int)s;
}

static inline int at_w32_bind(int s, const struct sockaddr *a, int len)
{
    if (bind((SOCKET)s, a, len) != 0) { at_w32_set_errno(); return -1; }
    return 0;
}

static inline int at_w32_listen(int s, int backlog)
{
    if (listen((SOCKET)s, backlog) != 0) { at_w32_set_errno(); return -1; }
    return 0;
}

static inline int at_w32_accept(int s, struct sockaddr *a, int *len)
{
    SOCKET c = accept((SOCKET)s, a, len);
    if (c == INVALID_SOCKET) { at_w32_set_errno(); return -1; }
    return (int)c;
}

static inline int at_w32_connect(int s, const struct sockaddr *a, int len)
{
    if (connect((SOCKET)s, a, len) != 0) { at_w32_set_errno(); return -1; }
    return 0;
}

static inline int at_w32_shutdown(int s, int how)
{
    if (shutdown((SOCKET)s, how) != 0) { at_w32_set_errno(); return -1; }
    return 0;
}

static inline int at_w32_would_block(int s, short events, int flags)
{
    if ((flags & MSG_DONTWAIT) && !at_w32_ready((SOCKET)s, events))
    {
        errno = EAGAIN;
        return 1;
    }
    return 0;
}

static inline ssize_t at_w32_send(int s, const void *buf, size_t len, int flags)
{
    if (at_w32_would_block(s, POLLOUT, flags))
        return -1;
    int n = send((SOCKET)s, (const char *)buf, (int)len, flags & ~MSG_DONTWAIT);
    if (n == SOCKET_ERROR) { at_w32_set_errno(); return -1; }
    return n;
}

static inline ssize_t at_w32_recv(int s, void *buf, size_t len, int flags)
{
    if (at_w32_would_block(s, POLLIN, flags))
        return -1;
    int n = recv((SOCKET)s, (char *)buf, (int)len, flags & ~MSG_DONTWAIT);
    if (n == SOCKET_ERROR) { at_w32_set_errno(); return -1; }
    return n;
}

static inline ssize_t at_w32_sendto(int s, const void *buf, size_t len, int flags,
                                    const struct sockaddr *to, int tolen)
{
    if (at_w32_would_block(s, POLLOUT, flags))
        return -1;
    int n = sendto((SOCKET)s, (const char *)buf, (int)len, flags & ~MSG_DONTWAIT,
                   to, tolen);
    if (n == SOCKET_ERROR) { at_w32_set_errno(); return -1; }
    return n;
}

static inline ssize_t at_w32_recvfrom(int s, void *buf, size_t len, int flags,
                                      struct sockaddr *from, int *fromlen)
{
    if (at_w32_would_block(s, POLLIN, flags))
        return -1;
    int n = recvfrom((SOCKET)s, (char *)buf, (int)len, flags & ~MSG_DONTWAIT,
                     from, fromlen);
    if (n == SOCKET_ERROR)
    {
        /* A datagram bigger than the buffer: POSIX truncates and returns the
         * part; Winsock fails it. Report the part, as AT's callers expect. */
        if (WSAGetLastError() == WSAEMSGSIZE)
            return (ssize_t)len;
        at_w32_set_errno();
        return -1;
    }
    return n;
}

static inline int at_w32_setsockopt(int s, int level, int name, const void *val, int len)
{
    /* POSIX takes a struct timeval for the socket timeouts; Winsock a DWORD of
     * milliseconds. */
    if (level == SOL_SOCKET && (name == SO_RCVTIMEO || name == SO_SNDTIMEO)
        && len == (int)sizeof(struct timeval))
    {
        const struct timeval *tv = (const struct timeval *)val;
        DWORD ms = (DWORD)(tv->tv_sec * 1000 + tv->tv_usec / 1000);
        if (ms == 0 && tv->tv_usec > 0)
            ms = 1;
        val = &ms;
        len = (int)sizeof(ms);
    }
    if (setsockopt((SOCKET)s, level, name, (const char *)val, len) != 0)
    {
        at_w32_set_errno();
        return -1;
    }
    return 0;
}

static inline int at_w32_getsockopt(int s, int level, int name, void *val, int *len)
{
    if (getsockopt((SOCKET)s, level, name, (char *)val, len) != 0)
    {
        at_w32_set_errno();
        return -1;
    }
    return 0;
}

static inline int at_w32_getsockname(int s, struct sockaddr *a, int *len)
{
    if (getsockname((SOCKET)s, a, len) != 0) { at_w32_set_errno(); return -1; }
    return 0;
}

static inline int at_w32_poll(struct pollfd *fds, nfds_t n, int timeout_ms)
{
    int r = WSAPoll(fds, n, timeout_ms);
    if (r == SOCKET_ERROR) { at_w32_set_errno(); return -1; }
    return r;
}

/* Object-like, not function-like: the names are also struct members and
 * parameters in AT (a transport's .send and .recv), and a rename has to apply
 * to every use in the translation unit alike. Not in C++, whose library uses
 * these names (std::bind); AT's one C++ file opens no socket. */
#ifndef __cplusplus
#define socket      at_w32_socket
#define bind        at_w32_bind
#define listen      at_w32_listen
#define accept      at_w32_accept
#define connect     at_w32_connect
#define shutdown    at_w32_shutdown
#define send        at_w32_send
#define recv        at_w32_recv
#define sendto      at_w32_sendto
#define recvfrom    at_w32_recvfrom
#define setsockopt  at_w32_setsockopt
#define getsockopt  at_w32_getsockopt
#define getsockname at_w32_getsockname
#define poll        at_w32_poll
#endif

/* ---- files and processes ------------------------------------------------- */
/* C only, like the socket names: libc++ has its own rename and mkdir. */
#ifndef __cplusplus

/* POSIX mkdir takes a mode; Windows has no permission bits to give it. */
#define mkdir(path, mode) _mkdir(path)

/* POSIX rename replaces an existing target atomically; the CRT's fails if the
 * target exists. AT renames every store into place over its last version. */
int at_w32_rename(const char *from, const char *to);
#define rename(from, to) at_w32_rename(from, to)

/* fsync: _commit flushes a CRT descriptor to disk. */
#define fsync(fd) _commit(fd)

/* realpath over _fullpath (which does not check the path exists; realpath
 * does, so neither does a caller get a path to nothing from this one). */
static inline char *realpath(const char *path, char *resolved)
{
    char *out = _fullpath(resolved, path, _MAX_PATH);
    if (out != NULL && _access(out, 0) != 0)
    {
        if (resolved == NULL)
            free(out);
        errno = ENOENT;
        return NULL;
    }
    return out;
}

/* setenv / unsetenv over the CRT's _putenv_s. */
static inline int setenv(const char *name, const char *value, int overwrite)
{
    if (!overwrite && getenv(name) != NULL)
        return 0;
    return _putenv_s(name, value) == 0 ? 0 : -1;
}

static inline int unsetenv(const char *name)
{
    return _putenv_s(name, "") == 0 ? 0 : -1;
}

/* timegm: UTC broken-down time to time_t. */
#define timegm _mkgmtime

/* mkdtemp: _mktemp_s fills the XXXXXX, then the directory is made. */
char *mkdtemp(char *tmpl);

/* strptime is POSIX only; AT parses ISO-8601 with it. */
char *strptime(const char *s, const char *format, struct tm *tm);

#endif /* !__cplusplus */

#ifndef SIGKILL
#define SIGKILL 9
#endif

#ifdef __cplusplus
}
#endif

#endif /* _WIN32 */
#endif /* AT_WIN32_H */
