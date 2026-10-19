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

#ifndef AT_MESSAGE_IPC_H
#define AT_MESSAGE_IPC_H

/* The delivery paths behind message.c's one API (private to the messaging
 * code; not installed).
 *
 *   unix datagram   the original: every queue a bound AF_UNIX SOCK_DGRAM
 *                   socket. Used between forked processes (POSIX default).
 *   in-process      a named, bounded FIFO in this process's memory, for the
 *                   queues of subsystems that run as threads (AT_IN_PROCESS;
 *                   always on Windows). message_inproc.c.
 *   stream          an AF_UNIX SOCK_STREAM listener carrying length-framed
 *                   messages, for the queues another process reaches (the app
 *                   link) where datagrams do not exist: Windows, whose
 *                   AF_UNIX is stream only (AT_IPC_STREAM on POSIX).
 *                   message_stream.c.
 *
 * Every path carries the same frame: an 8-byte big-endian length, then that
 * many bytes of the protobuf the datagram path sends. The in-process path keeps
 * serializing too, so it exercises exactly the encode/decode the wire does.
 *
 * A queue_t is never resized for this (it is embedded by value in at_node_t and
 * mirrored by the Python cffi cdef): which path owns a queue is kept in each
 * path's own table, keyed by the queue_t's address. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <sys/un.h>

#include "exception.h"
#include "message.h"

/* The frame length is big-endian on every path (what htonll gave the datagram
 * path on a little-endian host); spelled out so no platform's htonll is
 * needed. */
static inline uint64_t ntohll_portable(uint64_t be)
{
    const uint8_t *b = (const uint8_t *)&be;
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v = (v << 8) | b[i];
    return v;
}

static inline uint64_t htonll_portable(uint64_t v)
{
    uint64_t be;
    uint8_t *b = (uint8_t *)&be;
    for (int i = 7; i >= 0; i--)
    {
        b[i] = (uint8_t)(v & 0xFF);
        v >>= 8;
    }
    return be;
}

/* The largest frame any path carries, header included (see message.c). */
#define AT_IPC_FRAME_MAX 212992

/* Returned by a path's send when the target is not one of its queues, so the
 * dispatcher tries the next path. Never escapes message.c. */
#define AT_IPC_NOT_MINE (-2)

bool at_ipc_stream_link(void);

/* ---- in-process ---------------------------------------------------------- */
int  inproc_open(const char *key, queue_t *q);
bool inproc_owns(const queue_t *q);
bool inproc_bound(const char *key);
/* 0, EAGAIN (full, non-blocking), or AT_IPC_NOT_MINE (no such queue here). */
int  inproc_send(const char *key, const uint8_t *hdr, size_t hdr_len,
                 const uint8_t *data, size_t data_len, bool blocking);
/* 0 with *len set, or ENOMSG. */
int  inproc_recv(queue_t *q, uint8_t *buf, size_t cap, size_t *len, bool blocking);
void inproc_close(queue_t *q);

/* ---- stream -------------------------------------------------------------- */
int  stream_listen(const char *key, queue_t *q);
bool stream_owns(const queue_t *q);
bool stream_bound(const char *key);
/* 0, EAGAIN, AT_IPC_NOT_MINE (no stream queue by that name), or -1 with the
 * exception set. */
int  stream_send(const char *key, const uint8_t *hdr, size_t hdr_len,
                 const uint8_t *data, size_t data_len, bool blocking);
/* 0 with *len set, ENOMSG, or -1 with the exception set. */
int  stream_recv(queue_t *q, uint8_t *buf, size_t cap, size_t *len, bool blocking);
void stream_close(queue_t *q);

/* The socket path for a queue key (message.c), and the stream variant of it. */
int unix_addr(const char *key, struct sockaddr_un *addr);
int stream_addr(const char *key, struct sockaddr_un *addr);

#endif /* AT_MESSAGE_IPC_H */
