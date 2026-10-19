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

/* The stream path: a queue another process reaches, where unix datagrams do
 * not exist (Windows' AF_UNIX is stream only; $AT_IPC_STREAM selects it on
 * POSIX, which is how it is tested there).
 *
 * The receiving queue is an AF_UNIX SOCK_STREAM listener at
 * $root/var/at/<key>.s. The distinct name lets a sender tell a stream queue
 * from a datagram one with a stat, not a connect per send, and keeps the two
 * kinds from taking each other's socket file. Each message is one frame: the
 * datagram path's bytes, an 8-byte big-endian length then that much protobuf.
 *
 * What the datagram queues gave and this keeps:
 *   - a sender to a queue nobody holds is refused (connect fails), so
 *     messaging_bound and the §2.71 hold still tell "no app" from "app";
 *   - a full receiver pushes back: a non-blocking send whose connection is
 *     not writable answers EAGAIN, as a full datagram queue did;
 *   - only someone who may open the socket file may send, as before.
 * A sender keeps one connection per target and reconnects once if the
 * receiver has gone and come back. Frames from several threads to the same
 * target are serialized on that connection's lock, so none interleave. */

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "message_ipc.h"
#include "socket_helpers.h"
#include "util.h"

#define STREAM_MAX_CONNS   32   /* senders one queue serves at once */
#define STREAM_MAX_TARGETS 16   /* queues one process sends to */
#define STREAM_SEND_TIMEOUT_MS 2000

/* ---- receiving side ------------------------------------------------------ */

typedef struct
{
    int fd;
    uint8_t *buf;      /* AT_IPC_FRAME_MAX bytes */
    size_t have;
} stream_conn_t;

typedef struct stream_q
{
    queue_t *owner;     /* NULL when the slot is free */
    int listen_fd;
    char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    stream_conn_t conns[STREAM_MAX_CONNS];
    int nconns;
    int next;           /* round-robin start, so one busy sender cannot starve another */
    pthread_mutex_t mu;
} stream_q_t;

#define STREAM_MAX_QUEUES 8
static stream_q_t g_queues[STREAM_MAX_QUEUES];
static pthread_mutex_t g_queues_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t g_init_once = PTHREAD_ONCE_INIT;

static void _init(void)
{
    for (int i = 0; i < STREAM_MAX_QUEUES; i++)
        pthread_mutex_init(&g_queues[i].mu, NULL);
}

static stream_q_t *_queue_of(const queue_t *q)
{
    if (q == NULL)
        return NULL;
    pthread_once(&g_init_once, _init);
    stream_q_t *found = NULL;
    pthread_mutex_lock(&g_queues_mu);
    for (int i = 0; i < STREAM_MAX_QUEUES; i++)
        if (g_queues[i].owner == q)
            found = &g_queues[i];
    pthread_mutex_unlock(&g_queues_mu);
    return found;
}

int stream_addr(const char *key, struct sockaddr_un *addr)
{
    if (key == NULL)
        return EXCEPTION(EINVAL);
    char skey[MSG_KEY_LEN + 3];
    int n = snprintf(skey, sizeof(skey), "%s.s", key);
    if (n < 0 || (size_t)n >= sizeof(skey))
        return EXCEPTION(ENAMETOOLONG);
    return unix_addr(skey, addr);
}

int stream_listen(const char *key, queue_t *q)
{
    if (key == NULL || q == NULL)
        return EXCEPTION(EINVAL);
    q->fd = -1;   /* a caller's failure path may close whatever is left here */
    pthread_once(&g_init_once, _init);
    struct sockaddr_un local;
    if (stream_addr(key, &local) != 0)
        return -1;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return SYS_EXCEPTION();
    /* Same takeover rule as the datagram path: a crashed holder's file would
     * otherwise block the name for good. */
    if (unlink(local.sun_path) != 0 && errno != ENOENT)
    {
        at_socket_close(fd);
        return SYS_EXCEPTION();
    }
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) != 0
        || listen(fd, STREAM_MAX_CONNS) != 0
        || at_socket_set_nonblock(fd) != 0)
    {
        int saved = errno;
        at_socket_close(fd);
        errno = saved;
        return SYS_EXCEPTION();
    }

    pthread_mutex_lock(&g_queues_mu);
    stream_q_t *s = NULL;
    for (int i = 0; i < STREAM_MAX_QUEUES && s == NULL; i++)
        if (g_queues[i].owner == NULL)
            s = &g_queues[i];
    if (s == NULL)
    {
        pthread_mutex_unlock(&g_queues_mu);
        at_socket_close(fd);
        unlink(local.sun_path);
        return EXCEPTION(EMFILE);
    }
    pthread_mutex_lock(&s->mu);
    s->owner = q;
    s->listen_fd = fd;
    memcpy(s->path, local.sun_path, sizeof(s->path));
    s->nconns = 0;
    s->next = 0;
    pthread_mutex_unlock(&s->mu);
    pthread_mutex_unlock(&g_queues_mu);

    strncpy(q->key, key, MSG_KEY_LEN);
    q->key[MSG_KEY_LEN] = '\0';
    q->fd = fd;
    struct stat st;
    if (stat(local.sun_path, &st) == 0)
    {
        q->bound_dev = st.st_dev;
        q->bound_ino = st.st_ino;
    }
    else
    {
        q->bound_dev = 0;
        q->bound_ino = 0;
    }
    return 0;
}

bool stream_owns(const queue_t *q)
{
    return _queue_of(q) != NULL;
}

/* Caller holds s->mu. */
static void _drop_conn(stream_q_t *s, int i)
{
    at_socket_close(s->conns[i].fd);
    free(s->conns[i].buf);
    s->conns[i] = s->conns[s->nconns - 1];
    s->nconns--;
    if (s->next >= s->nconns)
        s->next = 0;
}

/* Caller holds s->mu. */
static void _accept_pending(stream_q_t *s)
{
    while (s->nconns < STREAM_MAX_CONNS)
    {
        int c = accept(s->listen_fd, NULL, NULL);
        if (c < 0)
            return;   /* EAGAIN: none waiting (or a transient error; retried next pass) */
        uint8_t *buf = malloc(AT_IPC_FRAME_MAX);
        if (buf == NULL || at_socket_set_nonblock(c) != 0)
        {
            free(buf);
            at_socket_close(c);
            continue;
        }
        s->conns[s->nconns].fd = c;
        s->conns[s->nconns].buf = buf;
        s->conns[s->nconns].have = 0;
        s->nconns++;
    }
}

/* Read what has arrived on one connection; true once it holds a whole frame.
 * Caller holds s->mu. Sets *gone when the sender hung up or broke the framing. */
static bool _fill(stream_conn_t *c, bool *gone)
{
    *gone = false;
    for (;;)
    {
        size_t want = sizeof(uint64_t);
        if (c->have >= sizeof(uint64_t))
        {
            uint64_t be;
            memcpy(&be, c->buf, sizeof(be));
            uint64_t data_len = ntohll_portable(be);
            if (data_len > AT_IPC_FRAME_MAX - sizeof(uint64_t))
            {
                *gone = true;   /* not a frame of ours: drop the connection */
                return false;
            }
            want = sizeof(uint64_t) + (size_t)data_len;
        }
        if (c->have >= want && c->have >= sizeof(uint64_t))
            return true;
        ssize_t n = recv(c->fd, (char *)c->buf + c->have, want - c->have, 0);
        if (n > 0)
        {
            c->have += (size_t)n;
            continue;
        }
        if (n == 0)
            *gone = true;
        else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
            *gone = true;
        return false;
    }
}

static size_t _frame_len(const stream_conn_t *c)
{
    uint64_t be;
    memcpy(&be, c->buf, sizeof(be));
    return sizeof(uint64_t) + (size_t)ntohll_portable(be);
}

int stream_recv(queue_t *q, uint8_t *buf, size_t cap, size_t *len, bool blocking)
{
    stream_q_t *s = _queue_of(q);
    if (s == NULL)
        return EXCEPTION(ENOTSOCK);
    for (;;)
    {
        pthread_mutex_lock(&s->mu);
        if (s->owner != q)
        {
            pthread_mutex_unlock(&s->mu);
            return ENOMSG;
        }
        _accept_pending(s);
        for (int k = 0; k < s->nconns; k++)
        {
            int i = (s->next + k) % s->nconns;
            stream_conn_t *c = &s->conns[i];
            bool gone = false;
            if (_fill(c, &gone))
            {
                size_t flen = _frame_len(c);
                int rc = 0;
                if (flen > cap)
                    rc = EXCEPTION(EMSGSIZE);
                else
                {
                    memcpy(buf, c->buf, flen);
                    *len = flen;
                }
                memmove(c->buf, c->buf + flen, c->have - flen);
                c->have -= flen;
                s->next = (i + 1) % s->nconns;
                pthread_mutex_unlock(&s->mu);
                return rc;
            }
            if (gone)
            {
                _drop_conn(s, i);
                k--;
            }
        }
        if (!blocking)
        {
            pthread_mutex_unlock(&s->mu);
            return ENOMSG;
        }
        /* Wait for a new sender or new bytes, without holding the lock. */
        struct pollfd pfds[STREAM_MAX_CONNS + 1];
        int n = 0;
        pfds[n].fd = s->listen_fd;
        pfds[n].events = POLLIN;
        n++;
        for (int i = 0; i < s->nconns; i++, n++)
        {
            pfds[n].fd = s->conns[i].fd;
            pfds[n].events = POLLIN;
        }
        pthread_mutex_unlock(&s->mu);
        (void)at_poll_eintr(pfds, (nfds_t)n, 200);
    }
}

void stream_close(queue_t *q)
{
    stream_q_t *s = _queue_of(q);
    if (s == NULL)
        return;
    pthread_mutex_lock(&g_queues_mu);
    pthread_mutex_lock(&s->mu);
    while (s->nconns > 0)
        _drop_conn(s, s->nconns - 1);
    at_socket_close(s->listen_fd);
    /* Our own file only, as messaging_qclose does for a datagram queue. */
    struct stat st;
    if (q->bound_ino == 0
        || (stat(s->path, &st) == 0 && st.st_dev == q->bound_dev
            && st.st_ino == q->bound_ino))
        unlink(s->path);
    s->owner = NULL;
    s->listen_fd = -1;
    pthread_mutex_unlock(&s->mu);
    pthread_mutex_unlock(&g_queues_mu);
    q->fd = -1;
}

/* ---- sending side -------------------------------------------------------- */

typedef struct
{
    char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    int fd;
    pthread_mutex_t mu;
    bool used;
} stream_target_t;

static stream_target_t g_targets[STREAM_MAX_TARGETS];
static pthread_mutex_t g_targets_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t g_targets_once = PTHREAD_ONCE_INIT;

static void _targets_init(void)
{
    for (int i = 0; i < STREAM_MAX_TARGETS; i++)
    {
        g_targets[i].fd = -1;
        pthread_mutex_init(&g_targets[i].mu, NULL);
    }
}

/* The cached connection slot for a socket path, claiming a free one (or the
 * first, closed, if all are taken). */
static stream_target_t *_target(const char *path)
{
    pthread_once(&g_targets_once, _targets_init);
    pthread_mutex_lock(&g_targets_mu);
    stream_target_t *t = NULL;
    for (int i = 0; i < STREAM_MAX_TARGETS && t == NULL; i++)
        if (g_targets[i].used && strcmp(g_targets[i].path, path) == 0)
            t = &g_targets[i];
    for (int i = 0; i < STREAM_MAX_TARGETS && t == NULL; i++)
        if (!g_targets[i].used)
            t = &g_targets[i];
    if (t == NULL)
    {
        t = &g_targets[0];
        pthread_mutex_lock(&t->mu);
        if (t->fd >= 0)
            at_socket_close(t->fd);
        t->fd = -1;
        pthread_mutex_unlock(&t->mu);
    }
    if (!t->used || strcmp(t->path, path) != 0)
    {
        pthread_mutex_lock(&t->mu);
        strncpy(t->path, path, sizeof(t->path) - 1);
        t->path[sizeof(t->path) - 1] = '\0';
        t->used = true;
        pthread_mutex_unlock(&t->mu);
    }
    pthread_mutex_unlock(&g_targets_mu);
    return t;
}

static int _connect(const char *path)
{
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    size_t n = strlen(path);
    if (n >= sizeof(addr.sun_path))
    {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(addr.sun_path, path, n + 1);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        int saved = errno;
        at_socket_close(fd);
        errno = saved;
        return -1;
    }
    (void)at_socket_nosigpipe(fd);
    (void)at_set_sndtimeo(fd, STREAM_SEND_TIMEOUT_MS, NULL);
    return fd;
}

static int _send_all(int fd, const uint8_t *p, size_t n)
{
    while (n > 0)
    {
        ssize_t w = at_send_eintr(fd, p, n, MSG_NOSIGNAL);
        if (w <= 0)
            return -1;
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

bool stream_bound(const char *key)
{
    struct sockaddr_un addr;
    if (stream_addr(key, &addr) != 0)
        return false;
    struct stat st;
    if (stat(addr.sun_path, &st) != 0)
        return false;
    int fd = _connect(addr.sun_path);
    if (fd < 0)
        return false;
    at_socket_close(fd);
    return true;
}

int stream_send(const char *key, const uint8_t *hdr, size_t hdr_len,
                const uint8_t *data, size_t data_len, bool blocking)
{
    struct sockaddr_un addr;
    if (stream_addr(key, &addr) != 0)
        return -1;
    struct stat st;
    if (stat(addr.sun_path, &st) != 0)
        return AT_IPC_NOT_MINE;

    stream_target_t *t = _target(addr.sun_path);
    pthread_mutex_lock(&t->mu);
    for (int attempt = 0; attempt < 2; attempt++)
    {
        if (t->fd < 0)
        {
            t->fd = _connect(addr.sun_path);
            if (t->fd < 0)
            {
                pthread_mutex_unlock(&t->mu);
                return SYS_EXCEPTION();   /* ECONNREFUSED: a stale file, nobody holds it */
            }
        }
        if (!blocking)
        {
            struct pollfd p = {.fd = t->fd, .events = POLLOUT};
            int r = at_poll_eintr(&p, 1, 0);
            if (r == 0)
            {
                pthread_mutex_unlock(&t->mu);
                return EAGAIN;    /* the receiver is not keeping up */
            }
            if (r < 0 || (p.revents & (POLLERR | POLLHUP | POLLNVAL)))
            {
                at_socket_close(t->fd);
                t->fd = -1;
                continue;         /* the receiver went away; reconnect once */
            }
        }
        if (_send_all(t->fd, hdr, hdr_len) == 0 && _send_all(t->fd, data, data_len) == 0)
        {
            pthread_mutex_unlock(&t->mu);
            return 0;
        }
        /* A broken connection mid-frame: the receiver drops the partial frame
         * with the connection, so a fresh one can carry the whole message. */
        at_socket_close(t->fd);
        t->fd = -1;
    }
    pthread_mutex_unlock(&t->mu);
    return SYS_EXCEPTION();
}
