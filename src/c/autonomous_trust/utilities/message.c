/********************
 *  Copyright 2024 TekFive, Inc., Sean M. Brennan, and contributors
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

#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "config/configuration.h"
#include "util.h"
#include "structures/data.h"
#include "structures/map.h"
#include "message.h"
#include "msg_types_priv.h"
#include "message_ipc.h"
#include "socket_helpers.h"

/* 108 on Linux, 104 on Darwin and the BSDs. */
#define SOCK_PATH_LEN ((int)sizeof(((struct sockaddr_un *)0)->sun_path))

/* The largest datagram a queue carries, header included: Linux's default unix
 * socket send buffer (net.core.wmem_default), which has always been the real
 * ceiling there (a bigger send fails with EMSGSIZE). Darwin's default is 2048
 * bytes (net.local.dgram.maxdgram), far below what AT sends, so messaging_init
 * raises every queue to this; on Linux the defaults already meet it, and
 * raising a Linux send buffer past them would change how many datagrams queue
 * before EAGAIN. */
#define AT_IPC_DGRAM_MAX AT_IPC_FRAME_MAX
/* Darwin queues a datagram in the RECEIVER's buffer (default 4096 bytes), so
 * that is what has to hold several of the largest. Linux does not limit unix
 * datagrams by it (measured: a raised receive buffer queues no more). */
#define AT_IPC_RCVBUF_MIN (4 * AT_IPC_DGRAM_MAX)

/*@
  axiomatic messaging_thread_safety {
    // Thread safety note: Unix domain SOCK_DGRAM provides atomic
    // datagram delivery.  sendmsg/recvfrom on separate file descriptors
    // are safe without additional locks.  The my_q static pointer is
    // set once via messaging_assign() before any concurrent use.
    // WP cannot verify concurrent properties; this axiom documents
    // the design invariant.
    axiom datagram_atomicity:
      \true;
  }
*/

static size_t _max_msg_size = DEFAULT_MAX_MSG_SIZE;

size_t messaging_max_size(void)
{
    return _max_msg_size;
}

void messaging_set_max_size(size_t size)
{
    if (size > 0)
        _max_msg_size = size;
}

/* Which delivery paths this process uses (message_ipc.h), read once. */
static bool g_in_process = false;
static bool g_stream_link = false;
static pthread_once_t g_mode_once = PTHREAD_ONCE_INIT;

#ifndef _WIN32
static bool _env_on(const char *name)
{
    const char *v = getenv(name);
    return v != NULL && strcmp(v, "1") == 0;
}
#endif

static void _mode_init(void)
{
#ifdef _WIN32
    /* No fork and no unix datagrams: always threads, always the stream link. */
    g_in_process = true;
    g_stream_link = true;
#else
    g_in_process = _env_on("AT_IN_PROCESS");
    g_stream_link = _env_on("AT_IPC_STREAM");
#endif
}

bool messaging_in_process(void)
{
    (void)pthread_once(&g_mode_once, _mode_init);
    return g_in_process;
}

bool at_ipc_stream_link(void)
{
    (void)pthread_once(&g_mode_once, _mode_init);
    return g_stream_link;
}

/* Darwin's <arpa/inet.h> has its own. */
#ifndef htonll
#define htonll(x) ((1 == htonl(1)) ? (x) : (((uint64_t)htonl((x) & 0xFFFFFFFFUL)) << 32) | htonl((uint32_t)((x) >> 32)))
#endif

#ifndef ntohll
#define ntohll(x) ((1 == ntohl(1)) ? (x) : (((uint64_t)ntohl((x) & 0xFFFFFFFFUL)) << 32) | ntohl((uint32_t)((x) >> 32)))
#endif

/* The receive buffer, one per thread (the blocking receives run on several),
 * freed when its thread exits. */
static pthread_key_t g_frame_key;
static pthread_once_t g_frame_once = PTHREAD_ONCE_INIT;

static void _frame_key_init(void)
{
    (void)pthread_key_create(&g_frame_key, free);
}

static uint8_t *_recv_frame(void)
{
    (void)pthread_once(&g_frame_once, _frame_key_init);
    uint8_t *frame = pthread_getspecific(g_frame_key);
    if (frame == NULL)
    {
        frame = malloc(AT_IPC_DGRAM_MAX);
        if (frame != NULL && pthread_setspecific(g_frame_key, frame) != 0)
        {
            free(frame);
            frame = NULL;
        }
    }
    return frame;
}

#ifndef _WIN32
/* Raise a socket buffer to at least `want`, never lower it: the defaults are
 * left alone wherever they already suffice. */
static void _ensure_sockbuf(int fd, int opt, int want)
{
    int have = 0;
    socklen_t len = sizeof(have);
    if (getsockopt(fd, SOL_SOCKET, opt, &have, &len) == 0 && have >= want)
        return;
    (void)setsockopt(fd, SOL_SOCKET, opt, &want, sizeof(want));
}
#endif

/*@
  requires key != \null && \valid_read(key);
  requires \valid(addr);
  assigns addr->sun_family, addr->sun_path[0 .. sizeof(addr->sun_path) - 1];
  behavior success:
    ensures \result == 0;
    ensures addr->sun_family == AF_UNIX;
  behavior failure:
    ensures \result == -1;
  disjoint behaviors;
*/
/* The socket path is built here and nowhere else. Two constructors of it is how
 * the startup overflow happened: `get_data_dir` was told this buffer held 255 bytes
 * when it holds 108, so a long AUTONOMOUS_TRUST_ROOT wrote past the end of the
 * caller's stack frame. Both bounds are now this function's own, and a root that
 * does not fit is REFUSED — a truncated socket path is a different socket, which
 * is the same rule `at_app_node_build_config` applies to a queue name. */
int unix_addr(const char *key, struct sockaddr_un *addr)
{
    if (key == NULL || addr == NULL)
        return EXCEPTION(EINVAL);

    char path[SOCK_PATH_LEN] = {0};
    int dir_len = get_data_dir(path, sizeof(path));
    if (dir_len < 0)
    {
        /* path_join refused: the data directory alone does not fit in a
         * sun_path. Name the cause, because the fix is the configuration and
         * nothing downstream can infer that from a bind failure. */
        log_error(NULL,
                  "AUTONOMOUS_TRUST_ROOT is too long: the data directory under \"%s\" "
                  "does not fit in a unix socket path (%d bytes). Use a shorter root.\n",
                  rootDir(), SOCK_PATH_LEN);
        return EXCEPTION(ENAMETOOLONG);
    }

    /* `path[strlen(path)] = '/'` used to go here, overwriting the NUL without
     * replacing it — after which strncat's own strlen ran off the end of the
     * buffer. Join with the bound instead, and refuse if the key does not fit:
     * at 99 bytes of root the old code silently dropped the queue name
     * ENTIRELY and left the caller binding a directory. */
    size_t used = (size_t)dir_len;
    size_t need = used + 1 + strlen(key) + 1;
    if (need > sizeof(path))
    {
        log_error(NULL,
                  "socket path for queue \"%s\" needs %zu bytes and a unix socket path "
                  "holds %d; AUTONOMOUS_TRUST_ROOT is too long for this queue name.\n",
                  key, need, SOCK_PATH_LEN);
        return EXCEPTION(ENAMETOOLONG);
    }
    path[used] = '/';
    memcpy(path + used + 1, key, strlen(key) + 1);

    addr->sun_family = AF_UNIX;
    /* Fits by construction now; the copy stays bounded so this cannot become the
     * next place the invariant is assumed rather than enforced. */
    memcpy(addr->sun_path, path, strlen(path) + 1);
    return 0;
}

/*@
  requires key != \null && \valid_read(key);
  assigns \nothing;
*/
bool messaging_bound(const char *key)
{
    if (key == NULL || key[0] == '\0')
        return false;
    if (messaging_in_process() && inproc_bound(key))
        return true;
    if (at_ipc_stream_link() && stream_bound(key))
        return true;

#ifdef _WIN32
    return false;   /* no unix datagrams: the paths above are all there is */
#else
    struct sockaddr_un addr = {0};
    if (unix_addr(key, &addr) != 0)
        return false;

    /* A `stat` of the path would be wrong, and the difference matters: a daemon
     * that died leaves its socket FILE behind, and a file check would call that
     * ready. `connect` on a SOCK_DGRAM unix socket succeeds only if something is
     * bound at the other end, and gives ECONNREFUSED for a stale file. It sends
     * nothing, so probing has no effect on whoever is listening. */
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0)
        return false;
    bool bound = connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0;
    at_socket_close(fd);
    return bound;
#endif
}

/*@
  requires id != \null && \valid_read(id);
  requires \valid(queue);
  assigns queue->key[0 .. MSG_KEY_LEN - 1], queue->fd;
  behavior success:
    ensures \result == 0;
    ensures queue->fd >= 0;
  behavior failure:
    ensures \result == -1;
  disjoint behaviors;
*/
#ifndef _WIN32
/* Frama-C: skipped — [solver-timeout] strncpy separation + assigns preconditions */
static int _dgram_init(const char *id, queue_t *queue)
{
    strncpy(queue->key, id, MSG_KEY_LEN - 1);
    /* Cleared up front: callers hand us stack queues, and an early return
     * below must not leave close() comparing against garbage. */
    queue->bound_dev = 0;
    queue->bound_ino = 0;

    queue->fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (queue->fd < 0)
        return SYS_EXCEPTION();
    _ensure_sockbuf(queue->fd, SO_SNDBUF, AT_IPC_DGRAM_MAX);
    _ensure_sockbuf(queue->fd, SO_RCVBUF, AT_IPC_RCVBUF_MIN);

    struct sockaddr_un local;
    if (unix_addr(id, &local) != 0)
    {
        /* Propagate, do NOT re-raise. `unix_addr` has already recorded exactly
         * why (ENAMETOOLONG for a root that cannot fit, EINVAL for a bad
         * argument), and `SYS_EXCEPTION()` here would overwrite that with
         * whatever `errno` happened to hold — `_set_exception` does not touch
         * errno, so the reason was replaced by an unrelated stale value. A
         * caller cannot act on "too long" it never gets told.
         *
         * The `close` is the other half: this path became reachable when
         * `unix_addr` started refusing instead of overflowing, and without it a
         * caller that retries leaks a descriptor per attempt. */
        at_socket_close(queue->fd);
        queue->fd = -1;
        return -1;
    }

    if (unlink(local.sun_path) != 0)
    {
        if (errno != ENOENT)
            return SYS_EXCEPTION();
    }

    if (bind(queue->fd, (struct sockaddr *)&local, sizeof(struct sockaddr_un)) != 0)
    {
        log_error(NULL, "Bind address %s\n", local.sun_path);
        return SYS_EXCEPTION();
    }
    /* Remember WHICH file this bind created, so messaging_qclose removes ours
     * and not a successor's. fstat on the socket fd would report the socket
     * inode, not this directory entry, so the path is what must be stat'd —
     * and it must be stat'd HERE, while the entry is certainly still ours. */
    struct stat st;
    if (stat(local.sun_path, &st) == 0)
    {
        queue->bound_dev = st.st_dev;
        queue->bound_ino = st.st_ino;
    }
    else
    {
        queue->bound_dev = 0;
        queue->bound_ino = 0;
    }
    return 0;
}

#endif /* !_WIN32 */

int messaging_init(const char *id, queue_t *queue)
{
    /* A queue of this process's own subsystems: threads of this process when
     * they run in-process, sockets between forked processes otherwise. */
    if (messaging_in_process())
        return inproc_open(id, queue);
#ifdef _WIN32
    return EXCEPTION(ENOSYS);   /* unreachable: Windows is always in-process */
#else
    return _dgram_init(id, queue);
#endif
}

int messaging_init_external(const char *id, queue_t *queue)
{
    /* A queue another process sends to (the app link). */
    if (at_ipc_stream_link())
        return stream_listen(id, queue);
#ifdef _WIN32
    return EXCEPTION(ENOSYS);   /* unreachable: Windows always uses the stream link */
#else
    return _dgram_init(id, queue);
#endif
}

/* The queue a messaging_recv reads. In-process every subsystem thread assigns
 * its own, so the receive side is per thread; the process-wide one stays as
 * the fallback, and is the only one a forked process has. Sending never needs
 * either in-process (helper threads of a subsystem send freely). */
static queue_t *my_q = NULL;
static _Thread_local queue_t *tl_q = NULL;

void messaging_assign(queue_t *queue)
{
    my_q = queue;
    tl_q = queue;
}

static queue_t *_assigned(void)
{
    if (messaging_in_process() && tl_q != NULL)
        return tl_q;
    return my_q;
}

#ifndef _WIN32
/* An unbound datagram socket to send from, for a sender with no datagram
 * queue of its own: any thread of an in-process node. sendmsg on one socket
 * from several threads is safe; each datagram is atomic. */
static int g_send_fd = -1;
static pthread_once_t g_send_fd_once = PTHREAD_ONCE_INIT;

static void _send_fd_init(void)
{
    g_send_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (g_send_fd >= 0)
        _ensure_sockbuf(g_send_fd, SO_SNDBUF, AT_IPC_DGRAM_MAX);
}
#endif

/* Frama-C: skipped — [syscall] mq_receive POSIX message queue */
int messaging_recv_from(generic_msg_t *msg, struct sockaddr_storage *their_addr, bool blocking)
{
    queue_t *q = _assigned();
    if (q == NULL)
        return EXCEPTION(EMSG_NOCONN);
    return messaging_recv_on(q, msg, their_addr, blocking);
}

/*@
  requires \valid(q);
  requires q->fd > 0;
  requires \valid(msg);
  requires their_addr == \null || \valid(their_addr);
  assigns msg->type, msg->size, msg->info;
  behavior success:
    ensures \result == 0;
  behavior no_message:
    ensures \result == ENOMSG;
  behavior error:
    ensures \result == -1;
  disjoint behaviors;
*/
/* Frama-C: skipped — [syscall] mq_receive POSIX message queue */
/* Decode one received frame (any path's): the length header, then the
 * protobuf body. */
static int _parse_frame(uint8_t *frame, size_t numbytes, generic_msg_t *msg)
{
    if (numbytes < sizeof(size_t))
        return -1;  /* runt */
    size_t net_size;
    memcpy(&net_size, frame, sizeof(size_t));
    size_t data_size = ntohll(net_size);
    size_t payload_len = numbytes - sizeof(size_t);
    if (payload_len < data_size)
        data_size = payload_len;  /* clamp to actual received bytes */

    int ret = proto_to_generic_msg(frame + sizeof(size_t), data_size, msg);
    return (ret != 0) ? -1 : 0;
}

int messaging_recv_on(queue_t *q, generic_msg_t *msg, struct sockaddr_storage *their_addr, bool blocking)
{
    bool inproc = messaging_in_process() && inproc_owns(q);
    if (inproc || (at_ipc_stream_link() && stream_owns(q)))
    {
        uint8_t *frame = _recv_frame();
        if (frame == NULL)
            return EXCEPTION(ENOMEM);
        size_t len = 0;
        int rc = inproc ? inproc_recv(q, frame, AT_IPC_DGRAM_MAX, &len, blocking)
                        : stream_recv(q, frame, AT_IPC_DGRAM_MAX, &len, blocking);
        if (rc != 0)
            return rc;   /* ENOMSG, or -1 with the exception set */
        if (their_addr != NULL)
            memset(their_addr, 0, sizeof(*their_addr));
        return _parse_frame(frame, len, msg);
    }

#ifdef _WIN32
    (void)their_addr;
    return EXCEPTION(ENOTSOCK);   /* not a queue of either path above */
#else
    if (q->fd <= 0)
        return EXCEPTION(ENOTSOCK);

    int flags = 0;
    if (!blocking)
        flags = MSG_DONTWAIT;

    /* One receive into a buffer that holds the largest datagram. It used to
     * peek with MSG_PEEK|MSG_TRUNC to learn the length first, but only Linux
     * reports the real length that way: Darwin returns 0, which read as a runt
     * and left that datagram at the head of the queue for good, so the queue
     * never delivered again. */
    uint8_t *frame = _recv_frame();
    if (frame == NULL)
        return EXCEPTION(ENOMEM);

    struct iovec iov = { .iov_base = frame, .iov_len = AT_IPC_DGRAM_MAX };
    struct msghdr mh = {
        .msg_name    = their_addr,
        .msg_namelen = their_addr ? sizeof(struct sockaddr_storage) : 0,
        .msg_iov     = &iov,
        .msg_iovlen  = 1,
    };
    ssize_t numbytes = recvmsg(q->fd, &mh, flags);
    if (numbytes < 0)
    {
        if (errno == EAGAIN)
            return ENOMSG;
        return SYS_EXCEPTION();
    }
    if (mh.msg_flags & MSG_TRUNC)
    {
        /* Bigger than any sender's buffer allows, so it cannot happen between
         * AT queues; refuse it rather than parse a cut message. Consumed
         * either way, so the queue moves on. */
        log_error(NULL, "Dropped an oversize message on queue %s (> %d bytes)\n",
                  q->key, AT_IPC_DGRAM_MAX);
        return -1;
    }
    return _parse_frame(frame, (size_t)numbytes, msg);
#endif
}

int signal_recv(queue_t *q, long *msg_type, signal_t *sig)
{
    generic_msg_t buf = {0};
    int ret = messaging_recv_on(q, &buf, NULL, false);
    if (ret != 0)
        return ret;
    *msg_type = buf.type;
    if (buf.type != SIGNAL)
        return -2;
    memcpy(sig, &buf.info.signal, sizeof(signal_t));
    return 0;
}

/*@
  requires key != \null && \valid_read(key);
  requires \valid(msg);
  assigns \nothing;
  behavior no_queue:
    ensures \result == -1;
  behavior success:
    ensures \result == 0;
  behavior would_block:
    ensures \result == EAGAIN;
  disjoint behaviors no_queue, success, would_block;
*/
static messaging_test_hook_t g_messaging_test_hook = NULL;

void messaging_set_test_hook(messaging_test_hook_t hook)
{
    g_messaging_test_hook = hook;
}

void messaging_recv_release(generic_msg_t *msg)
{
    if (msg == NULL)
        return;
    if (msg->type == NET_MESSAGE) {
        free(msg->info.net_msg.function);
        free(msg->info.net_msg.obj);
    } else if (msg->type == TASK_RESULT) {
        /* proto_to_generic_msg allocates the result bytes (msg_types.c). */
        free(msg->info.task_result.result_data);
    } else if (msg->type == PEER_CAPABILITIES
               && msg->info.peer_capabilities.items != NULL) {
        /* A decoded matrix nobody adopted (the PEER_CAPABILITIES handler
         * takes it, leaving this zeroed). */
        map_free(&msg->info.peer_capabilities);
    }
    memset(msg, 0, sizeof(*msg));
}

/* Frama-C: skipped — [syscall] mq_send POSIX message queue */
int messaging_send(const char *key, const message_type_t type, generic_msg_t *msg, bool blocking)
{
    /* Test-mode hook short-circuits the real transport. The conformance
     * harness installs a hook that captures the message into a per-
     * participant outbox and returns 0; production paths leave the hook
     * NULL so this branch costs one predictable comparison per send. */
    if (g_messaging_test_hook != NULL)
        return g_messaging_test_hook(key, type, msg, blocking);

    bool in_process = messaging_in_process();
    /* A forked process sends from its own queue's socket, as it always has. */
    if (!in_process && my_q == NULL)
        return EXCEPTION(EMSG_NOCONN);
    void *data;
    size_t data_len;
    if (generic_msg_to_proto(msg, &data, &data_len) != 0)
        return -1;
    if (sizeof(size_t) + data_len > AT_IPC_DGRAM_MAX)
    {
        free(data);
        return EXCEPTION(EMSGSIZE);
    }
    size_t net_size = htonll(data_len);

    /* A queue of this process (in-process), then another process's stream
     * queue, then a unix datagram queue: the first path that has the name. */
    int rc = AT_IPC_NOT_MINE;
    if (in_process)
        rc = inproc_send(key, (const uint8_t *)&net_size, sizeof(size_t),
                         data, data_len, blocking);
    if (rc == AT_IPC_NOT_MINE && at_ipc_stream_link())
        rc = stream_send(key, (const uint8_t *)&net_size, sizeof(size_t),
                         data, data_len, blocking);
    if (rc != AT_IPC_NOT_MINE)
    {
        free(data);
        return rc;   /* 0, EAGAIN, or -1 with the exception set */
    }
#ifdef _WIN32
    /* No unix datagrams here: a name no path has is a queue nobody holds. */
    free(data);
    return EXCEPTION(ENOENT);
#else
    int flags = 0;
    if (!blocking)
        flags = MSG_DONTWAIT;

    struct sockaddr_un target;
    if (unix_addr(key, &target) != 0)
    {
        free(data);  /* generic_msg_to_proto's buffer is plain malloc */
        return SYS_EXCEPTION();
    }

    int fd;
    if (in_process)
    {
        (void)pthread_once(&g_send_fd_once, _send_fd_init);
        fd = g_send_fd;
        if (fd < 0)
        {
            free(data);
            return SYS_EXCEPTION();
        }
    }
    else
        fd = my_q->fd;

    /* Send size header + payload as a single atomic datagram so that
     * concurrent senders to the same target cannot interleave. */
    struct iovec iov[2] = {
        { .iov_base = &net_size, .iov_len = sizeof(size_t) },
        { .iov_base = data,      .iov_len = data_len },
    };
    struct msghdr mh = {
        .msg_name    = &target,
        .msg_namelen = sizeof(struct sockaddr_un),
        .msg_iov     = iov,
        .msg_iovlen  = 2,
    };
    ssize_t numbytes = sendmsg(fd, &mh, flags);
    free(data);
    if (numbytes < 0)
    {
        /* A full receiver: EAGAIN on Linux, ENOBUFS on Darwin. */
        if (errno == EAGAIN || errno == ENOBUFS)
            return EAGAIN;
        return SYS_EXCEPTION();
    }
    return 0;
#endif
}

/*@
  requires queue == \null || \valid(queue);
  behavior null_queue:
    assumes queue == \null;
    assigns \nothing;
  behavior valid_queue:
    assumes queue != \null;
    assigns queue->fd;
  disjoint behaviors;
*/
void messaging_qclose(queue_t *queue)
{
    if (queue == NULL)
        return;
    if (messaging_in_process() && inproc_owns(queue))
    {
        inproc_close(queue);
        return;
    }
    if (at_ipc_stream_link() && stream_owns(queue))
    {
        stream_close(queue);
        return;
    }
    at_socket_close(queue->fd);
    struct sockaddr_un local;
    if (unix_addr(queue->key, &local) != 0)
        return;
    /* UNLINK OUR OWN SOCKET, NOT WHATEVER NOW ANSWERS TO THAT NAME. Queue
     * names are fixed strings ("at_to_extern" and friends), messaging_init
     * unlinks before binding, and short-lived clients come and go on the same
     * name: a departing process that unlinks by name alone can delete the
     * entry a newly-started one just bound. That leaves the newcomer polling a
     * nameless socket forever while every sender to that name gets ENOENT —
     * which is how the P3.3 cohort's expulsion ask vanished between a node
     * that logged receiving it and a driver that logged waiting for it.
     *
     * If the post-bind stat failed we have nothing to compare, so fall back to
     * the old behavior rather than leaking the entry. */
    if (queue->bound_ino != 0)
    {
        struct stat st;
        if (stat(local.sun_path, &st) != 0)
            return;                     /* already gone, or replaced and removed */
        if (st.st_dev != queue->bound_dev || st.st_ino != queue->bound_ino)
            return;                     /* somebody else's socket now — leave it */
    }
    unlink(local.sun_path);
}

void messaging_close()
{
    messaging_qclose(my_q);
}
