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

#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>

#include "config/configuration.h"
#include "util.h"
#include "structures/data.h"
#include "structures/map.h"
#include "message.h"
#include "msg_types_priv.h"

#define SOCK_PATH_LEN 108

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

#define htonll(x) ((1 == htonl(1)) ? (x) : (((uint64_t)htonl((x) & 0xFFFFFFFFUL)) << 32) | htonl((uint32_t)((x) >> 32)))

#define ntohll(x) ((1 == ntohl(1)) ? (x) : (((uint64_t)ntohl((x) & 0xFFFFFFFFUL)) << 32) | ntohl((uint32_t)((x) >> 32)))

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
int unix_addr(const char *key, struct sockaddr_un *addr)
{
    char path[SOCK_PATH_LEN] = {0};
    if (get_data_dir(path) < 0)
        return SYS_EXCEPTION();
    path[strlen(path)] = '/';
    strncat(path, key, SOCK_PATH_LEN - strlen(path) - 1);

    addr->sun_family = AF_UNIX;
    strncpy(addr->sun_path, path, sizeof(addr->sun_path) - 1);
    addr->sun_path[sizeof(addr->sun_path) - 1] = '\0';
    return 0;
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
/* Frama-C: skipped — [solver-timeout] strncpy separation + assigns preconditions */
int messaging_init(const char *id, queue_t *queue)
{
    strncpy(queue->key, id, MSG_KEY_LEN - 1);

    queue->fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (queue->fd < 0)
        return SYS_EXCEPTION();

    struct sockaddr_un local;
    if (unix_addr(id, &local) != 0)
        return SYS_EXCEPTION();

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
    return 0;
}

static queue_t *my_q = NULL;

void messaging_assign(queue_t *queue)
{
    my_q = queue;
}

/* Frama-C: skipped — [syscall] mq_receive POSIX message queue */
int messaging_recv_from(generic_msg_t *msg, struct sockaddr_storage *their_addr, bool blocking)
{
    if (my_q == NULL)
        return EXCEPTION(EMSG_NOCONN);
    return messaging_recv_on(my_q, msg, their_addr, blocking);
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
int messaging_recv_on(queue_t *q, generic_msg_t *msg, struct sockaddr_storage *their_addr, bool blocking)
{
    if (q->fd <= 0)
        return EXCEPTION(ENOTSOCK);

    int flags = 0;
    if (!blocking)
        flags = MSG_DONTWAIT;

    /* Peek to learn the total datagram size (size_t header + payload).
     * MSG_PEEK | MSG_TRUNC returns the real datagram length even if our
     * buffer is too small, without consuming the datagram. */
    ssize_t dgram_len = recvfrom(q->fd, NULL, 0,
                                 flags | MSG_PEEK | MSG_TRUNC, NULL, NULL);
    if (dgram_len < 0)
    {
        if (errno == EAGAIN)
            return ENOMSG;
        return SYS_EXCEPTION();
    }
    if ((size_t)dgram_len < sizeof(size_t))
        return -1;  /* runt datagram */

    uint8_t *frame = malloc(dgram_len);
    if (frame == NULL)
        return EXCEPTION(ENOMEM);

    socklen_t addr_len = sizeof(struct sockaddr_storage);
    socklen_t *len_ptr = their_addr ? &addr_len : NULL;
    ssize_t numbytes = recvfrom(q->fd, frame, dgram_len,
                                flags, (struct sockaddr *)their_addr, len_ptr);
    if (numbytes < 0)
    {
        free(frame);
        if (errno == EAGAIN)
            return ENOMSG;
        return SYS_EXCEPTION();
    }

    size_t net_size;
    memcpy(&net_size, frame, sizeof(size_t));
    size_t data_size = ntohll(net_size);
    size_t payload_len = (size_t)numbytes - sizeof(size_t);
    if (payload_len < data_size)
        data_size = payload_len;  /* clamp to actual received bytes */

    int ret = proto_to_generic_msg(frame + sizeof(size_t), data_size, msg);
    free(frame);
    return (ret != 0) ? -1 : 0;
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
/* Frama-C: skipped — [syscall] mq_send POSIX message queue */
int messaging_send(const char *key, const message_type_t type, generic_msg_t *msg, bool blocking)
{
    if (my_q == NULL)
        return EXCEPTION(EMSG_NOCONN);
    int flags = 0;
    if (!blocking)
        flags = MSG_DONTWAIT;
    void *data;
    size_t data_len;
    if (generic_msg_to_proto(msg, &data, &data_len) != 0)
        return -1;

    struct sockaddr_un target;
    if (unix_addr(key, &target) != 0)
    {
        smrt_deref(data);
        return SYS_EXCEPTION();
    }

    /* Send size header + payload as a single atomic datagram so that
     * concurrent senders to the same target cannot interleave. */
    size_t net_size = htonll(data_len);
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
    ssize_t numbytes = sendmsg(my_q->fd, &mh, flags);
    smrt_deref(data);
    if (numbytes < 0)
    {
        if (errno == EAGAIN)
            return EAGAIN;
        return SYS_EXCEPTION();
    }
    return 0;
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
    close(queue->fd);
    struct sockaddr_un local;
    if (unix_addr(queue->key, &local) == 0)
        unlink(local.sun_path);
}

void messaging_close()
{
    messaging_qclose(my_q);
}
