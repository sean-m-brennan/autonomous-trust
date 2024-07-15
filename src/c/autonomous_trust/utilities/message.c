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

#define htonll(x) ((1 == htonl(1)) ? (x) : (((uint64_t)htonl((x) & 0xFFFFFFFFUL)) << 32) | htonl((uint32_t)((x) >> 32)))

#define ntohll(x) ((1 == ntohl(1)) ? (x) : (((uint64_t)ntohl((x) & 0xFFFFFFFFUL)) << 32) | ntohl((uint32_t)((x) >> 32)))

int unix_addr(const char *key, struct sockaddr_un *addr)
{
    char path[SOCK_PATH_LEN] = {0};
    if (get_data_dir(path) < 0)
        return SYS_EXCEPTION();
    path[strlen(path)] = '/';
    strncat(path, key, SOCK_PATH_LEN - strlen(path) - 1);

    addr->sun_family = AF_UNIX;
    strcpy(addr->sun_path, path);
    return 0;
}

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

int messaging_recv_from(generic_msg_t *msg, struct sockaddr_storage *their_addr, bool blocking)
{
    if (my_q == NULL)
        return EXCEPTION(EMSG_NOCONN);
    return messaging_recv_on(my_q, msg, their_addr, blocking);
}

int messaging_recv_on(queue_t *q, generic_msg_t *msg, struct sockaddr_storage *their_addr, bool blocking)
{
    if (q->fd <= 0)
        return EXCEPTION(ENOTSOCK);

    int flags = 0;
    if (!blocking)
        flags = MSG_DONTWAIT;
    socklen_t addr_len = sizeof(struct sockaddr_storage);
    socklen_t *len_ptr = &addr_len;
    if (their_addr == NULL)
        len_ptr = NULL;

    size_t net_size = 0;
    ssize_t numbytes = recvfrom(q->fd, &net_size, sizeof(size_t),
                                flags, (struct sockaddr *)their_addr, len_ptr);
    if (numbytes < 0)
    {
        if (errno == EAGAIN)
            return ENOMSG;
        return SYS_EXCEPTION();
    }
    size_t data_size = ntohll(net_size);
    uint8_t *data = malloc(data_size);
    numbytes = recvfrom(q->fd, data, data_size,
                        flags, (struct sockaddr *)their_addr, len_ptr);
    if (numbytes < 0)
        return SYS_EXCEPTION();

    if (proto_to_generic_msg(data, numbytes, msg) != 0)
        return -1;
    free(data);
    return 0;
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
        return SYS_EXCEPTION();

    size_t net_size = htonll(data_len);
    ssize_t numbytes = sendto(my_q->fd, &net_size, sizeof(size_t),
                              flags, (const struct sockaddr *)&target, sizeof(struct sockaddr_un));
    if (numbytes < 0)
    {
        if (errno == EAGAIN)
            return EAGAIN;
        return SYS_EXCEPTION();
    }
    numbytes = sendto(my_q->fd, data, data_len,
                      flags, (const struct sockaddr *)&target, sizeof(struct sockaddr_un));
    smrt_deref(data);
    if (numbytes < 0)
    {
        if (errno == EAGAIN)
            return EAGAIN;
        return SYS_EXCEPTION();
    }
    return 0;
}

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
