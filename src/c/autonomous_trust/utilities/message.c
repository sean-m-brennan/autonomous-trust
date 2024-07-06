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

#include "config/configuration.h"
#include "util.h"
#include "structures/data.h"
#include "structures/map.h"
#include "message.h"
#include "msg_types_priv.h"

#define SOCK_PATH_LEN 108

int unix_addr(const char *key, struct sockaddr_un *addr)
{
    char path[SOCK_PATH_LEN] = {};
    if (get_data_dir(path) < 0)
        return SYS_EXCEPTION();
    strncat(path, key, SOCK_PATH_LEN - strlen(key) - 1);

    addr->sun_family = AF_UNIX;
    IGNORE_GCC_DIAGNOSTIC(-Wstringop-truncation)
    strncpy(addr->sun_path, path, sizeof(addr->sun_path)-1);
    END_IGNORE_GCC_DIAGNOSTIC
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
        return SYS_EXCEPTION();  // FIXME error success

    if (unlink(local.sun_path) != 0)
    {
        if (errno != ENOENT)
            return SYS_EXCEPTION();
    }
    socklen_t len = strlen(local.sun_path) + sizeof(local.sun_family);

    if (bind(queue->fd, (struct sockaddr *)&local, len) != 0)
        return SYS_EXCEPTION();

    return 0;
}

static queue_t *my_q = NULL;

void messaging_assign(queue_t *queue)
{
    my_q = queue;
}

int messaging_recv(generic_msg_t *msg)
{
    if (my_q == NULL)
        return EXCEPTION(EMSG_NOCONN);
    return messaging_recv_on(my_q, msg);
}

int messaging_recv_on(queue_t *q, generic_msg_t *msg) //, struct sockaddr_storage *their_addr)
{
#if TRACK_SENDER
    struct sockaddr_storage their_addr;
    socklen_t addr_len = sizeof(their_addr);
#endif

    uint8_t data[MAX_MSG_SIZE];
    if (q->fd <= 0)
        return EXCEPTION(ENOTSOCK);  // FIXME Socket operation on non-socket (ENOTSOCK)
    ssize_t numbytes = recvfrom(q->fd, data, sizeof(data), MSG_DONTWAIT,
#if TRACK_SENDER
                                (struct sockaddr *)&their_addr, &addr_len);
#else
                                NULL, NULL);
#endif
    if (numbytes < 0)
    {
        if (errno == EAGAIN)
            return ENOMSG;
        return SYS_EXCEPTION();
    }

    if (proto_to_generic_msg(data, numbytes, msg) != 0)
        return -1;
    return 0;
}

int messaging_send(const char *key, const message_type_t type, generic_msg_t *msg)
{
    if (my_q == NULL)
        return EXCEPTION(EMSG_NOCONN);
    void *data;
    size_t data_len;
    if (generic_msg_to_proto(msg, &data, &data_len) != 0)
        return -1;

    struct sockaddr_un target;
    if (unix_addr(key, &target) != 0)
        return SYS_EXCEPTION();

    ssize_t numbytes = sendto(my_q->fd, data, data_len, MSG_DONTWAIT,
                              (const struct sockaddr *)&target, sizeof(target));
    free(data);
    if (numbytes < 0)
    {
        if (errno == EAGAIN)
            return EAGAIN;
        return SYS_EXCEPTION();
    }
    return 0;
}
