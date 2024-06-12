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
#include "msg_types.h"

size_t message_size(message_type_t type)
{
    switch (type)
    {
    case SIGNAL:
        return sizeof(signal_t);
    case GROUP:
        return sizeof(group_t);
    case PEERS:
        return sizeof(public_identity_t) * MAX_PEERS;
    case CAPABILITIES:
        return sizeof(capability_t) * MAX_CAPABILITIES;
    case PEER_CAPABILITIES:
        return sizeof(capability_t) * MAX_PEERS * MAX_CAPABILITIES;
    case NET_MESSAGE:
        return sizeof(net_msg_t);
    case TASK: // FIXME
    default:
        return 0;
    }
}

#ifdef MSGQ

static int id_seed = 0;
static char msg_cfg_path[CFG_PATH_LEN] = {0};

int messaging_fetch_queue(map_t *map, const char *key, queue_id_t *q)
{
    data_t *mk_dat;
    int err = map_get(map, (char *)key, &mk_dat);
    if (err != 0)
        return err;
    int mk = 0;
    err = data_integer(mk_dat, &mk);
    if (err != 0)
        return err;
    return mk;
}


int messaging_new_id(char *id, msg_key_t *key)
{
    if (strlen(msg_cfg_path) == 0)
    {
        int err = get_cfg_dir(msg_cfg_path);
        if (err < 0)
            return SYS_EXCEPTION();

        struct stat st = {0};
        if (stat(msg_cfg_path, &st) == -1)
        {
            err = makedirs(msg_cfg_path, 0700);
            if (err != 0)
                return err;
        }
    }
    char cfg_path[CFG_PATH_LEN];
    strncpy(cfg_path, msg_cfg_path, CFG_PATH_LEN);
    strncat(cfg_path, id, CFG_PATH_LEN - strlen(msg_cfg_path));

    int r_id = seed;
    if (seed == 0)
    {
        r_id = id_seed++;
        // srand(time(0));
        // unsigned int min = (INT_MAX / 2); // do not interfere with user-defined (hopefully)
        // r_id = (random() % (INT_MAX - min)) + min;
    }
    int err = ftok(msg_cfg_path, r_id);
    if (err != 0)
        return SYS_EXCEPTION();
    *key = err;
    return 0;
}

queue_id_t messaging_init(msg_key_t id)
{
    int fd = msgget(id, 0666 | IPC_CREAT);
    if (fd < 0)
        return SYS_EXCEPTION();
    return fd;
}

int messaging_recv(queue_id_t qid, generic_msg_t *data)
{
    ssize_t err = msgrcv(qid, data, MAX_MSG_SIZE, 0, IPC_NOWAIT);
    if (err == -1)
    {
        if (errno == ENOMSG)
            return ENOMSG;
        return SYS_EXCEPTION();
    }
    return 0;
}

int messaging_send(queue_id_t qid, message_type_t type, void *data)
{
    int err = msgsnd(qid, data, message_size(type), type);
    if (err != 0)
    {
        if (errno == EAGAIN)
            return EAGAIN;
        return SYS_EXCEPTION();
    }
    return 0;
}

// end MSGQ
#else
#ifdef U_SOCK

int messaging_fetch_queue(map_t *map, const char *key, queue_id_t *q)
{
    data_t *mk_dat;
    int err = map_get(map, (char *)key, &mk_dat);
    if (err != 0)
        return err;
    int mk = 0;
    err = data_integer(mk_dat, &mk);
    if (err != 0)
        return err;
    return mk;
}



int messaging_new_id(char *id, msg_key_t *key)
{
    int err = get_data_dir(*key);
    if (err < 0)
        return SYS_EXCEPTION();
    strncat(*key, id, CFG_PATH_LEN - strlen(*key));
    return 0;
}

int messaging_init(msg_key_t id)
{
    int sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sock < 0)
        return SYS_EXCEPTION();

    int incr = 0;
    while (true) {
        struct sockaddr_un local;
        local.sun_family = AF_UNIX;
        snprintf(local.sun_path, "%s%d", id, incr, sizeof(local.sun_path) - 1);
        unlink(local.sun_path);
        socklen_t len = strlen(local.sun_path) + sizeof(local.sun_family);

        int one = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0)
            return SYS_EXCEPTION();
        if (bind(sock, (struct sockaddr *)&local, len) != 0) {
            incr++;
            if (incr > 20)
                return SYS_EXCEPTION();
        } else
            break;
    }
    return sock;
}

int messaging_recv(queue_id_t qid, generic_msg_t *msg)
{
    // FIXME convert structs to protobuf
#if TRACK_SENDER
    struct sockaddr_storage their_addr;
    socklen_t addr_len = sizeof(their_addr);
#endif
    ssize_t numbytes = recvfrom(qid, msg, sizeof(generic_msg_t), MSG_DONTWAIT,
#if TRACK_SENDER
                                (struct sockaddr *)&their_addr, &addr_len);
#else
                                NULL, NULL);
#endif
    if (numbytes < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return EAGAIN;
        return SYS_EXCEPTION();
    }
    // FIXME convert protobuf to struct
    return 0;
}

int messaging_send(queue_id_t qid, message_type_t type, void *data)
{
    // FIXME convert struct to protobuf
    struct sockaddr_un target;
    target.sun_family = AF_UNIX;
    strncpy(target.sun_path, process, PROC_NAMELEN-1);
    ssize_t numbytes = sendto(qid, data, message_size(type), MSG_DONTWAIT, &target, sizeof(target));
    if (numbytes < 0)
    {
        if (errno == EAGAIN)
            return EAGAIN;
        return SYS_EXCEPTION();
    }
    return 0;
}

#endif // end U_SOCK
#endif
