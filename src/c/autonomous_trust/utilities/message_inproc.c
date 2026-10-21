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

/* In-process queues: the subsystems of an in-process node (AT_IN_PROCESS, and
 * every Windows node) are threads of one process, and their queues are named
 * FIFOs here instead of sockets.
 *
 * Bounded like the unix datagram queues they replace, and full the same way:
 * a non-blocking send to a full queue answers EAGAIN, which is what the §2.40
 * retry (utilities/send_retry.c) and the drains in the run loops were built
 * around. The depth defaults to what a Linux unix datagram queue holds
 * (net.unix.max_dgram_qlen, 10, admits 11); $AT_INPROC_QUEUE_DEPTH changes it.
 *
 * Entries are never freed. A queue name belongs to one fixed role (a
 * subsystem, its signal queue, the main queue), there are a few dozen, and a
 * sender that found an entry can then use it without racing a close: a closed
 * entry refuses sends and is reopened in place, empty, by the next owner,
 * exactly as unlink-then-bind gives a fresh socket. */

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "message_ipc.h"

#define INPROC_DEPTH_DEFAULT 11
#define INPROC_DEPTH_MAX     4096

typedef struct inproc_q
{
    char key[MSG_KEY_LEN + 1];
    queue_t *owner;          /* NULL while closed */
    pthread_mutex_t mu;
    pthread_cond_t changed;  /* a frame arrived, a slot freed, or it closed */
    uint8_t **frames;        /* ring of depth entries */
    size_t *lens;
    size_t head;
    size_t count;
    struct inproc_q *next;
} inproc_q_t;

static pthread_mutex_t g_reg_mu = PTHREAD_MUTEX_INITIALIZER;
static inproc_q_t *g_reg = NULL;
static size_t g_depth = 0;

static size_t _depth(void)
{
    if (g_depth == 0)
    {
        size_t d = INPROC_DEPTH_DEFAULT;
        const char *env = getenv("AT_INPROC_QUEUE_DEPTH");
        if (env != NULL && env[0] != '\0')
        {
            long v = strtol(env, NULL, 10);
            if (v > 0 && v <= INPROC_DEPTH_MAX)
                d = (size_t)v;
        }
        g_depth = d;
    }
    return g_depth;
}

/* Caller holds g_reg_mu. */
static inproc_q_t *_find(const char *key)
{
    for (inproc_q_t *e = g_reg; e != NULL; e = e->next)
        if (strncmp(e->key, key, MSG_KEY_LEN) == 0)
            return e;
    return NULL;
}

static inproc_q_t *_lookup(const char *key)
{
    pthread_mutex_lock(&g_reg_mu);
    inproc_q_t *e = _find(key);
    pthread_mutex_unlock(&g_reg_mu);
    return e;
}

static inproc_q_t *_lookup_owner(const queue_t *q)
{
    if (q == NULL)
        return NULL;
    inproc_q_t *e = _lookup(q->key);
    if (e == NULL)
        return NULL;
    pthread_mutex_lock(&e->mu);
    bool mine = e->owner == q;
    pthread_mutex_unlock(&e->mu);
    return mine ? e : NULL;
}

/* Caller holds e->mu. */
static void _drop_frames(inproc_q_t *e)
{
    size_t depth = _depth();
    while (e->count > 0)
    {
        free(e->frames[e->head]);
        e->frames[e->head] = NULL;
        e->head = (e->head + 1) % depth;
        e->count--;
    }
    e->head = 0;
}

int inproc_open(const char *key, queue_t *q)
{
    if (key == NULL || q == NULL)
        return EXCEPTION(EINVAL);
    q->fd = -1;   /* no descriptor: a caller's failure path must not close one */
    size_t depth = _depth();
    pthread_mutex_lock(&g_reg_mu);
    inproc_q_t *e = _find(key);
    if (e == NULL)
    {
        e = calloc(1, sizeof(*e));
        if (e != NULL)
        {
            e->frames = calloc(depth, sizeof(*e->frames));
            e->lens = calloc(depth, sizeof(*e->lens));
        }
        if (e == NULL || e->frames == NULL || e->lens == NULL)
        {
            pthread_mutex_unlock(&g_reg_mu);
            if (e != NULL)
            {
                free(e->frames);
                free(e->lens);
                free(e);
            }
            return EXCEPTION(ENOMEM);
        }
        strncpy(e->key, key, MSG_KEY_LEN);
        pthread_mutex_init(&e->mu, NULL);
        pthread_cond_init(&e->changed, NULL);
        e->next = g_reg;
        g_reg = e;
    }
    pthread_mutex_unlock(&g_reg_mu);

    /* A new owner takes the name over, as bind after unlink does: whatever a
     * departed owner left unread is gone. */
    pthread_mutex_lock(&e->mu);
    _drop_frames(e);
    e->owner = q;
    pthread_cond_broadcast(&e->changed);
    pthread_mutex_unlock(&e->mu);

    strncpy(q->key, key, MSG_KEY_LEN);
    q->key[MSG_KEY_LEN] = '\0';
    q->fd = -1;
    q->bound_dev = 0;
    q->bound_ino = 0;
    return 0;
}

bool inproc_owns(const queue_t *q)
{
    return _lookup_owner(q) != NULL;
}

bool inproc_bound(const char *key)
{
    if (key == NULL)
        return false;
    inproc_q_t *e = _lookup(key);
    if (e == NULL)
        return false;
    pthread_mutex_lock(&e->mu);
    bool bound = e->owner != NULL;
    pthread_mutex_unlock(&e->mu);
    return bound;
}

int inproc_send(const char *key, const uint8_t *hdr, size_t hdr_len,
                const uint8_t *data, size_t data_len, bool blocking)
{
    inproc_q_t *e = _lookup(key);
    if (e == NULL)
        return AT_IPC_NOT_MINE;
    size_t len = hdr_len + data_len;
    uint8_t *copy = malloc(len);
    if (copy == NULL)
        return EXCEPTION(ENOMEM);
    memcpy(copy, hdr, hdr_len);
    memcpy(copy + hdr_len, data, data_len);

    size_t depth = _depth();
    pthread_mutex_lock(&e->mu);
    while (e->owner != NULL && e->count == depth && blocking)
        pthread_cond_wait(&e->changed, &e->mu);
    if (e->owner == NULL)
    {
        /* Closed: the socket analog is ECONNREFUSED on a stale file. */
        pthread_mutex_unlock(&e->mu);
        free(copy);
        return EXCEPTION(ECONNREFUSED);
    }
    if (e->count == depth)
    {
        pthread_mutex_unlock(&e->mu);
        free(copy);
        return EAGAIN;
    }
    size_t slot = (e->head + e->count) % depth;
    e->frames[slot] = copy;
    e->lens[slot] = len;
    e->count++;
    pthread_cond_broadcast(&e->changed);
    pthread_mutex_unlock(&e->mu);
    return 0;
}

int inproc_recv(queue_t *q, uint8_t *buf, size_t cap, size_t *len, bool blocking)
{
    inproc_q_t *e = _lookup_owner(q);
    if (e == NULL)
        return EXCEPTION(ENOTSOCK);
    size_t depth = _depth();
    pthread_mutex_lock(&e->mu);
    while (e->owner == q && e->count == 0 && blocking)
        pthread_cond_wait(&e->changed, &e->mu);
    if (e->owner != q || e->count == 0)
    {
        pthread_mutex_unlock(&e->mu);
        return ENOMSG;
    }
    uint8_t *frame = e->frames[e->head];
    size_t flen = e->lens[e->head];
    e->frames[e->head] = NULL;
    e->head = (e->head + 1) % depth;
    e->count--;
    pthread_cond_broadcast(&e->changed);
    pthread_mutex_unlock(&e->mu);

    /* Senders build frames no larger than the receive buffer, but say so
     * rather than cut one if that ever changes. */
    if (flen > cap)
    {
        free(frame);
        return EXCEPTION(EMSGSIZE);
    }
    memcpy(buf, frame, flen);
    free(frame);
    *len = flen;
    return 0;
}

void inproc_close(queue_t *q)
{
    inproc_q_t *e = _lookup_owner(q);
    if (e == NULL)
        return;
    pthread_mutex_lock(&e->mu);
    if (e->owner == q)
    {
        e->owner = NULL;
        _drop_frames(e);
        pthread_cond_broadcast(&e->changed);
    }
    pthread_mutex_unlock(&e->mu);
}
