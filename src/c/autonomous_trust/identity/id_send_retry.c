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

/* Frames identity could not hand a sibling queue, retried on the identity
 * tick. See id_send_retry.h and ISSUES §2.40. */

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "identity/id_send_retry.h"
#include "utilities/message.h"

typedef struct {
    char          queue[PROC_NAME_LEN + 1];
    generic_msg_t msg;          /* owns net_msg.obj and net_msg.function */
    char          what[64];
    char          whom[NAME_LEN + 1];
    double        first;        /* when it was first deferred */
    int           attempts;     /* drain attempts so far */
    id_send_sent_fn on_sent;    /* run once it lands or is given up on */
    bool          sent;         /* the outcome on_sent is told */
    unsigned char ctx[ID_SEND_RETRY_CTX_MAX];
} id_deferred_t;

/* Oldest first: a defer appends, a drain removes in place. */
static id_deferred_t *g_deferred[ID_SEND_RETRY_MAX];
static size_t g_num_deferred;
static pthread_mutex_t g_deferred_lock = PTHREAD_MUTEX_INITIALIZER;

static double _age_limit(void)
{
    const char *v = getenv("AT_ID_SEND_RETRY_SEC");
    if (v != NULL && *v != '\0') {
        char *end = NULL;
        double d = strtod(v, &end);
        if (end != v && d > 0.0)
            return d;
    }
    return ID_SEND_RETRY_AGE_DEFAULT;
}

bool id_send_retry_supported(long type)
{
    return type == NET_MESSAGE || type == TRANSACTION_SCORE
        || type == PEER_STANDING;
}

/* The serializer reads only an identity's inline fields (msg_types.c), so a
 * kept copy drops the heap ones rather than share memory the caller frees. */
static void _strip_identity(public_identity_t *p)
{
    p->operator_key_binding = NULL;
    p->operator_key_binding_len = 0;
    p->zta_credential = NULL;
    p->zta_credential_len = 0;
    for (size_t i = 0; i < ZTA_MAX_CREDENTIALS; i++) {
        p->zta_credentials[i].der = NULL;
        p->zta_credentials[i].der_len = 0;
        p->zta_credentials[i].binding = NULL;
        p->zta_credentials[i].binding_len = 0;
    }
    p->num_zta_credentials = 0;
}

static void _free_entry(id_deferred_t *e)
{
    if (e == NULL)
        return;
    if (e->msg.type == NET_MESSAGE) {
        free(e->msg.info.net_msg.obj);
        free(e->msg.info.net_msg.function);
    }
    free(e);
}

int id_send_retry_defer(const char *queue, const generic_msg_t *msg,
                        const char *what, const char *whom, double now)
{
    return id_send_retry_defer_then(queue, msg, what, whom, now, NULL, NULL, 0);
}

int id_send_retry_defer_then(const char *queue, const generic_msg_t *msg,
                             const char *what, const char *whom, double now,
                             id_send_sent_fn on_sent, const void *ctx,
                             size_t ctx_len)
{
    if (queue == NULL || msg == NULL || !id_send_retry_supported(msg->type)
        || ctx_len > ID_SEND_RETRY_CTX_MAX || (ctx_len > 0 && ctx == NULL))
        return -1;
    id_deferred_t *e = calloc(1, sizeof(*e));
    if (e == NULL)
        return -1;
    e->on_sent = on_sent;
    if (ctx_len > 0)
        memcpy(e->ctx, ctx, ctx_len);
    snprintf(e->queue, sizeof(e->queue), "%s", queue);
    snprintf(e->what, sizeof(e->what), "%s", what != NULL ? what : "a frame");
    snprintf(e->whom, sizeof(e->whom), "%s", whom != NULL ? whom : "peer");
    e->first = now;
    memcpy(&e->msg, msg, sizeof(generic_msg_t));
    if (msg->type == NET_MESSAGE) {
        net_msg_t *nm = &e->msg.info.net_msg;
        const net_msg_t *src = &msg->info.net_msg;
        nm->obj = NULL;
        nm->function = NULL;
        if (src->obj != NULL && src->len > 0) {
            nm->obj = malloc(src->len);
            if (nm->obj == NULL) {
                free(e);
                return -1;
            }
            memcpy(nm->obj, src->obj, src->len);
        }
        if (src->function != NULL) {
            nm->function = strdup(src->function);
            if (nm->function == NULL) {
                _free_entry(e);
                return -1;
            }
        }
        _strip_identity(&nm->to_whom);
        _strip_identity(&nm->from_whom);
    }
    int rc = -1;
    pthread_mutex_lock(&g_deferred_lock);
    if (g_num_deferred < ID_SEND_RETRY_MAX) {
        g_deferred[g_num_deferred++] = e;
        rc = 0;
    }
    pthread_mutex_unlock(&g_deferred_lock);
    if (rc != 0)
        _free_entry(e);
    return rc;
}

/* Whether @p name is already in the first @p n entries of @p list. */
static bool _listed(char (*list)[PROC_NAME_LEN + 1], size_t n, const char *name)
{
    for (size_t i = 0; i < n; i++)
        if (strcmp(list[i], name) == 0)
            return true;
    return false;
}

size_t id_send_retry_drain(const process_t *proc, const char *queue, double now)
{
    logger_t *logger = proc != NULL ? proc->logger : NULL;
    double limit = _age_limit();
    /* Frames done with (landed or given up on) that have an on-sent callback:
     * run after the unlock, because a callback may send (social scores go to
     * reputation) and so come back through this list. */
    id_deferred_t *done[ID_SEND_RETRY_MAX];
    size_t num_done = 0;
    size_t delivered = 0;
    /* Queues that refused this pass: their later frames keep their place. */
    char blocked[ID_SEND_RETRY_MAX][PROC_NAME_LEN + 1];
    size_t num_blocked = 0;

    pthread_mutex_lock(&g_deferred_lock);
    size_t keep = 0;
    for (size_t i = 0; i < g_num_deferred; i++) {
        id_deferred_t *e = g_deferred[i];
        bool mine = queue == NULL || strcmp(e->queue, queue) == 0;
        if (!mine || _listed(blocked, num_blocked, e->queue)) {
            g_deferred[keep++] = e;
            continue;
        }
        if (now - e->first > limit) {
            log_warn(logger,
                     "Identity: could not send %s to %s after %.0f s (%s queue still"
                     " full) — the action DID NOT HAPPEN\n",
                     e->what, e->whom, limit, e->queue);
            if (e->on_sent != NULL)
                done[num_done++] = e;
            else
                _free_entry(e);
            continue;
        }
        e->attempts++;
        /* One try: the tick is the retry loop. The send serializes and does
         * not take the payload, so the entry stays ours either way. */
        int ret = messaging_send(e->queue, (message_type_t)e->msg.type,
                                 &e->msg, false);
        if (ret == 0) {
            log_info(logger, "Identity: sent the deferred %s to %s (%d tick%s late)\n",
                     e->what, e->whom, e->attempts, e->attempts == 1 ? "" : "s");
            delivered++;
            e->sent = true;
            if (e->on_sent != NULL)
                done[num_done++] = e;
            else
                _free_entry(e);
            continue;
        }
        if (ret == EAGAIN) {
            snprintf(blocked[num_blocked++], PROC_NAME_LEN + 1, "%s", e->queue);
            g_deferred[keep++] = e;
            continue;
        }
        log_warn(logger,
                 "Identity: could not send the deferred %s to %s (send failed)"
                 " — the action DID NOT HAPPEN\n", e->what, e->whom);
        if (e->on_sent != NULL)
            done[num_done++] = e;
        else
            _free_entry(e);
    }
    g_num_deferred = keep;
    pthread_mutex_unlock(&g_deferred_lock);
    for (size_t i = 0; i < num_done; i++) {
        done[i]->on_sent(proc, done[i]->ctx, done[i]->sent);
        _free_entry(done[i]);
    }
    return delivered;
}

size_t id_send_retry_pending(const char *queue)
{
    size_t n = 0;
    pthread_mutex_lock(&g_deferred_lock);
    for (size_t i = 0; i < g_num_deferred; i++)
        if (queue == NULL || strcmp(g_deferred[i]->queue, queue) == 0)
            n++;
    pthread_mutex_unlock(&g_deferred_lock);
    return n;
}

void id_send_retry_reset(void)
{
    pthread_mutex_lock(&g_deferred_lock);
    for (size_t i = 0; i < g_num_deferred; i++)
        _free_entry(g_deferred[i]);
    g_num_deferred = 0;
    pthread_mutex_unlock(&g_deferred_lock);
}
