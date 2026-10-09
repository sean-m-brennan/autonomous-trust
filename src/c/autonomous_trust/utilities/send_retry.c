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

/* One-shot frames a full queue refused, retried on the process tick. See
 * send_retry.h and ISSUES §2.40 / §2.14. */

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sodium.h>

#include "utilities/send_retry.h"
#include "utilities/message.h"
#include "utilities/msg_registry.h"

typedef struct {
    char          queue[PROC_NAME_LEN + 1];
    generic_msg_t msg;          /* owns net_msg.obj and net_msg.function */
    char          what[64];
    char          whom[NAME_LEN + 1];
    double        first;        /* when it was first deferred */
    int           attempts;     /* drain attempts so far */
    at_send_sent_fn on_sent;    /* run once it lands or is given up on */
    bool          sent;         /* the outcome on_sent is told */
    unsigned char ctx[AT_SEND_RETRY_CTX_MAX];
} at_deferred_t;

/* Oldest first: a defer appends, a drain removes in place. */
static at_deferred_t *g_deferred[AT_SEND_RETRY_MAX];
static size_t g_num_deferred;
static pthread_mutex_t g_deferred_lock = PTHREAD_MUTEX_INITIALIZER;

static double _age_limit(void)
{
    static const char *const names[] = { "AT_SEND_RETRY_SEC",
                                         "AT_ID_SEND_RETRY_SEC" };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        const char *v = getenv(names[i]);
        if (v != NULL && *v != '\0') {
            char *end = NULL;
            double d = strtod(v, &end);
            if (end != v && d > 0.0)
                return d;
        }
    }
    return AT_SEND_RETRY_AGE_DEFAULT;
}

/* "Identity", "Reputation", ...: the process's name as its log lines spell
 * it, or "AT" with no process in hand. */
static const char *_who(const process_t *proc, char *buf, size_t len)
{
    if (proc == NULL || proc->name[0] == '\0')
        return "AT";
    snprintf(buf, len, "%s", proc->name);
    buf[0] = (char)toupper((unsigned char)buf[0]);
    return buf;
}

bool at_send_retry_supported(long type)
{
    switch (type) {
    case NET_MESSAGE:
    case TASK_RESULT:
    case TASK_STATUS:
    case TRANSACTION_SCORE:
    case PEER_STANDING:
    case PEER_RTT_UPDATE:
    case PEER_RTT_OBSERVED:
    case PEER_OBSERVED:
    case PEER_REPUTATION:
    case PEER_REMOVED:
    case PEER_PRESENCE:
        return true;
    default:
        break;
    }
    /* A feature's type serialized as a fixed raw copy of its payload is plain
     * data by construction (msg_registry.h), so a whole copy is a deep one. */
    const at_msg_vtable_t *vt = at_msg_type_lookup(type);
    return vt != NULL && vt->to_proto == NULL;
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

static void _free_entry(at_deferred_t *e)
{
    if (e == NULL)
        return;
    if (e->msg.type == NET_MESSAGE) {
        free(e->msg.info.net_msg.obj);
        free(e->msg.info.net_msg.function);
    } else if (e->msg.type == TASK_RESULT) {
        free(e->msg.info.task_result.result_data);
    }
    /* A kept frame may carry a secret its sender zeroes after the send (a
     * backup event's passphrase), so the copy is zeroed too. */
    sodium_memzero(e, sizeof(*e));
    free(e);
}

int at_send_retry_defer(const char *queue, const generic_msg_t *msg,
                        const char *what, const char *whom, double now)
{
    return at_send_retry_defer_then(queue, msg, what, whom, now, NULL, NULL, 0);
}

int at_send_retry_defer_then(const char *queue, const generic_msg_t *msg,
                             const char *what, const char *whom, double now,
                             at_send_sent_fn on_sent, const void *ctx,
                             size_t ctx_len)
{
    if (queue == NULL || msg == NULL || !at_send_retry_supported(msg->type)
        || ctx_len > AT_SEND_RETRY_CTX_MAX || (ctx_len > 0 && ctx == NULL))
        return -1;
    at_deferred_t *e = calloc(1, sizeof(*e));
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
    } else if (msg->type == TASK_RESULT) {
        task_result_msg_t *tr = &e->msg.info.task_result;
        const task_result_msg_t *src = &msg->info.task_result;
        tr->result_data = NULL;
        if (src->result_data != NULL && src->result_len > 0) {
            tr->result_data = malloc(src->result_len);
            if (tr->result_data == NULL) {
                free(e);
                return -1;
            }
            memcpy(tr->result_data, src->result_data, src->result_len);
        } else {
            tr->result_len = 0;
        }
    }
    int rc = -1;
    pthread_mutex_lock(&g_deferred_lock);
    if (g_num_deferred < AT_SEND_RETRY_MAX) {
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

size_t at_send_retry_drain(const process_t *proc, const char *queue, double now)
{
    logger_t *logger = proc != NULL ? proc->logger : NULL;
    char who_buf[PROC_NAME_LEN + 1];
    const char *who = _who(proc, who_buf, sizeof(who_buf));
    double limit = _age_limit();
    /* Frames done with (landed or given up on) that have an on-sent callback:
     * run after the unlock, because a callback may send (social scores go to
     * reputation) and so come back through this list. */
    at_deferred_t *done[AT_SEND_RETRY_MAX];
    size_t num_done = 0;
    size_t delivered = 0;
    /* Queues that refused this pass: their later frames keep their place. */
    char blocked[AT_SEND_RETRY_MAX][PROC_NAME_LEN + 1];
    size_t num_blocked = 0;

    pthread_mutex_lock(&g_deferred_lock);
    size_t keep = 0;
    for (size_t i = 0; i < g_num_deferred; i++) {
        at_deferred_t *e = g_deferred[i];
        bool mine = queue == NULL || strcmp(e->queue, queue) == 0;
        if (!mine || _listed(blocked, num_blocked, e->queue)) {
            g_deferred[keep++] = e;
            continue;
        }
        if (now - e->first > limit) {
            log_warn(logger,
                     "%s: could not send %s to %s after %.0f s (%s queue still"
                     " full) — the action DID NOT HAPPEN\n",
                     who, e->what, e->whom, limit, e->queue);
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
            log_info(logger, "%s: sent %s to %s (kept, %d tick%s late)\n",
                     who, e->what, e->whom, e->attempts,
                     e->attempts == 1 ? "" : "s");
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
                 "%s: could not send the kept %s to %s (send failed)"
                 " — the action DID NOT HAPPEN\n", who, e->what, e->whom);
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

size_t at_send_retry_pending(const char *queue)
{
    size_t n = 0;
    pthread_mutex_lock(&g_deferred_lock);
    for (size_t i = 0; i < g_num_deferred; i++)
        if (queue == NULL || strcmp(g_deferred[i]->queue, queue) == 0)
            n++;
    pthread_mutex_unlock(&g_deferred_lock);
    return n;
}

void at_send_retry_reset(void)
{
    pthread_mutex_lock(&g_deferred_lock);
    for (size_t i = 0; i < g_num_deferred; i++)
        _free_entry(g_deferred[i]);
    g_num_deferred = 0;
    pthread_mutex_unlock(&g_deferred_lock);
}

int at_send(const process_t *proc, const char *queue, generic_msg_t *out,
            const char *what, const char *whom, unsigned flags,
            at_send_sent_fn on_sent, const void *ctx, size_t ctx_len)
{
    logger_t *logger = proc != NULL ? proc->logger : NULL;
    char who_buf[PROC_NAME_LEN + 1];
    const char *who = _who(proc, who_buf, sizeof(who_buf));
    const char *to = whom == NULL ? "peer" : whom;
    if (what == NULL)
        what = "a frame";
    double now = (double)time(NULL);
    if (at_send_retry_pending(queue) > 0) {
        at_send_retry_drain(proc, queue, now);
        if (at_send_retry_pending(queue) > 0
            && at_send_retry_defer_then(queue, out, what, whom, now, on_sent,
                                        ctx, ctx_len) == 0) {
            log_info(logger, "%s: %s to %s waits behind earlier frames for a"
                     " full %s queue\n", who, what, to, queue);
            return 0;
        }
    }
    int tries = (flags & AT_SEND_NOW) ? 1 : 10;
    int ret = -1;
    for (int attempt = 0; attempt < tries; attempt++) {
        if (attempt > 0)
            usleep(20000); /* 20ms */
        ret = messaging_send(queue, (message_type_t)out->type, out, false);
        if (ret == 0) {
            if (on_sent != NULL)
                on_sent(proc, ctx, true);
            return 0;
        }
    }
    if (ret == EAGAIN && at_send_retry_defer_then(queue, out, what, whom, now,
                                                  on_sent, ctx, ctx_len) == 0) {
        log_info(logger, "%s: %s to %s deferred (%s queue full); the tick"
                 " retries it\n", who, what, to, queue);
        return 0;
    }
    log_warn(logger,
             "%s: could not send %s to %s after %d tr%s (%s) — the action DID"
             " NOT HAPPEN and nothing retries it\n",
             who, what, to, tries, tries == 1 ? "y" : "ies",
             ret != EAGAIN ? "send failed"
             : !at_send_retry_supported(out->type)
                 ? "queue still full, and this type cannot be kept"
                 : "queue still full, and no room to keep it");
    return ret;
}
