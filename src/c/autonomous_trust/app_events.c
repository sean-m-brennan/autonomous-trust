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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>
#include <uuid/uuid.h>

#include "app_events.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
#include "utilities/msg_types_priv.h"   /* net_msg_pack_json */
#include "app_events_registry.h"

struct at_app_events_s {
    queue_t queue;
    /* False when the handle borrows a queue somebody else bound (see
     * at_app_events_open_existing) — then close must not unbind it. */
    bool owns_queue;
};

/* A queue name only survives if the messaging layer keeps all of it:
 * messaging_init copies MSG_KEY_LEN - 1 bytes into a zeroed key, so a name of
 * exactly that length is the longest intact one. Truncating means binding, or
 * sending to, a name the other side does not share — break #4 with no visible
 * cause — so both flat entry points refuse rather than shorten. */
bool at_app_name_survives(const char *name)
{
    return name != NULL && name[0] != '\0' && strlen(name) <= MSG_KEY_LEN - 1;
}

at_app_events_t *at_app_events_open(const char *q_in)
{
    /* The Agora decoders are libat_social's; its consumers keep them in the
     * link themselves (at_social_link()). */
    if (!at_app_name_survives(q_in))
        return NULL;
    at_app_events_t *h = calloc(1, sizeof(*h));
    if (h == NULL)
        return NULL;
    if (messaging_init(q_in, &h->queue) != 0)
    {
        free(h);
        return NULL;
    }
    h->owns_queue = true;
    /* Sends (the roster request) go out through the process's assigned queue,
     * so a standalone consumer needs one; this is it. */
    messaging_assign(&h->queue);
    return h;
}

at_app_events_t *at_app_events_open_existing(void)
{
    at_app_events_t *h = calloc(1, sizeof(*h));
    if (h == NULL)
        return NULL;
    h->owns_queue = false;
    return h;
}

int at_app_events_poll(at_app_events_t *handle, at_app_event_t *out, size_t max)
{
    if (handle == NULL || out == NULL)
        return -1;
    size_t n = 0;
    generic_msg_t msg = {0};
    while (n < max)
    {
        messaging_recv_release(&msg);   /* the previous pass's */
        /* Non-blocking: a poll reports what has arrived, it does not wait. */
        int ret = handle->owns_queue
                      ? messaging_recv_on(&handle->queue, &msg, NULL, false)
                      : messaging_recv_from(&msg, NULL, false);
        if (ret != 0)
            break;   /* nothing left (or a receive error) — report what we have */

        switch (msg.type)
        {
        case PEER_OBSERVED:
        {
            at_app_event_t *ev = &out[n++];
            memset(ev, 0, sizeof(*ev));
            ev->kind = AT_APP_EVENT_PEER_OBSERVED;
            memcpy(ev->data.peer.peer_uuid, msg.info.peer_observed.peer_uuid,
                   AT_APP_UUID_LEN);
            memcpy(ev->data.peer.signing_pubkey,
                   msg.info.peer_observed.signing_pubkey,
                   AT_APP_SIGNING_KEY_LEN);
            ev->data.peer.rank = msg.info.peer_observed.rank;
            ev->data.peer.operator_bound =
                msg.info.peer_observed.operator_bound;
            /* Re-assert the invariant the emitter already enforces, so it
             * holds even if this handle is fed by some other producer: an
             * attendance stamp without a verified operator means nothing. */
            ev->data.peer.operator_attested_at =
                msg.info.peer_observed.operator_bound
                    ? msg.info.peer_observed.operator_attested_at : 0.0;
            /* Same re-assertion for the guardian key: a consumer reading this
             * ABI must never see a named guardian on a peer whose human was
             * not verified, whoever produced the message. The event was
             * memset above, so declining to copy IS the all-zero "no guardian
             * advertised" answer. */
            if (msg.info.peer_observed.operator_bound)
                memcpy(ev->data.peer.operator_pubkey,
                       msg.info.peer_observed.operator_pubkey,
                       AT_APP_SIGNING_KEY_LEN);
            ev->data.peer.in_group = msg.info.peer_observed.in_group;
            ev->data.peer.blocked = msg.info.peer_observed.blocked;
            break;
        }
        case PEER_REPUTATION:
        {
            at_app_event_t *ev = &out[n++];
            memset(ev, 0, sizeof(*ev));
            ev->kind = AT_APP_EVENT_PEER_REPUTATION;
            memcpy(ev->data.reputation.peer_uuid,
                   msg.info.peer_reputation.peer_uuid, AT_APP_UUID_LEN);
            ev->data.reputation.rated = msg.info.peer_reputation.rated;
            ev->data.reputation.score =
                msg.info.peer_reputation.rated
                    ? msg.info.peer_reputation.score : 0.0;
            ev->data.reputation.effective_tier =
                msg.info.peer_reputation.effective_tier;
            /* Written on EVERY path, including the no-ceiling one: the event
             * was memset above, and an unwritten 0.0 would read as "floored at
             * zero" rather than "unbounded". */
            ev->data.reputation.standing_ceiling =
                msg.info.peer_reputation.standing_ceiling < 0.0
                    ? PEER_NO_CEILING
                    : msg.info.peer_reputation.standing_ceiling;
            break;
        }
        case PEER_RTT_OBSERVED:
        {
            at_app_event_t *ev = &out[n++];
            memset(ev, 0, sizeof(*ev));
            ev->kind = AT_APP_EVENT_PEER_RTT;
            memcpy(ev->data.rtt.peer_uuid,
                   msg.info.peer_rtt_update.peer_uuid, AT_APP_UUID_LEN);
            ev->data.rtt.rtt_ms = msg.info.peer_rtt_update.rtt_ms;
            break;
        }
        case PEER_PRESENCE:
        {
            at_app_event_t *ev = &out[n++];
            memset(ev, 0, sizeof(*ev));
            ev->kind = AT_APP_EVENT_PEER_PRESENCE;
            memcpy(ev->data.presence.peer_uuid,
                   msg.info.peer_presence.peer_uuid, AT_APP_UUID_LEN);
            ev->data.presence.present = msg.info.peer_presence.present;
            ev->data.presence.last_heard = msg.info.peer_presence.last_heard;
            break;
        }
        default:
        {
            /* A feature's event (app_events_registry.h), e.g. Agora's. The
             * slot is zeroed first, as every inline case always did. */
            at_app_event_decoder_t dec = at_app_event_decoder_lookup(msg.type);
            /* Not app-facing: skipped rather than surfaced as an event. A
             * consumer of this ABI is not given AT's internal traffic. */
            if (dec == NULL)
                break;
            at_app_event_t *ev = &out[n];
            memset(ev, 0, sizeof(*ev));
            if (dec(&msg, ev) == 0)
                n++;
            break;
        }
        }
    }
    messaging_recv_release(&msg);
    return (int)n;
}

int at_app_events_request_roster(at_app_events_t *handle, const char *q_out)
{
    if (handle == NULL || !at_app_name_survives(q_out))
        return -1;
    /* Separate "nobody is listening yet" from "the send failed", because on a cold
     * daemon the first is the ordinary case and the two were the same answer. */
    if (!messaging_bound(q_out))
        return AT_APP_NOT_READY;
    generic_msg_t req = {0};
    req.type = NET_MESSAGE;
    snprintf(req.info.net_msg.process, sizeof(req.info.net_msg.process),
             "identity");
    req.info.net_msg.function = (char *)AT_APP_ROSTER_REQUEST;
    req.info.net_msg.encrypt = false;
    return messaging_send(q_out, NET_MESSAGE, &req, false) == 0 ? 0 : -1;
}


int at_app_events_peer_standing(at_app_events_t *handle, const char *q_out,
                                const uint8_t peer_uuid[AT_APP_UUID_LEN],
                                const char *standing, double ceiling,
                                const char *source, const char *reason)
{
    if (handle == NULL || !at_app_name_survives(q_out) || peer_uuid == NULL
        || standing == NULL || source == NULL)
        return -1;
    /* Refuse the two shapes the core would only refuse later, HERE, where the
     * caller still has the context to say what it meant. An off-scale ceiling
     * is not a bound on AT's [0, 1] scale at all, and a caller claiming to
     * speak as ZTA is either confused or forging: an app cannot know what a
     * credential authority proved. Both are refused again in the handler,
     * because this library is not the only way to reach it. */
    if (ceiling > 1.0)
        return -1;
    if (strcmp(source, PEER_STANDING_SOURCE_ZTA) == 0)
        return -1;
    if (!messaging_bound(q_out))
        return AT_APP_NOT_READY;
    char uuid_str[37];
    uuid_unparse_lower((const unsigned char *)peer_uuid, uuid_str);
    json_t *env = json_object();
    if (env == NULL)
        return -1;
    json_object_set_new(env, "peer", json_string(uuid_str));
    json_object_set_new(env, "standing", json_string(standing));
    json_object_set_new(env, "ceiling", json_real(ceiling));
    json_object_set_new(env, "source", json_string(source));
    json_object_set_new(env, "reason", json_string(reason ? reason : ""));
    generic_msg_t req = {0};
    req.type = NET_MESSAGE;
    snprintf(req.info.net_msg.process, sizeof(req.info.net_msg.process),
             "identity");
    req.info.net_msg.function = (char *)AT_APP_PEER_STANDING;
    req.info.net_msg.encrypt = false;
    if (net_msg_pack_json(&req.info.net_msg, env) != 0) {
        json_decref(env);
        return -1;
    }
    json_decref(env);
    int rc = messaging_send(q_out, NET_MESSAGE, &req, false);
    net_msg_free_obj(&req.info.net_msg);
    return rc == 0 ? 0 : -1;
}

uint32_t at_app_abi_version(void)
{
    return AT_APP_ABI_VERSION;
}

/* ---- The decoder registry (app_events_registry.h). Filled by constructors
 * before main(), read-only after, so unlocked -- as msg_registry.c. ---- */

static struct {
    long msg_type;
    at_app_event_decoder_t fn;
} _decoders[AT_APP_EVENT_DECODER_MAX];
static size_t _decoders_len = 0;

int at_app_event_decoder_register(long msg_type, at_app_event_decoder_t fn)
{
    if (fn == NULL || msg_type < AT_MSG_TYPE_EXT_MIN
        || at_app_event_decoder_lookup(msg_type) != NULL)
    {
        fprintf(stderr, "at_app_event_decoder_register: refusing type %ld\n", msg_type);
        return -1;
    }
    if (_decoders_len >= AT_APP_EVENT_DECODER_MAX)
    {
        fprintf(stderr, "at_app_event_decoder_register: refusing type %ld: full\n", msg_type);
        return -2;
    }
    _decoders[_decoders_len].msg_type = msg_type;
    _decoders[_decoders_len].fn = fn;
    _decoders_len++;
    return 0;
}

at_app_event_decoder_t at_app_event_decoder_lookup(long msg_type)
{
    for (size_t i = 0; i < _decoders_len; i++)
        if (_decoders[i].msg_type == msg_type)
            return _decoders[i].fn;
    return NULL;
}

void at_app_events_close(at_app_events_t *handle)
{
    if (handle == NULL)
        return;
    if (handle->owns_queue)
        messaging_qclose(&handle->queue);
    free(handle);
}
