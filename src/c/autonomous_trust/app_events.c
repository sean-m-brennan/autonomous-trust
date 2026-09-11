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

#include <stdlib.h>
#include <string.h>

#include <jansson.h>

#include "app_events.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
#include "utilities/msg_types_priv.h"   /* net_msg_pack_json */

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
static bool name_survives(const char *name)
{
    return name != NULL && name[0] != '\0' && strlen(name) <= MSG_KEY_LEN - 1;
}

at_app_events_t *at_app_events_open(const char *q_in)
{
    if (!name_survives(q_in))
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
    while (n < max)
    {
        generic_msg_t msg = {0};
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
        case PEER_POSITION_OBSERVED:
        {
            at_app_event_t *ev = &out[n++];
            memset(ev, 0, sizeof(*ev));
            ev->kind = AT_APP_EVENT_PEER_POSITION;
            memcpy(ev->data.position.peer_uuid,
                   msg.info.peer_position.peer_uuid, AT_APP_UUID_LEN);
            /* Bounded copy of the opaque geohash; the emitter already NUL-caps
             * it, and the event was memset so a short string stays terminated. */
            memcpy(ev->data.position.geohash, msg.info.peer_position.geohash,
                   AT_APP_GEOHASH_LEN);
            ev->data.position.geohash[AT_APP_GEOHASH_LEN] = '\0';
            break;
        }
        case PEER_PROFILE_OBSERVED:
        {
            at_app_event_t *ev = &out[n++];
            memset(ev, 0, sizeof(*ev));
            ev->kind = AT_APP_EVENT_PEER_PROFILE;
            memcpy(ev->data.profile.peer_uuid,
                   msg.info.peer_profile.peer_uuid, AT_APP_UUID_LEN);
            /* Bounded copy of the compact profile JSON; the emitter NUL-caps it
             * and the event was memset, so a short string stays terminated. */
            memcpy(ev->data.profile.profile_json,
                   msg.info.peer_profile.profile_json, AT_APP_PROFILE_JSON_LEN);
            ev->data.profile.profile_json[AT_APP_PROFILE_JSON_LEN] = '\0';
            break;
        }
        default:
            /* Not app-facing: skipped rather than surfaced as an event. A
             * consumer of this ABI is not given AT's internal traffic. */
            break;
        }
    }
    return (int)n;
}

int at_app_events_request_roster(at_app_events_t *handle, const char *q_out)
{
    if (handle == NULL || !name_survives(q_out))
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

int at_app_events_set_position(at_app_events_t *handle, const char *q_out,
                               const char *geohash)
{
    if (handle == NULL || !name_survives(q_out))
        return -1;
    if (!messaging_bound(q_out))
        return AT_APP_NOT_READY;
    generic_msg_t req = {0};
    req.type = NET_MESSAGE;
    snprintf(req.info.net_msg.process, sizeof(req.info.net_msg.process),
             "identity");
    req.info.net_msg.function = (char *)AT_APP_SET_POSITION;
    req.info.net_msg.encrypt = false;
    /* {"pos": "<geohash>"}; NULL/"" opts out (clears own position). */
    json_t *env = json_object();
    if (env == NULL)
        return -1;
    json_object_set_new(env, "pos",
                        json_string(geohash != NULL ? geohash : ""));
    if (net_msg_pack_json(&req.info.net_msg, env) != 0) {
        json_decref(env);
        return -1;
    }
    json_decref(env);
    return messaging_send(q_out, NET_MESSAGE, &req, false) == 0 ? 0 : -1;
}

int at_app_events_set_profile(at_app_events_t *handle, const char *q_out,
                              const char *profile_json)
{
    if (handle == NULL || !name_survives(q_out))
        return -1;
    if (!messaging_bound(q_out))
        return AT_APP_NOT_READY;
    /* Payload IS the profile object; NULL/"" => empty object => clears it. */
    json_t *env = NULL;
    if (profile_json != NULL && profile_json[0] != '\0') {
        json_error_t jerr;
        env = json_loads(profile_json, 0, &jerr);
        if (env == NULL || !json_is_object(env)) {
            if (env != NULL) json_decref(env);
            return -1;
        }
    } else {
        env = json_object();
        if (env == NULL) return -1;
    }
    generic_msg_t req = {0};
    req.type = NET_MESSAGE;
    snprintf(req.info.net_msg.process, sizeof(req.info.net_msg.process),
             "identity");
    req.info.net_msg.function = (char *)AT_APP_SET_PROFILE;
    req.info.net_msg.encrypt = false;
    if (net_msg_pack_json(&req.info.net_msg, env) != 0) {
        json_decref(env);
        return -1;
    }
    json_decref(env);
    return messaging_send(q_out, NET_MESSAGE, &req, false) == 0 ? 0 : -1;
}

void at_app_events_close(at_app_events_t *handle)
{
    if (handle == NULL)
        return;
    if (handle->owns_queue)
        messaging_qclose(&handle->queue);
    free(handle);
}
