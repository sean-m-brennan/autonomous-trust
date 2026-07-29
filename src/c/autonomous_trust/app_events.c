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

#include "app_events.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"

struct at_app_events_s {
    queue_t queue;
    /* False when the handle borrows a queue somebody else bound (see
     * at_app_events_open_existing) — then close must not unbind it. */
    bool owns_queue;
};

at_app_events_t *at_app_events_open(const char *q_in)
{
    if (q_in == NULL || q_in[0] == '\0')
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
    if (handle == NULL || q_out == NULL || q_out[0] == '\0')
        return -1;
    generic_msg_t req = {0};
    req.type = NET_MESSAGE;
    snprintf(req.info.net_msg.process, sizeof(req.info.net_msg.process),
             "identity");
    req.info.net_msg.function = (char *)AT_APP_ROSTER_REQUEST;
    req.info.net_msg.encrypt = false;
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
