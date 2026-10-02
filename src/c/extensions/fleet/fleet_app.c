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

/**
 * @file fleet_app.c
 * @brief at_fleet.h: the app-side sender of app_fleet_propose and the decoder
 *        that turns FLEET_UPDATE_ACCEPTED into an app event.
 */

#include <stdio.h>
#include <string.h>

#include <jansson.h>

#include "fleet/at_fleet.h"
#include "fleet/fleet_proc.h"
#include "fleet/update_proposal.h"
#include "app_events_registry.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"   /* net_msg_pack_json */

static int _decode_accepted(const generic_msg_t *msg, at_app_event_t *ev)
{
    const fleet_update_accepted_msg_t *m = AT_MSG_EXT_CONST(msg, fleet_update_accepted_msg_t);
    at_app_fleet_accepted_t *out = AT_APP_EVENT_EXT(ev, at_app_fleet_accepted_t);
    ev->kind = AT_APP_EVENT_FLEET_UPDATE_ACCEPTED;
    memcpy(out->proposal_uuid, m->proposal_uuid, AT_APP_UUID_LEN);
    return 0;
}
AT_APP_EVENT_DECODER_REGISTER(fleet_update_accepted, FLEET_UPDATE_ACCEPTED, _decode_accepted)

const at_app_fleet_accepted_t *at_fleet_accepted_event(const at_app_event_t *ev)
{
    if (ev == NULL || ev->kind != AT_APP_EVENT_FLEET_UPDATE_ACCEPTED)
        return NULL;
    return (const at_app_fleet_accepted_t *)(const void *)ev->data.payload;
}

static bool _is_hex(const char *s, size_t len)
{
    if (s == NULL || strlen(s) != len)
        return false;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return false;
    }
    return true;
}

int at_app_fleet_propose(at_app_events_t *handle, const char *q_out, const char *version,
                         const char *artifact_hash, const char *target_arch,
                         double min_proposer_reputation)
{
    if (handle == NULL || !at_app_name_survives(q_out) || version == NULL
        || version[0] == '\0' || strlen(version) > UPDATE_VERSION_LEN
        || !_is_hex(artifact_hash, 2 * UPDATE_HASH_LEN)
        || (target_arch != NULL && strlen(target_arch) > UPDATE_ARCH_LEN))
        return -1;
    if (!messaging_bound(q_out))
        return AT_APP_NOT_READY;
    json_t *body = json_pack("{s:s, s:s, s:s, s:f}", "version", version,
                             "artifact_hash", artifact_hash,
                             "target_arch", target_arch != NULL ? target_arch : "unknown",
                             "min_proposer_reputation", min_proposer_reputation);
    if (body == NULL)
        return -1;
    generic_msg_t req = {0};
    req.type = NET_MESSAGE;
    snprintf(req.info.net_msg.process, sizeof(req.info.net_msg.process), "fleet");
    req.info.net_msg.function = (char *)AT_APP_FLEET_PROPOSE;
    req.info.net_msg.encrypt = false;
    int rc = net_msg_pack_json(&req.info.net_msg, body);
    json_decref(body);
    if (rc != 0)
        return -1;
    rc = messaging_send(q_out, NET_MESSAGE, &req, false);
    net_msg_free_obj(&req.info.net_msg);
    return rc == 0 ? 0 : -1;
}
