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
#include <uuid/uuid.h>

#include "app_events.h"
#include "utilities/message.h"
#include "utilities/msg_types.h"
#include "utilities/msg_types_priv.h"   /* net_msg_pack_json */
#ifdef AT_SOCIAL_ENABLED
#include "identity/cosign.h"             /* at_cosign_op_ok / at_cosign_bytes_ok */
#endif

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
#ifdef AT_SOCIAL_ENABLED
            ev->data.peer.in_group = msg.info.peer_observed.in_group;
#endif /* AT_SOCIAL_ENABLED */
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
#ifdef AT_SOCIAL_ENABLED
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
        case PEER_BUSINESS_AD_OBSERVED:
        {
            at_app_event_t *ev = &out[n++];
            memset(ev, 0, sizeof(*ev));
            ev->kind = AT_APP_EVENT_BUSINESS_AD;
            memcpy(ev->data.business_ad.advertiser_uuid,
                   msg.info.peer_business_ad.peer_uuid, AT_APP_UUID_LEN);
            /* The emitter NUL-caps every string; the event was memset, so a
             * short string stays terminated after the bounded copy. */
            memcpy(ev->data.business_ad.polity, msg.info.peer_business_ad.polity,
                   AT_APP_BUSINESS_DID_LEN);
            ev->data.business_ad.polity[AT_APP_BUSINESS_DID_LEN] = '\0';
            memcpy(ev->data.business_ad.ad_id, msg.info.peer_business_ad.ad_id,
                   AT_APP_BUSINESS_AD_ID_LEN);
            ev->data.business_ad.ad_id[AT_APP_BUSINESS_AD_ID_LEN] = '\0';
            ev->data.business_ad.satisfaction =
                msg.info.peer_business_ad.satisfaction;
            ev->data.business_ad.seq = msg.info.peer_business_ad.seq;
            ev->data.business_ad.ts = msg.info.peer_business_ad.ts;
            memcpy(ev->data.business_ad.bundle, msg.info.peer_business_ad.bundle,
                   AT_APP_BUSINESS_BUNDLE_LEN);
            ev->data.business_ad.bundle[AT_APP_BUSINESS_BUNDLE_LEN] = '\0';
            break;
        }
        case PEER_BUSINESS_POST_OBSERVED:
        {
            at_app_event_t *ev = &out[n++];
            memset(ev, 0, sizeof(*ev));
            ev->kind = AT_APP_EVENT_BUSINESS_POST;
            memcpy(ev->data.business_post.publisher_uuid,
                   msg.info.peer_business_post.peer_uuid, AT_APP_UUID_LEN);
            /* The emitter NUL-caps every string; the event was memset, so a
             * short string stays terminated after the bounded copy. */
            memcpy(ev->data.business_post.polity,
                   msg.info.peer_business_post.polity, AT_APP_BUSINESS_DID_LEN);
            ev->data.business_post.polity[AT_APP_BUSINESS_DID_LEN] = '\0';
            memcpy(ev->data.business_post.post_id,
                   msg.info.peer_business_post.post_id,
                   AT_APP_BUSINESS_POST_ID_LEN);
            ev->data.business_post.post_id[AT_APP_BUSINESS_POST_ID_LEN] = '\0';
            ev->data.business_post.seq = msg.info.peer_business_post.seq;
            ev->data.business_post.ts = msg.info.peer_business_post.ts;
            ev->data.business_post.hops = msg.info.peer_business_post.hops;
            memcpy(ev->data.business_post.bundle,
                   msg.info.peer_business_post.bundle,
                   AT_APP_BUSINESS_POST_BUNDLE_LEN);
            ev->data.business_post.bundle[AT_APP_BUSINESS_POST_BUNDLE_LEN] = '\0';
            break;
        }
        case PEER_COSIGN_REQUEST_OBSERVED:
        {
            at_app_event_t *ev = &out[n++];
            memset(ev, 0, sizeof(*ev));
            ev->kind = AT_APP_EVENT_COSIGN_REQUEST;
            memcpy(ev->data.cosign_request.requester_uuid,
                   msg.info.peer_cosign_request.peer_uuid, AT_APP_UUID_LEN);
            /* The emitter NUL-caps every string; the event was memset, so a
             * short string stays terminated after the bounded copy. */
            memcpy(ev->data.cosign_request.record,
                   msg.info.peer_cosign_request.record, AT_APP_COSIGN_TOKEN_LEN);
            ev->data.cosign_request.record[AT_APP_COSIGN_TOKEN_LEN] = '\0';
            memcpy(ev->data.cosign_request.op,
                   msg.info.peer_cosign_request.op, AT_APP_COSIGN_TOKEN_LEN);
            ev->data.cosign_request.op[AT_APP_COSIGN_TOKEN_LEN] = '\0';
            memcpy(ev->data.cosign_request.polity,
                   msg.info.peer_cosign_request.polity, AT_APP_COSIGN_DID_LEN);
            ev->data.cosign_request.polity[AT_APP_COSIGN_DID_LEN] = '\0';
            memcpy(ev->data.cosign_request.cid,
                   msg.info.peer_cosign_request.cid, AT_APP_COSIGN_CID_LEN);
            ev->data.cosign_request.cid[AT_APP_COSIGN_CID_LEN] = '\0';
            ev->data.cosign_request.seq = msg.info.peer_cosign_request.seq;
            ev->data.cosign_request.ts = msg.info.peer_cosign_request.ts;
            memcpy(ev->data.cosign_request.bytes,
                   msg.info.peer_cosign_request.bytes, AT_APP_COSIGN_BYTES_LEN);
            ev->data.cosign_request.bytes[AT_APP_COSIGN_BYTES_LEN] = '\0';
            break;
        }
        case PEER_COSIGN_SIG_OBSERVED:
        {
            at_app_event_t *ev = &out[n++];
            memset(ev, 0, sizeof(*ev));
            ev->kind = AT_APP_EVENT_COSIGN_SIGNATURE;
            memcpy(ev->data.cosign_sig.signer_uuid,
                   msg.info.peer_cosign_sig.peer_uuid, AT_APP_UUID_LEN);
            memcpy(ev->data.cosign_sig.cid, msg.info.peer_cosign_sig.cid,
                   AT_APP_COSIGN_CID_LEN);
            ev->data.cosign_sig.cid[AT_APP_COSIGN_CID_LEN] = '\0';
            memcpy(ev->data.cosign_sig.signer_did,
                   msg.info.peer_cosign_sig.signer, AT_APP_COSIGN_DID_LEN);
            ev->data.cosign_sig.signer_did[AT_APP_COSIGN_DID_LEN] = '\0';
            memcpy(ev->data.cosign_sig.sig, msg.info.peer_cosign_sig.sig,
                   AT_APP_COSIGN_SIG_LEN);
            ev->data.cosign_sig.sig[AT_APP_COSIGN_SIG_LEN] = '\0';
            ev->data.cosign_sig.seq = msg.info.peer_cosign_sig.seq;
            ev->data.cosign_sig.ts = msg.info.peer_cosign_sig.ts;
            break;
        }
        case PEER_PROXIMITY_OBSERVED:
        {
            at_app_event_t *ev = &out[n++];
            memset(ev, 0, sizeof(*ev));
            ev->kind = AT_APP_EVENT_PROXIMITY;
            memcpy(ev->data.proximity.peer_uuid,
                   msg.info.peer_proximity.peer_uuid, AT_APP_UUID_LEN);
            ev->data.proximity.band = (int32_t)msg.info.peer_proximity.band;
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
        case PEER_CONNECTION_REQUEST_OBSERVED:
        {
            at_app_event_t *ev = &out[n++];
            memset(ev, 0, sizeof(*ev));
            ev->kind = AT_APP_EVENT_CONNECTION_REQUEST;
            memcpy(ev->data.connection.peer_uuid,
                   msg.info.peer_connection.peer_uuid, AT_APP_UUID_LEN);
            ev->data.connection.state = msg.info.peer_connection.state;
            break;
        }
        case PEER_CONNECTION_STATE_OBSERVED:
        {
            at_app_event_t *ev = &out[n++];
            memset(ev, 0, sizeof(*ev));
            ev->kind = AT_APP_EVENT_CONNECTION_STATE;
            memcpy(ev->data.connection.peer_uuid,
                   msg.info.peer_connection.peer_uuid, AT_APP_UUID_LEN);
            ev->data.connection.state = msg.info.peer_connection.state;
            break;
        }
        case PEER_DM_OBSERVED:
        {
            at_app_event_t *ev = &out[n++];
            memset(ev, 0, sizeof(*ev));
            ev->kind = AT_APP_EVENT_DM;
            memcpy(ev->data.dm.peer_uuid,
                   msg.info.peer_dm.peer_uuid, AT_APP_UUID_LEN);
            ev->data.dm.seq = msg.info.peer_dm.seq;
            ev->data.dm.ts = msg.info.peer_dm.ts;
            /* Bounded copy of the message body; the emitter NUL-caps it and the
             * event was memset, so a short string stays terminated. */
            memcpy(ev->data.dm.text, msg.info.peer_dm.text, AT_APP_DM_TEXT_LEN);
            ev->data.dm.text[AT_APP_DM_TEXT_LEN] = '\0';
            break;
        }
        case PEER_POST_OBSERVED:
        {
            at_app_event_t *ev = &out[n++];
            memset(ev, 0, sizeof(*ev));
            ev->kind = AT_APP_EVENT_POST;
            memcpy(ev->data.post.author_uuid,
                   msg.info.peer_post.peer_uuid, AT_APP_UUID_LEN);
            /* The emitter NUL-caps both strings; the event was memset, so a
             * short string stays terminated after the bounded copy. */
            memcpy(ev->data.post.post_id, msg.info.peer_post.post_id,
                   AT_APP_POST_ID_LEN);
            ev->data.post.post_id[AT_APP_POST_ID_LEN] = '\0';
            ev->data.post.seq = msg.info.peer_post.seq;
            ev->data.post.ts = msg.info.peer_post.ts;
            ev->data.post.required_tier = msg.info.peer_post.required_tier;
            memcpy(ev->data.post.body, msg.info.peer_post.body,
                   AT_APP_POST_BODY_LEN);
            ev->data.post.body[AT_APP_POST_BODY_LEN] = '\0';
            break;
        }
        case PEER_REACTION_OBSERVED:
        {
            at_app_event_t *ev = &out[n++];
            memset(ev, 0, sizeof(*ev));
            ev->kind = AT_APP_EVENT_REACTION;
            memcpy(ev->data.reaction.peer_uuid,
                   msg.info.peer_reaction.peer_uuid, AT_APP_UUID_LEN);
            /* The emitter NUL-caps the id; the event was memset, so a short
             * string stays terminated after the bounded copy. */
            memcpy(ev->data.reaction.post_id, msg.info.peer_reaction.post_id,
                   AT_APP_POST_ID_LEN);
            ev->data.reaction.post_id[AT_APP_POST_ID_LEN] = '\0';
            ev->data.reaction.seq = msg.info.peer_reaction.seq;
            ev->data.reaction.ts = msg.info.peer_reaction.ts;
            break;
        }
#endif /* AT_SOCIAL_ENABLED */
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

#ifdef AT_SOCIAL_ENABLED
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

/* Shared body for the two connection app→AT verbs (Increment 5): pack
 * {"peer": "<uuid_str>"} plus, for a respond, {"accept": <bool>}, and send the
 * verb to identity. @p accept is ignored unless @p include_accept. */
static int connect_send(at_app_events_t *handle, const char *q_out,
                        const char *verb,
                        const uint8_t peer_uuid[AT_APP_UUID_LEN],
                        bool include_accept, bool accept)
{
    if (handle == NULL || !name_survives(q_out) || peer_uuid == NULL)
        return -1;
    if (!messaging_bound(q_out))
        return AT_APP_NOT_READY;
    char uuid_str[37];
    uuid_unparse_lower((const unsigned char *)peer_uuid, uuid_str);
    json_t *env = json_object();
    if (env == NULL)
        return -1;
    json_object_set_new(env, "peer", json_string(uuid_str));
    if (include_accept)
        json_object_set_new(env, "accept", json_boolean(accept));
    generic_msg_t req = {0};
    req.type = NET_MESSAGE;
    snprintf(req.info.net_msg.process, sizeof(req.info.net_msg.process),
             "identity");
    req.info.net_msg.function = (char *)verb;
    req.info.net_msg.encrypt = false;
    if (net_msg_pack_json(&req.info.net_msg, env) != 0) {
        json_decref(env);
        return -1;
    }
    json_decref(env);
    return messaging_send(q_out, NET_MESSAGE, &req, false) == 0 ? 0 : -1;
}

int at_app_events_connect_request(at_app_events_t *handle, const char *q_out,
                                  const uint8_t peer_uuid[AT_APP_UUID_LEN])
{
    return connect_send(handle, q_out, AT_APP_CONNECT_REQUEST, peer_uuid,
                        false, false);
}

int at_app_events_connect_respond(at_app_events_t *handle, const char *q_out,
                                  const uint8_t peer_uuid[AT_APP_UUID_LEN],
                                  bool accept)
{
    return connect_send(handle, q_out, AT_APP_CONNECT_RESPOND, peer_uuid,
                        true, accept);
}

int at_app_events_request_attend(at_app_events_t *handle, const char *q_out,
                                 const uint8_t peer_uuid[AT_APP_UUID_LEN])
{
    /* Same {"peer": "<uuid>"} shape as a connect request; identity issues a
     * nonce-fresh operator_attest_query to the peer (Phase 2, presence). */
    return connect_send(handle, q_out, AT_APP_REQUEST_ATTEND, peer_uuid,
                        false, false);
}

int at_app_events_request_proximity(at_app_events_t *handle, const char *q_out,
                                    const uint8_t peer_uuid[AT_APP_UUID_LEN])
{
    /* {"peer": "<uuid>"}; identity runs the pairwise distance-band probe with
     * this CONNECTED peer (Phase 2, private proximity). */
    return connect_send(handle, q_out, AT_APP_REQUEST_PROXIMITY, peer_uuid,
                        false, false);
}

int at_app_events_set_exact_position(at_app_events_t *handle, const char *q_out,
                                     bool opt_in, double lat, double lon)
{
    if (handle == NULL || !name_survives(q_out))
        return -1;
    if (!messaging_bound(q_out))
        return AT_APP_NOT_READY;
    /* {"lat","lon"} to opt in; an empty object to opt out (clear). The exact
     * position is stored LOCAL-ONLY by identity and never advertised. */
    json_t *env = json_object();
    if (env == NULL)
        return -1;
    if (opt_in) {
        json_object_set_new(env, "lat", json_real(lat));
        json_object_set_new(env, "lon", json_real(lon));
    }
    generic_msg_t req = {0};
    req.type = NET_MESSAGE;
    snprintf(req.info.net_msg.process, sizeof(req.info.net_msg.process),
             "identity");
    req.info.net_msg.function = (char *)AT_APP_SET_EXACT_POSITION;
    req.info.net_msg.encrypt = false;
    if (net_msg_pack_json(&req.info.net_msg, env) != 0) {
        json_decref(env);
        return -1;
    }
    json_decref(env);
    return messaging_send(q_out, NET_MESSAGE, &req, false) == 0 ? 0 : -1;
}

int at_app_events_send_dm(at_app_events_t *handle, const char *q_out,
                          const uint8_t peer_uuid[AT_APP_UUID_LEN],
                          const char *text)
{
    if (handle == NULL || !name_survives(q_out) || peer_uuid == NULL)
        return -1;
    if (!messaging_bound(q_out))
        return AT_APP_NOT_READY;
    char uuid_str[37];
    uuid_unparse_lower((const unsigned char *)peer_uuid, uuid_str);
    /* {"peer": "<uuid_str>", "text": "<body>"}; identity bound-truncates text
     * and sends the directed encrypted peer_dm. */
    json_t *env = json_object();
    if (env == NULL)
        return -1;
    json_object_set_new(env, "peer", json_string(uuid_str));
    json_object_set_new(env, "text", json_string(text != NULL ? text : ""));
    generic_msg_t req = {0};
    req.type = NET_MESSAGE;
    snprintf(req.info.net_msg.process, sizeof(req.info.net_msg.process),
             "identity");
    req.info.net_msg.function = (char *)AT_APP_SEND_DM;
    req.info.net_msg.encrypt = false;
    if (net_msg_pack_json(&req.info.net_msg, env) != 0) {
        json_decref(env);
        return -1;
    }
    json_decref(env);
    return messaging_send(q_out, NET_MESSAGE, &req, false) == 0 ? 0 : -1;
}

int at_app_events_publish_post(at_app_events_t *handle, const char *q_out,
                               const char *body, int required_tier)
{
    if (handle == NULL || !name_survives(q_out))
        return -1;
    if (!messaging_bound(q_out))
        return AT_APP_NOT_READY;
    if (required_tier < 0) required_tier = 0;
    if (required_tier > 4) required_tier = 4;
    /* {"body": "<body>", "tier": <int>}; identity signs, group-encrypts and
     * multicasts the post. */
    json_t *env = json_object();
    if (env == NULL)
        return -1;
    json_object_set_new(env, "body", json_string(body != NULL ? body : ""));
    json_object_set_new(env, "tier", json_integer(required_tier));
    generic_msg_t req = {0};
    req.type = NET_MESSAGE;
    snprintf(req.info.net_msg.process, sizeof(req.info.net_msg.process),
             "identity");
    req.info.net_msg.function = (char *)AT_APP_PUBLISH_POST;
    req.info.net_msg.encrypt = false;
    if (net_msg_pack_json(&req.info.net_msg, env) != 0) {
        json_decref(env);
        return -1;
    }
    json_decref(env);
    return messaging_send(q_out, NET_MESSAGE, &req, false) == 0 ? 0 : -1;
}

int at_app_events_advertise_business(at_app_events_t *handle, const char *q_out,
                                     const char *polity_did, const char *bundle,
                                     int64_t seq)
{
    if (handle == NULL || !name_survives(q_out) || polity_did == NULL
        || bundle == NULL || polity_did[0] == '\0' || bundle[0] == '\0')
        return -1;
    if (!messaging_bound(q_out))
        return AT_APP_NOT_READY;
    /* {"polity": "<did>", "bundle": "<opaque ethne json>", "seq": <int>};
     * identity signs the ad with THIS node's key and group-multicasts it. */
    json_t *env = json_object();
    if (env == NULL)
        return -1;
    json_object_set_new(env, "polity", json_string(polity_did));
    json_object_set_new(env, "bundle", json_string(bundle));
    json_object_set_new(env, "seq", json_integer((json_int_t)seq));
    generic_msg_t req = {0};
    req.type = NET_MESSAGE;
    snprintf(req.info.net_msg.process, sizeof(req.info.net_msg.process),
             "identity");
    req.info.net_msg.function = (char *)AT_APP_ADVERTISE_BUSINESS;
    req.info.net_msg.encrypt = false;
    if (net_msg_pack_json(&req.info.net_msg, env) != 0) {
        json_decref(env);
        return -1;
    }
    json_decref(env);
    return messaging_send(q_out, NET_MESSAGE, &req, false) == 0 ? 0 : -1;
}

int at_app_events_publish_business_post(at_app_events_t *handle, const char *q_out,
                                        const char *polity_did, const char *bundle,
                                        int64_t seq)
{
    if (handle == NULL || !name_survives(q_out) || polity_did == NULL
        || bundle == NULL || polity_did[0] == '\0' || bundle[0] == '\0')
        return -1;
    if (!messaging_bound(q_out))
        return AT_APP_NOT_READY;
    /* {"polity": "<did>", "bundle": "<opaque ethne {post,delegation}>",
     *  "seq": <int>}; identity signs the canonical post with THIS node's key
     * and group-multicasts it. The envoy signature that makes it the
     * business's word is already INSIDE the bundle — this call cannot and does
     * not confer it. */
    json_t *env = json_object();
    if (env == NULL)
        return -1;
    json_object_set_new(env, "polity", json_string(polity_did));
    json_object_set_new(env, "bundle", json_string(bundle));
    json_object_set_new(env, "seq", json_integer((json_int_t)seq));
    generic_msg_t req = {0};
    req.type = NET_MESSAGE;
    snprintf(req.info.net_msg.process, sizeof(req.info.net_msg.process),
             "identity");
    req.info.net_msg.function = (char *)AT_APP_PUBLISH_BUSINESS_POST;
    req.info.net_msg.encrypt = false;
    if (net_msg_pack_json(&req.info.net_msg, env) != 0) {
        json_decref(env);
        return -1;
    }
    json_decref(env);
    return messaging_send(q_out, NET_MESSAGE, &req, false) == 0 ? 0 : -1;
}

int at_app_events_set_customer(at_app_events_t *handle, const char *q_out,
                               const char *polity_did, int satisfaction,
                               const char *bundle, int64_t seq)
{
    if (handle == NULL || !name_survives(q_out) || polity_did == NULL
        || polity_did[0] == '\0')
        return -1;
    if (!messaging_bound(q_out))
        return AT_APP_NOT_READY;
    if (satisfaction > 4) satisfaction = 4;
    /* {"polity": "<did>", "satisfaction": <0..4 | -1 to clear>,
     *  "bundle": "<opaque ethne json>", "seq": <int>}. A negative satisfaction
     * clears the customer edge, after which this node simply goes quiet about
     * the business — it never publishes a negative. */
    json_t *env = json_object();
    if (env == NULL)
        return -1;
    json_object_set_new(env, "polity", json_string(polity_did));
    json_object_set_new(env, "satisfaction", json_integer(satisfaction));
    json_object_set_new(env, "bundle",
                        json_string(bundle != NULL ? bundle : ""));
    json_object_set_new(env, "seq", json_integer((json_int_t)seq));
    generic_msg_t req = {0};
    req.type = NET_MESSAGE;
    snprintf(req.info.net_msg.process, sizeof(req.info.net_msg.process),
             "identity");
    req.info.net_msg.function = (char *)AT_APP_SET_CUSTOMER;
    req.info.net_msg.encrypt = false;
    if (net_msg_pack_json(&req.info.net_msg, env) != 0) {
        json_decref(env);
        return -1;
    }
    json_decref(env);
    return messaging_send(q_out, NET_MESSAGE, &req, false) == 0 ? 0 : -1;
}

int at_app_events_react_post(at_app_events_t *handle, const char *q_out,
                             const uint8_t author_uuid[AT_APP_UUID_LEN],
                             const char *post_id)
{
    if (handle == NULL || !name_survives(q_out) || author_uuid == NULL
        || post_id == NULL)
        return -1;
    if (!messaging_bound(q_out))
        return AT_APP_NOT_READY;
    char uuid_str[37];
    uuid_unparse_lower((const unsigned char *)author_uuid, uuid_str);
    /* {"author": "<uuid_str>", "post_id": "<hex>"}; identity sends the directed
     * encrypted peer_reaction to the author. */
    json_t *env = json_object();
    if (env == NULL)
        return -1;
    json_object_set_new(env, "author", json_string(uuid_str));
    json_object_set_new(env, "post_id", json_string(post_id));
    generic_msg_t req = {0};
    req.type = NET_MESSAGE;
    snprintf(req.info.net_msg.process, sizeof(req.info.net_msg.process),
             "identity");
    req.info.net_msg.function = (char *)AT_APP_REACT_POST;
    req.info.net_msg.encrypt = false;
    if (net_msg_pack_json(&req.info.net_msg, env) != 0) {
        json_decref(env);
        return -1;
    }
    json_decref(env);
    return messaging_send(q_out, NET_MESSAGE, &req, false) == 0 ? 0 : -1;
}

int at_app_events_block(at_app_events_t *handle, const char *q_out,
                        const uint8_t peer_uuid[AT_APP_UUID_LEN])
{
    if (handle == NULL || !name_survives(q_out) || peer_uuid == NULL)
        return -1;
    if (!messaging_bound(q_out))
        return AT_APP_NOT_READY;
    char uuid_str[37];
    uuid_unparse_lower((const unsigned char *)peer_uuid, uuid_str);
    /* {"peer": "<uuid_str>"}; identity clamps the peer's local tier to 0. */
    json_t *env = json_object();
    if (env == NULL)
        return -1;
    json_object_set_new(env, "peer", json_string(uuid_str));
    generic_msg_t req = {0};
    req.type = NET_MESSAGE;
    snprintf(req.info.net_msg.process, sizeof(req.info.net_msg.process),
             "identity");
    req.info.net_msg.function = (char *)AT_APP_BLOCK;
    req.info.net_msg.encrypt = false;
    if (net_msg_pack_json(&req.info.net_msg, env) != 0) {
        json_decref(env);
        return -1;
    }
    json_decref(env);
    return messaging_send(q_out, NET_MESSAGE, &req, false) == 0 ? 0 : -1;
}

int at_app_events_request_cosign(at_app_events_t *handle, const char *q_out,
                                 const uint8_t *peer_uuids, size_t n_peers,
                                 const char *record, const char *op,
                                 const char *polity_did, const char *cid,
                                 const char *bytes)
{
    if (handle == NULL || !name_survives(q_out) || peer_uuids == NULL
        || n_peers == 0 || polity_did == NULL || cid == NULL
        || polity_did[0] == '\0' || cid[0] == '\0')
        return -1;
    /* Refuse an unknown act or a payload that never came from an exporter,
     * HERE, where the caller still has it. A malformed ask that reached the
     * signers would only be refused after somebody had been interrupted to look
     * at it. */
    if (!at_cosign_op_ok(record, op) || !at_cosign_bytes_ok(bytes))
        return -1;
    if (!messaging_bound(q_out))
        return AT_APP_NOT_READY;
    json_t *peers = json_array();
    if (peers == NULL)
        return -1;
    for (size_t i = 0; i < n_peers; i++) {
        char uuid_str[37];
        uuid_unparse_lower((const unsigned char *)(peer_uuids + i * AT_APP_UUID_LEN),
                           uuid_str);
        if (json_array_append_new(peers, json_string(uuid_str)) != 0) {
            json_decref(peers);
            return -1;
        }
    }
    /* {"peers": [...], "record", "op", "polity", "cid", "bytes"}; identity sends
     * each named peer a directed encrypted peer_cosign_request. NO description:
     * every signer's own node derives what the bytes commit to. */
    json_t *env = json_object();
    if (env == NULL) {
        json_decref(peers);
        return -1;
    }
    json_object_set_new(env, "peers", peers);
    json_object_set_new(env, "record", json_string(record));
    json_object_set_new(env, "op", json_string(op));
    json_object_set_new(env, "polity", json_string(polity_did));
    json_object_set_new(env, "cid", json_string(cid));
    json_object_set_new(env, "bytes", json_string(bytes));
    generic_msg_t req = {0};
    req.type = NET_MESSAGE;
    snprintf(req.info.net_msg.process, sizeof(req.info.net_msg.process),
             "identity");
    req.info.net_msg.function = (char *)AT_APP_REQUEST_COSIGN;
    req.info.net_msg.encrypt = false;
    if (net_msg_pack_json(&req.info.net_msg, env) != 0) {
        json_decref(env);
        return -1;
    }
    json_decref(env);
    return messaging_send(q_out, NET_MESSAGE, &req, false) == 0 ? 0 : -1;
}

int at_app_events_return_cosign(at_app_events_t *handle, const char *q_out,
                                const uint8_t peer_uuid[AT_APP_UUID_LEN],
                                const char *cid, const char *signer_did,
                                const char *sig_hex)
{
    if (handle == NULL || !name_survives(q_out) || peer_uuid == NULL
        || cid == NULL || signer_did == NULL || sig_hex == NULL
        || cid[0] == '\0' || signer_did[0] == '\0' || sig_hex[0] == '\0')
        return -1;
    if (!messaging_bound(q_out))
        return AT_APP_NOT_READY;
    char uuid_str[37];
    uuid_unparse_lower((const unsigned char *)peer_uuid, uuid_str);
    /* {"peer", "cid", "signer", "sig"}; identity sends the requester a directed
     * encrypted peer_cosign_sig. The signature is checked against the payload by
     * the assembling node — the only one that holds it. */
    json_t *env = json_object();
    if (env == NULL)
        return -1;
    json_object_set_new(env, "peer", json_string(uuid_str));
    json_object_set_new(env, "cid", json_string(cid));
    json_object_set_new(env, "signer", json_string(signer_did));
    json_object_set_new(env, "sig", json_string(sig_hex));
    generic_msg_t req = {0};
    req.type = NET_MESSAGE;
    snprintf(req.info.net_msg.process, sizeof(req.info.net_msg.process),
             "identity");
    req.info.net_msg.function = (char *)AT_APP_RETURN_COSIGN;
    req.info.net_msg.encrypt = false;
    if (net_msg_pack_json(&req.info.net_msg, env) != 0) {
        json_decref(env);
        return -1;
    }
    json_decref(env);
    return messaging_send(q_out, NET_MESSAGE, &req, false) == 0 ? 0 : -1;
}
#endif /* AT_SOCIAL_ENABLED */

void at_app_events_close(at_app_events_t *handle)
{
    if (handle == NULL)
        return;
    if (handle->owns_queue)
        messaging_qclose(&handle->queue);
    free(handle);
}
