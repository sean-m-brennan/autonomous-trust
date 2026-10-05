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
 * @file rdv_roster.c
 * @brief The roster app verbs (at_rendezvous.h): identity handlers rendezvous
 *        registers, the event type that answers them, and the app-side senders.
 *
 * FEATURE_SPLIT_PLAN Phase 7b, D10: moved from first contact's area_contact.c
 * with the logic unchanged. They are registered whenever rendezvous is linked,
 * because the roster files are rendezvous's own configuration. Mirrors Python
 * autonomous_trust.rendezvous.roster.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>

#include "rendezvous/at_rendezvous.h"
#include "rendezvous/rdv_roster.h"
#include "rendezvous/net_relay_rosters.h"
#include "rendezvous/net_rendezvous.h"   /* the anchor reaches rdv_net.c */
#include "app_events_registry.h"
#include "identity/id_proc_priv.h"
#include "processes/extension.h"
#include "processes/processes.h"
#include "utilities/logger.h"
#include "utilities/message.h"
#include "utilities/msg_registry.h"
#include "utilities/msg_types_priv.h"   /* net_msg_pack_json, net_msg_unpack_json */
#include "utilities/util.h"
#include "utilities/send_retry.h"   /* at_send: keep a refused event */

/* -- the event type ------------------------------------------------------------ */

/** The roster answers: rendezvous's one app-bound type. */
#define RENDEZVOUS_ROSTER_EVENT ((message_type_t)(AT_MSG_TYPE_RDV_MIN + 0))

typedef struct {
    int32_t kind;
    at_app_roster_t data;
} rdv_roster_msg_t;

AT_MSG_ASSERT_FITS(rdv_roster_msg_t);

static const at_msg_vtable_t rendezvous_roster_event_vt = {
    .name = "RENDEZVOUS_ROSTER_EVENT", .size = sizeof(rdv_roster_msg_t),
    .app_bound = true };
AT_MSG_TYPE_REGISTER(rendezvous_roster_event, RENDEZVOUS_ROSTER_EVENT,
                     &rendezvous_roster_event_vt)

static bool _is_roster_kind(int32_t kind)
{
    return kind >= AT_APP_EVENT_ROSTER_INSTALLED && kind <= AT_APP_EVENT_ROSTER_REMOVED;
}

static int _decode_roster(const generic_msg_t *msg, at_app_event_t *ev)
{
    const rdv_roster_msg_t *m = AT_MSG_EXT_CONST(msg, rdv_roster_msg_t);
    if (!_is_roster_kind(m->kind))
        return -1;
    ev->kind = m->kind;
    memcpy(AT_APP_EVENT_EXT(ev, at_app_roster_t), &m->data, sizeof(m->data));
    return 0;
}
AT_APP_EVENT_DECODER_REGISTER(rendezvous_roster_event, RENDEZVOUS_ROSTER_EVENT,
                              _decode_roster)

const at_app_roster_t *at_rendezvous_roster_event(const at_app_event_t *ev)
{
    if (ev == NULL || !_is_roster_kind(ev->kind))
        return NULL;
    return (const at_app_roster_t *)(const void *)ev->data.payload;
}

typedef struct {
    const char *ref, *issuer, *reason;
    int64_t seq;
    int32_t count;
} roster_ev_t;

static void _emit(const process_t *proc, int32_t kind, roster_ev_t e)
{
    generic_msg_t msg = {0};
    msg.type = RENDEZVOUS_ROSTER_EVENT;
    rdv_roster_msg_t *m = AT_MSG_EXT(&msg, rdv_roster_msg_t);
    m->kind = kind;
    at_strlcpy(m->data.ref, e.ref != NULL ? e.ref : "", sizeof(m->data.ref));
    at_strlcpy(m->data.issuer, e.issuer != NULL ? e.issuer : "", sizeof(m->data.issuer));
    at_strlcpy(m->data.reason, e.reason != NULL ? e.reason : "", sizeof(m->data.reason));
    m->data.seq = e.seq;
    m->data.count = e.count;
    if (at_send(proc, AT_MAIN_QUEUE, &msg, "a roster event", "the app",
                AT_SEND_NOW, NULL, NULL, 0) != 0)
        log_debug(proc->logger, "Identity: roster: could not hand the app event %d\n", kind);
}

/* -- the handlers ---------------------------------------------------------------- */

/* The request object, or NULL when the payload is not one. */
static json_t *_payload(net_msg_t *nmsg)
{
    json_t *req = NULL;
    if (net_msg_unpack_json(nmsg, &req) != 0 || req == NULL)
        return NULL;
    if (!json_is_object(req)) {
        json_decref(req);
        return NULL;
    }
    return req;
}

/* The request's ref ("" when absent), or NULL when it is present but not a
 * string that fits: a cut ref would answer nobody. Mirrors Python _app_ref. */
static const char *_ref(const json_t *req)
{
    json_t *r = req != NULL ? json_object_get(req, "ref") : NULL;
    if (r == NULL || json_is_null(r))
        return "";
    const char *ref = json_string_value(r);
    if (ref == NULL || strlen(ref) >= AT_RDV_REF_LEN)
        return NULL;
    return ref;
}

static bool _is_hex_key(const char *k)
{
    if (k == NULL || strlen(k) != AT_RELAY_ROSTER_KEY_HEX)
        return false;
    for (const char *c = k; *c != '\0'; c++)
        if (!((*c >= '0' && *c <= '9') || (*c >= 'a' && *c <= 'f')))
            return false;
    return true;
}

static char RDV_APP_ROSTER_INSTALL[] = AT_APP_ROSTER_INSTALL;
static char RDV_APP_ROSTER_REMOVE[] = AT_APP_ROSTER_REMOVE;

bool handle_roster_app_install(const process_t *proc, directory_t *queues,
                               generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!identity_is_local_app_verb(proc, nmsg))
        return identity_refuse_remote_app_verb(proc, nmsg, AT_APP_ROSTER_INSTALL);
    json_t *req = _payload(nmsg);
    const char *r = _ref(req);
    char ref[AT_RDV_REF_LEN];
    at_strlcpy(ref, r != NULL ? r : "", sizeof(ref));
    json_t *roster = json_object_get(req, "roster");
    char *text = json_is_object(roster) ? json_dumps(roster, JSON_COMPACT)
               : json_is_string(roster) ? strdup(json_string_value(roster)) : NULL;
    json_decref(req);
    if (r == NULL || text == NULL) {
        free(text);
        _emit(proc, AT_APP_EVENT_ROSTER_REFUSED, (roster_ev_t){ .ref = ref,
                                                               .reason = "bad_request" });
        return true;
    }
    char issuer[AT_RELAY_ROSTER_KEY_HEX + 1] = "";
    long long seq = 0;
    int rc = net_relay_rosters_install(text, issuer, &seq);
    free(text);
    if (rc != 0) {
        log_warn(proc->logger, "Identity: roster refused (%d)\n", rc);
        _emit(proc, AT_APP_EVENT_ROSTER_REFUSED, (roster_ev_t){
            .ref = ref, .reason = rc == -2 ? "stale" : "invalid" });
        return true;
    }
    log_info(proc->logger, "Identity: installed the relay roster of %.16s... (seq %lld)\n",
             issuer, seq);
    _emit(proc, AT_APP_EVENT_ROSTER_INSTALLED, (roster_ev_t){ .ref = ref, .issuer = issuer,
                                                             .seq = (int64_t)seq });
    return true;
}

bool handle_roster_app_remove(const process_t *proc, directory_t *queues,
                              generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!identity_is_local_app_verb(proc, nmsg))
        return identity_refuse_remote_app_verb(proc, nmsg, AT_APP_ROSTER_REMOVE);
    json_t *req = _payload(nmsg);
    const char *r = _ref(req);
    const char *raw = json_string_value(json_object_get(req, "issuer"));
    char ref[AT_RDV_REF_LEN], issuer[AT_RELAY_ROSTER_KEY_HEX + 1] = "";
    at_strlcpy(ref, r != NULL ? r : "", sizeof(ref));
    bool ok = r != NULL && raw != NULL && strlen(raw) == AT_RELAY_ROSTER_KEY_HEX;
    if (ok) {
        for (size_t i = 0; i <= AT_RELAY_ROSTER_KEY_HEX; i++)
            issuer[i] = (char)(raw[i] >= 'A' && raw[i] <= 'Z' ? raw[i] + 32 : raw[i]);
        ok = _is_hex_key(issuer);
    }
    json_decref(req);
    if (!ok) {
        _emit(proc, AT_APP_EVENT_ROSTER_REFUSED, (roster_ev_t){ .ref = ref,
                                                               .reason = "bad_request" });
        return true;
    }
    int had = net_relay_rosters_remove(issuer);
    _emit(proc, AT_APP_EVENT_ROSTER_REMOVED, (roster_ev_t){ .ref = ref, .issuer = issuer,
                                                           .count = had > 0 ? 1 : 0 });
    return true;
}

/* -- registration ---------------------------------------------------------------- */

static int _register(process_t *proc, const char *proc_name)
{
    if (strcmp(proc_name, "identity") != 0)
        return 0;
    process_register_handler(proc, RDV_APP_ROSTER_INSTALL,
                             (handler_ptr_t)handle_roster_app_install);
    process_register_handler(proc, RDV_APP_ROSTER_REMOVE,
                             (handler_ptr_t)handle_roster_app_remove);
    return 0;
}

/* Always on: rendezvous linked means its roster configuration can be changed.
 * Mirrors Python rendezvous's EXTENSION, which carries the same two verbs. */
static const at_extension_t rendezvous_extension = {
    .name = "rendezvous",
    .enabled = NULL,
    .register_handlers = _register,
};
AT_EXTENSION_REGISTER(rendezvous, &rendezvous_extension)

/* The app may send exactly these verbs, each only to identity. */
AT_APP_VERB_REGISTER(roster_install, AT_APP_ROSTER_INSTALL, "identity")
AT_APP_VERB_REGISTER(roster_remove, AT_APP_ROSTER_REMOVE, "identity")

/* -- the app side ------------------------------------------------------------------ */

static int _send(at_app_events_t *handle, const char *q_out, const char *ref,
                 const char *verb, const char *field, const char *value)
{
    if (handle == NULL || !at_app_name_survives(q_out) || value == NULL
        || value[0] == '\0' || (ref != NULL && strlen(ref) >= AT_RDV_REF_LEN))
        return -1;
    if (!messaging_bound(q_out))
        return AT_APP_NOT_READY;
    json_t *body = json_pack("{s:s, s:s}", "ref", ref != NULL ? ref : "", field, value);
    if (body == NULL)
        return -1;
    generic_msg_t req = {0};
    req.type = NET_MESSAGE;
    snprintf(req.info.net_msg.process, sizeof(req.info.net_msg.process), "identity");
    req.info.net_msg.function = (char *)verb;
    req.info.net_msg.encrypt = false;
    int rc = net_msg_pack_json(&req.info.net_msg, body);
    json_decref(body);
    if (rc != 0)
        return -1;
    rc = messaging_send(q_out, NET_MESSAGE, &req, false);
    net_msg_free_obj(&req.info.net_msg);
    return rc == 0 ? 0 : -1;
}

int at_app_relay_roster_install(at_app_events_t *handle, const char *q_out,
                                const char *ref, const char *roster)
{
    return _send(handle, q_out, ref, AT_APP_ROSTER_INSTALL, "roster", roster);
}

int at_app_relay_roster_remove(at_app_events_t *handle, const char *q_out,
                               const char *ref, const char *issuer)
{
    return _send(handle, q_out, ref, AT_APP_ROSTER_REMOVE, "issuer", issuer);
}

/* Referencing a function of rdv_net.c keeps that object too, and with it the
 * network extension's constructor. */
void at_rendezvous_link(void)
{
    volatile const void *keep = (const void *)&net_rendezvous_service_register;
    (void)keep;
}
