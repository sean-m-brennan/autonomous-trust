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

/* First contact's half of the flat app ABI (at_first_contact.h): the event
 * type both processes must know by name, its decoder, the accessor, and the
 * two app->AT senders. Kept apart from identity/first_contact.c because this
 * half runs in the APP's process; the daemon half references it through
 * at_first_contact_app_link so a static link keeps the type registered on
 * both sides. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <uuid/uuid.h>

#include <jansson.h>

#include "at_first_contact.h"
#include "app_events_registry.h"
#include "identity/first_contact.h"
#include "utilities/message.h"
#include "utilities/msg_registry.h"
#include "utilities/msg_types_priv.h"   /* net_msg_pack_json */

AT_MSG_ASSERT_FITS(fc_event_msg_t);

static const at_msg_vtable_t first_contact_event_vt = {
    .name = "FIRST_CONTACT_EVENT", .size = sizeof(fc_event_msg_t),
    .app_bound = true };
AT_MSG_TYPE_REGISTER(first_contact_event, FIRST_CONTACT_EVENT,
                     &first_contact_event_vt)

static bool _is_fc_kind(int32_t kind)
{
    return kind >= AT_APP_EVENT_FC_INVITATION
        && kind <= AT_APP_EVENT_FC_ESTABLISHED;
}

static int _decode_first_contact(const generic_msg_t *msg, at_app_event_t *ev)
{
    const fc_event_msg_t *m = AT_MSG_EXT_CONST(msg, fc_event_msg_t);
    if (!_is_fc_kind(m->kind))
        return -1;
    ev->kind = m->kind;
    memcpy(AT_APP_EVENT_EXT(ev, at_app_first_contact_t), &m->data,
           sizeof(m->data));
    return 0;
}
AT_APP_EVENT_DECODER_REGISTER(first_contact_event, FIRST_CONTACT_EVENT,
                              _decode_first_contact)

AT_MSG_ASSERT_FITS(fc_contact_msg_t);

static const at_msg_vtable_t first_contact_contact_event_vt = {
    .name = "FIRST_CONTACT_CONTACT_EVENT", .size = sizeof(fc_contact_msg_t),
    .app_bound = true };
AT_MSG_TYPE_REGISTER(first_contact_contact_event, FIRST_CONTACT_CONTACT_EVENT,
                     &first_contact_contact_event_vt)

static bool _is_contact_kind(int32_t kind)
{
    return kind >= AT_APP_EVENT_FC_CONTACT && kind <= AT_APP_EVENT_FC_REMOVED;
}

static int _decode_contact(const generic_msg_t *msg, at_app_event_t *ev)
{
    const fc_contact_msg_t *m = AT_MSG_EXT_CONST(msg, fc_contact_msg_t);
    if (!_is_contact_kind(m->kind))
        return -1;
    ev->kind = m->kind;
    memcpy(AT_APP_EVENT_EXT(ev, at_app_contact_t), &m->data, sizeof(m->data));
    return 0;
}
AT_APP_EVENT_DECODER_REGISTER(first_contact_contact_event,
                              FIRST_CONTACT_CONTACT_EVENT, _decode_contact)

AT_MSG_ASSERT_FITS(fc_directory_msg_t);

static const at_msg_vtable_t first_contact_directory_event_vt = {
    .name = "FIRST_CONTACT_DIRECTORY_EVENT", .size = sizeof(fc_directory_msg_t),
    .app_bound = true };
AT_MSG_TYPE_REGISTER(first_contact_directory_event, FIRST_CONTACT_DIRECTORY_EVENT,
                     &first_contact_directory_event_vt)

static bool _is_directory_kind(int32_t kind)
{
    return kind >= AT_APP_EVENT_DIR_PUBLISHED && kind <= AT_APP_EVENT_DIR_DECLINED;
}

static int _decode_directory(const generic_msg_t *msg, at_app_event_t *ev)
{
    const fc_directory_msg_t *m = AT_MSG_EXT_CONST(msg, fc_directory_msg_t);
    if (!_is_directory_kind(m->kind))
        return -1;
    ev->kind = m->kind;
    memcpy(AT_APP_EVENT_EXT(ev, at_app_directory_t), &m->data, sizeof(m->data));
    return 0;
}
AT_APP_EVENT_DECODER_REGISTER(first_contact_directory_event,
                              FIRST_CONTACT_DIRECTORY_EVENT, _decode_directory)

const at_app_directory_t *at_first_contact_directory_event(const at_app_event_t *ev)
{
    if (ev == NULL || !_is_directory_kind(ev->kind))
        return NULL;
    return (const at_app_directory_t *)(const void *)ev->data.payload;
}

void at_first_contact_app_link(void) {}

const at_app_contact_t *at_first_contact_contact_event(const at_app_event_t *ev)
{
    if (ev == NULL || !_is_contact_kind(ev->kind))
        return NULL;
    return (const at_app_contact_t *)(const void *)ev->data.payload;
}

const at_app_first_contact_t *at_first_contact_event(const at_app_event_t *ev)
{
    if (ev == NULL || !_is_fc_kind(ev->kind))
        return NULL;
    return (const at_app_first_contact_t *)(const void *)ev->data.payload;
}

/* A ref must survive intact, like a queue name: a shortened ref is a
 * different ref, and the event carrying it would answer nobody. */
static bool _ref_fits(const char *ref)
{
    return ref == NULL || strlen(ref) < AT_FC_REF_LEN;
}

static int _send(const char *q_out, const char *verb, json_t *body)
{
    if (!messaging_bound(q_out)) {
        json_decref(body);
        return AT_APP_NOT_READY;
    }
    generic_msg_t req = {0};
    req.type = NET_MESSAGE;
    snprintf(req.info.net_msg.process, sizeof(req.info.net_msg.process),
             "identity");
    req.info.net_msg.function = (char *)verb;
    req.info.net_msg.encrypt = false;
    int rc = net_msg_pack_json(&req.info.net_msg, body);
    json_decref(body);
    if (rc != 0)
        return -1;
    return messaging_send(q_out, NET_MESSAGE, &req, false) == 0 ? 0 : -1;
}

int at_app_first_contact_invite(at_app_events_t *handle, const char *q_out,
                                const char *ref, long ttl_seconds,
                                const char *const *rendezvous,
                                size_t n_rendezvous)
{
    if (handle == NULL || !at_app_name_survives(q_out) || !_ref_fits(ref)
        || (rendezvous == NULL && n_rendezvous > 0))
        return -1;
    json_t *body = json_object();
    json_t *hints = json_array();
    if (body == NULL || hints == NULL) {
        json_decref(body);
        json_decref(hints);
        return -1;
    }
    json_object_set_new(body, "ref", json_string(ref != NULL ? ref : ""));
    /* Absent means "the node's default"; the node reads 0 as "never". */
    if (ttl_seconds >= 0)
        json_object_set_new(body, "ttl_seconds", json_integer(ttl_seconds));
    for (size_t i = 0; i < n_rendezvous; i++) {
        if (rendezvous[i] == NULL) {
            json_decref(hints);
            json_decref(body);
            return -1;
        }
        json_array_append_new(hints, json_string(rendezvous[i]));
    }
    json_object_set_new(body, "rendezvous", hints);
    return _send(q_out, AT_APP_FC_INVITE, body);
}

int at_app_first_contact_initiate(at_app_events_t *handle, const char *q_out,
                                  const char *ref, const char *invitation,
                                  const char *endpoint, bool in_person,
                                  const char *petname)
{
    if (handle == NULL || !at_app_name_survives(q_out) || !_ref_fits(ref)
        || invitation == NULL || invitation[0] == '\0')
        return -1;
    json_t *body = json_object();
    if (body == NULL)
        return -1;
    json_object_set_new(body, "ref", json_string(ref != NULL ? ref : ""));
    json_object_set_new(body, "invitation", json_string(invitation));
    if (endpoint != NULL && endpoint[0] != '\0')
        json_object_set_new(body, "endpoint", json_string(endpoint));
    json_object_set_new(body, "in_person", json_boolean(in_person));
    if (petname != NULL && petname[0] != '\0')
        json_object_set_new(body, "petname", json_string(petname));
    return _send(q_out, AT_APP_FC_INITIATE, body);
}

/* The shared shape of the address-book requests: a ref and a peer uuid. */
static json_t *_book_body(at_app_events_t *handle, const char *q_out,
                          const char *ref, const uint8_t *peer)
{
    if (handle == NULL || !at_app_name_survives(q_out) || !_ref_fits(ref))
        return NULL;
    json_t *body = json_object();
    if (body == NULL)
        return NULL;
    json_object_set_new(body, "ref", json_string(ref != NULL ? ref : ""));
    if (peer != NULL) {
        char u[37];
        uuid_unparse_lower(peer, u);
        json_object_set_new(body, "peer", json_string(u));
    }
    return body;
}

int at_app_first_contact_safety_number(at_app_events_t *handle, const char *q_out,
                                       const char *ref,
                                       const uint8_t peer[AT_APP_UUID_LEN])
{
    if (peer == NULL)
        return -1;
    json_t *body = _book_body(handle, q_out, ref, peer);
    return body == NULL ? -1 : _send(q_out, AT_APP_FC_SAFETY_NUMBER, body);
}

int at_app_first_contact_verify(at_app_events_t *handle, const char *q_out,
                                const char *ref,
                                const uint8_t peer[AT_APP_UUID_LEN],
                                const char *presented, bool confirmed)
{
    /* Exactly one way to verify per call: digits, or a confirmation. */
    bool typed = presented != NULL && presented[0] != '\0';
    if (peer == NULL || typed == confirmed)
        return -1;
    json_t *body = _book_body(handle, q_out, ref, peer);
    if (body == NULL)
        return -1;
    if (typed)
        json_object_set_new(body, "presented", json_string(presented));
    else
        json_object_set_new(body, "confirmed", json_true());
    return _send(q_out, AT_APP_FC_VERIFY, body);
}

int at_app_first_contact_list(at_app_events_t *handle, const char *q_out,
                              const char *ref)
{
    json_t *body = _book_body(handle, q_out, ref, NULL);
    return body == NULL ? -1 : _send(q_out, AT_APP_FC_LIST, body);
}

int at_app_first_contact_rename(at_app_events_t *handle, const char *q_out,
                                const char *ref,
                                const uint8_t peer[AT_APP_UUID_LEN],
                                const char *petname)
{
    if (peer == NULL || petname == NULL || petname[0] == '\0'
        || strlen(petname) >= AT_FC_NICKNAME_LEN)
        return -1;
    json_t *body = _book_body(handle, q_out, ref, peer);
    if (body == NULL)
        return -1;
    json_object_set_new(body, "petname", json_string(petname));
    return _send(q_out, AT_APP_FC_RENAME, body);
}

int at_app_first_contact_remove(at_app_events_t *handle, const char *q_out,
                                const char *ref,
                                const uint8_t peer[AT_APP_UUID_LEN])
{
    if (peer == NULL)
        return -1;
    json_t *body = _book_body(handle, q_out, ref, peer);
    return body == NULL ? -1 : _send(q_out, AT_APP_FC_REMOVE, body);
}

/* -- the directory ---------------------------------------------------------- */
static json_t *_dir_body(at_app_events_t *handle, const char *q_out, const char *ref)
{
    if (handle == NULL || !at_app_name_survives(q_out) || !_ref_fits(ref))
        return NULL;
    json_t *body = json_object();
    if (body != NULL)
        json_object_set_new(body, "ref", json_string(ref != NULL ? ref : ""));
    return body;
}

static int _dir_send(at_app_events_t *handle, const char *q_out, const char *ref,
                     const char *verb, const char *field, const char *value)
{
    if (value == NULL || value[0] == '\0')
        return -1;
    json_t *body = _dir_body(handle, q_out, ref);
    if (body == NULL)
        return -1;
    json_object_set_new(body, field, json_string(value));
    return _send(q_out, verb, body);
}

int at_app_directory_publish(at_app_events_t *handle, const char *q_out,
                             const char *ref, const char *attestation,
                             const char *visibility)
{
    json_t *att = attestation != NULL ? json_loads(attestation, 0, NULL) : NULL;
    json_t *body = att != NULL ? _dir_body(handle, q_out, ref) : NULL;
    if (body == NULL) {
        json_decref(att);
        return -1;
    }
    json_object_set_new(body, "attestation", att);
    json_object_set_new(body, "visibility",
                        json_string(visibility != NULL ? visibility : "anyone"));
    return _send(q_out, AT_APP_DIR_PUBLISH, body);
}

int at_app_directory_withdraw(at_app_events_t *handle, const char *q_out,
                              const char *ref, const char *dir_handle)
{
    return _dir_send(handle, q_out, ref, AT_APP_DIR_WITHDRAW, "handle", dir_handle);
}

int at_app_directory_lookup(at_app_events_t *handle, const char *q_out,
                            const char *ref, const char *dir_handle)
{
    return _dir_send(handle, q_out, ref, AT_APP_DIR_LOOKUP, "handle", dir_handle);
}

int at_app_first_contact_request(at_app_events_t *handle, const char *q_out,
                                 const char *ref, const char *dir_handle)
{
    return _dir_send(handle, q_out, ref, AT_APP_FC_REQUEST, "handle", dir_handle);
}

int at_app_first_contact_accept(at_app_events_t *handle, const char *q_out,
                                const char *request_ref)
{
    json_t *body = _dir_body(handle, q_out, request_ref);
    return body == NULL ? -1 : _send(q_out, AT_APP_FC_ACCEPT, body);
}

int at_app_first_contact_decline(at_app_events_t *handle, const char *q_out,
                                 const char *request_ref)
{
    json_t *body = _dir_body(handle, q_out, request_ref);
    return body == NULL ? -1 : _send(q_out, AT_APP_FC_DECLINE, body);
}
