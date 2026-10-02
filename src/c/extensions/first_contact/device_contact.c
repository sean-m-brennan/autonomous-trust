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
/** @file One human, several devices, on the wire (C twin of
 *  first_contact/device_contact.py). See device_contact.h. */

#include "first_contact/device_contact.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <jansson.h>
#include <uuid/uuid.h>

#include "config/configuration.h"
#include "first_contact/contacts.h"
#include "first_contact/device.h"
#include "first_contact/fc_shared.h"
#include "first_contact/first_contact.h"
#include "identity/id_proc_priv.h"
#include "identity/identity_priv.h"
#include "first_contact/sibling_sync.h"
#include "rendezvous/net_relay.h"
#include "utilities/logger.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"   /* net_msg_pack_json */
#include "utilities/util.h"

int at_device_own_cert(const process_t *proc, at_dir_signed_t *out)
{
    if (proc == NULL || out == NULL)
        return -1;
    memset(out, 0, sizeof(*out));
    char dir[CFG_PATH_LEN + 1] = {0};
    if (get_cfg_dir(dir, sizeof(dir)) <= 0)
        return -1;
    char path[CFG_PATH_LEN + 64];
    snprintf(path, sizeof(path), "%s/%s", dir, AT_DEVICE_CERT_FILENAME);
    json_t *wire = json_load_file(path, 0, NULL);
    if (wire == NULL)
        return -1;      /* none installed: the normal case */
    int rc = at_dir_from_wire(wire, out) == AT_DIR_OK ? at_device_cert_verify(out)
                                                      : AT_DEVICE_MALFORMED;
    json_decref(wire);
    public_identity_t self;
    memset(&self, 0, sizeof(self));
    if (rc == AT_DEVICE_OK && identity_own_public_identity(proc, &self) == 0) {
        if (!at_device_cert_names(out, &self))
            rc = AT_DEVICE_MISMATCH;
        at_fc_free_public(&self);
    } else if (rc == AT_DEVICE_OK) {
        rc = AT_DEVICE_MALFORMED;
    }
    if (rc != AT_DEVICE_OK) {
        log_warn(proc->logger, "Identity: device cert at %s unusable (%s); ignored\n",
                 path, at_device_reason(rc));
        at_dir_free(out);
        return -1;
    }
    return 0;
}

static bool _load_store(contacts_t *store, char *dir, size_t len)
{
    contacts_init(store);
    if (get_data_dir(dir, len) <= 0)
        return false;
    (void)contacts_load(dir, store);
    return true;
}

/* One device of @p c as a public identity: index 0 is the first. */
static bool _device_identity(const contact_t *c, size_t d, public_identity_t *out)
{
    memset(out, 0, sizeof(*out));
    if (d == 0) {
        *out = c->identity;
        out->operator_key_binding = NULL;
        out->operator_key_binding_len = 0;
        return true;
    }
    return at_contact_device_identity(&c->devices[d - 1], out) == 0;
}

static void _send(const process_t *proc, char *verb, bool encrypt,
                  const public_identity_t *to, const public_identity_t *self, json_t *body)
{
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    at_strlcpy(msg.info.net_msg.process, "identity", sizeof(msg.info.net_msg.process));
    msg.info.net_msg.function = verb;
    msg.info.net_msg.encrypt = encrypt;
    memcpy(&msg.info.net_msg.to_whom, to, sizeof(public_identity_t));
    memcpy(&msg.info.net_msg.from_whom, self, sizeof(public_identity_t));
    at_strlcpy(msg.info.net_msg.return_to, "identity", sizeof(msg.info.net_msg.return_to));
    net_msg_pack_json(&msg.info.net_msg, body);
    (void)identity_send_to_network(proc, &msg, "device cert / announce", NULL);
    net_msg_free_obj(&msg.info.net_msg);
    (void)proc;
}

int at_device_push_own_cert(const process_t *proc, const public_identity_t *only)
{
    if (proc == NULL)
        return 0;
    at_dir_signed_t cert;
    if (at_device_own_cert(proc, &cert) != 0)
        return 0;
    json_t *wire = at_dir_to_wire(&cert);
    at_dir_free(&cert);
    public_identity_t self;
    memset(&self, 0, sizeof(self));
    if (wire == NULL || identity_own_public_identity(proc, &self) != 0) {
        json_decref(wire);
        return 0;
    }
    int sent = 0;
    if (only != NULL) {
        _send(proc, ID_FC_DEVICE_CERT, true, only, &self, wire);
        sent = 1;
    } else {
        char dir[CFG_PATH_LEN + 1] = {0};
        contacts_t store;
        _load_store(&store, dir, sizeof(dir));
        for (size_t i = 0; i < store.count; i++)
            for (size_t d = 0; d <= store.items[i].devices_count; d++) {
                public_identity_t who;
                if (!_device_identity(&store.items[i], d, &who))
                    continue;
                public_identity_t peer;
                bool is_peer = false;
                peers_read_lock(proc);
                for (size_t j = 0; j < proc->protocol.num_peers && !is_peer; j++)
                    if (uuid_compare(proc->protocol.peers[j].uuid, who.uuid) == 0) {
                        peer = proc->protocol.peers[j];
                        is_peer = true;
                    }
                peers_read_unlock(proc);
                if (is_peer && uuid_compare(who.uuid, self.uuid) != 0) {
                    _send(proc, ID_FC_DEVICE_CERT, true, &peer, &self, wire);
                    sent++;
                }
                if (d > 0)
                    at_fc_free_public(&who);
            }
        contacts_free(&store);
    }
    json_decref(wire);
    at_fc_free_public(&self);
    return sent;
}

bool handle_device_cert(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    const public_identity_t *sender = &nmsg->from_whom;
    if (!at_fc_has_sender(sender))
        return true;
    json_t *wire = at_fc_app_payload(nmsg);
    bool paired = at_sibling_on_device_cert(proc, queues, sender, wire);
    json_decref(wire);
    if (paired)
        return true;     /* it answered a pair handshake */
    char uu[UUID_STRING_LEN + 1];
    uuid_unparse_lower(sender->uuid, uu);
    char dir[CFG_PATH_LEN + 1] = {0};
    contacts_t store;
    if (!_load_store(&store, dir, sizeof(dir))) {
        contacts_free(&store);
        return true;
    }
    contact_t *c = contacts_get(&store, uu);
    if (c == NULL || uuid_compare(c->identity.uuid, sender->uuid) != 0) {
        log_debug(proc->logger, "Identity: device cert from %.8s, not a contact's first "
                  "device; ignored\n", uu);
        contacts_free(&store);
        return true;
    }
    if (strcasecmp((const char *)c->identity.signature.public_hex,
                   (const char *)sender->signature.public_hex) != 0) {
        log_warn(proc->logger, "Identity: device cert from %s under another key; "
                 "ignored\n", c->petname);
        contacts_free(&store);
        return true;
    }
    json_t *payload = at_fc_app_payload(nmsg);
    at_dir_signed_t cert;
    int rc = at_dir_from_wire(payload, &cert) == AT_DIR_OK ? AT_DEVICE_OK : AT_DEVICE_MALFORMED;
    json_decref(payload);
    char had[AT_OPERATOR_KEY_HEX_LEN + 1];
    at_strlcpy(had, c->operator_key, sizeof(had));
    if (rc == AT_DEVICE_OK)
        rc = at_adopt_operator(c, &cert, &store);
    at_dir_free(&cert);
    if (rc != AT_DEVICE_OK) {
        log_warn(proc->logger, "Identity: device cert from %s refused (%s)\n", c->petname,
                 at_device_reason(rc));
    } else if (strcmp(had, c->operator_key) != 0) {
        if (contacts_save(&store, dir) != 0)
            log_warn(proc->logger, "Identity: could not persist contact for %s\n",
                     c->petname);
        log_info(proc->logger, "Identity: first contact: learned the operator key of %s\n",
                 c->petname);
        contacts_free(&store);
        (void)at_sibling_push_changes(proc);
        return true;
    }
    contacts_free(&store);
    return true;
}

/* Announce to every device of @p only (NULL: of every contact in the store). */
static int _announce(const process_t *proc, const contact_t *only);

int at_device_announce(const process_t *proc)
{
    return _announce(proc, NULL);
}

int at_device_announce_contact(const process_t *proc, const contact_t *c)
{
    return c == NULL ? 0 : _announce(proc, c);
}

static int _announce(const process_t *proc, const contact_t *only)
{
    if (proc == NULL)
        return 0;
    at_dir_signed_t cert;
    if (at_device_own_cert(proc, &cert) != 0)
        return 0;
    char hints[AT_RELAY_MAX][AT_RELAY_HOST_LEN + 96];
    size_t n_hints = at_fc_own_hints(hints, AT_RELAY_MAX);
    json_t *relays = json_array();
    for (size_t i = 0; i < n_hints; i++)
        json_array_append_new(relays, json_string(hints[i]));
    json_t *body = json_pack("{s:o, s:o}", "cert", at_dir_to_wire(&cert), "relays", relays);
    at_dir_free(&cert);
    public_identity_t self;
    memset(&self, 0, sizeof(self));
    if (body == NULL || identity_own_public_identity(proc, &self) != 0) {
        json_decref(body);
        return 0;
    }
    char dir[CFG_PATH_LEN + 1] = {0};
    contacts_t store;
    _load_store(&store, dir, sizeof(dir));
    int sent = 0;
    size_t n_items = only != NULL ? 1 : store.count;
    for (size_t i = 0; i < n_items; i++) {
        const contact_t *ci = only != NULL ? only : &store.items[i];
        for (size_t d = 0; d <= ci->devices_count; d++) {
            public_identity_t who;
            if (!_device_identity(ci, d, &who))
                continue;
            if (uuid_compare(who.uuid, self.uuid) != 0) {
                _send(proc, ID_FC_DEVICE_ANNOUNCE, false, &who, &self, body);
                sent++;
            }
            if (d > 0)
                at_fc_free_public(&who);
        }
    }
    contacts_free(&store);
    json_decref(body);
    at_fc_free_public(&self);
    if (sent > 0)
        log_info(proc->logger, "Identity: first contact: announced this device to %d "
                 "contact node(s)\n", sent);
    return sent;
}

bool handle_device_announce(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    const public_identity_t *sender = &nmsg->from_whom;
    if (!at_fc_has_sender(sender)) {
        log_warn(proc->logger, "Identity: device announce with no sender identity; "
                 "ignoring\n");
        return true;
    }
    char uu[UUID_STRING_LEN + 1];
    uuid_unparse_lower(sender->uuid, uu);
    json_t *payload = at_fc_app_payload(nmsg);
    at_dir_signed_t cert;
    int rc = at_dir_from_wire(json_object_get(payload, "cert"), &cert) == AT_DIR_OK
        ? AT_DEVICE_OK : AT_DEVICE_MALFORMED;
    char dir[CFG_PATH_LEN + 1] = {0};
    contacts_t store;
    _load_store(&store, dir, sizeof(dir));
    bool known = contacts_get(&store, uu) != NULL;
    contact_t *c = NULL;
    if (rc == AT_DEVICE_OK)
        rc = at_link_device(&store, sender, &cert, &c);
    at_dir_free(&cert);
    if (rc != AT_DEVICE_OK || known) {
        if (rc != AT_DEVICE_OK)
            log_info(proc->logger, "Identity: device announce from %.8s refused (%s)\n",
                     uu, at_device_reason(rc));
        json_decref(payload);
        contacts_free(&store);
        return true;     /* refused, or already filed: nothing to say */
    }
    if (contacts_save(&store, dir) != 0)
        log_warn(proc->logger, "Identity: could not persist contact for %s\n", c->petname);
    (void)at_sibling_push_changes(proc);
    (void)identity_admit_direct_peer((process_t *)proc, queues, sender);
    /* Its relays, then ours. */
    const char *route[2 * AT_RELAY_MAX];
    size_t n = 0;
    json_t *relays = json_object_get(payload, "relays");
    for (size_t i = 0; json_is_array(relays) && i < json_array_size(relays)
                       && n < AT_RELAY_MAX; i++) {
        const char *h = json_string_value(json_array_get(relays, i));
        if (h != NULL && strncmp(h, AT_RELAY_SCHEME, strlen(AT_RELAY_SCHEME)) == 0)
            route[n++] = h;
    }
    char own[AT_RELAY_MAX][AT_RELAY_HOST_LEN + 96];
    size_t n_own = at_fc_own_hints(own, AT_RELAY_MAX);
    size_t theirs = n;
    for (size_t i = 0; i < n_own && n < 2 * AT_RELAY_MAX; i++) {
        bool dup = false;
        for (size_t j = 0; j < theirs && !dup; j++)
            dup = strcmp(route[j], own[i]) == 0;
        if (!dup)
            route[n++] = own[i];
    }
    at_fc_send_route_hints(sender->uuid, route, n);
    at_fc_push_own_record(proc, sender);
    log_info(proc->logger, "Identity: first contact: %s is another device of %s; linked\n",
             sender->nickname, c->petname);
    at_fc_emit_device_linked(proc, c, sender->uuid);
    json_decref(payload);
    contacts_free(&store);
    return true;
}

void at_device_contact_register(process_t *proc)
{
    process_register_handler(proc, ID_FC_DEVICE_CERT, (handler_ptr_t)handle_device_cert);
    process_register_handler(proc, ID_FC_DEVICE_ANNOUNCE,
                             (handler_ptr_t)handle_device_announce);
}
