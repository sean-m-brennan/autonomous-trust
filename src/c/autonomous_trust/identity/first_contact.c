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

/* The live 1:1 first-contact handshake. See first_contact.h for the flow and
 * the reason this is its own translation unit. */

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include <jansson.h>

#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"
#include "utilities/logger.h"
#include "utilities/util.h"
#include "utilities/allocation.h"
#include "config/configuration.h"
#include "contacts/contacts.h"
#include "identity/identity.h"
#include "first_contact.h"
#include "id_proc_priv.h"

bool at_first_contact_enabled(void)
{
    const char *v = getenv(AT_FIRST_CONTACT_ENV);
    if (v == NULL || v[0] == '\0')
        return false;
    return strcmp(v, "1") == 0 || strcasecmp(v, "true") == 0
        || strcasecmp(v, "yes") == 0 || strcasecmp(v, "on") == 0;
}

/****************************
 *  Durable single-use guard
 *
 *  The invitation nonces this node has already honored, so a RESTART cannot
 *  let a redeemer re-present a still-unexpired invitation.
 *
 *  Persisted as <data_dir>/first_contact_nonces.cfg.json, written atomically
 *  (temp + rename) exactly like contacts_save, so a crash never leaves a torn
 *  guard. Each nonce is stored with its invitation's expiry, so a record is
 *  pruned once the invitation would be rejected as expired anyway; a nonce
 *  from a no-expiry invitation (expiry 0) is kept forever, because such an
 *  invitation never becomes self-limiting and single use is then the ONLY
 *  thing bounding replay.
 *
 *  Only the identity process reads or writes this file, so no cross-process
 *  locking is needed; the mutex guards the two harness/handler threads inside
 *  it. A save failure degrades to in-memory enforcement for the current run
 *  rather than dropping the frame (logged, never raised) -- mirrors Python
 *  SpentNonces._save.
 ****************************/

typedef struct {
    char nonce[AT_CONTACT_NONCE_MAX + 1];
    long expiry;                 /* epoch seconds; 0 = never expires */
} fc_spent_t;

static struct {
    pthread_mutex_t lock;
    bool initialized;            /* the store has been loaded from disk */
    fc_spent_t *items;
    size_t count;
    size_t cap;
} fc_state = { PTHREAD_MUTEX_INITIALIZER, false, NULL, 0, 0 };

static int _fc_path(char *out, size_t out_len)
{
    char data_dir[CFG_PATH_LEN + 1] = {0};
    if (get_data_dir(data_dir, sizeof(data_dir)) <= 0)
        return -1;
    if ((size_t)snprintf(out, out_len, "%s/%s", data_dir, AT_FC_NONCE_FILENAME)
        >= out_len)
        return -1;   /* path too long: refuse rather than truncate */
    return 0;
}

/* Caller holds fc_state.lock. */
static int _fc_append_locked(const char *nonce, long expiry)
{
    if (fc_state.count == fc_state.cap) {
        size_t cap = fc_state.cap == 0 ? 8 : fc_state.cap * 2;
        fc_spent_t *grown = realloc(fc_state.items, cap * sizeof(fc_spent_t));
        if (grown == NULL)
            return -1;
        fc_state.items = grown;
        fc_state.cap = cap;
    }
    fc_spent_t *slot = &fc_state.items[fc_state.count++];
    memset(slot, 0, sizeof(*slot));
    at_strlcpy(slot->nonce, nonce, sizeof(slot->nonce));
    slot->expiry = expiry;
    return 0;
}

/* Caller holds fc_state.lock. Load once per data dir; a missing file is an
 * empty guard, and an UNREADABLE one is a fail-safe empty guard (loud, because
 * it is a weakening: re-honoring is only possible within an invitation's
 * expiry, and trust still gates on the out-of-band safety number). */
static void _fc_load_locked(const logger_t *logger)
{
    if (fc_state.initialized)
        return;
    fc_state.initialized = true;

    char path[CFG_PATH_LEN + 64];
    if (_fc_path(path, sizeof(path)) != 0)
        return;
    if (access(path, R_OK) != 0)
        return;   /* no file yet: an empty guard is correct */

    json_error_t error;
    json_t *root = json_load_file(path, 0, &error);
    json_t *nonces = (root != NULL) ? json_object_get(root, "nonces") : NULL;
    if (!json_is_object(nonces)) {
        log_warn((logger_t *)logger,
                 "first-contact nonce store unreadable (%s); starting with an "
                 "empty single-use guard\n",
                 root == NULL ? error.text : "no nonces object");
        if (root != NULL)
            json_decref(root);
        return;
    }
    const char *key = NULL;
    json_t *val = NULL;
    json_object_foreach(nonces, key, val) {
        if (key == NULL || key[0] == '\0')
            continue;
        long expiry = json_is_integer(val) ? (long)json_integer_value(val) : 0;
        (void)_fc_append_locked(key, expiry);
    }
    json_decref(root);
}

/* Caller holds fc_state.lock. */
static void _fc_save_locked(const logger_t *logger)
{
    char path[CFG_PATH_LEN + 64];
    char data_dir[CFG_PATH_LEN + 1] = {0};
    if (get_data_dir(data_dir, sizeof(data_dir)) <= 0
        || _fc_path(path, sizeof(path)) != 0) {
        log_warn((logger_t *)logger,
                 "could not resolve the first-contact nonce store path; "
                 "single use enforced in-memory for this run\n");
        return;
    }
    if (makedirs(data_dir, 0755) != 0) {
        log_warn((logger_t *)logger,
                 "could not create %s for the first-contact nonce store (%s); "
                 "single use enforced in-memory for this run\n",
                 data_dir, strerror(errno));
        return;
    }

    json_t *nonces = json_object();
    if (nonces == NULL)
        return;
    for (size_t i = 0; i < fc_state.count; i++)
        json_object_set_new(nonces, fc_state.items[i].nonce,
                            json_integer((json_int_t)fc_state.items[i].expiry));
    json_t *root = json_object();
    if (root == NULL) {
        json_decref(nonces);
        return;
    }
    json_object_set_new(root, "typename", json_string(AT_FC_NONCE_TYPENAME));
    json_object_set_new(root, "version", json_integer(AT_FC_NONCE_VERSION));
    json_object_set_new(root, "nonces", nonces);

    /* Atomic: dump to a temp sibling, rename over the target. Same discipline
     * as contacts_save and Python's atomic_write. */
    char tmp[sizeof(path) + 16];
    snprintf(tmp, sizeof(tmp), "%s.tmp%d", path, (int)getpid());
    int rc = json_dump_file(root, tmp, JSON_INDENT(2) | JSON_SORT_KEYS);
    json_decref(root);
    if (rc != 0 || rename(tmp, path) != 0) {
        unlink(tmp);
        log_warn((logger_t *)logger,
                 "could not persist the first-contact nonce store (%s); "
                 "single use enforced in-memory for this run\n",
                 strerror(errno));
    }
}

/* Caller holds fc_state.lock. Drop records whose invitation has expired
 * anyway; expiry 0 is kept forever. Mirrors Python SpentNonces.prune. */
static void _fc_prune_locked(double now)
{
    size_t kept = 0;
    for (size_t i = 0; i < fc_state.count; i++) {
        if (fc_state.items[i].expiry == 0
            || (double)fc_state.items[i].expiry > now) {
            if (kept != i)
                fc_state.items[kept] = fc_state.items[i];
            kept++;
        }
    }
    fc_state.count = kept;
}

/* Caller holds fc_state.lock. */
static bool _fc_contains_locked(const char *nonce)
{
    if (nonce == NULL)
        return false;
    for (size_t i = 0; i < fc_state.count; i++)
        if (strcmp(fc_state.items[i].nonce, nonce) == 0)
            return true;
    return false;
}

bool at_first_contact_nonce_spent(const char *nonce)
{
    pthread_mutex_lock(&fc_state.lock);
    _fc_load_locked(NULL);
    bool found = _fc_contains_locked(nonce);
    pthread_mutex_unlock(&fc_state.lock);
    return found;
}

void at_first_contact_reset(void)
{
    pthread_mutex_lock(&fc_state.lock);
    free(fc_state.items);
    fc_state.items = NULL;
    fc_state.count = 0;
    fc_state.cap = 0;
    fc_state.initialized = false;
    pthread_mutex_unlock(&fc_state.lock);
}

/* Record a spent nonce (pruning expired records first) and persist. Mirrors
 * Python SpentNonces.add. */
static void _fc_spend(const logger_t *logger, const char *nonce, long expiry,
                      double now)
{
    pthread_mutex_lock(&fc_state.lock);
    _fc_load_locked(logger);
    _fc_prune_locked(now);
    if (!_fc_contains_locked(nonce))
        (void)_fc_append_locked(nonce, expiry);
    _fc_save_locked(logger);
    pthread_mutex_unlock(&fc_state.lock);
}

int at_first_contact_register(process_t *proc)
{
    if (proc == NULL)
        return -1;
    /* Prime the durable guard so a replay is refused on the very first frame
     * after a restart, not only after the store happens to be touched. */
    pthread_mutex_lock(&fc_state.lock);
    _fc_load_locked(proc->logger);
    pthread_mutex_unlock(&fc_state.lock);
    process_register_handler(proc, ID_FC_HELLO,
                             (handler_ptr_t)handle_first_contact_hello);
    process_register_handler(proc, ID_FC_HELLO_ACK,
                             (handler_ptr_t)handle_first_contact_hello_ack);
    return 0;
}

/* An envelope with no sender identity carries nothing to admit. Python's
 * `isinstance(sender, Identity)` guard; here an all-zero uuid is the tell. */
static bool _has_sender(const public_identity_t *who)
{
    if (who == NULL)
        return false;
    for (size_t i = 0; i < sizeof(uuid_t); i++)
        if (((const unsigned char *)who->uuid)[i] != 0)
            return true;
    return false;
}

/* The hello payload is the invitation blob as a RAW string, not JSON: Python
 * puts `str(self.obj)` straight into the wire envelope (network/message.py
 * `_obj_str`), so net_msg_unpack_json would (correctly) fail on a base64url
 * blob. Copy it out NUL-terminated and length-bounded. */
static char *_payload_string(const net_msg_t *nmsg)
{
    if (nmsg == NULL || nmsg->obj == NULL || nmsg->len == 0)
        return NULL;
    size_t len = strnlen((const char *)nmsg->obj, nmsg->len);
    char *out = malloc(len + 1);
    if (out == NULL)
        return NULL;
    memcpy(out, nmsg->obj, len);
    out[len] = '\0';
    return out;
}

static void _free_public(public_identity_t *p)
{
    if (p != NULL && p->operator_key_binding != NULL) {
        free(p->operator_key_binding);
        p->operator_key_binding = NULL;
    }
}

/* How many reachability hints one contact keeps. The C twin of Python's
 * first_contact.MAX_RENDEZVOUS_HINTS, and it has to be the same number: both
 * runtimes write the SAME contacts.cfg.json, so a different cap would make the
 * file's contents depend on which runtime last touched it. */
#define AT_FC_MAX_RENDEZVOUS_HINTS 4

/* Put `endpoint` at the head of the hint list, deduped and capped. Newest
 * first because it is the one worth trying; capped because a peer that
 * re-handshakes from a new network on every join would otherwise grow a record
 * in a file nothing prunes. */
static void _rendezvous_refresh(contact_t *c, const char *endpoint)
{
    if (c == NULL || endpoint == NULL || endpoint[0] == '\0')
        return;
    char **hints = calloc(AT_FC_MAX_RENDEZVOUS_HINTS, sizeof(char *));
    if (hints == NULL)
        return;             /* keep what we have rather than lose it */
    size_t n = 0;
    hints[n] = strdup(endpoint);
    if (hints[n] == NULL) {
        free(hints);
        return;
    }
    n++;
    for (size_t i = 0; i < c->rendezvous_count
                       && n < AT_FC_MAX_RENDEZVOUS_HINTS; i++) {
        if (c->rendezvous[i] == NULL
            || strcmp(c->rendezvous[i], endpoint) == 0)
            continue;
        char *dup = strdup(c->rendezvous[i]);
        if (dup == NULL)
            break;
        hints[n++] = dup;
    }
    for (size_t i = 0; i < c->rendezvous_count; i++)
        free(c->rendezvous[i]);
    free(c->rendezvous);
    c->rendezvous = hints;
    c->rendezvous_count = n;
}

/* Write or refresh the durable contact for a peer we just handshook with.
 *
 * Mirrors Python first_contact._record_contact exactly, because both runtimes
 * write the same file:
 *
 *   - a NEW contact is always token-provenance and UNVERIFIED. The accepter
 *     cannot know how its invitation travelled (at_create_invitation carries no
 *     in-person flag -- that is the redeemer's local knowledge), so a key that
 *     arrived over the wire has had no out-of-band confirmation, and earns no
 *     trust seed until a safety-number compare.
 *   - an EXISTING contact keeps verified / petname / provenance / trust_seed /
 *     added_at, and only its reachability and nonce are refreshed. A handshake
 *     must never downgrade a verified contact -- a re-presented ticket would
 *     otherwise be a way to strip the verified flag -- and must never rename
 *     one the user already sees.
 *
 * Best-effort: every failure is logged and the handshake continues, because the
 * peer is admitted either way and a lost record costs a re-add, not a security
 * property. */
static void _record_contact(const process_t *proc, const public_identity_t *who,
                            const char *nonce, const char *endpoint)
{
    if (who == NULL)
        return;
    char data_dir[CFG_PATH_LEN + 1] = {0};
    if (get_data_dir(data_dir, sizeof(data_dir)) <= 0) {
        log_warn(proc->logger,
                 "Identity: first contact: no data dir; contact not recorded\n");
        return;
    }

    contacts_t store;
    contacts_init(&store);
    /* A missing file is the normal first-run state, and contacts_load reports
     * it as an empty store rather than an error. */
    (void)contacts_load(data_dir, &store);

    char uuid_s[UUID_STRING_LEN + 1] = {0};
    uuid_unparse(who->uuid, uuid_s);
    contact_t *existing = contacts_get(&store, uuid_s);
    if (existing != NULL) {
        _rendezvous_refresh(existing, endpoint);
        if (nonce != NULL && nonce[0] != '\0')
            at_strlcpy(existing->nonce, nonce, sizeof(existing->nonce));
        log_debug(proc->logger,
                  "Identity: first contact: refreshed reachability for %s\n",
                  existing->petname);
    } else {
        contact_t fresh;
        memset(&fresh, 0, sizeof(fresh));
        /* Borrowed: contacts_add deep-copies, so this never owns the identity
         * and must not free it. */
        fresh.identity = *who;
        at_strlcpy(fresh.petname, who->petname, sizeof(fresh.petname));
        fresh.provenance = AT_PROV_TOKEN;
        fresh.verified = false;
        fresh.trust_seed = 0.0;
        fresh.added_at = (double)time(NULL);
        if (nonce != NULL)
            at_strlcpy(fresh.nonce, nonce, sizeof(fresh.nonce));
        _rendezvous_refresh(&fresh, endpoint);
        if (contacts_add(&store, &fresh) == 0)
            log_info(proc->logger,
                     "Identity: first contact: recorded %s as an unverified "
                     "contact\n", fresh.petname);
        else
            log_warn(proc->logger,
                     "Identity: first contact: could not record contact %s\n",
                     uuid_s);
        /* Only the hint list is ours; the identity is borrowed (above). */
        for (size_t i = 0; i < fresh.rendezvous_count; i++)
            free(fresh.rendezvous[i]);
        free(fresh.rendezvous);
    }

    if (contacts_save(&store, data_dir) != 0)
        log_warn(proc->logger,
                 "Identity: first contact: could not persist contacts (%s)\n",
                 strerror(errno));
    contacts_free(&store);
}

bool handle_first_contact_hello(const process_t *proc, directory_t *queues,
                                generic_msg_t *msg)
{
    if (proc == NULL || msg == NULL)
        return true;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!_has_sender(&nmsg->from_whom)) {
        log_warn(proc->logger,
                 "Identity: first-contact hello with no sender identity; ignoring\n");
        return true;
    }

    char *blob = _payload_string(nmsg);
    if (blob == NULL) {
        log_warn(proc->logger,
                 "Identity: first-contact hello: empty ticket; ignoring\n");
        return true;
    }

    at_invitation_t inv;
    if (at_invitation_decode(blob, &inv) != AT_INVITE_OK) {
        log_warn(proc->logger,
                 "Identity: first-contact hello: invalid invitation "
                 "(malformed); ignoring\n");
        free(blob);
        return true;
    }
    free(blob);

    public_identity_t inviter;
    if (at_invitation_verify(&inv, &inviter) != AT_INVITE_OK) {
        log_warn(proc->logger,
                 "Identity: first-contact hello: invalid invitation "
                 "(bad signature); ignoring\n");
        at_invitation_free(&inv);
        return true;
    }

    /* The ticket must be one WE signed, or it is not ours to honor. */
    public_identity_t self;
    memset(&self, 0, sizeof(self));
    bool ours = (identity_own_public_identity(proc, &self) == 0)
                && uuid_compare(self.uuid, inviter.uuid) == 0;
    _free_public(&self);
    _free_public(&inviter);
    if (!ours) {
        log_warn(proc->logger,
                 "Identity: first-contact hello: invitation not minted by us; "
                 "ignoring\n");
        at_invitation_free(&inv);
        return true;
    }

    double now = (double)time(NULL);
    if (at_invitation_is_expired(&inv, now)) {
        log_info(proc->logger,
                 "Identity: first-contact hello: invitation expired; ignoring\n");
        at_invitation_free(&inv);
        return true;
    }

    const char *nonce = json_string_value(json_object_get(inv.body, "nonce"));
    json_t *exp = json_object_get(inv.body, "expiry");
    long expiry = json_is_integer(exp) ? (long)json_integer_value(exp) : 0;
    if (nonce == NULL)
        nonce = "";
    if (at_first_contact_nonce_spent(nonce)) {
        log_warn(proc->logger,
                 "Identity: first-contact hello: nonce already spent "
                 "(single-use); ignoring\n");
        at_invitation_free(&inv);
        return true;
    }
    char nonce_copy[AT_CONTACT_NONCE_MAX + 1];
    at_strlcpy(nonce_copy, nonce, sizeof(nonce_copy));
    at_invitation_free(&inv);
    _fc_spend(proc->logger, nonce_copy, expiry, now);  /* durable: survives a restart */

    identity_admit_direct_peer((process_t *)proc, queues, &nmsg->from_whom);
    log_info(proc->logger,
             "Identity: first contact: admitted %s as a direct peer\n",
             nmsg->from_whom.nickname);

    /* The acknowledgement, plaintext: the initiator is not a known peer on
     * their side of the exchange either until this lands. */
    json_t *body = json_object();
    if (body == NULL)
        return true;
    json_object_set_new(body, "nonce", json_string(nonce_copy));

    generic_msg_t ack = {0};
    ack.type = NET_MESSAGE;
    at_strlcpy(ack.info.net_msg.process, "identity",
               sizeof(ack.info.net_msg.process));
    ack.info.net_msg.function = ID_FC_HELLO_ACK;
    ack.info.net_msg.encrypt = false;
    memcpy(&ack.info.net_msg.to_whom, &nmsg->from_whom,
           sizeof(public_identity_t));
    (void)identity_own_public_identity(proc, &ack.info.net_msg.from_whom);
    at_strlcpy(ack.info.net_msg.return_to, "identity",
               sizeof(ack.info.net_msg.return_to));
    net_msg_pack_json(&ack.info.net_msg, body);
    json_decref(body);
    messaging_send("network", NET_MESSAGE, &ack, false);
    _free_public(&ack.info.net_msg.from_whom);
    /* After the ack is on its way: the address book is durable state, not part
     * of the handshake's critical path. */
    _record_contact(proc, &nmsg->from_whom, nonce_copy, nmsg->from_whom.address);
    return true;
}

bool handle_first_contact_hello_ack(const process_t *proc, directory_t *queues,
                                    generic_msg_t *msg)
{
    if (proc == NULL || msg == NULL)
        return true;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!_has_sender(&nmsg->from_whom)) {
        log_warn(proc->logger,
                 "Identity: first-contact ack with no sender identity; ignoring\n");
        return true;
    }
    /* The echoed nonce is informational: what makes the ack trustworthy is
     * that we already hold the accepter's key from the invitation we redeemed,
     * so the envelope signature is checked against it upstream. Python's
     * handle_hello_ack reads the payload no further either. */
    identity_admit_direct_peer((process_t *)proc, queues, &nmsg->from_whom);
    /* Our own side of the address book. The redeemer usually already has a
     * contact for this identity (at_redeem_invitation built one, possibly
     * verified in person); the preserve rule in _record_contact keeps that
     * posture and only refreshes where the inviter answered from. */
    char ack_nonce[AT_CONTACT_NONCE_MAX + 1] = {0};
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) == 0 && payload != NULL) {
        const char *n = json_string_value(json_object_get(payload, "nonce"));
        if (n != NULL)
            at_strlcpy(ack_nonce, n, sizeof(ack_nonce));
        json_decref(payload);
    }
    _record_contact(proc, &nmsg->from_whom, ack_nonce, nmsg->from_whom.address);
    log_info(proc->logger,
             "Identity: first contact: %s accepted; direct peer established\n",
             nmsg->from_whom.nickname);
    return true;
}

/* Copy [begin, end) into out, or FAIL and clear it.
 *
 * Truncation policy follows cidr_split (network/network.c): a partially-copied
 * address is worse than none, because a caller that ignores the return code
 * would go on to use it as if it were whole -- and half an address still LOOKS
 * like an address. Clearing it makes the next use fail loudly instead. */
static int _copy_host(const char *begin, const char *end,
                      char *out, size_t out_len)
{
    size_t len = (size_t)(end - begin);
    if (len >= out_len) {
        out[0] = '\0';
        return -1;
    }
    memcpy(out, begin, len);
    out[len] = '\0';
    return 0;
}

int at_first_contact_endpoint_host(const char *raw, char *out, size_t out_len)
{
    if (out == NULL || out_len == 0)
        return -1;
    out[0] = '\0';
    if (raw == NULL)
        return -1;

    /* Drop any path tail first, so a port search never runs over it. */
    const char *end = strchr(raw, '/');
    if (end == NULL)
        end = raw + strlen(raw);

    if (*raw == '[') {
        /* Bracketed literal: the host is inside the brackets, and anything
         * after ']' is the port. An unterminated bracket yields everything
         * after '[' -- a best effort on malformed input, chosen so this agrees
         * with Python rather than because it means anything. */
        const char *open = raw + 1;
        if (open > end)
            open = end;
        const char *close = memchr(open, ']', (size_t)(end - open));
        return _copy_host(open, close != NULL ? close : end, out, out_len);
    }

    /* A bracketless IPv6 literal cannot express a port -- the colons are part
     * of the address -- so only a SINGLE colon is a host/port separator. This
     * is the whole point of the function: `strrchr(raw, ':')` turned fe80::1
     * into fe80:, mangling a well-formed address into an unroutable one that
     * still looks like an address. */
    size_t colons = 0;
    const char *sep = NULL;
    for (const char *p = raw; p < end; p++) {
        if (*p == ':') {
            colons++;
            sep = p;
        }
    }
    return _copy_host(raw, colons == 1 ? sep : end, out, out_len);
}

int at_first_contact_initiate(const process_t *proc, directory_t *queues,
                              const char *blob, const char *endpoint,
                              public_identity_t *out)
{
    (void)queues;
    if (proc == NULL || blob == NULL)
        return -1;

    at_invitation_t inv;
    int rc = at_invitation_decode(blob, &inv);
    if (rc != AT_INVITE_OK)
        return rc;
    public_identity_t inviter;
    rc = at_invitation_verify(&inv, &inviter);
    if (rc != AT_INVITE_OK) {
        at_invitation_free(&inv);
        return rc;
    }

    /* Where to reach them: the caller's override, else the invitation's first
     * rendezvous hint, else the address the identity itself advertises. */
    const char *host = endpoint;
    if (host == NULL) {
        json_t *rv = json_object_get(inv.body, "rendezvous");
        if (json_is_array(rv) && json_array_size(rv) > 0)
            host = json_string_value(json_array_get(rv, 0));
    }
    if (host == NULL || host[0] == '\0')
        host = inviter.address;
    char resolved[ADDR_LEN + 1];
    if (at_first_contact_endpoint_host(host, resolved, sizeof(resolved)) != 0) {
        /* Refused, not truncated: sending the hello to a clipped address would
         * fail somewhere far from here, looking like an unreachable peer rather
         * than an address we mangled ourselves. ADDR_LEN + 1 is IPV6_ADDR_LEN,
         * so any numeric address fits and this is reached only by a scoped
         * literal or a name -- see the note in first_contact.h. */
        log_error(proc->logger,
                  "Identity: first contact: endpoint '%s' does not fit in "
                  "%d chars; refusing to send a truncated address\n",
                  host != NULL ? host : "(null)", ADDR_LEN);
        at_invitation_free(&inv);
        _free_public(&inviter);
        return -1;
    }
    at_strlcpy(inviter.address, resolved, sizeof(inviter.address));

    generic_msg_t hello = {0};
    hello.type = NET_MESSAGE;
    at_strlcpy(hello.info.net_msg.process, "identity",
               sizeof(hello.info.net_msg.process));
    hello.info.net_msg.function = ID_FC_HELLO;
    hello.info.net_msg.encrypt = false;
    memcpy(&hello.info.net_msg.to_whom, &inviter, sizeof(public_identity_t));
    (void)identity_own_public_identity(proc, &hello.info.net_msg.from_whom);
    at_strlcpy(hello.info.net_msg.return_to, "identity",
               sizeof(hello.info.net_msg.return_to));
    /* The ticket rides as the RAW blob, byte-for-byte as received -- the same
     * bytes Python's initiate forwards, and the bytes the inviter's signature
     * covers. Not net_msg_pack_json: that would JSON-quote it. */
    size_t blen = strlen(blob);
    hello.info.net_msg.obj = smrt_create(blen + 1);
    if (hello.info.net_msg.obj == NULL) {
        at_invitation_free(&inv);
        _free_public(&inviter);
        _free_public(&hello.info.net_msg.from_whom);
        return -1;
    }
    memcpy(hello.info.net_msg.obj, blob, blen + 1);
    hello.info.net_msg.len = blen;
    messaging_send("network", NET_MESSAGE, &hello, false);
    _free_public(&hello.info.net_msg.from_whom);
    at_invitation_free(&inv);

    if (out != NULL)
        memcpy(out, &inviter, sizeof(public_identity_t));
    else
        _free_public(&inviter);
    return 0;
}
