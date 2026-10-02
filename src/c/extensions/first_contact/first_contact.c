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
#include <sys/stat.h>

#include <jansson.h>
#include <sodium.h>

#include "processes/processes.h"
#include "utilities/message.h"
#include "utilities/msg_types_priv.h"
#include "utilities/logger.h"
#include "utilities/util.h"
#include "utilities/allocation.h"
#include "config/configuration.h"
#include "first_contact/contacts.h"
#include "first_contact/device.h"
#include "first_contact/device_contact.h"
#include "identity/identity.h"
#include "identity/identity_priv.h"
#include "first_contact/first_contact.h"
#include "identity/id_proc_priv.h"
#include "processes/extension.h"
#include "network/network.h"
#include "rendezvous/net_rendezvous.h"
#include "rendezvous/net_relay.h"
#include "identity/id_ext.h"
#include "negotiation/neg_ext.h"
#include "reputation/rep_ext.h"
#include "rendezvous/reach.h"
#include "first_contact/fc_shared.h"
#include "first_contact/directory_contact.h"
#include "first_contact/area_contact.h"
#include "first_contact/sibling_sync.h"
#include "first_contact/backup_contact.h"
#include "first_contact/siblings.h"

/* First contact: the OPTIONAL 1:1 introduction handshake (opt-in via
 * AT_FIRST_CONTACT; first_contact/first_contact.c, doc/architecture/first-contact.md).
 * DISTINCT from the cohort vote: a node holding a signed invitation reaches the
 * inviter directly, and each side admits the other as a DIRECT peer
 * (identity_admit_direct_peer -- no group key) rather than as a group member.
 *
 * Both ride the OPEN unencrypted channel because the first hello arrives before
 * the sender is a known peer, exactly like ID_ACCEPT. They are deliberately NOT
 * bootstrap verbs: they confer no group membership and hand over no group key,
 * so the gateway boundary need not refuse them.
 *
 * Owned by first contact (FEATURE_SPLIT_PLAN Phase 7, C6), not by the core's
 * verb table: declared `extern` in first_contact.h so the other first-contact
 * modules share the definition instead of respelling it. Mirrors Python
 * FirstContactProtocol.hello / .hello_ack. */
char ID_FC_HELLO[]     = "first_contact_hello";
char ID_FC_HELLO_ACK[] = "first_contact_hello_ack";
/* Directory contact (FIRST_CONTACT_PLAN Phase 3): the finder's request and
 * the holder's accept. Mirrors Python FirstContactProtocol.contact_request
 * / .contact_accept. */
char ID_FC_REQUEST[]   = "first_contact_request";
char ID_FC_ACCEPT[]    = "first_contact_accept";
/* One human, several devices (FIRST_CONTACT_PLAN Phase 4): our device cert,
 * sealed, to a contact; and a new device telling a contact it is one of
 * theirs, plaintext. Mirrors Python FirstContactProtocol.device_cert /
 * .device_announce. */
char ID_FC_DEVICE_CERT[]     = "device_cert";
char ID_FC_DEVICE_ANNOUNCE[] = "device_announce";

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

/****************************
 *  Pending hellos and minted refs (in memory only)
 *
 *  A hello this node sent, and what the inviter's ack must match to be
 *  honored: the ack's sender uuid, the nonce of the ticket presented, and the
 *  SIGNING KEY that ticket carried. The key is not redundant with the uuid --
 *  the envelope is verified against the identity it itself carries, so a
 *  forger can name the inviter's uuid and still sign correctly, with its own
 *  key. Keyed by inviter: a second initiate to the same inviter replaces the
 *  first. Mirrors Python first_contact._Pending / _take_pending.
 *
 *  Minted refs map an invitation this node minted FOR ITS APP back to the
 *  app's ref, so a redemption can be reported under it. Oldest dropped first.
 *
 *  Neither survives a restart, and neither needs to: a forgotten pending hello
 *  costs the user a re-add, and a forgotten ref an empty ref on one event.
 ****************************/

#define AT_FC_PENDING_MAX 64
#define AT_FC_MINTED_MAX 256    /* Python first_contact.MINTED_REFS_MAX */

/* A relay endpoint and the pin naming who must answer there (unset: anyone). */
typedef struct {
    net_relay_ep_t ep;
    net_relay_pin_t pin;
} fc_relay_t;

typedef struct {
    bool used;
    uuid_t inviter;
    unsigned char signing_key[crypto_sign_PUBLICKEYBYTES];
    char nonce[AT_CONTACT_NONCE_MAX + 1];
    char ref[AT_FC_REF_LEN];
    double deadline;
    /* The link's relay:// hints, for the contact the ack records. */
    char relays[AT_RELAY_MAX][AT_RELAY_HOST_LEN + 96];
    size_t n_relays;
    /* How the contact the ack records was found. */
    at_provenance_t provenance;
    /* The link was a pairing invitation (Phase 4, first_contact/sibling_sync.h). */
    bool pair;
} fc_pending_t;

typedef struct {
    char nonce[AT_CONTACT_NONCE_MAX + 1];
    char ref[AT_FC_REF_LEN];
} fc_minted_t;

static struct {
    pthread_mutex_t lock;
    fc_pending_t pending[AT_FC_PENDING_MAX];
    fc_minted_t minted[AT_FC_MINTED_MAX];
    size_t minted_next;          /* ring cursor: the oldest slot */
    /* Our own relays' proven identities, from the network process
     * (NET_FN_RELAY_IDENTITY), to pin them in the links we mint. */
    fc_relay_t own_pins[AT_RELAY_MAX];
    size_t n_own_pins;
} fc_app = { .lock = PTHREAD_MUTEX_INITIALIZER };

/* One of our own relays as a pinned pair: pinned to who it proved to be when it
 * has, else to the operator's configured pin, else unpinned. */
static fc_relay_t _fc_own_relay(const net_relay_ep_t *ep, const net_relay_pin_t *configured)
{
    fc_relay_t r;
    r.ep = *ep;
    memset(&r.pin, 0, sizeof(r.pin));
    if (configured != NULL && configured->set)
        r.pin = *configured;
    pthread_mutex_lock(&fc_app.lock);
    for (size_t i = 0; i < fc_app.n_own_pins; i++)
        if (fc_app.own_pins[i].ep.port == ep->port
            && strcmp(fc_app.own_pins[i].ep.host, ep->host) == 0)
            r.pin = fc_app.own_pins[i].pin;
    pthread_mutex_unlock(&fc_app.lock);
    return r;
}

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

    pthread_mutex_lock(&fc_app.lock);
    memset(fc_app.pending, 0, sizeof(fc_app.pending));
    memset(fc_app.minted, 0, sizeof(fc_app.minted));
    fc_app.minted_next = 0;
    memset(fc_app.own_pins, 0, sizeof(fc_app.own_pins));
    fc_app.n_own_pins = 0;
    pthread_mutex_unlock(&fc_app.lock);
    at_sibling_sync_reset();
}

/* Record the hello we are about to send. Replaces an earlier one to the same
 * inviter; when full, evicts the one closest to its deadline (it is the one
 * least likely still to be answered). */
static void _fc_pend(const public_identity_t *inviter, const char *nonce,
                     const char *ref, double now,
                     const fc_relay_t *relays, size_t n_relays,
                     at_provenance_t provenance, bool pair)
{
    pthread_mutex_lock(&fc_app.lock);
    fc_pending_t *slot = NULL;
    for (size_t i = 0; i < AT_FC_PENDING_MAX && slot == NULL; i++)
        if (fc_app.pending[i].used
            && uuid_compare(fc_app.pending[i].inviter, inviter->uuid) == 0)
            slot = &fc_app.pending[i];
    for (size_t i = 0; i < AT_FC_PENDING_MAX && slot == NULL; i++)
        if (!fc_app.pending[i].used || fc_app.pending[i].deadline <= now)
            slot = &fc_app.pending[i];
    if (slot == NULL) {
        slot = &fc_app.pending[0];
        for (size_t i = 1; i < AT_FC_PENDING_MAX; i++)
            if (fc_app.pending[i].deadline < slot->deadline)
                slot = &fc_app.pending[i];
    }
    memset(slot, 0, sizeof(*slot));
    slot->used = true;
    uuid_copy(slot->inviter, inviter->uuid);
    memcpy(slot->signing_key, inviter->signature.public, sizeof(slot->signing_key));
    at_strlcpy(slot->nonce, nonce != NULL ? nonce : "", sizeof(slot->nonce));
    at_strlcpy(slot->ref, ref != NULL ? ref : "", sizeof(slot->ref));
    slot->deadline = now + AT_FC_PENDING_TTL_SECONDS;
    slot->provenance = provenance;
    slot->pair = pair;
    for (size_t i = 0; i < n_relays && slot->n_relays < AT_RELAY_MAX; i++)
        if (net_relay_hint_for_pinned(relays[i].ep.host, relays[i].ep.port,
                                      &relays[i].pin,
                                      slot->relays[slot->n_relays],
                                      sizeof(slot->relays[0])) == 0)
            slot->n_relays++;
    pthread_mutex_unlock(&fc_app.lock);
}

/* Consume the pending hello `accepter`'s ack answers, copying its ref into
 * `ref_out`; false (and logged) if there is none it may answer. The whole of
 * the ack's trust -- see the block comment above fc_pending_t. */
static bool _fc_take_pending(const process_t *proc,
                             const public_identity_t *accepter,
                             const char *nonce, double now, char *ref_out,
                             size_t ref_len,
                             char relays_out[][AT_RELAY_HOST_LEN + 96],
                             size_t *n_relays_out, at_provenance_t *prov_out,
                             bool *pair_out)
{
    char who[UUID_STRING_LEN + 1];
    uuid_unparse_lower(accepter->uuid, who);
    const char *why = NULL;
    pthread_mutex_lock(&fc_app.lock);
    fc_pending_t *entry = NULL;
    for (size_t i = 0; i < AT_FC_PENDING_MAX; i++) {
        fc_pending_t *p = &fc_app.pending[i];
        if (p->used && p->deadline <= now)
            memset(p, 0, sizeof(*p));          /* expired: drop */
        else if (p->used && uuid_compare(p->inviter, accepter->uuid) == 0)
            entry = p;
    }
    if (entry == NULL)
        why = "no hello pending to it (unsolicited or too late)";
    else if (sodium_memcmp(entry->signing_key, accepter->signature.public,
                           sizeof(entry->signing_key)) != 0)
        why = "signing key differs from the invitation";
    else if (strcmp(entry->nonce, nonce != NULL ? nonce : "") != 0)
        why = "nonce does not match the ticket we presented";
    if (why == NULL) {
        at_strlcpy(ref_out, entry->ref, ref_len);
        *n_relays_out = entry->n_relays;
        *prov_out = entry->provenance;
        *pair_out = entry->pair;
        for (size_t i = 0; i < entry->n_relays; i++)
            at_strlcpy(relays_out[i], entry->relays[i], sizeof(entry->relays[i]));
        memset(entry, 0, sizeof(*entry));
    }
    pthread_mutex_unlock(&fc_app.lock);
    if (why != NULL)
        log_warn(proc->logger,
                 "Identity: first-contact ack from %.8s: %s; ignoring\n", who, why);
    return why == NULL;
}

static void _fc_remember_minted(const char *nonce, const char *ref)
{
    pthread_mutex_lock(&fc_app.lock);
    fc_minted_t *slot = &fc_app.minted[fc_app.minted_next];
    fc_app.minted_next = (fc_app.minted_next + 1) % AT_FC_MINTED_MAX;
    at_strlcpy(slot->nonce, nonce, sizeof(slot->nonce));
    at_strlcpy(slot->ref, ref != NULL ? ref : "", sizeof(slot->ref));
    pthread_mutex_unlock(&fc_app.lock);
}

static void _fc_minted_ref(const char *nonce, char *ref_out, size_t ref_len)
{
    ref_out[0] = '\0';
    if (nonce == NULL || nonce[0] == '\0')
        return;
    pthread_mutex_lock(&fc_app.lock);
    for (size_t i = 0; i < AT_FC_MINTED_MAX; i++)
        if (strcmp(fc_app.minted[i].nonce, nonce) == 0) {
            at_strlcpy(ref_out, fc_app.minted[i].ref, ref_len);
            break;
        }
    pthread_mutex_unlock(&fc_app.lock);
}

/* Hand one outcome to the main loop, which owns the hop to the app. A failed
 * send is not an error: nothing may be listening (tests, a node with no app). */
static void _fc_emit(const process_t *proc, int32_t kind, const char *ref,
                     const public_identity_t *peer, at_fc_reason_t reason,
                     at_fc_role_t role, long expiry, const char *blob)
{
    generic_msg_t msg = {0};
    msg.type = FIRST_CONTACT_EVENT;
    fc_event_msg_t *m = AT_MSG_EXT(&msg, fc_event_msg_t);
    m->kind = kind;
    at_strlcpy(m->data.ref, ref != NULL ? ref : "", sizeof(m->data.ref));
    if (peer != NULL) {
        memcpy(m->data.peer_uuid, peer->uuid, sizeof(m->data.peer_uuid));
        at_strlcpy(m->data.nickname, peer->nickname, sizeof(m->data.nickname));
    }
    m->data.reason = (int32_t)reason;
    m->data.role = (int32_t)role;
    m->data.expiry = (int64_t)expiry;
    if (blob != NULL)
        at_strlcpy(m->data.blob, blob, sizeof(m->data.blob));
    if (messaging_send(AT_MAIN_QUEUE, FIRST_CONTACT_EVENT, &msg, false) != 0)
        log_debug(proc->logger,
                  "Identity: first contact: no main queue for event %d\n", kind);
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

/* The handler table keys on a mutable name, as id_proc.c's verb arrays do. */
static char FC_APP_INVITE[] = AT_APP_FC_INVITE;
/* A contact's reachability record (contacts/reach.h). Mirror: Python
 * FirstContactProtocol.reach_record. */
static char FC_REACH_RECORD[] = "reach_record";
static char FC_APP_INITIATE[] = AT_APP_FC_INITIATE;
static char FC_APP_SAFETY_NUMBER[] = AT_APP_FC_SAFETY_NUMBER;
static char FC_APP_VERIFY[] = AT_APP_FC_VERIFY;
static char FC_APP_LIST[] = AT_APP_FC_LIST;
static char FC_APP_RENAME[] = AT_APP_FC_RENAME;
static char FC_APP_REMOVE[] = AT_APP_FC_REMOVE;

_Static_assert(AT_FC_SAFETY_NUMBER_LEN == AT_SAFETY_NUMBER_LEN,
               "the app ABI's safety-number buffer is the contacts module's");

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
    process_register_handler(proc, FC_APP_INVITE,
                             (handler_ptr_t)handle_first_contact_app_invite);
    process_register_handler(proc, NET_FN_RELAY_IDENTITY,
                             (handler_ptr_t)handle_first_contact_relay_identity);
    process_register_handler(proc, NET_FN_RELAY_PEER,
                             (handler_ptr_t)handle_first_contact_relay_peer);
    process_register_handler(proc, FC_REACH_RECORD,
                             (handler_ptr_t)handle_first_contact_reach_record);
    process_register_handler(proc, FC_APP_INITIATE,
                             (handler_ptr_t)handle_first_contact_app_initiate);
    process_register_handler(proc, FC_APP_SAFETY_NUMBER,
                             (handler_ptr_t)handle_first_contact_app_safety_number);
    process_register_handler(proc, FC_APP_VERIFY,
                             (handler_ptr_t)handle_first_contact_app_verify);
    process_register_handler(proc, FC_APP_LIST,
                             (handler_ptr_t)handle_first_contact_app_list);
    process_register_handler(proc, FC_APP_RENAME,
                             (handler_ptr_t)handle_first_contact_app_rename);
    process_register_handler(proc, FC_APP_REMOVE,
                             (handler_ptr_t)handle_first_contact_app_remove);
    /* Finding someone by handle (FIRST_CONTACT_PLAN Phase 3). */
    at_dir_contact_register(proc);
    /* One human, several devices (Phase 4). */
    at_device_contact_register(proc);
    /* One's own devices, paired and in sync (Phase 4). */
    at_sibling_sync_register(proc);
    at_backup_contact_register(proc);
    /* Finding people nearby at an area hub. */
    at_area_contact_register(proc);
    return 0;
}

/* First contact as an extension (processes/extension.h): identity's handlers
 * only, behind AT_FIRST_CONTACT, which the registry re-reads on every
 * registration so a harness can flip it between scenarios. */
static int _fc_extension_register(process_t *proc, const char *proc_name)
{
    if (strcmp(proc_name, "identity") != 0)
        return 0;
    int rc = at_first_contact_register(proc);
    if (rc == 0)
        log_info(proc->logger,
                 "Identity: first contact (1:1 introduction) enabled\n");
    return rc;
}

static bool _fc_is_relay_hint(const char *hint);
static void _fc_send_relay_route(const uuid_t uuid, const fc_relay_t *eps,
                                 size_t n);
static void _fc_merge_hints(contact_t *c, const char *const *fresh, size_t n_fresh);
/* Reachability records (contacts/reach.h), defined at the end of the file. */
void at_first_contact_refresh_own_record(const process_t *proc);
static void _fc_push_own_record(const process_t *proc,
                                const public_identity_t *only);

static void _free_public(public_identity_t *p);

/* At startup, reconnect every saved contact: re-admit it as a direct peer
 * (peers[] is rebuilt each session and keeps no direct peer) and tell the
 * network process which relays reach it -- the ones its record names, then our
 * own, where it registered to reach us. Unverified contacts come back
 * tier-capped as before (at_first_contact_capped_tier). Mirrors Python
 * first_contact.restore_contacts. Returns how many. */
int at_first_contact_restore_contacts(process_t *proc)
{
    if (proc == NULL || !at_first_contact_enabled())
        return 0;
    char data_dir[CFG_PATH_LEN + 1] = {0};
    if (get_data_dir(data_dir, sizeof(data_dir)) <= 0)
        return 0;
    contacts_t store;
    contacts_init(&store);
    (void)contacts_load(data_dir, &store);
    public_identity_t self;
    memset(&self, 0, sizeof(self));
    bool have_self = identity_own_public_identity(proc, &self) == 0;
    net_relay_ep_t own[AT_RELAY_MAX];
    net_relay_pin_t own_cfg[AT_RELAY_MAX];
    size_t n_own = net_relay_own_hints(own, own_cfg, AT_RELAY_MAX);
    int restored = 0;
    for (size_t i = 0; i < store.count; i++) {
        contact_t *c = &store.items[i];
        if (have_self && uuid_compare(c->identity.uuid, self.uuid) == 0)
            continue;
        (void)identity_admit_direct_peer(proc, NULL, &c->identity);
        /* Its relays first, then ours, deduplicated and capped. */
        fc_relay_t eps[AT_RELAY_MAX];
        size_t n = 0;
        for (size_t pass = 0; pass < 2; pass++) {
            size_t cnt = pass == 0 ? c->rendezvous_count : n_own;
            for (size_t j = 0; j < cnt && n < AT_RELAY_MAX; j++) {
                fc_relay_t r;
                if (pass == 0) {
                    const char *h = c->rendezvous[j];
                    if (h == NULL || !_fc_is_relay_hint(h)
                        || net_relay_parse_hint(h, r.ep.host, sizeof(r.ep.host),
                                                &r.ep.port, &r.pin) != 0)
                        continue;
                } else {
                    r = _fc_own_relay(&own[j], &own_cfg[j]);
                }
                bool dup = false;
                for (size_t k = 0; k < n && !dup; k++)
                    dup = eps[k].ep.port == r.ep.port
                          && strcmp(eps[k].ep.host, r.ep.host) == 0;
                if (!dup)
                    eps[n++] = r;
            }
        }
        _fc_send_relay_route(c->identity.uuid, eps, n);
        /* Every further device of the contact (Phase 4), routed the same way
         * until per-device reach records exist. */
        for (size_t d = 0; d < c->devices_count; d++) {
            public_identity_t dev;
            if (at_contact_device_identity(&c->devices[d], &dev) != 0)
                continue;
            if (!(have_self && uuid_compare(dev.uuid, self.uuid) == 0)) {
                (void)identity_admit_direct_peer(proc, NULL, &dev);
                _fc_send_relay_route(dev.uuid, eps, n);
            }
            _free_public(&dev);
        }
        restored++;
    }
    if (have_self)
        _free_public(&self);
    contacts_free(&store);
    if (restored > 0)
        log_info(proc->logger,
                 "Identity: first contact: reconnecting %d saved contact(s)\n",
                 restored);
    at_first_contact_refresh_own_record(proc);
    return restored;
}

/* The network process says one of our own relays proved who it is ({relay,
 * uuid, fp}). Local IPC only: a peer must not choose the pin our links carry.
 * Mirrors Python first_contact.handle_relay_identity. */
bool handle_first_contact_relay_peer(const process_t *proc, directory_t *queues,
                                     generic_msg_t *msg)
{
    (void)queues;
    if (proc == NULL || msg == NULL)
        return true;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!uuid_is_null(nmsg->from_whom.uuid)) {
        log_warn(proc->logger,
                 "Identity: first contact: refusing relay_peer from the wire\n");
        return true;
    }
    json_t *body = NULL;
    char who[UUID_STRING_LEN + 1] = "";
    if (net_msg_unpack_json(nmsg, &body) == 0 && body != NULL) {
        const char *u = json_string_value(json_object_get(body, "uuid"));
        if (u != NULL)
            at_strlcpy(who, u, sizeof(who));
        json_decref(body);
    }
    uuid_t uu;
    if (who[0] == '\0' || uuid_parse(who, uu) != 0)
        return true;
    char lower[UUID_STRING_LEN + 1];
    uuid_unparse_lower(uu, lower);
    /* A contact (any of its devices) or one of our own devices. */
    char dir[CFG_PATH_LEN + 1] = {0};
    bool ours = false;
    if (get_data_dir(dir, sizeof(dir)) > 0) {
        contacts_t store;
        contacts_init(&store);
        (void)contacts_load(dir, &store);
        ours = contacts_get(&store, lower) != NULL;
        contacts_free(&store);
        if (!ours) {
            at_siblings_t sib;
            at_siblings_load(dir, &sib);
            ours = at_siblings_contains(&sib, lower);
            at_siblings_free(&sib);
        }
    }
    if (!ours)
        return true;
    public_identity_t pub;
    if (!identity_find_peer_pub(proc, uu, &pub))
        return true;
    _free_public(&pub);
    _fc_push_own_record(proc, &pub);
    log_debug(proc->logger, "Identity: first contact: sent our reachability record to "
              "%.8s, which just reached us through a relay\n", lower);
    return true;
}

bool handle_first_contact_relay_identity(const process_t *proc, directory_t *queues,
                                         generic_msg_t *msg)
{
    (void)queues;
    if (proc == NULL || msg == NULL)
        return true;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!uuid_is_null(nmsg->from_whom.uuid)) {
        log_warn(proc->logger,
                 "Identity: first contact: refusing relay_identity from the wire\n");
        return true;
    }
    json_t *body = NULL;
    fc_relay_t r;
    memset(&r, 0, sizeof(r));
    bool ok = false;
    if (net_msg_unpack_json(nmsg, &body) == 0 && body != NULL) {
        const char *where = json_string_value(json_object_get(body, "relay"));
        const char *u = json_string_value(json_object_get(body, "uuid"));
        const char *fp = json_string_value(json_object_get(body, "fp"));
        char hint[AT_RELAY_HOST_LEN + 96];
        ok = where != NULL && u != NULL && fp != NULL
             && (size_t)snprintf(hint, sizeof(hint), "%s:%s@%s", u, fp, where)
                < sizeof(hint)
             && net_relay_parse_hint(hint, r.ep.host, sizeof(r.ep.host),
                                     &r.ep.port, &r.pin) == 0
             && r.pin.set;
        json_decref(body);
    }
    if (!ok) {
        log_warn(proc->logger,
                 "Identity: first contact: unusable relay_identity\n");
        return true;
    }
    bool changed = false;
    pthread_mutex_lock(&fc_app.lock);
    size_t i;
    for (i = 0; i < fc_app.n_own_pins; i++)
        if (fc_app.own_pins[i].ep.port == r.ep.port
            && strcmp(fc_app.own_pins[i].ep.host, r.ep.host) == 0)
            break;
    if (i < fc_app.n_own_pins) {
        changed = strcmp(fc_app.own_pins[i].pin.uuid, r.pin.uuid) != 0
                  || strcmp(fc_app.own_pins[i].pin.fp, r.pin.fp) != 0;
        fc_app.own_pins[i] = r;
    } else if (fc_app.n_own_pins < AT_RELAY_MAX) {
        fc_app.own_pins[fc_app.n_own_pins++] = r;
        changed = true;
    }
    pthread_mutex_unlock(&fc_app.lock);
    if (changed) {
        log_info(proc->logger, "Identity: first contact: our relay %s:%d is "
                 "%.8s; links now pin it\n", r.ep.host, r.ep.port, r.pin.uuid);
        at_first_contact_refresh_own_record(proc);
    }
    return true;
}

static void _fc_run_start(process_t *proc)
{
    (void)at_first_contact_restore_contacts(proc);
    (void)at_sibling_restore(proc);
    (void)at_dir_contact_restore_entries(proc);
    (void)at_area_contact_refresh(proc);
    /* Phase 4: our cert to every contact now a peer, and this device to all. */
    (void)at_device_push_own_cert(proc, NULL);
    (void)at_device_announce(proc);
}

/* First contact follows identity's start (id_ext.h) to restore the address
 * book; the registry is not gated, so the hook checks AT_FIRST_CONTACT. */
/* With the caps-resync sweep: give up on pair handshakes whose cert never
 * came, push any address-book edit not pushed yet, and keep our area cards
 * fresh while we stay listed. Python _periodic. */
static void _fc_periodic(const process_t *proc)
{
    if (!at_first_contact_enabled())
        return;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    (void)at_sibling_expire(proc, NULL, (double)ts.tv_sec + (double)ts.tv_nsec / 1e9);
    (void)at_sibling_push_changes(proc);
    (void)at_area_contact_refresh(proc);
}

static const identity_ext_t first_contact_identity_ext = {
    .name = "first_contact",
    .run_start = _fc_run_start,
    .periodic_resync = _fc_periodic,
};
IDENTITY_EXT_REGISTER(first_contact, &first_contact_identity_ext)

/* Each arrives before the sender is a peer here, so there is no key it could
 * be sealed under. Granted only by unencrypted_verbs.cfg.json. Mirrors Python
 * EXTENSION.plaintext_verbs. */
static const char *const first_contact_plaintext_verbs[] = {
    ID_FC_HELLO, ID_FC_HELLO_ACK, ID_FC_REQUEST, ID_FC_ACCEPT,
    ID_FC_DEVICE_ANNOUNCE, NULL,
};

static const at_extension_t first_contact_extension = {
    .name = "first_contact",
    .enabled = at_first_contact_enabled,
    .register_handlers = _fc_extension_register,
    .reset = at_first_contact_reset,
    .plaintext_verbs = first_contact_plaintext_verbs,
};
AT_EXTENSION_REGISTER(first_contact, &first_contact_extension)

/* §10.3's cap on what an unverified contact may ask of this node, applied by
 * the negotiation process (negotiation/neg_ext.h). */
static const neg_tier_cap_t first_contact_tier_cap = {
    .name = "first_contact",
    .cap = at_first_contact_capped_tier,
};
NEG_TIER_CAP_REGISTER(first_contact, &first_contact_tier_cap)

/* mtime of contacts.cfg.json as of the last seed pass. The identity process
 * rewrites that file on every handshake and every verification, so its mtime is
 * the cheap "anything new?" test that makes a per-iteration call affordable.
 * 0 == not yet read. Read in the reputation process only. */
static double fc_seed_mtime;

/* Offer each VERIFIED contact's cold-start reputation prior to the reputation
 * process (reputation/rep_ext.h), which applies it only to a peer it holds no
 * reputation for.
 *
 * The C twin of Python first_contact.trust_seeds (FIRST_CONTACT_PLAN.md
 * §10.5), and it reads the same file: contacts.cfg.json is already shared
 * byte-for-byte between the runtimes, which is why the seed travels through
 * the store rather than through a new identity->reputation message. Both
 * halves of the record are checked (verified AND a seed above zero): the file
 * is plain JSON in the user's data dir, so honouring a hand-written trust_seed
 * on an unverified record would make one editable float into a reputation
 * prior. Not gated on $AT_FIRST_CONTACT: a contact verified while it was on
 * stays verified. */
static void _fc_trust_seeds(const process_t *proc, rep_seed_offer_fn offer, void *arg)
{
    char data_dir[CFG_PATH_LEN + 1] = {0};
    if (get_data_dir(data_dir, sizeof(data_dir)) <= 0)
        return;
    char path[CFG_PATH_LEN + 64] = {0};
    if ((size_t)snprintf(path, sizeof(path), "%s/%s", data_dir,
                         AT_CONTACTS_FILENAME) >= sizeof(path))
        return;

    struct stat st;
    if (stat(path, &st) != 0)
        return;         /* no contacts file at all: the norm for most nodes */
    double mtime = (double)st.st_mtime;
    if (mtime <= fc_seed_mtime)
        return;         /* nothing written since the last pass */
    fc_seed_mtime = mtime;

    contacts_t store;
    contacts_init(&store);
    if (contacts_load(data_dir, &store) != 0) {
        log_warn(proc->logger,
                 "Reputation: contacts store unreadable; no trust seeds "
                 "applied this pass\n");
        contacts_free(&store);
        return;
    }
    size_t total = contacts_count(&store);
    for (size_t i = 0; i < total; i++) {
        const contact_t *c = &store.items[i];
        if (!c->verified || c->trust_seed <= 0.0)
            continue;
        /* Every device of the contact is its own node, each seeded on its own
         * (Phase 4): the human was verified, the standing is not shared. */
        for (size_t d = 0; d <= c->devices_count; d++) {
            uuid_t who;
            if (d == 0)
                uuid_copy(who, c->identity.uuid);
            else if (uuid_parse(c->devices[d - 1].uuid, who) != 0)
                continue;
            offer(arg, who, c->trust_seed, "verified contact");
        }
    }
    contacts_free(&store);
}

static const rep_seed_provider_t first_contact_seeds = {
    .name = "first contact",
    .seeds = _fc_trust_seeds,
};
REP_SEED_PROVIDER_REGISTER(first_contact, &first_contact_seeds)

/* The app may send exactly these verbs, each only to identity. Mirrors
 * Python's EXTENSION.app_verbs. */
AT_APP_VERB_REGISTER(fc_invite, AT_APP_FC_INVITE, "identity")
AT_APP_VERB_REGISTER(fc_initiate, AT_APP_FC_INITIATE, "identity")
AT_APP_VERB_REGISTER(fc_safety_number, AT_APP_FC_SAFETY_NUMBER, "identity")
AT_APP_VERB_REGISTER(fc_verify, AT_APP_FC_VERIFY, "identity")
AT_APP_VERB_REGISTER(fc_list, AT_APP_FC_LIST, "identity")
AT_APP_VERB_REGISTER(fc_rename, AT_APP_FC_RENAME, "identity")
AT_APP_VERB_REGISTER(fc_remove, AT_APP_FC_REMOVE, "identity")

void at_first_contact_link(void)
{
    at_first_contact_app_link();
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

static bool _fc_is_relay_hint(const char *hint)
{
    return strncmp(hint, AT_RELAY_SCHEME, strlen(AT_RELAY_SCHEME)) == 0;
}

/* A contact's rendezvous list: @p fresh hints ahead of what it has,
 * deduplicated. Relay hints and direct addresses are capped separately
 * (AT_RELAY_MAX and AT_FC_MAX_RENDEZVOUS_HINTS), so refreshing an address can
 * never push out a relay the contact is reached through; relay hints come
 * first, in the order to try them. Both runtimes write the same
 * contacts.cfg.json, so this is Python first_contact._merge_hints exactly. */
static void _fc_merge_hints(contact_t *c, const char *const *fresh, size_t n_fresh)
{
    if (c == NULL || n_fresh == 0)
        return;
    size_t cap = AT_RELAY_MAX + AT_FC_MAX_RENDEZVOUS_HINTS;
    char **hints = calloc(cap, sizeof(char *));
    if (hints == NULL)
        return;             /* keep what we have rather than lose it */
    size_t n = 0;
    for (int want_relay = 1; want_relay >= 0; want_relay--) {
        size_t limit = want_relay ? AT_RELAY_MAX : AT_FC_MAX_RENDEZVOUS_HINTS;
        size_t kept = 0;
        for (size_t pass = 0; pass < 2; pass++) {
            const char *const *src = pass == 0 ? fresh : (const char *const *)c->rendezvous;
            size_t cnt = pass == 0 ? n_fresh : c->rendezvous_count;
            for (size_t i = 0; i < cnt && kept < limit; i++) {
                const char *h = src[i];
                if (h == NULL || h[0] == '\0' || _fc_is_relay_hint(h) != (bool)want_relay)
                    continue;
                bool dup = false;
                if (want_relay) {
                    /* One hint per relay endpoint, the first (freshest) kept:
                     * a pinned and an unpinned hint name the same relay. */
                    char h_host[AT_RELAY_HOST_LEN], o_host[AT_RELAY_HOST_LEN];
                    int h_port = 0, o_port = 0;
                    if (net_relay_parse_endpoint(h, h_host, sizeof(h_host), &h_port) != 0)
                        continue;
                    for (size_t j = 0; j < n && !dup; j++)
                        dup = _fc_is_relay_hint(hints[j])
                              && net_relay_parse_endpoint(hints[j], o_host,
                                                          sizeof(o_host), &o_port) == 0
                              && o_port == h_port && strcmp(o_host, h_host) == 0;
                } else {
                    for (size_t j = 0; j < n && !dup; j++)
                        dup = strcmp(hints[j], h) == 0;
                }
                if (dup)
                    continue;
                char *copy = strdup(h);
                if (copy == NULL)
                    continue;
                hints[n++] = copy;
                kept++;
            }
        }
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
                            const char *nonce, const char *endpoint,
                            const char *const *relays, size_t n_relays,
                            at_provenance_t provenance)
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
    /* The peer's relay:// hints (the initiator's copy of the link's) ahead of
     * the address it answered from. */
    const char *fresh_hints[AT_RELAY_MAX + 1];
    size_t n_fresh = 0;
    for (size_t i = 0; i < n_relays && i < AT_RELAY_MAX; i++)
        fresh_hints[n_fresh++] = relays[i];
    if (endpoint != NULL && endpoint[0] != '\0')
        fresh_hints[n_fresh++] = endpoint;
    contact_t *existing = contacts_get(&store, uuid_s);
    if (existing != NULL) {
        _fc_merge_hints(existing, fresh_hints, n_fresh);
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
        /* A sender rebuilt from the envelope's flat from_* fields has no
         * petname -- none crosses the wire -- and a contact with an empty one
         * shows the user nothing to call them by. Derive one, as Python's
         * Contact does for an empty petname. */
        if (fresh.petname[0] == '\0')
            public_identity_derive_petname(who->nickname, fresh.petname,
                                           sizeof(fresh.petname));
        fresh.provenance = provenance;
        fresh.verified = false;
        fresh.trust_seed = 0.0;
        fresh.added_at = (double)time(NULL);
        if (nonce != NULL)
            at_strlcpy(fresh.nonce, nonce, sizeof(fresh.nonce));
        _fc_merge_hints(&fresh, fresh_hints, n_fresh);
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

    /* From here the ticket is provably ours, so a refusal is worth telling our
     * app about ("your link expired"). Before this point it is a stranger's
     * garbage, and reporting it would let anyone on the LAN flood the app. */
    const char *nonce = json_string_value(json_object_get(inv.body, "nonce"));
    json_t *exp = json_object_get(inv.body, "expiry");
    long expiry = json_is_integer(exp) ? (long)json_integer_value(exp) : 0;
    if (nonce == NULL)
        nonce = "";
    char ref[AT_FC_REF_LEN];
    _fc_minted_ref(nonce, ref, sizeof(ref));

    double now = (double)time(NULL);
    if (at_invitation_is_expired(&inv, now)) {
        log_info(proc->logger,
                 "Identity: first-contact hello: invitation expired; ignoring\n");
        _fc_emit(proc, AT_APP_EVENT_FC_REFUSED, ref, &nmsg->from_whom,
                 AT_FC_REASON_EXPIRED, AT_FC_ROLE_INVITER, 0, NULL);
        at_invitation_free(&inv);
        return true;
    }
    if (at_first_contact_nonce_spent(nonce)) {
        log_warn(proc->logger,
                 "Identity: first-contact hello: nonce already spent "
                 "(single-use); ignoring\n");
        _fc_emit(proc, AT_APP_EVENT_FC_REFUSED, ref, &nmsg->from_whom,
                 AT_FC_REASON_SPENT, AT_FC_ROLE_INVITER, 0, NULL);
        at_invitation_free(&inv);
        return true;
    }
    char nonce_copy[AT_CONTACT_NONCE_MAX + 1];
    at_strlcpy(nonce_copy, nonce, sizeof(nonce_copy));
    bool pair = strcmp(at_invitation_purpose(&inv), AT_INVITATION_PURPOSE_PAIR) == 0;
    at_invitation_free(&inv);
    _fc_spend(proc->logger, nonce_copy, expiry, now);  /* durable: survives a restart */

    /* A pairing invitation of ours: no contact; wait for the sender's cert
     * (first_contact/sibling_sync.h). Without a cert of our own there is no one to
     * pair under, and no ack. Python _hello_pair. */
    if (pair && !at_sibling_can_pair(proc)) {
        at_sibling_refuse(proc, queues, &nmsg->from_whom, ref, AT_FC_ROLE_INVITER, false);
        return true;
    }

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
    (void)identity_send_to_network(proc, &ack, "first contact ack", NULL);
    net_msg_free_obj(&ack.info.net_msg);
    _free_public(&ack.info.net_msg.from_whom);
    if (pair) {
        const char *hints[1] = {nmsg->from_whom.address};
        at_sibling_begin(proc, queues, &nmsg->from_whom, ref, AT_FC_ROLE_INVITER, hints,
                         nmsg->from_whom.address[0] != '\0' ? 1 : 0);
        log_info(proc->logger, "Identity: first contact: pairing with %s\n",
                 nmsg->from_whom.nickname);
        return true;
    }
    /* After the ack is on its way: the address book is durable state, not part
     * of the handshake's critical path. */
    _record_contact(proc, &nmsg->from_whom, nonce_copy, nmsg->from_whom.address,
                    NULL, 0, at_area_contact_is_invite(nonce_copy) ? AT_PROV_AREA
                             : at_dir_contact_is_invite(nonce_copy) ? AT_PROV_DIRECTORY
                                                                    : AT_PROV_TOKEN);
    _fc_push_own_record(proc, &nmsg->from_whom);
    (void)at_device_push_own_cert(proc, &nmsg->from_whom);
    (void)at_sibling_push_changes(proc);
    _fc_emit(proc, AT_APP_EVENT_FC_ESTABLISHED, ref, &nmsg->from_whom,
             AT_FC_REASON_NONE, AT_FC_ROLE_INVITER, 0, NULL);
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
    char ack_nonce[AT_CONTACT_NONCE_MAX + 1] = {0};
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) == 0 && payload != NULL) {
        const char *n = json_string_value(json_object_get(payload, "nonce"));
        if (n != NULL)
            at_strlcpy(ack_nonce, n, sizeof(ack_nonce));
        json_decref(payload);
    }
    /* Only an ack answering a hello WE sent. Before this gate any stranger's
     * plaintext ack made it a direct peer: the unknown-sender receive path
     * routes a plaintext envelope with no verb filter, and the envelope is
     * verified only against the identity it carries -- so nothing upstream
     * stood in the way. */
    char ref[AT_FC_REF_LEN] = {0};
    char relays[AT_RELAY_MAX][AT_RELAY_HOST_LEN + 96];
    size_t n_relays = 0;
    at_provenance_t provenance = AT_PROV_TOKEN;
    bool pair = false;
    if (!_fc_take_pending(proc, &nmsg->from_whom, ack_nonce,
                          (double)time(NULL), ref, sizeof(ref), relays, &n_relays,
                          &provenance, &pair))
        return true;
    const char *relay_hints[AT_RELAY_MAX + 1];
    for (size_t i = 0; i < n_relays; i++)
        relay_hints[i] = relays[i];
    identity_admit_direct_peer((process_t *)proc, queues, &nmsg->from_whom);
    if (pair) {
        size_t n = n_relays;
        if (nmsg->from_whom.address[0] != '\0')
            relay_hints[n++] = nmsg->from_whom.address;
        at_sibling_begin(proc, queues, &nmsg->from_whom, ref, AT_FC_ROLE_INITIATOR,
                         relay_hints, n);
        log_info(proc->logger, "Identity: first contact: pairing with %s\n",
                 nmsg->from_whom.nickname);
        return true;
    }
    /* Our own side of the address book. The redeemer usually already has a
     * contact for this identity (at_redeem_invitation built one, possibly
     * verified in person); the preserve rule in _record_contact keeps that
     * posture and only refreshes where the inviter answered from. */
    _record_contact(proc, &nmsg->from_whom, ack_nonce, nmsg->from_whom.address,
                    relay_hints, n_relays, provenance);
    log_info(proc->logger,
             "Identity: first contact: %s accepted; direct peer established\n",
             nmsg->from_whom.nickname);
    _fc_push_own_record(proc, &nmsg->from_whom);
    (void)at_device_push_own_cert(proc, &nmsg->from_whom);
    (void)at_sibling_push_changes(proc);
    _fc_emit(proc, AT_APP_EVENT_FC_ESTABLISHED, ref, &nmsg->from_whom,
             AT_FC_REASON_NONE, AT_FC_ROLE_INITIATOR, 0, NULL);
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

/* Tell the network process to reach @p uuid through @p eps, in preference
 * order: {uuid, relays: [host:port, ...]}. Local IPC. Mirrors Python
 * first_contact._send_relay_route. */
static void _fc_send_relay_route(const uuid_t uuid, const fc_relay_t *eps,
                                 size_t n)
{
    if (n == 0)
        return;
    json_t *rb = json_object();
    json_t *list = json_array();
    if (rb == NULL || list == NULL) {
        json_decref(rb);
        json_decref(list);
        return;
    }
    char iu[UUID_STRING_LEN + 1];
    uuid_unparse_lower(uuid, iu);
    for (size_t i = 0; i < n; i++) {
        /* "[uuid:fp@]host:port": the hint without its scheme. */
        char hint[AT_RELAY_HOST_LEN + 96];
        if (net_relay_hint_for_pinned(eps[i].ep.host, eps[i].ep.port, &eps[i].pin,
                                      hint, sizeof(hint)) == 0)
            json_array_append_new(list, json_string(hint + strlen(AT_RELAY_SCHEME)));
    }
    json_object_set_new(rb, "uuid", json_string(iu));
    json_object_set_new(rb, "relays", list);
    generic_msg_t route = {0};
    route.type = NET_MESSAGE;
    at_strlcpy(route.info.net_msg.process, "network",
               sizeof(route.info.net_msg.process));
    route.info.net_msg.function = NET_FN_RELAY_ROUTE;
    route.info.net_msg.encrypt = false;
    net_msg_pack_json(&route.info.net_msg, rb);
    json_decref(rb);
    (void)identity_send_to_network(NULL, &route, "first contact relay route", NULL);
    net_msg_free_obj(&route.info.net_msg);
}

int at_first_contact_initiate(const process_t *proc, directory_t *queues,
                              const char *blob, const char *endpoint,
                              public_identity_t *out)
{
    return at_first_contact_initiate_ref(proc, queues, blob, endpoint, NULL, out);
}

int at_first_contact_initiate_ref(const process_t *proc, directory_t *queues,
                                  const char *blob, const char *endpoint,
                                  const char *ref, public_identity_t *out)
{
    return at_first_contact_initiate_prov(proc, queues, blob, endpoint, ref,
                                          AT_PROV_TOKEN, out);
}

int at_first_contact_initiate_prov(const process_t *proc, directory_t *queues,
                                   const char *blob, const char *endpoint,
                                   const char *ref, at_provenance_t provenance,
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
     * DIRECT rendezvous hint, else the address the identity itself advertises.
     * A relay hint wins when the caller names no endpoint: it reaches an
     * inviter behind NAT, which its own address cannot. The network process
     * is told the route BEFORE the hello goes, so the hello takes it
     * (network/net_relay.h); the address below is then only a label. Mirrors
     * Python first_contact.initiate. */
    const char *host = endpoint;
    fc_relay_t relay_eps[AT_RELAY_MAX];
    size_t n_relay = 0;
    json_t *rv = json_object_get(inv.body, "rendezvous");
    size_t n_rv = json_is_array(rv) ? json_array_size(rv) : 0;
    for (size_t i = 0; i < n_rv; i++) {
        const char *hint = json_string_value(json_array_get(rv, i));
        if (hint == NULL)
            continue;
        if (_fc_is_relay_hint(hint)) {
            /* Every relay the link names, in its order, to fail over along. */
            fc_relay_t r;
            if (endpoint == NULL && n_relay < AT_RELAY_MAX
                && net_relay_parse_hint(hint, r.ep.host, sizeof(r.ep.host),
                                        &r.ep.port, &r.pin) == 0) {
                bool dup = false;
                for (size_t j = 0; j < n_relay && !dup; j++)
                    dup = relay_eps[j].ep.port == r.ep.port
                          && strcmp(relay_eps[j].ep.host, r.ep.host) == 0;
                if (!dup)
                    relay_eps[n_relay++] = r;
            }
        } else if (host == NULL) {
            host = hint;
        }
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
    hello.info.net_msg.obj = malloc(blen + 1);
    if (hello.info.net_msg.obj == NULL) {
        at_invitation_free(&inv);
        _free_public(&inviter);
        _free_public(&hello.info.net_msg.from_whom);
        return -1;
    }
    memcpy(hello.info.net_msg.obj, blob, blen + 1);
    hello.info.net_msg.len = blen;
    _fc_send_relay_route(inviter.uuid, relay_eps, n_relay);
    /* Pending BEFORE the send, so an ack that races back finds it. */
    _fc_pend(&inviter,
             json_string_value(json_object_get(inv.body, "nonce")), ref,
             (double)time(NULL), relay_eps, n_relay, provenance,
             strcmp(at_invitation_purpose(&inv), AT_INVITATION_PURPOSE_PAIR) == 0);
    (void)identity_send_to_network(proc, &hello, "first contact hello", NULL);
    net_msg_free_obj(&hello.info.net_msg);
    _free_public(&hello.info.net_msg.from_whom);
    at_invitation_free(&inv);

    if (out != NULL)
        memcpy(out, &inviter, sizeof(public_identity_t));
    else
        _free_public(&inviter);
    return 0;
}

/****************************
 *  App verbs: how an application adds a friend (at_first_contact.h)
 ****************************/

/* The request's JSON object, or NULL. Caller decrefs. */
static json_t *_fc_app_payload(net_msg_t *nmsg)
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

/* The request's ref, or NULL when it is present but not a string that fits:
 * a cut ref would answer nobody. Mirrors Python _app_ref / REF_MAX. */
static const char *_fc_app_ref(const json_t *req)
{
    json_t *r = req != NULL ? json_object_get(req, "ref") : NULL;
    if (r == NULL || json_is_null(r))
        return "";
    const char *ref = json_string_value(r);
    if (ref == NULL || strlen(ref) >= AT_FC_REF_LEN)
        return NULL;
    return ref;
}

/* A number the way Python's int() takes it: integers, and reals truncated. */
static bool _fc_json_long(const json_t *v, long *out)
{
    if (!json_is_number(v))
        return false;
    *out = json_is_integer(v) ? (long)json_integer_value(v)
                              : (long)json_real_value(v);
    return true;
}

/* A fresh anti-replay nonce: 16 random bytes as UPPER-case hex, the form
 * Python's base64.b16encode gives, so a nonce reads the same from either
 * runtime. (at_create_invitation writes "" for a NULL nonce, so the caller
 * must supply one.) */
static void _fc_new_nonce(char out[33])
{
    unsigned char raw[16];
    randombytes_buf(raw, sizeof(raw));
    sodium_bin2hex(out, 33, raw, sizeof(raw));
    for (size_t i = 0; out[i] != '\0'; i++)
        if (out[i] >= 'a' && out[i] <= 'f')
            out[i] = (char)(out[i] - 'a' + 'A');
}

bool handle_first_contact_app_invite(const process_t *proc, directory_t *queues,
                                     generic_msg_t *msg)
{
    (void)queues;
    if (proc == NULL || msg == NULL)
        return true;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!identity_is_local_app_verb(proc, nmsg))
        return identity_refuse_remote_app_verb(proc, nmsg, AT_APP_FC_INVITE);

    json_t *req = _fc_app_payload(nmsg);
    const char *ref = _fc_app_ref(req);
    if (ref == NULL) {
        log_warn(proc->logger,
                 "Identity: first contact: app invite ref over %d chars\n",
                 AT_FC_REF_LEN - 1);
        _fc_emit(proc, AT_APP_EVENT_FC_REFUSED, "", NULL,
                 AT_FC_REASON_BAD_REQUEST, AT_FC_ROLE_NONE, 0, NULL);
        json_decref(req);
        return true;
    }
    char ref_copy[AT_FC_REF_LEN];
    at_strlcpy(ref_copy, ref, sizeof(ref_copy));

    /* Expiry: an absolute `expiry` wins, then `ttl_seconds` (0 = never), then
     * the default week -- Python create_invitation's precedence exactly. */
    long now = (long)time(NULL);
    long expiry = now + AT_FC_DEFAULT_TTL_SECONDS;
    bool ok = true;
    json_t *jexp = req != NULL ? json_object_get(req, "expiry") : NULL;
    json_t *jttl = req != NULL ? json_object_get(req, "ttl_seconds") : NULL;
    long v = 0;
    if (jexp != NULL) {
        ok = _fc_json_long(jexp, &v);
        expiry = v;
    } else if (jttl != NULL) {
        ok = _fc_json_long(jttl, &v);
        expiry = v != 0 ? now + v : 0;
    }

    /* `pair`: a pairing invitation (first_contact/sibling_sync.h); true or false. */
    json_t *jpair = req != NULL ? json_object_get(req, "pair") : NULL;
    bool pair = json_is_true(jpair);
    if (jpair != NULL && !json_is_boolean(jpair))
        ok = false;
    const char **hints = NULL;
    size_t n_hints = 0;
    json_t *jrv = req != NULL ? json_object_get(req, "rendezvous") : NULL;
    if (ok && jrv != NULL && !json_is_null(jrv)) {
        if (!json_is_array(jrv)) {
            ok = false;
        } else if (json_array_size(jrv) > 0) {
            hints = calloc(json_array_size(jrv), sizeof(*hints));
            ok = hints != NULL;
            for (size_t i = 0; ok && i < json_array_size(jrv); i++) {
                hints[i] = json_string_value(json_array_get(jrv, i));
                ok = hints[i] != NULL;
                n_hints++;
            }
        }
    }
    if (!ok) {
        log_warn(proc->logger,
                 "Identity: first contact: app invite with an unusable payload\n");
        _fc_emit(proc, AT_APP_EVENT_FC_REFUSED, ref_copy, NULL,
                 AT_FC_REASON_BAD_REQUEST, AT_FC_ROLE_NONE, 0, NULL);
        free(hints);
        json_decref(req);
        return true;
    }

    if (pair && !at_sibling_can_pair(proc)) {
        log_warn(proc->logger, "Identity: first contact: no device cert installed; "
                 "cannot mint a pairing invitation\n");
        _fc_emit(proc, AT_APP_EVENT_FC_REFUSED, ref_copy, NULL,
                 AT_FC_REASON_NOT_SIBLING, AT_FC_ROLE_NONE, 0, NULL);
        free(hints);
        json_decref(req);
        return true;
    }

    /* Behind relays, say so in the link: they are how a friend on another
     * network reaches us at all (network/net_relay.h). All of them, in our
     * order of preference, so the friend can fail over; none if the app named
     * its own. */
    net_relay_ep_t own[AT_RELAY_MAX];
    net_relay_pin_t own_cfg[AT_RELAY_MAX];
    size_t n_own = net_relay_own_hints(own, own_cfg, AT_RELAY_MAX);
    char own_hints[AT_RELAY_MAX][AT_RELAY_HOST_LEN + 96];
    bool has = false;
    for (size_t i = 0; i < n_hints && !has; i++)
        has = _fc_is_relay_hint(hints[i]);
    if (!has && n_own > 0) {
        const char **grown = realloc(hints, (n_hints + n_own) * sizeof(*hints));
        if (grown != NULL) {
            hints = grown;
            for (size_t i = 0; i < n_own; i++) {
                fc_relay_t r = _fc_own_relay(&own[i], &own_cfg[i]);
                if (net_relay_hint_for_pinned(r.ep.host, r.ep.port, &r.pin,
                                              own_hints[i], sizeof(own_hints[i])) == 0)
                    hints[n_hints++] = own_hints[i];
            }
        }
    }
    char nonce[33];
    _fc_new_nonce(nonce);
    char *blob = NULL;
    const identity_t *self = identity_self_identity(proc);
    int rc = self == NULL ? -1
           : at_create_invitation_purpose(self, hints, n_hints, expiry, nonce,
                                          pair ? AT_INVITATION_PURPOSE_PAIR : NULL,
                                          &blob);
    free(hints);            /* borrowed strings; req still owns them */
    json_decref(req);

    char link[AT_FC_BLOB_LEN];
    if (rc != 0 || blob == NULL) {
        log_error(proc->logger,
                  "Identity: first contact: could not mint an invitation\n");
        _fc_emit(proc, AT_APP_EVENT_FC_REFUSED, ref_copy, NULL,
                 AT_FC_REASON_MINT_FAILED, AT_FC_ROLE_NONE, 0, NULL);
        free(blob);
        return true;
    }
    size_t need = (size_t)snprintf(link, sizeof(link), "%s:%s",
                                   AT_INVITATION_URI_SCHEME, blob);
    free(blob);
    if (need >= sizeof(link)) {
        /* Refused, not cut: a truncated link is not a shorter link but a
         * broken one, and it would fail in the friend's hands, far from here. */
        log_error(proc->logger,
                  "Identity: first contact: minted link is %zu chars, over the "
                  "%d the app event carries; not handed out\n",
                  need, AT_FC_BLOB_LEN - 1);
        _fc_emit(proc, AT_APP_EVENT_FC_REFUSED, ref_copy, NULL,
                 AT_FC_REASON_MINT_FAILED, AT_FC_ROLE_NONE, 0, NULL);
        return true;
    }
    _fc_remember_minted(nonce, ref_copy);
    log_info(proc->logger,
             "Identity: first contact: minted an invitation for the app\n");
    _fc_emit(proc, AT_APP_EVENT_FC_INVITATION, ref_copy, NULL,
             AT_FC_REASON_NONE, AT_FC_ROLE_NONE, expiry, link);
    return true;
}

/* Refuse an initiate request, logged and reported under the app's ref. */
static bool _fc_initiate_refused(const process_t *proc, const char *ref,
                                 at_fc_reason_t reason,
                                 const public_identity_t *peer)
{
    static const char *const names[] = {
        "", "malformed", "bad_signature", "expired", "spent", "endpoint",
        "bad_request", "mint_failed", "mismatch", "unknown_contact", "not_sibling" };
    log_warn(proc->logger,
             "Identity: first contact: app initiate refused (%s)\n",
             names[reason]);
    _fc_emit(proc, AT_APP_EVENT_FC_REFUSED, ref, peer, reason,
             AT_FC_ROLE_INITIATOR, 0, NULL);
    return true;
}

bool handle_first_contact_app_initiate(const process_t *proc,
                                       directory_t *queues, generic_msg_t *msg)
{
    if (proc == NULL || msg == NULL)
        return true;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!identity_is_local_app_verb(proc, nmsg))
        return identity_refuse_remote_app_verb(proc, nmsg, AT_APP_FC_INITIATE);

    json_t *req = _fc_app_payload(nmsg);
    const char *ref = _fc_app_ref(req);
    if (ref == NULL) {
        json_decref(req);
        return _fc_initiate_refused(proc, "", AT_FC_REASON_BAD_REQUEST, NULL);
    }
    char ref_copy[AT_FC_REF_LEN];
    at_strlcpy(ref_copy, ref, sizeof(ref_copy));
    const char *blob = req != NULL
        ? json_string_value(json_object_get(req, "invitation")) : NULL;
    if (blob == NULL || blob[0] == '\0') {
        json_decref(req);
        return _fc_initiate_refused(proc, ref_copy, AT_FC_REASON_BAD_REQUEST, NULL);
    }

    /* The checks at_redeem_invitation makes, one at a time, so the app is told
     * WHICH one failed. */
    at_invitation_t inv;
    if (at_invitation_decode(blob, &inv) != AT_INVITE_OK) {
        json_decref(req);
        return _fc_initiate_refused(proc, ref_copy, AT_FC_REASON_MALFORMED, NULL);
    }
    public_identity_t inviter;
    memset(&inviter, 0, sizeof(inviter));
    if (at_invitation_verify(&inv, &inviter) != AT_INVITE_OK) {
        at_invitation_free(&inv);
        json_decref(req);
        return _fc_initiate_refused(proc, ref_copy, AT_FC_REASON_BAD_SIGNATURE,
                                    NULL);
    }
    double now = (double)time(NULL);
    at_fc_reason_t bad = AT_FC_REASON_NONE;
    if (at_invitation_is_expired(&inv, now))
        bad = AT_FC_REASON_EXPIRED;
    const identity_t *self = identity_self_identity(proc);
    if (bad == AT_FC_REASON_NONE && self != NULL
        && uuid_compare(self->uuid, inviter.uuid) == 0)
        bad = AT_FC_REASON_BAD_REQUEST;       /* our own link */
    bool pair = strcmp(at_invitation_purpose(&inv), AT_INVITATION_PURPOSE_PAIR) == 0;
    if (bad == AT_FC_REASON_NONE && pair && !at_sibling_can_pair(proc))
        bad = AT_FC_REASON_NOT_SIBLING;
    at_invitation_free(&inv);
    if (bad != AT_FC_REASON_NONE) {
        _fc_initiate_refused(proc, ref_copy, bad, &inviter);
        _free_public(&inviter);
        json_decref(req);
        return true;
    }

    /* Another device of ours: no contact, only the handshake, then certs
     * (first_contact/sibling_sync.h). */
    if (pair) {
        const char *ep = json_string_value(json_object_get(req, "endpoint"));
        public_identity_t sent;
        memset(&sent, 0, sizeof(sent));
        int prc = at_first_contact_initiate_ref(proc, queues, blob,
                                                ep != NULL && ep[0] != '\0' ? ep : NULL,
                                                ref_copy, &sent);
        json_decref(req);
        if (prc != 0)
            _fc_initiate_refused(proc, ref_copy, AT_FC_REASON_ENDPOINT, &inviter);
        else
            _fc_emit(proc, AT_APP_EVENT_FC_HELLO_SENT, ref_copy, &inviter,
                     AT_FC_REASON_NONE, AT_FC_ROLE_INITIATOR, 0, NULL);
        _free_public(&sent);
        _free_public(&inviter);
        return true;
    }

    /* The address book first: in person means verified at once. */
    bool in_person = json_is_true(json_object_get(req, "in_person"));
    const char *petname = json_string_value(json_object_get(req, "petname"));
    contact_t fresh;
    memset(&fresh, 0, sizeof(fresh));
    char data_dir[CFG_PATH_LEN + 1] = {0};
    if (at_redeem_invitation(blob, in_person, now, &fresh) == AT_INVITE_OK
        && get_data_dir(data_dir, sizeof(data_dir)) > 0) {
        if (petname != NULL && petname[0] != '\0')
            at_strlcpy(fresh.petname, petname, sizeof(fresh.petname));
        contacts_t store;
        contacts_init(&store);
        (void)contacts_load(data_dir, &store);
        char uuid_s[UUID_STRING_LEN + 1] = {0};
        uuid_unparse(inviter.uuid, uuid_s);
        contact_t *existing = contacts_get(&store, uuid_s);
        if (existing == NULL) {
            (void)contacts_add(&store, &fresh);
        } else {
            if (fresh.verified && !existing->verified)
                /* Re-adding someone in person upgrades them; nothing here
                 * downgrades. */
                contact_mark_verified(existing, AT_FIRST_CONTACT_VERIFIED_SEED);
            /* A newer link says where they are now. */
            _fc_merge_hints(existing, (const char *const *)fresh.rendezvous,
                            fresh.rendezvous_count);
        }
        if (contacts_save(&store, data_dir) != 0)
            log_warn(proc->logger,
                     "Identity: first contact: could not persist contact (%s)\n",
                     strerror(errno));
        contacts_free(&store);
        (void)at_sibling_push_changes(proc);
    }
    contact_free(&fresh);

    const char *endpoint = json_string_value(json_object_get(req, "endpoint"));
    if (endpoint != NULL && endpoint[0] == '\0')
        endpoint = NULL;
    public_identity_t sent;
    memset(&sent, 0, sizeof(sent));
    int rc = at_first_contact_initiate_ref(proc, queues, blob, endpoint,
                                           ref_copy, &sent);
    json_decref(req);
    if (rc != 0) {
        /* Decode and signature already passed, so this is the endpoint. */
        _fc_initiate_refused(proc, ref_copy, AT_FC_REASON_ENDPOINT, &inviter);
        _free_public(&inviter);
        return true;
    }
    _fc_emit(proc, AT_APP_EVENT_FC_HELLO_SENT, ref_copy, &inviter,
             AT_FC_REASON_NONE, AT_FC_ROLE_INITIATOR, 0, NULL);
    _free_public(&sent);
    _free_public(&inviter);
    return true;
}

/****************************
 *  App verbs: the address book, through the node
 ****************************/

/* One address-book answer, to the main loop and on to the app. */
static void _fc_emit_contact_o(const process_t *proc, int32_t kind,
                               const char *ref, const contact_t *c,
                               const char *safety, at_fc_method_t method,
                               bool dropped, int32_t count, int32_t origin);

static void _fc_emit_contact(const process_t *proc, int32_t kind,
                             const char *ref, const contact_t *c,
                             const char *safety, at_fc_method_t method,
                             bool dropped, int32_t count)
{
    _fc_emit_contact_o(proc, kind, ref, c, safety, method, dropped, count,
                       AT_FC_ORIGIN_LOCAL);
}

static void _fc_emit_contact_o(const process_t *proc, int32_t kind,
                               const char *ref, const contact_t *c,
                               const char *safety, at_fc_method_t method,
                               bool dropped, int32_t count, int32_t origin)
{
    generic_msg_t msg = {0};
    msg.type = FIRST_CONTACT_CONTACT_EVENT;
    fc_contact_msg_t *m = AT_MSG_EXT(&msg, fc_contact_msg_t);
    m->kind = kind;
    at_strlcpy(m->data.ref, ref != NULL ? ref : "", sizeof(m->data.ref));
    if (c != NULL) {
        memcpy(m->data.peer_uuid, c->identity.uuid, sizeof(m->data.peer_uuid));
        at_strlcpy(m->data.nickname, c->identity.nickname,
                   sizeof(m->data.nickname));
        at_strlcpy(m->data.petname, c->petname, sizeof(m->data.petname));
        m->data.verified = c->verified;
        m->data.provenance = (int32_t)c->provenance;
        m->data.added_at = c->added_at;
        m->data.verified_at = c->verified_at;
    }
    if (safety != NULL)
        at_strlcpy(m->data.safety_number, safety, sizeof(m->data.safety_number));
    m->data.method = (int32_t)method;
    m->data.peer_dropped = dropped;
    m->data.count = count;
    m->data.origin = origin;
    if (messaging_send(AT_MAIN_QUEUE, FIRST_CONTACT_CONTACT_EVENT, &msg, false) != 0)
        log_debug(proc->logger,
                  "Identity: first contact: no main queue for event %d\n", kind);
}

/* A refusal of an address-book request, on the first-contact event. */
static bool _fc_book_refused(const process_t *proc, const char *ref,
                             const char *peer, at_fc_reason_t reason)
{
    generic_msg_t msg = {0};
    msg.type = FIRST_CONTACT_EVENT;
    fc_event_msg_t *m = AT_MSG_EXT(&msg, fc_event_msg_t);
    m->kind = AT_APP_EVENT_FC_REFUSED;
    at_strlcpy(m->data.ref, ref != NULL ? ref : "", sizeof(m->data.ref));
    uuid_t u;
    if (peer != NULL && uuid_parse(peer, u) == 0)
        memcpy(m->data.peer_uuid, u, sizeof(m->data.peer_uuid));
    m->data.reason = (int32_t)reason;
    if (messaging_send(AT_MAIN_QUEUE, FIRST_CONTACT_EVENT, &msg, false) != 0)
        log_debug(proc->logger,
                  "Identity: first contact: no main queue for a refusal\n");
    return true;
}

/* What every address-book request shares: local-only, a usable ref, a peer
 * uuid, and the store loaded. On success the caller owns `req` and `store`
 * and gets the named contact (NULL = not in the book, already reported). */
typedef struct {
    json_t *req;
    char ref[AT_FC_REF_LEN];
    char peer[UUID_STRING_LEN + 1];
    char data_dir[CFG_PATH_LEN + 1];
    contacts_t store;
    contact_t *contact;
} fc_book_t;

static bool _fc_book_open(const process_t *proc, generic_msg_t *msg,
                          const char *verb, bool needs_peer, fc_book_t *b)
{
    memset(b, 0, sizeof(*b));
    contacts_init(&b->store);
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!identity_is_local_app_verb(proc, nmsg)) {
        identity_refuse_remote_app_verb(proc, nmsg, verb);
        return false;
    }
    b->req = _fc_app_payload(nmsg);
    const char *ref = _fc_app_ref(b->req);
    if (ref == NULL) {
        _fc_book_refused(proc, "", NULL, AT_FC_REASON_BAD_REQUEST);
        return false;
    }
    at_strlcpy(b->ref, ref, sizeof(b->ref));
    if (needs_peer) {
        const char *peer = json_string_value(json_object_get(b->req, "peer"));
        uuid_t u;
        if (peer == NULL || uuid_parse(peer, u) != 0) {
            _fc_book_refused(proc, b->ref, NULL, AT_FC_REASON_BAD_REQUEST);
            return false;
        }
        uuid_unparse_lower(u, b->peer);
    }
    if (get_data_dir(b->data_dir, sizeof(b->data_dir)) <= 0) {
        log_warn(proc->logger, "Identity: first contact: no data dir\n");
        _fc_book_refused(proc, b->ref, NULL, AT_FC_REASON_BAD_REQUEST);
        return false;
    }
    (void)contacts_load(b->data_dir, &b->store);
    if (needs_peer) {
        b->contact = contacts_get(&b->store, b->peer);
        if (b->contact == NULL) {
            log_info(proc->logger,
                     "Identity: first contact: %s names no contact\n", verb);
            _fc_book_refused(proc, b->ref, b->peer,
                             AT_FC_REASON_UNKNOWN_CONTACT);
            return false;
        }
    }
    return true;
}

static void _fc_book_close(fc_book_t *b)
{
    contacts_free(&b->store);
    json_decref(b->req);
}

static void _fc_book_save(const process_t *proc, fc_book_t *b)
{
    if (contacts_save(&b->store, b->data_dir) != 0)
        log_warn(proc->logger,
                 "Identity: first contact: could not persist contacts (%s)\n",
                 strerror(errno));
    /* What the user just changed, to our other devices. */
    (void)at_sibling_push_changes(proc);
}

bool handle_first_contact_app_safety_number(const process_t *proc,
                                            directory_t *queues,
                                            generic_msg_t *msg)
{
    (void)queues;
    if (proc == NULL || msg == NULL)
        return true;
    fc_book_t b;
    if (_fc_book_open(proc, msg, AT_APP_FC_SAFETY_NUMBER, true, &b)) {
        public_identity_t me;
        memset(&me, 0, sizeof(me));
        char number[AT_SAFETY_NUMBER_LEN] = {0};
        if (identity_own_public_identity(proc, &me) == 0
            && at_safety_number(&me, &b.contact->identity, number,
                                sizeof(number)) == 0)
            _fc_emit_contact(proc, AT_APP_EVENT_FC_SAFETY_NUMBER, b.ref,
                             b.contact, number, AT_FC_METHOD_NONE, false, 0);
        else
            _fc_book_refused(proc, b.ref, b.peer, AT_FC_REASON_BAD_REQUEST);
        _free_public(&me);
    }
    _fc_book_close(&b);
    return true;
}

bool handle_first_contact_app_verify(const process_t *proc, directory_t *queues,
                                     generic_msg_t *msg)
{
    (void)queues;
    if (proc == NULL || msg == NULL)
        return true;
    fc_book_t b;
    if (!_fc_book_open(proc, msg, AT_APP_FC_VERIFY, true, &b)) {
        _fc_book_close(&b);
        return true;
    }
    /* Typed digits are compared here; a confirmation is the user's word, on
     * the local channel, as in_person is. Sending back the number this node
     * handed out would compare it with itself, which is why a confirmation is
     * its own path rather than a disguised comparison. */
    const char *presented =
        json_string_value(json_object_get(b.req, "presented"));
    bool typed = false;
    for (const char *p = presented; p != NULL && *p != '\0'; p++)
        if (*p != ' ' && *p != '\t' && *p != '\n' && *p != '\r')
            typed = true;
    at_fc_method_t method = AT_FC_METHOD_NONE;
    if (typed) {
        public_identity_t me;
        memset(&me, 0, sizeof(me));
        int rc = identity_own_public_identity(proc, &me) == 0
               ? at_verify_contact(b.contact, presented, &me) : -1;
        _free_public(&me);
        if (rc != 0) {
            log_warn(proc->logger,
                     "Identity: first contact: safety number mismatch for %s; "
                     "left unverified\n", b.contact->petname);
            _fc_book_refused(proc, b.ref, b.peer, AT_FC_REASON_MISMATCH);
            _fc_book_close(&b);
            return true;
        }
        method = AT_FC_METHOD_PRESENTED;
    } else if (json_is_true(json_object_get(b.req, "confirmed"))) {
        contact_mark_verified(b.contact, AT_FIRST_CONTACT_VERIFIED_SEED);
        method = AT_FC_METHOD_CONFIRMED;
    } else {
        _fc_book_refused(proc, b.ref, b.peer, AT_FC_REASON_BAD_REQUEST);
        _fc_book_close(&b);
        return true;
    }
    _fc_book_save(proc, &b);
    log_info(proc->logger, "Identity: first contact: %s verified (%s)\n",
             b.contact->petname,
             method == AT_FC_METHOD_PRESENTED ? "presented" : "confirmed");
    _fc_emit_contact(proc, AT_APP_EVENT_FC_VERIFIED, b.ref, b.contact, NULL,
                     method, false, 0);
    _fc_book_close(&b);
    return true;
}

/* Oldest first, uuid breaking ties -- the order Python's list sends. */
static int _fc_by_added(const void *a, const void *b)
{
    const contact_t *x = *(const contact_t *const *)a;
    const contact_t *y = *(const contact_t *const *)b;
    if (x->added_at < y->added_at) return -1;
    if (x->added_at > y->added_at) return 1;
    char ux[UUID_STRING_LEN + 1], uy[UUID_STRING_LEN + 1];
    uuid_unparse_lower(x->identity.uuid, ux);
    uuid_unparse_lower(y->identity.uuid, uy);
    return strcmp(ux, uy);
}

bool handle_first_contact_app_list(const process_t *proc, directory_t *queues,
                                   generic_msg_t *msg)
{
    (void)queues;
    if (proc == NULL || msg == NULL)
        return true;
    fc_book_t b;
    if (_fc_book_open(proc, msg, AT_APP_FC_LIST, false, &b)) {
        size_t n = contacts_count(&b.store);
        const contact_t **order = n > 0 ? calloc(n, sizeof(*order)) : NULL;
        if (n > 0 && order == NULL)
            n = 0;
        for (size_t i = 0; i < n; i++)
            order[i] = &b.store.items[i];
        if (n > 1)
            qsort(order, n, sizeof(*order), _fc_by_added);
        for (size_t i = 0; i < n; i++) {
            _fc_emit_contact(proc, AT_APP_EVENT_FC_CONTACT, b.ref, order[i],
                             NULL, AT_FC_METHOD_NONE, false, 0);
            /* Each further device, in filing order, so an app can rebuild
               which devices are one person after a restart, a sibling sync or
               a restore -- none of which says so live. */
            for (size_t d = 0; d < order[i]->devices_count; d++) {
                uuid_t dev;
                if (uuid_parse(order[i]->devices[d].uuid, dev) == 0)
                    at_fc_emit_device_linked_ref(proc, b.ref, order[i], dev);
            }
        }
        /* Always, so an empty book is an answer and not a silence. */
        _fc_emit_contact(proc, AT_APP_EVENT_FC_CONTACTS_DONE, b.ref, NULL, NULL,
                         AT_FC_METHOD_NONE, false, (int32_t)n);
        free(order);
    }
    _fc_book_close(&b);
    return true;
}

bool handle_first_contact_app_rename(const process_t *proc, directory_t *queues,
                                     generic_msg_t *msg)
{
    (void)queues;
    if (proc == NULL || msg == NULL)
        return true;
    fc_book_t b;
    if (_fc_book_open(proc, msg, AT_APP_FC_RENAME, true, &b)) {
        const char *name = json_string_value(json_object_get(b.req, "petname"));
        bool blank = true;
        for (const char *p = name; p != NULL && *p != '\0'; p++)
            if (*p != ' ' && *p != '\t' && *p != '\n' && *p != '\r')
                blank = false;
        if (name == NULL || blank || strlen(name) > NAME_LEN) {
            _fc_book_refused(proc, b.ref, b.peer, AT_FC_REASON_BAD_REQUEST);
        } else {
            at_strlcpy(b.contact->petname, name, sizeof(b.contact->petname));
            contact_touch(b.contact, -1.0);
            _fc_book_save(proc, &b);
            _fc_emit_contact(proc, AT_APP_EVENT_FC_CONTACT, b.ref, b.contact,
                             NULL, AT_FC_METHOD_NONE, false, 0);
        }
    }
    _fc_book_close(&b);
    return true;
}

bool handle_first_contact_app_remove(const process_t *proc, directory_t *queues,
                                     generic_msg_t *msg)
{
    if (proc == NULL || msg == NULL)
        return true;
    fc_book_t b;
    if (!_fc_book_open(proc, msg, AT_APP_FC_REMOVE, true, &b)) {
        _fc_book_close(&b);
        return true;
    }
    /* The event describes what was removed, so copy it out before the store
     * frees it. Only the flat fields are read, so a shallow copy will do. */
    contact_t gone = *b.contact;
    uuid_t u;
    uuid_copy(u, b.contact->identity.uuid);
    (void)contacts_remove(&b.store, b.peer);
    _fc_book_save(proc, &b);
    bool dropped = identity_remove_direct_peer((process_t *)proc, queues, u) == 0;
    log_info(proc->logger, "Identity: first contact: removed %s%s\n",
             gone.petname, dropped ? " and dropped the direct peer" : "");
    gone.rendezvous = NULL;
    gone.rendezvous_count = 0;
    gone.identity.operator_key_binding = NULL;
    _fc_emit_contact(proc, AT_APP_EVENT_FC_REMOVED, b.ref, &gone, NULL,
                     AT_FC_METHOD_NONE, dropped, 0);
    _fc_book_close(&b);
    return true;
}

/****************************
 *  §10.3: an unverified contact may message, and no more, until verified
 ****************************/

static bool _fc_in_group(const group_t *grp, const char *key)
{
    data_t *unused = NULL;
    return grp != NULL
        && map_get((map_t *)&grp->address_map, (map_key_t)key, &unused) == 0;
}

/* In this node's group, or a child group it gateways: a group's vote admitted
 * them, and they are never capped. */
static bool _fc_in_a_child_group(const process_t *proc, const char *key)
{
    if (proc->protocol.child_groups == NULL)
        return false;
    bool found = false;
    map_key_t gkey = NULL;
    data_t *gval = NULL;
    map_entries_for_each(proc->protocol.child_groups, gkey, gval)
    {
        void *gp = NULL;
        if (!found && data_object_ptr(gval, &gp) == 0
            && _fc_in_group((const group_t *)gp, key))
            found = true;
    }
    map_end_for_each
    return found;
}

/* A peer's standing in contacts.cfg.json. */
typedef enum { FC_CONTACT_NONE, FC_CONTACT_UNVERIFIED, FC_CONTACT_VERIFIED } fc_contact_t;

/* Every recorded contact and whether it is verified, re-read only when
 * contacts.cfg.json changes (one stat on the usual call) -- the same guard
 * reputation's seed pass uses. */
static struct {
    pthread_mutex_t lock;
    char path[CFG_PATH_LEN + 64];
    struct timespec mtime;
    bool loaded;
    char (*uuids)[UUID_STRING_LEN + 1];
    bool *verified;
    size_t count;
} fc_records = { .lock = PTHREAD_MUTEX_INITIALIZER };

static fc_contact_t _fc_contact_status(const char *key)
{
    char dir[CFG_PATH_LEN + 1] = {0};
    char path[CFG_PATH_LEN + 64];
    if (get_data_dir(dir, sizeof(dir)) <= 0)
        return FC_CONTACT_NONE;
    snprintf(path, sizeof(path), "%s/%s", dir, AT_CONTACTS_FILENAME);
    struct stat st;
    bool present = stat(path, &st) == 0;

    pthread_mutex_lock(&fc_records.lock);
    bool stale = !fc_records.loaded || strcmp(fc_records.path, path) != 0
        || (present && (st.st_mtim.tv_sec != fc_records.mtime.tv_sec
                        || st.st_mtim.tv_nsec != fc_records.mtime.tv_nsec))
        || (!present && fc_records.count > 0);
    if (stale) {
        free(fc_records.uuids);
        free(fc_records.verified);
        fc_records.uuids = NULL;
        fc_records.verified = NULL;
        fc_records.count = 0;
        at_strlcpy(fc_records.path, path, sizeof(fc_records.path));
        memset(&fc_records.mtime, 0, sizeof(fc_records.mtime));
        if (present) {
            fc_records.mtime = st.st_mtim;
            contacts_t store;
            contacts_init(&store);
            (void)contacts_load(dir, &store);
            /* Every device of every contact (Phase 4). */
            size_t total = store.count;
            for (size_t i = 0; i < store.count; i++)
                total += store.items[i].devices_count;
            if (total > 0) {
                fc_records.uuids = calloc(total, sizeof(*fc_records.uuids));
                fc_records.verified = calloc(total, sizeof(*fc_records.verified));
                if (fc_records.uuids == NULL || fc_records.verified == NULL) {
                    free(fc_records.uuids);
                    free(fc_records.verified);
                    fc_records.uuids = NULL;
                    fc_records.verified = NULL;
                }
            }
            for (size_t i = 0; fc_records.uuids != NULL && i < store.count; i++) {
                uuid_unparse_lower(store.items[i].identity.uuid,
                                   fc_records.uuids[fc_records.count]);
                fc_records.verified[fc_records.count++] = store.items[i].verified;
                for (size_t d = 0; d < store.items[i].devices_count; d++) {
                    at_strlcpy(fc_records.uuids[fc_records.count],
                               store.items[i].devices[d].uuid,
                               sizeof(fc_records.uuids[0]));
                    fc_records.verified[fc_records.count++] = store.items[i].verified;
                }
            }
            contacts_free(&store);
        }
        fc_records.loaded = true;
    }
    fc_contact_t status = FC_CONTACT_NONE;
    for (size_t i = 0; i < fc_records.count && status == FC_CONTACT_NONE; i++)
        if (strcmp(fc_records.uuids[i], key) == 0)
            status = fc_records.verified[i] ? FC_CONTACT_VERIFIED
                                            : FC_CONTACT_UNVERIFIED;
    pthread_mutex_unlock(&fc_records.lock);
    return status;
}

int at_first_contact_capped_tier(const process_t *proc, const unsigned char *peer,
                                 int tier)
{
    if (proc == NULL || peer == NULL || tier <= AT_FC_UNVERIFIED_TIER_CAP
        || !at_first_contact_enabled())
        return tier;
    char key[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer, key);
    /* Own-group members: that group's vote admitted them. */
    if (_fc_in_group(&proc->protocol.group, key))
        return tier;
    fc_contact_t status = _fc_contact_status(key);
    if (status == FC_CONTACT_VERIFIED)
        return tier;
    /* One of our own devices (first_contact/sibling_sync.h). */
    if (at_sibling_is(key))
        return tier;
    /* A child-group member is capped only while on record as an UNVERIFIED
     * contact: the child's vote does not vouch for what first contact
     * introduced, and an ordinary child member never went through it. */
    if (status == FC_CONTACT_NONE && _fc_in_a_child_group(proc, key))
        return tier;
    return AT_FC_UNVERIFIED_TIER_CAP;
}


/****************************
 *  Reachability records (contacts/reach.h): ours, pushed and published;
 *  theirs, verified against the key we already hold and applied. Mirrors the
 *  record half of Python first_contact.
 ****************************/

#define AT_FC_REACH_STATE_FILENAME "reach.cfg.json"

static int _fc_reach_state_path(char *out, size_t out_len)
{
    char dir[CFG_PATH_LEN + 1] = {0};
    if (get_data_dir(dir, sizeof(dir)) <= 0)
        return -1;
    int n = snprintf(out, out_len, "%s/%s", dir, AT_FC_REACH_STATE_FILENAME);
    return (n < 0 || (size_t)n >= out_len) ? -1 : 0;
}

/* {seq, record} from var/at/reach.cfg.json (new reference), or NULL. */
static json_t *_fc_reach_state(void)
{
    char path[CFG_PATH_LEN + 64];
    if (_fc_reach_state_path(path, sizeof(path)) != 0)
        return NULL;
    json_t *st = json_load_file(path, 0, NULL);
    if (!json_is_object(st)) {
        json_decref(st);
        return NULL;
    }
    return st;
}

/* Our last issued record, if it is still valid, into @p out. */
static bool _fc_current_own_record(at_reach_record_t *out)
{
    json_t *st = _fc_reach_state();
    bool ok = st != NULL
        && at_reach_from_wire(json_object_get(st, "record"), out) == AT_REACH_OK;
    json_decref(st);
    if (ok && at_reach_verify(out, (double)time(NULL)) != AT_REACH_OK) {
        at_reach_free(out);
        ok = false;
    }
    return ok;
}

static bool _fc_same_strings(json_t *arr, char hints[][AT_RELAY_HOST_LEN + 96], size_t n)
{
    if (!json_is_array(arr) || json_array_size(arr) != n)
        return false;
    for (size_t i = 0; i < n; i++) {
        const char *v = json_string_value(json_array_get(arr, i));
        if (v == NULL || strcmp(v, hints[i]) != 0)
            return false;
    }
    return true;
}

/* Send our record to @p only, or to every contact that is a peer right now.
 * Over the sealed channel: each is a known peer. */
static void _fc_push_own_record(const process_t *proc, const public_identity_t *only)
{
    at_reach_record_t rec;
    if (proc == NULL || !_fc_current_own_record(&rec))
        return;
    json_t *wire = at_reach_to_wire(&rec);
    at_reach_free(&rec);
    if (wire == NULL)
        return;
    public_identity_t self;
    memset(&self, 0, sizeof(self));
    if (identity_own_public_identity(proc, &self) != 0) {
        json_decref(wire);
        return;
    }
    /* Who to tell: @p only, or the contacts we hold as peers. */
    public_identity_t targets[AT_FC_PENDING_MAX];
    size_t n = 0;
    if (only != NULL) {
        targets[n++] = *only;
    } else {
        char dir[CFG_PATH_LEN + 1] = {0};
        contacts_t store;
        contacts_init(&store);
        if (get_data_dir(dir, sizeof(dir)) > 0)
            (void)contacts_load(dir, &store);
        peers_read_lock(proc);
        for (size_t i = 0; i < store.count && n < AT_FC_PENDING_MAX; i++)
            for (size_t d = 0; d <= store.items[i].devices_count
                               && n < AT_FC_PENDING_MAX; d++) {
                /* Every device of the contact (Phase 4). */
                uuid_t who;
                if (d == 0)
                    uuid_copy(who, store.items[i].identity.uuid);
                else if (uuid_parse(store.items[i].devices[d - 1].uuid, who) != 0)
                    continue;
                for (size_t j = 0; j < proc->protocol.num_peers; j++)
                    if (uuid_compare(proc->protocol.peers[j].uuid, who) == 0) {
                        targets[n++] = proc->protocol.peers[j];
                        break;
                    }
            }
        peers_read_unlock(proc);
        contacts_free(&store);
        /* And our own devices (Phase 4). */
        at_siblings_t sib;
        at_siblings_init(&sib);
        if (get_data_dir(dir, sizeof(dir)) > 0)
            at_siblings_load(dir, &sib);
        for (size_t i = 0; i < sib.count && n < AT_FC_PENDING_MAX; i++) {
            uuid_t who;
            public_identity_t pub;
            if (uuid_parse(sib.devices[i].uuid, who) == 0
                && identity_find_peer_pub(proc, who, &pub)) {
                /* The binding is not needed to address it; drop it first so
                 * the copy owns nothing. */
                _free_public(&pub);
                targets[n++] = pub;
            }
        }
        at_siblings_free(&sib);
    }
    for (size_t i = 0; i < n; i++) {
        if (uuid_compare(targets[i].uuid, self.uuid) == 0)
            continue;
        generic_msg_t msg = {0};
        msg.type = NET_MESSAGE;
        at_strlcpy(msg.info.net_msg.process, "identity",
                   sizeof(msg.info.net_msg.process));
        msg.info.net_msg.function = FC_REACH_RECORD;
        msg.info.net_msg.encrypt = true;
        memcpy(&msg.info.net_msg.to_whom, &targets[i], sizeof(public_identity_t));
        memcpy(&msg.info.net_msg.from_whom, &self, sizeof(public_identity_t));
        at_strlcpy(msg.info.net_msg.return_to, "identity",
                   sizeof(msg.info.net_msg.return_to));
        net_msg_pack_json(&msg.info.net_msg, wire);
        (void)identity_send_to_network(proc, &msg, "first contact reachability record", NULL);
        net_msg_free_obj(&msg.info.net_msg);
    }
    json_decref(wire);
    _free_public(&self);
}

/* Issue a new record when what it states has changed, or when the one we have
 * is past half its life; push it to every contact that is a peer now and hand
 * it to the network process to file at our relays. With nothing new, the record
 * we have is handed on again (a restarted network process holds none). A relay
 * not yet re-proven this run keeps the pin our last record gave it. Mirrors
 * Python first_contact.refresh_own_record. */
void at_first_contact_refresh_own_record(const process_t *proc)
{
    if (proc == NULL || !at_first_contact_enabled())
        return;
    const identity_t *self = identity_self_identity(proc);
    if (self == NULL)
        return;
    at_reach_record_t current;
    bool have_current = _fc_current_own_record(&current);

    /* What our record states now. */
    net_relay_ep_t own[AT_RELAY_MAX];
    net_relay_pin_t own_cfg[AT_RELAY_MAX];
    size_t n_own = net_relay_own_hints(own, own_cfg, AT_RELAY_MAX);
    char relays[AT_RELAY_MAX][AT_RELAY_HOST_LEN + 96];
    const char *relay_ptrs[AT_RELAY_MAX];
    size_t n_relays = 0;
    for (size_t i = 0; i < n_own; i++) {
        fc_relay_t r = _fc_own_relay(&own[i], &own_cfg[i]);
        json_t *prev = have_current ? at_reach_relays(&current) : NULL;
        for (size_t k = 0; !r.pin.set && prev != NULL && k < json_array_size(prev); k++) {
            net_relay_ep_t pe;
            net_relay_pin_t pp;
            const char *h = json_string_value(json_array_get(prev, k));
            if (h != NULL && net_relay_parse_hint(h, pe.host, sizeof(pe.host),
                                                  &pe.port, &pp) == 0
                && pp.set && pe.port == r.ep.port && strcmp(pe.host, r.ep.host) == 0)
                r.pin = pp;
        }
        if (net_relay_hint_for_pinned(r.ep.host, r.ep.port, &r.pin, relays[n_relays],
                                      sizeof(relays[0])) == 0) {
            relay_ptrs[n_relays] = relays[n_relays];
            n_relays++;
        }
    }
    char endpoints[1][AT_RELAY_HOST_LEN + 96];
    const char *endpoint_ptrs[1];
    size_t n_endpoints = 0;
    if (self->address[0] != '\0') {
        at_strlcpy(endpoints[0], self->address, sizeof(endpoints[0]));
        endpoint_ptrs[0] = endpoints[0];
        n_endpoints = 1;
    }
    if (n_relays == 0 && n_endpoints == 0) {
        if (have_current)
            at_reach_free(&current);
        return;
    }
    long now = (long)time(NULL);
    bool fresh = have_current
        && _fc_same_strings(at_reach_relays(&current), relays, n_relays)
        && _fc_same_strings(at_reach_endpoints(&current), endpoints, n_endpoints)
        && (at_reach_expiry(&current) == 0
            || at_reach_expiry(&current) - now > AT_REACH_DEFAULT_TTL_SECONDS / 2);
    at_reach_record_t rec;
    if (fresh) {
        rec = current;
    } else {
        json_t *st = _fc_reach_state();
        int64_t seq = (st != NULL && json_is_integer(json_object_get(st, "seq"))
                       ? (int64_t)json_integer_value(json_object_get(st, "seq")) : 0) + 1;
        json_decref(st);
        if (have_current)
            at_reach_free(&current);
        if (at_reach_create(self, seq, relay_ptrs, n_relays, endpoint_ptrs,
                            n_endpoints, now + AT_REACH_DEFAULT_TTL_SECONDS,
                            &rec) != AT_REACH_OK)
            return;
        char path[CFG_PATH_LEN + 64];
        json_t *state = json_object();
        json_object_set_new(state, "seq", json_integer((json_int_t)seq));
        json_object_set_new(state, "record", at_reach_to_wire(&rec));
        char tmp[CFG_PATH_LEN + 80];
        char data_dir[CFG_PATH_LEN + 1] = {0};
        if (get_data_dir(data_dir, sizeof(data_dir)) > 0)
            (void)makedirs(data_dir, 0755);     /* a fresh root has no var/at yet */
        bool saved = _fc_reach_state_path(path, sizeof(path)) == 0
            && (size_t)snprintf(tmp, sizeof(tmp), "%s.tmp", path) < sizeof(tmp)
            && json_dump_file(state, tmp, JSON_COMPACT) == 0
            && rename(tmp, path) == 0;
        json_decref(state);
        if (!saved) {
            log_warn(proc->logger, "Identity: first contact: could not save our "
                     "reachability record; not publishing it\n");
            at_reach_free(&rec);
            return;
        }
        log_info(proc->logger, "Identity: first contact: our reachability is now "
                 "%zu relay(s), %zu endpoint(s) (record seq %lld)\n", n_relays,
                 n_endpoints, (long long)seq);
        at_reach_free(&rec);
        _fc_push_own_record(proc, NULL);
        if (!_fc_current_own_record(&rec))
            return;
    }
    json_t *wire = at_reach_to_wire(&rec);
    at_reach_free(&rec);
    generic_msg_t msg = {0};
    msg.type = NET_MESSAGE;
    at_strlcpy(msg.info.net_msg.process, "network", sizeof(msg.info.net_msg.process));
    msg.info.net_msg.function = NET_FN_REACH_PUBLISH;
    msg.info.net_msg.encrypt = false;
    net_msg_pack_json(&msg.info.net_msg, wire);
    json_decref(wire);
    (void)identity_send_to_network(proc, &msg, "first contact relay registration", NULL);
    net_msg_free_obj(&msg.info.net_msg);
}

/* A contact's reachability record: pushed by the contact itself (from_whom =
 * the contact), or handed on by our network process from a relay lookup (no
 * sender). Applied only if it verifies, its key is the key we hold for that
 * contact, and its seq is above any applied. Mirrors Python
 * first_contact.handle_reach_record. */
bool handle_first_contact_reach_record(const process_t *proc, directory_t *queues,
                                       generic_msg_t *msg)
{
    (void)queues;
    if (proc == NULL || msg == NULL)
        return true;
    net_msg_t *nmsg = &msg->info.net_msg;
    json_t *wire = NULL;
    at_reach_record_t rec;
    if (net_msg_unpack_json(nmsg, &wire) != 0
        || at_reach_from_wire(wire, &rec) != AT_REACH_OK) {
        json_decref(wire);
        log_warn(proc->logger, "Identity: first contact: reachability record "
                 "refused: malformed\n");
        return true;
    }
    json_decref(wire);
    int v = at_reach_verify(&rec, (double)time(NULL));
    if (v != AT_REACH_OK) {
        log_warn(proc->logger, "Identity: first contact: reachability record "
                 "refused: %s\n", v == AT_REACH_EXPIRED ? "record has expired"
                 : "signature does not match the record key");
        at_reach_free(&rec);
        return true;
    }
    const char *ru = at_reach_uuid(&rec), *rk = at_reach_key(&rec);
    uuid_t ruu;
    if (ru == NULL || rk == NULL || uuid_parse(ru, ruu) != 0) {
        at_reach_free(&rec);
        return true;
    }
    if (!uuid_is_null(nmsg->from_whom.uuid)
        && uuid_compare(nmsg->from_whom.uuid, ruu) != 0) {
        log_warn(proc->logger, "Identity: first contact: a peer pushed a record "
                 "for %.8s; refused\n", ru);
        at_reach_free(&rec);
        return true;
    }
    char dir[CFG_PATH_LEN + 1] = {0};
    if (get_data_dir(dir, sizeof(dir)) <= 0) {
        at_reach_free(&rec);
        return true;
    }
    contacts_t store;
    contacts_init(&store);
    (void)contacts_load(dir, &store);
    char us[UUID_STRING_LEN + 1];
    uuid_unparse(ruu, us);
    contact_t *c = contacts_get(&store, us);
    if (c == NULL && at_sibling_apply_record(proc, &rec)) {
        contacts_free(&store);
        at_reach_free(&rec);
        return true;
    }
    const char *why = NULL;
    if (c == NULL)
        why = "not a contact";
    else if (strcasecmp((const char *)c->identity.signature.public_hex, rk) != 0)
        why = "signed by another key";
    else if (at_reach_seq(&rec) <= c->reach_seq)
        why = "not newer";
    if (why != NULL) {
        if (c != NULL && strcmp(why, "not newer") != 0)
            log_warn(proc->logger, "Identity: first contact: record for %s %s; "
                     "refused\n", c->petname, why);
        contacts_free(&store);
        at_reach_free(&rec);
        return true;
    }
    /* Apply: the record's relays and endpoints ahead of what we had. */
    const char *fresh[AT_RELAY_MAX + AT_REACH_MAX_ENDPOINTS];
    size_t nf = 0;
    json_t *rv = at_reach_relays(&rec), *ev = at_reach_endpoints(&rec);
    for (size_t i = 0; rv != NULL && i < json_array_size(rv) && nf < AT_RELAY_MAX; i++)
        if (json_string_value(json_array_get(rv, i)) != NULL)
            fresh[nf++] = json_string_value(json_array_get(rv, i));
    size_t n_rec_relays = nf;
    for (size_t i = 0; ev != NULL && i < json_array_size(ev)
                       && nf < AT_RELAY_MAX + AT_REACH_MAX_ENDPOINTS; i++)
        if (json_string_value(json_array_get(ev, i)) != NULL)
            fresh[nf++] = json_string_value(json_array_get(ev, i));
    _fc_merge_hints(c, fresh, nf);
    c->reach_seq = at_reach_seq(&rec);
    if (contacts_save(&store, dir) != 0)
        log_warn(proc->logger, "Identity: first contact: could not persist "
                 "contacts (%s)\n", strerror(errno));
    /* Route: its relays, then ours. */
    fc_relay_t eps[AT_RELAY_MAX];
    size_t n = 0;
    for (size_t i = 0; i < c->rendezvous_count && n < AT_RELAY_MAX; i++) {
        fc_relay_t r;
        if (c->rendezvous[i] != NULL && _fc_is_relay_hint(c->rendezvous[i])
            && net_relay_parse_hint(c->rendezvous[i], r.ep.host, sizeof(r.ep.host),
                                    &r.ep.port, &r.pin) == 0)
            eps[n++] = r;
    }
    net_relay_ep_t own[AT_RELAY_MAX];
    net_relay_pin_t own_cfg[AT_RELAY_MAX];
    size_t n_own = net_relay_own_hints(own, own_cfg, AT_RELAY_MAX);
    for (size_t i = 0; i < n_own && n < AT_RELAY_MAX; i++) {
        bool dup = false;
        for (size_t k = 0; k < n && !dup; k++)
            dup = eps[k].ep.port == own[i].port && strcmp(eps[k].ep.host, own[i].host) == 0;
        if (!dup)
            eps[n++] = _fc_own_relay(&own[i], &own_cfg[i]);
    }
    _fc_send_relay_route(c->identity.uuid, eps, n);
    log_info(proc->logger, "Identity: first contact: %s is reachable via %zu "
             "relay(s) (record seq %lld)\n", c->petname, n_rec_relays,
             (long long)c->reach_seq);
    contacts_free(&store);
    at_reach_free(&rec);
    return true;
}


/****************************
 *  Shared with directory_contact.c (first_contact/fc_shared.h)
 ****************************/

bool at_fc_has_sender(const public_identity_t *who) { return _has_sender(who); }
void at_fc_free_public(public_identity_t *p) { _free_public(p); }
json_t *at_fc_app_payload(net_msg_t *nmsg) { return _fc_app_payload(nmsg); }
const char *at_fc_app_ref(const json_t *req) { return _fc_app_ref(req); }
void at_fc_remember_minted(const char *nonce, const char *ref)
{
    _fc_remember_minted(nonce, ref);
}
void at_fc_new_nonce(char out[33]) { _fc_new_nonce(out); }

void at_fc_emit_hello_sent(const process_t *proc, const char *ref,
                           const public_identity_t *peer)
{
    _fc_emit(proc, AT_APP_EVENT_FC_HELLO_SENT, ref, peer, AT_FC_REASON_NONE,
             AT_FC_ROLE_INITIATOR, 0, NULL);
}

size_t at_fc_own_hints(char out[][AT_RELAY_HOST_LEN + 96], size_t max)
{
    net_relay_ep_t own[AT_RELAY_MAX];
    net_relay_pin_t own_cfg[AT_RELAY_MAX];
    size_t n_own = net_relay_own_hints(own, own_cfg, AT_RELAY_MAX);
    size_t n = 0;
    for (size_t i = 0; i < n_own && n < max; i++) {
        fc_relay_t r = _fc_own_relay(&own[i], &own_cfg[i]);
        if (net_relay_hint_for_pinned(r.ep.host, r.ep.port, &r.pin, out[n],
                                      sizeof(out[0])) == 0)
            n++;
    }
    return n;
}

void at_fc_push_own_record(const process_t *proc, const public_identity_t *only)
{
    _fc_push_own_record(proc, only);
}

void at_fc_emit_device_linked(const process_t *proc, const contact_t *c,
                              const uuid_t device)
{
    at_fc_emit_device_linked_ref(proc, "", c, device);
}

void at_fc_emit_device_linked_ref(const process_t *proc, const char *ref,
                                  const contact_t *c, const uuid_t device)
{
    generic_msg_t msg = {0};
    msg.type = FIRST_CONTACT_CONTACT_EVENT;
    fc_contact_msg_t *m = AT_MSG_EXT(&msg, fc_contact_msg_t);
    m->kind = AT_APP_EVENT_FC_DEVICE_LINKED;
    at_strlcpy(m->data.ref, ref != NULL ? ref : "", sizeof(m->data.ref));
    memcpy(m->data.peer_uuid, c->identity.uuid, sizeof(m->data.peer_uuid));
    at_strlcpy(m->data.nickname, c->identity.nickname, sizeof(m->data.nickname));
    at_strlcpy(m->data.petname, c->petname, sizeof(m->data.petname));
    m->data.verified = c->verified;
    m->data.provenance = (int32_t)c->provenance;
    m->data.added_at = c->added_at;
    m->data.verified_at = c->verified_at;
    memcpy(m->data.device_uuid, device, sizeof(m->data.device_uuid));
    if (messaging_send(AT_MAIN_QUEUE, FIRST_CONTACT_CONTACT_EVENT, &msg, false) != 0)
        log_debug(proc->logger,
                  "Identity: first contact: no main queue for event %d\n", m->kind);
}

void at_fc_emit_event(const process_t *proc, int32_t kind, const char *ref,
                      const public_identity_t *peer, at_fc_reason_t reason,
                      at_fc_role_t role)
{
    _fc_emit(proc, kind, ref, peer, reason, role, 0, NULL);
}

void at_fc_emit_contact(const process_t *proc, int32_t kind, const char *ref,
                        const contact_t *c, bool dropped, int32_t origin)
{
    _fc_emit_contact_o(proc, kind, ref, c, NULL, AT_FC_METHOD_NONE, dropped, 0, origin);
}

void at_fc_emit_sibling(const process_t *proc, int32_t kind, const char *ref,
                        const char *uuid, const char *nickname, double added_at,
                        bool dropped, int32_t count)
{
    generic_msg_t msg = {0};
    msg.type = FIRST_CONTACT_CONTACT_EVENT;
    fc_contact_msg_t *m = AT_MSG_EXT(&msg, fc_contact_msg_t);
    m->kind = kind;
    at_strlcpy(m->data.ref, ref != NULL ? ref : "", sizeof(m->data.ref));
    uuid_t u;
    if (uuid != NULL && uuid_parse(uuid, u) == 0)
        memcpy(m->data.peer_uuid, u, sizeof(m->data.peer_uuid));
    if (nickname != NULL)
        at_strlcpy(m->data.nickname, nickname, sizeof(m->data.nickname));
    m->data.added_at = added_at;
    m->data.peer_dropped = dropped;
    m->data.count = count;
    if (messaging_send(AT_MAIN_QUEUE, FIRST_CONTACT_CONTACT_EVENT, &msg, false) != 0)
        log_debug(proc->logger,
                  "Identity: first contact: no main queue for event %d\n", kind);
}

void at_fc_send_route_hints(const uuid_t uuid, const char *const *hints, size_t n)
{
    fc_relay_t eps[AT_RELAY_MAX];
    size_t m = 0;
    for (size_t i = 0; i < n && m < AT_RELAY_MAX; i++)
        if (hints[i] != NULL
            && net_relay_parse_hint(hints[i], eps[m].ep.host, sizeof(eps[m].ep.host),
                                    &eps[m].ep.port, &eps[m].pin) == 0)
            m++;
    _fc_send_relay_route(uuid, eps, m);
}
