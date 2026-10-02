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

/** @file First contact: the 1:1 introduction primitive (C twin).
 *
 *  Byte-for-byte twin of Python autonomous_trust.core.contacts
 *  (FIRST_CONTACT_PLAN.md §4.0/§4.1/§4.4). This is the offline slice: the
 *  Contact record, out-of-band signed invitations, and safety-number
 *  verification. There is no directory and no relay here.
 *
 *  Wire discipline that MUST stay identical to Python (a conformance protocol
 *  pins it):
 *   - The invitation signature is a DETACHED 64-byte ed25519 signature
 *     (crypto_sign_detached / crypto_sign_verify_detached), transmitted hex --
 *     matching PyNaCl's SignedMessage.signature. NOT the combined-mode
 *     identity_sign/identity_verify.
 *   - The signed bytes are the exact canonical body string (sorted-key compact
 *     JSON); we verify the received bytes as-is, never a re-serialization.
 *   - The safety number is an iterated-blake2b fingerprint over PUBLIC key
 *     material only, the two per-identity fingerprints concatenated in sorted
 *     order so both parties derive the same string.
 */
#ifndef AUTONOMOUS_TRUST_CONTACTS_H
#define AUTONOMOUS_TRUST_CONTACTS_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <jansson.h>

#include "identity/identity.h"

/* --- constants (keep byte-identical to Python contacts) ------------------ */
#define AT_INVITATION_VERSION 1
#define AT_INVITATION_TYPENAME "at-invitation"
#define AT_INVITATION_URI_SCHEME "at+contact"
/* The `purpose` of an invitation one's own old device shows a new one: redeem
 * it to become its sibling (first_contact/siblings.h), not its contact. Signed
 * with the rest of the body; an ordinary invitation carries none. Python
 * invitation.PURPOSE_PAIR. */
#define AT_INVITATION_PURPOSE_PAIR "pair"

/* Reputation seed applied on the verified transition. One notch above the
 * cold-start neutral (0.2) and well below the ~0.5 near-trusted band -- see
 * Python FIRST_CONTACT_VERIFIED_SEED and reputation PREREP_NEUTRAL/COMM_CUTOFF. */
#define AT_FIRST_CONTACT_VERIFIED_SEED 0.3

#define AT_SAFETY_NUMBER_ITERATIONS 1024
#define AT_SAFETY_NUMBER_GROUPS 6          /* 5-digit groups PER identity */
#define AT_SAFETY_NUMBER_DOMAIN "at-safety-number-v1"
/* 12 groups of 5 digits + 11 spaces + NUL */
#define AT_SAFETY_NUMBER_LEN (2 * AT_SAFETY_NUMBER_GROUPS * 6)

#define AT_CONTACT_NONCE_MAX 64

/* --- Provenance ---------------------------------------------------------- */
typedef enum {
    AT_PROV_IN_PERSON = 0,   /* QR/blob exchanged face-to-face: no MITM possible */
    AT_PROV_TOKEN = 1,       /* signed invite link/code over a remote channel */
    AT_PROV_DIRECTORY = 2,   /* resolved via an opt-in directory (Phase 3) */
    AT_PROV_SIBLING = 3,     /* copied from another of this user's own devices (Phase 4) */
    AT_PROV_AREA = 4,        /* found at an (opt-in) area hub */
    AT_PROV_BACKUP = 5,      /* restored from an encrypted backup (Phase 4) */
} at_provenance_t;

const char *at_provenance_str(at_provenance_t p);

/* --- Devices (Phase 4, first_contact/device.h) ------------------------------- */
/** Most devices one contact lists besides its first. Same as Python's
 *  device.DEVICES_MAX. */
#define AT_CONTACT_DEVICES_MAX 8
#define AT_OPERATOR_KEY_HEX_LEN 64

/** One more device of a contact, each its own node. Kept in the canonical
 *  JSON forms it is stored in, so copying is a reference and nothing can
 *  drift from what is on disk. */
typedef struct {
    char uuid[UUID_STRING_LEN + 1];   /* lower case */
    json_t *identity;                 /* canonical public identity (owned) */
    json_t *cert;                     /* its device cert, {body, sig} (owned) */
    double added_at;
} at_contact_device_t;

/* --- Contact ------------------------------------------------------------- */
typedef struct {
    public_identity_t identity;   /* the trust root, public-only */
    char petname[NAME_LEN + 1];   /* local Zooko name; never on the wire */
    bool verified;                /* first-contact verification state (§4.4) */
    at_provenance_t provenance;
    double trust_seed;            /* 0.0 until verified, then the seed above */
    char nonce[AT_CONTACT_NONCE_MAX + 1];
    char **rendezvous;            /* last-known reachability hints (owned) */
    size_t rendezvous_count;
    double added_at;              /* epoch seconds */
    double verified_at;           /* epoch seconds, 0 until verified */
    /* The highest reachability-record seq applied (contacts/reach.h): a record
     * at or below it is a replay and is refused. Stored only once set. */
    int64_t reach_seq;
    /* Phase 4: the human's operator key (hex, "" until learned from a device
     * cert the first device presented) and the further devices it vouched for.
     * Both stored only once set, as Python does. */
    char operator_key[AT_OPERATOR_KEY_HEX_LEN + 1];
    at_contact_device_t *devices;     /* owned; devices_count of them */
    size_t devices_count;
    /* When the user last changed this record in a way their other devices
     * should copy (a rename, a device or operator link; first_contact/sync.h).
     * Adding and verifying are dated by added_at/verified_at already, so 0
     * until the first such edit, and stored only once set. */
    double updated_at;
} contact_t;

/** When @p c last changed for sync purposes: the latest of added_at,
 *  verified_at and updated_at. */
double contact_version(const contact_t *c);

/** Date an edit the user's other devices should copy, at @p now (epoch
 *  seconds; negative = the wall clock). Never moves the version back. */
void contact_touch(contact_t *c, double now);

/* Flip to verified, stamp verified_at, and seed the trust edge (idempotent). */
void contact_mark_verified(contact_t *c, double seed);

/* Release everything the contact owns (rendezvous list + the embedded public
 * identity's operator_key_binding). Safe on a zeroed contact. */
void contact_free(contact_t *c);

/* --- Invitation ---------------------------------------------------------- */
typedef enum {
    AT_INVITE_OK = 0,
    AT_INVITE_MALFORMED = -1,   /* bad base64/JSON, or not an AT invitation */
    AT_INVITE_BAD_SIG = -2,     /* signature does not match embedded identity */
    AT_INVITE_EXPIRED = -3,
} at_invite_status_t;

/* Parsed invitation. Owns the jansson envelope; body/body_str/sig_hex borrow it.
 * Free with at_invitation_free. */
typedef struct {
    json_t *envelope;        /* {"body": <str>, "sig": <hex>} */
    json_t *body;            /* parsed body object */
    const char *body_str;    /* the EXACT signed bytes (borrowed) */
    const char *sig_hex;     /* detached signature, hex (borrowed) */
} at_invitation_t;

/* Decode a base64url blob or at+contact: URI. Does NOT verify. */
int at_invitation_decode(const char *blob, at_invitation_t *out);
void at_invitation_free(at_invitation_t *inv);

/* Verify the detached signature against the embedded identity. On success fills
 * *ident_out (caller frees via contact_free-style or public identity teardown). */
int at_invitation_verify(const at_invitation_t *inv, public_identity_t *ident_out);

int at_invitation_is_expired(const at_invitation_t *inv, double now);

/* Full redeem: decode + verify + expiry-check + build a contact. `now` is epoch
 * seconds (compared only when the invitation carries a non-zero expiry). */
int at_redeem_invitation(const char *blob, bool in_person, double now,
                         contact_t *out);

/* Mint a signed invitation from *my* (signable) identity. `blob_out` is
 * malloc'd; caller frees. rendezvous is n_rv opaque strings (may be 0). */
int at_create_invitation(const identity_t *self,
                         const char *const *rendezvous, size_t n_rv,
                         long expiry, const char *nonce, char **blob_out);
/* at_create_invitation with a `purpose` (AT_INVITATION_PURPOSE_PAIR); NULL or
 * "" writes none. */
int at_create_invitation_purpose(const identity_t *self,
                                 const char *const *rendezvous, size_t n_rv,
                                 long expiry, const char *nonce,
                                 const char *purpose, char **blob_out);
/* The invitation's purpose, "" when it has none. Borrowed from @p inv. */
const char *at_invitation_purpose(const at_invitation_t *inv);

/* --- Safety number (§4.4) ------------------------------------------------ */
/* Symmetric 12-group safety number for the pair. Writes into `out`
 * (>= AT_SAFETY_NUMBER_LEN). Returns 0 on success. */
int at_safety_number(const public_identity_t *a, const public_identity_t *b,
                     char *out, size_t out_len);

/* Confirm a contact by comparing the presented safety number, then promote it.
 * Returns 0 on match (contact verified + seeded), AT_INVITE_BAD_SIG on
 * mismatch (contact left unverified). `presented` may contain arbitrary
 * whitespace. */
int at_verify_contact(contact_t *c, const char *presented,
                      const public_identity_t *my_identity);

/* --- Durable store ------------------------------------------------------- */
/* The cross-runtime address book. Persists as <data_dir>/contacts.cfg.json in
 * the DRY canonical form (Contact.identity via public_identity_to_json), so a
 * store written by the Python twin (first_contact/store.py) loads here and vice
 * versa. Not registered in the DEFINE_CONFIGURATION table -- it is standalone,
 * user-owned state the app loads explicitly, like the reputation store. */
#define AT_CONTACTS_TYPENAME "contacts"
#define AT_CONTACTS_VERSION 1
#define AT_CONTACTS_FILENAME "contacts.cfg.json"

/** A removed contact (Phase 4, first_contact/sync.h): the removal the user's other
 *  devices copy. Kept for good -- dropping one would let a device that was
 *  away long enough bring the contact back. */
typedef struct {
    char uuid[UUID_STRING_LEN + 1];   /* lower case */
    double at;                        /* when it was removed, epoch seconds */
} at_tombstone_t;

typedef struct {
    contact_t *items;   /* owned; each fully owned (deep) */
    size_t count;
    size_t cap;
    at_tombstone_t *tombstones;   /* owned; stored only once there is one */
    size_t tombstones_count;
    size_t tombstones_cap;
} contacts_t;

void contacts_init(contacts_t *store);
void contacts_free(contacts_t *store);
size_t contacts_count(const contacts_t *store);

/* Add or replace, keyed by identity uuid. Deep-copies `c` into the store; the
 * caller keeps ownership of its own copy. Adding a contact again undoes an
 * earlier removal of it (drops its tombstone). */
int contacts_add(contacts_t *store, const contact_t *c);
/** The contact @p uuid belongs to: its first device, or any further one. */
contact_t *contacts_get(contacts_t *store, const char *uuid);
/** The contact whose operator key @p operator_key is, or NULL. */
contact_t *contacts_by_operator(contacts_t *store, const char *operator_key);
contact_t *contacts_by_petname(contacts_t *store, const char *petname);
/** Drop the contact filed under @p uuid (its first device), with every
 *  device it lists, leaving a tombstone dated now. */
bool contacts_remove(contacts_t *store, const char *uuid);
/** contacts_remove, the tombstone dated @p at (never older than the version
 *  of what it removed, or an earlier tombstone of the same uuid). */
bool contacts_remove_at(contacts_t *store, const char *uuid, double at);
/** The contact filed under @p uuid as its FIRST device, or NULL (unlike
 *  contacts_get, a further device does not count). */
contact_t *contacts_get_first(contacts_t *store, const char *uuid);
/** When @p uuid was removed, or a negative value if it was not. */
double contacts_tombstone(const contacts_t *store, const char *uuid);
/** Record that @p uuid was removed at @p at, keeping the later of it and any
 *  tombstone already there. No contact is touched. 0, or -1 (no memory). */
int contacts_set_tombstone(contacts_t *store, const char *uuid, double at);
/** Whether @p v is a uuid in canonical lowercase text form. */
bool at_is_lower_uuid(const char *v);

/* Canonical (cross-runtime) JSON <-> struct. */
int contact_to_json(const contact_t *c, json_t **obj_out);
int contact_from_json(const json_t *obj, contact_t *out);
int contacts_to_json(const contacts_t *store, json_t **obj_out);
int contacts_from_json(const json_t *obj, contacts_t *store);

/* Load/save <data_dir>/contacts.cfg.json. A missing file yields an empty store
 * (not an error). Save mkdir -p's data_dir and writes atomically (temp+rename)
 * so a concurrent reader never sees a torn file. */
int contacts_load(const char *data_dir, contacts_t *store);
int contacts_save(const contacts_t *store, const char *data_dir);

#endif /* AUTONOMOUS_TRUST_CONTACTS_H */
