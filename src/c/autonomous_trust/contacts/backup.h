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

#ifndef AT_CONTACTS_BACKUP_H
#define AT_CONTACTS_BACKUP_H

/**
 * @file backup.h
 * @brief An encrypted backup of the address book, for a lost device
 * (FIRST_CONTACT_PLAN Phase 4, recovery). C twin of Python
 * contacts/backup.py: same file, same checks in the same order, same reasons.
 *
 *     {typename: "at-backup", v: 1,
 *      kdf: "argon2id13", ops: 3, mem: 268435456, salt: <32 hex>,
 *      aead: "xchacha20poly1305-ietf", nonce: <48 hex>, ct: <base64>}
 *
 * The key is Argon2id (crypto_pwhash) over the passphrase and salt; ct is
 * XChaCha20-Poly1305 of the contents with at_backup_header_ad as associated
 * data. The contents:
 *
 *     {typename: "at-backup-contents", v: 1, created_at,
 *      contacts: <contacts/sync payload>, siblings: <siblings.cfg.json form>,
 *      operator_key?: <hex seed, put there only by tools/backup.py>}
 *
 * A restore merges (at_sync_merge_as, provenance AT_PROV_BACKUP) and adds the
 * backed-up siblings when our own device cert names the same operator. A
 * passphrase has at least AT_BACKUP_PASSPHRASE_MIN characters (UTF-8 code
 * points); one shaped like a generated code (six groups of four base32
 * characters split by '-' or ' ') is upper-cased with '-' separators before
 * the key is derived.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <jansson.h>

#include "contacts/contacts.h"
#include "contacts/directory.h"
#include "contacts/siblings.h"
#include "contacts/sync.h"

#define AT_BACKUP_TYPENAME "at-backup"
#define AT_BACKUP_CONTENTS_TYPENAME "at-backup-contents"
#define AT_BACKUP_VERSION 1
#define AT_BACKUP_KDF "argon2id13"
#define AT_BACKUP_AEAD "xchacha20poly1305-ietf"

/** What a backup is made with: libsodium's MODERATE. */
#define AT_BACKUP_OPS_DEFAULT 3ULL
#define AT_BACKUP_MEM_DEFAULT ((size_t)256 << 20)
/** What an open accepts, inclusive. */
#define AT_BACKUP_OPS_MIN 1ULL
#define AT_BACKUP_OPS_MAX 10ULL
#define AT_BACKUP_MEM_MIN ((size_t)8192)
#define AT_BACKUP_MEM_MAX ((size_t)1 << 30)

#define AT_BACKUP_SALT_BYTES 16
#define AT_BACKUP_NONCE_BYTES 24
#define AT_BACKUP_KEY_BYTES 32
#define AT_BACKUP_TAG_BYTES 16
/** The largest ciphertext an open reads. */
#define AT_BACKUP_CT_MAX ((size_t)16 << 20)

/** Shortest passphrase a backup is made with, in characters. */
#define AT_BACKUP_PASSPHRASE_MIN 12
/** A generated code: six groups of four and five dashes. */
#define AT_BACKUP_CODE_LEN 29

/** Why a seal, an open or a request failed. Same order as Python's
 *  backup_contact.REASONS, whose strings are these names in lower case. */
typedef enum {
    AT_BACKUP_OK = 0,
    AT_BACKUP_MALFORMED = 1,        /**< not a backup */
    AT_BACKUP_UNSUPPORTED = 2,      /**< another version/algorithm, or params out of range */
    AT_BACKUP_BAD_PASSPHRASE = 3,   /**< the open failed: wrong passphrase or a changed file */
    AT_BACKUP_WEAK_PASSPHRASE = 4,  /**< too short to make a backup with */
    AT_BACKUP_BAD_REQUEST = 5,      /**< the app's request itself (identity/backup_contact) */
    AT_BACKUP_IO = 6,               /**< the file could not be read or written */
} at_backup_reason_t;

/** "malformed", ..., "" for AT_BACKUP_OK. */
const char *at_backup_reason_str(int reason);

/** Override what a seal uses by default (tests: libsodium's minimum). Both 0
 *  restore AT_BACKUP_OPS_DEFAULT / AT_BACKUP_MEM_DEFAULT. */
void at_backup_set_default_params(unsigned long long ops, size_t mem);

/** A fresh 120-bit code, "XXXX-XXXX-XXXX-XXXX-XXXX-XXXX" (A-Z, 2-7). */
void at_backup_generate_passphrase(char out[AT_BACKUP_CODE_LEN + 1]);
/** What the key is derived from, into @p out (at least strlen(@p in) + 1). */
void at_backup_normalize_passphrase(const char *in, char *out, size_t len);
/** AT_BACKUP_OK, or AT_BACKUP_WEAK_PASSPHRASE. */
int at_backup_check_passphrase(const char *passphrase);

/** The associated data into @p out: "at-backup-v1|argon2id13|ops|mem|salt|
 *  xchacha20poly1305-ietf|nonce". @return its length, or -1. */
int at_backup_header_ad(unsigned long long ops, size_t mem, const char *salt_hex,
                        const char *nonce_hex, char *out, size_t len);

/** Encrypt @p pt into a backup object (*out, new reference). @p ops / @p mem
 *  0 = the defaults; @p salt / @p nonce NULL = random. An at_backup_reason_t. */
int at_backup_seal_bytes(const uint8_t *pt, size_t n, const char *passphrase,
                         unsigned long long ops, size_t mem, const uint8_t *salt,
                         const uint8_t *nonce, json_t **out);
/** The plaintext of @p blob (*pt malloc'd, *n its length). An
 *  at_backup_reason_t. */
int at_backup_open_bytes(const json_t *blob, const char *passphrase, uint8_t **pt,
                         size_t *n);
/** at_backup_open_bytes on the file's text (NUL-terminated). */
int at_backup_open_text(const char *text, const char *passphrase, uint8_t **pt,
                        size_t *n);

/** What a backup holds: the whole book and the siblings (omitted when none).
 *  New reference, or NULL. */
json_t *at_backup_build_contents(const contacts_t *store, const at_siblings_t *sib,
                                 double now);
/** The backup file's text for @p contents (*text malloc'd). An
 *  at_backup_reason_t. */
int at_backup_seal(const json_t *contents, const char *passphrase, char **text);
/** The contents of the backup @p text (*contents new reference). An
 *  at_backup_reason_t. */
int at_backup_open_contents(const char *text, const char *passphrase,
                            json_t **contents);

/** Fold opened @p contents into @p store and @p sib (may be NULL). The book's
 *  changes go to *changes / *n_changes (as at_sync_merge); the uuids added to
 *  @p sib to *paired (malloc'd, may be NULL) / *n_paired. Siblings are added
 *  only with @p own_cert (NULL: none). @p own_uuid may be NULL. An
 *  at_backup_reason_t (MALFORMED: the book is not a sync payload). */
int at_backup_restore(contacts_t *store, at_siblings_t *sib, const json_t *contents,
                      const at_dir_signed_t *own_cert, const char *own_uuid, double now,
                      at_sync_change_t **changes, size_t *n_changes,
                      char (**paired)[UUID_STRING_LEN + 1], size_t *n_paired);

#endif /* AT_CONTACTS_BACKUP_H */
