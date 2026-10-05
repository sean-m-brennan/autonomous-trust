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

/** @file The backup app verbs (C twin of first_contact/backup_contact.py). See
 *  backup_contact.h. */

#define _GNU_SOURCE
#include "first_contact/backup_contact.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#include <jansson.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "first_contact/at_first_contact.h"
#include "config/configuration.h"
#include "first_contact/backup.h"
#include "first_contact/contacts.h"
#include "first_contact/device.h"
#include "first_contact/siblings.h"
#include "first_contact/sync.h"
#include "first_contact/device_contact.h"
#include "first_contact/fc_shared.h"
#include "first_contact/first_contact.h"
#include "identity/id_proc_priv.h"
#include "first_contact/sibling_sync.h"
#include "utilities/logger.h"
#include "utilities/message.h"
#include "utilities/msg_registry.h"
#include "utilities/util.h"
#include "utilities/send_retry.h"   /* at_send: keep a refused event */

static char FN_APP_BACKUP_EXPORT[] = AT_APP_BACKUP_EXPORT;
static char FN_APP_BACKUP_IMPORT[] = AT_APP_BACKUP_IMPORT;

typedef struct {
    const char *ref, *path, *passphrase;
    int reason;
    int32_t contacts, siblings, added, updated, removed;
} backup_ev_t;

static void _emit(const process_t *proc, int32_t kind, backup_ev_t e)
{
    generic_msg_t msg = {0};
    msg.type = FIRST_CONTACT_BACKUP_EVENT;
    fc_backup_msg_t *m = AT_MSG_EXT(&msg, fc_backup_msg_t);
    m->kind = kind;
    at_strlcpy(m->data.ref, e.ref != NULL ? e.ref : "", sizeof(m->data.ref));
    at_strlcpy(m->data.path, e.path != NULL ? e.path : "", sizeof(m->data.path));
    at_strlcpy(m->data.passphrase, e.passphrase != NULL ? e.passphrase : "",
               sizeof(m->data.passphrase));
    at_strlcpy(m->data.reason, at_backup_reason_str(e.reason), sizeof(m->data.reason));
    m->data.contacts = e.contacts;
    m->data.siblings = e.siblings;
    m->data.added = e.added;
    m->data.updated = e.updated;
    m->data.removed = e.removed;
    if (at_send(proc, AT_MAIN_QUEUE, &msg, "a backup event", "the app",
                AT_SEND_NOW, NULL, NULL, 0) != 0)
        log_debug(proc->logger, "Identity: backup: could not hand the app event %d\n", kind);
    sodium_memzero(m->data.passphrase, sizeof(m->data.passphrase));
}

static bool _refuse(const process_t *proc, const char *ref, int reason, const char *path)
{
    _emit(proc, AT_APP_EVENT_BACKUP_REFUSED,
          (backup_ev_t){ .ref = ref, .path = path, .reason = reason });
    return true;
}

/* The shared front half: local-only, a usable ref, an absolute path. NULL once
 * it has refused; else the request (caller decrefs) with *ref and *path. */
static json_t *_request(const process_t *proc, generic_msg_t *msg, const char *verb,
                        const char **ref, const char **path)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!identity_is_local_app_verb(proc, nmsg)) {
        (void)identity_refuse_remote_app_verb(proc, nmsg, verb);
        return NULL;
    }
    json_t *req = at_fc_app_payload(nmsg);
    *ref = at_fc_app_ref(req);
    if (*ref == NULL) {
        _refuse(proc, "", AT_BACKUP_BAD_REQUEST, "");
        json_decref(req);
        return NULL;
    }
    *path = json_string_value(json_object_get(req, "path"));
    if (*path == NULL || (*path)[0] != '/' || strlen(*path) >= AT_FC_PATH_LEN ||
        strlen(*path) != json_string_length(json_object_get(req, "path"))) {
        _refuse(proc, *ref, AT_BACKUP_BAD_REQUEST, "");
        json_decref(req);
        return NULL;
    }
    return req;
}

static bool _data_dir(char *dir, size_t len)
{
    return get_data_dir(dir, len) > 0;
}

/* Write @p text to @p path atomically, mode 0600: a temp beside it, then
 * rename. 0, or -1. */
static int _write_private(const char *path, const char *text)
{
    char tmp[AT_FC_PATH_LEN + 32];
    const char *slash = strrchr(path, '/');
    int dir_len = (int)(slash - path);
    if (snprintf(tmp, sizeof(tmp), "%.*s/.%s.XXXXXX", dir_len, path, slash + 1) >=
        (int)sizeof(tmp))
        return -1;
    int fd = mkstemp(tmp);          /* 0600 */
    if (fd < 0)
        return -1;
    size_t len = strlen(text), off = 0;
    while (off < len) {
        ssize_t w = write(fd, text + off, len - off);
        if (w < 0 && errno == EINTR)
            continue;
        if (w <= 0) {
            close(fd);
            unlink(tmp);
            return -1;
        }
        off += (size_t)w;
    }
    if (fsync(fd) != 0 || close(fd) != 0 || rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    (void)chmod(path, 0600);
    return 0;
}

/* The file's text, NUL-terminated (malloc'd), or NULL: unreadable, or larger
 * than any backup (*too_big). */
static char *_read_file(const char *path, bool *too_big)
{
    *too_big = false;
    FILE *fp = fopen(path, "rb");
    if (fp == NULL)
        return NULL;
    size_t cap = 2 * AT_BACKUP_CT_MAX + 1, n = 0, size = 4096;
    char *buf = malloc(size + 1);
    while (buf != NULL) {
        if (n == size) {
            if (size >= cap) {
                *too_big = true;
                break;
            }
            size = size * 2 < cap ? size * 2 : cap;
            char *grown = realloc(buf, size + 1);
            if (grown == NULL)
                break;
            buf = grown;
        }
        size_t got = fread(buf + n, 1, size - n, fp);
        n += got;
        if (got == 0) {
            bool err = ferror(fp) != 0;
            fclose(fp);
            if (err) {
                free(buf);
                return NULL;
            }
            if (n > 2 * AT_BACKUP_CT_MAX) {
                *too_big = true;
                free(buf);
                return NULL;
            }
            buf[n] = '\0';
            return buf;
        }
    }
    fclose(fp);
    free(buf);
    return NULL;
}

bool handle_app_backup_export(const process_t *proc, directory_t *queues,
                              generic_msg_t *msg)
{
    (void)queues;
    const char *ref = NULL, *path = NULL;
    json_t *req = _request(proc, msg, AT_APP_BACKUP_EXPORT, &ref, &path);
    if (req == NULL)
        return true;
    json_t *jgen = json_object_get(req, "generate");
    json_t *jpass = json_object_get(req, "passphrase");
    if (json_is_null(jpass))
        jpass = NULL;   /* as Python's req.get(): null is absent */
    bool generate = json_is_true(jgen);
    if (generate == (jpass != NULL) || (!generate && !json_is_string(jpass))) {
        _refuse(proc, ref, AT_BACKUP_BAD_REQUEST, path);
        json_decref(req);
        return true;
    }
    char code[AT_BACKUP_CODE_LEN + 1] = "";
    const char *passphrase = json_string_value(jpass);
    if (generate) {
        at_backup_generate_passphrase(code);
        passphrase = code;
    }
    char dir[CFG_PATH_LEN + 1] = {0};
    contacts_t store;
    at_siblings_t sib;
    contacts_init(&store);
    at_siblings_init(&sib);
    if (_data_dir(dir, sizeof(dir))) {
        (void)contacts_load(dir, &store);
        at_siblings_free(&sib);
        at_siblings_load(dir, &sib);
    }
    json_t *contents = at_backup_build_contents(&store, &sib, (double)time(NULL));
    char *text = NULL;
    int rc = contents != NULL ? at_backup_seal(contents, passphrase, &text)
                              : AT_BACKUP_MALFORMED;
    json_decref(contents);
    if (rc == AT_BACKUP_OK && _write_private(path, text) != 0) {
        log_warn(proc->logger, "Identity: first contact: backup not written to %s (%s)\n",
                 path, strerror(errno));
        rc = AT_BACKUP_IO;
    }
    free(text);
    if (rc != AT_BACKUP_OK) {
        _refuse(proc, ref, rc, path);
    } else {
        log_info(proc->logger, "Identity: first contact: backup of %zu contact(s), %zu "
                 "sibling(s) written\n", contacts_count(&store), sib.count);
        _emit(proc, AT_APP_EVENT_BACKUP_WRITTEN,
              (backup_ev_t){ .ref = ref, .path = path,
                             .passphrase = generate ? code : "",
                             .contacts = (int32_t)contacts_count(&store),
                             .siblings = (int32_t)sib.count });
    }
    sodium_memzero(code, sizeof(code));
    contacts_free(&store);
    at_siblings_free(&sib);
    json_decref(req);
    return true;
}

bool handle_app_backup_import(const process_t *proc, directory_t *queues,
                              generic_msg_t *msg)
{
    const char *ref = NULL, *path = NULL;
    json_t *req = _request(proc, msg, AT_APP_BACKUP_IMPORT, &ref, &path);
    if (req == NULL)
        return true;
    const char *passphrase = json_string_value(json_object_get(req, "passphrase"));
    if (passphrase == NULL) {
        _refuse(proc, ref, AT_BACKUP_BAD_REQUEST, path);
        json_decref(req);
        return true;
    }
    bool too_big = false;
    char *text = _read_file(path, &too_big);
    if (text == NULL) {
        if (!too_big)
            log_warn(proc->logger, "Identity: first contact: backup at %s unreadable\n",
                     path);
        _refuse(proc, ref, too_big ? AT_BACKUP_MALFORMED : AT_BACKUP_IO, path);
        json_decref(req);
        return true;
    }
    json_t *contents = NULL;
    int rc = at_backup_open_contents(text, passphrase, &contents);
    free(text);

    char dir[CFG_PATH_LEN + 1] = {0};
    bool have_dir = _data_dir(dir, sizeof(dir));
    contacts_t store, before;
    at_siblings_t sib;
    contacts_init(&store);
    contacts_init(&before);
    at_siblings_init(&sib);
    if (have_dir) {
        (void)contacts_load(dir, &store);
        (void)contacts_load(dir, &before);
        at_siblings_free(&sib);
        at_siblings_load(dir, &sib);
    }
    at_sync_change_t *ch = NULL;
    size_t n = 0, n_paired = 0;
    char (*paired)[UUID_STRING_LEN + 1] = NULL;
    if (rc == AT_BACKUP_OK) {
        at_dir_signed_t own;
        memset(&own, 0, sizeof(own));
        bool have_own = at_device_own_cert(proc, &own) == 0;
        char me[UUID_STRING_LEN + 1] = "";
        const identity_t *self = identity_self_identity(proc);
        if (self != NULL)
            uuid_unparse_lower(self->uuid, me);
        rc = at_backup_restore(&store, &sib, contents, have_own ? &own : NULL, me,
                               (double)time(NULL), &ch, &n, &paired, &n_paired);
        if (have_own)
            at_dir_free(&own);
    }
    json_decref(contents);
    if (rc != AT_BACKUP_OK) {
        log_info(proc->logger, "Identity: first contact: backup at %s refused (%s)\n",
                 path, at_backup_reason_str(rc));
        _refuse(proc, ref, rc, path);
    } else {
        if (n_paired > 0 && (!have_dir || at_siblings_save(&sib, dir) != 0))
            log_warn(proc->logger, "Identity: could not persist the sibling list\n");
        if (n > 0) {
            if (!have_dir || contacts_save(&store, dir) != 0)
                log_warn(proc->logger, "Identity: could not persist the contacts store\n");
            /* A local edit as far as our current siblings are concerned. */
            (void)at_sibling_push_changes(proc);
            at_sibling_apply_changes(proc, queues, &store, &before, ch, n,
                                     AT_FC_ORIGIN_BACKUP);
        }
        int32_t added = 0, updated = 0, removed = 0;
        for (size_t k = 0; k < n; k++) {
            if (ch[k].action == AT_SYNC_ADDED)
                added++;
            else if (ch[k].action == AT_SYNC_UPDATED)
                updated++;
            else if (ch[k].action == AT_SYNC_REMOVED)
                removed++;
        }
        log_info(proc->logger, "Identity: first contact: backup restored (%d added, %d "
                 "updated, %d removed, %zu sibling(s))\n", added, updated, removed,
                 n_paired);
        _emit(proc, AT_APP_EVENT_BACKUP_RESTORED,
              (backup_ev_t){ .ref = ref, .path = path,
                             .contacts = (int32_t)contacts_count(&store),
                             .siblings = (int32_t)n_paired, .added = added,
                             .updated = updated, .removed = removed });
    }
    free(ch);
    free(paired);
    contacts_free(&store);
    contacts_free(&before);
    at_siblings_free(&sib);
    json_decref(req);
    return true;
}

void at_backup_contact_register(process_t *proc)
{
    process_register_handler(proc, FN_APP_BACKUP_EXPORT,
                             (handler_ptr_t)handle_app_backup_export);
    process_register_handler(proc, FN_APP_BACKUP_IMPORT,
                             (handler_ptr_t)handle_app_backup_import);
}

/* The app may send these verbs, each only to identity. Python's
 * backup_contact.APP_VERBS. */
AT_APP_VERB_REGISTER(backup_export, AT_APP_BACKUP_EXPORT, "identity")
AT_APP_VERB_REGISTER(backup_import, AT_APP_BACKUP_IMPORT, "identity")
