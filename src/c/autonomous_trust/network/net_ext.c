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

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include <sodium.h>

#include "network/net_ext.h"
#include "utilities/util.h"

/* Filled by constructors before main(), then read-only, so unlocked -- as
 * processes/extension.c. */
static const net_ext_t *exts[NET_EXT_MAX];
static size_t n_exts = 0;

int net_ext_register(const net_ext_t *ext)
{
    if (ext == NULL || ext->name == NULL || ext->name[0] == '\0') {
        fprintf(stderr, "net_ext_register: refusing an unnamed extension\n");
        return -1;
    }
    if (net_ext_present(ext->name)) {
        fprintf(stderr, "net_ext_register: refusing %s: already registered\n",
                ext->name);
        return -1;
    }
    if (n_exts >= NET_EXT_MAX) {
        fprintf(stderr, "net_ext_register: refusing %s: registry full\n", ext->name);
        return -1;
    }
    exts[n_exts++] = ext;
    return 0;
}

bool net_ext_present(const char *name)
{
    if (name == NULL)
        return false;
    for (size_t i = 0; i < n_exts; i++)
        if (strcmp(exts[i]->name, name) == 0)
            return true;
    return false;
}

void net_ext_start(net_thread_ctx_t *ctx)
{
    for (size_t i = 0; i < n_exts; i++)
        if (exts[i]->start != NULL)
            exts[i]->start(ctx);
}

void net_ext_periodic(net_thread_ctx_t *ctx)
{
    for (size_t i = 0; i < n_exts; i++)
        if (exts[i]->periodic != NULL)
            exts[i]->periodic(ctx);
}

bool net_ext_local_verb(net_thread_ctx_t *ctx, net_msg_t *nmsg)
{
    for (size_t i = 0; i < n_exts; i++)
        if (exts[i]->local_verb != NULL && exts[i]->local_verb(ctx, nmsg))
            return true;
    return false;
}

bool net_ext_reachable(const uuid_t peer)
{
    for (size_t i = 0; i < n_exts; i++)
        if (exts[i]->reachable != NULL && exts[i]->reachable(peer))
            return true;
    return false;
}

int net_ext_unicast(const uuid_t peer, const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < n_exts; i++) {
        if (exts[i]->unicast == NULL)
            continue;
        int rc = exts[i]->unicast(peer, buf, len);
        if (rc != 1)
            return rc;
    }
    return 1;
}

/****************************
 *  Exclusions (C4)
 ****************************/

#define NET_MAX_EXCLUDED 256
#define NET_KEY_HEX_LEN (crypto_sign_PUBLICKEYBYTES * 2)

static struct {
    pthread_mutex_t lock;
    char uuids[NET_MAX_EXCLUDED][UUID_STR_LEN + 1];
    size_t n_uuids;
    char keys[NET_MAX_EXCLUDED][NET_KEY_HEX_LEN + 1];
    size_t n_keys;
} excl = { .lock = PTHREAD_MUTEX_INITIALIZER };

static int _find(char list[][NET_KEY_HEX_LEN + 1], size_t n, const char *v)
{
    for (size_t i = 0; i < n; i++)
        if (strcasecmp(list[i], v) == 0)
            return (int)i;
    return -1;
}

static int _find_uuid(const char *v)
{
    for (size_t i = 0; i < excl.n_uuids; i++)
        if (strcasecmp(excl.uuids[i], v) == 0)
            return (int)i;
    return -1;
}

void net_note_exclusion(const char *uuid, const char *pubkey_hex, bool excluded)
{
    uuid_t u;
    if (uuid == NULL || uuid_parse(uuid, u) != 0)
        return;
    char ul[UUID_STR_LEN + 1];
    uuid_unparse_lower(u, ul);
    bool have_key = pubkey_hex != NULL && pubkey_hex[0] != '\0'
                    && strlen(pubkey_hex) <= NET_KEY_HEX_LEN;
    pthread_mutex_lock(&excl.lock);
    if (excluded) {
        if (_find_uuid(ul) < 0 && excl.n_uuids < NET_MAX_EXCLUDED)
            at_strlcpy(excl.uuids[excl.n_uuids++], ul, sizeof(excl.uuids[0]));
        if (have_key && _find(excl.keys, excl.n_keys, pubkey_hex) < 0
            && excl.n_keys < NET_MAX_EXCLUDED)
            at_strlcpy(excl.keys[excl.n_keys++], pubkey_hex, sizeof(excl.keys[0]));
    } else {
        int i = _find_uuid(ul);
        if (i >= 0)
            memcpy(excl.uuids[i], excl.uuids[--excl.n_uuids], sizeof(excl.uuids[0]));
        i = have_key ? _find(excl.keys, excl.n_keys, pubkey_hex) : -1;
        if (i >= 0)
            memcpy(excl.keys[i], excl.keys[--excl.n_keys], sizeof(excl.keys[0]));
    }
    pthread_mutex_unlock(&excl.lock);
    for (size_t i = 0; i < n_exts; i++)
        if (exts[i]->exclusion != NULL)
            exts[i]->exclusion(ul, excluded);
}

bool net_is_excluded(const char *uuid, const char *pubkey_hex)
{
    pthread_mutex_lock(&excl.lock);
    bool bad = uuid != NULL && _find_uuid(uuid) >= 0;
    if (!bad && pubkey_hex != NULL && pubkey_hex[0] != '\0')
        bad = _find(excl.keys, excl.n_keys, pubkey_hex) >= 0;
    pthread_mutex_unlock(&excl.lock);
    return bad;
}

void net_exclusions_reset(void)
{
    pthread_mutex_lock(&excl.lock);
    excl.n_uuids = 0;
    excl.n_keys = 0;
    pthread_mutex_unlock(&excl.lock);
}
