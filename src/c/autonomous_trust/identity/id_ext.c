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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "identity/id_ext.h"
#include "identity/id_proc_priv.h"

static const identity_ext_t *_exts[IDENTITY_EXT_MAX];
static size_t _exts_len = 0;

int identity_ext_register(const identity_ext_t *ext)
{
    if (ext == NULL || ext->name == NULL || ext->name[0] == '\0') {
        fprintf(stderr, "identity_ext_register: refusing an unnamed extension\n");
        return -1;
    }
    for (size_t i = 0; i < _exts_len; i++)
        if (strcmp(_exts[i]->name, ext->name) == 0) {
            fprintf(stderr, "identity_ext_register: refusing %s: already registered\n",
                    ext->name);
            return -1;
        }
    if (_exts_len >= IDENTITY_EXT_MAX) {
        fprintf(stderr, "identity_ext_register: refusing %s: registry full\n",
                ext->name);
        return -2;
    }
    _exts[_exts_len++] = ext;
    /* A library loaded after identity initialized (dlopen) would otherwise
     * run on zeroed state until the next reset. */
    if (identity_state_initialized() && ext->init != NULL)
        ext->init();
    return 0;
}

bool identity_ext_present(const char *name)
{
    if (name == NULL)
        return false;
    for (size_t i = 0; i < _exts_len; i++)
        if (strcmp(_exts[i]->name, name) == 0)
            return true;
    return false;
}

/* The declarations a node's environment can make, and the extension that
 * must be present to honour each. Names only, as neg_oracle.c's table: the
 * core knows what a feature is called, never what it does, and an absent
 * feature cannot declare its own variables. */
static const struct { const char *env; const char *ext; const char *lib; } declarations[] = {
    { "AT_OWN_GEOHASH", "social", "libat_social" },
    { "AT_OWN_PROFILE", "social", "libat_social" },
};

int identity_ext_check_env(logger_t *logger)
{
    int rc = 0;
    for (size_t i = 0; i < sizeof(declarations) / sizeof(declarations[0]); i++) {
        const char *v = getenv(declarations[i].env);
        if (v == NULL || v[0] == '\0' || identity_ext_present(declarations[i].ext))
            continue;
        log_error(logger, "Identity: $%s is set, but %s is not loaded; refusing "
                          "to start rather than ignore it\n",
                  declarations[i].env, declarations[i].lib);
        rc = -1;
    }
    return rc;
}

void identity_ext_init(void)
{
    for (size_t i = 0; i < _exts_len; i++)
        if (_exts[i]->init != NULL)
            _exts[i]->init();
}

void identity_ext_reset(void)
{
    for (size_t i = 0; i < _exts_len; i++)
        if (_exts[i]->reset != NULL)
            _exts[i]->reset();
}

void identity_ext_run_start(process_t *proc)
{
    for (size_t i = 0; i < _exts_len; i++)
        if (_exts[i]->run_start != NULL)
            _exts[i]->run_start(proc);
}

void identity_ext_peer_confirmed(const process_t *proc, const public_identity_t *peer)
{
    for (size_t i = 0; i < _exts_len; i++)
        if (_exts[i]->peer_confirmed != NULL)
            _exts[i]->peer_confirmed(proc, peer);
}

void identity_ext_group_update_seen(const process_t *proc, const char *from_uuid_str,
                                    const char *their_group_uuid_str)
{
    for (size_t i = 0; i < _exts_len; i++)
        if (_exts[i]->group_update_seen != NULL)
            _exts[i]->group_update_seen(proc, from_uuid_str, their_group_uuid_str);
}

void identity_ext_periodic_resync(const process_t *proc)
{
    for (size_t i = 0; i < _exts_len; i++)
        if (_exts[i]->periodic_resync != NULL)
            _exts[i]->periodic_resync(proc);
}

bool identity_ext_roster_replay(const process_t *proc, int n_observed)
{
    bool logged = false;
    for (size_t i = 0; i < _exts_len; i++)
        if (_exts[i]->roster_replay != NULL)
            logged = _exts[i]->roster_replay(proc, n_observed) || logged;
    return logged;
}

bool identity_ext_peer_in_group(const process_t *proc, const char *uuid_str)
{
    for (size_t i = 0; i < _exts_len; i++)
        if (_exts[i]->peer_in_group != NULL && _exts[i]->peer_in_group(proc, uuid_str))
            return true;
    return false;
}

bool identity_ext_peer_blocked(const char *uuid_str)
{
    for (size_t i = 0; i < _exts_len; i++)
        if (_exts[i]->peer_blocked != NULL && _exts[i]->peer_blocked(uuid_str))
            return true;
    return false;
}
