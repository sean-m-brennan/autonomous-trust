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

#include <jansson.h>

#include "config/configuration.h"
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

/* The configuration a node can carry that only an extension acts on: a
 * section file, the key that turns it on, and the extension that must be
 * present. Names only, as above. Without the extension the section is not even
 * registered, so load_all_configs skips the file as unknown and the node would
 * start enforcing nothing. */
static const struct { const char *section; const char *key; const char *ext;
                      const char *lib; } config_declarations[] = {
    { "zta_policy", "enabled", "zta", "libat_zta" },
};

int identity_ext_check_config(const char *cfg_dir, logger_t *logger)
{
    char dir[CFG_PATH_LEN + 1] = {0};
    if (cfg_dir == NULL) {
        if (get_cfg_dir(dir, sizeof(dir)) <= 0)
            return 0;
        cfg_dir = dir;
    }
    int rc = 0;
    for (size_t i = 0; i < sizeof(config_declarations) / sizeof(config_declarations[0]); i++) {
        if (identity_ext_present(config_declarations[i].ext))
            continue;
        char path[CFG_PATH_LEN + 64];
        snprintf(path, sizeof(path), "%s/%s.cfg.json", cfg_dir, config_declarations[i].section);
        json_t *root = json_load_file(path, 0, NULL);
        bool on = root != NULL && json_is_true(json_object_get(root, config_declarations[i].key));
        json_decref(root);
        if (!on)
            continue;
        log_error(logger, "Identity: %s enables %s, but %s is not loaded; refusing "
                          "to start rather than ignore it\n",
                  path, config_declarations[i].section, config_declarations[i].lib);
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

identity_ext_gate_t identity_ext_admission_gate(const process_t *proc, public_identity_t *peer,
                                                const uint8_t claimed_key[crypto_sign_PUBLICKEYBYTES])
{
    identity_ext_gate_t worst = IDENTITY_EXT_ADMIT;
    for (size_t i = 0; i < _exts_len; i++) {
        if (_exts[i]->admission_gate == NULL)
            continue;
        identity_ext_gate_t g = _exts[i]->admission_gate(proc, peer, claimed_key);
        if (g == IDENTITY_EXT_REJECT)
            return g;
        if (g > worst)
            worst = g;
    }
    return worst;
}

bool identity_ext_join_refused(const process_t *proc, const public_identity_t *new_id)
{
    for (size_t i = 0; i < _exts_len; i++)
        if (_exts[i]->join_refused != NULL && _exts[i]->join_refused(proc, new_id))
            return true;
    return false;
}

bool identity_ext_gateway_refused(const process_t *proc, const char *uuid_str)
{
    for (size_t i = 0; i < _exts_len; i++)
        if (_exts[i]->gateway_refused != NULL && _exts[i]->gateway_refused(proc, uuid_str))
            return true;
    return false;
}

bool identity_ext_operator_credential(const process_t *proc, const public_identity_t *claim)
{
    for (size_t i = 0; i < _exts_len; i++)
        if (_exts[i]->operator_credential != NULL
            && _exts[i]->operator_credential(proc, claim))
            return true;
    return false;
}

bool identity_ext_credential_anchored(const process_t *proc, const public_identity_t *carried)
{
    for (size_t i = 0; i < _exts_len; i++)
        if (_exts[i]->credential_anchored != NULL
            && _exts[i]->credential_anchored(proc, carried))
            return true;
    return false;
}
