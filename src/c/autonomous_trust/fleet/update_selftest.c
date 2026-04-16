/********************
 *  Copyright 2025 Sean M. Brennan and contributors
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

/**
 * update_selftest.c — pure self-test functions for verifying binary health
 * after an in-place update.
 */

#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sodium.h>
#include <jansson.h>

#include "fleet/update_proc.h"

/* Frama-C: skipped — [syscall] file I/O + JSON parsing */
bool selftest_identity(const char *cfg_dir)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/identity.cfg.json", cfg_dir);

    /* If file doesn't exist, that's not a binary problem */
    FILE *f = fopen(path, "r");
    if (!f)
        return true;
    fclose(f);

    /* File exists — try to parse it */
    json_error_t err;
    json_t *root = json_load_file(path, 0, &err);
    if (!root)
        return false;

    json_decref(root);
    return true;
}

/* Frama-C: skipped — [syscall] file I/O + crypto operations */
bool selftest_crypto(void)
{
    if (sodium_init() < -1)
        return false;

    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    if (crypto_sign_keypair(pk, sk) != 0)
        return false;

    const char *msg = "autonomous_trust_selftest";
    size_t msg_len = strlen(msg);

    unsigned char sig[crypto_sign_BYTES];
    if (crypto_sign_detached(sig, NULL, (const unsigned char *)msg, msg_len, sk) != 0)
        return false;

    if (crypto_sign_verify_detached(sig, (const unsigned char *)msg, msg_len, pk) != 0)
        return false;

    return true;
}

/* Frama-C: skipped — [syscall] file I/O + directory traversal */
bool selftest_config(const char *cfg_dir)
{
    DIR *d = opendir(cfg_dir);
    if (!d)
        return true;  /* dir doesn't exist — not a binary problem */

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        const char *name = ent->d_name;
        size_t len = strlen(name);

        /* Check for .cfg.json suffix */
        const char *suffix = ".cfg.json";
        size_t suf_len = strlen(suffix);
        if (len < suf_len)
            continue;
        if (strcmp(name + len - suf_len, suffix) != 0)
            continue;

        char path[512];
        snprintf(path, sizeof(path), "%s/%s", cfg_dir, name);

        json_error_t err;
        json_t *root = json_load_file(path, 0, &err);
        if (!root) {
            closedir(d);
            return false;
        }
        json_decref(root);
    }

    closedir(d);
    return true;
}
