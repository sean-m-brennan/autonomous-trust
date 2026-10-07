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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE  /* dladdr */
#endif
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include <sodium.h>

#include "config/configuration.h"
#include "package_hash.h"

static char g_hash[AT_PACKAGE_HASH_LEN + 1];
static pthread_once_t g_once = PTHREAD_ONCE_INIT;

/* blake2b-256 of @p path into "c:<hex>"; leaves g_hash empty on failure. */
static void _hash_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL)
        return;
    crypto_generichash_state st;
    unsigned char buf[65536];
    unsigned char out[32];
    size_t n;
    bool ok = crypto_generichash_init(&st, NULL, 0, sizeof(out)) == 0;
    while (ok && (n = fread(buf, 1, sizeof(buf), f)) > 0)
        ok = crypto_generichash_update(&st, buf, n) == 0;
    ok = ok && !ferror(f) && crypto_generichash_final(&st, out, sizeof(out)) == 0;
    fclose(f);
    if (!ok)
        return;
    char hex[sizeof(out) * 2 + 1];
    sodium_bin2hex(hex, sizeof(hex), out, sizeof(out));
    snprintf(g_hash, sizeof(g_hash), "c:%s", hex);
}

static void _compute(void)
{
    if (sodium_init() < 0)
        return;
    /* The object holding this very function: libautonomous_trust.so, or the
     * executable a static build is linked into. dli_fname is the path the
     * loader used, which for the main program can be a bare argv[0], so that
     * case reads /proc/self/exe instead. */
    Dl_info info;
    if (dladdr((void *)&at_package_hash, &info) != 0 && info.dli_fname != NULL
        && strchr(info.dli_fname, '/') != NULL)
        _hash_file(info.dli_fname);
    if (g_hash[0] == '\0')
        _hash_file("/proc/self/exe");
}

const char *at_package_hash(void)
{
    pthread_once(&g_once, _compute);
    return g_hash;
}

void at_package_hash_of_json(const json_t *slot, char *out, size_t cap)
{
    if (out == NULL || cap == 0)
        return;
    out[0] = '\0';
    if (json_is_string(slot))
    {
        snprintf(out, cap, "%s", json_string_value(slot));
        return;
    }
    const char *type = json_string_value(json_object_get(slot, "__type__"));
    const char *b64 = json_string_value(json_object_get(slot, "__value__"));
    if (type == NULL || strcmp(type, "bytes") != 0 || b64 == NULL)
        return;
    unsigned char raw[256];
    size_t len = 0;
    if (sodium_base642bin(raw, sizeof(raw) - 1, b64, strlen(b64), NULL, &len,
                          NULL, sodium_base64_VARIANT_ORIGINAL) != 0)
        return;
    raw[len] = '\0';
    /* Python's digest is hex ASCII already; anything else is not a hash. */
    for (size_t i = 0; i < len; i++)
        if (!((raw[i] >= '0' && raw[i] <= '9') || (raw[i] >= 'a' && raw[i] <= 'f')))
            return;
    snprintf(out, cap, "py:%s", (const char *)raw);
}

bool at_package_hash_listed(const json_t *allowlist, const char *tagged)
{
    if (tagged == NULL || tagged[0] == '\0')
        return false;
    size_t len = strlen(tagged);
    size_t i;
    json_t *v;
    json_array_foreach(json_object_get(allowlist, "accepted"), i, v)
    {
        const char *s = json_string_value(v);
        if (s != NULL && strlen(s) == len && sodium_memcmp(s, tagged, len) == 0)
            return true;
    }
    return false;
}

bool at_package_hash_admissible(const char *tagged, char *why, size_t why_cap)
{
    char cfg_dir[CFG_PATH_LEN + 1] = {0};
    if (get_cfg_dir(cfg_dir, sizeof(cfg_dir)) < 0)
        return true;
    char path[CFG_PATH_LEN + 64];
    snprintf(path, sizeof(path), "%s/%s", cfg_dir, AT_PACKAGE_HASHES_FILE);
    FILE *probe = fopen(path, "r");
    if (probe == NULL)
        return true;  /* no allowlist: the gate is off */
    fclose(probe);
    json_t *doc = json_load_file(path, 0, NULL);
    bool ok = json_is_object(doc) && at_package_hash_listed(doc, tagged);
    json_decref(doc);
    if (!ok && why != NULL && why_cap > 0)
        snprintf(why, why_cap, "package hash %.10s not on the allowlist",
                 (tagged != NULL && tagged[0] != '\0') ? tagged : "(none)");
    return ok;
}
