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
 * config_proc_helpers.c — pure, dependency-free helper functions for config_proc.
 *
 * Kept in a separate translation unit so that unit tests can link only
 * config_proc_helpers.c without pulling in the full process/messaging
 * infrastructure that config_proc.c will depend upon.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sodium.h>
#include <jansson.h>

#include "fleet/config_proc.h"

/* ------------------------------------------------------------------ */
/* Static helper: copy a file byte-for-byte                            */
/* ------------------------------------------------------------------ */

static int copy_file(const char *src, const char *dst)
{
    FILE *in = fopen(src, "rb");
    if (!in) return -1;

    FILE *out = fopen(dst, "wb");
    if (!out) {
        fclose(in);
        return -1;
    }

    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) {
            fclose(in);
            fclose(out);
            return -1;
        }
    }

    int ret = ferror(in) ? -1 : 0;
    fclose(in);
    fclose(out);
    return ret;
}

/* ------------------------------------------------------------------ */
/* JSON serialization                                                  */
/* ------------------------------------------------------------------ */

json_t *config_proposal_to_json(const config_proposal_t *prop)
{
    json_t *obj = json_object();
    if (!obj) return NULL;

    json_object_set_new(obj, "config_name", json_string(prop->config_name));

    char hash_hex[UPDATE_HASH_LEN * 2 + 1];
    sodium_bin2hex(hash_hex, sizeof(hash_hex), prop->content_hash, UPDATE_HASH_LEN);
    json_object_set_new(obj, "content_hash", json_string(hash_hex));

    json_object_set_new(obj, "version", json_string(prop->version));

    char proposer_str[37];
    uuid_unparse_lower(prop->proposer_uuid, proposer_str);
    json_object_set_new(obj, "proposer_uuid", json_string(proposer_str));

    json_object_set_new(obj, "min_proposer_reputation", json_real(prop->min_proposer_reputation));

    char proposal_str[37];
    uuid_unparse_lower(prop->proposal_uuid, proposal_str);
    json_object_set_new(obj, "proposal_uuid", json_string(proposal_str));

    char sig_hex[UPDATE_SIG_LEN * 2 + 1];
    sodium_bin2hex(sig_hex, sizeof(sig_hex), prop->signature, UPDATE_SIG_LEN);
    json_object_set_new(obj, "signature", json_string(sig_hex));

    return obj;
}

int config_proposal_from_json(const json_t *json, config_proposal_t *prop)
{
    memset(prop, 0, sizeof(*prop));

    const char *config_name = json_string_value(json_object_get(json, "config_name"));
    const char *hash_hex = json_string_value(json_object_get(json, "content_hash"));
    const char *version = json_string_value(json_object_get(json, "version"));
    const char *proposer_str = json_string_value(json_object_get(json, "proposer_uuid"));
    json_t *j_rep = json_object_get(json, "min_proposer_reputation");
    const char *proposal_str = json_string_value(json_object_get(json, "proposal_uuid"));
    const char *sig_hex = json_string_value(json_object_get(json, "signature"));

    if (!config_name || !hash_hex || !version || !proposer_str ||
        !j_rep || !proposal_str || !sig_hex)
        return -1;

    strncpy(prop->config_name, config_name, CFG_NAME_SIZE);
    strncpy(prop->version, version, UPDATE_VERSION_LEN);
    prop->min_proposer_reputation = json_real_value(j_rep);

    if (sodium_hex2bin(prop->content_hash, UPDATE_HASH_LEN,
                       hash_hex, strlen(hash_hex), NULL, NULL, NULL) != 0)
        return -1;

    if (uuid_parse(proposer_str, prop->proposer_uuid) != 0)
        return -1;

    if (uuid_parse(proposal_str, prop->proposal_uuid) != 0)
        return -1;

    if (sodium_hex2bin(prop->signature, UPDATE_SIG_LEN,
                       sig_hex, strlen(sig_hex), NULL, NULL, NULL) != 0)
        return -1;

    return 0;
}

/* ------------------------------------------------------------------ */
/* Signing / verification                                              */
/* ------------------------------------------------------------------ */

static size_t build_config_signable(const config_proposal_t *prop, uint8_t *buf, size_t buflen)
{
    size_t offset = 0;
    size_t nlen = strlen(prop->config_name);

    if (offset + nlen > buflen) return 0;
    memcpy(buf + offset, prop->config_name, nlen);
    offset += nlen;

    if (offset + UPDATE_HASH_LEN > buflen) return 0;
    memcpy(buf + offset, prop->content_hash, UPDATE_HASH_LEN);
    offset += UPDATE_HASH_LEN;

    size_t vlen = strlen(prop->version);
    if (offset + vlen > buflen) return 0;
    memcpy(buf + offset, prop->version, vlen);
    offset += vlen;

    return offset;
}

int config_proposal_sign(config_proposal_t *prop, const uint8_t *sk)
{
    uint8_t msg[256];
    size_t msg_len = build_config_signable(prop, msg, sizeof(msg));
    if (msg_len == 0) return -1;

    unsigned long long sig_len;
    return crypto_sign_detached(prop->signature, &sig_len, msg, msg_len, sk);
}

int config_proposal_verify(const config_proposal_t *prop, const uint8_t *pk)
{
    uint8_t msg[256];
    size_t msg_len = build_config_signable(prop, msg, sizeof(msg));
    if (msg_len == 0) return -1;

    return crypto_sign_verify_detached(prop->signature, msg, msg_len, pk);
}

/* ------------------------------------------------------------------ */
/* Identity guard                                                      */
/* ------------------------------------------------------------------ */

bool config_is_identity(const char *config_name)
{
    if (!config_name || config_name[0] == '\0')
        return false;
    return strcmp(config_name, "identity") == 0;
}

/* ------------------------------------------------------------------ */
/* JSON validation                                                     */
/* ------------------------------------------------------------------ */

bool config_validate_json(const uint8_t *data, size_t len)
{
    json_error_t err;
    json_t *root = json_loadb((const char *)data, len, 0, &err);
    if (!root)
        return false;

    json_t *tn = json_object_get(root, "typename");
    bool valid = (tn != NULL && json_is_string(tn));

    json_decref(root);
    return valid;
}

/* ------------------------------------------------------------------ */
/* Backup / restore paths                                              */
/* ------------------------------------------------------------------ */

int config_backup_dir(const char *data_dir, char *buf, size_t buflen)
{
    return snprintf(buf, buflen, "%s/config_backup", data_dir) < (int)buflen ? 0 : -1;
}

int config_backup_all(const char *cfg_dir, const char *data_dir)
{
    char backup[512];
    if (config_backup_dir(data_dir, backup, sizeof(backup)) != 0)
        return -1;

    struct stat st;
    if (stat(backup, &st) != 0) {
        if (mkdir(backup, 0755) != 0 && errno != EEXIST)
            return -1;
    }

    DIR *d = opendir(cfg_dir);
    if (!d) return -1;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        size_t nlen = strlen(ent->d_name);
        if (nlen < 9) continue; /* minimum: "x.cfg.json" is 10 chars */
        if (strcmp(ent->d_name + nlen - 9, ".cfg.json") != 0)
            continue;

        char src[512], dst[512];
        snprintf(src, sizeof(src), "%s/%s", cfg_dir, ent->d_name);
        snprintf(dst, sizeof(dst), "%s/%s", backup, ent->d_name);
        if (copy_file(src, dst) != 0) {
            closedir(d);
            return -1;
        }
    }

    closedir(d);
    return 0;
}

int config_restore_all(const char *cfg_dir, const char *data_dir)
{
    char backup[512];
    if (config_backup_dir(data_dir, backup, sizeof(backup)) != 0)
        return -1;

    DIR *d = opendir(backup);
    if (!d) return -1;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        size_t nlen = strlen(ent->d_name);
        if (nlen < 9) continue;
        if (strcmp(ent->d_name + nlen - 9, ".cfg.json") != 0)
            continue;

        char src[512], dst[512];
        snprintf(src, sizeof(src), "%s/%s", backup, ent->d_name);
        snprintf(dst, sizeof(dst), "%s/%s", cfg_dir, ent->d_name);
        if (copy_file(src, dst) != 0) {
            closedir(d);
            return -1;
        }
    }

    closedir(d);
    return 0;
}

int config_backup_delete(const char *data_dir)
{
    char backup[512];
    if (config_backup_dir(data_dir, backup, sizeof(backup)) != 0)
        return -1;

    DIR *d = opendir(backup);
    if (!d) {
        if (errno == ENOENT)
            return 0; /* already absent is fine */
        return -1;
    }

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", backup, ent->d_name);
        unlink(path);
    }

    closedir(d);
    return rmdir(backup);
}
