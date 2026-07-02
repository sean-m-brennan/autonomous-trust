/********************
 *  Copyright 2024 TekFive, Inc., Sean M. Brennan, and contributors
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

#define _DEFAULT_SOURCE
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdbool.h>

#include <jansson.h>

#define CONFIG_IMPL

#include "configuration_priv.h"
#include "structures/array.h"
#include "utilities/exception.h"
#include "utilities/logger.h"
#include "utilities/util.h"
#include "structures/map.h"
#include "config_table_priv.h"

#define MAX_CONFIGS 64

static const char *required_configs[] = {
    "subsystems", "network", "identity",
    "negotiation", "reputation",
};
static const int num_req_cfgs = 5;

const char ROOT_ENV_VAR[] = "AUTONOMOUS_TRUST_ROOT";

const char CFG_PATH[] = "etc/at";

const char DATA_PATH[] = "var/at";

const char *rootDir()
{
    const char *root = getenv(ROOT_ENV_VAR);
    if (root == NULL)
        root = "";
    return root;
}

/* Cached on first call; getenv is read-once for the process lifetime
 * (matches Python's class-attribute evaluation at module import). */
static int  _serialize_mode_cache = 0;  /* 0 = uninitialized */

at_serialize_mode_t at_serialize_mode_current(void)
{
    if (_serialize_mode_cache != 0)
        return (at_serialize_mode_t)_serialize_mode_cache;

    int mode = (int)AT_SERIALIZE_JSON;
    const char *env = getenv("AT_SERIALIZE_MODE");
    if (env != NULL && env[0] != '\0') {
        char *end = NULL;
        long v = strtol(env, &end, 10);
        if (end != NULL && *end == '\0' &&
            (v == AT_SERIALIZE_PROTO || v == AT_SERIALIZE_JSON || v == AT_SERIALIZE_PJSON))
            mode = (int)v;
    }
    _serialize_mode_cache = mode;
    return (at_serialize_mode_t)mode;
}

const char *at_serialize_mode_file_ext(at_serialize_mode_t mode)
{
    switch (mode) {
    case AT_SERIALIZE_PROTO: return ".cfg.pb";
    case AT_SERIALIZE_JSON:
    case AT_SERIALIZE_PJSON: return ".cfg.json";
    }
    return ".cfg.json";
}

/* Frama-C: skipped — get_data_dir / get_cfg_dir: path_join with assigns. */
int get_cfg_dir(char path[])
{
    return path_join(path, 255, rootDir(), CFG_PATH);
}

/* Frama-C: skipped — get_data_dir / get_cfg_dir: path_join with assigns. */
int get_data_dir(char path[])
{
    return path_join(path, 255, rootDir(), DATA_PATH);
}

/* Frama-C: skipped — find_configuration: 3x assigns + ensures. */
/*@
  requires name != \null && \valid_read(name);
  assigns \nothing;
  ensures \result == \null || \valid(\result);
*/
config_t *find_configuration(const char *name)
{
    for (size_t i = 0; i < configuration_table_size; i++)
    {
        config_t *entry = &configuration_table[i];
        if (strncmp(entry->name, name, strlen(name)) == 0)
            return entry;
    }
    return NULL;
}

/* Frama-C: skipped — num_config_files: terminates. */
int num_config_files(char path[])
{
    DIR *d = opendir(path);
    if (d == NULL)
        return SYS_EXCEPTION();
    int i = 0;
    while (true)
    {
        struct dirent *de = readdir(d);
        if (de == NULL)
            break;
        i++;
    }
    closedir(d);
    return i;
}

/* Frama-C: skipped —
 * all_config_files: readdir + strncpy/strlen/strcmp/strchr + string_data + set_exception
 * cascade.
 */
int all_config_files(char dir[], array_t *paths)
{
    DIR *d = opendir(dir);
    if (d == NULL)
        return SYS_EXCEPTION();
    int i = 0;
    while (true)
    {
        struct dirent *de = readdir(d);
        if (de == NULL)
            break;
        if (de->d_type == DT_REG || de->d_type == DT_UNKNOWN)
        {
            char *dot = strchr(de->d_name, '.');
            /* Accept all three legacy/current extensions regardless of
             * the env-var mode. A mode-switched node may still need to
             * read pre-existing files from before the switch. */
            if (dot && (!strcmp(dot, ".cfg.jsn") || !strcmp(dot, ".cfg.json")
                        || !strcmp(dot, ".cfg.pb")))
            {
                char *path = malloc(CFG_PATH_LEN + 1);
                if (path == NULL)
                    return SYS_EXCEPTION();
                strncpy(path, de->d_name, CFG_PATH_LEN);
                data_t *str_dat = string_data(path, strlen(path));
                int err = array_append(paths, str_dat);
                if (err != 0)
                    return err;
                i++;
            }
        }
    }
    closedir(d);
    return 0;
}

/* Frama-C: skipped —
 * [alloc-pattern] config_absolute_path: at_memcpy + strstr/strlen + 4x set_exception
 * cascade.
 */
int config_absolute_path(const char *path_in, char *path_out)
{
    if (path_in == NULL || path_out == NULL)
        return EXCEPTION(EINVAL);

    char cfg_dir[CFG_PATH_LEN + 1];
    int len = get_cfg_dir(cfg_dir);
    if (len < 0 || len > CFG_PATH_LEN)
        return -1;

    /* Reject traversal segments outright.  Legitimate config names never
     * contain "..", so a substring check is acceptable even though it
     * also rejects oddities like "foo..bar.cfg.json". */
    if (strstr(path_in, "..") != NULL)
    {
        log_info(NULL, "config_absolute_path: rejected traversal in '%s'\n", path_in);
        return EXCEPTION(EINVAL);
    }

    /* Absolute inputs must already sit inside cfg_dir.  Require that the
     * match is followed by '/' (or end of string) so "/etc/at_evil" is
     * NOT accepted as prefixed by "/etc/at". */
    if (path_in[0] == '/')
    {
        size_t dir_len = strlen(cfg_dir);
        if (strncmp(path_in, cfg_dir, dir_len) != 0 ||
            (path_in[dir_len] != '\0' && path_in[dir_len] != '/'))
        {
            log_info(NULL, "config_absolute_path: '%s' outside cfg_dir '%s'\n",
                     path_in, cfg_dir);
            return EXCEPTION(EINVAL);
        }
        size_t total = strlen(path_in);
        if (total > CFG_PATH_LEN)
            return EXCEPTION(EINVAL);
        memcpy(path_out, path_in, total + 1);   /* includes NUL */
        return 0;
    }

    /* Relative path: join under cfg_dir. */
    int remain = path_join(path_out, CFG_PATH_LEN, cfg_dir, path_in);
    if (remain < 0)
        return EXCEPTION(EINVAL);
    return 0;
}

/* Detect on-disk format from the filename extension. PROTO mode files
 * may live alongside JSON files in a mixed cfg dir during migration; the
 * extension is authoritative, NOT the AT_SERIALIZE_MODE env. */
static bool _filename_is_proto(const char *filename)
{
    if (filename == NULL) return false;
    size_t n = strlen(filename);
    return n >= 7 && strcmp(filename + n - 7, ".cfg.pb") == 0;
}

/* Read a .cfg.pb file. Looks up the config by basename (filename without
 * the extension) since binary protobuf carries no field equivalent to
 * JSON's "typename". @p data_struct is populated via the per-config
 * from_proto callback. */
static int _read_proto_config(const char *filename, void *data_struct)
{
    /* basename without extension */
    const char *slash = strrchr(filename, '/');
    const char *base = (slash != NULL) ? slash + 1 : filename;
    char cfg_name[CFG_NAME_SIZE + 1] = {0};
    const char *dot = strchr(base, '.');
    size_t n = (dot != NULL) ? (size_t)(dot - base) : strlen(base);
    if (n > CFG_NAME_SIZE) n = CFG_NAME_SIZE;
    memcpy(cfg_name, base, n);

    config_t *cfg = find_configuration(cfg_name);
    if (cfg == NULL || cfg->from_proto == NULL)
        return EXCEPTION(ECFG_NOIMPL);

    FILE *f = fopen(filename, "rb");
    if (f == NULL) return SYS_EXCEPTION();
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return EXCEPTION(ECFG_BADFMT); }
    uint8_t *buf = malloc((size_t)sz);
    if (buf == NULL) { fclose(f); return SYS_EXCEPTION(); }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) { free(buf); return EXCEPTION(ECFG_BADFMT); }

    int err = cfg->from_proto(buf, (size_t)sz, data_struct);
    free(buf);
    return err;
}

/* Frama-C: skipped —
 * [syscall] read_config_file: file I/O + strncpy + 3x set_exception + terminates_part
 * cascade.
 */
/*@
  requires filename != \null && \valid_read(filename);
  requires data_struct != \null && \valid(data_struct);
  behavior success:
    ensures \result == 0;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int read_config_file(const char *filename, void *data_struct)
{
    /* Dispatch by on-disk extension, NOT by the env-var mode. A node
     * configured for JSON may still need to read a leftover .cfg.pb
     * file (or vice versa) during an in-place mode migration. */
    if (_filename_is_proto(filename))
        return _read_proto_config(filename, data_struct);

    char typename[CFG_NAME_SIZE + 1] = {0};
    json_t *root = json_load_file(filename, 0, NULL);
    if (root == NULL)
        return EXCEPTION(ECFG_BADFMT);  // caller (load_config) logs the config name
    if (!json_is_object(root))
    {
        json_decref(root);
        return EXCEPTION(ECFG_BADFMT);
    }

    json_t *name_obj = json_object_get(root, "typename");
    if (name_obj == NULL || !json_is_string(name_obj))
    {
        json_decref(root);
        return EXCEPTION(ECFG_BADFMT);
    }
    strncpy(typename, json_string_value(name_obj), CFG_NAME_SIZE - 1);

    config_t *cfg = find_configuration(typename);
    if (cfg == NULL)
    {
        json_decref(root);
        return EXCEPTION(ECFG_NOIMPL);
    }

    int err = cfg->from_json(root, data_struct);
    json_decref(root); // frees created tree
    return err;
}

/*@
  requires \valid(cfg_obj);
  requires data_struct != \null && \valid_read(data_struct);
  requires filename != \null && \valid_read(filename);
  assigns \nothing;
  behavior success:
    ensures \result == 0;
  behavior failure:
    ensures \result != 0;
  disjoint behaviors;
*/
int write_config_file(const config_t *cfg_obj, const void *data_struct, const char *filename)
{
    /* Dispatch by on-disk extension so a path ending in `.cfg.pb` is
     * always written as protobuf regardless of the env-var mode (and a
     * `.cfg.json` path is always JSON). Callers that respect the global
     * mode build filenames via at_serialize_mode_file_ext(); ad-hoc
     * callers still get a coherent format. */
    if (_filename_is_proto(filename)) {
        if (cfg_obj->to_proto == NULL) {
            /* TODO (divergence.md H3 follow-up): no proto serializer is
             * wired for this config yet. The framework supports PROTO
             * mode; each `DECLARE_CONFIGURATION` call site needs its
             * `.to_proto` / `.from_proto` filled in to participate.
             * `processes/capabilities.c` already has `capability_to_proto`
             * / `peer_capabilities_to_proto` ready — exposing them
             * through this dispatch is the cheapest first wiring. Falling
             * back to JSON-with-renamed-extension would corrupt the
             * on-disk shape, so refuse instead. */
            return EXCEPTION(ECFG_NOIMPL);
        }
        void  *buf = NULL;
        size_t len = 0;
        int err = cfg_obj->to_proto(data_struct, &buf, &len);
        if (err != 0) return err;
        FILE *f = fopen(filename, "wb");
        if (f == NULL) { free(buf); return SYS_EXCEPTION(); }
        size_t wrote = fwrite(buf, 1, len, f);
        fclose(f);
        free(buf);
        if (wrote != len) return EXCEPTION(EJSN_DUMP);
        return 0;
    }

    json_t *root;
    int err = cfg_obj->to_json(data_struct, &root);
    if (err != 0)
        return err;

    err = json_dump_file(root, filename, 0);
    json_decref(root); // frees created tree
    if (err != 0)
        return EXCEPTION(EJSN_DUMP); // ECFG_BADFMT);
    return 0;
}

int load_all_configs(char *cfg_dir, map_t *configs, logger_t *logger)
{
    // read all other config files (peers, group, etc)
    if (map_init(configs) != 0)
    {
        log_exception(logger);
        return -1;
    }
    array_t config_files = {0};
    if (array_init(&config_files) != 0)
    {
        log_exception(logger);
        return -1;
    }
    if (all_config_files(cfg_dir, &config_files) != 0)
    {
        log_exception(logger);
        return -1;
    }
    int num_err = 0;
    int required = num_req_cfgs - 1;  // process tracker already loaded

    for (size_t i = 0; i < array_size(&config_files); i++)
    {
        data_t *str_dat;
        if (array_get(&config_files, i, &str_dat) != 0)
        {
            log_exception(logger);
            num_err++;
            continue;
        }
        char *filepath;
        if (data_string_ptr(str_dat, &filepath) != 0)
        {
            log_exception(logger);
            num_err++;
            continue;
        }

        config_t *config;
        char cfg_name[CFG_NAME_SIZE + 1] = {0};
        if (load_config(filepath, &config, cfg_name, logger) < 0)
            return -1;

        for (int j = 0; j < num_req_cfgs; j++)
        {
            if (strncmp(cfg_name, required_configs[j], CFG_NAME_SIZE) == 0)
            {
                required--;
                break;
            }
        }
        data_t *ds = object_ptr_data(config, sizeof(config_t));
        if (map_set(configs, cfg_name, ds) != 0)
        {
            log_exception(logger);
            num_err++;
        }
    }
    /* Python `load_configs` (discover.py:35-44) is lenient — it loads
     * whatever is present in the cfg dir without asserting required
     * names. Downgrade from error to warning so a minimal setup that
     * omits one of the standard configs doesn't surface as a hard
     * failure in C while passing on the Python side. Hard failures
     * still come from `num_err` (file-parse errors). Mirrors the
     * divergence.md M11 audit note. */
    if (required > 0)
        log_warn(logger, "%d required configurations not found\n", required);
    return num_err;
}

/* Frama-C: skipped —
 * [solver-timeout] load_config: 9x assigns + smrt_deref/smrt_create + at_memcpy + success
 * ensures + log_exception_extra precondition cascade.
 */
/*@
  requires filepath == \null || \valid_read(filepath);
  requires \valid(config_ptr);
  behavior null_path:
    assumes filepath == \null;
    ensures \result != 0;
  behavior success:
    assumes filepath != \null;
    ensures \result == 0 ==> *config_ptr != \null;
  disjoint behaviors;
*/
int load_config(char *filepath, config_t **config_ptr, char *cfg_name, logger_t *logger)
{
    if (filepath == NULL)
    {
        return EXCEPTION(EINVAL);
    }
    char abspath[CFG_PATH_LEN + 1];
    if (config_absolute_path(filepath, abspath) != 0)
    {
        return -1;
    }
    char *filename = strrchr(filepath, '/');
    if (filename == NULL)
        filename = filepath;

    if (strncmp(filename, default_tracker_filename, CFG_PATH_LEN) == 0)
        return 0; // skip tracker cfg, already loaded
    char *ext = strchr(filename, '.');
    int extlen = 0;
    if (ext != NULL)
        extlen = strlen(ext);
    char cfg_name_stack[CFG_NAME_SIZE + 1] = {0};
    if (cfg_name == NULL)
        cfg_name = cfg_name_stack;
    /* Cap at the DESTINATION size (CFG_NAME_SIZE), not CFG_PATH_LEN — the
     * latter is ~4x larger and was overflowing cfg_name for long basenames. */
    size_t copy = (size_t)(strlen(filename) - extlen);
    if (copy > CFG_NAME_SIZE)
        copy = CFG_NAME_SIZE;
    /* memcpy (not strncpy): `copy` is computed from src length, so there is
     * never a NUL inside the range; explicit NUL at [copy]. Avoids
     * -Wstringop-truncation false positive on length-from-source patterns. */
    memcpy(cfg_name, filename, copy);
    cfg_name[copy] = '\0';
    *config_ptr = find_configuration(cfg_name);
    config_t *config = *config_ptr;
    if (config == NULL)
    {
        log_error(logger, "No config for %s\n", cfg_name);
        return -1;
    }
    config->data_struct = smrt_create(config->data_len);
    if (config->data_struct == NULL)
        return EXCEPTION(ENOMEM);
    if (read_config_file(abspath, config->data_struct) != 0)
    {
        smrt_deref(config->data_struct);
        config->data_struct = NULL;
        log_exception_extra(logger, " for config named '%s'\n", cfg_name);
        return -1;
    }
    return 0;
}