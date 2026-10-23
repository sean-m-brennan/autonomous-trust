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
#include <unistd.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "group_file.h"
#include "identity_priv.h"
#include "config/configuration.h"
#include "config/discover.h"
#include "utilities/b64.h"

/* The type names ConfigJSONEncoder writes, which config_json_decoder resolves
 * by import path. */
static const char PY_GROUP[] = "autonomous_trust.core._python.identity.group.Group";
static const char PY_ENCRYPTOR[] = "autonomous_trust.core._python.identity.encrypt.Encryptor";
static const char PY_STEP[] = "autonomous_trust.core._python.structures.dag.LinkedStep";

/* {"__type__": type, "__value__": value}; steals @p value. */
static json_t *_tagged(const char *type, json_t *value)
{
    json_t *o = json_object();
    if (o == NULL)
    {
        json_decref(value);
        return NULL;
    }
    json_object_set_new(o, "__type__", json_string(type));
    json_object_set_new(o, "__value__", value);
    return o;
}

/* Python `bytes`: base64 of @p text's bytes. */
static json_t *_tagged_bytes(const char *text)
{
    size_t n = strlen(text);
    size_t cap = b64_encoded_len(n);
    char *enc = malloc(cap);
    if (enc == NULL)
        return NULL;
    base64_encode((const unsigned char *)text, n, enc, cap);
    json_t *out = _tagged("bytes", json_string(enc));
    free(enc);
    return out;
}

/* The text a tagged `bytes` value (or a plain string) carries, as a fresh
 * NUL-terminated string the caller frees, or NULL. */
static char *_untag_bytes(const json_t *v)
{
    if (json_is_string(v))
        return strdup(json_string_value(v));
    const char *enc = json_string_value(json_object_get((json_t *)v, "__value__"));
    if (enc == NULL)
        return NULL;
    size_t n = strlen(enc);
    char *out = calloc(n + 1, 1);
    if (out == NULL)
        return NULL;
    size_t got = 0;
    if (sodium_base642bin((unsigned char *)out, n, enc, n, NULL, &got, NULL,
                          sodium_base64_VARIANT_ORIGINAL) != 0)
    {
        free(out);
        return NULL;
    }
    out[got] = '\0';
    return out;
}

/* A tagged value's `__value__` string, or a plain string as is. Borrowed. */
static const char *_untag_string(const json_t *v)
{
    if (json_is_string(v))
        return json_string_value(v);
    return json_string_value(json_object_get((json_t *)v, "__value__"));
}

json_t *step_to_tagged_json(const linked_step_t *step)
{
    json_t *plain = linked_step_to_json(step);
    if (plain == NULL)
        return NULL;
    json_t *o = json_object();
    if (o == NULL)
    {
        json_decref(plain);
        return NULL;
    }
    json_object_set_new(o, "__type__", json_string(PY_STEP));
    const char *payload = json_string_value(json_object_get(plain, "payload"));
    json_object_set_new(o, "payload", payload != NULL ? _tagged_bytes(payload)
                                                      : json_null());
    json_object_set_new(o, "uuid", _tagged("UUID", json_string(
        json_string_value(json_object_get(plain, "uuid")))));
    const char *ts = json_string_value(json_object_get(plain, "timestamp"));
    if (ts != NULL)
        json_object_set_new(o, "timestamp", _tagged("datetime", json_string(ts)));
    json_decref(plain);
    return o;
}

int step_from_any_json(const json_t *obj, linked_step_t **step_out)
{
    if (!json_is_object(obj) || step_out == NULL)
        return EINVAL;
    if (!json_is_object(json_object_get((json_t *)obj, "uuid")))
        return linked_step_from_json(obj, step_out);
    /* Tagged: rebuild the plain form and parse that. */
    json_t *plain = json_object();
    if (plain == NULL)
        return ENOMEM;
    const char *uuid = _untag_string(json_object_get((json_t *)obj, "uuid"));
    const char *ts = _untag_string(json_object_get((json_t *)obj, "timestamp"));
    char *payload = NULL;
    json_t *pv = json_object_get((json_t *)obj, "payload");
    if (pv != NULL && !json_is_null(pv))
        payload = _untag_bytes(pv);
    if (uuid != NULL)
        json_object_set_new(plain, "uuid", json_string(uuid));
    if (ts != NULL)
        json_object_set_new(plain, "timestamp", json_string(ts));
    if (payload != NULL)
        json_object_set_new(plain, "payload", json_string(payload));
    free(payload);
    int rc = linked_step_from_json(plain, step_out);
    json_decref(plain);
    return rc;
}

json_t *group_to_tagged_json(const group_t *g)
{
    json_t *flat = NULL;
    if (g == NULL || group_to_json(g, &flat) != 0 || flat == NULL)
    {
        json_decref(flat);
        return NULL;
    }
    json_t *o = json_object();
    json_t *enc = json_object();
    if (o == NULL || enc == NULL)
    {
        json_decref(o);
        json_decref(enc);
        json_decref(flat);
        return NULL;
    }
    char uuid[UUID_STRING_LEN + 1];
    uuid_unparse_lower(g->uuid, uuid);
    json_t *flat_enc = json_object_get(flat, "encryptor");
    json_t *public_only = json_object_get(flat_enc, "public_only");
    const char *seed = json_string_value(json_object_get(flat_enc, "hex_seed"));
    json_object_set_new(enc, "__type__", json_string(PY_ENCRYPTOR));
    json_object_set_new(enc, "hex_seed", _tagged_bytes(seed != NULL ? seed : ""));
    json_object_set(enc, "public_only", public_only != NULL ? public_only : json_false());

    json_object_set_new(o, "__type__", json_string(PY_GROUP));
    json_object_set_new(o, "_uuid", json_string(uuid));
    json_object_set(o, "_address_map", json_object_get(flat, "address_map"));
    /* C keeps no group nickname; Python's is cosmetic. */
    json_object_set_new(o, "_nickname", json_string(""));
    json_object_set_new(o, "_encryptor", enc);
    json_object_set(o, "_public_only", public_only != NULL ? public_only : json_false());
    json_object_set(o, "_created", json_object_get(flat, "created"));
    json_object_set(o, "_key_epoch", json_object_get(flat, "key_epoch"));
    json_object_set(o, "_wire_format", json_object_get(flat, "wire_format"));
    json_decref(flat);
    return o;
}

int group_from_any_json(const json_t *obj, group_t *out)
{
    if (!json_is_object(obj) || out == NULL)
        return -1;
    memset(out, 0, sizeof(*out));
    if (json_object_get((json_t *)obj, "_uuid") == NULL)
        return group_from_json(obj, out) == 0 ? 0 : -1;
    /* Python's tagged form: rebuild the flat canonical form and parse that. */
    json_t *flat = json_object();
    json_t *enc = json_object();
    if (flat == NULL || enc == NULL)
    {
        json_decref(flat);
        json_decref(enc);
        return -1;
    }
    json_t *penc = json_object_get((json_t *)obj, "_encryptor");
    char *seed = _untag_bytes(json_object_get(penc, "hex_seed"));
    if (seed != NULL)
        json_object_set_new(enc, "hex_seed", json_string(seed));
    free(seed);
    json_t *po = json_object_get(penc, "public_only");
    json_object_set(enc, "public_only", po != NULL ? po : json_false());
    json_object_set(flat, "uuid", json_object_get((json_t *)obj, "_uuid"));
    json_t *amap = json_object_get((json_t *)obj, "_address_map");
    json_object_set_new(flat, "address_map", amap != NULL ? json_incref(amap)
                                                          : json_object());
    json_object_set_new(flat, "encryptor", enc);
    const char *keys[3][2] = { {"_created", "created"}, {"_key_epoch", "key_epoch"},
                               {"_wire_format", "wire_format"} };
    for (int i = 0; i < 3; i++)
    {
        json_t *v = json_object_get((json_t *)obj, keys[i][0]);
        if (v != NULL && !json_is_null(v))
            json_object_set(flat, keys[i][1], v);
    }
    int rc = group_from_json(flat, out) == 0 ? 0 : -1;
    json_decref(flat);
    return rc;
}

int group_file_path(char *out, size_t cap)
{
    char cfg_dir[CFG_PATH_LEN + 1] = {0};
    if (out == NULL || get_cfg_dir(cfg_dir, sizeof(cfg_dir)) < 0)
        return -1;
    int n = snprintf(out, cap, "%s/group%s", cfg_dir, CFG_FILE_EXT);
    return (n < 0 || (size_t)n >= cap) ? -1 : 0;
}

int group_file_write(const char *path, const group_t *g, json_t *steps)
{
    if (path == NULL || g == NULL)
        return -1;
    json_t *group = group_to_tagged_json(g);
    if (group == NULL)
        return -1;
    json_t *hist = json_object();
    json_object_set(hist, "step_dag", json_is_array(steps) ? steps : json_array());
    json_object_set_new(hist, "blacklist", json_array());
    json_t *doc = json_array();
    json_array_append_new(doc, group);
    json_array_append_new(doc, hist);
    /* Written whenever the group changes, and read at boot: write then
     * rename, so a reader never sees a half-written file (as Python's
     * atomic_write). */
    size_t tlen = strlen(path) + 8;
    char *tmp = malloc(tlen);
    int rc = -1;
    if (tmp != NULL)
    {
        snprintf(tmp, tlen, "%s.tmp", path);
        if (json_dump_file(doc, tmp, JSON_INDENT(2)) == 0 && rename(tmp, path) == 0)
            rc = 0;
        else
            unlink(tmp);
        free(tmp);
    }
    json_decref(doc);
    return rc;
}

int group_file_read(const char *path, group_t *g_out, json_t **steps_out)
{
    if (path == NULL || g_out == NULL || steps_out == NULL)
        return -1;
    *steps_out = NULL;
    json_error_t jerr;
    json_t *doc = json_load_file(path, 0, &jerr);
    if (doc == NULL)
        return -1;
    /* [group, history], or a bare group (a seeded gateway's file). */
    json_t *gj = json_is_array(doc) ? json_array_get(doc, 0) : doc;
    json_t *hj = json_is_array(doc) ? json_array_get(doc, 1) : NULL;
    if (group_from_any_json(gj, g_out) != 0)
    {
        json_decref(doc);
        return -1;
    }
    json_t *steps = json_object_get(hj, "step_dag");
    *steps_out = json_is_array(steps) ? json_incref(steps) : json_array();
    json_decref(doc);
    return 0;
}
