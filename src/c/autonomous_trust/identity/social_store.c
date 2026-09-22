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

#include <jansson.h>

#include "identity/social_store.h"
#include "structures/data.h"
#include "utilities/util.h"

static int _default_path(const char *cfg_dir, char *out, size_t out_len)
{
    int n = snprintf(out, out_len, "%s/%s", cfg_dir, AT_SOCIAL_FILENAME);
    return (n > 0 && (size_t)n < out_len) ? 0 : -1;
}

int social_store_load(const char *cfg_dir, map_t *blocks)
{
    if (blocks == NULL)
        return -1;
    map_free(blocks);
    map_init(blocks);
    if (cfg_dir == NULL)
        return -1;
    char path[4096];
    if (_default_path(cfg_dir, path, sizeof(path)) != 0)
        return -1;
    if (access(path, F_OK) != 0)
        return 0;   /* no file yet -> empty store, not an error */

    json_error_t err;
    json_t *root = json_load_file(path, 0, &err);
    if (root == NULL)
        return -1;
    json_t *j_blocks = json_object_get(root, "blocks");
    if (!json_is_object(j_blocks)) {
        json_decref(root);
        return -1;
    }
    /* The VERSION is read but not enforced: an older reader meeting a newer
     * document should keep the blocks it understands rather than discard
     * somebody's moderation state over a number. A shape it cannot parse at
     * all is what the checks above already refuse. */
    const char *uuid_str;
    json_t *entry;
    json_object_foreach(j_blocks, uuid_str, entry) {
        double at = 0.0;
        if (json_is_object(entry)) {
            json_t *j_at = json_object_get(entry, "at");
            if (json_is_number(j_at))
                at = json_number_value(j_at);
        }
        data_t *dat = floating_pt_dbl_data(at);
        if (dat != NULL)
            map_set(blocks, (map_key_t)uuid_str, dat);
    }
    json_decref(root);
    return 0;
}

int social_store_save(const map_t *blocks, const char *cfg_dir)
{
    if (blocks == NULL || cfg_dir == NULL)
        return -1;
    char path[4096];
    if (_default_path(cfg_dir, path, sizeof(path)) != 0)
        return -1;

    json_t *j_blocks = json_object();
    if (j_blocks == NULL)
        return -1;
    map_key_t key = NULL;
    data_t *val = NULL;
    map_entries_for_each((map_t *)blocks, key, val)
    {
        double at = 0.0;
        if (val != NULL)
            (void)data_floating_pt_dbl(val, &at);
        /* `reason` is written empty and always present: the field has no
         * producer yet (no UI collects one), but a key that appears only
         * sometimes would make the two runtimes' files differ by whether
         * anyone had typed something. The shape is the contract. */
        json_t *entry = json_pack("{s:o, s:s}",
                                  "at", json_real(at),
                                  "reason", "");
        if (entry != NULL)
            json_object_set_new(j_blocks, key, entry);
    }
    map_end_for_each

    json_t *doc = json_pack("{s:i, s:o}",
                            "version", AT_SOCIAL_STORE_VERSION,
                            "blocks", j_blocks);
    if (doc == NULL) {
        json_decref(j_blocks);
        return -1;
    }

    /* Atomic write: dump to a temp sibling, then rename over the target, so a
     * concurrent reader — or a crash — never sees a torn social.cfg.json.
     * rename(2) is atomic within a filesystem, and the temp sits beside the
     * target so they are always on the same one. Copied from contacts_save,
     * which is the house pattern for this. */
    char tmp[4096 + 16];
    snprintf(tmp, sizeof(tmp), "%s.tmp%d", path, (int)getpid());
    /* SORT_KEYS is not cosmetic: the Python twin writes the same document with
     * sort_keys=True, and test/social_store_test.c pins the exact bytes
     * against the identical golden string in tests/a_unit/test_social_store.py.
     * Map iteration order is not a contract; sorted order is. */
    int rc = json_dump_file(doc, tmp, JSON_INDENT(2) | JSON_SORT_KEYS);
    json_decref(doc);
    if (rc != 0) {
        unlink(tmp);
        return -1;
    }
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}
