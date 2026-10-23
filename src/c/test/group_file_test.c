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

/** @file group.cfg.json in Python's schema (RD_14.4 plan, D10).
 *
 *  C had no group persistence, so a restarted C node could not rejoin its own
 *  group. It now writes Python's file and reads either runtime's (the user's
 *  call, 2026-10-23). PY_FILE below was written by Python's
 *  ConfigJSONEncoder; tests/a_unit/test_choose_group.py reads C_FILE's shape
 *  back. Steps are pinned in both of their wire forms: Python's tagged
 *  LinkedStep (also what `history_diff` carries) and C's plain one.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <jansson.h>
#include <sodium.h>
#include <uuid/uuid.h>

#include "identity/group.h"
#include "identity/group_file.h"
#include "identity/history.h"
#include "identity/identity_priv.h"

/* Written by Python (json.dumps((group, history.to_dict()), cls=ConfigJSONEncoder)). */
static const char PY_FILE[] =
    "[{\"__type__\":\"autonomous_trust.core._python.identity.group.Group\","
    "\"_uuid\":\"4b664af2-7120-4e41-bb35-627c55362965\","
    "\"_address_map\":{\"11111111-1111-4111-8111-111111111111\":\"10.0.0.1\"},"
    "\"_nickname\":\"grp\",\"_encryptor\":{\"__type__\":"
    "\"autonomous_trust.core._python.identity.encrypt.Encryptor\",\"hex_seed\":"
    "{\"__type__\":\"bytes\",\"__value__\":\"NmFmODIzOTU1MGU1MjQ1NmIxYzU4OGI3ZWFjMGJhM2Nj"
    "NTg4MTcyNjQ3YjMxMDQ3ZTE0NjBjYWY5MDkzOThkNw==\"},\"public_only\":false},"
    "\"_public_only\":false,\"_created\":1792721083.067064,\"_key_epoch\":0,"
    "\"_wire_format\":\"json\"},{\"step_dag\":[{\"__type__\":"
    "\"autonomous_trust.core._python.structures.dag.LinkedStep\",\"payload\":"
    "{\"__type__\":\"bytes\",\"__value__\":\"YWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJh"
    "YmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYmFiYWJhYg==\"},\"uuid\":{\"__type__\":\"UUID\","
    "\"__value__\":\"a0d8104b-ed19-405b-a3fe-58ef942ac0b7\"},\"timestamp\":"
    "{\"__type__\":\"datetime\",\"__value__\":\"2026-10-23T02:04:43.067288+00:00\"}}],"
    "\"blacklist\":[]}]";

static const char SEED[] = "6af8239550e52456b1c588b7eac0ba3cc588172647b31047e1460caf909398d7";

static void _tmp_path(char *out, size_t cap)
{
    char dir[] = "/tmp/at-group-file-XXXXXX";
    ck_assert(mkdtemp(dir) != NULL);
    snprintf(out, cap, "%s/group.cfg.json", dir);
}

DEFINE_TEST(test_pythons_file_reads)
{
    char path[128];
    _tmp_path(path, sizeof(path));
    FILE *f = fopen(path, "w");
    ck_assert_ptr_nonnull(f);
    fputs(PY_FILE, f);
    fclose(f);

    group_t g;
    json_t *steps = NULL;
    ck_assert_int_eq(group_file_read(path, &g, &steps), 0);
    char uuid[UUID_STRING_LEN + 1];
    uuid_unparse_lower(g.uuid, uuid);
    ck_assert_str_eq(uuid, "4b664af2-7120-4e41-bb35-627c55362965");
    data_t *addr = NULL;
    ck_assert_int_eq(map_get(&g.address_map,
                             (map_key_t)"11111111-1111-4111-8111-111111111111",
                             &addr), 0);
    unsigned char *priv = encryptor_serialize_private(&g.encryptor);
    ck_assert_str_eq((char *)priv, SEED);
    free(priv);
    ck_assert_int_eq((int)json_array_size(steps), 1);

    linked_step_t *step = NULL;
    ck_assert_int_eq(step_from_any_json(json_array_get(steps, 0), &step), 0);
    ck_assert_str_eq(step->uuid, "a0d8104b-ed19-405b-a3fe-58ef942ac0b7");
    json_t *plain = linked_step_to_json(step);
    ck_assert_str_eq(json_string_value(json_object_get(plain, "payload")),
                     "abababababababababababababababababababababababababababababababab");
    json_decref(plain);
    json_decref(steps);
    map_free(&g.address_map);
    unlink(path);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_ours_round_trips_in_pythons_schema)
{
    group_t g = {0};
    ck_assert_ret_ok(group_init(NULL, (char *)"10.0.0.7", &g));
    group_add_address(&g, "22222222-2222-4222-8222-222222222222", "10.0.0.8");
    g.key_epoch = 3;
    g.created = 1792700000.5;

    /* A plain step (C's full_history form) in, a tagged one out. */
    json_t *plain = json_pack("{s:s, s:s, s:s}",
                              "uuid", "b1d8104b-ed19-405b-a3fe-58ef942ac0b7",
                              "timestamp", "2026-10-23T02:04:43.067288+00:00",
                              "payload",
                              "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd");
    linked_step_t *step = NULL;
    ck_assert_int_eq(step_from_any_json(plain, &step), 0);
    json_decref(plain);
    json_t *tagged = step_to_tagged_json(step);
    ck_assert_str_eq(json_string_value(json_object_get(tagged, "__type__")),
                     "autonomous_trust.core._python.structures.dag.LinkedStep");
    ck_assert_str_eq(json_string_value(json_object_get(
                         json_object_get(tagged, "uuid"), "__type__")), "UUID");
    json_t *steps = json_array();
    json_array_append_new(steps, tagged);

    char path[128];
    _tmp_path(path, sizeof(path));
    ck_assert_int_eq(group_file_write(path, &g, steps), 0);
    json_decref(steps);

    /* The file is Python's shape. */
    json_t *doc = json_load_file(path, 0, NULL);
    ck_assert(json_is_array(doc) && json_array_size(doc) == 2);
    json_t *gj = json_array_get(doc, 0);
    ck_assert_str_eq(json_string_value(json_object_get(gj, "__type__")),
                     "autonomous_trust.core._python.identity.group.Group");
    ck_assert_ptr_nonnull(json_object_get(json_object_get(gj, "_encryptor"), "hex_seed"));
    ck_assert(json_is_array(json_object_get(json_array_get(doc, 1), "blacklist")));
    json_decref(doc);

    group_t back;
    json_t *back_steps = NULL;
    ck_assert_int_eq(group_file_read(path, &back, &back_steps), 0);
    ck_assert_int_eq(uuid_compare(back.uuid, g.uuid), 0);
    ck_assert_int_eq(memcmp(back.encryptor.private, g.encryptor.private,
                            sizeof(g.encryptor.private)), 0);
    ck_assert_int_eq(memcmp(back.encryptor.public, g.encryptor.public,
                            sizeof(g.encryptor.public)), 0);
    ck_assert_int_eq((int)back.key_epoch, 3);
    ck_assert(back.created > 1792700000.0);
    linked_step_t *again = NULL;
    ck_assert_int_eq(step_from_any_json(json_array_get(back_steps, 0), &again), 0);
    ck_assert_str_eq(again->uuid, "b1d8104b-ed19-405b-a3fe-58ef942ac0b7");
    json_decref(back_steps);
    map_free(&back.address_map);
    map_free(&g.address_map);
    unlink(path);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_an_absent_file_is_no_group)
{
    group_t g;
    json_t *steps = NULL;
    ck_assert_int_eq(group_file_read("/tmp/at-no-such-dir/group.cfg.json", &g, &steps), -1);
    ck_assert_ptr_null(steps);
}
END_TEST_DEFINITION()

RUN_TESTS(GroupFile,
          test_pythons_file_reads,
          test_ours_round_trips_in_pythons_schema,
          test_an_absent_file_is_no_group)
