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

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

#include <jansson.h>

#include "autonomous_trust/config/configuration.h"
#include "autonomous_trust/structures/array_priv.h"

extern int num_config_files(char path[]);
extern int all_config_files(char dir[], array_t *paths);
extern int read_config_file(const char *filename, void *data_struct);
extern int config_absolute_path(const char *path_in, char *path_out);

static char test_root[512];

static void make_test_dirs(void)
{
    char tmpl[] = "/tmp/at_cfg2_XXXXXX";
    char *dir = mkdtemp(tmpl);
    ck_assert_ptr_nonnull(dir);
    strncpy(test_root, dir, sizeof(test_root) - 1);

    char cfg_dir[1024];
    snprintf(cfg_dir, sizeof(cfg_dir), "%s/etc", test_root);
    mkdir(cfg_dir, 0755);
    snprintf(cfg_dir, sizeof(cfg_dir), "%s/etc/at", test_root);
    mkdir(cfg_dir, 0755);

    char data_dir[1024];
    snprintf(data_dir, sizeof(data_dir), "%s/var", test_root);
    mkdir(data_dir, 0755);
    snprintf(data_dir, sizeof(data_dir), "%s/var/at", test_root);
    mkdir(data_dir, 0755);

    setenv("AUTONOMOUS_TRUST_ROOT", test_root, 1);
}

static void write_test_file(const char *name, const char *content)
{
    char path[1024];
    int n = snprintf(path, sizeof(path), "%s/etc/at/%s", test_root, name);
    ck_assert(n > 0 && (size_t)n < sizeof(path));
    FILE *f = fopen(path, "w");
    ck_assert_ptr_nonnull(f);
    fputs(content, f);
    fclose(f);
}

DEFINE_TEST(test_num_config_files)
{
    make_test_dirs();

    char cfg_dir[1024];
    snprintf(cfg_dir, sizeof(cfg_dir), "%s/etc/at", test_root);

    /* Empty dir has . and .. = 2 entries */
    int n = num_config_files(cfg_dir);
    ck_assert(n >= 2);

    /* Add some files */
    write_test_file("test1.cfg.json", "{}");
    write_test_file("test2.cfg.json", "{}");
    write_test_file("not_config.txt", "hello");

    int n2 = num_config_files(cfg_dir);
    ck_assert_int_eq(n2, n + 3);

    unsetenv("AUTONOMOUS_TRUST_ROOT");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_all_config_files)
{
    make_test_dirs();

    char cfg_dir[1024];
    snprintf(cfg_dir, sizeof(cfg_dir), "%s/etc/at", test_root);

    write_test_file("alpha.cfg.json", "{}");
    write_test_file("beta.cfg.json", "{}");
    write_test_file("gamma.cfg.jsn", "{}");
    write_test_file("not_cfg.txt", "nope");

    array_t paths;
    array_init(&paths);
    ck_assert_ret_ok(all_config_files(cfg_dir, &paths));

    /* Should find 3 config files (.cfg.json and .cfg.jsn) */
    ck_assert_uint_eq(array_size(&paths), 3);

    unsetenv("AUTONOMOUS_TRUST_ROOT");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_num_config_files_bad_dir)
{
    /* Non-existent directory should fail */
    char bad[] = "/tmp/at_nonexistent_dir_xyz_99999";
    int n = num_config_files(bad);
    ck_assert(n != 0);  /* Should return error */
}
END_TEST_DEFINITION()

DEFINE_TEST(test_read_config_file_bad_json)
{
    make_test_dirs();

    /* Write invalid JSON */
    write_test_file("bad.cfg.json", "not json at all");

    char path[1024];
    int n = snprintf(path, sizeof(path), "%s/etc/at/bad.cfg.json", test_root);
    ck_assert(n > 0 && (size_t)n < sizeof(path));

    char buf[1024] = {0};
    int ret = read_config_file(path, buf);
    ck_assert_ret_nonzero(ret);  /* Should fail on bad JSON */

    unsetenv("AUTONOMOUS_TRUST_ROOT");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_read_config_file_no_typename)
{
    make_test_dirs();

    /* Valid JSON but no typename field */
    write_test_file("notype.cfg.json", "{\"key\": \"value\"}");

    char path[1024];
    int n = snprintf(path, sizeof(path), "%s/etc/at/notype.cfg.json", test_root);
    ck_assert(n > 0 && (size_t)n < sizeof(path));

    char buf[1024] = {0};
    int ret = read_config_file(path, buf);
    ck_assert_ret_nonzero(ret);  /* Should fail: no typename */

    unsetenv("AUTONOMOUS_TRUST_ROOT");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_read_config_file_unknown_type)
{
    make_test_dirs();

    /* Valid JSON with unknown typename */
    write_test_file("unknown.cfg.json", "{\"typename\": \"nonexistent_type_xyz\"}");

    char path[1024];
    int n = snprintf(path, sizeof(path), "%s/etc/at/unknown.cfg.json", test_root);
    ck_assert(n > 0 && (size_t)n < sizeof(path));

    char buf[1024] = {0};
    int ret = read_config_file(path, buf);
    ck_assert_ret_nonzero(ret);  /* Should fail: unknown config type */

    unsetenv("AUTONOMOUS_TRUST_ROOT");
}
END_TEST_DEFINITION()

RUN_TESTS(Config2, test_num_config_files, test_all_config_files,
          test_num_config_files_bad_dir, test_read_config_file_bad_json,
          test_read_config_file_no_typename, test_read_config_file_unknown_type)
