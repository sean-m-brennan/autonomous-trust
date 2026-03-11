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

#include "autonomous_trust/config/configuration.h"

extern int config_absolute_path(const char *path_in, char *path_out);

DEFINE_TEST(test_get_cfg_dir)
{
    /* Set a known root */
    setenv("AUTONOMOUS_TRUST_ROOT", "/tmp/at_test", 1);

    char path[256] = {0};
    int len = get_cfg_dir(path);
    ck_assert(len > 0);
    ck_assert_str_eq(path, "/tmp/at_test/etc/at");

    unsetenv("AUTONOMOUS_TRUST_ROOT");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_get_data_dir)
{
    setenv("AUTONOMOUS_TRUST_ROOT", "/tmp/at_test", 1);

    char path[256] = {0};
    int len = get_data_dir(path);
    ck_assert(len > 0);
    ck_assert_str_eq(path, "/tmp/at_test/var/at");

    unsetenv("AUTONOMOUS_TRUST_ROOT");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_get_dirs_empty_root)
{
    /* When AUTONOMOUS_TRUST_ROOT is unset, should still return valid paths */
    unsetenv("AUTONOMOUS_TRUST_ROOT");

    char cfg_path[256] = {0};
    char data_path[256] = {0};
    int len1 = get_cfg_dir(cfg_path);
    int len2 = get_data_dir(data_path);
    ck_assert(len1 > 0);
    ck_assert(len2 > 0);
    /* Should contain the relative paths */
    ck_assert(strstr(cfg_path, "etc/at") != NULL);
    ck_assert(strstr(data_path, "var/at") != NULL);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_find_configuration_missing)
{
    /* Looking up a nonexistent configuration should return NULL */
    config_t *cfg = find_configuration("nonexistent_config_xyz_12345");
    ck_assert_ptr_null(cfg);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_find_configuration_exists)
{
    /* "network" is a known entry in the configuration table */
    config_t *cfg = find_configuration("network");
    if (cfg != NULL) {
        ck_assert_str_eq(cfg->name, "network");
        ck_assert(cfg->to_json != NULL);
        ck_assert(cfg->from_json != NULL);
    }
    /* Also check process_tracker */
    cfg = find_configuration("process_tracker");
    if (cfg != NULL)
        ck_assert_str_eq(cfg->name, "process_tracker");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_config_absolute_path)
{
    setenv("AUTONOMOUS_TRUST_ROOT", "/tmp/at_test", 1);

    char path_out[256] = {0};
    ck_assert_ret_ok(config_absolute_path("test.cfg.json", path_out));
    ck_assert(strstr(path_out, "etc/at/test.cfg.json") != NULL);

    /* If already absolute (starts with cfg dir), should be a no-op */
    char path_out2[256] = {0};
    ck_assert_ret_ok(config_absolute_path("/tmp/at_test/etc/at/test.cfg.json", path_out2));

    unsetenv("AUTONOMOUS_TRUST_ROOT");
}
END_TEST_DEFINITION()

RUN_TESTS(Config, test_get_cfg_dir, test_get_data_dir,
          test_get_dirs_empty_root, test_find_configuration_missing,
          test_find_configuration_exists, test_config_absolute_path)
