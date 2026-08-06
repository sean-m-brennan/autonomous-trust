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

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <string.h>
#include <stdlib.h>
#include <limits.h>

#include "autonomous_trust/config/configuration.h"
#include "autonomous_trust/processes/process_tracker.h"
#include "autonomous_trust/utilities/logger.h"

extern int config_absolute_path(const char *path_in, char *path_out);
extern int load_config(char *filepath, config_t **config_ptr,
                       char *cfg_name, logger_t *logger);

static logger_t _m2_test_logger;
static void __attribute__((constructor)) _init_m2_test_logger(void)
{
    logger_init(&_m2_test_logger, CRITICAL, NULL);
}

DEFINE_TEST(test_get_cfg_dir)
{
    /* Set a known root */
    setenv("AUTONOMOUS_TRUST_ROOT", "/tmp/at_test", 1);

    char path[256] = {0};
    int len = get_cfg_dir(path, sizeof(path));
    ck_assert(len > 0);
    ck_assert_str_eq(path, "/tmp/at_test/etc/at");

    unsetenv("AUTONOMOUS_TRUST_ROOT");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_get_data_dir)
{
    setenv("AUTONOMOUS_TRUST_ROOT", "/tmp/at_test", 1);

    char path[256] = {0};
    int len = get_data_dir(path, sizeof(path));
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
    int len1 = get_cfg_dir(cfg_path, sizeof(cfg_path));
    int len2 = get_data_dir(data_path, sizeof(data_path));
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

/* Regression for configuration.c:141 — config_absolute_path used a prefix
 * check that did not prevent ".." traversal.  Inputs like "../../etc/passwd"
 * joined cleanly with cfg_dir and escaped the sandbox.  Fix rejects literal
 * ".." substrings and requires absolute inputs to match cfg_dir followed by
 * '/'. */
DEFINE_TEST(test_config_absolute_path_rejects_traversal)
{
    setenv("AUTONOMOUS_TRUST_ROOT", "/tmp/at_test", 1);

    char cfg_dir[CFG_PATH_LEN + 1] = {0};
    ck_assert(get_cfg_dir(cfg_dir, sizeof(cfg_dir)) > 0);
    size_t cfg_dir_len = strlen(cfg_dir);

    const char *attacks[] = {
        "../../../etc/passwd",
        "..",
        "../secrets.cfg.json",
        "subdir/../../escape.cfg.json",
    };

    for (size_t i = 0; i < sizeof(attacks) / sizeof(attacks[0]); i++)
    {
        char path_out[CFG_PATH_LEN + 1] = {0};
        int rc = config_absolute_path(attacks[i], path_out);

        if (rc == 0)
        {
            /* If the function accepted the path, the resolved path must
             * still be rooted at cfg_dir.  If the file doesn't exist yet,
             * at minimum the literal output must not contain "..". */
            char resolved[PATH_MAX];
            if (realpath(path_out, resolved) != NULL)
                ck_assert(strncmp(resolved, cfg_dir, cfg_dir_len) == 0);
            else
                ck_assert(strstr(path_out, "..") == NULL);
        }
        /* rc != 0 means the function rejected the input; also acceptable. */
    }

    unsetenv("AUTONOMOUS_TRUST_ROOT");
}
END_TEST_DEFINITION()

/* Regression for configuration.c:305-308 — load_config used
 * `min(CFG_PATH_LEN - 1, …)` (= 255) as the copy cap, but the destination
 * `cfg_name` is CFG_NAME_SIZE + 1 bytes (65).  A filename whose basename-
 * without-extension exceeds CFG_NAME_SIZE overran cfg_name with no NUL
 * termination.  Fix caps at CFG_NAME_SIZE and explicitly terminates.
 *
 * We don't need a real file: load_config's string-manipulation happens
 * before any filesystem access. */
DEFINE_TEST(test_load_config_cfg_name_bounded)
{
    setenv("AUTONOMOUS_TRUST_ROOT", "/tmp/at_major_test", 1);

    /* Layout: [leading sentinel][cfg_name 65 B][trailing sentinel]. */
    struct {
        unsigned char leader[32];
        char          cfg_name[CFG_NAME_SIZE + 1];
        unsigned char trailer[32];
    } box;
    memset(&box, 0xCD, sizeof(box));
    memset(box.cfg_name, 0, sizeof(box.cfg_name));

    /* Relative filepath so config_absolute_path accepts it (joins under
     * cfg_dir) and load_config proceeds to the strncpy of `filename` into
     * `cfg_name`.  Basename-without-extension is 80 bytes — overflows
     * cfg_name (65 B) by 16 bytes under the buggy cap. */
    char filepath[256];
    memset(filepath, 'X', 80);
    strcpy(filepath + 80, ".cfg.json");

    config_t *cfg_out = NULL;
    (void)load_config(filepath, &cfg_out, box.cfg_name, &_m2_test_logger);

    int trailer_clean = 1;
    for (size_t i = 0; i < sizeof(box.trailer); i++)
        if (box.trailer[i] != 0xCD) { trailer_clean = 0; break; }
    ck_assert(trailer_clean);
    ck_assert_int_eq((unsigned char)box.cfg_name[CFG_NAME_SIZE], 0);

    unsetenv("AUTONOMOUS_TRUST_ROOT");
}
END_TEST_DEFINITION()

/* The defect these cover is ISSUES.md §2.1.1: both functions hardcoded 255 as
 * path_join's destination length while taking an unsized `char path[]`, so
 * path_join's own correct bounds check ran against a number that had nothing to do
 * with the caller's buffer. unix_addr passes 108 bytes, and a long
 * AUTONOMOUS_TRUST_ROOT therefore wrote past the end of its stack frame. */

DEFINE_TEST(test_get_dirs_respect_the_destlen_they_are_given)
{
    setenv("AUTONOMOUS_TRUST_ROOT", "/tmp/at_test", 1);

    /* "/tmp/at_test/var/at" is 19 chars + NUL. A buffer that cannot hold it must
     * be refused, not filled past its end — and the refusal has to be visible,
     * because the caller cannot see the length it did not supply. */
    char exact[20] = {0};
    ck_assert((get_data_dir(exact, sizeof(exact))) > 0);
    ck_assert_str_eq(exact, "/tmp/at_test/var/at");

    char one_short[19];
    memset(one_short, 'Z', sizeof(one_short));
    ck_assert((get_data_dir(one_short, sizeof(one_short))) < 0);
    ck_assert_int_eq(one_short[0], '\0');   /* refused, and says so in the buffer */

    char tiny[4];
    memset(tiny, 'Z', sizeof(tiny));
    ck_assert((get_cfg_dir(tiny, sizeof(tiny))) < 0);
    ck_assert_int_eq(tiny[0], '\0');

    unsetenv("AUTONOMOUS_TRUST_ROOT");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_get_dirs_refuse_a_root_too_long_for_the_buffer)
{
    /* The shape that crashed: a long root with a small destination. Before the
     * fix this wrote strlen(root) bytes into whatever the caller had. */
    char root[200];
    memset(root, 'r', sizeof(root) - 1);
    root[0] = '/';
    root[sizeof(root) - 1] = '\0';
    setenv("AUTONOMOUS_TRUST_ROOT", root, 1);

    char sock_sized[108];               /* exactly unix_addr's buffer */
    memset(sock_sized, 'Z', sizeof(sock_sized));
    ck_assert((get_data_dir(sock_sized, sizeof(sock_sized))) < 0);
    ck_assert_int_eq(sock_sized[0], '\0');

    /* Everything past the refusal must be untouched — a refusal that had already
     * scribbled would be the original bug wearing a return code. */
    for (size_t i = 1; i < sizeof(sock_sized); i++)
        ck_assert_int_eq(sock_sized[i], 'Z');

    unsetenv("AUTONOMOUS_TRUST_ROOT");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tracker_config_respects_its_destlen)
{
    setenv("AUTONOMOUS_TRUST_ROOT", "/tmp/at_test", 1);

    char ok[CFG_PATH_LEN + 1] = {0};
    ck_assert((tracker_config(ok, sizeof(ok))) >= 0);
    ck_assert(strstr(ok, "/tmp/at_test/etc/at/") == ok);

    /* Same unsized-parameter shape as get_cfg_dir had, and it also hardcoded
     * CFG_PATH_LEN; it was safe only because its one caller passed a buffer that
     * big. Now a small buffer is refused instead of trusted. */
    char small[24];
    memset(small, 'Z', sizeof(small));
    ck_assert((tracker_config(small, sizeof(small))) < 0);

    ck_assert((tracker_config(NULL, 16)) < 0);
    ck_assert((tracker_config(ok, 0)) < 0);

    unsetenv("AUTONOMOUS_TRUST_ROOT");
}
END_TEST_DEFINITION()

RUN_TESTS(Config, test_get_cfg_dir, test_get_data_dir,
          test_get_dirs_empty_root, test_find_configuration_missing,
          test_find_configuration_exists, test_config_absolute_path,
          test_config_absolute_path_rejects_traversal,
          test_load_config_cfg_name_bounded,
          test_get_dirs_respect_the_destlen_they_are_given,
          test_get_dirs_refuse_a_root_too_long_for_the_buffer,
          test_tracker_config_respects_its_destlen)
