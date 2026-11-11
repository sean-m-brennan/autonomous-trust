/* ******************
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
 * ****************** */
/* The deployment manifest's C half (RD_13.4 §3.3). The validation rules are
 * pinned on both runtimes by the conformance case network/deployment-manifest;
 * these cover what that case does not: the load paths, the active-manifest
 * lifecycle, and what a parsed manifest holds. */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "autonomous_trust/config/deployment_manifest.h"
#include "autonomous_trust/config/generate.h"

#define GW1 "aaaaaaaa-0000-4000-8000-000000000001"
#define GW2 "aaaaaaaa-0000-4000-8000-000000000002"
#define LEAF "11111111-0000-4000-8000-000000000001"

static const char *TWO_GATEWAYS =
    "{\"version\": 1,"
    " \"cohorts\": {"
    "  \"a\": {\"members\": [\"" GW1 "\", \"" GW2 "\", \"" LEAF "\"], \"n_min\": 4},"
    "  \"b\": {\"members\": [\"" GW1 "\", \"" GW2 "\"]}},"
    " \"gateways\": ["
    "  {\"node\": \"" GW1 "\", \"between\": [\"b\", \"a\"]},"
    "  {\"node\": \"" GW2 "\", \"between\": [\"a\", \"b\"]}]}";

static char g_path[128];

static const char *_write(const char *body)
{
    snprintf(g_path, sizeof(g_path), "/tmp/at_dm_test_%d.json", (int)getpid());
    FILE *fh = fopen(g_path, "w");
    if (fh == NULL)
        return NULL;
    fputs(body, fh);
    fclose(fh);
    return g_path;
}

DEFINE_TEST(a_valid_manifest_holds_what_it_says)
{
    deployment_manifest_t m;
    char err[256] = {0};
    ck_assert_int_eq(deployment_manifest_load(_write(TWO_GATEWAYS), &m, err,
                                              sizeof(err), NULL), 0);
    ck_assert_uint_eq(m.n_cohorts, 2);
    ck_assert_uint_eq(m.n_gateways, 2);
    /* A pair has one spelling, whichever order the file used. */
    ck_assert_str_eq(m.gateways[0].between[0], "a");
    ck_assert_str_eq(m.gateways[0].between[1], "b");
    ck_assert_uint_eq(deployment_manifest_gateway_pairs(&m, GW1), 1);
    ck_assert_uint_eq(deployment_manifest_gateway_pairs(&m, LEAF), 0);
    ck_assert_uint_eq(deployment_manifest_gateway_pairs(&m, NULL), 0);
    ck_assert_int_eq(m.cohorts[0].n_min + m.cohorts[1].n_min, 4);
    deployment_manifest_free(&m);
    unlink(g_path);
}
END_TEST_DEFINITION()

DEFINE_TEST(an_explicit_missing_path_is_an_error)
{
    deployment_manifest_t m;
    char err[256] = {0};
    ck_assert(deployment_manifest_load("/nonexistent/at_dm.json", &m, err,
                                       sizeof(err), NULL) != 0);
    ck_assert_ptr_nonnull(strstr(err, "not found"));
}
END_TEST_DEFINITION()

DEFINE_TEST(the_environment_names_the_file)
{
    deployment_manifest_t m;
    char err[256] = {0};
    unsetenv(DEPLOYMENT_MANIFEST_ENV);
    ck_assert_int_eq(deployment_manifest_load(NULL, &m, err, sizeof(err), NULL), 0);
    ck_assert_uint_eq(m.n_gateways, 0);
    /* Missing: empty, the restrictive answer, not a refusal. */
    setenv(DEPLOYMENT_MANIFEST_ENV, "/nonexistent/at_dm.json", 1);
    ck_assert_int_eq(deployment_manifest_load(NULL, &m, err, sizeof(err), NULL), 0);
    ck_assert_uint_eq(m.n_gateways, 0);
    setenv(DEPLOYMENT_MANIFEST_ENV, _write(TWO_GATEWAYS), 1);
    ck_assert_int_eq(deployment_manifest_load(NULL, &m, err, sizeof(err), NULL), 0);
    ck_assert_uint_eq(m.n_gateways, 2);
    deployment_manifest_free(&m);
    unsetenv(DEPLOYMENT_MANIFEST_ENV);
    unlink(g_path);
}
END_TEST_DEFINITION()

DEFINE_TEST(a_refused_configure_keeps_the_active_manifest)
{
    deployment_manifest_reset();
    ck_assert_uint_eq(deployment_manifest_active()->n_gateways, 0);
    ck_assert_int_eq(deployment_manifest_configure(_write(TWO_GATEWAYS), NULL), 0);
    ck_assert_uint_eq(deployment_manifest_gateway_pairs(
                          deployment_manifest_active(), GW2), 1);
    ck_assert(deployment_manifest_configure(_write("{\"version\": 2}"),
                                            NULL) != 0);
    ck_assert_uint_eq(deployment_manifest_gateway_pairs(
                          deployment_manifest_active(), GW2), 1);
    deployment_manifest_reset();
    ck_assert_uint_eq(deployment_manifest_active()->n_gateways, 0);
    unlink(g_path);
}
END_TEST_DEFINITION()

DEFINE_TEST(generate_identity_adopts_a_provisioned_uuid)
{
    /* AT_IDENTITY_UUID: a deployment generator that writes a manifest names
     * each node's uuid before the node exists. Canonical form only; anything
     * else refuses before a file is written. Mirrors the Python test in
     * test_config_generate.py. */
    char dir[] = "/tmp/at_dm_gen_XXXXXX";
    ck_assert_ptr_nonnull(mkdtemp(dir));
    setenv("AT_SERIALIZE_MODE", "json", 1);
    const char *bad[] = {"5B1F8F3E-2D7A-5C1E-9A40-0123456789AB",
                         "5b1f8f3e2d7a5c1e9a400123456789ab", "not-a-uuid"};
    for (size_t i = 0; i < 3; i++) {
        setenv("AT_IDENTITY_UUID", bad[i], 1);
        ck_assert(generate_identity("t@example", dir, false, true) != 0);
    }
    const char *want = "5b1f8f3e-2d7a-5c1e-9a40-0123456789ab";
    setenv("AT_IDENTITY_UUID", want, 1);
    ck_assert_int_eq(generate_identity("t@example", dir, false, true), 0);
    char path[128];
    snprintf(path, sizeof(path), "%s/identity.cfg.json", dir);
    FILE *fh = fopen(path, "r");
    ck_assert_ptr_nonnull(fh);
    char buf[8192] = {0};
    size_t n = fread(buf, 1, sizeof(buf) - 1, fh);
    fclose(fh);
    ck_assert(n > 0);
    ck_assert_ptr_nonnull(strstr(buf, want));
    unlink(path);
    rmdir(dir);
    unsetenv("AT_IDENTITY_UUID");
    unsetenv("AT_SERIALIZE_MODE");
}
END_TEST_DEFINITION()

RUN_TESTS("deployment_manifest",
          a_valid_manifest_holds_what_it_says,
          an_explicit_missing_path_is_an_error,
          the_environment_names_the_file,
          a_refused_configure_keeps_the_active_manifest,
          generate_identity_adopts_a_provisioned_uuid)
