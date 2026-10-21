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
/* The trust-ladder loader's C half (doc/architecture/trust-tiers.md). The Python
 * half existed and C registered capabilities in code only, which was the one
 * asymmetry in that doc's §9 parity table.
 *
 * The ladder is JSON so ONE file serves both runtimes (Python's loader reads it
 * unchanged, YAML being a superset of JSON). `test_the_shared_example_parses`
 * reads the very file the Python suite reads, and the two assert the same
 * numbers — the pin that makes "one file, both runtimes" a fact rather than an
 * intention. */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "autonomous_trust/config/trust_ladder.h"

/* Write `body` to a temp file; returns a heap path the caller frees. */
static char *_ladder_file(const char *body)
{
    char *path = malloc(64);
    snprintf(path, 64, "/tmp/at_ladder_test_%d_%p.json", (int)getpid(),
             (void *)body);
    FILE *fh = fopen(path, "w");
    if (fh == NULL)
        return NULL;
    fputs(body, fh);
    fclose(fh);
    return path;
}

DEFINE_TEST(test_defaults_are_the_documented_ones)
{
    /* trust-tiers §8: "everything tier 0, weight 1, bootstrap on". */
    trust_ladder_t ladder;
    trust_ladder_defaults(&ladder);
    ck_assert_int_eq((int)ladder.num_capabilities, 0);
    ck_assert(ladder.bootstrap.enabled == true);
    ck_assert_int_eq(ladder.bootstrap.duration_sec, 30);
    ck_assert_int_eq(ladder.bootstrap.pairs, 20);
    ck_assert_double_eq_tol(ladder.tier_demotion_epsilon, 0.02, 1e-9);
}

DEFINE_TEST(test_a_full_ladder_parses)
{
    char *path = _ladder_file(
        "{\"version\": 1,"
        " \"bootstrap\": {\"enabled\": false, \"duration_sec\": 5, \"pairs\": 7},"
        " \"capabilities\": {"
        "   \"at.handshake\": {\"required_tier\": 0, \"transaction_weight\": 1},"
        "   \"dod.sensor-report\": {\"required_tier\": 2, \"transaction_weight\": 4}},"
        " \"tier_demotion_epsilon\": 0.5}");
    trust_ladder_t ladder;
    ck_assert_ret_ok(trust_ladder_load(path, &ladder));
    ck_assert_int_eq((int)ladder.num_capabilities, 2);
    ck_assert(ladder.bootstrap.enabled == false);
    ck_assert_int_eq(ladder.bootstrap.duration_sec, 5);
    ck_assert_int_eq(ladder.bootstrap.pairs, 7);
    ck_assert_double_eq_tol(ladder.tier_demotion_epsilon, 0.5, 1e-9);
    const ladder_capability_t *sensor =
        trust_ladder_find(&ladder, "dod.sensor-report");
    ck_assert(sensor != NULL);
    ck_assert_int_eq(sensor->required_tier, 2);
    ck_assert_int_eq(sensor->transaction_weight, 4);
    remove(path);
    free(path);
}

DEFINE_TEST(test_absent_fields_take_the_documented_defaults)
{
    /* An entry may be `{}` — the schema says every field is optional. */
    char *path = _ladder_file("{\"capabilities\": {\"bare\": {}}}");
    trust_ladder_t ladder;
    ck_assert_ret_ok(trust_ladder_load(path, &ladder));
    const ladder_capability_t *bare = trust_ladder_find(&ladder, "bare");
    ck_assert(bare != NULL);
    ck_assert_int_eq(bare->required_tier, 0);
    ck_assert_int_eq(bare->transaction_weight, 1);
    ck_assert_int_eq(ladder.bootstrap.duration_sec, 30);   /* stanza absent */
    remove(path);
    free(path);
}

DEFINE_TEST(test_an_empty_object_is_the_default_ladder)
{
    char *path = _ladder_file("{}");
    trust_ladder_t ladder;
    ck_assert_ret_ok(trust_ladder_load(path, &ladder));
    ck_assert_int_eq((int)ladder.num_capabilities, 0);
    ck_assert(ladder.bootstrap.enabled == true);
    remove(path);
    free(path);
}

DEFINE_TEST(test_a_missing_explicit_path_is_an_error)
{
    /* Python raises FileNotFoundError for an explicit path: the caller asked
     * for that file. Only the env path is forgiving. */
    trust_ladder_t ladder;
    ck_assert_ret_nonzero(
        trust_ladder_load("/tmp/at_ladder_does_not_exist.json", &ladder));
}

DEFINE_TEST(test_a_malformed_entry_is_rejected)
{
    char *path = _ladder_file(
        "{\"capabilities\": {\"bad\": {\"required_tier\": \"two\"}}}");
    trust_ladder_t ladder;
    ck_assert_ret_nonzero(trust_ladder_load(path, &ladder));
    /* And the out-param is left holding the defaults, so a caller that ignores
     * the return value reads documented behaviour rather than half a ladder. */
    ck_assert_int_eq((int)ladder.num_capabilities, 0);
    ck_assert_int_eq(ladder.bootstrap.duration_sec, 30);
    remove(path);
    free(path);
}

DEFINE_TEST(test_broken_json_is_rejected)
{
    char *path = _ladder_file("{\"capabilities\": ");
    trust_ladder_t ladder;
    ck_assert_ret_nonzero(trust_ladder_load(path, &ladder));
    remove(path);
    free(path);
}

DEFINE_TEST(test_a_non_object_capabilities_stanza_is_rejected)
{
    char *path = _ladder_file("{\"capabilities\": [\"at.handshake\"]}");
    trust_ladder_t ladder;
    ck_assert_ret_nonzero(trust_ladder_load(path, &ladder));
    remove(path);
    free(path);
}

DEFINE_TEST(test_env_unset_yields_defaults)
{
    unsetenv(TRUST_LADDER_ENV);
    trust_ladder_t ladder;
    ck_assert_ret_ok(trust_ladder_load_env(&ladder));
    ck_assert_int_eq((int)ladder.num_capabilities, 0);
}

DEFINE_TEST(test_env_pointing_at_a_missing_file_degrades_to_defaults)
{
    /* A misconfigured deployment should still start (Python warns and falls
     * back); only an explicit path is fatal. */
    setenv(TRUST_LADDER_ENV, "/tmp/at_ladder_does_not_exist.json", 1);
    trust_ladder_t ladder;
    ck_assert_ret_ok(trust_ladder_load_env(&ladder));
    ck_assert_int_eq((int)ladder.num_capabilities, 0);
    ck_assert(ladder.bootstrap.enabled == true);
    unsetenv(TRUST_LADDER_ENV);
}

DEFINE_TEST(test_env_pointing_at_a_real_ladder_loads_it)
{
    char *path = _ladder_file("{\"capabilities\": {\"x\": {\"required_tier\": 3}}}");
    setenv(TRUST_LADDER_ENV, path, 1);
    trust_ladder_t ladder;
    ck_assert_ret_ok(trust_ladder_load_env(&ladder));
    ck_assert_int_eq((int)ladder.num_capabilities, 1);
    ck_assert_int_eq(trust_ladder_find(&ladder, "x")->required_tier, 3);
    unsetenv(TRUST_LADDER_ENV);
    remove(path);
    free(path);
}

DEFINE_TEST(test_a_present_but_broken_env_file_still_fails)
{
    /* "Absent" degrades; "broken" does not — that is a ladder someone wrote
     * wrong, and starting with silent defaults would hide it. */
    char *path = _ladder_file("{ nope");
    setenv(TRUST_LADDER_ENV, path, 1);
    trust_ladder_t ladder;
    ck_assert_ret_nonzero(trust_ladder_load_env(&ladder));
    unsetenv(TRUST_LADDER_ENV);
    remove(path);
    free(path);
}

DEFINE_TEST(test_apply_overrides_code_declared_metadata)
{
    char *path = _ladder_file(
        "{\"capabilities\": {\"at.handshake\": "
        "{\"required_tier\": 1, \"transaction_weight\": 9}}}");
    trust_ladder_t ladder;
    ck_assert_ret_ok(trust_ladder_load(path, &ladder));

    capability_t caps[2];
    memset(caps, 0, sizeof(caps));
    at_strlcpy(caps[0].name, "at.handshake", sizeof(caps[0].name));
    caps[0].required_tier = 0;
    caps[0].transaction_weight = 1;
    at_strlcpy(caps[1].name, "not.in.ladder", sizeof(caps[1].name));
    caps[1].required_tier = 4;
    caps[1].transaction_weight = 7;

    ck_assert_int_eq(trust_ladder_apply(&ladder, caps, 2), 1);
    ck_assert_int_eq(caps[0].required_tier, 1);
    ck_assert_int_eq(caps[0].transaction_weight, 9);
    /* A capability the ladder does not name keeps what the code declared: a
     * ladder is written for a scenario, and a node is only part of one. */
    ck_assert_int_eq(caps[1].required_tier, 4);
    ck_assert_int_eq(caps[1].transaction_weight, 7);
    remove(path);
    free(path);
}

DEFINE_TEST(test_find_returns_null_for_an_unknown_capability)
{
    trust_ladder_t ladder;
    trust_ladder_defaults(&ladder);
    ck_assert(trust_ladder_find(&ladder, "nobody") == NULL);
    ck_assert(trust_ladder_find(&ladder, NULL) == NULL);
    ck_assert(trust_ladder_find(NULL, "x") == NULL);
}

DEFINE_TEST(test_the_shared_example_parses)
{
    /* The SAME file the Python suite reads (config/cfg/trust_ladder.example.json)
     * — this is what makes "one file, both runtimes" checkable. AT_REPO_ROOT is
     * set by CMake; skip rather than fail if the file is absent from an
     * installed tree. */
    const char *root = getenv("AT_REPO_ROOT");
    if (root == NULL)
        return;
    char path[512];
    snprintf(path, sizeof(path), "%s/config/cfg/trust_ladder.example.json", root);
    if (access(path, R_OK) != 0)
        return;
    trust_ladder_t ladder;
    ck_assert_ret_ok(trust_ladder_load(path, &ladder));
    ck_assert_int_eq((int)ladder.num_capabilities, 6);
    ck_assert_int_eq(ladder.bootstrap.duration_sec, 45);
    ck_assert_int_eq(ladder.bootstrap.pairs, 12);
    ck_assert(ladder.bootstrap.enabled == true);
    ck_assert_double_eq_tol(ladder.tier_demotion_epsilon, 0.05, 1e-9);
    ck_assert_int_eq(trust_ladder_find(&ladder, "demo.sensor-report")->required_tier, 2);
    ck_assert_int_eq(trust_ladder_find(&ladder, "demo.sensor-report")->transaction_weight, 4);
    /* Partial entry: tier from the file, weight from the documented default. */
    ck_assert_int_eq(trust_ladder_find(&ladder, "demo.fusion")->required_tier, 3);
    ck_assert_int_eq(trust_ladder_find(&ladder, "demo.fusion")->transaction_weight, 1);
    /* Empty entry: both defaults. */
    ck_assert_int_eq(trust_ladder_find(&ladder, "demo.command")->required_tier, 0);
    ck_assert_int_eq(trust_ladder_find(&ladder, "demo.command")->transaction_weight, 1);
}

RUN_TESTS(TrustLadder, test_defaults_are_the_documented_ones,
          test_a_full_ladder_parses,
          test_absent_fields_take_the_documented_defaults,
          test_an_empty_object_is_the_default_ladder,
          test_a_missing_explicit_path_is_an_error,
          test_a_malformed_entry_is_rejected,
          test_broken_json_is_rejected,
          test_a_non_object_capabilities_stanza_is_rejected,
          test_env_unset_yields_defaults,
          test_env_pointing_at_a_missing_file_degrades_to_defaults,
          test_env_pointing_at_a_real_ladder_loads_it,
          test_a_present_but_broken_env_file_still_fails,
          test_apply_overrides_code_declared_metadata,
          test_find_returns_null_for_an_unknown_capability,
          test_the_shared_example_parses)
