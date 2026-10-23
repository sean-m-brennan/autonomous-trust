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

/** @file The join-policy declaration and the anchor hook (RD_14.4 plan,
 *  Phase 2). Opt-in (D9): absent is inert, malformed refuses the start. The
 *  declaration chooses which anchor classes count (D6), and the core
 *  intersects what the extensions report with that list. The Python twin is
 *  tests/a_unit/test_join_policy.py; both read
 *  config/cfg/join_policy.example.json.
 */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "identity/id_ext.h"
#include "identity/id_proc_priv.h"
#include "identity/join_policy.h"

static bool _parses(const char *text)
{
    at_join_policy_t p;
    char err[256] = {0};
    return at_join_policy_parse(text, &p, err, sizeof(err));
}

DEFINE_TEST(test_absent_is_inert)
{
    unsetenv(AT_JOIN_POLICY_ENV);
    at_join_policy_t p = {.enabled = true, .anchors = AT_ANCHOR_ALL};
    char err[256] = {0};
    ck_assert(at_join_policy_load_env(&p, err, sizeof(err)));
    ck_assert(!p.enabled);
    ck_assert_uint_eq(p.anchors, 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_example_lists_the_recommended_three)
{
    char path[1024];
    snprintf(path, sizeof(path), "%s/config/cfg/join_policy.example.json",
             AT_REPO_ROOT_DEFAULT);
    if (access(path, R_OK) != 0)
        return;   /* not a source checkout */
    at_join_policy_t p;
    char err[256] = {0};
    ck_assert(at_join_policy_load(path, &p, err, sizeof(err)));
    ck_assert(p.enabled);
    ck_assert_uint_eq(p.anchors,
                      AT_ANCHOR_VERIFIED_CONTACT | AT_ANCHOR_ZTA | AT_ANCHOR_OPERATOR);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_malformed_is_refused)
{
    /* The same cases as the Python suite. */
    ck_assert(!_parses("[]"));
    ck_assert(!_parses("{\"enabled\": true}"));
    ck_assert(!_parses("{\"version\": 2}"));
    ck_assert(!_parses("{\"version\": true}"));
    ck_assert(!_parses("{\"version\": 1.0}"));
    ck_assert(!_parses("{\"version\": 1, \"enabled\": \"yes\"}"));
    ck_assert(!_parses("{\"version\": 1, \"anchors\": \"zta\"}"));
    ck_assert(!_parses("{\"version\": 1, \"anchors\": [\"friend\"]}"));
    ck_assert(!_parses("{\"version\": 1, \"anchors\": [\"zta\", \"zta\"]}"));
    ck_assert(!_parses("{\"version\": 1, \"anchor\": [\"zta\"]}"));
    ck_assert(!_parses("{\"version\": 1,"));
    ck_assert(_parses("{\"version\": 1, \"note\": \"why\", \"enabled\": false}"));
}
END_TEST_DEFINITION()

DEFINE_TEST(test_a_missing_or_malformed_file_refuses_the_start)
{
    char dir[] = "/tmp/at-join-policyXXXXXX";
    ck_assert_ptr_nonnull(mkdtemp(dir));
    char path[256];
    snprintf(path, sizeof(path), "%s/join_policy.json", dir);
    setenv(AT_JOIN_POLICY_ENV, path, 1);
    ck_assert_int_eq(identity_join_policy_check(NULL), -1);
    FILE *fp = fopen(path, "w");
    ck_assert_ptr_nonnull(fp);
    fputs("{\"version\": 1,", fp);
    fclose(fp);
    ck_assert_int_eq(identity_join_policy_check(NULL), -1);
    fp = fopen(path, "w");
    fputs("{\"version\": 1, \"enabled\": false, \"anchors\": [\"zta\"]}", fp);
    fclose(fp);
    ck_assert_int_eq(identity_join_policy_check(NULL), 0);
    unlink(path);
    rmdir(dir);
    unsetenv(AT_JOIN_POLICY_ENV);
}
END_TEST_DEFINITION()

/* A stand-in extension, registered by name, whose answer each test sets. */
static uint32_t g_answer;
static uint32_t _answer(const process_t *proc, const public_identity_t *ident)
{
    (void)proc;
    (void)ident;
    return g_answer;
}
static const identity_ext_t fake_zta = {.name = "zta", .anchor_classes = _answer};

DEFINE_TEST(test_a_class_no_extension_answers_refuses_the_start)
{
    /* Nothing but the stand-in "zta" is linked into this binary. */
    at_join_policy_t p = {.enabled = true,
                          .anchors = AT_ANCHOR_VERIFIED_CONTACT | AT_ANCHOR_ZTA};
    if (!identity_ext_present("zta"))
        ck_assert_int_eq(identity_ext_register(&fake_zta), 0);
    ck_assert_uint_eq(at_join_policy_missing_providers(&p), AT_ANCHOR_VERIFIED_CONTACT);
    /* Either extension answers operator. */
    p.anchors = AT_ANCHOR_OPERATOR;
    ck_assert_uint_eq(at_join_policy_missing_providers(&p), 0);
    /* A disabled policy needs none. */
    p.enabled = false;
    p.anchors = AT_ANCHOR_UNVERIFIED_CONTACT;
    ck_assert_uint_eq(at_join_policy_missing_providers(&p), 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_the_core_counts_only_declared_classes)
{
    if (!identity_ext_present("zta"))
        ck_assert_int_eq(identity_ext_register(&fake_zta), 0);
    public_identity_t peer;
    memset(&peer, 0, sizeof(peer));
    struct {
        at_join_policy_t policy;
        uint32_t answer, expected;
    } cases[] = {
        {{false, 0}, AT_ANCHOR_ZTA, 0},
        {{false, AT_ANCHOR_ZTA}, AT_ANCHOR_ZTA, 0},
        {{true, AT_ANCHOR_ZTA}, AT_ANCHOR_ZTA | AT_ANCHOR_OPERATOR, AT_ANCHOR_ZTA},
        {{true, AT_ANCHOR_VERIFIED_CONTACT | AT_ANCHOR_ZTA},
         AT_ANCHOR_UNVERIFIED_CONTACT | AT_ANCHOR_ZTA, AT_ANCHOR_ZTA},
        {{true, AT_ANCHOR_UNVERIFIED_CONTACT}, AT_ANCHOR_UNVERIFIED_CONTACT,
         AT_ANCHOR_UNVERIFIED_CONTACT},
        {{true, AT_ANCHOR_ZTA}, 0, 0},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        identity_set_join_policy(&cases[i].policy);
        g_answer = cases[i].answer;
        ck_assert_uint_eq(identity_anchor_classes(NULL, &peer), cases[i].expected);
        ck_assert(identity_is_anchored(NULL, &peer) == (cases[i].expected != 0));
    }
    ck_assert_uint_eq(identity_anchor_classes(NULL, NULL), 0);
    identity_set_join_policy(NULL);
    g_answer = AT_ANCHOR_ALL;
    ck_assert_uint_eq(identity_anchor_classes(NULL, &peer), 0);
}
END_TEST_DEFINITION()

RUN_TESTS(JoinPolicy,
          test_absent_is_inert,
          test_the_example_lists_the_recommended_three,
          test_malformed_is_refused,
          test_a_missing_or_malformed_file_refuses_the_start,
          test_a_class_no_extension_answers_refuses_the_start,
          test_the_core_counts_only_declared_classes)
