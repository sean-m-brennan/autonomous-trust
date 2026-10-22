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
 ********************/

/* Selective assignment (R+D.md §12.7; RD_12.7_SELECTIVE_ASSIGNMENT_PLAN.md).
 * The pure functions are pinned here against the Python twin's values -- the
 * draw, the chain -- and the requestor and peer halves are exercised against
 * each other. The cross-runtime pin lives in the conformance corpus
 * (scenarios/selection/); these are the per-side API and edge-case guards.
 * Mirrors tests/a_unit/test_selection.py. */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <jansson.h>

#include "selection/selection.h"

static const unsigned char ROOT[32] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };

static void _model(at_selection_model_t *m, int log_records)
{
    char text[256];
    snprintf(text, sizeof(text),
             "{\"version\": 1, \"probe\": {\"floor\": 0.1}, \"log_records\": %d,"
             " \"capabilities\": {\"q\": {\"k\": 2}, \"one\": {\"k\": 1}}}", log_records);
    ck_assert(at_selection_parse_text(text, m, NULL, 0));
}

DEFINE_TEST(test_the_draw_matches_python)
{
    double w[4] = { 1, 2, 3, 4 };
    bool sel[6];
    double inc[6];
    at_sel_kind_t kind;
    bool deg, fb;
    ck_assert_int_eq(at_sel_draw(w, 4, 1, 0.05, 42, sel, inc, &kind, &deg, &fb), 0);
    ck_assert(kind == AT_SEL_CATEGORICAL && !deg && !fb);
    ck_assert(sel[3] && !sel[0] && !sel[1] && !sel[2]);
    ck_assert_double_eq_tol(inc[0], 0.13, 1e-15);
    ck_assert_double_eq_tol(inc[3], 0.37000000000000005, 1e-15);

    double w6[6] = { 1, 2, 3, 4, 5, 6 };
    ck_assert_int_eq(at_sel_draw(w6, 6, 2, 0.05, 9001, sel, inc, &kind, &deg, &fb), 0);
    ck_assert(kind == AT_SEL_BERNOULLI && fb);
    ck_assert(sel[2]);
    ck_assert_double_eq_tol(inc[0], 0.17335429526748972, 1e-15);
    ck_assert_double_eq_tol(inc[5], 0.5200628858024692, 1e-15);
}

DEFINE_TEST(test_propensities_floor_and_degrade)
{
    double w[3] = { 1, 2, 3 }, p[3];
    ck_assert(at_sel_propensities(w, 3, 0.5, p));      /* 3 * 0.5 > 1 */
    ck_assert_double_eq_tol(p[1], 1.0 / 3.0, 1e-15);
    double z[2] = { 0, 0 };
    ck_assert(!at_sel_propensities(z, 2, 0.0, p));
    ck_assert_double_eq_tol(p[0], 0.5, 1e-15);
}

DEFINE_TEST(test_the_chain_matches_python)
{
    at_sel_chain_t *c = malloc(sizeof(*c));
    ck_assert(c != NULL);
    at_sel_chain_init(c, ROOT);
    char hex[AT_SEL_HEX_LEN + 1];
    at_sel_hex(c->head, AT_SEL_LINK_BYTES, hex);
    ck_assert_str_eq(hex, "beb82821ef49b96d977db0cb47004e58bcea8d5a49ac6603ace0bd25af61e4be");
    unsigned char link[32], known[32];
    at_sel_chain_link(c, 1, link);
    at_sel_hex(link, 32, hex);
    ck_assert_str_eq(hex, "d9bd3a6a13eb58fed222fa46ca1b9cb1a65ff49b413484ed1cc7c895c0d6551c");
    at_sel_chain_link(c, AT_SEL_CHAIN_LENGTH, link);
    ck_assert(memcmp(link, ROOT, 32) == 0);
    at_sel_chain_link(c, 300, link);
    at_sel_chain_link(c, 7, known);
    ck_assert(at_sel_verify_link(c->head, 300, link, 0, NULL));
    ck_assert(at_sel_verify_link(c->head, 300, link, 7, known));
    ck_assert(!at_sel_verify_link(c->head, 301, link, 0, NULL));
    ck_assert(!at_sel_verify_link(c->head, 0, link, 0, NULL));
    ck_assert(at_sel_verify_rotation(c->head, ROOT));
    ck_assert(at_sel_chain_link(c, AT_SEL_CHAIN_LENGTH + 1, link) == -1);
    free(c);
}

DEFINE_TEST(test_the_declaration_resolves_and_refuses)
{
    at_selection_model_t m;
    _model(&m, 16);
    ck_assert(m.declared && m.has_probe);
    ck_assert_int_eq(at_selection_policy_for(&m, "q")->k, 2);
    ck_assert(at_selection_selects(&m, "one"));
    ck_assert(!at_selection_selects(&m, "unnamed"));
    const char *bad[] = { "{\"version\": 2}", "{\"version\": true}", "{\"version\": 1.0}",
                          "{\"version\": 1, \"default\": {\"floor\": \"0.5\"}}",
                          "{\"version\": 1, \"default\": {\"k\": 0}}",
                          "{\"version\": 1, \"log_records\": 0}",
                          "{\"version\": 1, \"surprise\": 1}" };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        ck_assert(!at_selection_parse_text(bad[i], &m, NULL, 0));
    ck_assert(at_selection_parse(NULL, &m, NULL, 0));
    ck_assert(!m.declared);
}

static char _dir[64];

static void _fresh_dir(void)
{
    snprintf(_dir, sizeof(_dir), "/tmp/at-sel-test-XXXXXX");
    ck_assert(mkdtemp(_dir) != NULL);
}

static void _drop_dir(const at_sel_requestor_t *r)
{
    unlink(r->chain_path);
    unlink(r->log_path);
    rmdir(_dir);
}

DEFINE_TEST(test_the_requestor_persists_and_bounds)
{
    at_selection_model_t m;
    _model(&m, 2);
    _fresh_dir();
    at_sel_requestor_t r;
    ck_assert_int_eq(at_sel_requestor_open(&r, &m, "negotiation", _dir, ROOT), 0);
    char peers[3][37] = { "a", "b", "c" };
    double w[3] = { 1, 1, 1 };
    bool sel[3];
    char draw[512];
    for (int i = 0; i < 3; i++)
    {
        char task[8];
        snprintf(task, sizeof(task), "t%d", i);
        ck_assert_int_eq(at_sel_decide(&r, task, "one", peers, w, 3, 1, 0.05, false, 0,
                                       sel, draw, sizeof(draw)), 0);
    }
    ck_assert_int_eq((int)r.rec_n, 2);
    ck_assert(at_sel_record_at(&r, 1) == NULL);
    at_sel_requestor_flush(&r, true);
    at_sel_requestor_close(&r);
    ck_assert_int_eq(at_sel_requestor_open(&r, &m, "negotiation", _dir, NULL), 0);
    ck_assert_int_eq((int)r.next_index, 4);
    ck_assert_int_eq((int)r.rec_n, 2);
    _drop_dir(&r);
    at_sel_requestor_close(&r);
}

DEFINE_TEST(test_the_audit_round_trips)
{
    at_selection_model_t m;
    _model(&m, 16);
    _fresh_dir();
    at_sel_requestor_t r;
    ck_assert_int_eq(at_sel_requestor_open(&r, &m, "negotiation", _dir, ROOT), 0);
    char peers[3][37] = { "a", "b", "c" };
    double w[3] = { 1, 2, 3 };
    bool sel[3];
    char draw[512];
    int ks[5] = { 1, 2, 2, 1, 2 };
    for (int i = 0; i < 5; i++)
        ck_assert_int_eq(at_sel_decide(&r, "t", ks[i] == 1 ? "one" : "q", peers, w, 3, ks[i],
                                       0.05, false, 0, sel, draw, sizeof(draw)), 0);
    at_sel_peer_t p = {0};
    long gap[AT_SEL_AUDIT_MAX_PER_GAP];
    size_t n_gap;
    json_t *f1 = json_loads("{}", 0, NULL);
    const at_sel_record_t *rec = at_sel_record_at(&r, 1);
    json_object_set_new(f1, "head", json_string(rec->head));
    json_object_set_new(f1, "index", json_integer(1));
    json_object_set_new(f1, "link", json_string(rec->link));
    ck_assert(at_sel_check_draw(&p, "R", f1, gap, &n_gap) == NULL);
    rec = at_sel_record_at(&r, 5);
    json_object_set_new(f1, "index", json_integer(5));
    json_object_set_new(f1, "link", json_string(rec->link));
    ck_assert(at_sel_check_draw(&p, "R", f1, gap, &n_gap) == NULL);
    ck_assert_int_eq((int)n_gap, 3);
    ck_assert_int_eq((int)gap[0], 2);
    json_object_set_new(f1, "index", json_integer(3));
    ck_assert_str_eq(at_sel_check_draw(&p, "R", f1, gap, &n_gap), "index_not_increasing");
    json_decref(f1);
    for (long i = 2; i <= 4; i++)
    {
        json_t *answer = at_sel_audit_answer(&r, i, "b");
        const char *finding = at_sel_check_answer(&p, "R", answer);
        ck_assert(finding == NULL || strcmp(finding, "audit_selected_uninvited") == 0);
        json_t *row = json_object_get(answer, "row");
        json_object_set_new(row, "selected", json_boolean(!json_is_true(json_object_get(row, "selected"))));
        finding = at_sel_check_answer(&p, "R", answer);
        ck_assert(finding != NULL);
        json_decref(answer);
    }
    json_t *unknown = at_sel_audit_answer(&r, 99, "b");
    ck_assert_str_eq(at_sel_check_answer(&p, "R", unknown), "audit_unknown");
    json_decref(unknown);
    at_sel_peer_free(&p);
    _drop_dir(&r);
    at_sel_requestor_close(&r);
}

DEFINE_TEST(test_the_estimate_matches_the_hand_computation)
{
    /* Mirrors test_selection.py TestEstimate.test_values_and_regret. */
    const char *text =
        "[{\"index\": 1, \"capability\": \"p\", \"purpose\": \"probe\", \"eligible\":"
        "  [{\"peer\": \"a\", \"propensity\": 0.5, \"selected\": true},"
        "   {\"peer\": \"b\", \"propensity\": 0.5, \"selected\": false}], \"outcome\": {\"a\": 1.0}},"
        " {\"index\": 2, \"capability\": \"p\", \"purpose\": \"probe\", \"eligible\":"
        "  [{\"peer\": \"a\", \"propensity\": 0.5, \"selected\": false},"
        "   {\"peer\": \"b\", \"propensity\": 0.5, \"selected\": true}], \"outcome\": {\"b\": 0.0}},"
        " {\"index\": 3, \"capability\": \"q\", \"purpose\": \"task\", \"eligible\":"
        "  [{\"peer\": \"a\", \"propensity\": 0.25, \"selected\": true},"
        "   {\"peer\": \"b\", \"propensity\": 0.75, \"selected\": false}], \"outcome\": {\"a\": 0.9}}]";
    json_t *arr = json_loads(text, 0, NULL);
    ck_assert(arr != NULL);
    at_sel_record_t *recs[3];
    for (int i = 0; i < 3; i++)
        ck_assert((recs[i] = at_sel_record_from_json(json_array_get(arr, (size_t)i))) != NULL);
    json_t *out = at_sel_estimate(recs, 3);
    double ra = 2.0 / 3.0, rb = 1.0 / 3.0;
    double ta = ra + (0.9 - ra) / 0.25, tb = rb;
    json_t *v = json_object_get(json_object_get(out, "q"), "value");
    ck_assert_double_eq_tol(json_real_value(json_object_get(v, "logged")), 0.25 * ta + 0.75 * tb, 1e-12);
    ck_assert_double_eq_tol(json_real_value(json_object_get(v, "uniform")), (ta + tb) / 2, 1e-12);
    ck_assert_double_eq_tol(json_real_value(json_object_get(v, "greedy")), ta, 1e-12);
    json_decref(out);
    json_decref(arr);
    for (int i = 0; i < 3; i++)
        at_sel_record_free(recs[i]);
}

RUN_TESTS(Selection,
          test_the_draw_matches_python,
          test_propensities_floor_and_degrade,
          test_the_chain_matches_python,
          test_the_declaration_resolves_and_refuses,
          test_the_requestor_persists_and_bounds,
          test_the_audit_round_trips,
          test_the_estimate_matches_the_hand_computation)
