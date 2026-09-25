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

/* Certificate-carrying task interfaces (R+D.md §12.3). One checker per row of
 * the oracle doc's certifying-algorithms table, plus the DRAT refutation
 * checker that makes an UNSAT claim cost something. */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <math.h>
#include <string.h>

#include "certificates/certificates.h"
#include "certificates/drat.h"
#include "certificates/rng.h"

static const char *DECL =
    "{\"version\":1,\"capabilities\":{"
    "\"d.matmul\":{\"checker\":\"matrix_product\",\"repetitions\":4},"
    "\"d.solve\":{\"checker\":\"linear_solve\"},"
    "\"d.lp\":{\"checker\":\"lp\",\"tolerance\":1e-6},"
    "\"d.sat\":{\"checker\":\"sat\"},"
    "\"d.route\":{\"checker\":\"path\"},"
    "\"d.flow\":{\"checker\":\"flow\"},"
    "\"d.sched\":{\"checker\":\"schedule\"},"
    "\"d.filter\":{\"checker\":\"state_estimation\",\"max_lag\":3,\"bound\":0.5},"
    "\"d.opinion\":{\"checker\":null,\"note\":\"a judgement call\"},"
    "\"d.migrating\":{\"checker\":\"sat\",\"required\":false}}}";

#define MATMUL "{\"a\":[[1,2],[3,4]],\"b\":[[5,6],[7,8]]}"
#define LP     "{\"a\":[[1,1]],\"b\":[2],\"c\":[1,1]}"
#define CNF    "{\"cnf\":[[1,2],[-1,2],[1,-2]]}"
#define ROUTE  "{\"edges\":[[\"s\",\"a\",1],[\"a\",\"t\",1],[\"s\",\"t\",5]]," \
               "\"source\":\"s\",\"target\":\"t\"}"
#define POT    "{\"potential\":{\"s\":0,\"a\":1,\"t\":2}}"
#define FLOWIN "{\"edges\":[[\"s\",\"a\",3],[\"a\",\"t\",2],[\"s\",\"t\",1]]," \
               "\"source\":\"s\",\"sink\":\"t\"}"
#define SCHED  "{\"jobs\":[{\"id\":\"x\",\"duration\":2},{\"id\":\"y\"," \
               "\"duration\":3}],\"precedences\":[[\"x\",\"y\"]],\"capacity\":1}"

static void _load(at_cert_model_t *m)
{
    char err[AT_CERT_ERR_LEN] = {0};
    ck_assert(at_cert_model_parse(DECL, m, err, sizeof(err)));
}

static at_cert_verdict_t _ev(const at_cert_model_t *m, const char *cap,
                             const char *res, const char *cert, const char *kw)
{
    return at_cert_evaluate(m, cap, res, cert, kw, 7, NULL, 0);
}

/**********************
 * Declaration
 **********************/

DEFINE_TEST(test_declaration_states_are_distinguishable)
{
    at_cert_model_t m;
    _load(&m);
    ck_assert_int_eq(m.n_capabilities, 10);
    const at_cert_capability_t *lp = at_cert_for_capability(&m, "d.lp");
    ck_assert(lp != NULL && lp->checker[0] != '\0');
    /* Declared uncertifiable is a THIRD state, distinct from both "certified"
     * and "never mentioned" -- somebody looked and concluded no witness
     * exists, and the inventory reports that differently. */
    const at_cert_capability_t *op = at_cert_for_capability(&m, "d.opinion");
    ck_assert(op != NULL && op->checker[0] == '\0');
    ck_assert(at_cert_for_capability(&m, "d.nothing") == NULL);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_unknown_checker_is_refused_not_read_as_uncertifiable)
{
    /* The important one: a typo must not quietly turn a certified capability
     * into an unchecked one, which is what `null` means and is
     * indistinguishable from it downstream. */
    at_cert_model_t m;
    char err[AT_CERT_ERR_LEN] = {0};
    ck_assert(at_cert_model_parse(
        "{\"capabilities\":{\"a\":{\"checker\":\"matrix-product\"}}}",
        &m, err, sizeof(err)) == false);
    ck_assert(strstr(err, "unknown checker") != NULL);
    /* A rejected declaration leaves the EMPTY model, never a partial one. */
    ck_assert_int_eq(m.n_capabilities, 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_malformed_declarations_are_refused)
{
    at_cert_model_t m;
    char err[AT_CERT_ERR_LEN] = {0};
    ck_assert(at_cert_model_parse(
        "{\"capabilities\":{\"a\":{\"checker\":\"lp\",\"tolerance\":-1}}}",
        &m, err, sizeof(err)) == false);
    /* "required": "yes" must NOT coerce to true. */
    ck_assert(at_cert_model_parse(
        "{\"capabilities\":{\"a\":{\"checker\":\"lp\",\"required\":\"yes\"}}}",
        &m, err, sizeof(err)) == false);
    ck_assert(at_cert_model_parse("{\"version\":2,\"capabilities\":{}}",
                                  &m, err, sizeof(err)) == false);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_empty_model_says_nothing)
{
    at_cert_model_t m;
    ck_assert(at_cert_model_parse(NULL, &m, NULL, 0));
    ck_assert(at_cert_model_enabled(&m) == false);
    ck_assert_int_eq(_ev(&m, "d.matmul", "[[1]]", NULL, MATMUL), AT_CERT_NONE);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_every_declared_kind_has_a_checker)
{
    /* A kind in the closed set with no implementation would fail at the first
     * task result that needed it, in production, on the requestor side. */
    ck_assert_int_eq(at_cert_checker_kind_count(), 8);
    for (int i = 0; at_cert_checker_kinds[i] != NULL; i++)
        ck_assert(at_cert_checker_known(at_cert_checker_kinds[i]));
    ck_assert(at_cert_checker_known("matrix-product") == false);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_splitmix64_matches_the_reference_stream)
{
    /* Pinned because the Python twin must emit the same stream: a Freivalds
     * challenge that differs between runtimes is a verdict that differs. */
    at_splitmix64_t rng;
    at_splitmix64_init(&rng, 42);
    ck_assert(at_splitmix64_next(&rng) == 13679457532755275413ULL);
    at_splitmix64_init(&rng, 0);
    ck_assert(at_splitmix64_next(&rng) == 16294208416658607535ULL);
}
END_TEST_DEFINITION()

/**********************
 * Linear algebra
 **********************/

DEFINE_TEST(test_freivalds_accepts_a_correct_product)
{
    at_cert_model_t m;
    _load(&m);
    ck_assert_int_eq(_ev(&m, "d.matmul", "[[19,22],[43,50]]", NULL, MATMUL),
                     AT_CERT_VALID);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_freivalds_catches_a_single_wrong_entry)
{
    at_cert_model_t m;
    _load(&m);
    ck_assert_int_eq(_ev(&m, "d.matmul", "[[19,22],[43,51]]", NULL, MATMUL),
                     AT_CERT_INVALID);
    ck_assert_int_eq(_ev(&m, "d.matmul", "[[19,22]]", NULL, MATMUL),
                     AT_CERT_INVALID);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_our_missing_inputs_never_score_the_peer)
{
    /* The fault is on this side; scoring it would punish a peer for our own
     * lost record. */
    at_cert_model_t m;
    _load(&m);
    ck_assert_int_eq(_ev(&m, "d.matmul", "[[19,22],[43,50]]", NULL, "{}"),
                     AT_CERT_INDETERMINATE);
    ck_assert_double_eq_tol(at_cert_score(AT_CERT_INDETERMINATE), 0.0, 1e-12);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_linear_solve_residual)
{
    at_cert_model_t m;
    _load(&m);
    const char *sys = "{\"a\":[[2,1],[1,3]],\"b\":[3,4]}";
    ck_assert_int_eq(_ev(&m, "d.solve", "[1.0,1.0]", NULL, sys), AT_CERT_VALID);
    ck_assert_int_eq(_ev(&m, "d.solve", "[1.0,2.0]", NULL, sys), AT_CERT_INVALID);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_lp_duality_gap_catches_a_feasible_suboptimum)
{
    /* The check that makes the dual worth carrying: the answer is entirely
     * feasible, and only the gap reveals it is not optimal. */
    at_cert_model_t m;
    _load(&m);
    ck_assert_int_eq(_ev(&m, "d.lp", "{\"x\":[2.0,0.0]}", "{\"dual\":[1.0]}", LP),
                     AT_CERT_VALID);
    ck_assert_int_eq(_ev(&m, "d.lp", "{\"x\":[3.0,0.0]}", "{\"dual\":[1.0]}", LP),
                     AT_CERT_INVALID);
    ck_assert_int_eq(_ev(&m, "d.lp", "{\"x\":[0.0,0.0]}", "{\"dual\":[1.0]}", LP),
                     AT_CERT_INVALID);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_farkas_certifies_infeasibility)
{
    /* The one claim with no answer to inspect: "there is no solution". */
    at_cert_model_t m;
    _load(&m);
    ck_assert_int_eq(_ev(&m, "d.lp", "{\"infeasible\":true}",
                         "{\"farkas\":[1.0]}",
                         "{\"a\":[[-1]],\"b\":[1],\"c\":[1]}"), AT_CERT_VALID);
    ck_assert_int_eq(_ev(&m, "d.lp", "{\"infeasible\":true}",
                         "{\"farkas\":[1.0]}",
                         "{\"a\":[[1]],\"b\":[1],\"c\":[1]}"), AT_CERT_INVALID);
}
END_TEST_DEFINITION()

/**********************
 * SAT and DRAT
 **********************/

DEFINE_TEST(test_sat_assignment)
{
    at_cert_model_t m;
    _load(&m);
    ck_assert_int_eq(_ev(&m, "d.sat", "{\"sat\":true}",
                         "{\"assignment\":[1,2]}", CNF), AT_CERT_VALID);
    ck_assert_int_eq(_ev(&m, "d.sat", "{\"sat\":true}",
                         "{\"assignment\":[-1,-2]}", CNF), AT_CERT_INVALID);
    ck_assert_int_eq(_ev(&m, "d.sat", "{\"sat\":true}",
                         "{\"assignment\":[1,-1]}", CNF), AT_CERT_INVALID);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_unsat_needs_a_refutation)
{
    /* "I searched and found nothing" is the claim a lying peer makes for free,
     * and is exactly what DRAT exists to make expensive. */
    at_cert_model_t m;
    _load(&m);
    ck_assert_int_eq(_ev(&m, "d.sat", "{\"sat\":false}", NULL,
                         "{\"cnf\":[[1],[-1]]}"), AT_CERT_ABSENT);
    ck_assert_int_eq(_ev(&m, "d.sat", "{\"sat\":false}", "{\"proof\":[[]]}",
                         "{\"cnf\":[[1],[-1]]}"), AT_CERT_VALID);
    ck_assert_int_eq(_ev(&m, "d.sat", "{\"sat\":false}", "{\"proof\":[[]]}", CNF),
                     AT_CERT_INVALID);
}
END_TEST_DEFINITION()

static at_drat_result_t _drat(const char *f, const char *p)
{
    json_error_t e;
    json_t *jf = json_loads(f, 0, &e);
    json_t *jp = json_loads(p, 0, &e);
    at_drat_result_t r = at_drat_check(jf, jp, 100000, NULL, 0);
    json_decref(jf);
    json_decref(jp);
    return r;
}

DEFINE_TEST(test_drat_multi_step_refutation)
{
    ck_assert_int_eq(_drat("[[1,2],[-1,2],[1,-2],[-1,-2]]", "[[2],[-2],[]]"),
                     AT_DRAT_VALID);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_drat_sound_lemmas_that_never_reach_the_empty_clause)
{
    /* The single most important check: a proof of true things that proves
     * nothing about satisfiability must not be accepted, or a peer could claim
     * UNSAT by emitting arbitrary valid inferences. */
    ck_assert_int_eq(_drat("[[1,2],[-1,2],[1,-2],[-1,-2]]", "[[2]]"),
                     AT_DRAT_INVALID);
    ck_assert_int_eq(_drat("[[1,2]]", "[[3]]"), AT_DRAT_INVALID);
    /* And a lemma that is neither RUP nor RAT is rejected outright, before
     * the empty clause is ever reached. */
    ck_assert_int_eq(_drat("[[1,2],[-1,-2]]", "[[1],[]]"), AT_DRAT_INVALID);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_drat_deletion_removes_only_one_match)
{
    /* Deleting every duplicate would strip clauses the proof still needs, and
     * a checker that drops one the solver kept rejects a valid proof. */
    ck_assert_int_eq(_drat("[[1],[1],[-1]]", "[{\"d\":[1]},[]]"), AT_DRAT_VALID);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_drat_malformed_is_distinct_from_wrong)
{
    ck_assert_int_eq(_drat("[[1]]", "[[0]]"), AT_DRAT_MALFORMED);
    /* A tautological lemma adds nothing and is a no-op, not an error. */
    ck_assert_int_eq(_drat("[[1],[-1]]", "[[5,-5],[]]"), AT_DRAT_VALID);
}
END_TEST_DEFINITION()

/**********************
 * Graph and schedule
 **********************/

DEFINE_TEST(test_path_needs_a_feasible_potential_not_an_assertion)
{
    /* A bound the peer merely ASSERTS certifies nothing -- a detour can assert
     * a bound equal to its own cost. What is checkable is the bound's own
     * witness: node prices feasible on every edge, the LP dual. */
    at_cert_model_t m;
    _load(&m);
    ck_assert_int_eq(_ev(&m, "d.route", "{\"path\":[\"s\",\"a\",\"t\"]}", POT,
                         ROUTE), AT_CERT_VALID);
    ck_assert_int_eq(_ev(&m, "d.route", "{\"path\":[\"s\",\"t\"]}", POT, ROUTE),
                     AT_CERT_INVALID);
    ck_assert_int_eq(_ev(&m, "d.route", "{\"path\":[\"s\",\"t\"]}",
                         "{\"lower_bound\":5}", ROUTE), AT_CERT_INVALID);
    ck_assert_int_eq(_ev(&m, "d.route", "{\"path\":[\"s\",\"t\"]}",
                         "{\"potential\":{\"s\":0,\"a\":1,\"t\":9}}", ROUTE),
                     AT_CERT_INVALID);
    ck_assert_int_eq(_ev(&m, "d.route", "{\"path\":[\"s\",\"x\",\"t\"]}", POT,
                         ROUTE), AT_CERT_INVALID);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_flow_needs_the_cut_as_well_as_feasibility)
{
    /* A feasible flow alone certifies only that the peer returned A flow. */
    at_cert_model_t m;
    _load(&m);
    const char *good = "{\"flow\":[[\"s\",\"a\",2],[\"a\",\"t\",2],"
                       "[\"s\",\"t\",1]],\"value\":3}";
    ck_assert_int_eq(_ev(&m, "d.flow", good, "{\"cut\":[\"s\",\"a\"]}", FLOWIN),
                     AT_CERT_VALID);
    ck_assert_int_eq(_ev(&m, "d.flow",
                         "{\"flow\":[[\"s\",\"a\",1],[\"a\",\"t\",1]]}",
                         "{\"cut\":[\"s\",\"a\"]}", FLOWIN), AT_CERT_INVALID);
    ck_assert_int_eq(_ev(&m, "d.flow",
                         "{\"flow\":[[\"s\",\"a\",3],[\"a\",\"t\",2],"
                         "[\"s\",\"t\",1]]}", "{\"cut\":[\"s\",\"a\"]}", FLOWIN),
                     AT_CERT_INVALID);
    ck_assert_int_eq(_ev(&m, "d.flow",
                         "{\"flow\":[[\"s\",\"a\",9],[\"a\",\"t\",9],"
                         "[\"s\",\"t\",1]]}", "{\"cut\":[\"s\",\"a\"]}", FLOWIN),
                     AT_CERT_INVALID);
    ck_assert_int_eq(_ev(&m, "d.flow", good, "{\"cut\":[\"s\",\"a\",\"t\"]}",
                         FLOWIN), AT_CERT_INVALID);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_schedule_feasibility_and_the_claimed_makespan)
{
    at_cert_model_t m;
    _load(&m);
    ck_assert_int_eq(_ev(&m, "d.sched", "{\"start\":{\"x\":0,\"y\":2}}",
                         "{\"makespan\":5}", SCHED), AT_CERT_VALID);
    ck_assert_int_eq(_ev(&m, "d.sched", "{\"start\":{\"x\":0,\"y\":1}}",
                         "{\"makespan\":4}", SCHED), AT_CERT_INVALID);
    /* Claiming a better schedule than the one produced is the failure mode
     * worth catching, and it is invisible without checking the claim. */
    ck_assert_int_eq(_ev(&m, "d.sched", "{\"start\":{\"x\":0,\"y\":2}}",
                         "{\"makespan\":3}", SCHED), AT_CERT_INVALID);
    ck_assert_int_eq(_ev(&m, "d.sched", "{\"start\":{\"x\":0,\"y\":0}}",
                         "{\"makespan\":3}",
                         "{\"jobs\":[{\"id\":\"x\",\"duration\":2},"
                         "{\"id\":\"y\",\"duration\":3}],\"capacity\":1}"),
                     AT_CERT_INVALID);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_schedule_ids_are_compared_as_text)
{
    /* Start times arrive as a JSON object, whose keys are strings by
     * construction, so an integer job id would never match its own start and
     * every such schedule would read as missing one. */
    at_cert_model_t m;
    _load(&m);
    ck_assert_int_eq(_ev(&m, "d.sched", "{\"start\":{\"1\":0,\"2\":2}}",
                         "{\"makespan\":5}",
                         "{\"jobs\":[{\"id\":1,\"duration\":2},"
                         "{\"id\":2,\"duration\":3}],\"precedences\":[[1,2]],"
                         "\"capacity\":1}"), AT_CERT_VALID);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_state_estimation_whiteness)
{
    at_cert_model_t m;
    _load(&m);
    ck_assert_int_eq(_ev(&m, "d.filter", "{\"innovations\":[1,2,3,4,5,6,7,8]}",
                         NULL, "{}"), AT_CERT_INVALID);
    /* A constant sequence has no spectrum: INDETERMINATE, not a failure. */
    ck_assert_int_eq(_ev(&m, "d.filter", "{\"innovations\":[2,2,2,2,2,2]}",
                         NULL, "{}"), AT_CERT_INDETERMINATE);
    ck_assert_int_eq(_ev(&m, "d.filter", "{\"innovations\":[1,2,3]}", NULL, "{}"),
                     AT_CERT_INDETERMINATE);
}
END_TEST_DEFINITION()

/**********************
 * Declaration states and scoring
 **********************/

DEFINE_TEST(test_uncertifiable_and_undeclared_produce_no_verdict)
{
    at_cert_model_t m;
    _load(&m);
    ck_assert_int_eq(_ev(&m, "d.opinion", "\"yes\"", NULL, "{}"), AT_CERT_NONE);
    ck_assert_int_eq(_ev(&m, "d.other", "\"yes\"", NULL, "{}"), AT_CERT_NONE);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_optional_witness_may_be_absent_but_is_checked_when_present)
{
    at_cert_model_t m;
    _load(&m);
    ck_assert_int_eq(_ev(&m, "d.migrating", "{\"sat\":true}", NULL,
                         "{\"cnf\":[[1]]}"), AT_CERT_NONE);
    ck_assert_int_eq(_ev(&m, "d.migrating", "{\"sat\":true}",
                         "{\"assignment\":[-1]}", "{\"cnf\":[[1]]}"),
                     AT_CERT_INVALID);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_scores_and_names)
{
    ck_assert_double_eq_tol(at_cert_score(AT_CERT_VALID), 0.9, 1e-12);
    ck_assert_double_eq_tol(at_cert_score(AT_CERT_INVALID), 0.1, 1e-12);
    ck_assert_double_eq_tol(at_cert_score(AT_CERT_ABSENT), 0.3, 1e-12);
    ck_assert_double_eq_tol(at_cert_score(AT_CERT_NONE), 0.0, 1e-12);
    ck_assert_str_eq(at_cert_verdict_name(AT_CERT_VALID), "valid");
    ck_assert_str_eq(at_cert_verdict_name(AT_CERT_INDETERMINATE),
                     "indeterminate");
}
END_TEST_DEFINITION()

/**********************
 * Wrapper and inventory
 **********************/

DEFINE_TEST(test_wrapper_splits_answer_from_witness)
{
    char wrapped[512] = {0}, value[256] = {0}, cert[256] = {0};
    ck_assert(at_cert_wrap_result("{\"x\":[2.0]}", "{\"dual\":[1.0]}",
                                  wrapped, sizeof(wrapped)));
    ck_assert(at_cert_split_result(wrapped, value, sizeof(value),
                                   cert, sizeof(cert)));
    ck_assert(strstr(value, "\"x\"") != NULL);
    ck_assert(strstr(cert, "\"dual\"") != NULL);
    /* An ordinary answer is not wrapped and passes through untouched -- the
     * split must never be a guess, or an answer that happened to carry those
     * keys would be torn in half. */
    ck_assert(at_cert_split_result("[[19,22]]", value, sizeof(value),
                                   cert, sizeof(cert)) == false);
    ck_assert_str_eq(value, "[[19,22]]");
    ck_assert_str_eq(cert, "");
    ck_assert(at_cert_split_result("done", value, sizeof(value),
                                   cert, sizeof(cert)) == false);
    ck_assert_str_eq(value, "done");
}
END_TEST_DEFINITION()

DEFINE_TEST(test_inventory_separates_four_states_worst_first)
{
    at_cert_model_t m;
    _load(&m);
    const char *registered[] = {"d.matmul", "at.handshake"};
    at_cert_inv_row_t rows[AT_CERT_MAX_CAPABILITIES];
    int n = at_cert_inventory(&m, registered, 2, rows,
                              AT_CERT_MAX_CAPABILITIES);
    ck_assert_int_eq(n, 11);          /* 10 declared + 1 unexamined */
    /* Worst-known first: the state that accumulates silently is the one an
     * operator most needs to see. */
    ck_assert_int_eq(rows[0].state, AT_CERT_INV_UNEXAMINED);
    ck_assert_str_eq(rows[0].name, "at.handshake");

    int certified = 0, optional = 0, uncertifiable = 0, unexamined = 0;
    for (int i = 0; i < n; i++)
    {
        switch (rows[i].state)
        {
        case AT_CERT_INV_CERTIFIED:      certified++;      break;
        case AT_CERT_INV_OPTIONAL:       optional++;       break;
        case AT_CERT_INV_UNCERTIFIABLE:  uncertifiable++;  break;
        case AT_CERT_INV_UNEXAMINED:     unexamined++;     break;
        }
    }
    ck_assert_int_eq(certified, 8);
    ck_assert_int_eq(optional, 1);
    ck_assert_int_eq(uncertifiable, 1);
    ck_assert_int_eq(unexamined, 1);

    char report[4096] = {0};
    at_cert_inventory_format(rows, n, report, sizeof(report));
    ck_assert(strstr(report, "never examined") != NULL);
    ck_assert(strstr(report, "a judgement call") != NULL);   /* the note travels */
    ck_assert(strstr(report, "not mentioned in the declaration") != NULL);
}
END_TEST_DEFINITION()

RUN_TESTS(Certificates,
          test_declaration_states_are_distinguishable,
          test_unknown_checker_is_refused_not_read_as_uncertifiable,
          test_malformed_declarations_are_refused,
          test_empty_model_says_nothing,
          test_every_declared_kind_has_a_checker,
          test_splitmix64_matches_the_reference_stream,
          test_freivalds_accepts_a_correct_product,
          test_freivalds_catches_a_single_wrong_entry,
          test_our_missing_inputs_never_score_the_peer,
          test_linear_solve_residual,
          test_lp_duality_gap_catches_a_feasible_suboptimum,
          test_farkas_certifies_infeasibility,
          test_sat_assignment,
          test_unsat_needs_a_refutation,
          test_drat_multi_step_refutation,
          test_drat_sound_lemmas_that_never_reach_the_empty_clause,
          test_drat_deletion_removes_only_one_match,
          test_drat_malformed_is_distinct_from_wrong,
          test_path_needs_a_feasible_potential_not_an_assertion,
          test_flow_needs_the_cut_as_well_as_feasibility,
          test_schedule_feasibility_and_the_claimed_makespan,
          test_schedule_ids_are_compared_as_text,
          test_state_estimation_whiteness,
          test_uncertifiable_and_undeclared_produce_no_verdict,
          test_optional_witness_may_be_absent_but_is_checked_when_present,
          test_scores_and_names,
          test_wrapper_splits_answer_from_witness,
          test_inventory_separates_four_states_worst_first)
