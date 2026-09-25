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

/* Physical consistency as a pre-statistical falsification layer (R+D.md
 * §12.2). The units table and the grammar are pinned here as well as in the
 * conformance corpus, because they are the axioms: physics.json declares which
 * quantity a capability reports, and never what a newton is. */

#define DEBUG_TESTS 1
#include "test_setup.h"

#include <math.h>
#include <string.h>

#include "physics/physics.h"
#include "physics/units.h"

/**********************
 * Units
 **********************/

DEFINE_TEST(test_unit_parses_compound_expressions)
{
    at_dimension_t d;
    ck_assert(at_parse_unit("m/s", &d, NULL, 0));
    ck_assert_int_eq(d.exponents[0], 1);   /* m  */
    ck_assert_int_eq(d.exponents[2], -1);  /* s  */
    ck_assert(at_parse_unit("kg*m/s^2", &d, NULL, 0));
    ck_assert_int_eq(d.exponents[0], 1);
    ck_assert_int_eq(d.exponents[1], 1);
    ck_assert_int_eq(d.exponents[2], -2);
    /* "m3" is "m^3": no symbol in the table ends in a digit, which is what
     * makes the caret optional and lets a services-style "ug/m3" parse. */
    ck_assert(at_parse_unit("ug/m3", &d, NULL, 0));
    ck_assert_int_eq(d.exponents[0], -3);
    ck_assert_int_eq(d.exponents[1], 1);
    ck_assert(at_parse_unit("1/s", &d, NULL, 0));
    ck_assert_int_eq(d.exponents[2], -1);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_unit_dimensional_equality_ignores_scale)
{
    at_dimension_t n, kgms, w, js, km, m;
    ck_assert(at_parse_unit("N", &n, NULL, 0));
    ck_assert(at_parse_unit("kg*m/s^2", &kgms, NULL, 0));
    ck_assert(at_same_dimension(&n, &kgms));
    ck_assert(at_parse_unit("W", &w, NULL, 0));
    ck_assert(at_parse_unit("J/s", &js, NULL, 0));
    ck_assert(at_same_dimension(&w, &js));
    /* A prefix is a conversion, not a different dimension: that distinction
     * is the whole of the coherence check. */
    ck_assert(at_parse_unit("km", &km, NULL, 0));
    ck_assert(at_parse_unit("m", &m, NULL, 0));
    ck_assert(at_same_dimension(&km, &m));
    ck_assert_double_eq_tol(km.scale, 1000.0, 1e-12);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_unit_affine_only_whole)
{
    at_dimension_t d;
    char err[AT_UNIT_ERR_LEN] = {0};
    ck_assert(at_parse_unit("degC", &d, NULL, 0));
    ck_assert_double_eq_tol(at_dimension_to_si(&d, 20.0), 293.15, 1e-9);
    ck_assert(at_parse_unit("degF", &d, NULL, 0));
    ck_assert_double_eq_tol(at_dimension_to_si(&d, 32.0), 273.15, 1e-9);
    ck_assert_double_eq_tol(at_dimension_to_si(&d, 212.0), 373.15, 1e-9);
    /* Refused inside a compound expression: the offset does not distribute
     * over the quotient, and silently dropping it would turn a 20 degC claim
     * into 20 K and refute an honest peer. */
    ck_assert(at_parse_unit("degC/s", &d, err, sizeof(err)) == false);
    ck_assert(strstr(err, "affine") != NULL);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_unit_unknown_symbol_is_refused_not_guessed)
{
    at_dimension_t d;
    char err[AT_UNIT_ERR_LEN] = {0};
    ck_assert(at_parse_unit("furlong", &d, err, sizeof(err)) == false);
    ck_assert(strstr(err, "unknown symbol") != NULL);
    /* Case-sensitive, as SI is: T is the tesla, t the tonne. */
    at_dimension_t tesla, tonne;
    ck_assert(at_parse_unit("T", &tesla, NULL, 0));
    ck_assert(at_parse_unit("t", &tonne, NULL, 0));
    ck_assert(at_same_dimension(&tesla, &tonne) == false);
}
END_TEST_DEFINITION()

/**********************
 * Declaration
 **********************/

static const char *MODEL_JSON =
    "{\"version\":1,\"window_sec\":60.0,\"quantities\":{"
    "\"sat.solar-power\":{\"capability\":\"sat.solar\",\"unit\":\"W\","
    "\"min\":0.0,\"max\":2000.0,\"tolerance\":5.0,\"max_rate\":250.0},"
    "\"sat.load-power\":{\"capability\":\"sat.load\",\"unit\":\"W\","
    "\"min\":0.0,\"max\":2000.0},"
    "\"sat.batt-rate\":{\"capability\":\"sat.batt\",\"unit\":\"W\","
    "\"min\":-2000.0,\"max\":2000.0},"
    "\"sat.bus-temp\":{\"capability\":\"sat.temp\",\"unit\":\"degC\","
    "\"min\":-80.0,\"max\":120.0,\"max_rate\":2.0,\"tolerance\":1.0},"
    "\"sat.position\":{\"capability\":\"sat.pos\",\"unit\":\"m\","
    "\"components\":3,\"max_rate\":8000.0,\"max_accel\":50.0}},"
    "\"relations\":[{\"name\":\"power-balance\",\"terms\":{"
    "\"sat.solar-power\":1.0,\"sat.load-power\":-1.0,\"sat.batt-rate\":-1.0},"
    "\"constant\":0.0,\"tolerance\":2.0,\"window_sec\":5.0}]}";

DEFINE_TEST(test_model_parses_and_converts_bounds_to_si)
{
    at_physics_model_t m;
    char err[AT_PHYS_ERR_LEN] = {0};
    ck_assert(at_physics_model_parse(MODEL_JSON, &m, err, sizeof(err)));
    ck_assert_int_eq(m.n_quantities, 5);
    ck_assert_int_eq(m.n_relations, 1);
    /* Bounds are stated in the DECLARED unit and converted once, so a peer
     * reporting kilowatts is compared with one reporting watts on equal
     * terms. -80 degC is 193.15 K. */
    for (int i = 0; i < m.n_quantities; i++)
    {
        if (strcmp(m.quantities[i].name, "sat.bus-temp") == 0)
        {
            ck_assert_double_eq_tol(m.quantities[i].si_min, 193.15, 1e-9);
            ck_assert_double_eq_tol(m.quantities[i].si_max, 393.15, 1e-9);
            /* A RATE is a difference per second: the offset cancels and only
             * the scale applies, or every Celsius rate bound would gain
             * 273.15 K/s. */
            ck_assert_double_eq_tol(m.quantities[i].si_max_rate, 2.0, 1e-9);
        }
    }
}
END_TEST_DEFINITION()

DEFINE_TEST(test_model_rejects_incoherent_relation)
{
    /* Every term of a parity relation must share one dimension. Summing a
     * power and a temperature has no residual worth computing, and catching it
     * at load is the difference between an operator error and a peer refuted
     * by arithmetic on nonsense. */
    const char *bad =
        "{\"quantities\":{"
        "\"p\":{\"capability\":\"c.p\",\"unit\":\"W\"},"
        "\"k\":{\"capability\":\"c.k\",\"unit\":\"K\"}},"
        "\"relations\":[{\"name\":\"nonsense\",\"terms\":{\"p\":1.0,\"k\":1.0}}]}";
    at_physics_model_t m;
    char err[AT_PHYS_ERR_LEN] = {0};
    ck_assert(at_physics_model_parse(bad, &m, err, sizeof(err)) == false);
    ck_assert(strstr(err, "must share one dimension") != NULL);
    /* A rejected declaration leaves the EMPTY model, never a partial one:
     * checking a subset of what the operator declared is worse than not
     * checking, because the operator believes it is all being verified. */
    ck_assert_int_eq(m.n_quantities, 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_model_rejects_duplicate_capability_and_unknown_unit)
{
    at_physics_model_t m;
    char err[AT_PHYS_ERR_LEN] = {0};
    const char *dup =
        "{\"quantities\":{\"a\":{\"capability\":\"c\",\"unit\":\"W\"},"
        "\"b\":{\"capability\":\"c\",\"unit\":\"W\"}}}";
    ck_assert(at_physics_model_parse(dup, &m, err, sizeof(err)) == false);
    ck_assert(strstr(err, "already reported") != NULL);
    const char *unknown =
        "{\"quantities\":{\"a\":{\"capability\":\"c\",\"unit\":\"furlong\"}}}";
    ck_assert(at_physics_model_parse(unknown, &m, err, sizeof(err)) == false);
    ck_assert(strstr(err, "unknown symbol") != NULL);
    const char *undeclared =
        "{\"quantities\":{\"a\":{\"capability\":\"c\",\"unit\":\"W\"}},"
        "\"relations\":[{\"name\":\"r\",\"terms\":{\"missing\":1.0}}]}";
    ck_assert(at_physics_model_parse(undeclared, &m, err, sizeof(err)) == false);
    ck_assert(strstr(err, "undeclared quantity") != NULL);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_empty_model_says_nothing)
{
    /* The layer is OPT-IN. A physical refutation is the hardest evidence AT
     * produces, and a checker that guessed at undeclared quantities would be
     * manufacturing it. */
    at_physics_checker_t c;
    at_physics_checker_init(&c, NULL);
    ck_assert(at_physics_checker_enabled(&c) == false);
    ck_assert_int_eq(at_physics_check(&c, "sat.solar", "-5.0", "A", 0.0,
                                      NULL, NULL, 0), AT_PHYSICS_NONE);
}
END_TEST_DEFINITION()

/**********************
 * Single-claim refutation
 **********************/

static void _load(at_physics_checker_t *c)
{
    at_physics_model_t m;
    char err[AT_PHYS_ERR_LEN] = {0};
    ck_assert(at_physics_model_parse(MODEL_JSON, &m, err, sizeof(err)));
    at_physics_checker_init(c, &m);
}

static at_physics_verdict_t _check(at_physics_checker_t *c, const char *cap,
                                   const char *result, const char *subject,
                                   double now, double *score)
{
    return at_physics_check(c, cap, result, subject, now, score, NULL, 0);
}

DEFINE_TEST(test_undeclared_capability_and_absent_answer_say_nothing)
{
    at_physics_checker_t c;
    _load(&c);
    ck_assert_int_eq(_check(&c, "other.thing", "42", "A", 0.0, NULL),
                     AT_PHYSICS_NONE);
    /* An absent answer is not a FALSE claim; the completion arm handles it. */
    ck_assert_int_eq(_check(&c, "sat.solar", NULL, "A", 0.0, NULL),
                     AT_PHYSICS_NONE);
    ck_assert_int_eq(_check(&c, "sat.solar", "", "A", 0.0, NULL),
                     AT_PHYSICS_NONE);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_passing_physics_earns_nothing)
{
    /* A claim inside the feasible set is merely NOT REFUTED. Returning a good
     * score here would turn a falsification layer into a plausibility grade. */
    at_physics_checker_t c;
    _load(&c);
    ck_assert_int_eq(_check(&c, "sat.solar", "500.0", "A", 0.0, NULL),
                     AT_PHYSICS_NONE);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_bounds_and_shape_refute)
{
    at_physics_checker_t c;
    double score = 0.0;
    _load(&c);
    ck_assert_int_eq(_check(&c, "sat.solar", "-5.0", "A", 1.0, &score),
                     AT_PHYSICS_REFUTED);
    ck_assert_double_eq_tol(score, AT_PHYSICS_REFUTED_SCORE, 1e-12);
    /* A declared quantity answered with prose is a refutation, not a dud: the
     * peer claimed something that is not a quantity at all. */
    ck_assert_int_eq(_check(&c, "sat.solar", "lots", "A", 2.0, NULL),
                     AT_PHYSICS_REFUTED);
    ck_assert_int_eq(_check(&c, "sat.pos", "[1.0,2.0]", "A", 3.0, NULL),
                     AT_PHYSICS_REFUTED);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_dimension_mismatch_refutes_but_prefix_converts)
{
    at_physics_checker_t c;
    _load(&c);
    ck_assert_int_eq(_check(&c, "sat.solar", "{\"value\":500,\"unit\":\"kg\"}",
                            "A", 1.0, NULL), AT_PHYSICS_REFUTED);
    ck_assert_int_eq(_check(&c, "sat.solar", "{\"value\":500,\"unit\":\"furlong\"}",
                            "A", 2.0, NULL), AT_PHYSICS_REFUTED);
    /* 0.5 kW is 500 W: in bounds, and nothing to say. */
    ck_assert_int_eq(_check(&c, "sat.solar", "{\"value\":0.5,\"unit\":\"kW\"}",
                            "A", 3.0, NULL), AT_PHYSICS_NONE);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_rate_against_own_previous_claim_refutes)
{
    at_physics_checker_t c;
    _load(&c);
    ck_assert_int_eq(_check(&c, "sat.temp", "20.0", "A", 100.0, NULL),
                     AT_PHYSICS_NONE);
    ck_assert_int_eq(_check(&c, "sat.temp", "22.0", "A", 101.0, NULL),
                     AT_PHYSICS_NONE);
    /* 58 degC/s against a declared 2: a conflict of size one, so refuted
     * outright rather than merely implicated. */
    ck_assert_int_eq(_check(&c, "sat.temp", "80.0", "A", 102.0, NULL),
                     AT_PHYSICS_REFUTED);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_refuted_observation_is_not_stored)
{
    /* Load-bearing: the store feeds the intersection and the residuals, so
     * admitting a claim already known to be impossible would let one liar
     * manufacture conflicts against honest peers. After the refuted 80 above,
     * A's latest is still 22, so a return to 23 one second later is fine --
     * where storing 80 would have made 23 a 57 degC/s drop. */
    at_physics_checker_t c;
    _load(&c);
    _check(&c, "sat.temp", "20.0", "A", 100.0, NULL);
    _check(&c, "sat.temp", "22.0", "A", 101.0, NULL);
    ck_assert_int_eq(_check(&c, "sat.temp", "80.0", "A", 102.0, NULL),
                     AT_PHYSICS_REFUTED);
    ck_assert_int_eq(_check(&c, "sat.temp", "23.0", "A", 103.0, NULL),
                     AT_PHYSICS_NONE);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_vector_rate_uses_the_magnitude)
{
    at_physics_checker_t c;
    _load(&c);
    ck_assert_int_eq(_check(&c, "sat.pos", "[0.0,0.0,0.0]", "A", 300.0, NULL),
                     AT_PHYSICS_NONE);
    ck_assert_int_eq(_check(&c, "sat.pos", "[1000.0,0.0,0.0]", "A", 301.0, NULL),
                     AT_PHYSICS_NONE);
    ck_assert_int_eq(_check(&c, "sat.pos", "[1000000.0,0.0,0.0]", "A", 302.0, NULL),
                     AT_PHYSICS_REFUTED);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_unattributed_result_runs_only_identity_free_checks)
{
    /* A fan-out is not attributable to one peer. Shape, unit, arity and bounds
     * still apply; nothing is stored, because filing several peers' claims
     * under one key would manufacture conflicts between a peer and itself. */
    at_physics_checker_t c;
    _load(&c);
    ck_assert_int_eq(_check(&c, "sat.solar", "-5.0", NULL, 400.0, NULL),
                     AT_PHYSICS_REFUTED);
    ck_assert_int_eq(_check(&c, "sat.temp", "20.0", NULL, 400.0, NULL),
                     AT_PHYSICS_NONE);
    ck_assert_int_eq(_check(&c, "sat.temp", "20.0", NULL, 401.0, NULL),
                     AT_PHYSICS_NONE);
    /* Nothing was stored, so a wild swing is still not a rate violation. */
    ck_assert_int_eq(_check(&c, "sat.temp", "119.0", NULL, 402.0, NULL),
                     AT_PHYSICS_NONE);
}
END_TEST_DEFINITION()

/**********************
 * Diagnosis
 **********************/

DEFINE_TEST(test_minimal_hitting_sets)
{
    uint64_t out[AT_PHYS_MAX_QUANTITIES];
    /* One conflict {A}: the singleton case, which is how every single-claim
     * refutation reaches the same machinery. */
    uint64_t single[] = {0x1};
    ck_assert_int_eq(at_physics_minimal_hitting_sets(single, 1, out, 8), 1);
    ck_assert(out[0] == 0x1);
    /* {A,B} and {A,C}: minimal diagnoses are {A} and {B,C}. NOT just {A} --
     * see the subset-minimal note in physics.c. */
    uint64_t two[] = {0x3, 0x5};
    int n = at_physics_minimal_hitting_sets(two, 2, out, 8);
    ck_assert_int_eq(n, 2);
    bool saw_a = false, saw_bc = false;
    for (int i = 0; i < n; i++)
    {
        if (out[i] == 0x1) saw_a = true;
        if (out[i] == 0x6) saw_bc = true;
    }
    ck_assert(saw_a && saw_bc);
    /* A conflict that is a proper superset of another cannot constrain the
     * answer and is pruned. */
    uint64_t superset[] = {0x3, 0x7};
    ck_assert_int_eq(at_physics_minimal_hitting_sets(superset, 2, out, 8), 2);
    /* No conflicts: exactly one minimal hitting set, the empty one. */
    ck_assert_int_eq(at_physics_minimal_hitting_sets(NULL, 0, out, 8), 1);
    ck_assert(out[0] == 0);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_disagreeing_peers_are_implicated_not_refuted)
{
    /* Two peers reporting incompatible values means ONE of them is wrong and
     * the physics does not say which. Scoring both as refuted would let any
     * peer refute an honest one by lying about the same quantity. */
    at_physics_checker_t c;
    double score = 0.0;
    _load(&c);
    ck_assert_int_eq(_check(&c, "sat.temp", "20.0", "A", 100.0, NULL),
                     AT_PHYSICS_NONE);
    ck_assert_int_eq(_check(&c, "sat.temp", "60.0", "B", 101.0, &score),
                     AT_PHYSICS_IMPLICATED);
    ck_assert_double_eq_tol(score, AT_PHYSICS_IMPLICATED_SCORE, 1e-12);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_lone_outlier_against_two_is_still_only_implicated)
{
    /* The subset-minimal choice, tested where it bites: conflicts {C,A} and
     * {C,B} have minimal diagnoses {C} AND {A,B}, so C is in some but not all.
     * Preferring the smaller would convict C -- majority rule wearing
     * physics' clothes, which R+D.md §12.8 rules out. */
    at_physics_checker_t c;
    _load(&c);
    _check(&c, "sat.temp", "20.0", "A", 100.0, NULL);
    _check(&c, "sat.temp", "20.5", "B", 101.0, NULL);
    ck_assert_int_eq(_check(&c, "sat.temp", "90.0", "C", 102.0, NULL),
                     AT_PHYSICS_IMPLICATED);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_tolerance_zero_disables_the_intersection)
{
    /* A zero-width interval would make every distinct float a conflict, which
     * would report disagreement between two honest sensors of the same thing.
     * sat.load-power declares no tolerance. */
    at_physics_checker_t c;
    _load(&c);
    _check(&c, "sat.load", "400.0", "A", 100.0, NULL);
    ck_assert_int_eq(_check(&c, "sat.load", "1200.0", "B", 101.0, NULL),
                     AT_PHYSICS_NONE);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_stale_observations_do_not_conflict)
{
    /* Peers legitimately disagree about a quantity that has moved on since;
     * calling that a conflict refutes honest peers. window_sec is 60. */
    at_physics_checker_t c;
    _load(&c);
    _check(&c, "sat.temp", "20.0", "A", 100.0, NULL);
    ck_assert_int_eq(_check(&c, "sat.temp", "90.0", "B", 400.0, NULL),
                     AT_PHYSICS_NONE);
}
END_TEST_DEFINITION()

/**********************
 * Parity relations
 **********************/

DEFINE_TEST(test_parity_residual_conflicts_all_contributors)
{
    /* 1000 - 400 - 600 = 0 balances; 1000 - 400 - 100 = 500 does not. The
     * conflict is all three reporters, so each is only implicated: a violated
     * conservation law does not say which term was the lie. */
    at_physics_checker_t c;
    _load(&c);
    ck_assert_int_eq(_check(&c, "sat.solar", "1000.0", "A", 200.0, NULL),
                     AT_PHYSICS_NONE);
    ck_assert_int_eq(_check(&c, "sat.load", "400.0", "B", 200.0, NULL),
                     AT_PHYSICS_NONE);
    ck_assert_int_eq(_check(&c, "sat.batt", "600.0", "C", 200.0, NULL),
                     AT_PHYSICS_NONE);
    ck_assert_int_eq(_check(&c, "sat.batt", "100.0", "C", 201.0, NULL),
                     AT_PHYSICS_IMPLICATED);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_parity_from_one_peer_alone_refutes_it)
{
    /* When one peer supplied every term, the conflict is of size one -- the
     * peer contradicted itself, and there is no other story. */
    at_physics_checker_t c;
    _load(&c);
    _check(&c, "sat.solar", "1000.0", "S", 200.0, NULL);
    _check(&c, "sat.load", "400.0", "S", 200.0, NULL);
    ck_assert_int_eq(_check(&c, "sat.batt", "100.0", "S", 200.0, NULL),
                     AT_PHYSICS_REFUTED);
}
END_TEST_DEFINITION()

DEFINE_TEST(test_parity_incomplete_or_stale_is_not_evaluated)
{
    /* A residual over terms that are missing or stale invents violations out
     * of ordinary change. The relation's own window is 5 s. */
    at_physics_checker_t c;
    _load(&c);
    ck_assert_int_eq(_check(&c, "sat.solar", "1000.0", "A", 200.0, NULL),
                     AT_PHYSICS_NONE);   /* two terms still missing */
    _check(&c, "sat.load", "400.0", "B", 200.0, NULL);
    ck_assert_int_eq(_check(&c, "sat.batt", "100.0", "C", 300.0, NULL),
                     AT_PHYSICS_NONE);   /* the other two are 100 s stale */
}
END_TEST_DEFINITION()

RUN_TESTS(Physics,
          test_unit_parses_compound_expressions,
          test_unit_dimensional_equality_ignores_scale,
          test_unit_affine_only_whole,
          test_unit_unknown_symbol_is_refused_not_guessed,
          test_model_parses_and_converts_bounds_to_si,
          test_model_rejects_incoherent_relation,
          test_model_rejects_duplicate_capability_and_unknown_unit,
          test_empty_model_says_nothing,
          test_undeclared_capability_and_absent_answer_say_nothing,
          test_passing_physics_earns_nothing,
          test_bounds_and_shape_refute,
          test_dimension_mismatch_refutes_but_prefix_converts,
          test_rate_against_own_previous_claim_refutes,
          test_refuted_observation_is_not_stored,
          test_vector_rate_uses_the_magnitude,
          test_unattributed_result_runs_only_identity_free_checks,
          test_minimal_hitting_sets,
          test_disagreeing_peers_are_implicated_not_refuted,
          test_lone_outlier_against_two_is_still_only_implicated,
          test_tolerance_zero_disables_the_intersection,
          test_stale_observations_do_not_conflict,
          test_parity_residual_conflicts_all_contributors,
          test_parity_from_one_peer_alone_refutes_it,
          test_parity_incomplete_or_stale_is_not_evaluated)
