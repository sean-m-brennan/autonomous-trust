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

#ifndef AT_PHYSICS_H
#define AT_PHYSICS_H

/** @addtogroup internal_physics
 *  @{
 *
 * Physical consistency as a pre-statistical falsification layer (R+D.md §12.2;
 * doc/verification_oracle.md build-order step 1; design in
 * doc/architecture/physical-consistency.md).
 *
 * Check a peer's claim against dimensional coherence, declared range, kinematic
 * feasibility and linear conservation relations BEFORE any reputation math
 * runs. The verdict is a hard falsification rather than a statistic, which is
 * why it has its own evidence channel (TX_CHANNEL_PHYSICAL, R+D.md §12.8).
 *
 * The layer produces at most one verdict per result:
 *
 *   - AT_PHYSICS_REFUTED    — the claim is impossible, or the peer is in EVERY
 *                             consistent explanation of why the reports cannot
 *                             all be true. Scores 0.1 on `physical`.
 *   - AT_PHYSICS_IMPLICATED — the reports are mutually inconsistent and the
 *                             physics does not say whose fault that is. Scores
 *                             0.3 on `swarm_disagreement`.
 *   - AT_PHYSICS_NONE       — nothing to say. The common case.
 *
 * The last is the important one. PASSING PHYSICS EARNS A PEER NOTHING: a claim
 * outside the feasible set is refuted, but a claim inside it is merely
 * not-refuted, and rewarding it would turn a falsification layer into a
 * plausibility grade. So the checker never returns a good score, and the
 * existing arms of negotiation_score_task_result handle a surviving result on
 * their own terms.
 *
 * Two design points that are load-bearing:
 *
 *   - A REFUTED observation is NOT stored. The store feeds the multi-peer
 *     intersection and the parity residuals, so admitting a claim already known
 *     to be impossible would let one liar manufacture conflicts against honest
 *     peers.
 *   - An IMPLICATED peer is NOT accused. Two peers reporting incompatible
 *     values means one of them is wrong; scoring both as refuted would let any
 *     peer refute an honest one by lying about the same quantity.
 *
 * The Python twin is
 * src/autonomous-trust/autonomous_trust/core/_python/physics/. The two grade
 * the same peers off the same physics.json, so the conformance protocol
 * `physics` pins the rules rather than trusting the mirror — as with probe
 * scoring (R+D.md §12.7), the two runtimes cannot share a call site.
 */

#include <stdbool.h>
#include <stddef.h>

#include "physics/units.h"

/** Longest quantity or capability name held in a declaration. */
#define AT_PHYS_NAME_LEN 63

/** Longest relation name. */
#define AT_PHYS_REL_NAME_LEN 63

/** Maximum components of a vector quantity (a position is 3). */
#define AT_PHYS_MAX_COMPONENTS 8

/** Maximum declared quantities. Bounded because the model is a flat array in
 *  a runtime with no allocator discipline to lean on; a declaration larger
 *  than this is refused at load rather than truncated. */
#define AT_PHYS_MAX_QUANTITIES 64

/** Maximum declared relations. */
#define AT_PHYS_MAX_RELATIONS 32

/** Maximum terms in one parity relation. */
#define AT_PHYS_MAX_TERMS 16

/** Peers tracked per quantity in the observation store. */
#define AT_PHYS_MAX_PEERS 32

/** Observations retained per (quantity, peer). Rate needs two samples and
 *  acceleration three; the rest is slack for the intersection window. */
#define AT_PHYS_MAX_OBS 8

/** Buffer size for the reason/detail out-parameters. */
#define AT_PHYS_ERR_LEN 256

/** Verdict on one claim. Mirrors the Python twin's REFUTED / IMPLICATED /
 *  CLEARED, which the conformance vectors spell as those strings. */
typedef enum
{
    AT_PHYSICS_NONE = 0,   /**< no declaration, or nothing to say */
    AT_PHYSICS_IMPLICATED, /**< in SOME minimal diagnosis */
    AT_PHYSICS_REFUTED,    /**< in EVERY minimal diagnosis */
} at_physics_verdict_t;

/** Score for a hard falsification. The same number a tampered probe answer
 *  gets, and for the same reason: it is the strongest negative evidence AT
 *  produces, and the `physical` channel already multiplies its weight by
 *  three, so the score stays on the ordinary [0,1] scale. */
#define AT_PHYSICS_REFUTED_SCORE 0.1

/** Score for a peer implicated by a conflict that does not name it uniquely.
 *  A poor score, not a refutation. */
#define AT_PHYSICS_IMPLICATED_SCORE 0.3

/** One declared physical quantity and the bounds it is capable of. Bounds are
 *  stated in the DECLARED unit and converted to SI once, at load, so that
 *  everything downstream is in one coherent system and a peer reporting
 *  kilowatts is compared with a peer reporting watts on equal terms. */
typedef struct
{
    char name[AT_PHYS_NAME_LEN + 1];
    char capability[AT_PHYS_NAME_LEN + 1];
    char unit[AT_UNIT_SYMBOL_LEN + 1];
    at_dimension_t dimension;
    bool   has_min, has_max, has_max_rate, has_max_accel;
    double si_min, si_max;
    double si_max_rate;   /**< a difference per second: scale only, no offset */
    double si_max_accel;
    double si_tolerance;  /**< half-width; scale only. 0 disables intersection */
    int    components;
} at_phys_quantity_t;

/** A linear parity relation: constant + sum(coeff * value) ~ 0.
 *
 * The parity-relation form from the aerospace fault-detection tradition
 * (Isermann; Blanke et al.), restricted to the linear case — which is not a
 * shortcut, since conservation of mass, energy, momentum and charge are all
 * sums of signed flows, and it is what lets the residual be computed
 * identically in two languages with no expression evaluator to keep in step. */
typedef struct
{
    char   name[AT_PHYS_REL_NAME_LEN + 1];
    int    n_terms;
    int    term_quantity[AT_PHYS_MAX_TERMS]; /**< index into model.quantities */
    double term_coeff[AT_PHYS_MAX_TERMS];
    double constant;
    double tolerance;
    bool   has_window;
    double window_sec;
} at_phys_relation_t;

/** A parsed physics.json. Empty (n_quantities == 0) unless configured, which
 *  is the default everywhere: a physical refutation is the hardest evidence AT
 *  produces, and a checker that guessed at undeclared quantities would be
 *  manufacturing it. */
typedef struct
{
    int n_quantities;
    int n_relations;
    at_phys_quantity_t quantities[AT_PHYS_MAX_QUANTITIES];
    at_phys_relation_t relations[AT_PHYS_MAX_RELATIONS];
    double window_sec;
    int max_observations;
} at_physics_model_t;

/** One peer's claim about one quantity, in SI, with its arrival time. */
typedef struct
{
    double t;
    double values[AT_PHYS_MAX_COMPONENTS];
} at_phys_obs_t;

/** Per-(quantity, peer) ring of observations. */
typedef struct
{
    char   peer[AT_PHYS_NAME_LEN + 1];
    int    count;               /**< observations written, saturating logic */
    int    head;                /**< next write index */
    at_phys_obs_t obs[AT_PHYS_MAX_OBS];
} at_phys_peer_hist_t;

/** The checker: a model plus the observation window it judges against.
 *
 * Process-local and unsynchronised, which is correct rather than a limitation:
 * it runs inside the single process that holds the requestor's record of what
 * it asked (this runtime's negotiation process), and every value it compares
 * was observed by this node. Nothing here is consensus — the verdict enters
 * consensus as an ordinary transaction score and is judged by every peer on
 * its own terms. */
typedef struct
{
    at_physics_model_t model;
    /* store[quantity][peer], valid only for peer < store_peers[quantity].
     *
     * That bound is the ONLY thing that makes a row live: rows are zeroed when
     * they are created, never in bulk. This struct is over a megabyte, and
     * clearing it wholesale would fault in every page on every node — the
     * layer is opt-in, so most nodes never enable it and must not pay for it.
     * Emptying the store means zeroing `store_peers`, and nothing may read a
     * row past that count. */
    at_phys_peer_hist_t store[AT_PHYS_MAX_QUANTITIES][AT_PHYS_MAX_PEERS];
    int store_peers[AT_PHYS_MAX_QUANTITIES];
} at_physics_checker_t;

/**
 * @brief Parse a physics declaration from JSON text.
 *
 * @param json_text The declaration.
 * @param out       Zeroed and filled on success.
 * @param err       Optional buffer (AT_PHYS_ERR_LEN) for the rejection reason.
 * @param errlen    Size of @p err.
 * @return true on success. A malformed declaration is an OPERATOR error:
 *         false here means the layer must stay off, never that it should check
 *         a subset. An unknown unit, a relation naming an undeclared quantity,
 *         and a relation whose terms are not all of the same dimension are all
 *         rejections — that last is what makes a residual meaningful.
 */
bool at_physics_model_parse(const char *json_text, at_physics_model_t *out,
                            char *err, size_t errlen);

/**
 * @brief Load the declaration named by @p path, or by $AT_PHYSICS when NULL.
 *
 * With neither set, @p out is the EMPTY model and every check returns
 * AT_PHYSICS_NONE — the layer is opt-in. A configured path that cannot be read
 * or parsed returns false: a physics layer that quietly stopped checking is
 * worse than one that was never turned on, because the operator believes the
 * claims are being verified.
 */
bool at_physics_model_load(const char *path, at_physics_model_t *out,
                           char *err, size_t errlen);

/** @brief Initialise a checker over @p model (copied). Model may be NULL for
 *         the empty model. */
void at_physics_checker_init(at_physics_checker_t *checker,
                             const at_physics_model_t *model);

/** @brief Drop every stored observation, keeping the model. Tests and
 *         scenario replays only. */
void at_physics_checker_reset(at_physics_checker_t *checker);

/** @brief True when any quantity is declared. */
bool at_physics_checker_enabled(const at_physics_checker_t *checker);

/**
 * @brief Judge one returned task result.
 *
 * @param checker    The checker; its observation store is updated.
 * @param capability The capability that was requested.
 * @param result_str The peer's answer as text — a bare number, or a JSON
 *                   object/array. NULL or empty means no answer, which is not
 *                   a false claim and yields AT_PHYSICS_NONE.
 * @param subject    Identifier of the peer that answered, or NULL when the
 *                   result is not attributable to one peer (a fan-out). With
 *                   NULL only the checks that need no identity run — shape,
 *                   unit, arity and bounds — and nothing is stored: a conflict
 *                   between peers cannot be assigned without knowing who said
 *                   what, and inventing an identity to file it under would be
 *                   worse than not checking.
 * @param now        Observation time in seconds. A parameter rather than a
 *                   clock read so a replay produces the verdicts the live path
 *                   did.
 * @param score_out  Optional; receives the score for a non-NONE verdict.
 * @param reason_out Optional buffer (AT_PHYS_ERR_LEN) receiving a short reason
 *                   token followed by the detail, for the log.
 * @param reason_len Size of @p reason_out.
 * @return the verdict.
 */
at_physics_verdict_t at_physics_check(at_physics_checker_t *checker,
                                      const char *capability,
                                      const char *result_str,
                                      const char *subject,
                                      double now,
                                      double *score_out,
                                      char *reason_out, size_t reason_len);

/**
 * @brief Minimal hitting sets of @p conflicts, as bitmasks over peer indices.
 *
 * Reiter's HS-tree with the usual pruning. Exposed for the unit tests and the
 * conformance adapter, which pin the enumeration itself: the Python twin runs
 * the same algorithm over Python ints, so the two must agree on which sets are
 * minimal or they will disagree about a diagnosis.
 *
 * @param conflicts   Array of conflict masks.
 * @param n_conflicts How many.
 * @param out         Receives the minimal hitting sets.
 * @param out_cap     Capacity of @p out.
 * @return number written, or -1 if @p out_cap was too small.
 */
int at_physics_minimal_hitting_sets(const uint64_t *conflicts, int n_conflicts,
                                    uint64_t *out, int out_cap);

/** @} */
#endif /* AT_PHYSICS_H */
