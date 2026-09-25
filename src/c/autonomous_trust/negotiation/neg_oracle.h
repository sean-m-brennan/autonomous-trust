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

#ifndef NEG_ORACLE_H
#define NEG_ORACLE_H

/**
 * @file neg_oracle.h
 * @brief The oracle registry: how the verification layers of R+D.md §12
 *        (physics, calibration, certificates, prequential) reach the scorer
 *        without the core naming them.
 *
 * Each layer is its own library (src/c/extensions/<oracle>/, FEATURE_SPLIT_PLAN
 * Phase 3). From load-time constructors it
 *
 *  - **declares** itself (@ref NEG_ORACLE_REGISTER), which is what the
 *    start-time check looks for and where its reset hangs;
 *  - registers its **arms** (@ref NEG_ORACLE_ARM_REGISTER): a *verdict* arm may
 *    decide the score and channel; an *observe* arm only records;
 *  - may **provide** one of two services other layers or the core read:
 *    the quantity a capability reports (physics) and the competence
 *    multiplier (prequential).
 *
 * ::negotiation_score_task_result runs the known-answer probe, then the arms in
 * ascending @ref neg_oracle_arm_t.order -- the first verdict arm that decides
 * ends scoring -- then the completion arm. The orders the layers use reproduce
 * the scorer's fixed sequence:
 *
 *   100 physics check (verdict) · 200 calibration settle (observe) ·
 *   210 prequential settle + observe (observe) · 300 certificate check
 *   (verdict) · 400 calibration assess (verdict)
 *
 * Registering from a constructor is safe because linking a layer turns nothing
 * on: each still speaks only when its declaration ($AT_PHYSICS, ...) names a
 * model. The scorer is also called by tests and the conformance adapter with
 * no negotiation process running, so the arms cannot wait for one to start.
 * Filled before main(), then read-only, so unlocked, as the other registries.
 * An empty registry scores exactly as the probe + completion arms alone.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "utilities/logger.h"

/** Most arms / declared oracles the registry holds. */
#define NEG_ORACLE_ARM_MAX  16
#define NEG_ORACLE_MAX      8

/** The competence multiplier with no prequential layer: the authored weight
 *  verbatim. */
#define NEG_NEUTRAL_COMPETENCE 1.0

/** Buffer caps for the witness and prediction payloads the scorer is handed.
 *  Sized as they were when they were taken from the layers' error lengths. */
#define NEG_CERT_JSON_MAX (256 * 16)
#define NEG_PRED_JSON_MAX (256 * 8)

/** One result being scored: ::negotiation_score_task_result's inputs. */
typedef struct {
    const char *cap;               /**< capability name; may be NULL/"" */
    const char *kwargs_json;       /**< OUR record of the problem */
    const char *result_str;
    size_t      result_len;
    const char *certificate_json;  /**< the peer's witness, or NULL */
    const char *prediction_json;   /**< the peer's prediction set, or NULL */
    const char *subject;           /**< peer uuid string; NULL for a fan-out */
    double      now;               /**< monotonic seconds */
    uint64_t    seed;              /**< this verifier's challenge */
} neg_score_input_t;

/** One scorer arm. Exactly one of @c score / @c observe is set. */
typedef struct {
    const char *name;   /**< "physics.check"; for logs */
    int order;          /**< position in the scorer; ascending */
    /** Verdict arm: return true to decide, with *score and *channel set;
     *  false falls through to the next arm. */
    bool (*score)(const neg_score_input_t *in, double *score, const char **channel);
    /** Observe arm: side effects only. */
    void (*observe)(const neg_score_input_t *in);
} neg_oracle_arm_t;

/** One layer present in this binary. */
typedef struct {
    const char *name;      /**< "physics", "calibration", "prequential",
                            *   "certificates", "replication" */
    void (*reset)(void);   /**< drop its state (may be NULL) */
} neg_oracle_t;

/** Declare a layer. Refuses (-1, stderr) NULL, unnamed, duplicate, full. */
int neg_oracle_register(const neg_oracle_t *oracle);
/** True iff a layer named @p name is declared. */
bool neg_oracle_present(const char *name);

/** Add an arm. Refuses (-1, stderr) NULL, unnamed, neither or both hooks,
 *  full. Ties keep registration order. */
int neg_oracle_arm_register(const neg_oracle_arm_t *arm);

/** Run the arms over @p in. @return true if a verdict arm decided. */
bool neg_oracles_score(const neg_score_input_t *in, double *score, const char **channel);

/** Provide the capability -> reported-quantity lookup. One provider; a second
 *  is refused (-1). */
int neg_oracle_provide_quantity(const char *(*fn)(const char *capability));
/** The declared quantity @p capability reports, or NULL (no provider, or not
 *  declared). */
const char *neg_oracle_reported_quantity(const char *capability);

/** Provide the competence multiplier. One provider; a second is refused. */
int neg_oracle_provide_competence(double (*fn)(const char *cap, const char *subject));
/** The multiplier for @p subject on @p cap; ::NEG_NEUTRAL_COMPETENCE with no
 *  provider. */
double neg_oracle_competence(const char *cap, const char *subject);

/**
 * @brief Refuse a node whose environment declares a layer this binary lacks:
 * $AT_PHYSICS, $AT_CALIBRATION, $AT_PREQUENTIAL or $AT_CERTIFICATES set and
 * non-empty with that library absent. Checking silently not happening is the
 * one outcome worse than not starting -- a node declared to test physics would
 * accept results physics refutes. Logs an ERROR naming the library.
 * @return 0 or -1.
 */
int neg_oracles_check_env(logger_t *logger);

/** Call every declared layer's reset (tests, conformance, negotiation reset). */
void neg_oracles_reset(void);

/** Register @p oracle at load time. */
#define NEG_ORACLE_REGISTER(tag, oracle)                                        \
    static void __attribute__((constructor)) neg_oracle_register_##tag(void)    \
    {                                                                           \
        (void)neg_oracle_register(oracle);                                      \
    }

/** Register @p arm at load time. */
#define NEG_ORACLE_ARM_REGISTER(tag, arm)                                       \
    static void __attribute__((constructor)) neg_oracle_arm_register_##tag(void)\
    {                                                                           \
        (void)neg_oracle_arm_register(arm);                                     \
    }

#endif /* NEG_ORACLE_H */
