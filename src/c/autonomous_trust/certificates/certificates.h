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

#ifndef AT_CERTIFICATES_H
#define AT_CERTIFICATES_H

/** @addtogroup internal_certificates
 *  @{
 *
 * Certificate-carrying task interfaces (R+D.md §12.3; doc/verification_oracle.md
 * build-order step 2; design in doc/architecture/certificate-interfaces.md).
 *
 * For a large fraction of computational work, checking is asymptotically
 * cheaper than producing. Requiring every answer to arrive with a witness
 * converts peer judgement into running a checker, which makes the oracle EXACT
 * rather than statistical: an optimum comes with its dual, an UNSAT claim with
 * a DRAT refutation, a shortest path with a feasible potential, a maximum flow
 * with the cut that meets it.
 *
 * Unlike the physics layer (R+D.md §12.2), this one CAN return a good score,
 * and that is not an inconsistency. Surviving a feasibility test means "not
 * refuted"; a witness that checks out means "proved right", and declining to
 * say so would discard the strongest positive evidence a node can obtain.
 *
 *   AT_CERT_VALID          0.9 on `certificate` — the answer is proved right
 *   AT_CERT_INVALID        0.1 on `certificate` — the answer is proved wrong
 *   AT_CERT_ABSENT         0.3 on `certificate` — declared to certify, did not
 *   AT_CERT_INDETERMINATE  no score — OUR retained inputs will not support a
 *                          check, which is never the peer's fault
 *   AT_CERT_NONE           no score — undeclared, or declared uncertifiable
 *
 * THE CHECKER'S INPUTS COME FROM THE REQUESTOR'S OWN RECORD, never from the
 * reply. This is the integrity property that makes a honeypot probe worth
 * issuing (R+D.md §12.7), and it matters more here: a checker that read the
 * problem out of the peer's response would be verifying that the peer can
 * solve a problem of its own choosing, which every peer can. The answer and
 * the witness are the only things the peer supplies.
 *
 * The Python twin is
 * src/autonomous-trust/autonomous_trust/core/_python/certificates/. The two
 * grade the same peers off the same certificates.json, so the `certificate`
 * conformance protocol pins the rules rather than trusting the mirror.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <jansson.h>

/** Longest capability name or checker kind held in a declaration. */
#define AT_CERT_NAME_LEN 63

/** Longest operator note attached to a declaration. */
#define AT_CERT_NOTE_LEN 127

/** Maximum declared capabilities. A declaration larger than this is refused at
 *  load rather than truncated: silently dropping a capability would turn a
 *  certified one into an unchecked one, which is the failure this layer exists
 *  to prevent. */
#define AT_CERT_MAX_CAPABILITIES 128

/** Largest problem dimension a checker will accept on a side. */
#define AT_CERT_MAX_DIM 4096

/** Largest total element count in one matrix. Capping each DIMENSION is not
 *  enough — 4096 x 4096 is 134 MB of doubles — and the bound belongs on the
 *  area, since that is what gets allocated. */
#define AT_CERT_MAX_ELEMENTS (1 << 20)

/** Buffer size for the reason / error out-parameters. */
#define AT_CERT_ERR_LEN 256

/** Default numeric slack. Deliberately tight: a certificate is meant to be
 *  exact, and a domain needing looser bounds should say so in its declaration
 *  rather than inherit one. */
#define AT_CERT_DEFAULT_TOLERANCE 1e-9

/** Score for a witness that checks out. The same number a correct known-answer
 *  probe earns, because it is the same kind of fact: we know the answer is
 *  right, rather than having failed to catch it being wrong. */
#define AT_CERT_VALID_SCORE 0.9

/** Score for a witness that does not check out. The same number a tampered
 *  probe earns: an invalid witness is a demonstrated wrong answer, not a
 *  disappointing one. */
#define AT_CERT_INVALID_SCORE 0.1

/** Score for a declared-and-required witness that never arrived. Suspicious
 *  rather than proved wrong, matching the ZKP-available-but-absent arm. */
#define AT_CERT_ABSENT_SCORE 0.3

/** The verdict on one returned result. */
typedef enum
{
    AT_CERT_NONE = 0,       /**< undeclared, or declared uncertifiable */
    AT_CERT_VALID,          /**< the witness checks out */
    AT_CERT_INVALID,        /**< the witness does not check out */
    AT_CERT_ABSENT,         /**< declared to certify, and nothing presented */
    AT_CERT_INDETERMINATE,  /**< OUR inputs will not support a check */
} at_cert_verdict_t;

/** One capability's certification contract.
 *
 * `checker[0] == '\0'` means the capability is declared UNCERTIFIABLE — an
 * acknowledged expensive case, which is a different and more useful state than
 * not being mentioned at all. */
typedef struct
{
    char   name[AT_CERT_NAME_LEN + 1];
    char   checker[AT_CERT_NAME_LEN + 1];
    char   note[AT_CERT_NOTE_LEN + 1];
    bool   required;
    bool   require_optimal;
    double tolerance;
    int    repetitions;      /**< matrix_product: Freivalds rounds */
    int    max_lag;          /**< state_estimation: autocorrelation lags */
    double bound;            /**< state_estimation: |rho_k| bound */
    int    max_proof_len;    /**< sat: DRAT lemma cap */
} at_cert_capability_t;

/** A parsed certificates.json. Empty unless configured, which is the default
 *  everywhere: the layer is opt-in. */
typedef struct
{
    int n_capabilities;
    at_cert_capability_t capabilities[AT_CERT_MAX_CAPABILITIES];
} at_cert_model_t;

/** The closed set of checker kinds, NULL-terminated, in the order the oracle
 *  doc tabulates them. Closed for the same reason the evidence channels are:
 *  an unknown spelling is refused, never silently read as "no checker",
 *  because a typo that turned a certified capability into an unchecked one is
 *  exactly what this layer exists to prevent. */
extern const char *const at_cert_checker_kinds[];

/** @brief How many kinds :c:data:`at_cert_checker_kinds` holds. */
int at_cert_checker_kind_count(void);

/** @brief True when @p kind names a checker this runtime implements. */
bool at_cert_checker_known(const char *kind);

/**
 * @brief Parse a declaration from JSON text.
 * @return false on any malformation, leaving @p out EMPTY. A declaration that
 *         does not parse is an operator error: never degrade to checking the
 *         subset that happened to parse, because the operator believes the
 *         whole of it is being verified.
 */
bool at_cert_model_parse(const char *json_text, at_cert_model_t *out,
                         char *err, size_t errlen);

/**
 * @brief Load the declaration named by @p path, or by $AT_CERTIFICATES.
 *        With neither set, @p out is the empty model and every check is NONE.
 */
bool at_cert_model_load(const char *path, at_cert_model_t *out,
                        char *err, size_t errlen);

/** @brief The declaration for @p capability, or NULL. */
const at_cert_capability_t *at_cert_for_capability(const at_cert_model_t *model,
                                                   const char *capability);

/** @brief True when any capability is declared. */
bool at_cert_model_enabled(const at_cert_model_t *model);

/**
 * @brief Judge one returned result against its declared certificate.
 *
 * @param model          The declaration.
 * @param capability     The capability the REQUESTOR asked for.
 * @param result_json    The peer's answer, as JSON text (NULL for none).
 * @param certificate_json The peer's witness, as JSON text (NULL for none).
 * @param kwargs_json    The problem, from the requestor's OWN retained task.
 * @param seed           The verifier's challenge seed for the one
 *                       probabilistic checker (Freivalds). It must come from
 *                       this node at check time and must NOT be derivable from
 *                       the problem, or the peer can grind an answer that
 *                       passes; see rng.h. A parameter rather than a draw so a
 *                       replay reproduces the verdict.
 * @param reason         Optional buffer (AT_CERT_ERR_LEN) for the finding.
 */
at_cert_verdict_t at_cert_evaluate(const at_cert_model_t *model,
                                   const char *capability,
                                   const char *result_json,
                                   const char *certificate_json,
                                   const char *kwargs_json,
                                   uint64_t seed,
                                   char *reason, size_t reason_len);

/** @brief The score a verdict carries, or 0.0 for one that produces none. */
double at_cert_score(at_cert_verdict_t verdict);

/** @brief The verdict's name, as the conformance vectors spell it. */
const char *at_cert_verdict_name(at_cert_verdict_t verdict);

/**
 * @brief A fresh 64-bit verifier challenge seed.
 *
 * The requirement is that the peer could not have predicted this before it
 * answered, so this draws from the system CSPRNG rather than from a
 * process-global PRNG that anything else in the node may have observed or
 * reseeded. Mirrors Python certificates.default_seed().
 */
uint64_t at_cert_verifier_seed(void);

/****************************
 * Producing a witness
 *
 * The C twin of Python's `Certified(answer, witness)` wrapper. A certifying
 * capability writes
 *
 *     {"at_certified": {"value": <answer>, "certificate": <witness>}}
 *
 * into its result buffer, and the worker splits the two apart before they go
 * on the wire, so the reply carries them in SEPARATE fields exactly as Python
 * does. A marker key rather than a bare {"value", "certificate"} object
 * because the split must never be a guess: an answer that legitimately had
 * those keys would otherwise be silently torn in half, and the checker would
 * then be verifying the wrong object.
 *
 * A wrapper rather than a new out-parameter on capability_result_function_t:
 * that signature is already implemented by every declared capability, and
 * widening it for a feature most capabilities will never use would break them
 * all to serve the few.
 ****************************/

/**
 * @brief Split a possibly-wrapped result into its answer and its witness.
 *
 * @param result_json  What the capability wrote.
 * @param value_out    Receives the answer as JSON text (the whole input when
 *                     it is not wrapped).
 * @param cert_out     Receives the witness as JSON text, or "" when there is
 *                     none. May be NULL.
 * @return true if the input was a wrapped result.
 */
bool at_cert_split_result(const char *result_json,
                          char *value_out, size_t value_len,
                          char *cert_out, size_t cert_len);

/**
 * @brief Build the wrapper a certifying capability should emit.
 * @return true on success; false if the buffer is too small or either input
 *         is not JSON.
 */
bool at_cert_wrap_result(const char *value_json, const char *certificate_json,
                         char *out, size_t out_len);

/****************************
 * Inventory
 *
 * doc/verification_oracle.md asks that "a capability whose result cannot be
 * certified should be recognized as the expensive case rather than treated as
 * the normal one". Recognition is not automatic: a node that silently falls
 * through to completion scoring for everything it cannot check looks, from
 * outside, exactly like a node checking everything.
 ****************************/

typedef enum
{
    AT_CERT_INV_UNEXAMINED = 0, /**< registered here, absent from the file */
    AT_CERT_INV_UNCERTIFIABLE,  /**< declared `checker: null` */
    AT_CERT_INV_OPTIONAL,       /**< a checker, but a missing witness is free */
    AT_CERT_INV_CERTIFIED,      /**< a checker, and the witness is required */
} at_cert_inv_state_t;

typedef struct
{
    char name[AT_CERT_NAME_LEN + 1];
    char checker[AT_CERT_NAME_LEN + 1];
    char note[AT_CERT_NOTE_LEN + 1];
    at_cert_inv_state_t state;
} at_cert_inv_row_t;

/**
 * @brief Classify every capability this node knows about.
 *
 * Rows come back worst-known first, so the line an operator most needs is not
 * at the bottom of an alphabetical list.
 *
 * @return rows written, or -1 if @p out_cap was too small.
 */
int at_cert_inventory(const at_cert_model_t *model,
                      const char *const *registered, int n_registered,
                      at_cert_inv_row_t *out, int out_cap);

/** @brief Render an inventory as an operator-facing report into @p buf. */
void at_cert_inventory_format(const at_cert_inv_row_t *rows, int n,
                              char *buf, size_t len);

/** @brief The state's name, as the conformance vectors spell it. */
const char *at_cert_inv_state_name(at_cert_inv_state_t state);

/** @} */
#endif /* AT_CERTIFICATES_H */
