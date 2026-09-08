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

#ifndef AT_REPLICATION_H
#define AT_REPLICATION_H

/** @defgroup internal_replication Replication (R+D.md §12.6)
 *  @{
 *
 * Sampled replication with bisection dispute resolution, the C twin of
 * `autonomous_trust.core._python.replication`. Build-order step 6 of
 * doc/verification_oracle.md: replicate a random fraction of tasks, scale the
 * fraction to consequence, and resolve a disagreement by bisecting a
 * hash-chained trace rather than re-running. The outcome lands on the
 * `replication` evidence channel like any other finding (R+D.md §12.8).
 *
 * This header is the declaration: a default probability and per-capability
 * overrides, validated into [0, 1] on parse. The operator's number is the
 * anchor, exactly as for the authored transaction_weight and the calibration
 * level — the doc's "scale to consequence" is the operator setting
 * replicate_prob per capability, not a number derived opaquely from the weight.
 */

#include <stdbool.h>
#include <stddef.h>

/** Capability-name buffer, matching the other oracle layers. */
#define AT_REPL_NAME_LEN 63

/** Upper bound on declared per-capability overrides. */
#define AT_REPL_MAX_CAPS 32

/** The probability for a capability the declaration does not name. */
#define AT_REPLICATION_DEFAULT_PROB 0.05

typedef struct
{
    char   capability[AT_REPL_NAME_LEN + 1];
    double prob;
    double tolerance;   /* numeric agreement tolerance (slice B); 0 = exact */
} at_replication_cap_t;

typedef struct
{
    double               default_prob;
    at_replication_cap_t caps[AT_REPL_MAX_CAPS];
    size_t               num_caps;
} at_replication_model_t;

/** @brief Parse and validate a replication declaration from JSON text.
 *
 * Empty or NULL text yields the empty model (default_prob only). On a malformed
 * declaration or an out-of-range probability, writes @p err and returns false.
 * Mirrors Python `parse_replication`. */
bool at_replication_model_parse(const char *json_text,
                                at_replication_model_t *out,
                                char *err, size_t err_len);

/** @brief Read and validate a declaration from a file. */
bool at_replication_model_load(const char *path,
                               at_replication_model_t *out,
                               char *err, size_t err_len);

/** @brief The replication probability for @p capability: its own declared
 * number, or default_prob when the declaration does not name it. */
double at_replication_prob_for(const at_replication_model_t *model,
                               const char *capability);

/** @brief The numeric agreement tolerance for @p capability; 0.0 (exact) when
 * the declaration does not name one. Mirrors Python `tolerance_for`. */
double at_replication_tolerance_for(const at_replication_model_t *model,
                                    const char *capability);

/** @} */

#endif /* AT_REPLICATION_H */
