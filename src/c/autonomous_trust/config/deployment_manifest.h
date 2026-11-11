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
/**
 * @file deployment_manifest.h
 * @brief The deployment manifest: which nodes may be gateways (RD_13.4 §3.3).
 *
 * C twin of `core/_python/deployment_manifest.py`, which holds the full
 * description; the conformance case `network/deployment-manifest` pins the
 * rules on both runtimes.
 *
 * At runtime the manifest only BOUNDS: a gateway role is accepted only for a
 * node it lists, and the role still needs both cohorts' quorum certificates.
 * No manifest means no role is accepted, so a pair of cohorts has one gateway
 * and invariant G is unchanged. The runtime bound is by node alone (RD_13.4
 * R1); cohort names and members exist for validation and the offline checker.
 *
 * ```json
 * {
 *   "version": 1,
 *   "cohorts": { "<name>": { "members": ["<uuid>", ...], "n_min": 4 } },
 *   "gateways": [ { "node": "<uuid>", "between": ["<name>", "<name>"] } ]
 * }
 * ```
 *
 * `$AT_DEPLOYMENT_MANIFEST` names the file. Unset, or naming a file that does
 * not exist (with a warning), the manifest is empty. A file that exists and
 * breaks a rule refuses the start.
 */

#ifndef DEPLOYMENT_MANIFEST_H
#define DEPLOYMENT_MANIFEST_H

#include <stdbool.h>
#include <stddef.h>

#include <jansson.h>

#include "utilities/logger.h"

/** Env var naming the manifest file. Mirrors Python DEPLOYMENT_MANIFEST_ENV. */
#define DEPLOYMENT_MANIFEST_ENV "AT_DEPLOYMENT_MANIFEST"
#define DEPLOYMENT_MANIFEST_VERSION 1

/* Ceilings, matching Python. */
#define DM_MAX_COHORTS 64
#define DM_MAX_MEMBERS 1024     /* per cohort */
#define DM_MAX_GATEWAYS 256
#define DM_MAX_NAME_LEN 64
#define DM_UUID_LEN 36

typedef struct {
    char name[DM_MAX_NAME_LEN + 1];
    char (*members)[DM_UUID_LEN + 1];
    size_t n_members;
    int n_min;                  /**< 0 when absent. */
} dm_cohort_t;

typedef struct {
    char node[DM_UUID_LEN + 1];
    char between[2][DM_MAX_NAME_LEN + 1];   /**< Sorted, as Python's tuple. */
} dm_gateway_t;

typedef struct {
    dm_cohort_t *cohorts;
    size_t n_cohorts;
    dm_gateway_t *gateways;
    size_t n_gateways;
} deployment_manifest_t;

/** Empty @p m without freeing it (a zeroed struct is the empty manifest). */
void deployment_manifest_init(deployment_manifest_t *m);
void deployment_manifest_free(deployment_manifest_t *m);

/**
 * @brief Validate a decoded manifest into @p out.
 * @return 0, or -1 with the reason in @p err; @p out is then empty.
 */
int deployment_manifest_parse(const json_t *root, deployment_manifest_t *out,
                              char *err, size_t err_len);

/**
 * @brief Load and validate the file at @p path (NULL: `$AT_DEPLOYMENT_MANIFEST`).
 *
 * An explicit path that does not exist is an error. An env-named one that does
 * not exist gives the empty manifest and a warning. Duplicate keys are refused.
 * @return 0, or -1 with the reason in @p err.
 */
int deployment_manifest_load(const char *path, deployment_manifest_t *out,
                             char *err, size_t err_len, logger_t *logger);

/** How many cohort pairs @p node (a canonical uuid string) is listed for. */
size_t deployment_manifest_gateway_pairs(const deployment_manifest_t *m,
                                         const char *node);

/**
 * @brief Load the env-named manifest and make it the active one.
 *
 * Called at network start; a non-zero return refuses the start and leaves the
 * previous manifest in force. Mirrors Python `deployment_manifest.configure`.
 */
int deployment_manifest_configure(const char *path, logger_t *logger);
/** The active manifest; never NULL. */
const deployment_manifest_t *deployment_manifest_active(void);
void deployment_manifest_reset(void);

#endif /* DEPLOYMENT_MANIFEST_H */
