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
 * @file trust_ladder.h
 * @brief Trust-ladder loader: capability tier/weight metadata from config.
 *
 * C twin of `core/_python/trust_ladder.py` (ISSUES §10.1, the one asymmetry in
 * doc/architecture/trust-tiers.md §9's parity table — the Python half existed
 * and C registered capabilities in code only).
 *
 * **The ladder file is JSON, and ONE file serves both runtimes** (user decision,
 * 2026-08-12). C parses it with jansson, which the tree already depends on;
 * Python's loader reads it unchanged because YAML is a superset of JSON — the
 * same trick `data_source_proc.c` already relies on. That is why there is no new
 * dependency here and no conversion step between the runtimes: a scenario ships
 * one `trust_ladder.json` and both halves honour it. Scenario `.yaml` ladders
 * that only ever feed a demo's own Python loader are untouched.
 *
 * Schema — every field optional, documented defaults apply when absent
 * (trust-tiers §8: "everything tier 0, weight 1, bootstrap on"):
 *
 * ```json
 * {
 *   "version": 1,
 *   "bootstrap": { "enabled": true, "duration_sec": 30, "pairs": 20 },
 *   "capabilities": {
 *     "at.handshake":      { "required_tier": 0, "transaction_weight": 1 },
 *     "dod.sensor-report": { "required_tier": 2, "transaction_weight": 4 }
 *   },
 *   "tier_demotion_epsilon": 0.02
 * }
 * ```
 */

#ifndef TRUST_LADDER_H
#define TRUST_LADDER_H

#include <stdbool.h>
#include <stddef.h>

#include "processes/capabilities.h"

/** Ceiling on ladder entries. Same order as MAX_CAPABILITIES; a ladder longer
 *  than this is a configuration error, not something to silently truncate. */
#define TRUST_LADDER_MAX_CAPABILITIES MAX_CAPABILITIES

/** Env var naming a ladder file. Mirrors Python's TRUST_LADDER_ENV. */
#define TRUST_LADDER_ENV "AT_TRUST_LADDER"

/* Documented defaults (trust-tiers §8), mirroring the Python constants. */
#define TRUST_LADDER_DEFAULT_REQUIRED_TIER 0
#define TRUST_LADDER_DEFAULT_TRANSACTION_WEIGHT 1
#define TRUST_LADDER_DEFAULT_BOOTSTRAP_DURATION_SEC 30
#define TRUST_LADDER_DEFAULT_BOOTSTRAP_PAIRS 20
#define TRUST_LADDER_DEFAULT_TIER_DEMOTION_EPSILON 0.02

/** One capability's tier/weight metadata. Mirrors Python `CapMeta`. */
typedef struct {
    char name[CAP_NAMELEN + 1];
    int required_tier;
    int transaction_weight;
} ladder_capability_t;

/** The `bootstrap:` stanza. Mirrors Python `BootstrapParams`. */
typedef struct {
    bool enabled;
    int duration_sec;
    int pairs;
} ladder_bootstrap_t;

/** A parsed ladder. Mirrors Python `TrustLadder`. */
typedef struct {
    ladder_capability_t capabilities[TRUST_LADDER_MAX_CAPABILITIES];
    size_t num_capabilities;
    ladder_bootstrap_t bootstrap;
    double tier_demotion_epsilon;
} trust_ladder_t;

/**
 * @brief Fill @p out with the all-defaults ladder (no capabilities).
 *
 * The state Python's `default_ladder()` returns, and what both loaders below
 * fall back to, so the mechanism is inert until a scenario opts in.
 */
void trust_ladder_defaults(trust_ladder_t *out);

/**
 * @brief Parse the ladder JSON at @p path into @p out.
 *
 * Mirrors Python `load_trust_ladder(path)` for an EXPLICIT path: a missing file
 * is an error (the caller asked for that file), as is malformed content or a
 * ladder longer than TRUST_LADDER_MAX_CAPABILITIES. @p out is left holding the
 * defaults on any failure, so a caller that ignores the return value degrades
 * to documented behaviour rather than reading uninitialised metadata.
 *
 * @return 0 on success, non-zero on failure.
 */
int trust_ladder_load(const char *path, trust_ladder_t *out);

/**
 * @brief Load the ladder named by $AT_TRUST_LADDER, or the defaults.
 *
 * Mirrors Python `load_trust_ladder(None)`: with the env unset, @p out is the
 * all-defaults ladder; with the env set but the file missing, @p out is the
 * defaults and a warning is logged — a misconfigured deployment degrades rather
 * than failing to start. A file that EXISTS but is malformed still fails, since
 * that is a broken ladder rather than an absent one.
 *
 * @return 0 when @p out is usable (including both fallbacks), non-zero if a
 *         present file could not be parsed.
 */
int trust_ladder_load_env(trust_ladder_t *out);

/**
 * @brief Look up one capability's metadata by name.
 * @return pointer into @p ladder, or NULL when the ladder does not name it
 *         (the caller then applies the documented defaults).
 */
const ladder_capability_t *trust_ladder_find(const trust_ladder_t *ladder,
                                             const char *name);

/**
 * @brief Apply ladder metadata onto @p caps, matching by name.
 *
 * The C twin of Python's `register_trust_ladder`, with the difference the two
 * runtimes genuinely have: Python CREATES capabilities from the ladder because
 * its registry is dynamic, while C's capabilities are declared in code
 * (@ref register_bootstrap_capabilities and the generated table), so the ladder
 * OVERRIDES the tier/weight of the ones already present. An entry naming a
 * capability this node does not implement is not an error — a ladder is written
 * for a whole scenario, and a node is only ever part of one.
 *
 * @return the number of capabilities updated, or -1 on a NULL argument.
 */
int trust_ladder_apply(const trust_ladder_t *ladder, capability_t *caps,
                       size_t num_caps);

#endif /* TRUST_LADDER_H */
