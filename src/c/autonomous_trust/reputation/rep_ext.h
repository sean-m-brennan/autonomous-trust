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

#ifndef REP_EXT_H
#define REP_EXT_H

/**
 * @file rep_ext.h
 * @brief How an optional feature hands the reputation process cold-start
 *        priors, without the core naming it.
 *
 * FEATURE_SPLIT_PLAN Phase 7, hook C2. First contact seeds each VERIFIED
 * contact slightly above the cold-start neutral (FIRST_CONTACT_PLAN.md §10.5).
 * The reputation process asks every registered provider at startup (after the
 * persisted snapshot loads, before the idle fade) and again on each pass of
 * its loop, so a provider must make the usual pass cheap: first contact's
 * looks at its store's mtime and offers nothing when it has not changed.
 *
 * The policy stays the core's. A seed is a PRIOR, written only where this node
 * holds NO reputation for the peer at all, so it never overwrites an earned,
 * warm-started or slashed value. A seed outside (0, 1] is refused, not
 * clamped: reputation lives in [0, 1], and the provider's source may be a
 * hand-editable file. Filled before main(), then read-only, so unlocked, as
 * the other registries. Mirrors Python extensions.ReputationHooks.
 */

#include <stdbool.h>
#include <stddef.h>
#include <uuid/uuid.h>

#include "processes/processes.h"

/** Most seed providers the registry holds. */
#define REP_SEED_PROVIDER_MAX 4

/** Offer one seed: @p who starts at @p seed unless already known. @p what
 *  names it in the log ("verified contact"). */
typedef void (*rep_seed_offer_fn)(void *arg, const uuid_t who, double seed,
                                  const char *what);

/** One feature's seed provider. */
typedef struct {
    /** Unique; also the log's prefix ("first contact"). */
    const char *name;
    /** Offer any seeds that are new since the last call, through @p offer.
     *  @p proc is the reputation process. */
    void (*seeds)(const process_t *proc, rep_seed_offer_fn offer, void *arg);
} rep_seed_provider_t;

/** Register @p p (static storage). @return 0; -1 NULL, unnamed, duplicate or
 *  full. */
int rep_seed_provider_register(const rep_seed_provider_t *p);

/** True iff a seed provider named @p name is registered. */
bool rep_seed_provider_present(const char *name);

/** Every registered provider, in registration order (rep_proc.c). */
size_t rep_seed_providers(const rep_seed_provider_t **out, size_t max);

/** Register @p p at load time. */
#define REP_SEED_PROVIDER_REGISTER(tag, p)                                        \
    static void __attribute__((constructor)) rep_seed_provider_register_##tag(void) \
    {                                                                             \
        (void)rep_seed_provider_register(p);                                      \
    }

#endif /* REP_EXT_H */
