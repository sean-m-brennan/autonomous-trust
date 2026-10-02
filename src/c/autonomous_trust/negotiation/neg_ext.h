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

#ifndef NEG_EXT_H
#define NEG_EXT_H

/**
 * @file neg_ext.h
 * @brief How an optional feature caps the trust tier a peer may use when it
 *        asks this node to run a capability, without the core naming it.
 *
 * FEATURE_SPLIT_PLAN Phase 7, hook C1. First contact holds an unverified
 * contact at a low tier until the two humans verify each other
 * (doc/architecture/first-contact.md §10.3). The negotiation process asks
 * every registered cap, in registration order, after it has read the peer's
 * earned tier and before it compares that with the capability's
 * required_tier.
 *
 * A cap may only LOWER the tier: an answer above what it was given is ignored,
 * so no extension can raise a peer past what it earned. A cap decides its own
 * gate (first contact's reads $AT_FIRST_CONTACT on every call), which is why
 * registering one from a constructor turns nothing on. With none registered,
 * nothing is capped. Filled before main(), then read-only, so unlocked, as
 * the other registries. Mirrors Python extensions.NegotiationHooks.
 */

#include <stdbool.h>
#include <stddef.h>

#include "processes/processes.h"

/** Most tier caps the registry holds. */
#define NEG_TIER_CAP_MAX 4

/** One feature's tier cap. */
typedef struct {
    /** Unique; for logs. */
    const char *name;
    /** The tier @p peer (16 raw uuid bytes) may use, given its earned
     *  @p tier. @p proc is the negotiation process. */
    int (*cap)(const process_t *proc, const unsigned char *peer, int tier);
} neg_tier_cap_t;

/** Register @p cap (static storage). @return 0; -1 NULL, unnamed, duplicate
 *  or full. */
int neg_tier_cap_register(const neg_tier_cap_t *cap);

/** True iff a tier cap named @p name is registered. */
bool neg_tier_cap_present(const char *name);

/** @p tier after every registered cap, each given the previous one's answer.
 *  Never above @p tier. */
int neg_ext_capped_tier(const process_t *proc, const unsigned char *peer, int tier);

/** Register @p cap at load time. */
#define NEG_TIER_CAP_REGISTER(tag, cap)                                        \
    static void __attribute__((constructor)) neg_tier_cap_register_##tag(void) \
    {                                                                          \
        (void)neg_tier_cap_register(cap);                                      \
    }

#endif /* NEG_EXT_H */
