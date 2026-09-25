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

#ifndef ID_EXT_H
#define ID_EXT_H

/** @addtogroup internal_identity
 *  @{
 */

/**
 * @file id_ext.h
 * @brief How a feature follows the identity process's own events without the
 *        identity process naming it (FEATURE_SPLIT_PLAN Phase 5).
 *
 * processes/extension.h lets a feature register VERB handlers. A feature that
 * also keeps per-peer state -- social: positions, profiles, connections,
 * blocks -- needs to hear about identity's lifecycle and protocol events, and
 * to answer two questions identity asks about a peer. It registers one
 * @ref identity_ext_t from a constructor (@ref IDENTITY_EXT_REGISTER); every
 * member but @c name may be NULL.
 *
 * **The core calls every hook with no lock held** -- not id_state.lock, not a
 * peers lock -- so a feature may keep its own state behind its own lock and
 * call back into exported identity functions from a hook. The rule for the
 * feature's side is the converse: while holding its own lock it calls nothing
 * that takes a lock or dispatches a hook (see extensions.md, "Social").
 *
 * Filled before main(), then read-only, so unlocked, as the other registries.
 * With nothing registered every dispatcher is a no-op and every query false,
 * which is exactly a node without the feature.
 */

#include <stdbool.h>

#include "identity/identity.h"
#include "processes/processes.h"
#include "utilities/logger.h"

/** Most identity extensions. */
#define IDENTITY_EXT_MAX 4

/** One feature's view of the identity process. */
typedef struct {
    /** Unique; also what @ref identity_ext_present and the start-time check
     *  look for ("social"). */
    const char *name;

    /** Identity's state was (re)initialized. Runs inside identity's own init,
     *  before its lock exists: touch only the feature's own state, and call no
     *  identity_* function. Also called at registration when identity is
     *  already initialized (a library loaded late). */
    void (*init)(void);
    /** identity_reset_state ran (tests, conformance): drop all state. */
    void (*reset)(void);
    /** identity_run registered its handlers and is about to take traffic
     *  (restore persisted state here, not in @c init, which tests reach). */
    void (*run_start)(process_t *proc);

    /** A peer was confirmed into the group. */
    void (*peer_confirmed)(const process_t *proc, const public_identity_t *peer);
    /** A peer advertised its group (handle_group_update, BEFORE any adopt, so
     *  proc->protocol.group.uuid is still ours). Uuids are lower-case strings. */
    void (*group_update_seen)(const process_t *proc, const char *from_uuid_str,
                              const char *their_group_uuid_str);
    /** The periodic caps resync sweep ran (operational, in a group, not
     *  choosing). */
    void (*periodic_resync)(const process_t *proc);
    /** The app asked for the roster; identity already emitted @p n_observed
     *  peer observations. Return true if the hook logged the request (so
     *  identity does not log it a second time). */
    bool (*roster_replay)(const process_t *proc, int n_observed);

    /** Whether @p uuid_str (lower-case) shares our group, for PEER_OBSERVED's
     *  in_group. */
    bool (*peer_in_group)(const process_t *proc, const char *uuid_str);
    /** Whether we blocked @p uuid_str (lower-case): PEER_OBSERVED's blocked,
     *  and a blocked peer's tier reads 0 (identity_get_peer_tier). */
    bool (*peer_blocked)(const char *uuid_str);
} identity_ext_t;

/** Register @p ext (static storage). @return 0; -1 NULL/unnamed/duplicate;
 *  -2 full. Refusals go to stderr (this runs before main). */
int identity_ext_register(const identity_ext_t *ext);

/** True iff an identity extension named @p name is registered. */
bool identity_ext_present(const char *name);

/** Refuse a node whose environment declares a feature this binary lacks:
 *  $AT_OWN_GEOHASH or $AT_OWN_PROFILE set and non-empty with no "social"
 *  extension. The node was told to publish its position or profile; starting
 *  without the feature that would do it is a silent misconfiguration. Logs an
 *  ERROR naming the library. @return 0 or -1. */
int identity_ext_check_env(logger_t *logger);

/* Dispatchers, called by id_proc.c only, each with no lock held. */
void identity_ext_init(void);
void identity_ext_reset(void);
void identity_ext_run_start(process_t *proc);
void identity_ext_peer_confirmed(const process_t *proc, const public_identity_t *peer);
void identity_ext_group_update_seen(const process_t *proc, const char *from_uuid_str,
                                    const char *their_group_uuid_str);
void identity_ext_periodic_resync(const process_t *proc);
bool identity_ext_roster_replay(const process_t *proc, int n_observed);
bool identity_ext_peer_in_group(const process_t *proc, const char *uuid_str);
bool identity_ext_peer_blocked(const char *uuid_str);

/** Register @p ext at load time. */
#define IDENTITY_EXT_REGISTER(tag, ext)                                        \
    static void __attribute__((constructor)) identity_ext_register_##tag(void) \
    {                                                                          \
        (void)identity_ext_register(ext);                                      \
    }

/** @} */ /* end of internal_identity */

#endif /* ID_EXT_H */
