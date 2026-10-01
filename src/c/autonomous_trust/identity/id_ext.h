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
#include <stdint.h>

#include <sodium.h>

#include "identity/identity.h"
#include "processes/processes.h"
#include "utilities/logger.h"

/** Most identity extensions. */
#define IDENTITY_EXT_MAX 4

/** An admission gate's verdict. Ordered: the dispatcher returns the most
 *  restrictive any extension gives. */
typedef enum {
    IDENTITY_EXT_ADMIT = 0,
    /** Admitted, but unproved: the extension has published a ceiling. */
    IDENTITY_EXT_ADMIT_CAPPED = 1,
    IDENTITY_EXT_REJECT = 2,
} identity_ext_gate_t;

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

    /* An admission authority (ZTA, FEATURE_SPLIT_PLAN Phase 6). Each is
     * phrased so that NULL, and no extension at all, is a node with no such
     * authority: everyone admitted, nothing refused, nothing proved. */

    /** The welcoming committee is about to vote on @p peer, which claimed the
     *  operator key @p claimed_key (zeroed on @p peer itself, to be re-earned
     *  here). May write what it proves onto @p peer (anchors, a verified
     *  operator key). Publishes any standing it decides itself. */
    identity_ext_gate_t (*admission_gate)(const process_t *proc, public_identity_t *peer,
                                          const uint8_t claimed_key[crypto_sign_PUBLICKEYBYTES]);
    /** Whether a join request from @p new_id must be refused before the vote
     *  (e.g. it proved no anchor we share). */
    bool (*join_refused)(const process_t *proc, const public_identity_t *new_id);
    /** Whether we must not federate through the member @p uuid_str
     *  (lower-case): as a child gateway, a parent, or a hierarchy claimant. */
    bool (*gateway_refused)(const process_t *proc, const char *uuid_str);
    /** Whether @p claim carries an operator-class credential (an attestation
     *  re-verify). */
    bool (*operator_credential)(const process_t *proc, const public_identity_t *claim);
    /** Whether the credential @p carried presents chains to an anchor we
     *  accept. Asked by REPUTATION about a co-signer it has never admitted, so
     *  @p proc is the reputation process. */
    bool (*credential_anchored)(const process_t *proc, const public_identity_t *carried);
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

/** Refuse a node whose configuration turns on a feature this binary lacks: a
 *  zta_policy.cfg.json in @p cfg_dir (NULL: the node's cfg dir) with
 *  "enabled": true and no "zta" extension (libat_zta). Without the library the
 *  section is unregistered, so the file would be skipped as unknown and the
 *  node would start enforcing nothing. Logs an ERROR naming the file and the
 *  library. @return 0 or -1. */
int identity_ext_check_config(const char *cfg_dir, logger_t *logger);

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
/* The admission-authority dispatchers (each with no lock held). A REJECT
 * stops at the first extension that gives it. */
identity_ext_gate_t identity_ext_admission_gate(const process_t *proc, public_identity_t *peer,
                                                const uint8_t claimed_key[crypto_sign_PUBLICKEYBYTES]);
bool identity_ext_join_refused(const process_t *proc, const public_identity_t *new_id);
bool identity_ext_gateway_refused(const process_t *proc, const char *uuid_str);
bool identity_ext_operator_credential(const process_t *proc, const public_identity_t *claim);
bool identity_ext_credential_anchored(const process_t *proc, const public_identity_t *carried);

/** Register @p ext at load time. */
#define IDENTITY_EXT_REGISTER(tag, ext)                                        \
    static void __attribute__((constructor)) identity_ext_register_##tag(void) \
    {                                                                          \
        (void)identity_ext_register(ext);                                      \
    }

/** @} */ /* end of internal_identity */

#endif /* ID_EXT_H */
