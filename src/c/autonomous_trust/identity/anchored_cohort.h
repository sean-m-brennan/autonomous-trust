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

/** @file The anchored cohort (RD_14.4_HOSTILE_JOIN_PLAN.md Phase 6, D8 (b)).
 *
 *  A joiner that counts some of its cohort's members as anchors forms a second
 *  group with them, beside the cohort: its own key, reputation chain and
 *  quorum, no gateway and no rank gate. The lowest uuid among the node and
 *  those anchors mints it and invites the rest; a node accepts only under the
 *  join policy, when the sender and every other listed member are anchors it
 *  counts, and when it holds no other cohort. The coordinator (the lowest-uuid
 *  member) adds late anchors and drops members that refused or did not answer,
 *  rotating the key on either, and never offers a peer the membership it
 *  refused. Two point-to-point verbs: anchored_cohort_invite (the canonical
 *  group, key included) and anchored_cohort_reply ([uuid, key epoch,
 *  accepted]). Reputation learns the cohort over the local ANCHORED_COHORT
 *  message. The Python twin is core/_python/identity/anchored_cohort.py.
 */

#ifndef ANCHORED_COHORT_H
#define ANCHORED_COHORT_H

#include <stdbool.h>

#include "processes/processes.h"
#include "identity/group.h"
#include "identity/identity.h"

/** Seconds the coordinator waits for a member's reply before removing it. */
#define AT_COHORT_REPLY_TIMEOUT 60.0

/** The persisted cohort's file name in the config dir. */
#define AT_COHORT_FILE "anchored_cohort.cfg.json"

extern char ID_COHORT_INVITE[];
extern char ID_COHORT_REPLY[];

/** Register the two verbs' handlers on @p proc (identity). */
void identity_anchored_cohort_register(process_t *proc);

/** Form the cohort, or coordinate the one held. Run on every peer-list change
 *  and on the resync cadence. Mirrors Python _maybe_form_anchored_cohort. */
void identity_anchored_cohort_tick(const process_t *proc);

/** Restore the cohort persisted before a restart (under the policy). */
void identity_anchored_cohort_load(const process_t *proc);

/** A deep copy of the cohort held into @p out (free with
 *  identity_anchored_cohort_release); false when none is held. */
bool identity_anchored_cohort_held(group_t *out);

/** Free what identity_anchored_cohort_held copied. */
void identity_anchored_cohort_release(group_t *g);

/** Test seams: forget everything held (and nothing persisted is touched);
 *  answer "is this peer an anchor" with @p fn instead of the extensions; read
 *  the time from @p clock. NULL restores each. */
void identity_anchored_cohort_reset(void);
void identity_anchored_cohort_set_anchor_fn(
    bool (*fn)(const process_t *proc, const public_identity_t *peer));
void identity_anchored_cohort_set_clock(double (*clock)(void));

#endif /* ANCHORED_COHORT_H */
