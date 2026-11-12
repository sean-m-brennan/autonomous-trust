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

/* ---- Live replication (RD_12.6_LIVE_REPLICATION_PLAN.md section 3.7) -----
 *
 * The requestor's side of live replication is a feature (libat_replication):
 * the core asks it about every result it accepts, and gives it the few
 * negotiation acts it needs. Mirrors Python NegotiationHooks.on_result /
 * periodic and NegotiationProcess.release_result / start_directed. */

/** What a result hook decides. */
typedef enum {
    NEG_RESULT_LEAVE = 0,   /* the core scores and forwards it as ever */
    NEG_RESULT_HOLD,        /* forwarded, its score held for the feature */
    NEG_RESULT_CONSUME      /* a replica's: neither forwarded nor scored */
} neg_result_verdict_t;

/** A result the requestor accepted. Every pointer is valid only during the
 *  call: a feature that keeps the result copies what it needs. */
typedef struct {
    const unsigned char *task;      /* 16 raw uuid bytes */
    const unsigned char *executor;  /* the authenticated sender */
    const char *capability;
    const char *kwargs_json;
    double issued_at;
    const char *result;             /* NULL for none */
    size_t result_len;
    const char *certificate_json;   /* NULL for none */
    const char *prediction_json;    /* NULL for none */
    const char *trace_root;         /* NULL unless a trace was committed */
    int trace_len;
} neg_result_info_t;

/** One feature's result hook. */
typedef struct {
    const char *name;
    /** Decide @p info. Called with the negotiation state locked: it must not
     *  call back into the negotiation process (do that from @c periodic). */
    neg_result_verdict_t (*on_result)(const process_t *proc,
                                      const neg_result_info_t *info);
    /** Once per pass of the negotiation loop, unlocked. */
    void (*periodic)(const process_t *proc);
} neg_result_hook_t;

/** Register @p hook (static storage). @return 0; -1 NULL, unnamed, duplicate
 *  or full (one hook for now). */
int neg_result_hook_register(const neg_result_hook_t *hook);

/** The first decision any hook makes about @p info (LEAVE for none). */
neg_result_verdict_t neg_ext_on_result(const process_t *proc,
                                       const neg_result_info_t *info);

/** Run every hook's @c periodic (the result hook's and the selection
 *  hook's). */
void neg_ext_periodic(const process_t *proc);

/** Register @p hook at load time. */
#define NEG_RESULT_HOOK_REGISTER(tag, hook)                                       \
    static void __attribute__((constructor)) neg_result_hook_register_##tag(void) \
    {                                                                             \
        (void)neg_result_hook_register(hook);                                     \
    }

/** Release a result whose score a hook held: scored @p score on @p channel
 *  when @p have_score, else by the ordinary arms. Not with the state locked. */
void negotiation_release_held(const process_t *proc, const neg_result_info_t *info,
                              bool have_score, double score, const char *channel);

/** Ask one capable peer, other than @p exclude, this node and any peer
 *  heard from lately, to run @p capability with @p kwargs_json: the peer at
 *  @p seed modulo their count, sorted by uuid (Python's rule). Writes the new
 *  task and its peer. @return 0, or -1 when there is no such peer or the
 *  invitation did not leave. Not with the state locked. */
int negotiation_start_replica(const process_t *proc, const char *capability,
                              const char *kwargs_json, const unsigned char *exclude,
                              unsigned long long seed, unsigned char *task_out,
                              unsigned char *peer_out);

/** Propose a verifier-attested score about @p subject (D6 option 3): this
 *  node as verifier, @p evidence_digest and @p scope 64 lowercase hex. */
void negotiation_propose_attestation(const process_t *proc,
                                     const unsigned char *subject, double score,
                                     const char *channel, const char *capability,
                                     const char *evidence_digest, const char *scope);

/** Send @p verb with @p payload (borrowed) to @p peer. @return 0 when the
 *  network queue took it. */
int negotiation_send_replay(const process_t *proc, const char *verb,
                            const unsigned char *peer, const char *payload_json);

/* ---- Selective assignment (RD_12.7_SELECTIVE_ASSIGNMENT_PLAN.md section 3) ---
 *
 * A requestor may assign a task to k of its N capable peers, or draw a
 * probe's target, through a feature (libat_selection). The core asks it
 * before an announce goes out and after a verified decline; shows it every
 * fresh invitation a worker admits; and hands it every scored result of a
 * task it drew. Mirrors Python NegotiationHooks.select_participants,
 * on_decline, on_invitation and on_score. Every call is made with the
 * negotiation state locked, so none may call back into the negotiation
 * process: a feature that has to send does it from its periodic pass. */

/** The capable, present peers a task may go to, in the core's peer order. */
typedef struct {
    const unsigned char (*uuid)[16];
    const int *tier;            /* each one's trust tier, as the core reads it */
    size_t n;
} neg_candidates_t;

/** One feature's selection hooks. */
typedef struct {
    const char *name;
    /** Choose the invitees of @p task_uuid (36-char string) for
     *  @p capability among @p cands: @p target is the peer the start was
     *  addressed to (16 raw bytes), NULL for a fan-out. On true, @p selected
     *  holds one flag per candidate and @p draw_json the invitation's draw.
     *  False leaves the task to the core. */
    bool (*select)(const process_t *proc, const char *task_uuid,
                   const char *capability, const neg_candidates_t *cands,
                   const unsigned char *target, bool *selected,
                   char *draw_json, size_t draw_len);
    /** @p peer declined @p task_uuid: choose its replacement among
     *  @p cands, as @c select does. False for none. */
    bool (*on_decline)(const process_t *proc, const char *task_uuid,
                       const char *capability, const unsigned char *peer,
                       const neg_candidates_t *cands, bool *selected,
                       char *draw_json, size_t draw_len);
    /** A fresh invitation from @p requestor carrying @p draw_json (never
     *  empty). Observes only. */
    void (*on_invitation)(const process_t *proc, const unsigned char *requestor,
                          const char *draw_json);
    /** @p executor's result for drawn task @p task_uuid scored @p score. */
    void (*on_score)(const process_t *proc, const char *task_uuid,
                     const unsigned char *executor, double score);
    /** Once per pass of the negotiation loop, unlocked: where the feature
     *  sends. */
    void (*periodic)(const process_t *proc);
} neg_select_hook_t;

/** Register @p hook (static storage). @return 0; -1 NULL, unnamed, duplicate
 *  or full (one hook for now). */
int neg_select_hook_register(const neg_select_hook_t *hook);

/** The registered hook, or NULL. */
const neg_select_hook_t *neg_ext_select_hook(void);

/** Register @p hook at load time. */
#define NEG_SELECT_HOOK_REGISTER(tag, hook)                                       \
    static void __attribute__((constructor)) neg_select_hook_register_##tag(void) \
    {                                                                             \
        (void)neg_select_hook_register(hook);                                     \
    }

#endif /* NEG_EXT_H */
