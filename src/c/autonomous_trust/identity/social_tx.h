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

/**
 * @file social_tx.h
 * @brief Agora social-interaction reputation accrual (Increment 8).
 *
 * Reputation in this codebase is consensus over BILATERAL transactions: a
 * transaction only commits — and only then moves a peer's earned score — when
 * BOTH parties submit a score for the SAME task_uuid, and it moves the two
 * submitters (each by the counterparty's score). Agora accrual rides that model
 * directly: the two peers who actually interact ARE the two transaction slots, so
 * a one-way interaction (an unrequited DM, a back-scratch that is not returned)
 * never fills the second slot and never commits. That is the "bilateral_recent"
 * reciprocity rule, enforced by the transaction model rather than by trust in a
 * submitter.
 *
 * Each qualifying interaction derives a shared, deterministic task_uuid that both
 * peers compute independently (no wire field to forge), then submits a
 * diminishing-returns score to the reputation process. The effect surfaces to the
 * app through the existing PEER_REPUTATION score — no new app-boundary state.
 *
 * task_uuid CANONICAL (cross-language crux; MUST stay in lockstep with the Python
 * twin social_task_uuid() in capabilities.py):
 *
 *   canonical = domain_bytes || 0x00
 *             || uuid_min(a,b)[16] || uuid_max(a,b)[16]
 *             || tail_bytes
 *
 * The blake2b-256 hash of the canonical bytes, first 16 bytes, is the task_uuid.
 * The domain tag (@ref AT_SOCIAL_DOMAIN_CONN etc.) keeps the interaction kinds
 * from colliding. The uuid_min/uuid_max ordering makes the id independent
 * of which peer computes it.
 */

#ifndef AUTONOMOUS_TRUST_IDENTITY_SOCIAL_TX_H
#define AUTONOMOUS_TRUST_IDENTITY_SOCIAL_TX_H

#include <stddef.h>
#include <stdint.h>
#include <uuid/uuid.h>

/* Domain tags — one per interaction kind, so a connection, a DM, and a post
 * engagement between the same two peers never derive the same task_uuid. */
#define AT_SOCIAL_DOMAIN_CONN "agora-conn"
#define AT_SOCIAL_DOMAIN_DM   "agora-dm"
#define AT_SOCIAL_DOMAIN_POST "agora-post"
/* A first-person report (Phase 4 P4.1). Tail is reporter_uuid[16] || seq u64le:
 * the reporter's uuid is IN the tail, unlike a decline's bare seq, because the
 * two directions of a report are two different acts. With a bare seq, ada
 * reporting bob at her seq 42 and bob reporting ada at his seq 42 would derive
 * ONE task, and the second report would land in the first one's slots. */
#define AT_SOCIAL_DOMAIN_REPORT "agora-report"

/* Diminishing-returns positive accrual (user-locked, Increment 8):
 *   S_pos(count) = baseline + delta/count
 * count 1 -> 0.90 (the tier-4 floor), count 2 -> 0.775, ... -> baseline 0.65.
 * Peaks at a strong first mutual interaction but, folded through the slow
 * consensus EMA, social activity alone plateaus a peer near the tier-2 "established"
 * floor (0.65) and never manufactures the tier-3/4 trust that real task work earns.
 * MUST match the Python twin. */
#define AT_SOCIAL_POS_BASELINE 0.65
#define AT_SOCIAL_POS_DELTA    0.25

/* In-model bilateral negative for an explicit connection DECLINE. Above the
 * COMM_CUTOFF (0.10) so a single decline is a clear demerit but not an exile. */
#define AT_SOCIAL_NEG_SCORE 0.30

/* A REPORT (Phase 4 P4.1): the reporter's first-person account that an exchange
 * went badly, staged on the `first_person` channel. Worse than a decline — "this
 * went badly" is stronger than "no thank you" — and still above COMM_CUTOFF
 * (0.10), so one report is a serious demerit and not an exile. Deliberately not
 * 0.0: a zero is an authority finding wearing a scalar's clothes, and authority
 * findings are ceilings (PEER_STANDING), never scores.
 *
 * Its safety comes from BILATERAL PAIRING and the accrual caps, not from any
 * quorum: Paxos here commits on one grant (ISSUES.md §2.13), so nothing may be
 * built on the quorum size. */
#define AT_SOCIAL_REPORT_SCORE 0.15

/* What the REPORTED node stages about the reporter, so the report can pair.
 * A bilateral transaction moves each party by the other's score, so the
 * reported node's half is unavoidably a score ABOUT THE REPORTER. The social
 * baseline: reporting neither punishes the reporter (a mirrored 0.15 would make
 * every report mutual damage, and deter the people who most need to report) nor
 * rewards them (so a report is no way to farm standing). Staged on the default
 * channel — it is not the reported node's first-person account of anything. */
#define AT_SOCIAL_REPORTER_SCORE AT_SOCIAL_POS_BASELINE

/* One report per target per day, on BOTH sides: the reporter makes at most one
 * about each peer, and the reported node pairs at most one from each reporter.
 * One report is one account; a second the same day adds no information. The
 * reported side's cap is what bounds a FORKED reporter, whose own caps are
 * whatever it says they are. On the reporter's side a report ALSO spends the
 * shared per-edge and global budget below. */
#define AT_SOCIAL_REPORT_DAILY_CAP 1

/* "Recently interacted" window for the bilateral_recent gate (seconds, 7 days):
 * longer than REP_DECAY_ONSET (3600s) yet well inside REP_DECAY_HALF_LIFE
 * (86400s), so accrual outpaces decay for an actively tended edge. */
#define AT_SOCIAL_RECENCY_WINDOW 604800.0

/* Accrual caps: a chatty pair cannot inflate past a few commits/day, and a Sybil
 * fan-out is bounded globally. */
#define AT_SOCIAL_PER_EDGE_DAILY_CAP 3
#define AT_SOCIAL_GLOBAL_DAILY_CAP   20

/* One DM accrual opportunity per edge per hour (combined with the per-edge daily
 * cap). Also the bucket that lets both peers converge on the same DM task_uuid
 * without a shared sequence number. */
#define AT_SOCIAL_DM_BUCKET_SECONDS 3600

/* Seconds per day, for the rolling daily-cap window. */
#define AT_SOCIAL_DAY_SECONDS 86400

/**
 * Derive the shared bilateral task_uuid for a social interaction.
 *
 * @param domain    one of AT_SOCIAL_DOMAIN_* (NUL-terminated).
 * @param a,b       the two participants, in either order (canonicalized inside).
 * @param tail      extra binding bytes (a u64le seq, a u64le epoch bucket, or the
 *                  16 raw bytes of a post content-id); may be NULL if tail_len==0.
 * @param tail_len  length of @p tail in bytes.
 * @param out       receives the 16-byte task_uuid.
 * @return 0 on success, -1 on bad argument.
 */
int at_social_task_uuid(const char *domain, const uuid_t a, const uuid_t b,
                        const uint8_t *tail, size_t tail_len, uuid_t out);

/** Diminishing-returns positive score for the @p count-th interaction on an edge
 * (count is 1-based; count<=0 is treated as 1). Always within the TX [0,1] scale. */
double at_social_pos_score(int count);

#endif /* AUTONOMOUS_TRUST_IDENTITY_SOCIAL_TX_H */
