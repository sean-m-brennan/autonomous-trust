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

#ifndef TX_CHANNEL_H
#define TX_CHANNEL_H

/** @addtogroup internal_reputation
 *  @{
 */

#include <stdbool.h>
#include <string.h>

/****************************
 * Evidence channels (R+D.md §12.8, doc/verification_oracle.md "Keep the
 * channels separate")
 *
 * A transaction score says HOW WELL a peer did. The channel says HOW WE KNOW
 * — and those are not the same fact. "Refuted by conservation of energy,"
 * "poorly calibrated over the last hundred predictions," "disagrees with the
 * swarm," "failed a replicated task," and "contradicted its own signed
 * archive" are different findings warranting different responses (immediate
 * demotion, gradual decay, an opened dispute). Collapsing them into one
 * scalar before the score reaches the reputation algebra destroys exactly what
 * an escalation path would need to choose between those responses, and a
 * bare score is what the wire carried before this field existed.
 *
 * This slice is LEGIBILITY ONLY: the channel is recorded, carried on the wire,
 * and logged, but NOTHING branches on it. Weighting, the consensus EMA, tier
 * placement, and slashing are all byte-for-byte unchanged. That is deliberate
 * — the differentiated responses named above are worth building only once the
 * evidence they would act on is actually reaching the algebra, and the channel
 * has to cross the wire first for that to be true. A reader looking for the
 * demotion policy will not find it here, and that is not an omission.
 *
 * This is a CLOSED set: an unknown spelling is REFUSED, not passed through.
 * A channel that silently becomes "some string a peer sent" is worth less than
 * no channel at all, since the whole value is that a demotion reason means one
 * agreed thing on both sides of the wire. Adding a channel is a deliberate
 * edit here AND in the Python twin.
 *
 * These spellings must match Python TX_CHANNEL_* in
 * src/autonomous-trust/autonomous_trust/core/_python/reputation/reputation.py
 * verbatim — a divergence is a score one twin accepts and the other drops.
 ****************************/

/** Ordinary grading of a completed task: the negotiation-driven path that
 *  produced every score before channels existed. The default, and what an
 *  absent/empty channel normalizes to, so a legacy peer's scores stay
 *  indistinguishable from a tagged peer's task outcomes. */
#define TX_CHANNEL_TASK_OUTCOME       "task_outcome"

/** Hard refutation by conservation law or dimensional analysis. Needs no
 *  history and no training data (oracle layer 1) — a verdict, not a drift. */
#define TX_CHANNEL_PHYSICAL           "physical"

/** A certificate-carrying task interface checked out (or failed to). Interface
 *  work rather than algorithm work (oracle layer 2); this is where a ZKP
 *  verdict on a task result lands. */
#define TX_CHANNEL_CERTIFICATE        "certificate"

/** Conformal coverage audit / prequential log-loss: the peer is not wrong so
 *  much as overconfident, which averaged reputation cannot see (layers 3-4). */
#define TX_CHANNEL_CALIBRATION        "calibration"

/** The peer contradicted its own signed, hash-chained claim archive (layer 5).
 *  The cheapest channel of the set: falsification needing no peers, no
 *  physics, and no domain knowledge. */
#define TX_CHANNEL_SELF_CONSISTENCY   "self_consistency"

/** Outcome of sampled replication of the peer's work (layer 6). */
#define TX_CHANNEL_REPLICATION        "replication"

/** The peer disagrees with the swarm (layers 7-8). Named separately BECAUSE
 *  it is the one that should eventually open a dispute rather than levy a
 *  penalty — a majority is not an oracle. */
#define TX_CHANNEL_SWARM_DISAGREEMENT "swarm_disagreement"

/** A honeypot probe: a task whose correct answer the requestor already knows,
 *  checked against that answer (R+D.md §12.7; doc/verification_oracle.md
 *  "Anchoring and the adversarial fraction"). The AT bootstrap corpus
 *  (at.handshake / at.time-attest / at.echo-challenge) is this pattern.
 *
 *  Kept distinct from TX_CHANNEL_TASK_OUTCOME because a probe verdict is the
 *  one piece of evidence that does NOT degrade as the adversarial fraction
 *  rises: every other channel is ultimately an aggregate over peers, and the
 *  Byzantine-robust aggregation results are explicit that a majority cannot be
 *  beaten without an external reference. A probe IS that reference, so an
 *  escalation path that cannot tell "failed a known-answer challenge" from
 *  "scored badly on a task" has thrown away its only anchor.
 *
 *  Distinct from TX_CHANNEL_CERTIFICATE too, and the difference is who chose
 *  the question: a certificate is a proof the PEER supplies about its own work,
 *  while a probe is a question the VERIFIER authored and already knows the
 *  answer to. A peer can decline to carry a certificate; it cannot tell a
 *  probe from real work. */
#define TX_CHANNEL_PROBE              "probe"

/** Storage bound for a channel name, sized past the longest spelling above
 *  ("swarm_disagreement", 18) with room for a future one. Fields are
 *  `[TX_CHANNEL_NAMELEN + 1]` for the terminator, matching CAP_NAMELEN's
 *  convention next door. */
#define TX_CHANNEL_NAMELEN 31

/** The full closed set, in the build order of doc/verification_oracle.md.
 *  Iterated by @ref tx_channel_valid and mirrored by Python TX_CHANNELS. */
#define TX_CHANNEL_ALL \
    TX_CHANNEL_TASK_OUTCOME, \
    TX_CHANNEL_PHYSICAL, \
    TX_CHANNEL_CERTIFICATE, \
    TX_CHANNEL_CALIBRATION, \
    TX_CHANNEL_SELF_CONSISTENCY, \
    TX_CHANNEL_REPLICATION, \
    TX_CHANNEL_SWARM_DISAGREEMENT, \
    TX_CHANNEL_PROBE

/** True iff @p channel is exactly one of the closed set's spellings.
 *
 *  NULL and "" are NOT valid here — they are *absent*, which is a different
 *  question from *invalid*. Callers normalize absence with
 *  @ref tx_channel_or_default first; a caller that hands this a bare NULL is
 *  asking whether an unset field is a legal channel name, and the answer is
 *  no. Matching is byte-exact and case-sensitive: "Physical" is refused,
 *  because a channel that quietly accepts near-misses stops being a closed
 *  set. */
static inline bool tx_channel_valid(const char *channel)
{
    if (channel == NULL || channel[0] == '\0')
        return false;
    static const char *const all[] = { TX_CHANNEL_ALL };
    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++)
        if (strcmp(channel, all[i]) == 0)
            return true;
    return false;
}

/** @p channel if it is set at all, else the default channel.
 *
 *  Absence means "a peer or an app that predates channels," which is a task
 *  outcome by construction — every producer before this field was grading a
 *  completed task. Note this does NOT validate: it resolves absence only, so
 *  a garbage spelling survives it and is caught by @ref tx_channel_valid at
 *  the boundary that refuses. Keeping the two apart is what lets a caller
 *  report "unknown channel 'physicall'" instead of silently grading it as a
 *  task outcome. */
static inline const char *tx_channel_or_default(const char *channel)
{
    return (channel != NULL && channel[0] != '\0')
               ? channel : TX_CHANNEL_TASK_OUTCOME;
}

/****************************
 * What a channel DOES (R+D.md §12.8, the differentiated responses)
 *
 * Two responses, both settled with the user before implementing:
 *
 *   weighting        every channel carries an integer multiplier on the
 *                    consensus EMA, composed with the per-capability
 *                    transaction weight (they multiply: a heavy capability
 *                    refuted on physics counts as both).
 *   slash-eligible   the hard-falsification channels additionally make a
 *                    defection-grade score grounds to PROPOSE a slash, which
 *                    the EXISTING quorum co-signature then accepts or refuses.
 *
 * Both apply ONLY to evidence this node produced itself. The scorer chooses
 * its own channel, so honoring a remote tag would hand every peer a lever on
 * every other peer's reputation — tag a fabricated 0.0 `physical` and it lands
 * with triple weight and an accusation attached. A score off the wire keeps
 * its channel for legibility and is weighted by capability alone.
 *
 * Deliberately NOT a third mechanism: `swarm_disagreement` should open a
 * DISPUTE rather than levy a penalty (doc/verification_oracle.md), and no
 * dispute machinery exists in either runtime.
 *
 * These values and this set MUST match Python's TX_CHANNEL_WEIGHTS /
 * TX_CHANNELS_HARD (reputation.py).
 ****************************/

/** EMA multiplier for a locally-produced score, by channel.
 *
 *  Applied by folding the score into the EMA that many times (the same repeat
 *  mechanism the per-capability transaction weight uses, which is why these
 *  are small integers and why the two multiply).
 *
 *  A ranking of how much one observation tells you, not a tuning surface:
 *  1 = one peer's reading of one event; 2 = corroborated by construction (a
 *  replication has several executors; a probe is checked against an answer the
 *  verifier authored); 3 = a verdict that needs no history at all.
 *  `calibration` is deliberately 1 — the oracle doc names it as the channel
 *  that should decay a peer *gradually*.
 *
 *  Unknown channels weigh 1: an unrecognized channel must never weigh MORE
 *  than a recognized one, or adding a channel on one side of the wire would
 *  silently amplify it on the other. */
static inline int tx_channel_weight(const char *channel)
{
    const char *ch = tx_channel_or_default(channel);
    if (strcmp(ch, TX_CHANNEL_PHYSICAL) == 0
        || strcmp(ch, TX_CHANNEL_CERTIFICATE) == 0
        || strcmp(ch, TX_CHANNEL_SELF_CONSISTENCY) == 0)
        return 3;
    if (strcmp(ch, TX_CHANNEL_REPLICATION) == 0
        || strcmp(ch, TX_CHANNEL_PROBE) == 0)
        return 2;
    return 1;
}

/** True iff @p channel is a FALSIFICATION rather than a grade: the peer did
 *  not do poorly, it asserted something that is not true.
 *
 *  Each of the three is a verdict reachable without consulting any other peer
 *  — physics refutes, a certificate fails to verify, an archive contradicts
 *  itself — which is exactly what makes a single observation of one sufficient
 *  grounds to accuse.
 *
 *  `probe` is deliberately NOT here even though its ground truth is certain: a
 *  probe is synthetic traffic the verifier generates continuously (§12.7), so
 *  making one failed probe slash-eligible would put every node's exclusion in
 *  the hands of its own probe cadence. It gets the corroborated weight
 *  instead. Mirrors Python TX_CHANNELS_HARD. */
static inline bool tx_channel_is_hard(const char *channel)
{
    if (channel == NULL || channel[0] == '\0')
        return false;
    return strcmp(channel, TX_CHANNEL_PHYSICAL) == 0
           || strcmp(channel, TX_CHANNEL_CERTIFICATE) == 0
           || strcmp(channel, TX_CHANNEL_SELF_CONSISTENCY) == 0;
}

/** Prefix of the evidence-channel slash reasons (R+D.md §12.8). The suffix is
 *  the channel verbatim, so the closed channel set defines the closed reason
 *  set and neither can drift from the other. Mirrors Python
 *  SlashAttestation.REASON_REFUTED_PREFIX. */
#define REP_SLASH_REASON_REFUTED_PREFIX "refuted_"

/** Write the slash reason for a hard @p channel into @p out ("refuted_" plus
 *  the channel). Returns false — leaving @p out untouched — for a channel that
 *  is not slash-eligible, rather than inventing a reason no reader could
 *  place. The reason is part of the signed slash designation, so unlike an
 *  evidence_ref it cannot be altered in flight. */
static inline bool tx_channel_slash_reason(const char *channel,
                                           char *out, size_t outlen)
{
    if (out == NULL || outlen == 0 || !tx_channel_is_hard(channel))
        return false;
    size_t pfx = sizeof(REP_SLASH_REASON_REFUTED_PREFIX) - 1;
    if (strlen(channel) + pfx + 1 > outlen)
        return false;
    memcpy(out, REP_SLASH_REASON_REFUTED_PREFIX, pfx);
    memcpy(out + pfx, channel, strlen(channel) + 1);
    return true;
}

/** @} */ /* end of internal_reputation */

#endif  /* TX_CHANNEL_H */
