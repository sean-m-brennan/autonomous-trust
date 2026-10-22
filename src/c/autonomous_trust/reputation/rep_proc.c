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

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <math.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>

#include "processes/processes.h"
#include "processes/extension.h"
#include "processes/capabilities.h"
#include "reputation/reputation.h"
#include "algorithms/paxos.h"
#include "structures/map.h"
#include "structures/array.h"
#include "structures/data.h"
#include "utilities/message.h"
#include "utilities/send_retry.h"
#include "utilities/msg_types_priv.h"
#include "utilities/exception.h"
#include "utilities/probes.h"
#include "network/net_message.h"
#include "identity/identity_priv.h"   /* public_identity_to/from_json, unhexlify */
#include "identity/id_ext.h"   /* identity_ext_credential_anchored */
#include "identity/id_proc_priv.h"   /* identity_self_identity */
#include "config/configuration.h"   /* get_cfg_dir, CFG_PATH_LEN */
#include "config/discover.h"        /* CFG_FILE_EXT */
#include "reputation/rep_ext.h"   /* extensions' trust seeds */
#include "reputation/rep_proc_priv.h"

#define EREP_PAXOS 253
DEFINE_ERROR(EREP_PAXOS, "Paxos consensus error");

/****************************
 * Reputation-derived trust-tier elevation — mirrors Python
 * ReputationProcess TIER_FLOORS / _trust_tier / _publish_tier_change
 * (repprocess.py:52-57, 583-619). Each entry is (score_floor, tier).
 * Walks top-down so the highest matching floor wins; scores below
 * the lowest map to 0.
 *
 * Keep monotonically increasing in floor and tier to preserve the
 * walk-from-top invariant. Any change here must land in Python's
 * TIER_FLOORS at the same time.
 *
 * NOTE: trust tier is distinct from network rank (peer->rank) — rank
 * is topology / one-hop reachability, populated from identity.json.
 * See doc/architecture/trust-tiers.md §1 for the disambiguation.
 ****************************/

typedef struct { double floor; int tier; } tier_floor_t;
static const tier_floor_t TIER_FLOORS[] = {
    {0.50, 1},
    {0.65, 2},
    {0.80, 3},
    {0.90, 4},
};
#define NUM_TIER_FLOORS (sizeof(TIER_FLOORS) / sizeof(TIER_FLOORS[0]))

static int _trust_tier(double score)
{
    for (int i = (int)NUM_TIER_FLOORS - 1; i >= 0; i--) {
        if (score >= TIER_FLOORS[i].floor)
            return TIER_FLOORS[i].tier;
    }
    return 0;
}

/* The highest score that still maps to @p tier — the next tier's floor,
 * stepped down by one representable double.
 *
 * Derived from TIER_FLOORS rather than written as a literal so retuning the
 * ladder cannot leave a stale ceiling behind that quietly grants the tier
 * above. nextafter (not a hand-picked epsilon) because the clamp has to
 * satisfy _trust_tier(ceiling) == tier exactly: an epsilon too small rounds
 * back onto the floor and grants the very tier the clamp exists to withhold.
 * The top tier has no ceiling. Mirrors Python _tier_ceiling.
 *
 * Stepped down in FLOAT precision: reputations_t stores scores as floats, and
 * a double just under 0.80 rounds back up to 0.80000001 in storage, so a peer
 * clamped to tier 2 read back as tier 3 everywhere the stored score is read
 * (the attest co-sign gate among them). Found by rep_tenure_test. 0.65 only
 * escaped because it rounds down as a float. Python stores doubles, so its
 * ceiling sits a few 1e-8 higher; both map to the same tier. */
static double _tier_ceiling(int tier)
{
    for (size_t i = 0; i < NUM_TIER_FLOORS; i++) {
        if (TIER_FLOORS[i].tier == tier + 1)
        {
            float f = (float)TIER_FLOORS[i].floor;
            while ((double)f >= TIER_FLOORS[i].floor)
                f = nextafterf(f, 0.0f);
            return (double)f;
        }
    }
    return 1.0;
}

/****************************
 * Verifiable warm start constants — mirror repprocess.py.
 ****************************/

/* Tier a peer may hold on restoration when the persisted evidence does not
 * cover it. Tier 1 (presence/communication) because an
 * authenticated-but-COMPROMISED asset passes ZTA admission by definition —
 * credentials are exactly what it holds — so restoring a historically-earned
 * high tier the instant it is admitted re-opens the hole the system exists to
 * close, and for a short-lived asset there is no time for behavioural
 * re-evaluation to catch it first. Mirrors UNVERIFIED_RESTORE_TIER. */
#define REP_UNVERIFIED_RESTORE_TIER 1

/* Basename of the operational reputation snapshot, whose evidence
 * `reputation-history.cfg.json` attests. Its MTIME is what the offline-gap
 * decay measures from (_seed_idle_from_snapshot). */
#define REP_SNAPSHOT_FILE "reputation"

/* Seconds between checkpoint proposals this node originates (0 disables).
 * Checkpointing used to be reactive only — nothing ever triggered it — so no
 * deployment held a checkpoint, which meant no warm start could verify: the
 * mechanism above would have been unreachable in practice. Mirrors Python
 * CHECKPOINT_INTERVAL / AT_REP_CHECKPOINT_SEC. */
#define REP_CHECKPOINT_INTERVAL_DEFAULT 300.0
/* Seconds between rescore sweeps (_rescore_peers). Mirrors Python
 * RESCORE_INTERVAL / AT_REP_RESCORE_SEC. */
#define REP_RESCORE_INTERVAL_DEFAULT 60.0
#define REP_RESCORE_INTERVAL \
    (reputation_env_double("AT_REP_RESCORE_SEC", REP_RESCORE_INTERVAL_DEFAULT))
/* Seconds a member must have been in this node's peer list before it may hold
 * a tier above REP_TENURE_TIER (doc/architecture/reputation.md, "Tenure"). 0,
 * the default, turns the gate off. Mirrors Python MIN_TENURE /
 * AT_REP_MIN_TENURE_SEC. */
#define REP_MIN_TENURE (rep_state.tenure_min_override >= 0.0 \
    ? rep_state.tenure_min_override \
    : reputation_env_double("AT_REP_MIN_TENURE_SEC", 0.0))
/* The highest tier a member short of its tenure may hold: below the
 * replication tier (3), so a fresh sybil can neither replicate nor be counted
 * as a replica. */
#define REP_TENURE_TIER 2
#define REP_CHECKPOINT_INTERVAL \
    (reputation_env_double("AT_REP_CHECKPOINT_SEC", \
                           REP_CHECKPOINT_INTERVAL_DEFAULT))
/* How long OUR half of a task may go uncommitted before it is proposed again,
 * and how many times (ISSUES §2.24): a half whose co-signing round is lost on
 * the way is otherwise lost for good. Mirrors Python
 * COMMIT_TIMEOUT / AT_REP_COMMIT_TIMEOUT_SEC and COMMIT_RETRIES. */
#define REP_COMMIT_TIMEOUT_DEFAULT 15.0
/* Entries rep_state.round_granters or round_acceptors may hold before it
 * starts over. */
#define REP_ROUND_ACCEPTORS_CAP 4096
#define REP_COMMIT_TIMEOUT \
    (reputation_env_double("AT_REP_COMMIT_TIMEOUT_SEC", \
                           REP_COMMIT_TIMEOUT_DEFAULT))
#define REP_COMMIT_RETRIES 5
/* A half that used up its REP_COMMIT_RETRIES is PARKED, not dropped (ISSUES
 * §2.60). A minority island cannot commit since §2.13's majority rule, and it
 * waits out a partition far longer than five retries; dropped, its halves
 * never reached the healed chain, since only a COMMITTED entry goes back to
 * the pool after an adoption. A parked half is re-proposed when
 * the chain grows from a peer (_wake_parked_locked), and otherwise every
 * REP_PARK_RETRY seconds, until REP_PARK_TTL. Mirrors Python PARK_RETRY /
 * AT_REP_PARK_RETRY_SEC and PARK_TTL / AT_REP_PARK_TTL_SEC. */
#define REP_PARK_RETRY_DEFAULT 120.0
#define REP_PARK_RETRY \
    (reputation_env_double("AT_REP_PARK_RETRY_SEC", REP_PARK_RETRY_DEFAULT))
#define REP_PARK_TTL_DEFAULT 86400.0
/* Only a half that could not REACH a majority is parked (§2.60). Parking
 * contention losers too piled every node's probe losers into a backlog that
 * swamped the heal (part-2123724). Reach is measured per PEER, not per round:
 * a majority of the group, counting us, must have sent us any reputation frame
 * within this many commit timeouts of the decision. Counting the answers to a
 * half's own rounds undercounted (part-2136648): a round is retired when it is
 * re-proposed under a new ballot, so an answer that waited out a full queue
 * found nothing to land on, and a whole connected group parked its losers. */
#define REP_REACH_WINDOW_TIMEOUTS 2.0
/* A woken half is unparked with this many retries, twice a fresh half's: it
 * waited out the split, and the heal is its contended moment (part-2272442,
 * where ben's reaction lost six post-heal rounds in a row). */
#define REP_WAKE_RETRIES (2 * REP_COMMIT_RETRIES)
/* PROBE BACKPRESSURE (§2.60, part-2314213). AT's own probe halves (handshake,
 * time-attest, echo-challenge) carry an "at." capability; an app half carries
 * its app's, or none. After the heal, seven nodes proposed ~2,800 rounds in
 * four minutes, 95% of them probes, and ~150 committed, one chain slot at a
 * time: bob's app reaction lost all 24 of its rounds in that lottery. So a node
 * keeps at most REP_MAX_PROBE_HALVES probe halves in awaiting_commit (a new one
 * past that is dropped), and while an app half of its own is pending it
 * proposes no probe at all: new ones are dropped, and overdue ones wait. */
#define REP_PROBE_CAP_PREFIX "at."
#define REP_MAX_PROBE_HALVES_DEFAULT 4.0
#define REP_MAX_PROBE_HALVES \
    (reputation_env_double("AT_REP_MAX_PROBE_HALVES", \
                           REP_MAX_PROBE_HALVES_DEFAULT))
/* A wake spreads its halves over this many seconds, by task, so a whole
 * island's backlog does not hit the healed group in one tick. */
#define REP_WAKE_SPREAD_SEC 5.0
#define REP_PARK_TTL \
    (reputation_env_double("AT_REP_PARK_TTL_SEC", REP_PARK_TTL_DEFAULT))

/* How long a verifier's attestation round may stay short of a quorum before
 * its propose goes out again, and how many times (ISSUES §2.40). The propose is
 * a one-shot fan-out, and the network queue drops it under load
 * (Stele st-660084: the observer's copy was lost, the owner's arrived and was
 * declined as the subject's, and the round sat pending forever). Re-sending is
 * safe: the task id is derived from (verifier, subject, digest), so a repeat
 * is the same round, and a co-signer signs the same designation again. After
 * the last try the round is abandoned and its pending state dropped. Mirrors
 * Python ATTEST_RETRY_SEC / AT_REP_ATTEST_RETRY_SEC and ATTEST_RETRIES. */
#define REP_ATTEST_RETRY_DEFAULT 15.0
#define REP_ATTEST_RETRY \
    (reputation_env_double("AT_REP_ATTEST_RETRY_SEC", REP_ATTEST_RETRY_DEFAULT))
#define REP_ATTEST_RETRIES 5
#define REP_ATTEST_RETRY_MAX 16

/* Forward declaration — definition follows _ensure_init/state struct.
 * Emits a local-IPC tier_update to the identity process queue iff the
 * peer's trust tier has changed since the last publication, and an
 * exclude/readmit control message to the network process iff the peer
 * crossed the COMM_CUTOFF communication cut-off. Mirrors Python's
 * `_publish_tier_change` in repprocess.py. Takes @p proc to resolve the
 * peer's address (from proc->protocol.peers) for the exclusion message. */
static void _publish_tier_change(const process_t *proc,
                                 const uuid_t peer_uuid, double score);
/* Resolve @p peer_uuid to an address and send a Network exclude/readmit
 * control message to the network process. Mirrors Python
 * ReputationProcess._publish_exclusion. */
static void _publish_exclusion(const process_t *proc,
                               const uuid_t peer_uuid, bool excluded);
/* A standing as an authority finding (doc/architecture/zta-integration.md).
 * Bound @p score by what some authority proved about @p peer_uuid, and
 * act on an arriving standing. Mirrors Python's _apply_standing_ceiling /
 * _apply_peer_standings / _unwind_standing_failure in repprocess.py.
 *
 * ALWAYS COMPILED (Phase 4 P4.1). ZTA was the first authority to need a
 * ceiling; an Ethne expulsion is the second, and it arrives on a build with
 * AT_ZTA off. */
static double _standing_apply_ceiling(const uuid_t peer_uuid, double score);
static void _handle_peer_standing(const process_t *proc,
                                  const peer_standing_msg_t *st);
/* Defined with the app-facing carrier below; declared here because the
 * standing handler sits above it and must tell the app when a ceiling moves. */
static void _publish_reputation_change(const uuid_t peer_uuid, double score);
static double _score_peer_locked(const process_t *proc, const uuid_t peer_uuid);
static void _publish_standing_change(const process_t *proc,
                                     const uuid_t peer_uuid);
/* Both defined further down, beside the code that owns them; this block
 * sits above both because it belongs with _publish_tier_change, which it
 * calls. */
static void _persist_reputations(const process_t *proc);
/* Forward declarations — the slash replay marks are written from
 * _apply_slash_locked and the rehabilitation path, both of which sit well
 * above the persistence block that owns the file. */
static void _persist_slash_marks(const process_t *proc);
static void _load_slash_marks(const process_t *proc);
static bool _slash_mark_advance_locked(const char *target_str,
                                       const char *slasher_str,
                                       int64_t epoch);
/* Declared unconditionally: the batched consensus handler skips our own uuid,
 * and that path is not ZTA-gated (this declaration used to sit inside the
 * AT_ZTA_ENABLED block, where a default build could not see it). */
static bool _resolve_self_uuid(const process_t *proc, uuid_t out_uuid);
/* Forward declaration — definition sits with the rest of the verifiable
 * warm-start code (doc/architecture/reputation.md), below the state struct it writes. Records a
 * finalized checkpoint's root, window bounds and co-signatures, and persists
 * the evidence document. */
static void _store_checkpoint(const process_t *proc, const char *proposer,
                              const char *root, int64_t epoch,
                              int first_index, int count,
                              const char *chain_key, json_t *sigs);
/* Forward declaration — stamps "we just transacted with this peer" so the
 * staleness sweep leaves an actively-interacting peer alone. Takes
 * rep_state.lock itself, so callers must NOT hold it. */
static void _note_interaction(const uuid_t peer_uuid);
static uuid_t *_chain_peers_locked(size_t *n_out);
/* Forward declaration: makes every parked half due after the chain grew
 * from a peer (ISSUES §2.60). Defined beside awaiting_commit's helpers. */
static void _wake_parked(const process_t *proc, const char *source);
/* Verifier-attested scores: defined with the rest of the round, below. */
/* Longest designation: tag + 2 uuids (or uuid + 64-hex root) + reason +
 * fixed-form floor + three integers, plus separators. 512 is generous. */
#define REP_DESIG_MAX 512
#define REP_SIG_HEX_LEN (crypto_sign_BYTES * 2)
static bool _chain_json_certified(const process_t *proc, json_t *arr,
                                  const char *key);
static int *_placement_certified_indices(const process_t *proc, const char *key,
                                         const char *group, json_t *arr,
                                         int *n_out, bool *refused);
static void _apply_ahead(const process_t *proc, const char *key,
                         const char *group);
static json_t *_pool_to_json(const tx_history_t *h);
static int _pool_from_json(tx_history_t *h, const json_t *doc);
static bool _commit_cert_ok(const process_t *proc, const uuid_t scorer,
                            const uuid_t task, double score, const char *channel,
                            json_t *sigs, const char *group_uuid);
static int _cosign_hex(const process_t *proc, const uint8_t *desig,
                       size_t dlen, char *hex_out, size_t hex_cap);
static bool _verify_cosignature(const process_t *proc, const char *voter_str,
                                const uint8_t *desig, size_t dlen,
                                const char *sig_hex);
static void _record_cosig_locked(map_t *sigs, const char *round_key,
                                 const char *voter, const char *sig_hex);
static json_t *_cosigs_json_locked(map_t *sigs, const char *round_key,
                                   size_t *count_out);
static void _drop_cosigs_locked(map_t *sigs, const char *round_key);
static bool _chain_json_commit_certified(const process_t *proc, json_t *arr,
                                         const char *key);
void _forward_attestation(const process_t *proc, const tx_score_msg_t *ts,
                                 const uuid_t self_uuid);
static int _rescore_peers(const process_t *proc, double present,
                          const uuid_t self_uuid);
static bool _place_member(const process_t *proc, const char *voter);
static double _mono(void);
static bool _place_deciders_ok(const process_t *proc, const char *key, int k,
                               const char *me, const char *by);
static json_t *_roster_for_group(const process_t *proc, const char *group_uuid);
static bool _verify_cosignature_in(const process_t *proc, const json_t *roster,
                                   const char *voter, const uint8_t *desig,
                                   size_t dlen, const char *sig_hex);

/* Slash "reason" that lifts (rather than floors) a target: releases the
 * slash floor, restores the score to PREREP_NEUTRAL, and re-admits it.
 * Recovery is explicit-only. Mirror: Python SlashAttestation.REASON_REHABILITATE. */
#define REP_SLASH_REASON_REHABILITATE "rehabilitate"
/* The other reasons are not branched on here, but the slash designation covers
 * the reason string, so the spellings have to match Python's
 * SlashAttestation.REASON_* exactly or a co-signature verifies nowhere.
 * Declared in rep_proc_priv.h so the conformance adapter shares them rather
 * than repeating the literals. */

/****************************
 * Protocol-string definitions (declared `extern char[]` in
 * reputation.h). Writable arrays so `net_msg.function` (typed
 * `char *`) accepts them without a `(char *)` cast under
 * `-Wwrite-strings`.
 ****************************/

/* Catch-up quorum, both runtimes (repprocess.py REP_CATCHUP_QUORUM). It was 3,
 * counted as updates stored ONE PER SENDER, so a node with two peers could
 * never reach it: nothing was ever merged, chain lengths drifted apart, and
 * since a grant needs id2 == chain_len + 1, Paxos stopped granting anything
 * (moderation cohort run 7, 2026-09-23; very likely all of ISSUES.md §2.15).
 * One is safe here because the merge verifies the segment's hash links and
 * only appends past our own next index, so a peer cannot rewrite what we
 * hold. A commit already lands on one member's word (§2.16), so this does
 * not lower the chain's effective threshold. */
#define REP_CATCHUP_QUORUM 1

/* A catch-up reply carries the whole resident window (§2.51), and with commit
 * and placement certificates an entry runs about 1.4 KB, so a window soon
 * outgrows one UDP datagram: 57 entries came to 104 KB and the transport cut
 * every reply to 65,507 bytes, which then failed to decrypt (partition cohort
 * part-3629127, ISSUES §2.67). A window whose JSON exceeds this many bytes goes
 * as pages {"page", "of", "head", "chain"[, "group"]}, each well under the
 * datagram once encrypted and enveloped; the receiver collects every page of
 * one head from one sender and then handles the window as if it came whole.
 * Mirrors repprocess.py UPDATE_PAGE_BYTES. */
#define REP_UPDATE_PAGE_BYTES 24000
/* More pages than a 200-entry window at the page size ever needs. */
#define REP_UPDATE_PAGES_MAX 64
/* Paged replies being collected at once, one per sender and chain; the
 * oldest is dropped for a new one. */
#define REP_PAGE_BUFS 8

typedef struct
{
    bool used;
    char sender[UUID_STRING_LEN + 1];
    char key[UUID_STRING_LEN + 1];
    char head[TX_HASH_HEX_LEN + 1];
    int of;
    int got;
    uint64_t seq;               /* when it was started, for eviction */
    json_t *pages[REP_UPDATE_PAGES_MAX];
} rep_page_buf_t;

char REP_PROTO_RETIRED_REQUEST[]  = "ask permission";
char REP_PROTO_RETIRED_GRANT[]    = "permission granted";
char REP_PROTO_RETIRED_NACK[]     = "try again";
char REP_PROTO_RETIRED_BACKDATE[] = "out of date";
char REP_PROTO_TX[]          = "transaction";
char REP_PROTO_ACCEPTED[]    = "tx accepted";
char REP_PROTO_COMMITTED[]   = "tx committed";
char REP_PROTO_OUTDATED[]    = "update needed";
char REP_PROTO_UPDATE[]      = "latest update";
char REP_PROTO_REP_REQ[]     = "request reputation";
char REP_PROTO_REP_RESP[]    = "reputation response";
char REP_PROTO_CONSENSUS_REP_REQ[] = "request consensus reputation";
/* Batched form: one request naming many subjects, one roster reply. Byte-
 * identical to Python's ReputationProtocol.consensus_rep_batch_req — the
 * string IS the wire form, so a prettier spelling here breaks interop. */
char REP_PROTO_CONSENSUS_REP_BATCH_REQ[] = "request consensus reputation batch";
char REP_PROTO_LOCAL_QUERY[] = "local_rep_query";
char REP_PROTO_LOCAL_RESP[]  = "local_rep_response";
/* App -> AT (via the daemon main loop): re-emit the peer view on the
 * app-facing carrier. See doc/architecture/app-peer-carrier.md. */
char REP_PROTO_APP_ROSTER[]  = AT_APP_ROSTER_REQUEST;
char REP_PROTO_SLASH_PROPOSE[] = "slash propose";
char REP_PROTO_SLASH_SIGN[]    = "slash sign";
char REP_PROTO_SLASH_FINAL[]   = "slash final";
/* Verifier-attested scores (doc/architecture/reputation.md); Python
 * ReputationProtocol.attest_*. */
char REP_PROTO_ATTEST_PROPOSE[] = "attest propose";
char REP_PROTO_ATTEST_SIGN[]    = "attest sign";
char REP_PROTO_ATTEST_FINAL[]   = "attest final";
char REP_PROTO_CHECKPOINT_PROPOSE[] = "checkpoint propose";
char REP_PROTO_CHECKPOINT_SIGN[]    = "checkpoint sign";
char REP_PROTO_CHECKPOINT_FINAL[]   = "checkpoint final";
char REP_PROTO_REP_RESOLVE[]        = "resolve reputation";
char REP_PROTO_REP_RESOLVED[]       = "resolved reputation";
char REP_PROTO_PLACE_REQUEST[]      = "place request";
char REP_PROTO_PLACE_GRANT[]        = "place grant";
char REP_PROTO_PLACE_NACK[]         = "place nack";
char REP_PROTO_PLACE[]              = "place";
char REP_PROTO_PLACE_ACCEPTED[]     = "place accepted";
char REP_PROTO_PLACED[]             = "placed";

/* Local-IPC `function` field for the tier_update message reputation
 * emits to identity. Writable buffer so the assignment to
 * `nmsg->function` (typed `char *`) compiles under -Wwrite-strings.
 * Value must match Python IdentityProtocol.tier_update verbatim. */
static char ID_TIER_FUNC[] = "tier_update";
/* Local-IPC function field for the tier_lost message reputation emits
 * to negotiation when a peer's tier drops. Mirrors Python
 * IdentityProtocol.tier_lost verbatim. See doc/architecture/
 * trust-tiers.md §7.2 — negotiation's handle_tier_lost cancels any
 * in-flight tasks whose capability.required_tier exceeds the new tier.
 */
static char NEG_TIER_LOST_FUNC[] = "tier_lost";
/* Local-IPC function fields for the reputation communication cut-off:
 * reputation emits these to the network process, which excludes/readmits the
 * carried address. Matched by value against net_proc's NET_FN_EXCLUDE /
 * NET_FN_READMIT (network.h) — same cross-process string-match convention as
 * ID_TIER_FUNC above. Value must match Python Network.exclude / readmit. */
static char NET_EXCLUDE_FUNC[] = "exclude";
static char NET_READMIT_FUNC[] = "readmit";

/****************************
 * Process state (file-scope static, thread-safe via mutex)
 ****************************/

#define STALE_TIMEOUT    300  /* seconds */

/* One of our halves waiting to reach the chain (awaiting_commit). Everything a
 * re-proposal needs, plus when to give up waiting and how often we have. */
typedef struct {
    smrt_ptr_t;
    uuid_t task_uuid;
    uuid_t proposer;     /* us: the uuid our half commits under */
    double score;
    char   capability_name[CAP_NAMELEN + 1];
    char   channel[TX_CHANNEL_NAMELEN + 1];
    double competence;
    double deadline;
    int    attempts;     /* re-proposals so far */
    int    retries;      /* how many it gets before it is parked or given up */
    double parked_at;    /* when the retries ran out (§2.60); 0 = not parked */
    double last_proposed; /* when a round last went out for it */
} rep_awaiting_t;

/* A checkpoint proposal parked for a later co-sign (ISSUES §2.29). Everything
 * the co-signature covers is kept, plus who to send it to: the designation is
 * rebuilt from these fields, exactly as the proposer built it. */
/* One of our attestation rounds awaiting a quorum, for its re-propose clock. */
typedef struct {
    bool used;
    char task[UUID_STRING_LEN + 1];
    double due;          /* when the propose next goes out again */
    int attempts;        /* re-proposals so far */
} rep_attest_retry_t;

#define REP_PARKED_COSIGN_MAX 16
typedef struct {
    bool used;
    char proposer[UUID_STRING_LEN + 1];
    char group[UUID_STRING_LEN + 1];   /* the chain as the PROPOSER named it */
    char root[TX_HASH_HEX_LEN + 1];
    int64_t epoch;
    int64_t first_index;
    int64_t count;
    double parked_at;
    public_identity_t to;
} rep_parked_cosign_t;

static struct {
    tx_history_t history;
    /* Gateway reputation tree: one chain per child group this node gateways,
     * keyed by group-uuid string -> object_ptr_data(tx_history_t *). Empty on a
     * leaf node, and every code path below falls back to the single `history`
     * when it is, so leaf behaviour is unchanged. Mirrors Python
     * ReputationProcess.child_histories. See
     * doc/architecture/gateway-reputation-tree.md and
     * doc/architecture/gateway-reputation-tree.md. */
    map_t child_hist;
    /* Per-chain finalized checkpoints: chain key ("" = primary) ->
     * object_ptr_data(rep_chain_ckpt_t *). See _ckpt_slot_locked. */
    map_t chain_ckpts;
    /* Per-paxos-round group binding: paxos key -> string_data(group-uuid), set
     * by the proposer so the accept/commit path routes to the round's own chain
     * and sizes its quorum against that group rather than the conflated peer
     * list. Mirrors Python's round_group. */
    map_t round_group;
    /* --- Deep resolution: one peer, on demand
     * (doc/architecture/gateway-reputation-tree.md) ------------
     * resolve_pending: query-id -> object_ptr_data(rep_resolve_t *), a query
     * we are RELAYING and the neighbour its answer must go back to. The only
     * state the capability adds anywhere, and it exists because the answer
     * travels the reverse path -- nobody outside a boundary ever exchanges a
     * message with anybody inside it, so each hop must remember its caller.
     * resolve_outstanding: query-id -> rep_resolve_t *, queries WE originated.
     * resolve_seen: query-id -> integer_data(1), the loop guard; a briefly
     * cyclic tree would otherwise circulate a query until its TTL burned down
     * at every node it touched. Mirrors Python _resolve_pending /
     * _resolve_outstanding / _resolve_seen. */
    map_t resolve_pending;
    map_t resolve_outstanding;
    map_t resolve_seen;
    /* peer uuid-str -> object_ptr_data(rep_resolved_t *): answers we accepted
     * or refused, with the reason kept beside the verdict. */
    map_t resolved_reps;
    reputations_t reputations;
    map_t my_requests;     /* paxos_id_index -> tx_score_t* (pending Paxos rounds) */
    /* task uuid-str -> rep_awaiting_t*: OUR halves proposed and not yet in the
     * chain, keyed by TASK rather than round because the round is exactly
     * what gets lost (ISSUES §2.24). _retry_uncommitted_halves reads it. */
    map_t awaiting_commit;
    /* peer uuid_str -> integer_data(epoch seconds): when that peer last sent
     * us any reputation frame. Whether a majority is reachable is read from
     * this when a half's retries run out (§2.60, _majority_reachable). */
    map_t heard;
    /* peer uuid_str -> integer_data(epoch seconds): when that peer was first
     * seen in the live roster, and -> integer_data(passes done): how many
     * times our pending halves have been handed to it (ISSUES §2.62,
     * _hand_off_pending_halves). A peer that leaves the roster is forgotten,
     * so one that comes back is handed them again. */
    map_t handoff_seen;
    map_t handoff_passes;
    map_t updates;         /* uuid_str -> json_t* (pending chain updates) */
    /* Paged catch-up replies being collected (REP_UPDATE_PAGE_BYTES). */
    rep_page_buf_t page_bufs[REP_PAGE_BUFS];
    uint64_t page_seq;
    size_t update_page_bytes;   /* 0 = REP_UPDATE_PAGE_BYTES */
    array_t requested_reps; /* array of pending reputation responses */
    paxos_instance_t paxos;
    int num_peers;
    pthread_mutex_t lock;
    bool initialized;
    /* Conformance-only: set by the harness for synchronous dispatch, as
     * Python's adapter sets synchronous_dispatch. Production leaves it
     * false. */
    bool synchronous_dispatch;
    /* Last published trust tier per peer uuid-string. Suppresses
     * redundant tier_update IPC when the tier hasn't changed.
     * Mirrors Python's self.peer_tiers in repprocess.py. */
    map_t peer_tiers;
    /* Paxos rounds already committed locally. Keyed by paxos_id_index
     * (id1,id2), value is integer_data(1) — used as a set. Prevents
     * handle_accepted from re-firing its commit block on every late
     * ACCEPTED that arrives after majority is crossed; without this,
     * the same proposer would broadcast `committed` once per peer above
     * majority, and duplicate broadcasts corrupt the bilateral
     * Transaction (tx_history_update would set p2 = p1 = proposer).
     *
     * Capped at COMMITTED_ROUNDS_CAP (FIFO). The ring buffer tracks
     * insertion order so we can evict the oldest key when full.
     * Without this, the map grew without bound during long runs.
     * Mirrors Python's OrderedDict-based ordered set in
     * ReputationProcess.committed_paxos_rounds. */
    map_t committed_paxos_rounds;
    char committed_paxos_ring[COMMITTED_ROUNDS_CAP][64];
    int  committed_paxos_ring_head;  /* next slot to overwrite */
    int  committed_paxos_ring_len;   /* up to COMMITTED_ROUNDS_CAP */
    /* Proposer side: "round:voter" -> "1" for each member that granted, and
     * for each that accepted, a round of ours, so a member counts once per
     * round (the commit_sigs shape). Mirrors Python grants / acceptances. */
    map_t round_granters;
    map_t round_acceptors;
    /* Ordered placement: this node's acceptor state per chain (_place_state_
     * locked). Mirrors Python PlacementMixin._place_state. */
    struct rep_place_state_s *place;
    int place_len;
    /* Per-peer latch for the CTFT/pure-reputation dispatch in
     * handle_rep_request. uuid_str -> integer_data(0|1). Combined
     * with COOP_ENTER/COOP_EXIT to give the mode switch hysteresis;
     * mirrors Python's self._coop_mode in repprocess.py. */
    map_t coop_mode;
    /* Per-task transaction_weight cache (task_uuid_str -> int).
     * Populated at proposer time (_forward_transaction) and at receiver
     * time (handle_transaction) so both
     * sides agree on the weight for any given task. Consumed by
     * reputation_pure / reputation_consensus to apply the
     * Capability.transaction_weight multiplier from
     * doc/architecture/trust-tiers.md §5. FIFO-bounded at
     * 2 * MAX_CHAIN_LEN entries; ring tracks insertion order so the
     * oldest is evictable. Mirrors Python's self.task_weights. */
    map_t task_weights;
    char  task_weights_ring[2 * MAX_CHAIN_LEN][UUID_STRING_LEN + 1];
    int   task_weights_ring_head;
    int   task_weights_ring_len;
    /* Per-task capability tier cache (task_uuid_str -> int), parallel to
     * task_weights and evicted in lockstep with it (every task_tiers key is
     * also a task_weights key; _record_task_weight_locked removes both at the
     * same points, so no separate ring is needed). Feeds the per-tier
     * consensus view (reputation_consensus_by_tier). Mirrors Python's
     * self.task_tiers (deferred.md §2.3). */
    map_t task_tiers;
    /* Per-task evidence channel cache (task_uuid_str -> string), parallel to
     * task_weights and evicted in lockstep with it, exactly as task_tiers is.
     *
     * This is the C answer to a fact Python gets for free: Python's
     * handle_accepted reads the channel off its own retained
     * `self.proposals[idx]` (a whole TransactionScore), while C's paxos
     * instance is generic (`paxos_proposal_t` in algorithms/ carries a score
     * and a grant count, and a reputation-specific channel string has no
     * business in it). So the proposer stashes the channel here when it wins
     * the floor and reads it back when the round commits -- its OWN claim,
     * never the acceptor's echo of it (R+D.md §12.8). */
    map_t task_channels;
    /* --- Slashing (fast-penalty path) ---
     * Mirrors Python ReputationProcess._slashed / _slash_sigs /
     * _slash_pending. A finalized slash floors the target's reputation
     * immediately (bypassing the consensus EMA). The floor value is
     * mirrored into rep_state.reputations so reputation_get_peer_reputation
     * (and the consensus handler) reflect it. */
    map_t slashed;        /* target_uuid_str -> integer_data(epoch) */
    /* "target:epoch:voter" -> string_data(detached hex signature over the
     * attestation designation). Keyed by VOTER, not a bare count: the count
     * this replaced had no voter identity, so replaying one ack drove it past
     * quorum and a single peer could finalize alone. */
    map_t slash_sigs;
    /* "target:epoch" -> string_data(JSON {slasher_uuid, reason, floor_score}).
     * The whole round, because a co-signer and the finalizer must both
     * reproduce the proposer's designation byte for byte. */
    map_t slash_pending;
    /* Verifier-attested scores this node proposed: task uuid_str ->
     * string_data(JSON of the attestation), and "task:voter" -> signature
     * (the slash_sigs shape). */
    map_t attest_pending;
    map_t attest_sigs;
    /* Proposer side, only in a group that requires commit certificates:
     * "task:voter" -> the acceptor's verified signature over the half's
     * commit_designation (the slash_sigs shape). Mirrors Python
     * commit_sigs_pending. */
    map_t commit_sigs;
    /* The N_min each member reported in its place_accepted (RD_13.2 plan
     * section 0.4): {chain key: {voter uuid: n_min}}, 0 for none. A leader
     * restates the roster with the value a strict majority reports. Mirrors
     * Python _place_n_min_seen. */
    json_t *place_n_min_seen;
    /* Rounds already warned about falling short of a declared bar, as
     * {"where:round": true}; cleared when it grows past 1024. Mirrors Python
     * _bar_warned. */
    json_t *bar_warned;
    int64_t slash_epoch;
    /* "target:slasher" -> integer_data(epoch): the highest slash epoch this
     * node has ever APPLIED for that pair. Never removed, unlike `slashed`
     * (which a rehabilitation clears) — it is sized by the cohort, not by how
     * many rounds have passed, so there is no window in which an old slash
     * becomes applicable again. Persisted: the guard is only as good as its
     * memory, and a slash floors a peer into an exclusion that is sticky by
     * design, so a forgotten mark is a penalty an attacker gets to re-impose.
     *
     * Keyed by slasher as well as target because the epoch is a per-SLASHER
     * counter, so two detectors' sequences are independent and a single
     * per-target mark would refuse one detector's legitimate slash on the
     * strength of the other's. Mirrors Python ReputationProcess._slash_hw. */
    map_t slash_hw;
    /* Communication cut-off exclusion set: peers whose reputation fell below
     * COMM_CUTOFF and were excluded at the network layer. Tracks the crossing
     * so _publish_tier_change emits exclude/readmit only on an actual
     * transition. Mirrors Python ReputationProcess._excluded. (C has no
     * reputation persistence, so there is no snapshot to boot-reseed from —
     * the Python two-sided persist filter + _seed_exclusions_from_snapshot
     * have no C counterpart; see REPUTATION_THRESHOLDS_TODO.md.) */
    map_t excluded;       /* peer_uuid_str -> integer_data(1) */
    /* --- Phase 2: quorum-signed Merkle checkpoints ---
     * Mirrors Python ReputationProcess._checkpoint / _checkpoint_sigs /
     * _checkpoint_pending. A member co-signs a proposed checkpoint only when
     * its own transaction_window_root matches; on quorum the proposer
     * finalizes and every node stores the agreed root. */
    /* "proposer:epoch:voter" -> string_data(detached hex signature over the
     * checkpoint designation); same voter-keyed shape and same reason as
     * slash_sigs above. */
    map_t checkpoint_sigs;
    /* "proposer:epoch" -> string_data(JSON {root, first_index, count}) -- the
     * window bounds travel because the designation covers them. */
    map_t checkpoint_pending;
    /* Proposals we could not co-sign when they arrived because our chain did
     * not yet hold the proposed range (ISSUES §2.29). One slot per proposer
     * and chain -- a newer epoch replaces an older one -- re-checked every pass
     * by _recheck_parked_cosigns and dropped after one checkpoint interval. */
    rep_parked_cosign_t parked_cosigns[REP_PARKED_COSIGN_MAX];
    /* Our own attestation rounds still short of a quorum (ISSUES §2.40), re-
     * proposed by _retry_pending_attestations. */
    rep_attest_retry_t attest_retries[REP_ATTEST_RETRY_MAX];
    char  checkpoint_root[TX_HASH_HEX_LEN + 1];  /* latest finalized root */
    int64_t checkpoint_epoch;  /* epoch of the latest finalized checkpoint */
    bool  checkpoint_set;      /* a checkpoint has been finalized/stored */
    /* --- Verifiable warm start (doc/architecture/reputation.md) ---
     * The rest of the finalized checkpoint, kept because the PERSISTED
     * evidence has to carry it: a boot-time rebuild verifies the same quorum a
     * live receiver does, and a root with no window bounds and no signatures
     * beside it is a number anyone with write access to the config directory
     * could have chosen. Mirrors Python's _checkpoint / _checkpoint_sigs_final.
     */
    int   checkpoint_first_index;
    int   checkpoint_count;
    char  checkpoint_proposer[UUID_STRING_LEN + 1];
    /* The latest PRIMARY checkpoint a quorum attested, kept apart from the
     * slot above because the slot also holds our own proposals, stored with
     * only our signature before anyone has co-signed. Reconciliation treats
     * this window as final, and only while our own entries over it still hash
     * to its root (ISSUES.md §2.15). */
    bool  final_set;
    char  final_root[TX_HASH_HEX_LEN + 1];
    int   final_first;
    int   final_count;
    map_t checkpoint_sigs_final;   /* voter uuid-str -> string_data(hex sig) */
    /* Monotonic epoch for checkpoints THIS node originates (distinct from
     * checkpoint_epoch, which is whatever epoch we last stored — possibly
     * another node's). Resumed past the persisted checkpoint at boot so a
     * restart cannot reuse an epoch its peers have already deduped. */
    int64_t checkpoint_own_epoch;
    /* Periodic-origination clocks (see _maybe_checkpoint). The flag rather
     * than a sentinel value because the host build is -Wfloat-equal: a "not
     * set yet" double cannot be tested for equality. -1 head == no window has
     * been checkpointed. */
    double  next_checkpoint_at;
    bool    checkpoint_phase_taken;
    int     last_checkpoint_head;
    /* Staleness decay: peer uuid-str -> float_data(epoch seconds of our most
     * recent committed transaction with that peer). Seeded at boot from the
     * persisted snapshot's mtime, so the gap a peer spent out of contact while
     * we were down counts as idle time. Mirrors Python _last_interaction. */
    map_t   last_interaction;
    double  last_decay_sweep;
    bool    decay_swept;
    /* Peers whose chain advanced since they were last scored: uuid-str ->
     * integer_data(1), used as a set. Filled by _note_interaction on every
     * commit and emptied by _rescore_peers. Mirrors Python _rescore_due. */
    map_t   rescore_due;
    double  last_rescore_sweep;
    bool    rescore_swept;
    /* Child-group chains already attempted by _restore_child_evidence, and the
     * persisted score each clamped peer was clamped away FROM -- the upper
     * bound on any later lift, so late evidence restores standing instead of
     * inventing it. */
    map_t   child_evidence_tried;
    map_t   restore_clamped;
    /* Authority standings (doc/architecture/zta-integration.md). Volatile, like
     * the slash floor: a restart re-derives standing from the admission gate
     * rather than trusting a file for it. Mirrors Python's dicts in
     * repprocess.py.
     *   peer_ceilings:    peer uuid-str -> highest reputation an UNPROVED peer
     *                     may hold. Absent == no bound.
     *   peer_proved_index: peer uuid-str -> chain index at its last PROVED
     *                     verification; the point a later failure unwinds to.
     *   peer_acted:       peer uuid-str -> the standing already acted on, so the
     *                     hourly re-verification of an unchanged verdict is a
     *                     no-op instead of a second unwind. */
    map_t   peer_ceilings;
    map_t   peer_proved_index;
    map_t   peer_acted;
    /* Tenure (doc/architecture/reputation.md, "Tenure"). Mirrors Python's
     * _member_since / _tenure_capped.
     *   member_since:  peer uuid-str -> when this node first held it as a
     *                  member (seconds since the epoch);
     *   member_key:    peer uuid-str -> the signing key (hex) it held then; a
     *                  new key is a new identity and restarts the clock;
     *   tenure_capped: the peers the gate is holding at REP_TENURE_TIER, so
     *                  the sweep rescores each once its tenure is served;
     *   tenure_seeded: roster.cfg.json's first_seen has been read;
     *   tenure_min_override: the minimum set through
     *                  reputation_set_min_tenure (conformance), or negative
     *                  for AT_REP_MIN_TENURE_SEC. */
    map_t   member_since;
    map_t   member_key;
    map_t   tenure_capped;
    bool    tenure_seeded;
    double  tenure_min_override;
    /* Catch-up quorum: how many peers' matching chain reports handle_update
     * waits for before merging. Default REP_CATCHUP_QUORUM (1): apply the
     * hash-link-verified segment from the peer that answered us. Above 1,
     * the older majority vote runs instead (mirrors Python's
     * self.num_updates). */
    int num_updates;
} rep_state;

/* Is @p fn a frame that nothing re-sends if it is lost (ISSUES §2.28)?
 *
 * These carry STATE: a committed half, the transaction and its acceptance, a
 * chain answer, a checkpoint or slash round, an exclusion. Lose one and the
 * other side is simply wrong, as bob's commit broadcast was in part-3518232.
 *
 * Everything else rep sends is Paxos control chatter -- place request, place
 * grant, place nack, update needed -- plus request/response pairs whose asker times
 * out and asks again. The protocol re-sends all of it, and it is most of the
 * traffic: about 90% of what ada's network process sent in part-3614473. Giving
 * chatter the retry too kept net_proc's queue full for seconds, stalled this
 * process 200 ms per lost frame, and made identity lose the race for the queue
 * (a dropped full_history there forked the group), so chatter gets one try. */
static bool _rep_frame_is_state(const char *fn)
{
    if (fn == NULL)
        return false;
    static const char *const state[] = {
        REP_PROTO_TX, REP_PROTO_ACCEPTED, REP_PROTO_COMMITTED, REP_PROTO_UPDATE,
        REP_PROTO_CHECKPOINT_PROPOSE, REP_PROTO_CHECKPOINT_SIGN,
        REP_PROTO_CHECKPOINT_FINAL, REP_PROTO_SLASH_PROPOSE,
        REP_PROTO_SLASH_SIGN, REP_PROTO_SLASH_FINAL,
        REP_PROTO_ATTEST_PROPOSE, REP_PROTO_ATTEST_SIGN, REP_PROTO_ATTEST_FINAL,
        REP_PROTO_PLACE, REP_PROTO_PLACE_ACCEPTED, REP_PROTO_PLACED,
        NET_EXCLUDE_FUNC, NET_READMIT_FUNC,
    };
    for (size_t i = 0; i < sizeof(state) / sizeof(state[0]); i++)
        if (strcmp(fn, state[i]) == 0)
            return true;
    return false;
}

/* Hand net_proc a frame for the wire (ISSUES §2.28).
 *
 * messaging_send is non-blocking, and the network process's AF_UNIX datagram
 * queue holds net.unix.max_dgram_qlen frames -- 10 in every fresh network
 * namespace, whatever the host is tuned to. A frame that carries state
 * (_rep_frame_is_state) gets a bounded retry and, if the queue is still full,
 * is KEPT and retried on this process's tick for up to 30 s
 * (utilities/send_retry.h, ISSUES §2.14) rather than lost: 200 ms was not
 * enough for identity's one-shots either (§2.40). Chatter gets one try and a
 * debug line: the protocol will send it again. */
static int _rep_send_to_network(const process_t *proc, generic_msg_t *out)
{
    const char *fn = out->info.net_msg.function;
    if (_rep_frame_is_state(fn))
        return at_send(proc, "network", out, fn, "the network process", 0,
                       NULL, NULL, 0);
    int ret = messaging_send("network", NET_MESSAGE, out, false);
    if (ret != 0)
        log_debug(proc->logger,
                  "Reputation: dropped %s at a full network queue; the "
                  "protocol re-sends it\n", fn != NULL ? fn : "?");
    return ret;
}

static void _ensure_init(void)
{
    if (!rep_state.initialized)
    {
        tx_history_init(&rep_state.history);
        map_init(&rep_state.child_hist);
        map_init(&rep_state.chain_ckpts);
        map_init(&rep_state.round_group);
        map_init(&rep_state.resolve_pending);
        map_init(&rep_state.resolve_outstanding);
        map_init(&rep_state.resolve_seen);
        map_init(&rep_state.resolved_reps);
        reputations_init(&rep_state.reputations);
        map_init(&rep_state.my_requests);
        map_init(&rep_state.awaiting_commit);
        map_init(&rep_state.heard);
        map_init(&rep_state.handoff_seen);
        map_init(&rep_state.handoff_passes);
        map_init(&rep_state.updates);
        array_init(&rep_state.requested_reps);
        map_init(&rep_state.peer_tiers);
        map_init(&rep_state.committed_paxos_rounds);
        rep_state.committed_paxos_ring_head = 0;
        rep_state.committed_paxos_ring_len = 0;
        map_init(&rep_state.coop_mode);
        map_init(&rep_state.task_weights);
        rep_state.task_weights_ring_head = 0;
        rep_state.task_weights_ring_len = 0;
        map_init(&rep_state.task_tiers);
        map_init(&rep_state.task_channels);
        map_init(&rep_state.slashed);
        map_init(&rep_state.slash_sigs);
        map_init(&rep_state.slash_pending);
        map_init(&rep_state.attest_pending);
        map_init(&rep_state.attest_sigs);
        map_init(&rep_state.commit_sigs);
        rep_state.place_n_min_seen = json_object();
        rep_state.bar_warned = json_object();
        map_init(&rep_state.round_granters);
        map_init(&rep_state.round_acceptors);
        rep_state.slash_epoch = 0;
        map_init(&rep_state.slash_hw);
        map_init(&rep_state.excluded);
        map_init(&rep_state.checkpoint_sigs);
        map_init(&rep_state.checkpoint_pending);
        rep_state.checkpoint_root[0] = '\0';
        rep_state.checkpoint_epoch = 0;
        rep_state.checkpoint_set = false;
        map_init(&rep_state.checkpoint_sigs_final);
        rep_state.checkpoint_first_index = 0;
        rep_state.checkpoint_count = 0;
        rep_state.final_set = false;
        rep_state.checkpoint_proposer[0] = '\0';
        rep_state.checkpoint_own_epoch = 0;
        rep_state.next_checkpoint_at = 0.0;
        rep_state.checkpoint_phase_taken = false;
        rep_state.last_checkpoint_head = -1;
        map_init(&rep_state.last_interaction);
        rep_state.last_decay_sweep = 0.0;
        rep_state.decay_swept = false;
        map_init(&rep_state.rescore_due);
        rep_state.last_rescore_sweep = 0.0;
        rep_state.rescore_swept = false;
        map_init(&rep_state.child_evidence_tried);
        map_init(&rep_state.restore_clamped);
        map_init(&rep_state.peer_ceilings);
        map_init(&rep_state.peer_proved_index);
        map_init(&rep_state.peer_acted);
        map_init(&rep_state.member_since);
        map_init(&rep_state.member_key);
        map_init(&rep_state.tenure_capped);
        rep_state.tenure_seeded = false;
        rep_state.tenure_min_override = -1.0;
        rep_state.num_updates = REP_CATCHUP_QUORUM;
        /* paxos_init is called in reputation_run after num_peers is known */
        rep_state.num_peers = 0;
        pthread_mutex_init(&rep_state.lock, NULL);
        rep_state.initialized = true;
    }
}

/* ---- Gateway reputation tree: chain routing
 * (doc/architecture/gateway-reputation-tree.md) -------------
 *
 * A gateway belongs to more than one cohort, and their transaction histories
 * must not be merged: a subtree's reputation is that subtree's, and the parent
 * cohort has its own. So a commit tagged with a child group's uuid routes to
 * that group's chain, created on first use. Mirrors Python
 * ReputationProcess._chain_for_group / _chain_key.
 */

/* True if `key` names a cohort this node gateways. */
static bool _is_child_group(const process_t *proc, const char *key)
{
    if (proc == NULL || key == NULL || key[0] == '\0'
        || proc->protocol.child_groups == NULL)
        return false;
    data_t *unused = NULL;
    return map_get(proc->protocol.child_groups, (map_key_t)key, &unused) == 0;
}

/* Normalize a group-uuid to a CHAIN KEY: "" for the primary chain, the
 * group-uuid for a child chain.
 *
 * NULL, empty, our own primary group's uuid, and any uuid we do NOT gateway all
 * resolve to the primary chain. That last case is deliberate: an unrecognized
 * group must not be able to mint a chain, or a peer could make us accumulate
 * history under a cohort we have nothing to do with. */
static void _chain_key(const process_t *proc, const char *group_uuid,
                       char *out, size_t cap)
{
    out[0] = '\0';
    if (group_uuid == NULL || group_uuid[0] == '\0')
        return;
    char primary[UUID_STRING_LEN + 1] = {0};
    if (proc != NULL)
        uuid_unparse_lower(proc->protocol.group.uuid, primary);
    if (strncmp(group_uuid, primary, UUID_STRING_LEN + 1) == 0)
        return;
    if (!_is_child_group(proc, group_uuid))
        return;
    snprintf(out, cap, "%s", group_uuid);
}

/* The history a chain key names, creating a child chain on first use. Caller
 * holds rep_state.lock. */
static tx_history_t *_chain_for_key_locked(const char *chain_key)
{
    if (chain_key == NULL || chain_key[0] == '\0')
        return &rep_state.history;
    data_t *existing = NULL;
    if (map_get(&rep_state.child_hist, (map_key_t)chain_key, &existing) == 0
        && existing != NULL)
    {
        void *hp = NULL;
        if (data_object_ptr(existing, &hp) == 0 && hp != NULL)
            return (tx_history_t *)hp;
    }
    tx_history_t *fresh = calloc(1, sizeof(tx_history_t));
    if (fresh == NULL)
        return &rep_state.history;   /* degrade to the primary chain, never NULL */
    tx_history_init(fresh);
    data_t *d = object_ptr_data(fresh, sizeof(tx_history_t));
    if (d == NULL || map_set(&rep_state.child_hist, (map_key_t)chain_key, d) != 0)
    {
        tx_history_free(fresh);
        free(fresh);
        return &rep_state.history;
    }
    return fresh;
}

/* Convenience: resolve a group-uuid straight to its chain. Caller holds the
 * lock. */
static tx_history_t *_chain_for_group_locked(const process_t *proc,
                                             const char *group_uuid)
{
    char key[UUID_STRING_LEN + 1];
    _chain_key(proc, group_uuid, key, sizeof(key));
    return _chain_for_key_locked(key);
}

/* Remember which group a paxos round belongs to, so the accept/commit path can
 * route to the round's chain. Caller holds the lock. */
static void _set_round_group_locked(const char *paxos_key, const char *group_uuid)
{
    if (paxos_key == NULL || group_uuid == NULL || group_uuid[0] == '\0')
        return;
    map_set(&rep_state.round_group, (map_key_t)paxos_key,
            string_data((string_t)group_uuid, strlen(group_uuid)));
}

/* The group a paxos round was bound to, or "" (primary). Caller holds the
 * lock. */
static void _get_round_group_locked(const char *paxos_key, char *out, size_t cap)
{
    out[0] = '\0';
    if (paxos_key == NULL)
        return;
    data_t *d = NULL;
    if (map_get(&rep_state.round_group, (map_key_t)paxos_key, &d) != 0
        || d == NULL)
        return;
    string_t s = NULL;
    if (data_string_ptr(d, &s) == 0 && s != NULL)
        snprintf(out, cap, "%s", s);
}

/* Members of a group, by filtering the peer list against the group's address
 * map -- the C twin of Python's _members_of_group. `Group` carries an address
 * map rather than a uuid roster, and a gateway's peer list conflates every
 * group it belongs to, so this is how a per-group quorum gets sized. */
static group_t *_child_group_locked(const process_t *proc, const char *group_uuid)
{
    if (proc == NULL || group_uuid == NULL || group_uuid[0] == '\0'
        || proc->protocol.child_groups == NULL)
        return NULL;
    data_t *gd = NULL;
    if (map_get(proc->protocol.child_groups, (map_key_t)group_uuid, &gd) != 0
        || gd == NULL)
        return NULL;
    void *gp = NULL;
    if (data_object_ptr(gd, &gp) != 0 || gp == NULL)
        return NULL;
    return (group_t *)gp;
}

/* Whether one peer belongs to a group, by address. Factored out of
 * _members_of_group because deep resolution forwards to a group's members and
 * must decide membership by exactly the same rule the quorum is sized by --
 * two answers to "is this peer in that group" would eventually disagree. */
static bool _peer_in_group(const process_t *proc, const public_identity_t *peer,
                           const char *group_uuid)
{
    group_t *grp = _child_group_locked(proc, group_uuid);
    if (grp == NULL || peer == NULL)
        return false;
    map_key_t akey = NULL;
    data_t *aval = NULL;
    bool found = false;
    map_entries_for_each(&grp->address_map, akey, aval)
    {
        string_t addr = NULL;
        if (data_string_ptr(aval, &addr) == 0 && addr != NULL
            && strncmp(addr, peer->address, sizeof(peer->address)) == 0)
            found = true;
    }
    map_end_for_each
    return found;
}

/* How many peers processes_peer_is_member counts. Caller holds the peers read lock. */
static size_t _member_count(const process_t *proc)
{
    if (proc == NULL)
        return 0;
    size_t count = 0;
    for (size_t i = 0; i < proc->protocol.num_peers; i++)
        if (processes_peer_is_member(proc, &proc->protocol.peers[i]))
            count++;
    return count;
}

static size_t _members_of_group(const process_t *proc, const char *group_uuid)
{
    if (proc == NULL || group_uuid == NULL || group_uuid[0] == '\0')
        return _member_count(proc);
    if (_child_group_locked(proc, group_uuid) == NULL)
        return _member_count(proc);
    size_t count = 0;
    for (size_t i = 0; i < proc->protocol.num_peers; i++)
        if (_peer_in_group(proc, &proc->protocol.peers[i], group_uuid))
            count++;
    return count;
}

/* CHECKPOINT finality threshold for `group_uuid`: more than this many
 * co-signers, the proposer's own included, finalize a window. A MAJORITY OF
 * THE WHOLE GROUP, THIS NODE INCLUDED: floor(members / 2) where members is the
 * roster plus one.
 *
 * It used to be _quorum_for_group's num_peers / 2, which counts the roster
 * WITHOUT this node, and for an even-sized group that is one signature short:
 * two of a four-member group, and the proposer alone in a two-member one, met
 * it. So both halves of an even split finalized their own windows, each then
 * refused to rewrite inside its finality at the heal (tx_history_reconcile),
 * and the chains could never converge (Agora Phase 4 DDIL, 2026-09-25). Odd
 * sizes are unchanged. Paxos rounds now take the same majority
 * (_round_quorum_for_group), and so does slashing (_quorum_met). Mirrors
 * Python's
 * _checkpoint_quorum. */
/* The roster a checkpoint's quorum is sized from, this node NOT included: the
 * peers, or a gateway's members of that child group. Caller holds the peers
 * read lock. Mirrors Python _checkpoint_roster. */
static size_t _ckpt_roster_for_group(const process_t *proc, const char *group_uuid)
{
    if (proc == NULL)
        return 0;
    return (proc->protocol.child_groups == NULL
            || map_size(proc->protocol.child_groups) == 0
            || group_uuid == NULL || group_uuid[0] == '\0')
        ? _member_count(proc)
        : _members_of_group(proc, group_uuid);
}

/* @p f raises it (RD_13.2 plan section 0.4): more than (M + F) / 2 signers,
 * M the whole group. The caller reads F (_f_in_force) BEFORE taking the peers
 * lock, since the roster lives under rep_state.lock, which is taken first. */
static size_t _ckpt_quorum_for_group(const process_t *proc, const char *group_uuid,
                                     int f)
{
    if (proc == NULL)
        return 0;
    return (_ckpt_roster_for_group(proc, group_uuid) + 1 + (size_t)(f > 0 ? f : 0)) / 2;
}

/* Other members a Paxos round needs, grants and acceptances alike. With the
 * proposer's own vote that is a strict majority of the group: members / 2 of
 * the others, where members is the roster plus this node. The checkpoint
 * sizing, compared with `>=` over the others rather than `>` over everyone.
 * It used to be num_peers / 2 with the proposer left out, which asked one
 * member MORE than a majority to commit (three of three, four of five) and
 * one LESS to be granted in an even group (two of four). Caller holds the
 * peers read lock. Mirrors Python _round_quorum. */
static size_t _round_quorum_for_group(const process_t *proc, const char *group_uuid)
{
    if (proc == NULL)
        return 0;
    return (_ckpt_roster_for_group(proc, group_uuid) + 1) / 2;
}

/* _round_quorum_for_group for the round filed under `paxos_key`, sized NOW
 * against the round's own group. A grant carries the round at `>=` this many
 * (our own grant is the other one: paxos_next_ids outranks every ballot we
 * promised), and acceptances plus our own vote carry it at `>`.
 *
 * Both used to compare against PAXOS_MAJORITY(rep_state.num_peers), a count
 * read once in reputation_run, before discovery had found anybody, so in
 * production one grant and one acceptance carried every round however large
 * the group grew. Caller holds rep_state.lock. */
static size_t _round_quorum_locked(const process_t *proc, const char *paxos_key)
{
    char group[UUID_STRING_LEN + 1];
    _get_round_group_locked(paxos_key, group, sizeof(group));
    peers_read_lock(proc);
    size_t quorum = _round_quorum_for_group(proc, group[0] != '\0' ? group : NULL);
    peers_read_unlock(proc);
    return quorum;
}

/* How many distinct voters `sigs` holds for `round_key` ("<round>:<voter>"
 * keys, _record_cosig_locked's). Caller holds rep_state.lock. */
static size_t _round_voters_locked(map_t *sigs, const char *round_key)
{
    size_t prefix_len = strlen(round_key);
    size_t count = 0;
    map_key_t key = NULL;
    data_t *value = NULL;
    map_entries_for_each(sigs, key, value)
    {
        (void)value;
        if (strncmp(key, round_key, prefix_len) == 0 && key[prefix_len] == ':')
            count++;
    }
    map_end_for_each;
    return count;
}

/* Per-chain finalized-checkpoint state. A gateway checkpoints each of its
 * chains separately: its own epoch counter, its own quorum, its own evidence
 * file. Keyed by CHAIN KEY ("" = primary), so a leaf node simply has one slot
 * and behaves as before. Mirrors Python's _checkpoints /
 * _checkpoint_sigs_final / _checkpoint_epochs (doc/architecture/gateway-reputation-tree.md). */
typedef struct {
    char    proposer[UUID_STRING_LEN + 1];
    char    root[TX_HASH_HEX_LEN + 1];
    int64_t epoch;
    int     first_index;
    int     count;
    bool    set;
    map_t   sigs_final;    /* voter uuid-str -> string_data(hex sig) */
    int64_t own_epoch;     /* monotonic epoch for rounds WE originate */
    int     last_head;     /* -1 == this chain has never been checkpointed */
    json_t *forks;         /* equivocation records (R+D.md §14.1), or NULL */
} rep_chain_ckpt_t;

/* The slot for a chain key, created on first use. Caller holds the lock. */
static rep_chain_ckpt_t *_ckpt_slot_locked(const char *chain_key)
{
    const char *key = (chain_key == NULL) ? "" : chain_key;
    data_t *existing = NULL;
    if (map_get(&rep_state.chain_ckpts, (map_key_t)key, &existing) == 0
        && existing != NULL)
    {
        void *sp = NULL;
        if (data_object_ptr(existing, &sp) == 0 && sp != NULL)
            return (rep_chain_ckpt_t *)sp;
    }
    rep_chain_ckpt_t *slot = calloc(1, sizeof(rep_chain_ckpt_t));
    if (slot == NULL)
        return NULL;
    map_init(&slot->sigs_final);
    slot->last_head = -1;
    data_t *d = object_ptr_data(slot, sizeof(rep_chain_ckpt_t));
    if (d == NULL || map_set(&rep_state.chain_ckpts, (map_key_t)key, d) != 0)
    {
        map_free(&slot->sigs_final);
        free(slot);
        return NULL;
    }
    return slot;
}

/* Mirror the primary slot into the flat fields the older observables read
 * (reputation_get_checkpoint_root, the conformance snapshot, slash evidence's
 * fast path). Keeping one mirror in one place beats branching on "primary or
 * not" at a dozen call sites. Caller holds the lock. */
static void _mirror_primary_ckpt_locked(void)
{
    rep_chain_ckpt_t *slot = _ckpt_slot_locked("");
    if (slot == NULL)
        return;
    snprintf(rep_state.checkpoint_root, sizeof(rep_state.checkpoint_root),
             "%s", slot->root);
    snprintf(rep_state.checkpoint_proposer,
             sizeof(rep_state.checkpoint_proposer), "%s", slot->proposer);
    rep_state.checkpoint_epoch = slot->epoch;
    rep_state.checkpoint_first_index = slot->first_index;
    rep_state.checkpoint_count = slot->count;
    rep_state.checkpoint_set = slot->set;
}

/* Record a primary checkpoint as FINAL: a quorum attested it. Caller holds the
 * lock. */
static void _note_final_locked(const char *root, int first_index, int count)
{
    if (root == NULL || root[0] == '\0' || count <= 0)
        return;
    snprintf(rep_state.final_root, sizeof(rep_state.final_root), "%s", root);
    rep_state.final_first = first_index;
    rep_state.final_count = count;
    rep_state.final_set = true;
}

/* One past the last index reconciliation must not rewrite, or -1. A window is
 * final only if a quorum attested it AND our own entries over it hash to the
 * attested root: a node whose chain the quorum outvoted holds nothing final
 * there, so guarding it would pin the losing side of a fork. Caller holds the
 * lock. */
static int _final_end_locked(void)
{
    if (!rep_state.final_set)
        return -1;
    char mine[TX_HASH_HEX_LEN + 1];
    if (tx_history_range_root(&rep_state.history, rep_state.final_first,
                              rep_state.final_count, mine) != 0
        || strcmp(mine, rep_state.final_root) != 0)
        return -1;
    return rep_state.final_first + rep_state.final_count;
}

/* The latest quorate primary checkpoint, iff our own entries do NOT reproduce
 * it: the group finalized a chain ours lost to. Caller holds the lock. */
static bool _outvoted_locked(tx_attested_t *out)
{
    if (!rep_state.final_set)
        return false;
    char mine[TX_HASH_HEX_LEN + 1];
    if (tx_history_range_root(&rep_state.history, rep_state.final_first,
                              rep_state.final_count, mine) == 0
        && strcmp(mine, rep_state.final_root) == 0)
        return false;
    snprintf(out->root, sizeof(out->root), "%s", rep_state.final_root);
    out->first_index = rep_state.final_first;
    out->count = rep_state.final_count;
    return true;
}

/* Look up the transaction_weight for a capability by name. Mirrors
 * Python's _resolve_tx_weight: empty name → 1, unknown cap → 1,
 * otherwise the cap's transaction_weight (clamped to ≥1 because
 * proto3's 0-sentinel normalises to 1 in sync_from_message). */
static int _resolve_tx_weight(const char *cap_name)
{
    if (cap_name == NULL || cap_name[0] == '\0')
        return 1;
    capability_t *cap = find_capability(cap_name);
    if (cap == NULL)
        return 1;
    int w = cap->transaction_weight;
    return w > 0 ? w : 1;
}

/* The weight for a score THIS NODE produced: the capability's
 * transaction_weight times the evidence channel's multiplier (R+D.md §12.8).
 * Mirrors Python's `_resolve_tx_weight(score, local=True)`.
 *
 * Only the local site calls this — `_forward_transaction`. The wire path (handle_transaction) keeps calling
 * the capability-only form above, because the scorer picks its own channel and
 * honoring a remote tag would let any peer treble the weight of a score it
 * fabricated against any other. See tx_channel.h. */
static int _resolve_tx_weight_local(const char *cap_name, const char *channel,
                                    double competence)
{
    int w = _resolve_tx_weight(cap_name);
    /* The learned competence multiplier (R+D.md §12.5), between the authored
     * weight and the channel's, and on the LOCAL path only for the same reason
     * the channel is: this node measured the record, and a peer that could
     * stamp its own would hold a lever on every EMA it appears in.
     *
     * Non-positive is absence (a zeroed struct, or a producer predating the
     * field), which means the authored weight verbatim. Rounded by
     * at_tx_weight_round (tx_channel.h) -- floor(x + 0.5), the one rule both runtimes share
     * -- because C's lround and Python's round disagree at exactly 0.5, and a
     * weight is how many times the EMA folds the score in. Floored at 1 by the
     * return below: a capability authored at weight 1 therefore cannot be
     * demoted by competence, which
     * doc/architecture/prequential-competence.md records as a limitation of
     * the integer fold rather than working around. */
    if (competence > 0.0)
        w = at_tx_weight_round((double)w * competence);
    w *= tx_channel_weight(channel);
    return w > 0 ? w : 1;
}

/* Look up the required_tier for a capability by name (deferred.md §2.3).
 * Mirrors Python's _resolve_tx_tier: empty name → 0, unknown cap → 0,
 * otherwise the cap's required_tier (clamped to ≥0). Feeds the per-tier
 * consensus view via the task_tiers cache. */
static int _resolve_tx_tier(const char *cap_name)
{
    if (cap_name == NULL || cap_name[0] == '\0')
        return 0;
    capability_t *cap = find_capability(cap_name);
    if (cap == NULL)
        return 0;
    int t = cap->required_tier;
    return t > 0 ? t : 0;
}

/* Insert into rep_state.task_weights with FIFO eviction at the cap.
 * Caller must hold rep_state.lock. Refreshes order on re-insert so a
 * recent update isn't immediately evicted by an unrelated insert —
 * matches Python's _record_task_weight (pop-then-insert).
 *
 * Key type is `char *` (no const view) because that is what the
 * project's map_t API expects; the helper copies the key into the
 * map's internal storage and the ring buffer, so the caller's
 * buffer lifetime is not extended beyond this call. */
static void _record_task_weight_locked(char *task_uuid_str, int weight)
{
    if (task_uuid_str == NULL || task_uuid_str[0] == '\0') return;
    /* If present, drop the existing entry from both map AND ring so
     * the re-insert puts it at the tail. */
    data_t *existing = NULL;
    if (map_get(&rep_state.task_weights, task_uuid_str, &existing) == 0
        && existing != NULL)
    {
        map_remove(&rep_state.task_weights, task_uuid_str);
        map_remove(&rep_state.task_tiers, task_uuid_str);  /* lockstep (doc/architecture/network-wire-format.md) */
        map_remove(&rep_state.task_channels, task_uuid_str);   /* same lockstep */
        /* Best-effort ring compaction: walk and remove matching slot.
         * O(N) but N <= 2*MAX_CHAIN_LEN, and refresh hits are rare. */
        for (int i = 0; i < rep_state.task_weights_ring_len; i++)
        {
            int slot = (rep_state.task_weights_ring_head
                        - rep_state.task_weights_ring_len + i
                        + (int)(sizeof(rep_state.task_weights_ring)
                                / sizeof(rep_state.task_weights_ring[0])))
                       % (int)(sizeof(rep_state.task_weights_ring)
                               / sizeof(rep_state.task_weights_ring[0]));
            if (strncmp(rep_state.task_weights_ring[slot],
                        task_uuid_str, UUID_STRING_LEN) == 0)
            {
                rep_state.task_weights_ring[slot][0] = '\0';
                break;
            }
        }
    }

    /* Insert new entry. */
    data_t *w_dat = integer_data(weight > 0 ? weight : 1);
    if (w_dat == NULL) return;
    map_set(&rep_state.task_weights, task_uuid_str, w_dat);

    int cap = (int)(sizeof(rep_state.task_weights_ring)
                    / sizeof(rep_state.task_weights_ring[0]));
    if (rep_state.task_weights_ring_len >= cap)
    {
        /* Evict oldest non-empty slot. */
        int evict_slot = (rep_state.task_weights_ring_head + 1) % cap;
        while (rep_state.task_weights_ring[evict_slot][0] == '\0'
               && evict_slot != rep_state.task_weights_ring_head)
        {
            evict_slot = (evict_slot + 1) % cap;
        }
        if (rep_state.task_weights_ring[evict_slot][0] != '\0')
        {
            map_remove(&rep_state.task_weights,
                       rep_state.task_weights_ring[evict_slot]);
            map_remove(&rep_state.task_tiers,           /* lockstep (doc/architecture/network-wire-format.md) */
                       rep_state.task_weights_ring[evict_slot]);
            map_remove(&rep_state.task_channels,        /* same lockstep */
                       rep_state.task_weights_ring[evict_slot]);
            rep_state.task_weights_ring[evict_slot][0] = '\0';
        }
    }
    else
    {
        rep_state.task_weights_ring_len++;
    }
    rep_state.task_weights_ring_head =
        (rep_state.task_weights_ring_head + 1) % cap;
    strncpy(rep_state.task_weights_ring[rep_state.task_weights_ring_head],
            task_uuid_str, UUID_STRING_LEN);
    rep_state.task_weights_ring[rep_state.task_weights_ring_head][UUID_STRING_LEN] = '\0';
}

/* Record a task's capability tier into rep_state.task_tiers (deferred.md
 * doc/architecture/network-wire-format.md). No own ring: every tier key is recorded together with its weight
 * key, and _record_task_weight_locked removes both at the same eviction
 * points, so the tier map stays bounded in lockstep with task_weights.
 * Caller must hold rep_state.lock. */
static void _record_task_tier_locked(char *task_uuid_str, int tier)
{
    if (task_uuid_str == NULL || task_uuid_str[0] == '\0') return;
    data_t *t_dat = integer_data(tier > 0 ? tier : 0);
    if (t_dat == NULL) return;
    map_set(&rep_state.task_tiers, task_uuid_str, t_dat);
}

/* Record a task's evidence channel into rep_state.task_channels. No own ring,
 * for the same reason task_tiers has none: every channel key is recorded
 * together with its weight key and evicted with it. An absent/default channel
 * is NOT stored -- the entry it would produce is indistinguishable from no
 * entry (both mean `task_outcome`), and storing it would fill the map with
 * the common case. Caller must hold rep_state.lock. */
static void _record_task_channel_locked(char *task_uuid_str, const char *channel)
{
    if (task_uuid_str == NULL || task_uuid_str[0] == '\0') return;
    if (channel == NULL || channel[0] == '\0') return;
    if (strcmp(channel, TX_CHANNEL_DEFAULT) == 0) return;
    if (!tx_channel_valid(channel)) return;
    data_t *c_dat = string_data((string_t)channel, strlen(channel) + 1);
    if (c_dat == NULL) return;
    map_set(&rep_state.task_channels, task_uuid_str, c_dat);
}

/* The channel recorded for @p task_uuid_str, or NULL when none was (which
 * means `task_outcome`). Caller must hold rep_state.lock; the returned
 * pointer is owned by the map. */
static const char *_task_channel_locked(const char *task_uuid_str)
{
    if (task_uuid_str == NULL || task_uuid_str[0] == '\0') return NULL;
    data_t *dat = NULL;
    if (map_get(&rep_state.task_channels, (map_key_t)task_uuid_str, &dat) != 0
        || dat == NULL)
        return NULL;
    string_t val = NULL;
    if (data_string_ptr(dat, &val) != 0)
        return NULL;
    return (const char *)val;
}

static void _publish_tier_change(const process_t *proc,
                                 const uuid_t peer_uuid, double score)
{
    int new_tier = _trust_tier(score);
    char uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer_uuid, uuid_str);

    pthread_mutex_lock(&rep_state.lock);

    /* Communication cut-off crossing. Checked BEFORE the tier dedup
     * early-return because COMM_CUTOFF (0.1) lies WITHIN tier 0 ([0,0.5)):
     * a 0.15 -> 0.05 move is a tier-0 -> tier-0 no-op for the tier logic
     * yet must still exclude the peer. The exclusion set is the authority;
     * the network process is notified only on an actual crossing. Mirrors
     * Python repprocess._publish_tier_change. */
    int exclusion_action = 0;  /* +1 exclude, -1 readmit, 0 unchanged */
    bool now_excluded = (score < COMM_CUTOFF);
    data_t *ex_dat = NULL;
    bool was_excluded =
        (map_get(&rep_state.excluded, uuid_str, &ex_dat) == 0);
    (void)ex_dat;  /* membership only; value unused */
    if (now_excluded && !was_excluded) {
        map_set(&rep_state.excluded, uuid_str, integer_data(1));
        exclusion_action = 1;
    } else if (was_excluded && !now_excluded) {
        map_remove(&rep_state.excluded, uuid_str);
        exclusion_action = -1;
    }

    /* Dedup: skip if the tier hasn't changed from the last publication
     * for this peer. Mirrors Python's `self.peer_tiers.get(key) == new_tier`
     * guard in repprocess.py. */
    int prior = -1;
    data_t *prior_dat = NULL;
    if (map_get(&rep_state.peer_tiers, uuid_str, &prior_dat) == 0 &&
        prior_dat != NULL) {
        data_integer(prior_dat, &prior);
    }
    if (prior == new_tier) {
        pthread_mutex_unlock(&rep_state.lock);
        /* Still enforce the cut-off crossing even when the tier is
         * unchanged (the whole reason the cut-off check precedes this). */
        if (exclusion_action != 0)
            _publish_exclusion(proc, peer_uuid, exclusion_action > 0);
        return;
    }
    /* Capture demotion BEFORE we overwrite the cache so the
     * subsequent tier_lost emission sees a coherent old→new step.
     * Tier 0 is the floor — prior == -1 means "never published",
     * not a demotion. Mirrors Python's
     * `is_demotion = (old_tier is not None and new_tier < old_tier)`
     * in repprocess.py. */
    bool is_demotion = (prior >= 0 && new_tier < prior);
    data_t *tier_dat = integer_data(new_tier);
    if (tier_dat != NULL)
        map_set(&rep_state.peer_tiers, uuid_str, tier_dat);
    pthread_mutex_unlock(&rep_state.lock);

    /* Enforce the cut-off crossing (network exclude/readmit) alongside the
     * tier change. Done outside rep_state.lock because _publish_exclusion
     * takes the peers read-lock and sends IPC. */
    if (exclusion_action != 0)
        _publish_exclusion(proc, peer_uuid, exclusion_action > 0);

    /* Build the tier_update payload — a 2-element JSON array
     * [uuid_str, tier_int] matching Python's
     * `to_json_string((key, new_tier))` in repprocess.py. */
    json_t *arr = json_array();
    if (arr == NULL) return;
    json_array_append_new(arr, json_string(uuid_str));
    json_array_append_new(arr, json_integer(new_tier));

    generic_msg_t ipc = {0};
    ipc.type = NET_MESSAGE;
    strncpy(ipc.info.net_msg.process, "identity", PROC_NAME_LEN);
    ipc.info.net_msg.function = ID_TIER_FUNC;
    ipc.info.net_msg.encrypt = false;  /* local IPC, no wire egress */
    strncpy(ipc.info.net_msg.return_to, "reputation", PROC_NAME_LEN);
    net_msg_pack_json(&ipc.info.net_msg, arr);

    /* messaging_send keys by process name; "identity" routes to the
     * IdentityProcess queue directly, bypassing the network process.
     *
     * Bounded retry, and on failure UNDO the publication record above. The
     * record is what suppresses a repeat, so a send lost to a full identity
     * queue used to leave identity on the old tier until the score crossed
     * another boundary, which for a steady peer is never. Identity's gates
     * read that tier: after ada restarted in moderation cohort mod-2505620
     * (2026-09-23) her app read bob at tier 1 while her post gate still held
     * him at 0 and dropped his tier-1 post. Undone, the next rescore sweep
     * publishes it again. */
    int sent = -1;
    for (int attempt = 0; attempt < 10; attempt++) {
        sent = messaging_send("identity", NET_MESSAGE, &ipc, false);
        if (sent == 0)
            break;
        usleep(20000); /* 20ms */
    }
    if (sent != 0) {
        pthread_mutex_lock(&rep_state.lock);
        if (prior >= 0)
            map_set(&rep_state.peer_tiers, uuid_str, integer_data(prior));
        else
            map_remove(&rep_state.peer_tiers, uuid_str);
        /* Due again, so the sweep republishes it even when a steady score
         * gives it no other reason to. */
        map_set(&rep_state.rescore_due, uuid_str, integer_data(1));
        pthread_mutex_unlock(&rep_state.lock);
        log_warn(proc->logger,
                 "Reputation: tier_update %s -> %d not delivered after 10 "
                 "tries (%s); will republish on the next rescore\n",
                 uuid_str, new_tier,
                 sent == EAGAIN ? "identity queue still full" : "send failed");
    } else if (prior >= 0) {
        log_info(proc->logger, "Reputation: tier of %s %d -> %d (score %.3f)\n",
                 uuid_str, prior, new_tier, score);
    } else {
        log_info(proc->logger, "Reputation: tier of %s first set to %d (score %.3f)\n",
                 uuid_str, new_tier, score);
    }
    net_msg_free_obj(&ipc.info.net_msg);

    /* On demotion, also publish tier_lost to negotiation. The
     * payload is identical (uuid_str, new_tier); the receiver is
     * negotiation's handle_tier_lost, which cancels any in-flight
     * tasks the demoted peer can no longer authorize. */
    if (is_demotion) {
        generic_msg_t ipc_neg = {0};
        ipc_neg.type = NET_MESSAGE;
        strncpy(ipc_neg.info.net_msg.process, "negotiation", PROC_NAME_LEN);
        ipc_neg.info.net_msg.function = NEG_TIER_LOST_FUNC;
        ipc_neg.info.net_msg.encrypt = false;
        strncpy(ipc_neg.info.net_msg.return_to, "reputation", PROC_NAME_LEN);
        net_msg_pack_json(&ipc_neg.info.net_msg, arr);
        /* Kept if negotiation's queue is full (ISSUES §2.14): nothing
         * republishes a demotion's tier_lost, unlike the tier_update above,
         * whose rollback re-arms only identity's half. */
        (void)at_send(proc, "negotiation", &ipc_neg, "tier_lost", uuid_str, 0,
                      NULL, NULL, 0);
        net_msg_free_obj(&ipc_neg.info.net_msg);
    }

    json_decref(arr);
}

/****************************
 * Peer standing: the DDIL cap, and the unwind on an affirmative failure
 * (doc/architecture/zta-integration.md). Mirrors Python
 * repprocess._apply_standing_ceiling / _apply_peer_standings /
 * _unwind_standing_failure.
 *
 * ALWAYS COMPILED (Phase 4 P4.1). This machinery was written for ZTA and was
 * gated on AT_ZTA_ENABLED, which meant a build with ZTA off — Agora's, see
 * apps/agora/native/CMakeLists.txt — had no way to bound a peer at all. ZTA is
 * now one PRODUCER of a standing and stays behind its flag; an Ethne expulsion
 * is another, and arrives through the app. The mechanism is the substrate's.
 ****************************/

/** Room for "<uuid>|<source>" plus its terminator. */
#define STANDING_KEY_LEN (UUID_STRING_LEN + 1 + PEER_STANDING_SOURCE_LEN + 1)

/** The key under which ONE authority's finding about ONE peer is filed.
 *
 *  Standings are kept per (peer, source) — ceiling, unwind anchor and
 *  idempotence mark alike — because two authorities may bound the same peer
 *  for unrelated reasons and neither may clear the other's finding. Keying on
 *  the peer alone would let whichever authority spoke last overwrite the
 *  other's bound, and would make a ZTA re-verification silently lift an
 *  expulsion. Caller must hold rep_state.lock for any map this keys. */
static void _standing_key(char *out, size_t out_len, const char *uuid_str,
                          const char *source)
{
    snprintf(out, out_len, "%s|%s", uuid_str,
             peer_standing_source_or_default(source));
}

/** Highest reputation @p peer_uuid may hold given what EVERY authority has
 *  said, or a negative sentinel for "no bound".
 *
 *  The reduction is MINIMUM over sources: a peer is bounded by the strictest
 *  finding against it, and an authority that has said nothing withholds
 *  nothing. Iterating the closed source set rather than scanning the map keeps
 *  this O(sources) and needs no prefix iteration. Caller must hold
 *  rep_state.lock. */
static double _standing_ceiling_of(const uuid_t peer_uuid)
{
    char uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer_uuid, uuid_str);
    static const char *const all[] = { PEER_STANDING_SOURCE_ALL };
    double lowest = PEER_NO_CEILING;
    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++)
    {
        char key[STANDING_KEY_LEN];
        _standing_key(key, sizeof(key), uuid_str, all[i]);
        data_t *d = NULL;
        if (map_get(&rep_state.peer_ceilings, (map_key_t)key, &d) != 0 ||
            d == NULL)
            continue;
        double ceiling = PEER_NO_CEILING;
        if (data_floating_pt_dbl(d, &ceiling) != 0 || ceiling < 0.0)
            continue;
        if (lowest < 0.0 || ceiling < lowest)
            lowest = ceiling;
    }
    return lowest;
}

/* Bound a score by the peer's standing ceiling. Applied where the score is WRITTEN
 * rather than where it is read, so every consumer -- the tier computation,
 * persistence, the app-facing carrier, a peer answering a rep_req -- sees one
 * consistent number. A ceiling enforced only at read time would leave the
 * stored score above it and leak the unbounded value the moment some other
 * path reported it. Caller must hold rep_state.lock. */
static double _standing_apply_ceiling(const uuid_t peer_uuid, double score)
{
    double ceiling = _standing_ceiling_of(peer_uuid);
    if (ceiling < 0.0 || score <= ceiling)
        return score;
    return ceiling;
}

/** The score that evidence PREDATING the peer's last proved verification supports
 * (doc/architecture/zta-integration.md): back to the last point ZTA actually proved
 * something, and no further.
 *
 * A recomputation over the pre-anchor window rather than a stored "score as of then" --
 * no such score is checkpointed (a checkpoint commits to a history WINDOW, not to
 * per-peer values) -- reusing the same arithmetic the warm start uses so the unwind
 * inherits its shrinkage: a short pre-anchor history cannot justify a high score. Falls
 * back to the unverified-restore tier when there is no usable pre-anchor evidence, the
 * evicted-chain case included: absent evidence bounds a peer low, it does not excuse
 * it.
 *
 * Caller must hold rep_state.lock. */
static double _standing_unwind_ceiling(const uuid_t self_uuid,
                                  const uuid_t peer_uuid, int anchor,
                                  bool have_anchor)
{
    double floor_tier = _tier_ceiling(REP_UNVERIFIED_RESTORE_TIER);
    if (!have_anchor)
        return floor_tier;  /* never proved: none of its standing rests on ZTA */
    int lo = (rep_state.history.committed_count > 0)
                 ? rep_state.history.first_index
                 : rep_state.history.next_index;
    if (anchor <= lo)
        return floor_tier;  /* nothing committed before the proof point */

    char self_key[UUID_STRING_LEN + 1];
    uuid_unparse_lower(self_uuid, self_key);
    rep_checkpoint_t window;
    if (rep_checkpoint_init(&window) != 0)
        return floor_tier;
    map_t ceilings;
    if (map_init(&ceilings) != 0)
    {
        rep_checkpoint_free(&window);
        return floor_tier;
    }
    /* The window is [first_index, first_index + count), so the anchor is its
     * exclusive upper bound: everything committed while the credential was
     * proved, and nothing after. */
    window.present = true;
    window.first_index = lo;
    window.count = anchor - lo;
    double bound = floor_tier;
    if (reputation_evidence_ceilings(&rep_state.history, &window, self_key,
                                     &ceilings) == 0)
    {
        char key[UUID_STRING_LEN + 1];
        uuid_unparse_lower(peer_uuid, key);
        data_t *d = NULL;
        double found = 0.0;
        if (map_get(&ceilings, (map_key_t)key, &d) == 0 && d != NULL &&
            data_floating_pt_dbl(d, &found) == 0)
            bound = found;
    }
    map_free(&ceilings);
    rep_checkpoint_free(&window);
    return bound;
}

/* Act on one ZTA finding from the identity process.
 *
 * No scalar penalty is sent for a failure. A ZTA verdict is an authority
 * finding, not an interaction outcome, and AT's [0, 1] scale has no
 * representation for one (doc/architecture/reputation.md) -- which is why this function's predecessor,
 * `_send_reputation_penalty`'s `score = -0.8` TRANSACTION_SCORE, was discarded
 * at the boundary and cost a revoked peer exactly nothing. Bounding the value
 * and republishing the tier is the action; demotion, and exclusion below the
 * cut-off, follow from the score _publish_tier_change already reacts to. */
static void _handle_peer_standing(const process_t *proc,
                                 const peer_standing_msg_t *st)
{
    if (st == NULL)
        return;
    char key[UUID_STRING_LEN + 1];
    uuid_unparse_lower(st->peer_uuid, key);
    /* An unrecognized authority is refused outright rather than filed under a
     * key nothing reduces over: _standing_ceiling_of iterates the CLOSED set,
     * so a ceiling stored under "peer|nonsense" would bound nobody while
     * looking, in the map, exactly like one that did. Absence is a different
     * question and normalizes to ZTA — see peer_standing_source_or_default. */
    const char *source = peer_standing_source_or_default(st->source);
    if (!peer_standing_source_valid(source))
    {
        log_warn(proc->logger,
                 "Standing: refusing a finding about %s from unknown "
                 "authority '%s'\n", key, source);
        return;
    }
    /* The three standing maps are keyed per (peer, source); coop_mode and the
     * reputations store are NOT — those are about the peer itself. */
    char skey[STANDING_KEY_LEN];
    _standing_key(skey, sizeof(skey), key, source);

    /* Idempotence: periodic re-verification restates an unchanged verdict by
     * the hour, and acting on each restatement would ratchet a peer down for a
     * single offence. Per (peer, source), or a ZTA restatement and an Ethne
     * expulsion would each keep invalidating the other's mark and re-unwind
     * the peer between them. */
    char mark[128];
    snprintf(mark, sizeof(mark), "%d|%.17g|%s", (int)st->standing,
             st->ceiling, st->reason);
    pthread_mutex_lock(&rep_state.lock);
    data_t *prev = NULL;
    if (map_get(&rep_state.peer_acted, (map_key_t)skey, &prev) == 0 &&
        prev != NULL)
    {
        char *prev_str = NULL;
        if (data_string_ptr(prev, &prev_str) == 0 && prev_str != NULL &&
            strcmp(prev_str, mark) == 0)
        {
            pthread_mutex_unlock(&rep_state.lock);
            return;
        }
    }
    map_set(&rep_state.peer_acted, (map_key_t)skey, string_data(mark, strlen(mark)));

    if (st->standing == PEER_STANDING_PROVED)
    {
        /* Everything committed up to now was observed while THIS authority was
         * satisfied: that is the point a later failure BY THIS AUTHORITY
         * unwinds to. Only this source's ceiling lifts — from the app this is
         * a reinstatement, and reinstating an expelled member says nothing
         * about their credential. */
        map_remove(&rep_state.peer_ceilings, (map_key_t)skey);
        map_set(&rep_state.peer_proved_index, (map_key_t)skey,
                integer_data(rep_state.history.next_index));
        /* Rescore NOW, without the ceiling. The stored score is the CAPPED
         * one, and nothing else makes a steady peer due: moderation cohort
         * mod-2518340 read bob at the lifted cap of 0.300 long after the
         * lift. Marking him due for the next sweep was not enough either:
         * mod-2531555 read the cap again in the seconds before that sweep ran.
         * A lift takes effect the moment it lands, as a cap does. */
        bool rated = reputations_contains(&rep_state.reputations, st->peer_uuid);
        double rescored = rated ? _score_peer_locked(proc, st->peer_uuid) : 0.0;
        pthread_mutex_unlock(&rep_state.lock);
        if (rated)
            _persist_reputations(proc);
        log_info(proc->logger,
                 "Standing[%s]: %s proved; unwind anchor set at chain index %d\n",
                 source, key, rep_state.history.next_index);
        if (rated)
        {
            _publish_tier_change(proc, st->peer_uuid, rescored);
            _publish_reputation_change(st->peer_uuid, rescored);
        }
        else
            _publish_standing_change(proc, st->peer_uuid);
        return;
    }

    if (st->ceiling >= 0.0)
        map_set(&rep_state.peer_ceilings, (map_key_t)skey,
                floating_pt_dbl_data(st->ceiling));

    if (st->standing != PEER_STANDING_FAILED)
    {
        /* CAPPED: a bound going forward, and nothing more. A ceiling must not
         * itself drive a peer downward -- only an affirmative failure justifies
         * that -- or every disconnected DDIL deployment would be punished for
         * being disconnected. Due, so the bound applies at the next sweep. */
        map_set(&rep_state.rescore_due, (map_key_t)key, integer_data(1));
        pthread_mutex_unlock(&rep_state.lock);
        log_info(proc->logger, "Standing[%s]: %s capped at %.3f (%s)\n",
                 source, key, st->ceiling, st->reason);
        _publish_standing_change(proc, st->peer_uuid);
        return;
    }

    if (!reputations_contains(&rep_state.reputations, st->peer_uuid))
    {
        /* Nothing scored yet; the ceiling recorded above bounds the first score
         * it does earn, and there is nothing to unwind. */
        pthread_mutex_unlock(&rep_state.lock);
        log_info(proc->logger,
                 "Standing[%s]: %s failed (%s); no score to unwind\n",
                 source, key, st->reason);
        _publish_standing_change(proc, st->peer_uuid);
        return;
    }

    uuid_t self_uuid;
    bool have_self = _resolve_self_uuid(proc, self_uuid);
    data_t *idx_dat = NULL;
    int anchor = 0;
    bool have_anchor =
        (map_get(&rep_state.peer_proved_index, (map_key_t)skey, &idx_dat) == 0 &&
         idx_dat != NULL && data_integer(idx_dat, &anchor) == 0);
    double current = 0.0;
    reputations_get(&rep_state.reputations, st->peer_uuid, &current);
    double unwound = _standing_unwind_ceiling(have_self ? self_uuid : st->peer_uuid,
                                         st->peer_uuid, anchor, have_anchor);
    if (current <= unwound)
    {
        pthread_mutex_unlock(&rep_state.lock);
        log_info(proc->logger,
                 "Standing[%s]: %s failed (%s); score %.3f already at or below "
                 "what pre-verification evidence supports (%.3f)\n",
                 source, key, st->reason, current, unwound);
        _publish_standing_change(proc, st->peer_uuid);
        return;
    }
    reputations_update(&rep_state.reputations, st->peer_uuid, unwound);
    /* Force CTFT so a peer whose credential is later repaired re-earns trust
     * from the punished regime instead of snapping back into cooperation --
     * the same reasoning as the slash override. */
    map_set(&rep_state.coop_mode, (map_key_t)key, integer_data(0));
    pthread_mutex_unlock(&rep_state.lock);

    log_warn(proc->logger,
             "Standing[%s]: %s FAILED (%s); unwound %.3f -> %.3f (anchor %s)\n",
             source, key, st->reason, current, unwound,
             have_anchor ? "recorded" : "none - never proved");
    _publish_tier_change(proc, st->peer_uuid, unwound);
    _publish_reputation_change(st->peer_uuid, unwound);
    _persist_reputations(proc);
}


/****************************
 * The app-facing reputation carrier (ethne D5/D18; see
 * doc/architecture/app-peer-carrier.md).
 *
 * Deliberately NOT folded into _publish_tier_change: that function is gated
 * on a tier CROSSING, and a consumer tracking earned reputation needs every
 * change, not only the ones that step over one of four floors. It is also
 * not folded into the tier_update IPC, because that message exists to tell
 * the identity process a coarse tier and giving it the raw score would put a
 * cached second copy of the score store where nothing needs one.
 ****************************/

/* @p rated is the load-bearing argument: an unrated peer reads as
 * PREREP_NEUTRAL, which is also a score a peer can genuinely earn, so a
 * consumer given only the number cannot tell "no information" from
 * "rated 0.2". The score is zeroed when unrated so a consumer that ignores
 * the flag cannot silently read a plausible-looking number. */
static int _publish_reputation(const uuid_t peer_uuid, double score, bool rated)
{
    generic_msg_t msg = {0};
    msg.type = PEER_REPUTATION;
    msg.size = sizeof(peer_reputation_msg_t);
    uuid_copy(msg.info.peer_reputation.peer_uuid, peer_uuid);
    msg.info.peer_reputation.score = rated ? score : 0.0;
    msg.info.peer_reputation.rated = rated;
    /* The tier and the bound behind it (Phase 4 P4.1). A consumer can derive a
     * tier from the score — the app does — but it CANNOT derive a ceiling,
     * because a ceiling is not a function of the score. Carrying both is what
     * makes a bounded peer legible: an expelled member reads as an ordinary
     * score with a tier that does not follow from it.
     *
     * Every caller releases rep_state.lock before publishing (checked at all
     * six sites), so this takes it itself.
     *
     * The ceiling is written on EVERY path including the unbounded one: the
     * message was zero-initialized, and an unwritten 0.0 would say "floored at
     * zero" rather than "no bound". */
    pthread_mutex_lock(&rep_state.lock);
    double ceiling = _standing_ceiling_of(peer_uuid);
    pthread_mutex_unlock(&rep_state.lock);
    msg.info.peer_reputation.standing_ceiling =
        ceiling < 0.0 ? PEER_NO_CEILING : ceiling;
    /* The tier reputation ITSELF acts on. A score is bounded where it is
     * WRITTEN, but a ceiling that has just landed has not met a write yet —
     * _publish_standing_change restates the stored, unbounded score — so the
     * bound is applied here too, or a freshly capped peer would be reported
     * at the tier the cap exists to deny. An unrated peer has no tier. */
    double bounded = (ceiling >= 0.0 && score > ceiling) ? ceiling : score;
    msg.info.peer_reputation.effective_tier = rated ? _trust_tier(bounded) : 0;
    /* One try, then kept for the tick (ISSUES §2.14): no 200 ms per peer
     * inside a roster replay. */
    return at_send(NULL, AT_MAIN_QUEUE, &msg, "a peer reputation", "the app",
                   AT_SEND_NOW, NULL, NULL, 0);
}

/* A score this process just committed is by construction rated. */
static void _publish_reputation_change(const uuid_t peer_uuid, double score)
{
    _publish_reputation(peer_uuid, score, true);
}

/* Re-state a peer's reputation because its STANDING changed, not its score
 * (Phase 4 P4.1), and republish the tier the new bound allows.
 *
 * A ceiling arriving or lifting moves no score at all — a cap bounds what a
 * peer may rise to later, and a lift merely removes that bound. So nothing on
 * the ordinary change path fires, and without this the app would never learn
 * that a peer had been bounded by an authority: it would go on showing an
 * expelled member exactly as before. The score is restated unchanged; what is
 * new on the wire is standing_ceiling and the tier beside it.
 *
 * THE TIER GOES TO IDENTITY TOO, or the ceiling gates nothing. Identity's
 * tier-gates read the tier reputation last published, and until this
 * republished it a cap that had just landed left that tier where it was: the
 * capped peer's content kept arriving at its old tier until its score next
 * happened to be recomputed, which on a quiet link may be never. The STORED
 * score is left alone — a ceiling bounds, it does not itself drive a peer
 * downward — and _publish_tier_change's dedup makes a repeated identical
 * finding a no-op. The next score write applies the same bound anyway.
 *
 * Caller must NOT hold rep_state.lock. */
static void _publish_standing_change(const process_t *proc,
                                     const uuid_t peer_uuid)
{
    double score = 0.0;
    pthread_mutex_lock(&rep_state.lock);
    bool rated = reputations_contains(&rep_state.reputations, peer_uuid)
                 && reputations_get(&rep_state.reputations, peer_uuid,
                                    &score) == 0;
    double bounded = rated ? _standing_apply_ceiling(peer_uuid, score) : 0.0;
    pthread_mutex_unlock(&rep_state.lock);
    if (rated)
        _publish_tier_change(proc, peer_uuid, bounded);
    _publish_reputation(peer_uuid, score, rated);
}

int reputation_emit_all(const process_t *proc)
{
    if (proc == NULL || !rep_state.initialized)
        return 0;
    uuid_t uuids[DEFAULT_MAX_PEERS];
    peers_read_lock(proc);
    size_t n = proc->protocol.num_peers;
    if (n > DEFAULT_MAX_PEERS)
        n = DEFAULT_MAX_PEERS;
    for (size_t i = 0; i < n; i++)
        uuid_copy(uuids[i], proc->protocol.peers[i].uuid);
    peers_read_unlock(proc);

    int emitted = 0;
    for (size_t i = 0; i < n; i++)
    {
        /* A peer with no rating is reported AS unrated rather than skipped:
         * silence would leave a consumer unable to distinguish "we hold no
         * rating" from "the message was lost". This pull is the only place
         * rated=false can cross, since every change emission is rated. */
        double score = 0.0;
        pthread_mutex_lock(&rep_state.lock);
        bool rated = (reputations_get(&rep_state.reputations, uuids[i], &score) == 0);
        pthread_mutex_unlock(&rep_state.lock);
        if (_publish_reputation(uuids[i], score, rated) == 0)
            emitted++;
    }
    return emitted;
}

/* Handler: the app asked for the current peer view. */
static bool handle_app_roster_request(const process_t *proc,
                                      directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    /* The local app's verb only, never a peer's (ISSUES §2.17). */
    if (!identity_is_local_app_verb(proc, &msg->info.net_msg))
        return identity_refuse_remote_app_verb(proc, &msg->info.net_msg,
                                               REP_PROTO_APP_ROSTER);
    int n = reputation_emit_all(proc);
    log_debug(proc->logger,
              "Reputation: peer roster request -> %d reputation(s)\n", n);
    return true;
}

/* Resolve @p peer_uuid to its address from the live peer roster and send a
 * Network exclude/readmit control message to the network process. Local IPC
 * only (no wire egress). No-op if the address is unknown (nothing to key the
 * network-layer gate on). Mirrors Python ReputationProcess._publish_exclusion
 * (address resolution + Message(CfgIds.network, Network.exclude/readmit, addr)). */
static void _publish_exclusion(const process_t *proc,
                               const uuid_t peer_uuid, bool excluded)
{
    if (proc == NULL)
        return;
    char address[ADDR_LEN + 1];
    address[0] = '\0';
    peers_read_lock(proc);
    for (size_t i = 0; i < proc->protocol.num_peers; i++) {
        if (uuid_compare(proc->protocol.peers[i].uuid, peer_uuid) == 0) {
            snprintf(address, sizeof(address), "%s",
                     proc->protocol.peers[i].address);
            break;
        }
    }
    peers_read_unlock(proc);
    /* Sent even with no address: the uuid alone gates the peer as a relay
     * client and as a relay (net_relay_note_exclusion). Payload {address,
     * uuid}, the form Python _publish_exclusion sends. */
    char uuid_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer_uuid, uuid_str);
    generic_msg_t ipc = {0};
    ipc.type = NET_MESSAGE;
    strncpy(ipc.info.net_msg.process, "network", PROC_NAME_LEN);
    ipc.info.net_msg.function = excluded ? NET_EXCLUDE_FUNC : NET_READMIT_FUNC;
    ipc.info.net_msg.encrypt = false;  /* local IPC, no wire egress */
    strncpy(ipc.info.net_msg.return_to, "reputation", PROC_NAME_LEN);
    json_t *body = json_object();
    if (body == NULL)
        return;
    json_object_set_new(body, "address", json_string(address));
    json_object_set_new(body, "uuid", json_string(uuid_str));
    net_msg_pack_json(&ipc.info.net_msg, body);
    _rep_send_to_network(proc, &ipc);
    net_msg_free_obj(&ipc.info.net_msg);
    json_decref(body);
    log_info(proc->logger, "Reputation: %s %.8s (%s) at the network layer\n",
             excluded ? "excluded" : "readmitted", uuid_str,
             address[0] != '\0' ? address : "no address");
}

/* Bring the Paxos chain INDEX into line with the chain itself.
 *
 * Python takes the index straight from the chain on both sides of the round —
 * `id2 = len(self.history) + 1` when proposing (repprocess.py:990) and
 * `len(self.history) + 1 == id2` when deciding (repprocess.py:761). C instead
 * kept a private counter, paxos.chain_len, which `paxos_advance_chain`
 * advances ONLY on a round this node proposed and won.
 *
 * Those two quantities agree only while a single node ever proposes. With
 * three, each node's counter counts its OWN wins while every node's HISTORY
 * grows on every commit it learns of (handle_committed), so the counters
 * scatter within seconds. id2 then misses `chain_len + 1` on the acceptors,
 * every request answers PAXOS_BACKDATE, and the group falls into the
 * "out of date" -> "update needed" -> "latest update" loop that never
 * settles — plainly visible in the 2026-09-21 cohort, where the churn ran for
 * the whole ninety seconds and one of the three nodes committed nothing at
 * all. Nothing caught it because the conformance harness resets state between
 * steps, so no scenario has two proposers and a shared chain.
 *
 * The chain is the authority; the counter is a cache of it. Syncing here, at
 * both decision points, is what the Python adapter's own comment already
 * assumes of us: "The C twin reads tx_history rather than its paxos.chain_len
 * ballot counter" (harness/python/adapters/reputation.py:130).
 *
 * Caller must NOT hold rep_state.lock. */
/* Our committed head hash ("" for an empty chain) and length, for the fork
 * probe a request carries (ISSUES §2.51). */
static int _our_head(char out[TX_HASH_HEX_LEN + 1])
{
    pthread_mutex_lock(&rep_state.lock);
    int len = tx_history_len(&rep_state.history);
    if (rep_state.history.committed_count > 0)
        at_strlcpy(out, rep_state.history.head_hash, TX_HASH_HEX_LEN + 1);
    else
        out[0] = '\0';
    pthread_mutex_unlock(&rep_state.lock);
    return len;
}

/* Our committed head hash, for conformance adapters that must name it. */
int reputation_head_hash(char *out, size_t cap)
{
    char head[TX_HASH_HEX_LEN + 1];
    int len = _our_head(head);
    if (out != NULL && cap > 0)
        at_strlcpy(out, head, cap);
    return len;
}

/* "update needed" to @p to: it answers with its chain (handle_outdated). */
static void _request_chain(const process_t *proc, const public_identity_t *to)
{
    generic_msg_t update_req = {0};
    update_req.type = NET_MESSAGE;
    strncpy(update_req.info.net_msg.process, "reputation", PROC_NAME_LEN);
    update_req.info.net_msg.function = REP_PROTO_OUTDATED;
    update_req.info.net_msg.encrypt = true;
    memcpy(&update_req.info.net_msg.to_whom, to, sizeof(public_identity_t));
    strncpy(update_req.info.net_msg.return_to, "reputation", PROC_NAME_LEN);
    _rep_send_to_network(proc, &update_req);
}

/* "update needed" for chain @p key: a bare request for the primary chain,
 * {"from", "group"} for a gateway's child chain. Mirrors Python
 * _request_update(key=). */
static void _request_chain_for(const process_t *proc, const public_identity_t *to,
                               const char *key)
{
    if (key == NULL || key[0] == '\0')
    {
        _request_chain(proc, to);
        return;
    }
    generic_msg_t req = {0};
    req.type = NET_MESSAGE;
    strncpy(req.info.net_msg.process, "reputation", PROC_NAME_LEN);
    req.info.net_msg.function = REP_PROTO_OUTDATED;
    req.info.net_msg.encrypt = true;
    memcpy(&req.info.net_msg.to_whom, to, sizeof(public_identity_t));
    strncpy(req.info.net_msg.return_to, "reputation", PROC_NAME_LEN);
    pthread_mutex_lock(&rep_state.lock);
    int from = _chain_for_key_locked(key)->next_index;
    pthread_mutex_unlock(&rep_state.lock);
    json_t *body = json_pack("{s:i, s:s}", "from", from, "group", key);
    if (body != NULL)
    {
        net_msg_pack_json(&req.info.net_msg, body);
        json_decref(body);
    }
    _rep_send_to_network(proc, &req);
    net_msg_free_obj(&req.info.net_msg);
}

static void _sync_chain_index(void)
{
    pthread_mutex_lock(&rep_state.lock);
    int len = tx_history_len(&rep_state.history);
    pthread_mutex_unlock(&rep_state.lock);
    pthread_mutex_lock(&rep_state.paxos.lock);
    rep_state.paxos.chain_len = len;
    pthread_mutex_unlock(&rep_state.paxos.lock);
}

/* Send our half to the group to co-sign (_forward_transaction). The staged
 * half leaves my_requests, the round is bound to our primary group, and the
 * proposal asks to be certified and names that group, which is what an
 * acceptor checks before it takes the half (handle_transaction). Mirrors
 * Python _propose_half. */
static void _propose_half(const process_t *proc, int64_t id1, int64_t id2,
                          const char *peer_uuid_str, double tx_score)
{
    char round_key[PAXOS_KEY_LEN];
    paxos_id_index(round_key, sizeof(round_key), id1, id2);
    pthread_mutex_lock(&rep_state.lock);
    data_t *tx_dat = NULL;
    tx_score_t *tx = NULL;
    if (map_get(&rep_state.my_requests, round_key, &tx_dat) == 0)
        data_object_ptr(tx_dat, (void **)&tx);
    if (tx == NULL)
    {
        /* Already sent: a second grant past the quorum, racing the first. */
        pthread_mutex_unlock(&rep_state.lock);
        return;
    }
    /* Capture task_uuid + capability_name before potential removal.
     * The proposer caches its own weight here so reputation_pure (and
     * its EMA twin) on this side use the same weight as the
     * receivers, who will cache via handle_transaction below. */
    char task_uuid_str[UUID_STRING_LEN + 1] = {0};
    char cap_name_local[CAP_NAMELEN + 1] = {0};
    char channel_local[TX_CHANNEL_NAMELEN + 1] = {0};
    uuid_unparse_lower(tx->task_uuid, task_uuid_str);
    _drop_cosigs_locked(&rep_state.round_granters, round_key);
    strncpy(cap_name_local, tx->capability_name, CAP_NAMELEN);
    cap_name_local[CAP_NAMELEN] = '\0';
    /* Same copy-before-removal reason as cap_name: `tx` can be freed by
     * the map_remove below, and the channel is needed for the broadcast. */
    strncpy(channel_local, tx->channel, TX_CHANNEL_NAMELEN);
    channel_local[TX_CHANNEL_NAMELEN] = '\0';
    /* Same copy-before-removal reason again: the staged competence
     * multiplier has to outlive `tx` so this re-record reproduces the
     * weight the round started with (R+D.md §12.5). */
    double competence_local = tx->competence;
    if (task_uuid_str[0] != '\0')
    {
        /* Our own round, so the channel counts (R+D.md §12.8). */
        _record_task_weight_locked(task_uuid_str,
                                   _resolve_tx_weight_local(cap_name_local,
                                                            channel_local,
                                                            competence_local));
        /* ...and it has to survive to handle_accepted, which writes this
         * entry to our history and broadcasts it: the channel is part of
         * the committed fact now, and `tx` is freed by the map_remove
         * below. */
        _record_task_channel_locked(task_uuid_str, channel_local);
    }

    map_remove(&rep_state.my_requests, round_key);
    /* Bind the round to OUR primary group, the C twin of Python's
     * _start_paxos(round_group). The tag then travels on the commit
     * broadcast, and each receiver maps it through its own view: a sibling
     * member sees its primary group, while a GATEWAY sees one of its child
     * groups and routes the entry to that subtree's chain (doc/architecture/gateway-reputation-tree.md). */
    char own_group[UUID_STRING_LEN + 1];
    uuid_unparse_lower(proc->protocol.group.uuid, own_group);
    _set_round_group_locked(round_key, own_group);
    pthread_mutex_unlock(&rep_state.lock);

    /* Broadcast REP_PROTO_TX to all peers */
    json_t *tx_json = json_object();
    if (tx_json == NULL) {
        log_error(proc->logger, "Reputation: json_object OOM (tx)\n");
        return;
    }
    json_object_set_new(tx_json, "id1", json_integer(id1));
    json_object_set_new(tx_json, "id2", json_integer(id2));
    json_object_set_new(tx_json, "peer_uuid", json_string(peer_uuid_str));
    json_object_set_new(tx_json, "score", json_real(tx_score));
    if (task_uuid_str[0] != '\0')
        json_object_set_new(tx_json, "task_uuid", json_string(task_uuid_str));
    if (cap_name_local[0] != '\0')
        json_object_set_new(tx_json, "capability_name",
                            json_string(cap_name_local));
    /* Emitted only when set, matching capability_name's convention: an
     * absent key is how a receiver reads "task outcome" without this side
     * having to assert a channel it was never told (R+D.md §12.8). The
     * Python twin serializes the normalized value unconditionally; both
     * spellings of absence land on TX_CHANNEL_TASK_OUTCOME. */
    if (channel_local[0] != '\0')
        json_object_set_new(tx_json, "channel",
                            json_string(channel_local));
    /* Ask each acceptor to sign what it accepts, and name the group, which
     * is what an acceptor checks before it takes the half
     * (handle_transaction). The round is bound to our primary group (just
     * above). */
    json_object_set_new(tx_json, "certify", json_true());
    json_object_set_new(tx_json, "group", json_string(own_group));

    log_debug(proc->logger, "Reputation: Submit transaction score\n");

    peers_read_lock(proc);
    for (size_t i = 0; i < proc->protocol.num_peers; i++)
    {
        generic_msg_t tx_msg = {0};
        tx_msg.type = NET_MESSAGE;
        strncpy(tx_msg.info.net_msg.process, "reputation", PROC_NAME_LEN);
        tx_msg.info.net_msg.function = REP_PROTO_TX;
        tx_msg.info.net_msg.encrypt = true;
        memcpy(&tx_msg.info.net_msg.to_whom, &proc->protocol.peers[i], sizeof(public_identity_t));
        strncpy(tx_msg.info.net_msg.return_to, "reputation", PROC_NAME_LEN);
        net_msg_pack_json(&tx_msg.info.net_msg, tx_json);
        _rep_send_to_network(proc, &tx_msg);
        net_msg_free_obj(&tx_msg.info.net_msg);
    }
    peers_read_unlock(proc);
    json_decref(tx_json);
}

/****************************
 * Handler: handle_retired — a verb of the retired half round
 ****************************/

/* Senders already told their retired verb was dropped: logged once each. */
#define REP_RETIRED_FROM_MAX 64
static char g_retired_from[REP_RETIRED_FROM_MAX][UUID_STRING_LEN + 1];
static size_t g_retired_from_len;

/* A verb of the retired half round (REP_PROTO_RETIRED_*) from a node on a
 * build that still runs it. Nothing here answers it; it is dropped, and logged
 * once per sender so a mixed-version cohort shows in the log. Mirrors Python
 * ReputationProcess.handle_retired. */
static bool handle_retired(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    char sender[UUID_STRING_LEN + 1];
    uuid_unparse_lower(nmsg->from_whom.uuid, sender);
    pthread_mutex_lock(&rep_state.lock);
    bool seen = false;
    for (size_t i = 0; i < g_retired_from_len && !seen; i++)
        seen = strcmp(g_retired_from[i], sender) == 0;
    if (!seen && g_retired_from_len < REP_RETIRED_FROM_MAX)
        at_strlcpy(g_retired_from[g_retired_from_len++], sender,
                   sizeof(g_retired_from[0]));
    pthread_mutex_unlock(&rep_state.lock);
    if (!seen)
        log_info(proc->logger, "Reputation: retired reputation verb '%s' from "
                 "%s (a build from before every group placed its order); "
                 "dropped\n", nmsg->function != NULL ? nmsg->function : "?",
                 nmsg->from_whom.nickname[0] != '\0'
                     ? nmsg->from_whom.nickname : sender);
    return true;
}

/****************************
 * Handler: handle_transaction (transaction) — co-signing
 * Validate the proposal names its group, then sign and send accepted.
 ****************************/

/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
  requires rep_state.paxos.initialized == \true;
*/
static bool handle_transaction(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Reputation: transaction from %s\n", nmsg->from_whom.nickname);

    /* Reject unverified Paxos proposals. Mirrors Python
     * repprocess.handle_transaction:390 — without this guard a peer
     * with no private key (or an attacker who can deliver bytes to
     * net_proc) can drive consensus by submitting unsigned
     * transactions and have us co-sign them. */
    if (!nmsg->verified)
    {
        log_warn(proc->logger,
                    "Reputation: rejecting unverified Paxos proposal from %s\n",
                    nmsg->from_whom.nickname);
        return true;
    }

    /* Unpack (id1, id2, peer_uuid, score) */
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Reputation: handle_transaction: failed to unpack JSON\n");
        return false;
    }

    json_t *j_id1      = json_object_get(payload, "id1");
    json_t *j_id2      = json_object_get(payload, "id2");
    json_t *j_peer_uuid = json_object_get(payload, "peer_uuid");
    json_t *j_score    = json_object_get(payload, "score");

    if (!j_id1 || !j_id2 || !j_peer_uuid || !j_score)
    {
        json_decref(payload);
        log_error(proc->logger, "Reputation: handle_transaction: missing JSON fields\n");
        return false;
    }

    int64_t id2 = json_integer_value(j_id2);
    int64_t id1 = json_integer_value(j_id1);
    double score = json_real_value(j_score);
    /* doc/architecture/reputation.md: reject a peer-supplied score off AT's [0, 1] scale rather than
     * grading it. Mirrors the Python twin, which raises in TransactionScore's
     * constructor and drops the message in handle_transaction. */
    if (!tx_score_in_range(score))
    {
        json_decref(payload);
        log_warn(proc->logger,
                 "Reputation: handle_transaction: score %f is off the [%g, %g] "
                 "scale; dropping proposal\n", score, TX_SCORE_MIN, TX_SCORE_MAX);
        return true;   /* consumed: a malformed proposal is not another handler's */
    }
    /* peer_uuid / task_uuid are borrowed from `payload` but are echoed back
     * into the ACCEPTED reply AFTER json_decref(payload) below; copy them out
     * now to avoid a use-after-free. Preserve NULL so an absent field stays
     * absent in the reply rather than becoming an empty string. cap_name is
     * only consumed before the decref, so it can stay borrowed. */
    const char *peer_uuid_borrowed = json_string_value(j_peer_uuid);
    char peer_uuid_buf[UUID_STRING_LEN + 1];
    bool have_peer_uuid = peer_uuid_borrowed != NULL;
    if (have_peer_uuid)
    {
        strncpy(peer_uuid_buf, peer_uuid_borrowed, UUID_STRING_LEN);
        peer_uuid_buf[UUID_STRING_LEN] = '\0';
    }
    const char *peer_uuid_str = have_peer_uuid ? peer_uuid_buf : NULL;

    const char *task_uuid_borrowed =
        json_string_value(json_object_get(payload, "task_uuid"));
    char task_uuid_str_buf[UUID_STRING_LEN + 1];
    bool have_task_uuid = task_uuid_borrowed != NULL;
    if (have_task_uuid)
    {
        strncpy(task_uuid_str_buf, task_uuid_borrowed, UUID_STRING_LEN);
        task_uuid_str_buf[UUID_STRING_LEN] = '\0';
    }
    const char *task_uuid_str = have_task_uuid ? task_uuid_str_buf : NULL;

    const char *cap_name = json_string_value(
        json_object_get(payload, "capability_name"));

    /* Evidence channel (R+D.md §12.8). Absent is fine and means "task
     * outcome" -- a peer running a build from before this field is not in
     * error. A channel that is PRESENT but not in the closed set is refused
     * and the proposal dropped, exactly as an off-scale score is: the value of
     * the field is that a demotion reason means one agreed thing on both sides
     * of the wire, and passing an unrecognized spelling through would forfeit
     * that. Mirrors validate_tx_channel raising in the Python twin's
     * TransactionScore constructor, which handle_transaction there catches. */
    const char *channel_borrowed = json_string_value(
        json_object_get(payload, "channel"));
    if (channel_borrowed != NULL && channel_borrowed[0] != '\0' &&
        !tx_channel_valid(channel_borrowed))
    {
        log_warn(proc->logger,
                 "Reputation: handle_transaction: unknown evidence channel "
                 "'%s'; dropping proposal\n", channel_borrowed);
        json_decref(payload);
        return true;   /* consumed: a malformed proposal is not another handler's */
    }
    const char *channel_str = tx_channel_or_default(channel_borrowed);
    log_debug(proc->logger, "Reputation: transaction score %.2f via %s\n",
              score, channel_str);

    /* A proposal asks to be certified and names its group. One without both
     * is from a build that still ran the half round, which this node no
     * longer grants. Mirrors Python handle_transaction. */
    const char *placing_group = json_is_true(json_object_get(payload, "certify"))
        ? json_string_value(json_object_get(payload, "group")) : NULL;
    if (placing_group == NULL)
    {
        json_decref(payload);
        log_debug(proc->logger, "Reputation: dropping a proposal that names no "
                  "group (a half-round build)\n");
        return true;
    }

    /* Record the grant (score) in the paxos proposals for later acceptance tracking */
    paxos_record_grant(&rep_state.paxos, id1, id2, score);

    /* Asked to certify (a group that requires commit certificates): sign the
     * half this round writes. Only the proposer may ask -- a relayed proposal
     * carries somebody else's round, and signing it would vouch for a round
     * this node never saw that peer run. Computed here because the channel is
     * borrowed from `payload`. Mirrors Python handle_transaction. */
    char commit_sig[REP_SIG_HEX_LEN + 1] = {0};
    if (json_is_true(json_object_get(payload, "certify")))
    {
        uuid_t scorer, task;
        if (peer_uuid_str != NULL && task_uuid_str != NULL
            && uuid_parse(peer_uuid_str, scorer) == 0
            && uuid_parse(task_uuid_str, task) == 0
            && uuid_compare(nmsg->from_whom.uuid, scorer) == 0)
        {
            uint8_t desig[REP_DESIG_MAX];
            size_t dlen = commit_designation(scorer, task, score,
                                             channel_borrowed, desig,
                                             sizeof(desig));
            if (dlen == 0
                || _cosign_hex(proc, desig, dlen, commit_sig,
                               sizeof(commit_sig)) != 0)
            {
                commit_sig[0] = '\0';
                log_error(proc->logger, "Reputation: cannot sign the commit "
                          "designation; accepting unsigned\n");
            }
        }
        else
        {
            log_warn(proc->logger, "Reputation: not certifying a proposal from "
                     "%s for another peer's round\n", nmsg->from_whom.nickname);
        }
    }

    /* Cache the per-task transaction_weight so reputation_pure /
     * reputation_consensus can apply it when this transaction lands
     * in the chain. Mirrors Python handle_transaction's
     * _record_task_weight call. If the local registry doesn't know
     * the capability, weight falls back to 1. */
    if (task_uuid_str != NULL && task_uuid_str[0] != '\0')
    {
        char task_uuid_buf[UUID_STRING_LEN + 1];
        strncpy(task_uuid_buf, task_uuid_str, UUID_STRING_LEN);
        task_uuid_buf[UUID_STRING_LEN] = '\0';
        pthread_mutex_lock(&rep_state.lock);
        /* No channel term: a peer's tag is legibility only (R+D.md §12.8). */
        _record_task_weight_locked(task_uuid_buf, _resolve_tx_weight(cap_name));
        _record_task_tier_locked(task_uuid_buf, _resolve_tx_tier(cap_name));
        pthread_mutex_unlock(&rep_state.lock);
    }

    json_decref(payload);

    /* Send ACCEPTED back */
    json_t *acc_json = json_object();
    if (acc_json == NULL) {
        log_error(proc->logger, "Reputation: json_object OOM (accepted)\n");
        return true;
    }
    json_object_set_new(acc_json, "id1", json_integer(id1));
    json_object_set_new(acc_json, "id2", json_integer(id2));
    json_object_set_new(acc_json, "peer_uuid", json_string(peer_uuid_str));
    if (task_uuid_str)
        json_object_set_new(acc_json, "task_uuid", json_string(task_uuid_str));
    if (commit_sig[0] != '\0')
        json_object_set_new(acc_json, "sig", json_string(commit_sig));

    generic_msg_t accepted = {0};
    accepted.type = NET_MESSAGE;
    strncpy(accepted.info.net_msg.process, "reputation", PROC_NAME_LEN);
    accepted.info.net_msg.function = REP_PROTO_ACCEPTED;
    accepted.info.net_msg.encrypt = true;
    memcpy(&accepted.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
    strncpy(accepted.info.net_msg.return_to, "reputation", PROC_NAME_LEN);
    net_msg_pack_json(&accepted.info.net_msg, acc_json);
    json_decref(acc_json);

    _rep_send_to_network(proc, &accepted);
    net_msg_free_obj(&accepted.info.net_msg);
    return true;
}

/****************************
 * Handler: handle_accepted (tx accepted) — Paxos Phase 2b
 * Count acceptances; commit to history on majority.
 ****************************/

/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
  requires rep_state.paxos.initialized == \true;
*/
static bool handle_accepted(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Reputation: tx accepted by %s\n", nmsg->from_whom.nickname);

    /* Reject unverified Paxos acceptances. Mirrors Python
     * repprocess.handle_accepted:439 — a forged ACCEPTED can push
     * acc_count over the majority threshold and force a commit on a
     * proposal the honest cohort would have rejected. */
    if (!nmsg->verified)
    {
        log_warn(proc->logger,
                    "Reputation: rejecting unverified Paxos acceptance from %s\n",
                    nmsg->from_whom.nickname);
        return true;
    }

    /* Unpack (id1, id2, peer_uuid) */
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Reputation: handle_accepted: failed to unpack JSON\n");
        return false;
    }

    json_t *j_id1      = json_object_get(payload, "id1");
    json_t *j_id2      = json_object_get(payload, "id2");
    json_t *j_peer_uuid = json_object_get(payload, "peer_uuid");

    if (!j_id1 || !j_id2 || !j_peer_uuid)
    {
        json_decref(payload);
        log_error(proc->logger, "Reputation: handle_accepted: missing JSON fields\n");
        return false;
    }

    int64_t id1 = json_integer_value(j_id1);
    int64_t id2 = json_integer_value(j_id2);
    const char *peer_uuid_str = json_string_value(j_peer_uuid);

    /* Look up score from paxos proposals */
    char paxos_key[PAXOS_KEY_LEN];
    paxos_id_index(paxos_key, sizeof(paxos_key), id1, id2);

    pthread_mutex_lock(&rep_state.paxos.lock);
    data_t *prop_dat = NULL;
    double score = 0.0;
    if (map_get(&rep_state.paxos.proposals, paxos_key, &prop_dat) == 0)
    {
        paxos_proposal_t *ptc = NULL;
        data_object_ptr(prop_dat, (void **)&ptc);
        if (ptc != NULL) score = ptc->score;
    }
    pthread_mutex_unlock(&rep_state.paxos.lock);

    pthread_mutex_lock(&rep_state.lock);
    size_t acc_quorum = _round_quorum_locked(proc, paxos_key);
    char acc_group[UUID_STRING_LEN + 1];
    _get_round_group_locked(paxos_key, acc_group, sizeof(acc_group));
    pthread_mutex_unlock(&rep_state.lock);
    char acc_voter[UUID_STRING_LEN + 1];
    uuid_unparse_lower(nmsg->from_whom.uuid, acc_voter);
    char self_str[UUID_STRING_LEN + 1] = {0};
    uuid_t self_uuid;
    if (_resolve_self_uuid(proc, self_uuid))
        uuid_unparse_lower(self_uuid, self_str);

    /* Only SIGNED acceptances count, and the round carries once their signatures clear the bar
     * a receiver will hold them to (_commit_cert_ok), so a commit this node
     * sends is one its own group will write. Mirrors Python handle_accepted. */
    json_t *certificate = NULL;
    const char *acc_task_str = json_string_value(json_object_get(payload,
                                                                 "task_uuid"));
    {
        uuid_t scorer, task;
        char voter[UUID_STRING_LEN + 1];
        uuid_unparse_lower(nmsg->from_whom.uuid, voter);
        const char *sig = json_string_value(json_object_get(payload, "sig"));
        char chan[TX_CHANNEL_NAMELEN + 1] = {0};
        bool parsed = acc_task_str != NULL && peer_uuid_str != NULL
            && uuid_parse(acc_task_str, task) == 0
            && uuid_parse(peer_uuid_str, scorer) == 0;
        uint8_t desig[REP_DESIG_MAX];
        size_t dlen = 0;
        if (parsed)
        {
            pthread_mutex_lock(&rep_state.lock);
            const char *stashed = _task_channel_locked(acc_task_str);
            if (stashed != NULL)
                at_strlcpy(chan, stashed, sizeof(chan));
            pthread_mutex_unlock(&rep_state.lock);
            dlen = commit_designation(scorer, task, score, chan, desig,
                                      sizeof(desig));
        }
        json_t *in_force = _roster_for_group(proc, acc_group[0] != '\0' ? acc_group : NULL);
        bool counted = dlen > 0
            && _verify_cosignature_in(proc, in_force, voter, desig, dlen, sig);
        json_decref(in_force);
        if (!counted)
        {
            log_warn(proc->logger, "Reputation: acceptance from %s carries no "
                     "valid commit signature; not counted\n",
                     nmsg->from_whom.nickname);
            json_decref(payload);
            return true;
        }
        pthread_mutex_lock(&rep_state.lock);
        _record_cosig_locked(&rep_state.commit_sigs, acc_task_str, voter, sig);
        json_t *pending = _cosigs_json_locked(&rep_state.commit_sigs,
                                              acc_task_str, NULL);
        pthread_mutex_unlock(&rep_state.lock);
        if (_commit_cert_ok(proc, scorer, task, score, chan, pending,
                            acc_group[0] != '\0' ? acc_group : NULL))
            certificate = pending;
        else
            json_decref(pending);
    }

    /* One vote per member per round, ours included: sending the transaction
     * was our own acceptance. Rounds that never commit are not otherwise forgotten, so
     * past REP_ROUND_ACCEPTORS_CAP entries the map starts over: a round in
     * flight then loses its votes and is re-proposed by the commit sweep.
     * Mirrors Python handle_accepted. */
    pthread_mutex_lock(&rep_state.lock);
    if (map_size(&rep_state.round_acceptors) >= REP_ROUND_ACCEPTORS_CAP)
    {
        map_free(&rep_state.round_acceptors);
        map_init(&rep_state.round_acceptors);
    }
    _record_cosig_locked(&rep_state.round_acceptors, paxos_key, acc_voter, "1");
    size_t own = (self_str[0] != '\0' && peer_uuid_str != NULL
                  && strcmp(peer_uuid_str, self_str) == 0) ? 1 : 0;
    size_t votes = _round_voters_locked(&rep_state.round_acceptors, paxos_key)
        + own;
    pthread_mutex_unlock(&rep_state.lock);
    /* Carried once the signatures make a certificate: sized by the logged
     * roster when the chain has one (the certificate meets it), and by the
     * round's quorum before the genesis. Mirrors Python handle_accepted. */
    bool commit = false;
    if (certificate != NULL)
    {
        json_t *in_force = _roster_for_group(proc, acc_group[0] != '\0' ? acc_group : NULL);
        commit = in_force != NULL || votes > acc_quorum;
        json_decref(in_force);
    }
    if (!commit && certificate != NULL)
    {
        json_decref(certificate);
        certificate = NULL;
    }

    if (commit)
    {
        /* Idempotency guard: every ACCEPTED that arrives after the
         * majority threshold has been crossed would otherwise re-fire
         * the commit-and-broadcast block. That fans out ~N-majority
         * extra `committed` broadcasts per round, and duplicate
         * broadcasts corrupt the Transaction (tx_history_update would
         * set p2 = p1 = proposer because the bilateral guard there
         * would also be needed if this slipped through). Mirrors
         * repprocess.handle_accepted's `committed_paxos_rounds` set. */
        data_t *already = NULL;
        if (map_get(&rep_state.committed_paxos_rounds, paxos_key, &already) == 0)
        {
            json_decref(payload);
            return true;
        }
        data_t *mark = integer_data(1);
        map_set(&rep_state.committed_paxos_rounds, paxos_key, mark);
        pthread_mutex_lock(&rep_state.lock);
        _drop_cosigs_locked(&rep_state.round_acceptors, paxos_key);
        pthread_mutex_unlock(&rep_state.lock);
        /* FIFO ring: if we're at cap, the head slot already holds the
         * oldest key — drop it from the map before overwriting the
         * slot. ring_len caps at COMMITTED_ROUNDS_CAP; once steady
         * state, head wraps and each insert evicts one. Mirrors
         * Python's OrderedDict.popitem(last=False) loop in
         * repprocess.handle_accepted. */
        if (rep_state.committed_paxos_ring_len == COMMITTED_ROUNDS_CAP)
        {
            map_remove(&rep_state.committed_paxos_rounds,
                       rep_state.committed_paxos_ring[
                           rep_state.committed_paxos_ring_head]);
        }
        else
        {
            rep_state.committed_paxos_ring_len++;
        }
        /* snprintf rather than strncpy to silence -Wstringop-truncation
         * while still guaranteeing NUL termination. paxos_key is a
         * compact decimal string well under 64 bytes; truncation
         * cannot happen in practice. */
        snprintf(rep_state.committed_paxos_ring[
                     rep_state.committed_paxos_ring_head],
                 sizeof(rep_state.committed_paxos_ring[0]),
                 "%s", paxos_key);
        rep_state.committed_paxos_ring_head =
            (rep_state.committed_paxos_ring_head + 1)
            % COMMITTED_ROUNDS_CAP;

        /* Parse UUIDs and commit to history */
        uuid_t peer_uuid;
        uuid_t task_uuid;
        uuid_parse(peer_uuid_str, peer_uuid);

        const char *task_uuid_str = json_string_value(json_object_get(payload, "task_uuid"));
        bool have_task_uuid = (task_uuid_str
                               && uuid_parse(task_uuid_str, task_uuid) == 0);
        /* Route to the chain this round belongs to: a gateway keeps one per
         * child group, and merging a subtree's history into the primary chain
         * would make every group's reputation everyone else's (doc/architecture/gateway-reputation-tree.md). */
        char round_group[UUID_STRING_LEN + 1] = {0};
        _get_round_group_locked(paxos_key, round_group, sizeof(round_group));
        if (round_group[0] == '\0')
        {
            /* Unbound round (a peer that predates the binding, or a replayed
             * key): it is ours, so it belongs to our primary group. */
            uuid_unparse_lower(proc->protocol.group.uuid, round_group);
        }
        tx_history_t *chain = _chain_for_group_locked(proc, round_group);
        /* Our own proposal's channel, stashed when we won the floor. Empty
         * (i.e. `task_outcome`) for a task we never tagged, and for the
         * task_uuid-less fallback below, which has no task key to stash
         * under.
         *
         * COPIED out of the map rather than borrowed: the pointer the map
         * owns can be evicted (task_channels is bounded and evicts in
         * lockstep with task_weights), and it is still needed further down
         * for the broadcast. Same copy-before-use discipline as
         * `round_group` above. */
        char commit_channel[TX_CHANNEL_NAMELEN + 1] = {0};
        if (have_task_uuid)
        {
            const char *stashed = _task_channel_locked(task_uuid_str);
            if (stashed != NULL)
                at_strlcpy(commit_channel, stashed, sizeof(commit_channel));
        }
        if (have_task_uuid)
        {
            /* The half waits in the pool until a placement writes its entry
             * (doc/architecture/reputation.md, "Agreeing on an order").
             * Mirrors Python _record_committed_half. */
            char *text = certificate != NULL
                ? json_dumps(certificate, JSON_COMPACT | JSON_SORT_KEYS) : NULL;
            pthread_mutex_lock(&rep_state.lock);
            (void)tx_history_record_half(chain, task_uuid, peer_uuid, score,
                                         commit_channel, text);
            _drop_cosigs_locked(&rep_state.commit_sigs, task_uuid_str);
            pthread_mutex_unlock(&rep_state.lock);
            free(text);
        }
        paxos_advance_chain(&rep_state.paxos);
        /* Our half is in: stop watching it (ISSUES §2.24). */
        if (have_task_uuid)
        {
            pthread_mutex_lock(&rep_state.lock);
            map_remove(&rep_state.awaiting_commit, (map_key_t)task_uuid_str);
            pthread_mutex_unlock(&rep_state.lock);
        }
        /* Reset this peer's idle clock: the staleness sweep must leave an
         * actively-transacting peer alone (doc/architecture/reputation.md). */
        _note_interaction(peer_uuid);
        /* Name the task. A bare "committed" cannot be tied to the thing that
         * caused it — which is exactly what stopped the 2026-09-21 cohort
         * from asserting that an APP-driven round (a post reaction) reached
         * the chain, as opposed to one of AT's own background probes. The
         * task uuid is the only identifier both sides of a bilateral
         * interaction share, so it is the one worth printing. */
        log_info(proc->logger, "Reputation: Transaction committed (task %s)\n",
                 have_task_uuid ? task_uuid_str : "-");

        /* Phase 3 — broadcast committed (task_id, peer_id, score) to
         * the group so acceptors can write the same entry to their
         * own histories.  Bilateral Transactions form across peers
         * when both sides eventually run this for each other's
         * submissions. */
        json_t *commit_json = json_object();
        if (commit_json != NULL)
        {
            if (have_task_uuid)
                json_object_set_new(commit_json, "task_uuid",
                                    json_string(task_uuid_str));
            json_object_set_new(commit_json, "peer_uuid",
                                json_string(peer_uuid_str));
            json_object_set_new(commit_json, "score", json_real(score));
            /* The evidence channel rides along (R+D.md §12.8): without it an
             * acceptor writes the score and drops the reason, and "every peer
             * can judge a poor score for itself" is only true if the reason
             * reaches every peer. Omitted when absent/default, which keeps
             * the payload byte-identical for every untagged commit -- and
             * matches the entry hash, where absent and an explicit
             * `task_outcome` are the same bytes. */
            if (commit_channel[0] != '\0')
                json_object_set_new(commit_json, "channel",
                                    json_string(commit_channel));
            /* Tag the chain so receivers route it the same way we just did.
             * Omitted for the primary chain, which keeps the payload
             * byte-identical for every leaf node. */
            if (round_group[0] != '\0')
                json_object_set_new(commit_json, "group_uuid",
                                    json_string(round_group));
            /* The certificate the round carried. */
            if (certificate != NULL)
                json_object_set(commit_json, "certificate", certificate);

            generic_msg_t bcast = {0};
            bcast.type = NET_MESSAGE;
            strncpy(bcast.info.net_msg.process, "reputation", PROC_NAME_LEN);
            bcast.info.net_msg.function = REP_PROTO_COMMITTED;
            bcast.info.net_msg.encrypt = true;
            /* Group broadcast — handlers use the group key.  Mirror
             * the convention used by _forward_transaction's REQUEST
             * broadcast at rep_proc.c:1113-1122 (a per-peer loop on
             * the proc->protocol.peers list). */
            net_msg_pack_json(&bcast.info.net_msg, commit_json);
            json_decref(commit_json);

            peers_read_lock(proc);
            for (size_t i = 0; i < proc->protocol.num_peers; i++)
            {
                generic_msg_t per = bcast;  /* shallow copy */
                memcpy(&per.info.net_msg.to_whom,
                       &proc->protocol.peers[i],
                       sizeof(public_identity_t));
                _rep_send_to_network(proc, &per);
            }
            peers_read_unlock(proc);
            /* The per-peer copies share bcast's obj; free it once. */
            net_msg_free_obj(&bcast.info.net_msg);
        }
    }
    else
    {
        log_debug(proc->logger, "Reputation: Tx accepted (%zu of more than %zu so far)\n",
                  votes, acc_quorum);
    }

    json_decref(certificate);
    json_decref(payload);
    return true;
}

/****************************
 * Handler: handle_committed (tx committed) — Phase 3
 * Acceptor receives the proposer's commit announcement and writes
 * (task_id, peer_id, score) to local history.  The proposer's own
 * broadcast bounces back to itself — we skip the self-update because
 * handle_accepted already wrote the entry locally.
 ****************************/

/*@
  requires \valid(proc);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_committed(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Reputation: handle_committed: failed to unpack JSON\n");
        return false;
    }

    json_t *j_peer_uuid = json_object_get(payload, "peer_uuid");
    json_t *j_task_uuid = json_object_get(payload, "task_uuid");
    json_t *j_score     = json_object_get(payload, "score");

    if (!j_peer_uuid || !j_score)
    {
        json_decref(payload);
        log_error(proc->logger, "Reputation: handle_committed: missing JSON fields\n");
        return false;
    }

    const char *peer_uuid_str = json_string_value(j_peer_uuid);
    double score = json_real_value(j_score);
    /* doc/architecture/reputation.md, and this is the path that WRITES history on every acceptor, so the
     * bound matters most here. Same rejection as handle_transaction. */
    if (!tx_score_in_range(score))
    {
        json_decref(payload);
        log_warn(proc->logger,
                 "Reputation: handle_committed: score %f is off the [%g, %g] "
                 "scale; dropping\n", score, TX_SCORE_MIN, TX_SCORE_MAX);
        return true;
    }

    /* No self-bounce check needed in C — handle_accepted's broadcast
     * loop iterates proc->protocol.peers, which excludes self.  The
     * Python twin keeps a self-skip as a safety net because its
     * encrypted-group broadcast may or may not loop back through
     * the local network process. */

    uuid_t peer_uuid;
    if (uuid_parse(peer_uuid_str, peer_uuid) != 0)
    {
        json_decref(payload);
        log_error(proc->logger, "Reputation: handle_committed: bad peer_uuid\n");
        return false;
    }

    /* ISSUES.md §2.16, shape 2: provenance. Unsigned, a commit is nobody's
     * word; signed, it may write only its SENDER's own half -- the proposer
     * commits the score it gave. Without this, any member wrote both halves of
     * a fabricated entry about anybody. Mirrors Python handle_committed. */
    if (!nmsg->verified)
    {
        json_decref(payload);
        log_warn(proc->logger, "Reputation: rejecting unverified committed from %s\n",
                 nmsg->from_whom.nickname);
        return true;
    }
    if (uuid_compare(nmsg->from_whom.uuid, peer_uuid) != 0)
    {
        log_warn(proc->logger,
                 "Reputation: rejecting committed from %s: it writes %.8s's half, "
                 "not its own\n", nmsg->from_whom.nickname, peer_uuid_str);
        json_decref(payload);
        return true;
    }

    /* Evidence channel of the committed score (R+D.md §12.8). Absent means a
     * pre-channel proposer, which is `task_outcome`. A spelling outside the
     * closed set drops the whole commit rather than being coerced away: the
     * channel is part of the entry hash, so accepting one this node cannot
     * name would fork this chain away from the group's. Mirrors the Python
     * twin's validate_tx_channel call in handle_committed, and the same
     * refusal handle_transaction already makes for a proposal. */
    const char *chan_borrowed = json_string_value(json_object_get(payload,
                                                                 "channel"));
    if (chan_borrowed != NULL && chan_borrowed[0] != '\0'
        && !tx_channel_valid(chan_borrowed))
    {
        log_warn(proc->logger,
                 "Reputation: handle_committed: unknown evidence channel "
                 "'%s'; dropping commit\n", chan_borrowed);
        json_decref(payload);
        return true;
    }

    uuid_t task_uuid;
    const char *task_uuid_str = j_task_uuid ? json_string_value(j_task_uuid) : NULL;
    /* An untagged commit (or one naming a group we do not gateway) lands on the
     * primary chain, so a leaf node behaves exactly as it did. */
    const char *group_str = json_string_value(json_object_get(payload,
                                                             "group_uuid"));

    /* Commit certificates (doc/architecture/reputation.md): no ordinary half
     * goes to the pool without a quorum of the roster in force having signed
     * exactly this score. Mirrors Python handle_committed. */
    json_t *cert = json_object_get(payload, "certificate");
    bool certified = false;
    uuid_t cert_task;
    if (json_is_object(cert) && json_object_size(cert) > 0
        && task_uuid_str != NULL && uuid_parse(task_uuid_str, cert_task) == 0)
        certified = _commit_cert_ok(proc, peer_uuid, cert_task, score,
                                    chan_borrowed, cert, group_str);
    if (!certified)
    {
        log_warn(proc->logger, "Reputation: rejecting committed from %s: %s\n",
                 nmsg->from_whom.nickname,
                 json_is_object(cert) ? "its certificate does not meet our quorum"
                                      : "it carries no commit certificate");
        json_decref(payload);
        return true;
    }
    char *cert_text = json_dumps(cert, JSON_COMPACT | JSON_SORT_KEYS);

    /* To the pool, to wait for its placement (certified implies a parsed
     * task uuid). Mirrors Python _record_committed_half. */
    (void)uuid_parse(task_uuid_str, task_uuid);
    pthread_mutex_lock(&rep_state.lock);
    tx_history_t *chain = _chain_for_group_locked(proc, group_str);
    (void)tx_history_record_half(chain, task_uuid, peer_uuid, score,
                                 chan_borrowed, cert_text);
    pthread_mutex_unlock(&rep_state.lock);
    free(cert_text);
    _note_interaction(peer_uuid);   /* idle clock; see doc/architecture/reputation.md decay */
    log_debug(proc->logger, "Reputation: Recorded committed tx from %s via %s\n",
              peer_uuid_str, tx_channel_or_default(chan_borrowed));

    json_decref(payload);
    return true;
}

/* Reconcile chain @p key with a peer's verified segment @p arr and act on
 * the result. The segment's placement certificates decide (tx_history_reconcile_placed). @p finality applies our
 * finalized checkpoint (primary chain, quorum-of-one path). Mirrors Python
 * _reconcile_into. Caller holds no lock. */
static void _record_catchup_equivocation(const process_t *proc, const char *key,
                                         json_t *arr, int f, const uuid_t *sender);
static void _load_fork_records(const char *key, const json_t *doc);

static void _reconcile_into(const process_t *proc, const char *key, json_t *arr,
                            const char *who, const uuid_t *sender, bool finality)
{
    const char *group = key[0] != '\0' ? key : NULL;
    static const int none[1] = { 0 };
    int n_cert = 0;
    bool refused = false;
    int *cert = _placement_certified_indices(proc, key, group, arr, &n_cert,
                                             &refused);
    if (refused)
    {
        log_warn(proc->logger, "Reputation: rejecting chain from %s: a "
                 "placement certificate does not meet our quorum\n", who);
        free(cert);
        return;
    }
    bool primary = key[0] == '\0';
    pthread_mutex_lock(&rep_state.lock);
    tx_history_t *hist = _chain_for_key_locked(key);
    int before = tx_history_len(hist);
    /* Never rewrite inside our finalized checkpoint (user decision, ISSUES.md
     * §2.15). Outvoted: a chain reproducing the quorum's checkpoint wins even
     * an equal-length tiebreak (§2.15, mod-2538837). */
    int final_end = finality ? _final_end_locked() : -1;
    tx_attested_t att;
    bool outvoted = finality && _outvoted_locked(&att);
    /* Peers named before and after: an adoption can drop entries as well as
     * add them, and both move scores. */
    size_t n_before = 0, n_after = 0;
    uuid_t *peers_before = primary ? _chain_peers_locked(&n_before) : NULL;
    tx_reconcile_result_t res = { TX_RECONCILE_NONE, -1, 0, 0, NULL, 0 };
    tx_history_reconcile_placed(hist, arr, final_end, outvoted ? &att : NULL,
                                cert != NULL ? cert : none,
                                n_cert, &res);
    int after = tx_history_len(hist);
    uuid_t *peers_after = primary ? _chain_peers_locked(&n_after) : NULL;
    pthread_mutex_unlock(&rep_state.lock);
    free(cert);

    if (res.status == TX_RECONCILE_ADOPTED)
        log_info(proc->logger,
                 "Reputation: adopted chain from %s at index %d: dropped "
                 "%d, added %d (ours %d -> theirs %d)\n",
                 who, res.fork, res.dropped, res.added, before, after);
    else if (res.status == TX_RECONCILE_EXTENDED)
        log_info(proc->logger, "Reputation: caught up from %s: chain %d -> %d\n",
                 who, before, after);
    else if (res.status == TX_RECONCILE_REFUSED_FINAL)
        log_warn(proc->logger,
                 "Reputation: chain from %s forks at index %d, inside our "
                 "finalized checkpoint (ends %d); keeping ours\n",
                 who, res.fork, final_end);
    else if (res.status == TX_RECONCILE_EQUIVOCATION)
    {
        log_error(proc->logger,
                  "Reputation: chain from %s holds a certified placement at "
                  "index %d that differs from ours: two quorums signed two "
                  "values there; keeping ours\n", who, res.fork);
        _record_catchup_equivocation(proc, key, arr, res.fork, sender);
    }
    else
        log_debug(proc->logger, "Reputation: chain update from %s: status %d\n",
                  who, (int)res.status);

    bool grew = res.status == TX_RECONCILE_ADOPTED
             || res.status == TX_RECONCILE_EXTENDED;
    if (grew)
    {
        for (size_t k = 0; k < n_before; k++)
            _note_interaction(peers_before[k]);
        for (size_t k = 0; k < n_after; k++)
            _note_interaction(peers_after[k]);
    }
    free(peers_before);
    free(peers_after);
    /* Placements buffered ahead of the chain may now follow it. */
    if (grew)
        _apply_ahead(proc, key, group);
    /* The reconcile already returned what it dropped to the pool. */
    if (res.status == TX_RECONCILE_ADOPTED && res.pooled > 0)
        log_info(proc->logger, "Reputation: returned %d dropped entr%s "
                 "to the pool\n", res.pooled, res.pooled == 1 ? "y" : "ies");
    /* A chain that grew from a peer means a quorum may be back: the minority
     * side of a heal arrives here EXTENDED (§2.60). */
    if (primary && grew)
        _wake_parked(proc, who);
    tx_reconcile_result_free(&res);
}

/* Free a paged reply being collected and mark its slot unused. */
static void _page_buf_clear(rep_page_buf_t *buf)
{
    for (int i = 0; i < REP_UPDATE_PAGES_MAX; i++)
    {
        if (buf->pages[i] != NULL)
            json_decref(buf->pages[i]);
    }
    memset(buf, 0, sizeof(*buf));
}

/* Send @p era (a JSON array of entries, the whole window of chain @p key) to
 * @p to as pages whose entries each serialize to at most @p budget bytes,
 * every page naming @p head so the receiver puts together one window, not
 * pieces of two. A single entry larger than the budget gets a page alone. */
static void _send_update_pages(const process_t *proc, const public_identity_t *to,
                               const char *key, const char *head,
                               json_t *era, size_t budget)
{
    size_t n = json_array_size(era);
    int starts[REP_UPDATE_PAGES_MAX + 1];
    int pages = 0;
    size_t used = 0;
    for (size_t i = 0; i < n; i++)
    {
        char *text = json_dumps(json_array_get(era, i), JSON_COMPACT);
        size_t len = text != NULL ? strlen(text) + 1 : 0;
        free(text);
        if (pages == 0 || (used > 0 && used + len > budget))
        {
            if (pages == REP_UPDATE_PAGES_MAX)
            {
                log_error(proc->logger,
                          "Reputation: chain of %zu entries needs more than %d "
                          "pages; not sent\n", n, REP_UPDATE_PAGES_MAX);
                return;
            }
            starts[pages++] = (int)i;
            used = 0;
        }
        used += len;
    }
    starts[pages] = (int)n;
    log_info(proc->logger, "Reputation: sending our chain to %s in %d pages "
             "(%zu entries)\n", to->nickname, pages, n);
    for (int p = 0; p < pages; p++)
    {
        json_t *chunk = json_array();
        for (int i = starts[p]; i < starts[p + 1]; i++)
            json_array_append(chunk, json_array_get(era, (size_t)i));
        json_t *page = json_pack("{s:i, s:i, s:s, s:o}", "page", p, "of", pages,
                                 "head", head, "chain", chunk);
        if (page != NULL && key[0] != '\0')
            json_object_set_new(page, "group", json_string(key));
        generic_msg_t update = {0};
        update.type = NET_MESSAGE;
        strncpy(update.info.net_msg.process, "reputation", PROC_NAME_LEN);
        update.info.net_msg.function = REP_PROTO_UPDATE;
        update.info.net_msg.encrypt = true;
        memcpy(&update.info.net_msg.to_whom, to, sizeof(public_identity_t));
        strncpy(update.info.net_msg.return_to, "reputation", PROC_NAME_LEN);
        if (page != NULL)
        {
            net_msg_pack_json(&update.info.net_msg, page);
            json_decref(page);
        }
        _rep_send_to_network(proc, &update);
        net_msg_free_obj(&update.info.net_msg);
    }
}

/* A `latest update` that is one page of a window (_send_update_pages): keep
 * it, and once every page of that head from that sender is in, replace
 * @p *payload with the window as an unpaged reply carries it (an array, or
 * {"group", "chain"} for a child chain) and return true. Returns true with
 * @p *payload untouched for an unpaged reply, false while pages are missing
 * or when the page is malformed (consumed either way). */
static bool _assemble_update_pages(const process_t *proc, const net_msg_t *nmsg,
                                   json_t **payload)
{
    json_t *obj = *payload;
    if (!json_is_object(obj) || json_object_get(obj, "page") == NULL)
        return true;
    json_t *jp = json_object_get(obj, "page");
    json_t *jof = json_object_get(obj, "of");
    const char *head = json_string_value(json_object_get(obj, "head"));
    const char *group = json_string_value(json_object_get(obj, "group"));
    json_t *chunk = json_object_get(obj, "chain");
    int page = json_is_integer(jp) ? (int)json_integer_value(jp) : -1;
    int of = json_is_integer(jof) ? (int)json_integer_value(jof) : 0;
    if (head == NULL || !json_is_array(chunk) || of < 1
        || of > REP_UPDATE_PAGES_MAX || page < 0 || page >= of)
    {
        log_warn(proc->logger, "Reputation: malformed chain page from %s; "
                 "dropped\n", nmsg->from_whom.nickname);
        json_decref(obj);
        *payload = NULL;
        return false;
    }
    char sender[UUID_STRING_LEN + 1];
    uuid_unparse_lower(nmsg->from_whom.uuid, sender);
    const char *key = group != NULL ? group : "";

    pthread_mutex_lock(&rep_state.lock);
    rep_page_buf_t *buf = NULL, *free_slot = NULL, *oldest = NULL;
    for (int i = 0; i < REP_PAGE_BUFS; i++)
    {
        rep_page_buf_t *b = &rep_state.page_bufs[i];
        if (!b->used)
        {
            if (free_slot == NULL)
                free_slot = b;
            continue;
        }
        if (strcmp(b->sender, sender) == 0 && strcmp(b->key, key) == 0)
            buf = b;
        if (oldest == NULL || b->seq < oldest->seq)
            oldest = b;
    }
    /* A new head or page count means the sender's window moved on: start
     * over with this one. */
    if (buf != NULL && (strcmp(buf->head, head) != 0 || buf->of != of))
        _page_buf_clear(buf);
    if (buf == NULL || !buf->used)
    {
        if (buf == NULL)
            buf = free_slot != NULL ? free_slot : oldest;
        _page_buf_clear(buf);
        buf->used = true;
        at_strlcpy(buf->sender, sender, sizeof(buf->sender));
        at_strlcpy(buf->key, key, sizeof(buf->key));
        at_strlcpy(buf->head, head, sizeof(buf->head));
        buf->of = of;
        buf->seq = ++rep_state.page_seq;
    }
    if (buf->pages[page] == NULL)
    {
        buf->pages[page] = json_incref(chunk);
        buf->got++;
    }
    int got = buf->got;
    json_t *whole = NULL;
    if (got == of)
    {
        whole = json_array();
        for (int p = 0; p < of; p++)
            json_array_extend(whole, buf->pages[p]);
        _page_buf_clear(buf);
    }
    pthread_mutex_unlock(&rep_state.lock);

    if (whole == NULL)
    {
        log_debug(proc->logger, "Reputation: chain page %d of %d from %s; "
                  "%d in\n", page + 1, of, nmsg->from_whom.nickname, got);
        json_decref(obj);
        *payload = NULL;
        return false;
    }
    log_info(proc->logger, "Reputation: all %d pages of %s's chain are in "
             "(%zu entries)\n", of, nmsg->from_whom.nickname,
             json_array_size(whole));
    if (group != NULL)
    {
        json_t *wrapped = json_pack("{s:s, s:o}", "group", group, "chain", whole);
        json_decref(obj);
        *payload = wrapped;
    }
    else
    {
        json_decref(obj);
        *payload = whole;
    }
    return *payload != NULL;
}

/****************************
 * Handler: handle_outdated (update needed)
 * Send chain slice to requesting peer.
 ****************************/

/* Frama-C: skipped — [solver-timeout] memcpy of public_identity_t triggers
 * "Hide sub-term definition" cast warning blocking valid_dest/src/separation */
/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_outdated(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Reputation: update requested by %s\n", nmsg->from_whom.nickname);

    /* A bare request (or a length) is for the primary chain; an object names
     * the chain's group, so a gateway's child chain can be caught up too. */
    char key[UUID_STRING_LEN + 1] = {0};
    json_t *req = NULL;
    if (net_msg_unpack_json(nmsg, &req) == 0 && json_is_object(req))
    {
        const char *group = json_string_value(json_object_get(req, "group"));
        if (group != NULL && group[0] != '\0')
        {
            _chain_key(proc, group, key, sizeof(key));
            if (key[0] == '\0')
            {
                json_decref(req);
                return true;            /* not a chain we keep */
            }
        }
    }
    json_decref(req);

    pthread_mutex_lock(&rep_state.lock);

    json_t *era_json = NULL;
    tx_history_t *hist = _chain_for_key_locked(key);
    int chain_len = tx_history_len(hist);
    tx_history_era_to_json(hist, 0, chain_len, &era_json);

    char head[TX_HASH_HEX_LEN + 1];
    at_strlcpy(head, hist->head_hash, sizeof(head));
    size_t budget = rep_state.update_page_bytes > 0 ? rep_state.update_page_bytes
                                                    : REP_UPDATE_PAGE_BYTES;
    pthread_mutex_unlock(&rep_state.lock);

    char *whole = era_json != NULL ? json_dumps(era_json, JSON_COMPACT) : NULL;
    bool paged = whole != NULL && strlen(whole) > budget;
    free(whole);
    if (paged)
    {
        _send_update_pages(proc, &nmsg->from_whom, key, head, era_json, budget);
        json_decref(era_json);
        return true;
    }
    if (key[0] != '\0' && era_json != NULL)
    {
        json_t *wrapped = json_pack("{s:s, s:o}", "group", key, "chain", era_json);
        era_json = wrapped;
    }

    /* Send update with the era JSON packed into the message */
    generic_msg_t update = {0};
    update.type = NET_MESSAGE;
    strncpy(update.info.net_msg.process, "reputation", PROC_NAME_LEN);
    update.info.net_msg.function = REP_PROTO_UPDATE;
    update.info.net_msg.encrypt = true;
    memcpy(&update.info.net_msg.to_whom, &nmsg->from_whom, sizeof(public_identity_t));
    strncpy(update.info.net_msg.return_to, "reputation", PROC_NAME_LEN);

    if (era_json != NULL)
    {
        net_msg_pack_json(&update.info.net_msg, era_json);
        json_decref(era_json);
    }

    log_debug(proc->logger, "Reputation: Sent update\n");
    _rep_send_to_network(proc, &update);
    net_msg_free_obj(&update.info.net_msg);
    return true;
}

/****************************
 * Handler: handle_update (latest update)
 * Collect chain slices, vote on consistency, merge.
 ****************************/

/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_update(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_info(proc->logger, "Reputation: chain update from %s\n", nmsg->from_whom.nickname);

    /* Unpack chain JSON from payload */
    json_t *chain_json = NULL;
    if (net_msg_unpack_json(nmsg, &chain_json) != 0 || chain_json == NULL)
    {
        log_error(proc->logger, "Reputation: handle_update: failed to unpack JSON\n");
        return false;
    }
    /* A paged window waits here until every page is in. */
    if (!_assemble_update_pages(proc, nmsg, &chain_json))
        return true;

    /* A child chain's update: always applied directly, as the quorum of one
     * is (the vote below is the primary chain's). */
    if (json_is_object(chain_json))
    {
        const char *group = json_string_value(json_object_get(chain_json, "group"));
        json_t *arr = json_object_get(chain_json, "chain");
        char key[UUID_STRING_LEN + 1] = {0};
        if (group != NULL)
            _chain_key(proc, group, key, sizeof(key));
        if (key[0] != '\0' && json_is_array(arr)
            && _chain_json_certified(proc, arr, key))
            _reconcile_into(proc, key, arr, nmsg->from_whom.nickname,
                            &nmsg->from_whom.uuid, false);
        json_decref(chain_json);
        return true;
    }

    /* Every certificate the segment carries must meet OUR quorum, or catch-up
     * would be a way around the round (doc/architecture/reputation.md). */
    if (!_chain_json_certified(proc, chain_json, ""))
    {
        log_warn(proc->logger,
                 "Reputation: rejecting chain from %s: a certificate does not "
                 "meet the roster in force\n", nmsg->from_whom.nickname);
        json_decref(chain_json);
        return true;
    }

    /* Key by sender UUID */
    char sender_uuid[UUID_STRING_LEN + 1];
    uuid_unparse_lower(nmsg->from_whom.uuid, sender_uuid);

    pthread_mutex_lock(&rep_state.lock);

    /* Quorum of one: apply this peer's verified segment directly. It is not
     * stored, because a stored report from another peer would then out-vote
     * the current one in the majority path below. */
    if (rep_state.num_updates <= 1)
    {
        pthread_mutex_unlock(&rep_state.lock);
        if (json_is_array(chain_json))
            _reconcile_into(proc, "", chain_json, nmsg->from_whom.nickname,
                            &nmsg->from_whom.uuid, true);
        json_decref(chain_json);
        return true;
    }

    /* Store in rep_state.updates keyed by sender UUID */
    data_t *chain_dat = object_ptr_data(chain_json, sizeof(json_t));
    map_set(&rep_state.updates, sender_uuid, chain_dat);

    size_t up_count = map_size(&rep_state.updates);
    json_t *majority = NULL;

    if (up_count >= (size_t)rep_state.num_updates)
    {
        /* Group identical updates: find majority by comparing JSON dumps */
        /* Build parallel arrays of keys and serialized strings */
        array_t *keys = map_keys(&rep_state.updates);
        size_t nkeys = array_size(keys);

        /* Allocate string representations */
        char **strs = calloc(nkeys, sizeof(char *));
        json_t **jsons = calloc(nkeys, sizeof(json_t *));
        if (strs != NULL && jsons != NULL)
        {
            for (size_t ki = 0; ki < nkeys; ki++)
            {
                data_t *kdat = NULL;
                if (array_get(keys, (int)ki, &kdat) != 0) continue;
                char *kstr = NULL;
                if (data_string_ptr(kdat, &kstr) != 0 || kstr == NULL) continue;
                data_t *vdat = NULL;
                if (map_get(&rep_state.updates, kstr, &vdat) != 0) continue;
                void *jptr = NULL;
                if (data_object_ptr(vdat, &jptr) != 0 || jptr == NULL) continue;
                jsons[ki] = (json_t *)jptr;
                strs[ki] = json_dumps(jsons[ki], JSON_COMPACT);
            }

            /* Find best candidate */
            char *best_str = NULL;
            json_t *best_json = NULL;
            int best_count = 0;

            for (size_t oi = 0; oi < nkeys; oi++)
            {
                if (strs[oi] == NULL) continue;
                int count = 0;
                for (size_t ci = 0; ci < nkeys; ci++)
                {
                    if (strs[ci] != NULL && strcmp(strs[oi], strs[ci]) == 0)
                        count++;
                }
                if (count > best_count)
                {
                    best_count = count;
                    best_str = strs[oi];
                    best_json = jsons[oi];
                }
            }

            if (best_json != NULL && best_count > (int)(up_count / 2))
            {
                majority = json_incref(best_json);
                log_debug(proc->logger, "Reputation: Updated\n");
            }
            else
            {
                log_error(proc->logger,
                          "Reputation: Closest %zu peers unable to agree on history\n",
                          up_count);
            }

            /* Free all string dumps */
            for (size_t fi = 0; fi < nkeys; fi++)
            {
                if (strs[fi] != NULL && strs[fi] != best_str)
                    free(strs[fi]);
            }
            if (best_str != NULL)
                free(best_str);
        }
        if (strs != NULL) free(strs);
        if (jsons != NULL) free(jsons);
    }

    pthread_mutex_unlock(&rep_state.lock);
    if (majority != NULL)
    {
        _reconcile_into(proc, "", majority, "the majority chain", NULL, false);
        json_decref(majority);
    }
    return true;
}

/* Python's type tag for a single Reputation. Carried for the same reason the
 * warm-start snapshot carries one (see REP_SNAPSHOT_TYPE below): a reputation
 * response is the SAME state in both runtimes, and the requestor deserialises
 * each entry by this tag. Without it every entry arrives as a bare dict that a
 * Python requestor cannot read — it reaches for `.peer_id` and raises. */
#define REP_REPUTATION_TYPE \
    "autonomous_trust.core._python.reputation.reputation.Reputation"

/****************************
 * _reputation_json — one Reputation entry, in the form both runtimes read.
 *
 * Exactly Python's Reputation serialisation: the type tag, `peer_id`, `score`
 * and NOTHING else. An extra key is not harmless — the requestor reconstructs
 * the object by keyword, so a stray field is a TypeError rather than a value it
 * ignores. In particular the requesting process does NOT belong in here; it
 * routes the reply and travels in the envelope (see _send_rep_response).
 ****************************/

/*@
  requires peer_uuid_str != \null;
*/
static json_t *_reputation_json(const char *peer_uuid_str, double score)
{
    return json_pack("{s:s, s:s, s:f}",
                     "__type__", REP_REPUTATION_TYPE,
                     "peer_id", peer_uuid_str,
                     "score", score);
}

/****************************
 * _send_rep_response — emit a rep_resp for @p body back to the requestor.
 *
 * Takes ownership of @p body.
 *
 * The envelope's `process` is the REQUESTING process, not "reputation". A
 * requestor routes an inbound message by that field, so a reply that names
 * "reputation" is delivered to the requestor's reputation process — which has no
 * rep_resp handler on the Python side — instead of to the process that asked.
 * All three reply sites got this wrong identically, which is why there is now
 * one of them. Mirrors Python's forward_reputation, which builds
 * `Message(req_proc, rep_resp, ...)`.
 *
 * `return_to` stays "reputation": that is where an answer to THIS message would
 * come back to, and it is us.
 ****************************/

/*@
  requires \valid(proc);
  requires \valid(req);
  requires body != \null;
*/
static void _send_rep_response(const process_t *proc, const net_msg_t *req,
                               const char *req_proc, json_t *body)
{
    generic_msg_t resp = {0};
    resp.type = NET_MESSAGE;
    /* An absent or empty requesting process would address the reply to nothing;
     * fall back to our own process so it is at least deliverable and visible. */
    at_strlcpy(resp.info.net_msg.process,
               (req_proc != NULL && req_proc[0] != '\0') ? req_proc : "reputation",
               PROC_NAME_LEN);
    resp.info.net_msg.function = REP_PROTO_REP_RESP;
    resp.info.net_msg.encrypt = true;
    memcpy(&resp.info.net_msg.to_whom, &req->from_whom, sizeof(public_identity_t));
    at_strlcpy(resp.info.net_msg.return_to, "reputation", PROC_NAME_LEN);
    net_msg_pack_json(&resp.info.net_msg, body);
    json_decref(body);
    _rep_send_to_network(proc, &resp);
    net_msg_free_obj(&resp.info.net_msg);
}

/****************************
 * _consensus_score_for — the consensus score for one peer.
 *
 * Factored out so the single-subject and batched request handlers compute the
 * SAME number by construction: the batch verb exists to cut message count, and
 * a second copy of this arithmetic is how it would quietly become a scoring
 * change instead. Takes rep_state.lock itself, so callers must NOT hold it.
 ****************************/

/*@
  requires peer_uuid_str != \null;
  ensures \result >= 0.0 && \result <= 1.0;
*/
static double _consensus_score_for(const char *peer_uuid_str, const uuid_t peer_uuid)
{
    double score = 0.5;
    pthread_mutex_lock(&rep_state.lock);
    /* Slash override (fast-penalty path): a finalized slash floors the score,
     * bypassing the chain/EMA. Mirrors Python _consensus_reputation's
     * top-of-function check. The floor value lives in rep_state.reputations
     * (written by _apply_slash). */
    data_t *sl = NULL;
    if (map_get(&rep_state.slashed, (map_key_t)peer_uuid_str, &sl) == 0)
    {
        double floor = 0.0;
        reputations_get(&rep_state.reputations, peer_uuid, &floor);
        score = floor;
    }
    else
    {
        score = reputation_consensus(&rep_state.history, peer_uuid,
                                     &rep_state.task_weights);
    }
    pthread_mutex_unlock(&rep_state.lock);
    return score;
}

/****************************
 * Handler: handle_consensus_rep_request (consensus reputation request)
 *
 * Replies with reputation_consensus(history, peer_uuid) — a
 * deterministic, history-only EMA score every node arrives at
 * identically given the same chain state. Backs the inspector
 * dashboard. Deliberately skips reputations_update and the rank
 * publish: that dict feeds the rep_req path's mode selection and
 * pure-reputation weighting, so overwriting it with the consensus
 * value would corrupt the local trust path for any rep_req caller.
 * Mirrors Python's handle_consensus_reputation_request.
 ****************************/

/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_consensus_rep_request(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Reputation: consensus rep request from %s\n",
              nmsg->from_whom.nickname);
    probes_counter("rep.consensus", "enter", NULL);

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger,
                  "Reputation: handle_consensus_rep_request: failed to unpack JSON\n");
        probes_counter("rep.consensus", "exception", "unpack_failed");
        return false;
    }

    json_t *j_peer_uuid = json_object_get(payload, "peer_uuid");
    json_t *j_req_proc  = json_object_get(payload, "requesting_process");
    if (!j_peer_uuid || !j_req_proc)
    {
        json_decref(payload);
        log_error(proc->logger,
                  "Reputation: handle_consensus_rep_request: missing JSON fields\n");
        return false;
    }
    const char *peer_uuid_str = json_string_value(j_peer_uuid);
    const char *req_proc_str  = json_string_value(j_req_proc);

    uuid_t peer_uuid;
    double score = 0.5;
    if (uuid_parse(peer_uuid_str, peer_uuid) == 0)
    {
        score = _consensus_score_for(peer_uuid_str, peer_uuid);
        probes_counter("rep.consensus", "queued", NULL);
    }

    json_t *resp_json = _reputation_json(peer_uuid_str, score);
    if (resp_json == NULL) {
        log_error(proc->logger, "Reputation: json_pack OOM (consensus rep_resp)\n");
        json_decref(payload);
        return true;
    }
    /* Copied out, not borrowed: req_proc_str points into `payload`, which is
     * freed before the reply goes out. */
    char req_proc[PROC_NAME_LEN] = {0};
    at_strlcpy(req_proc, req_proc_str, PROC_NAME_LEN);
    json_decref(payload);
    _send_rep_response(proc, nmsg, req_proc, resp_json);
    return true;
}

/* Upper bound on how many subjects one batched request may name. Each named
 * subject costs a chain walk, so an unbounded list would let one small message
 * ask for arbitrary work. Mirrors Python's MAX_REP_BATCH_SUBJECTS. */
#define AT_MAX_REP_BATCH_SUBJECTS 256

/****************************
 * Handler: handle_consensus_rep_batch_request
 *
 * One request naming many subjects, answered with ONE roster: a JSON array of
 * Reputation objects, which is exactly what Python's forward_reputation emits
 * for a multi-element roster and what its rep_resp handling already unpacks one
 * entry per peer.
 *
 * Why it exists: an observer-by-subject sweep (the inspector's transitive-trust
 * round) cost N(N-1) messages with the per-subject verb — 6320 requests plus
 * 6320 signed replies at N=80, each with its own chain walk. Batched, a round is
 * N requests and N replies. Scores are unchanged: every entry comes from the
 * same _consensus_score_for the single-subject verb uses.
 *
 * Our own uuid is skipped, matching Python: the sweep has no use for a
 * self-pair, and excluding it responder-side is what lets one request body
 * (hence one signature) serve every observer in a round.
 *
 * Mirrors Python's handle_consensus_reputation_batch_request.
 ****************************/

/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_consensus_rep_batch_request(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Reputation: consensus rep batch request from %s\n",
              nmsg->from_whom.nickname);
    probes_counter("rep.consensus_batch", "enter", NULL);

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger,
                  "Reputation: handle_consensus_rep_batch_request: failed to unpack JSON\n");
        probes_counter("rep.consensus_batch", "exception", "unpack_failed");
        return false;
    }

    json_t *j_uuids    = json_object_get(payload, "peer_uuids");
    json_t *j_req_proc = json_object_get(payload, "requesting_process");
    if (!json_is_array(j_uuids) || !json_is_string(j_req_proc))
    {
        json_decref(payload);
        log_error(proc->logger,
                  "Reputation: handle_consensus_rep_batch_request: expected a "
                  "peer_uuids array and requesting_process\n");
        probes_counter("rep.consensus_batch", "exception", "bad_payload");
        return false;
    }
    /* Copied out, not borrowed: the reply is sent after the payload is freed,
     * and the routing string must outlive it. */
    char req_proc[PROC_NAME_LEN] = {0};
    at_strlcpy(req_proc, json_string_value(j_req_proc), PROC_NAME_LEN);

    size_t count = json_array_size(j_uuids);
    if (count > AT_MAX_REP_BATCH_SUBJECTS)
    {
        /* Truncated rather than refused: a legitimately oversized cohort still
         * gets a partial answer, and the count is logged so the cause is
         * visible instead of presenting as a silently incomplete graph. */
        log_warn(proc->logger,
                 "Reputation: consensus batch from %s named %zu subjects; "
                 "answering the first %d only\n",
                 nmsg->from_whom.nickname, count,
                 AT_MAX_REP_BATCH_SUBJECTS);
        probes_counter("rep.consensus_batch", "truncated", NULL);
        count = AT_MAX_REP_BATCH_SUBJECTS;
    }

    uuid_t self_uuid;
    char self_key[UUID_STR_LEN] = "";
    if (_resolve_self_uuid(proc, self_uuid))
        uuid_unparse_lower(self_uuid, self_key);

    json_t *roster = json_array();
    if (roster == NULL)
    {
        log_error(proc->logger, "Reputation: json_array OOM (consensus batch)\n");
        json_decref(payload);
        return true;
    }

    for (size_t i = 0; i < count; i++)
    {
        const char *peer_uuid_str = json_string_value(json_array_get(j_uuids, i));
        if (peer_uuid_str == NULL)
            continue;
        if (self_key[0] != '\0' && strcmp(peer_uuid_str, self_key) == 0)
            continue;
        uuid_t peer_uuid;
        if (uuid_parse(peer_uuid_str, peer_uuid) != 0)
            continue;
        /* Deduplicate against what we have already scored. A linear scan is
         * right here: this runtime's reply carries one entry per requested
         * subject (no child-group roster, unlike Python's gateway path), so the
         * only source of duplicates is a repeated uuid in the request, and the
         * array is bounded by AT_MAX_REP_BATCH_SUBJECTS. */
        bool already = false;
        size_t have = json_array_size(roster);
        for (size_t k = 0; k < have; k++)
        {
            const char *seen = json_string_value(
                json_object_get(json_array_get(roster, k), "peer_id"));
            if (seen != NULL && strcmp(seen, peer_uuid_str) == 0)
            {
                already = true;
                break;
            }
        }
        if (already)
            continue;

        double score = _consensus_score_for(peer_uuid_str, peer_uuid);
        json_t *entry = _reputation_json(peer_uuid_str, score);
        if (entry == NULL)
        {
            log_error(proc->logger,
                      "Reputation: json_pack OOM (consensus batch entry)\n");
            continue;
        }
        json_array_append_new(roster, entry);
    }
    json_decref(payload);

    if (json_array_size(roster) == 0)
    {
        /* Nothing to say: an empty roster would cost a signature and a round
         * trip to convey no information. */
        probes_counter("rep.consensus_batch", "empty", NULL);
        json_decref(roster);
        return true;
    }
    probes_counter("rep.consensus_batch", "queued", NULL);

    _send_rep_response(proc, nmsg, req_proc, roster);
    return true;
}

/****************************
 * Handler: handle_rep_request (reputation request)
 * Compute reputation for a peer and respond.
 ****************************/

/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
/* Bound a score by the peer's tenure (doc/architecture/reputation.md,
 * "Tenure"): until it has been a member of this node's peer list for
 * REP_MIN_TENURE seconds it holds at most REP_TENURE_TIER, however well it has
 * answered. A sybil that answers probes honestly earns a high score in a few
 * probes (Stele red team rt-3717776: tier 4 fourteen seconds after joining);
 * this makes it wait. A peer this node has never held as a member counts as
 * new. Logged when the gate first holds a peer and when it lets go. Like the
 * standing ceiling, applied where the score is written. Caller must hold
 * rep_state.lock. Mirrors Python _apply_tenure_ceiling. */
/* Whether @p uuid_str is short of its tenure in this node's view, and its
 * age so far. Caller must hold rep_state.lock. */
static bool _tenure_young_locked(const char *uuid_str, double *age_out)
{
    double min = REP_MIN_TENURE;
    double since = -1.0;
    data_t *d = NULL;
    if (map_get(&rep_state.member_since, (map_key_t)uuid_str, &d) == 0 && d != NULL)
        (void)data_floating_pt_dbl(d, &since);
    double age = since < 0.0 ? 0.0 : (double)time(NULL) - since;
    if (age_out != NULL)
        *age_out = age;
    return min > 0.0 && (since < 0.0 || age < min);
}

/* @p score bounded by @p peer_uuid's tenure, with no logging and no record:
 * for readers of a stored score (the attest co-sign gate), which may predate
 * the hold (a snapshot restored before the first sweep). Caller must hold
 * rep_state.lock. Mirrors Python _tenure_bound. */
static double _tenure_bound_locked(const uuid_t peer_uuid, double score)
{
    char u[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer_uuid, u);
    double ceiling = _tier_ceiling(REP_TENURE_TIER);
    return _tenure_young_locked(u, NULL) && score > ceiling ? ceiling : score;
}

static double _tenure_apply_locked(const process_t *proc, const uuid_t peer_uuid,
                                   double score)
{
    char u[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer_uuid, u);
    double min = REP_MIN_TENURE;
    double age = 0.0;
    bool young = _tenure_young_locked(u, &age);
    double ceiling = _tier_ceiling(REP_TENURE_TIER);
    data_t *c = NULL;
    bool held = map_get(&rep_state.tenure_capped, (map_key_t)u, &c) == 0;
    if (young && score > ceiling)
    {
        if (!held)
        {
            log_info(proc->logger, "Reputation: tier of %s held at %d until it "
                     "has been a member %.0f s (tenure; %.0f s so far)\n",
                     u, REP_TENURE_TIER, min, age);
            map_set(&rep_state.tenure_capped, (map_key_t)u, integer_data(1));
        }
        return ceiling;
    }
    if (held)
    {
        map_remove(&rep_state.tenure_capped, (map_key_t)u);
        if (!young)
            log_info(proc->logger, "Reputation: tier of %s no longer held: a "
                     "member %.0f s (tenure %.0f s)\n", u, age, min);
    }
    return score;
}

/* Score @p peer_uuid by the ordinary algebra, bound it by any standing, and
 * STORE it. The one place a score is computed: handle_rep_request answers with
 * it and _rescore_peers publishes it, so the two cannot drift apart. Returns
 * the stored score. Caller must hold rep_state.lock. */
static double _score_peer_locked(const process_t *proc, const uuid_t peer_uuid)
{
    double score = 0.0;
    /* This node's own uuid: contrite TFT scores only the transactions between
     * it and the peer, so without it no bilateral transaction ever matches and
     * every peer reads as having no history (the prereputation prior). Left
     * null only if the identity config is missing, the same fallback. */
    uuid_t self_uuid;
    uuid_clear(self_uuid);
    (void)_resolve_self_uuid(proc, self_uuid);

    /* Hysteresis: switch to pure mode only after the previous score
     * crosses COOP_ENTER; fall back to CTFT only after it drops
     * below COOP_EXIT. Mirrors Python's self._coop_mode latch in
     * repprocess.py. A single 0.5 gate caused peers hovering near
     * 0.5 to flip scoring functions every tick (CTFT's 0.51 →
     * pure_reputation's 0.4 → CTFT's 0.51 → …). reputation_compute
     * remains a single-gate pure function (used by unit tests);
     * the hysteresis lives here, at the protocol boundary, where
     * the per-peer state is available. */
    double current_score = 0.0;
    if (reputations_get(&rep_state.reputations, peer_uuid, &current_score) != 0)
    {
        /* A peer scored for the first time has no stored score, and an
         * absent score must not choose the regime: it read as 0, held a peer
         * known only through others at its cold-start prior, and the next
         * entry about it (a finding, in Stele's cohort st-2590772) flipped it
         * to the pure mean and RAISED it. The first score's regime follows
         * what this node would assign it now (ISSUES §2.64). Mirrors Python's
         * _compute_reputation. */
        current_score = reputation_contrite_tft(&rep_state.history,
                                                &rep_state.reputations,
                                                self_uuid, peer_uuid);
    }

    char coop_key[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer_uuid, coop_key);
    int in_coop = 0;
    data_t *mode_dat = NULL;
    if (map_get(&rep_state.coop_mode, coop_key, &mode_dat) == 0 &&
        mode_dat != NULL) {
        data_integer(mode_dat, &in_coop);
    }
    bool use_pure = in_coop
        ? (current_score > COOP_EXIT)
        : (current_score > COOP_ENTER);
    map_set(&rep_state.coop_mode, coop_key,
            integer_data(use_pure ? 1 : 0));

    if (use_pure) {
        score = reputation_pure(&rep_state.history,
                                &rep_state.reputations, peer_uuid,
                                &rep_state.task_weights);
    } else {
        score = reputation_contrite_tft(&rep_state.history,
                                        &rep_state.reputations,
                                        self_uuid, peer_uuid);
    }
    /* doc/architecture/zta-integration.md: an authority's finding bounds how far this peer may
     * rise, whichever regime produced the score above. Applied where the
     * score is WRITTEN, so every consumer sees one consistent number. */
    score = _standing_apply_ceiling(peer_uuid, score);
    score = _tenure_apply_locked(proc, peer_uuid, score);
    reputations_update(&rep_state.reputations, peer_uuid, score);
    return score;
}

static bool handle_rep_request(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Reputation: rep request from %s\n", nmsg->from_whom.nickname);
    /* Mirrors Python's `_probes.counter('rep.compute', 'enter')` at
     * repprocess.py:429; the rep.compute layer correlates handle_req
     * → compute → forward across the reputation pipeline. */
    probes_counter("rep.compute", "enter", NULL);

    /* Unpack (peer_uuid, requesting_process) */
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Reputation: handle_rep_request: failed to unpack JSON\n");
        probes_counter("rep.compute", "exception", "unpack_failed");
        return false;
    }

    json_t *j_peer_uuid  = json_object_get(payload, "peer_uuid");
    json_t *j_req_proc   = json_object_get(payload, "requesting_process");

    if (!j_peer_uuid || !j_req_proc)
    {
        json_decref(payload);
        log_error(proc->logger, "Reputation: handle_rep_request: missing JSON fields\n");
        return false;
    }

    const char *peer_uuid_str = json_string_value(j_peer_uuid);
    const char *req_proc_str  = json_string_value(j_req_proc);

    /* Parse UUID and compute reputation */
    uuid_t peer_uuid;
    double score = 0.0;
    bool have_uuid = false;
    if (uuid_parse(peer_uuid_str, peer_uuid) == 0)
    {
        /* A node never scores itself: its own history holds no bilateral
         * evidence about it, and a stored self-score would feed its own tier.
         * Dropped, not answered -- _rescore_peers already skips self; this
         * closes the rep_req path. Mirrors Python _compute_reputation. */
        uuid_t self_uuid;
        if (_resolve_self_uuid(proc, self_uuid) &&
            uuid_compare(peer_uuid, self_uuid) == 0) {
            probes_counter("rep.compute", "self_skipped", NULL);
            json_decref(payload);
            return true;
        }
        have_uuid = true;
        pthread_mutex_lock(&rep_state.lock);
        score = _score_peer_locked(proc, peer_uuid);
        pthread_mutex_unlock(&rep_state.lock);
        /* Python's _compute_reputation persists after every score, so the
         * snapshot is live, not only a shutdown artifact; outside the lock
         * because _persist_reputations takes it. */
        _persist_reputations(proc);
    }

    /* Publish a tier_update IPC to identity if the score crossed a tier.
     * Mirrors Python's _publish_tier_change drain in repprocess.py.
     * Done inline here (rather than queued) because handle_rep_request
     * already holds the send context; Python uses a queue because its
     * _compute_reputation runs in a spawned thread without queue access. */
    if (have_uuid) {
        _publish_tier_change(proc, peer_uuid, score);
        _publish_reputation_change(peer_uuid, score);
        probes_counter("rep.compute", "queued", NULL);
    }

    /* Pack the response as a Reputation, the form both runtimes read. */
    json_t *resp_json = _reputation_json(peer_uuid_str, score);
    if (resp_json == NULL) {
        log_error(proc->logger, "Reputation: json_pack OOM (rep_resp)\n");
        json_decref(payload);
        return true;
    }
    /* Copied out, not borrowed: req_proc_str points into `payload`, which is
     * freed before the reply goes out. */
    char req_proc[PROC_NAME_LEN] = {0};
    at_strlcpy(req_proc, req_proc_str, PROC_NAME_LEN);
    json_decref(payload);
    _send_rep_response(proc, nmsg, req_proc, resp_json);
    return true;
}

/****************************
 * Handler: handle_rep_response (reputation response)
 ****************************/

/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_rep_response(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;
    log_debug(proc->logger, "Reputation: rep response from %s\n", nmsg->from_whom.nickname);

    /* Unpack and store in requested_reps array */
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Reputation: handle_rep_response: failed to unpack JSON\n");
        return false;
    }

    /* Store the JSON payload in requested_reps for later processing */
    data_t *resp_dat = object_ptr_data(payload, sizeof(json_t));
    pthread_mutex_lock(&rep_state.lock);
    array_append(&rep_state.requested_reps, resp_dat);
    pthread_mutex_unlock(&rep_state.lock);

    return true;
}

/****************************
 * Handler: handle_local_rep_query (local IPC reputation query)
 * Another local process (e.g. ZTA) asks for a peer's reputation score.
 * Responds via local IPC to the requesting process. Refused off the wire:
 * the reply is pushed to whichever process the payload names.
 ****************************/

/*@
  requires \valid(proc);
  requires \valid(queues);
  requires \valid(msg);
  requires proc->logger == \null || \valid(proc->logger);
*/
static bool handle_local_rep_query(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    net_msg_t *nmsg = &msg->info.net_msg;

    if (!identity_is_local_app_verb(proc, nmsg))
        return identity_refuse_remote_app_verb(proc, nmsg,
                                               REP_PROTO_LOCAL_QUERY);

    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
    {
        log_error(proc->logger, "Reputation: handle_local_rep_query: failed to unpack JSON\n");
        return false;
    }

    json_t *j_peer_uuid  = json_object_get(payload, "peer_uuid");
    json_t *j_return_proc = json_object_get(payload, "return_process");

    if (!j_peer_uuid || !j_return_proc)
    {
        json_decref(payload);
        log_error(proc->logger, "Reputation: handle_local_rep_query: missing JSON fields\n");
        return false;
    }

    const char *peer_uuid_str = json_string_value(j_peer_uuid);
    const char *return_proc   = json_string_value(j_return_proc);
    if (peer_uuid_str == NULL || return_proc == NULL)
    {
        json_decref(payload);
        log_error(proc->logger, "Reputation: handle_local_rep_query: missing JSON fields\n");
        return false;
    }

    uuid_t peer_uuid;
    double score = 0.0;
    bool found = false;
    if (uuid_parse(peer_uuid_str, peer_uuid) == 0)
    {
        pthread_mutex_lock(&rep_state.lock);
        if (reputations_contains(&rep_state.reputations, peer_uuid))
        {
            reputations_get(&rep_state.reputations, peer_uuid, &score);
            found = true;
        }
        pthread_mutex_unlock(&rep_state.lock);
    }

    /* Build response */
    json_t *resp_json = json_object();
    if (resp_json == NULL) {
        log_error(proc->logger, "Reputation: json_object OOM (local_resp)\n");
        json_decref(payload);
        return true;
    }
    json_object_set_new(resp_json, "peer_uuid", json_string(peer_uuid_str));
    json_object_set_new(resp_json, "score", json_real(score));
    json_object_set_new(resp_json, "found", json_boolean(found));

    /* return_proc lives in payload: copy it before payload is released. */
    char return_buf[PROC_NAME_LEN + 1];
    at_strlcpy(return_buf, return_proc, sizeof return_buf);
    return_proc = return_buf;
    json_decref(payload);

    generic_msg_t resp = {0};
    resp.type = NET_MESSAGE;
    at_strlcpy(resp.info.net_msg.process, return_proc,
               sizeof resp.info.net_msg.process);
    resp.info.net_msg.function = REP_PROTO_LOCAL_RESP;
    net_msg_pack_json(&resp.info.net_msg, resp_json);
    json_decref(resp_json);

    /* The asker waits on this reply (ZTA defers a vouch until it comes) and
     * does not ask again on its own, so it is kept if the queue is full
     * (ISSUES §2.14). */
    (void)at_send(proc, return_proc, &resp, "a local reputation reply",
                  return_proc, 0, NULL, NULL, 0);
    net_msg_free_obj(&resp.info.net_msg);
    return true;
}

/****************************
 * Forward transaction: start Paxos for a local score
 * Called when TRANSACTION_SCORE message arrives from negotiation.
 ****************************/

/* Frama-C: skipped — [solver-timeout] uuid_unparse + strncpy + memcpy +
 * json_object_set_new + smrt_create cascade with peer-loop too complex for SMT */
/*@
  requires \valid(proc);
  requires proc->logger == \null || \valid(proc->logger);
  requires rep_state.paxos.initialized == \true;
*/
/* OUR HALF, UNTIL IT IS IN THE CHAIN (ISSUES §2.24).
 *
 * A co-signing round can be lost on the way (a dropped proposal, acceptances
 * that never reach a certificate), and nothing else notices. Partition
 * cohort part-3490610: island B's app reaction, forwarded by both sides,
 * collided with one of AT's probe rounds for the same slot, and was never
 * heard of again.
 *
 * So the task is followed rather than the round. Every proposal of ours files
 * (or refreshes) an entry here. A commit of our half clears it, and
 * _retry_uncommitted_halves re-proposes any whose deadline passed without one.
 * Caller holds rep_state.lock. */
static void _await_commit_locked(const tx_score_t *tx, const uuid_t proposer)
{
    if (tx == NULL)
        return;
    char task_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(tx->task_uuid, task_str);
    double deadline = (double)time(NULL) + REP_COMMIT_TIMEOUT;
    data_t *dat = NULL;
    rep_awaiting_t *w = NULL;
    if (map_get(&rep_state.awaiting_commit, task_str, &dat) == 0)
        data_object_ptr(dat, (void **)&w);
    if (w != NULL) {
        /* A re-proposal (the commit sweep's, or a woken half's): same task, so
         * the attempt count carries on and only the clock restarts. A parked
         * half keeps the park's slower clock (§2.60). */
        w->deadline = w->parked_at > 0
            ? (double)time(NULL) + REP_PARK_RETRY : deadline;
        w->last_proposed = (double)time(NULL);
        return;
    }
    w = smrt_create(sizeof(rep_awaiting_t));
    if (w == NULL)
        return;
    uuid_copy(w->task_uuid, tx->task_uuid);
    uuid_copy(w->proposer, proposer);
    w->score = tx->score;
    at_strlcpy(w->capability_name, tx->capability_name,
               sizeof(w->capability_name));
    at_strlcpy(w->channel, tx->channel, sizeof(w->channel));
    w->competence = tx->competence;
    w->deadline = deadline;
    w->attempts = 0;
    w->retries = REP_COMMIT_RETRIES;
    w->parked_at = 0;
    w->last_proposed = (double)time(NULL);
    data_t *wd = object_ptr_data(w, sizeof(rep_awaiting_t));
    if (wd == NULL || map_set(&rep_state.awaiting_commit, task_str, wd) != 0)
        smrt_deref(w);
}

/* Does @p chain hold @p proposer's half of @p task_uuid (bilateral or not)? */
static bool _half_in_chain_locked(const tx_history_t *chain,
                                  const uuid_t task_uuid, const uuid_t proposer)
{
    char task_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(task_uuid, task_str);
    data_t *slot = NULL;
    if (map_get((map_t *)&chain->task_map, task_str, &slot) != 0)
        return false;
    int idx = -1;
    if (data_integer(slot, &idx) != 0 || idx < 0 || idx >= chain->chain_len)
        return false;
    const transaction_t *t = &chain->chain[idx];
    return (t->p1_set && uuid_compare(t->p1_uuid, proposer) == 0)
        || (t->p2_set && uuid_compare(t->p2_uuid, proposer) == 0);
}

/* Is @p proposer's half of @p task_uuid waiting in @p chain's pool? */
static bool _half_in_pool_locked(const tx_history_t *chain,
                                 const uuid_t task_uuid, const uuid_t proposer)
{
    const transaction_t *t = tx_history_pooled(chain, task_uuid);
    return t != NULL
        && ((t->p1_set && uuid_compare(t->p1_uuid, proposer) == 0)
            || (t->p2_set && uuid_compare(t->p2_uuid, proposer) == 0));
}

/* The primary chain, or any child chain a gateway keeps. */
static bool _own_half_recorded_locked(const uuid_t task_uuid,
                                      const uuid_t proposer)
{
    if (_half_in_chain_locked(&rep_state.history, task_uuid, proposer)
        || _half_in_pool_locked(&rep_state.history, task_uuid, proposer))
        return true;
    bool found = false;
    map_key_t ck = NULL;
    data_t *cv = NULL;
    map_entries_for_each(&rep_state.child_hist, ck, cv)
    {
        void *hp = NULL;
        if (!found && data_object_ptr(cv, &hp) == 0 && hp != NULL
            && (_half_in_chain_locked((const tx_history_t *)hp, task_uuid,
                                      proposer)
                || _half_in_pool_locked((const tx_history_t *)hp, task_uuid,
                                        proposer)))
            found = true;
    }
    map_end_for_each;
    return found;
}

/* @p peer sent us a reputation frame at @p when (§2.60). Any frame counts:
 * reach is a property of the island, not of one round. */
void reputation_note_heard(const uuid_t peer, double when)
{
    if (uuid_is_null(peer))
        return;
    char peer_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer, peer_str);
    data_t *at = integer_data((int)when);
    if (at == NULL)
        return;
    pthread_mutex_lock(&rep_state.lock);
    if (map_set(&rep_state.heard, peer_str, at) != 0)
        smrt_deref(at);
    pthread_mutex_unlock(&rep_state.lock);
}

/* How many members of the group, this node included, sent us a reputation
 * frame within REP_REACH_WINDOW_TIMEOUTS commit timeouts of @p present; the
 * group's size goes to @p members. Caller holds rep_state.lock. */
static size_t _members_reachable_locked(const process_t *proc, double present,
                                        size_t *members)
{
    double since = present - REP_REACH_WINDOW_TIMEOUTS * REP_COMMIT_TIMEOUT;
    size_t reached = 1;
    peers_read_lock(proc);
    size_t n = 0;
    for (size_t i = 0; i < proc->protocol.num_peers; i++) {
        if (!processes_peer_is_member(proc, &proc->protocol.peers[i]))
            continue;
        n++;
        char peer_str[UUID_STRING_LEN + 1];
        uuid_unparse_lower(proc->protocol.peers[i].uuid, peer_str);
        data_t *at = NULL;
        int when = 0;
        if (map_get(&rep_state.heard, peer_str, &at) == 0
            && data_integer(at, &when) == 0 && (double)when >= since)
            reached++;
    }
    peers_read_unlock(proc);
    *members = n + 1;
    return reached;
}

size_t reputation_awaiting_commit_count(void)
{
    pthread_mutex_lock(&rep_state.lock);
    size_t n = map_size(&rep_state.awaiting_commit);
    pthread_mutex_unlock(&rep_state.lock);
    return n;
}

/* How many of the halves in awaiting_commit are parked (§2.60). */
size_t reputation_parked_count(void)
{
    size_t n = 0;
    pthread_mutex_lock(&rep_state.lock);
    map_key_t key = NULL;
    data_t *value = NULL;
    map_entries_for_each(&rep_state.awaiting_commit, key, value)
    {
        rep_awaiting_t *w = NULL;
        if (data_object_ptr(value, (void **)&w) == 0 && w != NULL
            && w->parked_at > 0)
            n++;
    }
    map_end_for_each;
    pthread_mutex_unlock(&rep_state.lock);
    return n;
}

/* The chain just grew from a peer, so a quorum may be reachable again: make
 * every parked half due on the next pass (§2.60). Returns how many. Caller
 * holds rep_state.lock. */
static size_t _wake_parked_locked(void)
{
    size_t n = 0;
    map_key_t key = NULL;
    data_t *value = NULL;
    map_entries_for_each(&rep_state.awaiting_commit, key, value)
    {
        rep_awaiting_t *w = NULL;
        if (data_object_ptr(value, (void **)&w) == 0 && w != NULL
            && w->parked_at > 0) {
            /* Not before its last round has had its chance, and spread by
             * task so the island's backlog does not land in one tick. */
            double spread = (double)(((unsigned)w->task_uuid[0] << 8
                                      | w->task_uuid[1]) % 1000)
                            * REP_WAKE_SPREAD_SEC / 1000.0;
            double due = w->last_proposed + REP_COMMIT_TIMEOUT;
            double soon = (double)time(NULL) + spread;
            if (soon > due)
                due = soon;
            if (due < w->deadline)
                w->deadline = due;
            /* Unparked: an active half again, with REP_WAKE_RETRIES retries,
             * and reachability decides afresh when they run out. Left parked,
             * every chain growth after the heal re-sent the whole backlog, and
             * ben's reaction never won a round (part-2272442). */
            w->parked_at = 0;
            w->attempts = 0;
            w->retries = REP_WAKE_RETRIES;
            n++;
        }
    }
    map_end_for_each;
    return n;
}

static bool _is_probe_cap(const char *cap)
{
    return cap != NULL && strncmp(cap, REP_PROBE_CAP_PREFIX,
                                  sizeof(REP_PROBE_CAP_PREFIX) - 1) == 0;
}

/* How many probe halves of ours are in awaiting_commit (parked included), and
 * is an app half of ours pending (active, not parked)? Caller holds
 * rep_state.lock. */
static size_t _probe_load_locked(bool *app_pending)
{
    size_t probes = 0;
    bool app = false;
    map_key_t key = NULL;
    data_t *value = NULL;
    map_entries_for_each(&rep_state.awaiting_commit, key, value)
    {
        rep_awaiting_t *w = NULL;
        if (data_object_ptr(value, (void **)&w) != 0 || w == NULL)
            continue;
        if (_is_probe_cap(w->capability_name))
            probes++;
        else if (w->parked_at <= 0)
            app = true;
    }
    map_end_for_each;
    if (app_pending != NULL)
        *app_pending = app;
    return probes;
}

bool _admit_new_half(const process_t *proc, const uuid_t task_uuid,
                     const char *capability_name)
{
    if (!_is_probe_cap(capability_name))
        return true;
    char task_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(task_uuid, task_str);
    bool app_pending = false;
    pthread_mutex_lock(&rep_state.lock);
    /* A probe already followed (a resubmission) is not a new load. */
    data_t *dat = NULL;
    bool known = map_get(&rep_state.awaiting_commit, task_str, &dat) == 0;
    size_t probes = _probe_load_locked(&app_pending);
    pthread_mutex_unlock(&rep_state.lock);
    if (known)
        return true;
    double cap = REP_MAX_PROBE_HALVES;
    if (app_pending) {
        log_info(proc->logger,
                 "Reputation: dropping probe half for task %s (%s): an app "
                 "half of ours is pending\n", task_str, capability_name);
        return false;
    }
    if (cap > 0 && (double)probes >= cap) {
        log_info(proc->logger,
                 "Reputation: dropping probe half for task %s (%s): %zu probe "
                 "half(s) in flight, cap %.0f\n", task_str, capability_name,
                 probes, cap);
        return false;
    }
    return true;
}

/* _wake_parked_locked from outside the lock, said out loud when it woke any. */
static void _wake_parked(const process_t *proc, const char *source)
{
    pthread_mutex_lock(&rep_state.lock);
    size_t n = _wake_parked_locked();
    pthread_mutex_unlock(&rep_state.lock);
    if (n > 0)
        log_info(proc->logger,
                 "Reputation: chain grew from %s; re-proposing %zu parked "
                 "half(s)\n", source != NULL ? source : "a peer", n);
}

void _forward_transaction(const process_t *proc, const uuid_t task_uuid,
                          const uuid_t peer_uuid, double score,
                          const char *capability_name, const char *channel,
                          const uuid_t subject_uuid, double competence)
{
    char task_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(task_uuid, task_str);
    /* The channel is logged AND acted on (R+D.md §12.8): "score 0.30 via
     * certificate" says a proof failed where "score 0.30" alone does not, and
     * because this is our OWN evidence it also weights the EMA below.
     *
     * IT DOES NOT PROPOSE A SLASH. This comment used to claim that a hard
     * channel "proposes a slash at the end of this function"; it never has.
     * This function ends at the co-signing proposal, and
     * REP_PROTO_SLASH_PROPOSE is sent by NOTHING in production code — it is
     * declared here, registered as a handler, and originated only by
     * conformance/adapters/reputation.c and test/rep_quorum_test.c. So the
     * whole slash flow (propose -> sign -> final) is unreachable in a running
     * system today. Deciding when a node should accuse a peer is a design
     * question, deliberately left open rather than invented; until it is
     * answered, treat those three handlers as receive-only. */
    const char *chan = tx_channel_or_default(channel);
    log_info(proc->logger, "Reputation: forwarding transaction for task %s, score %.2f (cap %s, via %s)\n",
             task_str, score,
             (capability_name && capability_name[0]) ? capability_name : "-",
             chan);

    /* Mint the round's ids FIRST: the pending entry below is filed under the
     * round, so the id has to exist before the entry does. (Python mints in
     * _start_paxos and keys my_requests with the same idx, repprocess.py:991.) */
    int64_t id1, id2;
    _sync_chain_index();
    paxos_next_ids(&rep_state.paxos, &id1, &id2);
    char round_key[PAXOS_KEY_LEN];
    paxos_id_index(round_key, sizeof(round_key), id1, id2);

    pthread_mutex_lock(&rep_state.lock);

    /* Store in my_requests */
    tx_score_t *tx = smrt_create(sizeof(tx_score_t));
    if (tx != NULL)
    {
        uuid_copy(tx->task_uuid, task_uuid);
        tx->score = score;
        /* Carry the capability name so _pure_reputation weights this tx by
         * its tier (mirrors Python TransactionScore.capability_name). */
        if (capability_name != NULL)
            strncpy(tx->capability_name, capability_name, CAP_NAMELEN);
        else
            tx->capability_name[0] = '\0';
        tx->capability_name[CAP_NAMELEN] = '\0';
        /* Stage the (already normalized) channel so _propose_half can put it
         * on the REP_PROTO_TX proposal. */
        strncpy(tx->channel, chan, TX_CHANNEL_NAMELEN);
        tx->channel[TX_CHANNEL_NAMELEN] = '\0';
        /* Stage the learned multiplier too (R+D.md §12.5), so _propose_half
         * re-records the SAME weight this round was started with. */
        tx->competence = competence;
        data_t *tx_dat = object_ptr_data(tx, sizeof(tx_score_t));
        /* KEYED BY THE ROUND: _propose_half looks it up by (id1, id2). */
        map_set(&rep_state.my_requests, round_key, tx_dat);
        _await_commit_locked(tx, peer_uuid);
    }

    /* Cache the weight for this task so _pure_reputation can aggregate it
     * (mirrors Python _start_paxos → _record_task_weight). Done under the
     * same lock as the my_requests insert. */
    _record_task_weight_locked(task_str,
                               _resolve_tx_weight_local(capability_name, chan,
                                                        competence));
    _record_task_tier_locked(task_str, _resolve_tx_tier(capability_name));

    pthread_mutex_unlock(&rep_state.lock);

    /* Get identity UUID for the request */
    char identity_uuid[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer_uuid, identity_uuid);

    /* The half needs no round of its own: its place in the chain is decided
     * by placement (doc/architecture/reputation.md, "Agreeing on an order"),
     * so it goes straight to the co-signing phase. The score is filed as a
     * first grant would file it, so handle_accepted finds it. Mirrors Python
     * _start_paxos. */
    paxos_record_grant(&rep_state.paxos, id1, id2, score);
    _propose_half(proc, id1, id2, identity_uuid, score);

    /* After the round is under way, not before: a refutation is an accusation
     * about a peer, and the score that carries the evidence still belongs in
     * the chain whatever the accusation does (R+D.md §12.8). */
}

/****************************
 * Reputation process main entry
 ****************************/

/****************************
 * Slashing (fast-penalty path) — Phase 0 C twin.
 * Mirrors Python repprocess.handle_slash_propose / _sign / _final +
 * _apply_slash. A finalized slash floors the target's reputation
 * immediately, bypassing the consensus EMA. Wire payloads are plain
 * JSON objects (per-implementation shape; byte_pinning:false conformance
 * checks state equivalence, not injected-message bytes). There is no
 * self-skip, and none is needed -- handle_committed documents the same: the
 * broadcast loop excludes self, and applying an idempotent floor twice is
 * harmless.
 ****************************/

/* Advance the per-(target, slasher) high-water mark, or refuse.
 *
 * Returns true when `epoch` is strictly above every epoch already applied
 * from that slasher against that target — the only case in which a slash
 * decision is new. A second presentation of any earlier decision returns
 * false, INCLUDING a punitive slash replayed after a rehabilitation lifted
 * it, which the `slashed` set alone could not catch because a rehabilitation
 * removes the target from it.
 *
 * Epochs are assigned pre-incremented from 1, so 0 is the never-seen floor
 * and an attestation claiming epoch <= 0 is malformed; both land on the same
 * refusal. Caller holds the lock. */
static bool _slash_mark_advance_locked(const char *target_str,
                                       const char *slasher_str,
                                       int64_t epoch)
{
    char hw_key[UUID_STRING_LEN * 2 + 4];
    snprintf(hw_key, sizeof(hw_key), "%s:%s", target_str,
             (slasher_str == NULL) ? "" : slasher_str);
    data_t *mark = NULL;
    int applied = 0;
    if (map_get(&rep_state.slash_hw, (map_key_t)hw_key, &mark) == 0 && mark)
        data_integer(mark, &applied);
    if (epoch <= (int64_t)applied)
        return false;
    map_set(&rep_state.slash_hw, (map_key_t)hw_key, integer_data((int)epoch));
    return true;
}

/* Mirror the floor into the reputations store (so
 * reputation_get_peer_reputation + handle_consensus_rep_request reflect
 * it) and record the target in the slashed set. Caller holds the lock.
 * Idempotent per target, and replay-bounded per (target, slasher). */
static void _apply_slash_locked(const char *target_str,
                                const char *slasher_str,
                                const uuid_t target_uuid,
                                double floor, int64_t epoch)
{
    if (!_slash_mark_advance_locked(target_str, slasher_str, epoch))
        return;  /* replay of a decision already applied (or superseded) */
    data_t *seen = NULL;
    if (map_get(&rep_state.slashed, (map_key_t)target_str, &seen) == 0)
        return;  /* already slashed */
    reputations_update(&rep_state.reputations, target_uuid, floor);
    map_set(&rep_state.slashed, (map_key_t)target_str,
            integer_data((int)epoch));
}

/* Phase 3: gate a slash on Merkle evidence. Mirrors Python
 * ReputationProcess._verify_slash_evidence.
 *  - evidence absent/null -> true (Phase 0 trust-the-detector fallback).
 *  - evidence present -> the offending tx's inclusion proof
 *    {leaf, proof:[[sibling,is_left],...], root} must verify, AND root must
 *    equal a checkpoint this node has FINALIZED (rep_state.checkpoint_root),
 *    so the accuser cannot pick the root. Malformed/mismatched -> false. */
/* The evidence object on a slash payload, under either spelling. This
 * runtime and the conformance corpus write "evidence"; Python's live wire form
 * is a serialized SlashAttestation, whose field is "evidence_ref". */
static json_t *_slash_evidence_of(json_t *payload)
{
    json_t *ev = json_object_get(payload, "evidence");
    if (ev == NULL || json_is_null(ev))
        ev = json_object_get(payload, "evidence_ref");
    return ev;
}

static bool _verify_slash_evidence(json_t *evidence)
{
    if (evidence == NULL || json_is_null(evidence))
        return true;
    /* Kind dispatch before the Merkle branch: only an inclusion proof is
     * verifiable here, and only an inclusion proof claims to be. An evidence
     * object carrying no proof at all is a detector's own account of what it
     * saw (the behaviour governor's per-feature attribution), which is
     * evidence for a HUMAN -- running it through the Merkle branch refused it
     * on a missing key and quietly made every such slash un-cosignable. This
     * opens no hole that is not already open: a slasher wanting to dodge the
     * Merkle branch can simply send no evidence at all. */
    json_t *leaf_j = json_object_get(evidence, "leaf");
    json_t *root_j = json_object_get(evidence, "root");
    json_t *proof = json_object_get(evidence, "proof");
    if (leaf_j == NULL && root_j == NULL && proof == NULL)
        return true;
    const char *leaf = json_string_value(leaf_j);
    const char *root = json_string_value(root_j);
    if (leaf == NULL || root == NULL || !json_is_array(proof))
        return false;
    size_t n = json_array_size(proof);
    if (n > MAX_CHAIN_LEN)
        return false;
    tx_merkle_step_t steps[MAX_CHAIN_LEN];
    for (size_t i = 0; i < n; i++)
    {
        json_t *step = json_array_get(proof, i);
        if (!json_is_array(step) || json_array_size(step) < 2)
            return false;
        const char *sib = json_string_value(json_array_get(step, 0));
        if (sib == NULL)
            return false;
        strncpy(steps[i].sibling, sib, TX_HASH_HEX_LEN);
        steps[i].sibling[TX_HASH_HEX_LEN] = '\0';
        steps[i].sibling_is_left = json_is_true(json_array_get(step, 1));
    }
    /* ANY chain we have finalized counts, not only the primary one: a gateway
     * finalizes a checkpoint per child group, and a tx that offended inside a
     * child group is anchored in THAT group's root. Accepting only the primary
     * root would refuse every legitimate subtree slash while adding no
     * security — each root cleared the same quorum test (doc/architecture/gateway-reputation-tree.md). */
    pthread_mutex_lock(&rep_state.lock);
    bool root_ok = false;
    map_key_t ck_key = NULL;
    data_t *ck_val = NULL;
    map_entries_for_each(&rep_state.chain_ckpts, ck_key, ck_val)
    {
        void *sp = NULL;
        if (data_object_ptr(ck_val, &sp) != 0 || sp == NULL)
            continue;
        rep_chain_ckpt_t *slot = (rep_chain_ckpt_t *)sp;
        if (slot->set
            && strncmp(root, slot->root, TX_HASH_HEX_LEN + 1) == 0)
            root_ok = true;
    }
    map_end_for_each
    pthread_mutex_unlock(&rep_state.lock);
    if (!root_ok)
        return false;
    return tx_merkle_verify(leaf, steps, (int)n, root);
}

/****************************
 * Quorum co-signatures (slash + checkpoint)
 *
 * Mirrors Python repprocess._detached_sig / _cosigner_identity /
 * _verify_cosignature / _verified_cosigners / _quorum_met.
 *
 * Both rounds used to carry no attestation whatsoever. This side was the
 * thinner of the two: the co-sign ack reported `uuid_clear`'d bytes as its
 * signer and no signature at all, and the tally was a BARE COUNT
 * (integer_data) with no voter identity — so replaying one ack drove the count
 * past quorum and a single peer finalized alone. The `*_final` handlers then
 * applied whatever arrived, on transport authentication only. Since a slash
 * floors a peer below COMM_CUTOFF into exclusion that is sticky (recovery only
 * by explicit REASON_REHABILITATE), that was a permanent-exclusion primitive
 * available to any admitted member.
 *
 * Now: a co-signer signs the round's designation with its own key, the tally is
 * keyed by VOTER (so one voter is one vote however many acks arrive), the
 * finalizer carries the retained signatures, and every receiver re-verifies
 * them against the member keys it holds before acting. Designation bytes are
 * byte-identical to Python's SlashAttestation.designation /
 * Checkpoint.designation — the hazard to watch when editing either side.
 *
 * Signature form follows _partition_sign_hex / _partition_verify_hex in
 * id_proc.c: detached Ed25519, carried as ASCII hex.
 ****************************/

/* A pending round record, held as a small JSON string. It carries EVERY field
 * the round's designation covers, not just the floor / root the maps used to
 * hold: a co-signer and the finalizer both have to reproduce the proposer's
 * exact bytes, and a field missing here is a signature that verifies nowhere. */
#define REP_PENDING_MAX 256

static void _store_pending_locked(map_t *pending, const char *key, json_t *rec)
{
    if (rec == NULL)
        return;
    char *text = json_dumps(rec, JSON_COMPACT | JSON_SORT_KEYS);
    if (text != NULL && strlen(text) < REP_PENDING_MAX)
        map_set(pending, (map_key_t)key,
                string_data((string_t)text, strlen(text) + 1));
    free(text);
}

/* Read a pending round record back. Caller owns the returned reference. */
static json_t *_load_pending_locked(map_t *pending, const char *key)
{
    data_t *dat = NULL;
    if (map_get(pending, (map_key_t)key, &dat) != 0 || dat == NULL)
        return NULL;
    char text[REP_PENDING_MAX] = {0};
    if (data_string(dat, text, sizeof(text)) != 0)
        return NULL;
    json_error_t err;
    return json_loads(text, 0, &err);
}

/* Canonical bytes a slash co-signer signs. MUST stay byte-identical to
 * Python SlashAttestation.designation:
 *   "AT-SLASH\0" slasher "|" target "|" reason "|" %.6f floor "|" epoch
 * The float is fixed-precision because that is the one byte-pinning hazard
 * across the two languages. Returns the length, or 0 on bad input. */
static size_t _slash_designation(const char *slasher, const char *target,
                                 const char *reason, double floor,
                                 int64_t epoch, uint8_t *out, size_t cap)
{
    if (slasher == NULL || target == NULL || reason == NULL || out == NULL)
        return 0;
    static const char tag[] = "AT-SLASH";
    size_t tag_len = sizeof(tag);   /* includes the NUL separator */
    int n = snprintf((char *)out + tag_len, cap - tag_len,
                     "%s|%s|%s|%.6f|%lld", slasher, target, reason, floor,
                     (long long)epoch);
    if (n < 0 || (size_t)n >= cap - tag_len)
        return 0;
    memcpy(out, tag, tag_len);
    return tag_len + (size_t)n;
}

/* Sign `desig` with our own key, ASCII hex out (REP_SIG_HEX_LEN + 1 bytes). */
static int _cosign_hex(const process_t *proc, const uint8_t *desig,
                       size_t dlen, char *hex_out, size_t hex_cap)
{
    const identity_t *self = identity_self_identity(proc);
    if (self == NULL || desig == NULL || dlen == 0
        || hex_cap < REP_SIG_HEX_LEN + 1)
        return -1;
    unsigned char sig[crypto_sign_BYTES];
    if (crypto_sign_detached(sig, NULL, desig, dlen,
                             self->signature.private) != 0)
        return -1;
    hexlify(sig, crypto_sign_BYTES, (unsigned char *)hex_out);
    return 0;
}

/* Copy out the signing public key for `voter_str`: self first (a proposer
 * counts its own signature), then the peer roster. False when the claimed
 * voter is unknown to us — an unknown voter's signature cannot be verified, so
 * it cannot count. Copies rather than returning a pointer into peers[], which
 * is only valid under the rwlock. */
static bool _cosigner_pubkey(const process_t *proc, const char *voter_str,
                             unsigned char out[crypto_sign_PUBLICKEYBYTES])
{
    if (proc == NULL || voter_str == NULL || out == NULL)
        return false;
    const identity_t *self = identity_self_identity(proc);
    if (self != NULL)
    {
        char self_str[UUID_STRING_LEN + 1];
        uuid_unparse_lower(self->uuid, self_str);
        if (strncmp(self_str, voter_str, sizeof(self_str)) == 0)
        {
            memcpy(out, self->signature.public, crypto_sign_PUBLICKEYBYTES);
            return true;
        }
    }
    bool found = false;
    peers_read_lock(proc);
    for (size_t i = 0; i < proc->protocol.num_peers; i++)
    {
        char peer_str[UUID_STRING_LEN + 1];
        uuid_unparse_lower(proc->protocol.peers[i].uuid, peer_str);
        if (strncmp(peer_str, voter_str, sizeof(peer_str)) == 0
            && processes_peer_is_member(proc, &proc->protocol.peers[i]))
        {
            memcpy(out, proc->protocol.peers[i].signature.public,
                   crypto_sign_PUBLICKEYBYTES);
            found = true;
            break;
        }
    }
    peers_read_unlock(proc);
    return found;
}

/* True iff `sig_hex` is `voter_str`'s signature over `desig`. Any malformed /
 * unknown / bad-signature case is false: a co-signature that cannot be checked
 * must never be counted. */
static bool _verify_cosignature(const process_t *proc, const char *voter_str,
                                const uint8_t *desig, size_t dlen,
                                const char *sig_hex)
{
    if (voter_str == NULL || sig_hex == NULL || desig == NULL || dlen == 0)
        return false;
    if (strnlen(sig_hex, REP_SIG_HEX_LEN + 2) != REP_SIG_HEX_LEN)
        return false;
    unsigned char pubkey[crypto_sign_PUBLICKEYBYTES];
    if (!_cosigner_pubkey(proc, voter_str, pubkey))
        return false;
    unsigned char sig[crypto_sign_BYTES];
    if (unhexlify((const unsigned char *)sig_hex, REP_SIG_HEX_LEN, sig) != 0)
        return false;
    return crypto_sign_verify_detached(sig, desig, dlen, pubkey) == 0;
}

/* Count the DISTINCT voters in the `sigs` object whose signature over `desig`
 * verifies. JSON object keys are unique by construction, so distinctness comes
 * for free — the property Python gets from keying a dict by voter, and the one
 * the old bare count lacked. */
static size_t _verified_cosigners(const process_t *proc, json_t *sigs,
                                  const uint8_t *desig, size_t dlen)
{
    if (sigs == NULL || !json_is_object(sigs))
        return 0;
    size_t count = 0;
    const char *voter = NULL;
    json_t *val = NULL;
    json_object_foreach(sigs, voter, val)
    {
        if (_verify_cosignature(proc, voter, desig, dlen,
                                json_string_value(val)))
            count++;
    }
    return count;
}

/* ---- The logged roster (doc/architecture/reputation.md, "Who is in the
 * group") -----------------------------------------------------------------
 *
 * Once a placing chain holds a roster entry, the members of the roster in
 * force for an instance decide it, and their signatures are verified with the
 * keys the roster records -- not with the live peer list, which a join can
 * change between a decision and its learning (partition cohort
 * part-3546034). Mirrors the `roster` arguments of Python
 * _verify_cosignature / _verified_cosigners. */

/* The roster in force for instance @p k of chain @p key, as its canonical
 * member list [[uuid, key], ...] (a new reference), or NULL while the chain
 * holds none. Caller holds rep_state.lock. */
static json_t *_roster_at_locked(const char *key, int k)
{
    transaction_t r;
    tx_history_t *chain = _chain_for_key_locked(key);
    if (tx_history_roster_at(chain, k, &r) != 0)
        return NULL;
    const char *text = tx_history_roster_members(chain, r.roster_digest);
    return text != NULL ? json_loads(text, 0, NULL) : NULL;
}

static json_t *_roster_at(const char *key, int k)
{
    pthread_mutex_lock(&rep_state.lock);
    json_t *r = _roster_at_locked(key, k);
    pthread_mutex_unlock(&rep_state.lock);
    return r;
}

/* The roster in force for the next instance of @p group_uuid's chain, or
 * NULL before its genesis, when the live view decides. Mirrors Python
 * _roster_for_group. */
static json_t *_roster_for_group(const process_t *proc, const char *group_uuid)
{
    if (proc == NULL)
        return NULL;
    char key[UUID_STRING_LEN + 1];
    _chain_key(proc, group_uuid, key, sizeof(key));
    pthread_mutex_lock(&rep_state.lock);
    json_t *r = _roster_at_locked(key, _chain_for_key_locked(key)->next_index);
    pthread_mutex_unlock(&rep_state.lock);
    return r;
}

/* @p uuid's signing key (hex) in @p roster, or NULL when it is no member. */
static const char *_roster_key_of(const json_t *roster, const char *uuid)
{
    size_t i;
    json_t *m;
    json_array_foreach((json_t *)roster, i, m)
    {
        const char *u = json_string_value(json_array_get(m, 0));
        if (u != NULL && uuid != NULL && strcasecmp(u, uuid) == 0)
            return json_string_value(json_array_get(m, 1));
    }
    return NULL;
}

/* A strict majority of @p roster, as a count of signatures. */
static size_t _roster_majority(const json_t *roster)
{
    return json_array_size(roster) / 2 + 1;
}

/* _verify_cosignature against @p roster's keys and members, or against the
 * live view when @p roster is NULL. */
static bool _verify_cosignature_in(const process_t *proc, const json_t *roster,
                                   const char *voter, const uint8_t *desig,
                                   size_t dlen, const char *sig_hex)
{
    if (roster == NULL)
        return _verify_cosignature(proc, voter, desig, dlen, sig_hex);
    const char *kh = _roster_key_of(roster, voter);
    if (kh == NULL || sig_hex == NULL || desig == NULL || dlen == 0
        || strnlen(sig_hex, REP_SIG_HEX_LEN + 2) != REP_SIG_HEX_LEN
        || strlen(kh) != 2 * crypto_sign_PUBLICKEYBYTES)
        return false;
    unsigned char pk[crypto_sign_PUBLICKEYBYTES], sig[crypto_sign_BYTES];
    if (unhexlify((const unsigned char *)kh, 2 * crypto_sign_PUBLICKEYBYTES, pk) != 0
        || unhexlify((const unsigned char *)sig_hex, REP_SIG_HEX_LEN, sig) != 0)
        return false;
    return crypto_sign_verify_detached(sig, desig, dlen, pk) == 0;
}

/* _verified_cosigners against @p roster (NULL: the live view). */
static size_t _verified_cosigners_in(const process_t *proc, const json_t *roster,
                                     json_t *sigs, const uint8_t *desig, size_t dlen)
{
    if (sigs == NULL || !json_is_object(sigs))
        return 0;
    size_t count = 0;
    const char *voter = NULL;
    json_t *val = NULL;
    json_object_foreach(sigs, voter, val)
    {
        if (_verify_cosignature_in(proc, roster, voter, desig, dlen,
                                   json_string_value(val)))
            count++;
    }
    return count;
}

/* The N_min the roster in force for @p group_uuid's chain declares (RD_13.2
 * plan section 0.4), 0 for none or before a genesis. Takes rep_state.lock, so
 * the caller holds neither it nor the peers lock. */
static int _n_min_in_force(const process_t *proc, const char *group_uuid)
{
    if (proc == NULL)
        return 0;
    char key[UUID_STRING_LEN + 1];
    _chain_key(proc, group_uuid, key, sizeof(key));
    transaction_t r;
    pthread_mutex_lock(&rep_state.lock);
    tx_history_t *chain = _chain_for_key_locked(key);
    int n = tx_history_roster_at(chain, chain->next_index, &r) == 0
        ? r.roster_n_min : 0;
    pthread_mutex_unlock(&rep_state.lock);
    return n;
}

/* Does @p have reach the Byzantine bar over @p members (RD_13.2 plan section
 * 0.4)? The bar is (members + F) / 2 + @p extra signatures, F from @p n_min:
 * @p extra is 1 where the count includes the round's own author, 0 where the
 * author is the remaining vote. At F = 0 that is the strict majority every
 * site already used. Short of a declared bar, warn once per round (keyed by
 * the designation) with the bar and the declaration. Caller holds no lock.
 * Mirrors Python _bar_met. */
static bool _bar_met(const process_t *proc, const char *where,
                     const uint8_t *round, size_t round_len, size_t have,
                     size_t members, size_t extra, int n_min)
{
    int f = tx_byzantine_f(n_min);
    size_t need = (members + (size_t)f) / 2 + extra;
    if (have >= need)
        return true;
    if (f > 0 && proc != NULL)
    {
        unsigned char h[16];
        crypto_generichash(h, sizeof(h), round, round_len, NULL, 0);
        char mark[64];
        int n = snprintf(mark, sizeof(mark), "%s:", where);
        for (size_t i = 0; n > 0 && (size_t)n + 2 < sizeof(mark) && i < sizeof(h); i++)
            n += snprintf(mark + n, sizeof(mark) - (size_t)n, "%02x", h[i]);
        bool fresh = false;
        pthread_mutex_lock(&rep_state.lock);
        if (rep_state.bar_warned != NULL
            && json_object_get(rep_state.bar_warned, mark) == NULL)
        {
            if (json_object_size(rep_state.bar_warned) > 1024)
                json_object_clear(rep_state.bar_warned);
            json_object_set_new(rep_state.bar_warned, mark, json_true());
            fresh = true;
        }
        pthread_mutex_unlock(&rep_state.lock);
        if (fresh)
            log_warn(proc->logger,
                     "Reputation: %s: %zu of the %zu signature(s) needed; the group "
                     "declares N_min %d (F %d) over %zu member(s)%s\n", where, have,
                     need, n_min, f, members,
                     members >= (size_t)n_min ? ""
                     : ", fewer than N_min, so the bar may be out of reach");
    }
    return false;
}

/* _quorum_met_for with the CHECKPOINT threshold (_ckpt_quorum_for_group). */
static bool _ckpt_quorum_met_for(const process_t *proc, json_t *sigs,
                                 const uint8_t *desig, size_t dlen,
                                 const char *group_uuid)
{
    if (proc == NULL)
        return false;
    peers_read_lock(proc);
    size_t members = _ckpt_roster_for_group(proc, group_uuid) + 1;
    peers_read_unlock(proc);
    return _bar_met(proc, "checkpoint", desig, dlen,
                    _verified_cosigners(proc, sigs, desig, dlen), members, 1,
                    _n_min_in_force(proc, group_uuid));
}

/* The slash quorum, at the slasher's tally and at every receiver: a strict
 * majority of the whole group, the slasher's own signature counted, over the
 * signatures of `desig` that verify. Sized from OUR view, so the finalizer
 * cannot also choose the bar it has to clear: the logged roster in force,
 * verified with the keys it records, as commit, placement and attestation are;
 * before a genesis, the live view (the checkpoint majority).
 *
 * It used to be more than num_peers / 2, the roster without this node, which
 * let two members of four finalize a slash, and the slasher sized it from the
 * roster a gateway conflates across its groups (RD_13.2 plan section 0.4,
 * 2026-10-22). Caller holds neither rep_state.lock nor the peers lock.
 * Mirrors Python _quorum_met. */
static bool _quorum_met_for(const process_t *proc, json_t *sigs,
                            const uint8_t *desig, size_t dlen,
                            const char *group_uuid)
{
    if (proc == NULL || !json_is_object(sigs))
        return false;
    json_t *roster = _roster_for_group(proc, group_uuid);
    if (roster == NULL)
        return _ckpt_quorum_met_for(proc, sigs, desig, dlen, group_uuid);
    size_t count = 0;
    const char *voter = NULL;
    json_t *val = NULL;
    json_object_foreach(sigs, voter, val)
    {
        if (_verify_cosignature_in(proc, roster, voter, desig, dlen,
                                   json_string_value(val)))
            count++;
    }
    size_t members = json_array_size(roster);
    json_decref(roster);
    return _bar_met(proc, "slash", desig, dlen, count, members, 1,
                    _n_min_in_force(proc, group_uuid));
}

static bool _quorum_met(const process_t *proc, json_t *sigs,
                        const uint8_t *desig, size_t dlen)
{
    return _quorum_met_for(proc, sigs, desig, dlen, NULL);
}

/* Record one verified co-signature for a round. The map is keyed
 * "<round>:<voter>" so a voter re-sending its ack overwrites rather than
 * increments: one voter, one vote. */
static void _record_cosig_locked(map_t *sigs, const char *round_key,
                                 const char *voter, const char *sig_hex)
{
    /* Three uuids' worth: a checkpoint round key is already
     * "<proposer>:<epoch>:<chain>" (two uuids plus an int64), and the voter
     * appends a third. Sized for the epoch a PEER can put on the wire, not the
     * small ones real rounds use -- at 19 digits the old two-uuid buffer
     * truncated the voter out of the key, which recorded the vote under a name
     * no receiver could verify against. */
    char key[UUID_STRING_LEN * 3 + 64];
    snprintf(key, sizeof(key), "%s:%s", round_key, voter);
    map_set(sigs, (map_key_t)key,
            string_data((string_t)sig_hex, strlen(sig_hex) + 1));
}

/* Collect a round's recorded co-signatures into a fresh JSON object
 * {voter: sig_hex} for the finalizer to carry, and report how many there are.
 * Caller owns the returned reference. */
static json_t *_cosigs_json_locked(map_t *sigs, const char *round_key,
                                   size_t *count_out)
{
    json_t *out = json_object();
    size_t count = 0;
    if (out == NULL)
    {
        if (count_out) *count_out = 0;
        return NULL;
    }
    size_t prefix_len = strlen(round_key) + 1;   /* "<round>:" */
    map_key_t key = NULL;
    data_t *value = NULL;
    map_entries_for_each(sigs, key, value)
    {
        if (strncmp(key, round_key, prefix_len - 1) != 0
            || key[prefix_len - 1] != ':')
            continue;
        char sig_hex[REP_SIG_HEX_LEN + 1] = {0};
        if (data_string(value, sig_hex, sizeof(sig_hex)) != 0)
            continue;
        json_object_set_new(out, key + prefix_len, json_string(sig_hex));
        count++;
    }
    map_end_for_each;
    if (count_out) *count_out = count;
    return out;
}

/****************************
 * Verifier-attested scores (doc/architecture/reputation.md, "Verifier-attested
 * scores"). A fourth three-phase quorum, shaped like slash and checkpoint:
 *
 *   _forward_attestation : a local producer (an extension, e.g. Stele's) sends
 *                          an attested TRANSACTION_SCORE; we sign it as its
 *                          verifier and send attest propose to every peer.
 *   handle_attest_propose: a member other than the subject co-signs iff the
 *                          attestation is ADMISSIBLE in its own view. It vouches
 *                          for nothing about the finding's truth.
 *   handle_attest_sign   : the verifier tallies verified co-signatures; on a
 *                          strict majority of the non-subject members it
 *                          appends the entry and sends attest final.
 *   handle_attest_final  : every node checks the quorum itself, against its own
 *                          roster, and appends the entry.
 *
 * The subject's signature is never counted, so it cannot block the entry.
 * Wire payloads are this runtime's own JSON shapes, as for slash (state
 * equivalence is what conformance checks). Mirrors Python repprocess.py
 * forward_attestation / handle_attest_*.
 ****************************/

/* A record of one attestation: everything its designation covers. */
typedef struct {
    char   verifier[UUID_STRING_LEN + 1];
    char   subject[UUID_STRING_LEN + 1];
    char   task[UUID_STRING_LEN + 1];
    double score;
    char   channel[TX_CHANNEL_NAMELEN + 1];
    char   digest[TX_ATTEST_DIGEST_HEX_LEN + 1];
    char   scope[TX_ATTEST_DIGEST_HEX_LEN + 1];   /* "" for none */
    char   group[UUID_STRING_LEN + 1];
} rep_attest_t;

/* The shape every node checks before anything else -- two distinct parties, a
 * score in [0, 1], an attestable channel, a valid digest -- and the derived
 * task id, filled in. Normalizes the uuids to lowercase. */
static bool _attest_well_formed(rep_attest_t *a)
{
    uuid_t v, s, t;
    if (uuid_parse(a->verifier, v) != 0 || uuid_parse(a->subject, s) != 0
        || uuid_compare(v, s) == 0)
        return false;
    if (!(a->score >= 0.0 && a->score <= 1.0))
        return false;
    if (!tx_channel_attestable(a->channel) || !tx_attest_digest_valid(a->digest))
        return false;
    if (a->scope[0] != '\0' && !tx_attest_digest_valid(a->scope))
        return false;
    uuid_unparse_lower(v, a->verifier);
    uuid_unparse_lower(s, a->subject);
    tx_attest_task_uuid(v, s, a->digest, t);
    uuid_unparse_lower(t, a->task);
    return true;
}

static bool _attest_from_json(const json_t *j, rep_attest_t *a)
{
    memset(a, 0, sizeof(*a));
    if (!json_is_object(j))
        return false;
    const char *v = json_string_value(json_object_get((json_t *)j, "verifier_uuid"));
    const char *s = json_string_value(json_object_get((json_t *)j, "subject_uuid"));
    const char *c = json_string_value(json_object_get((json_t *)j, "channel"));
    const char *d = json_string_value(json_object_get((json_t *)j, "evidence_digest"));
    const char *g = json_string_value(json_object_get((json_t *)j, "group_uuid"));
    const char *sp = json_string_value(json_object_get((json_t *)j, "attest_scope"));
    json_t *sc = json_object_get((json_t *)j, "score");
    if (v == NULL || s == NULL || c == NULL || d == NULL || !json_is_number(sc))
        return false;
    if (sp != NULL)
        at_strlcpy(a->scope, sp, sizeof(a->scope));
    at_strlcpy(a->verifier, v, sizeof(a->verifier));
    at_strlcpy(a->subject, s, sizeof(a->subject));
    at_strlcpy(a->channel, c, sizeof(a->channel));
    at_strlcpy(a->digest, d, sizeof(a->digest));
    if (g != NULL)
        at_strlcpy(a->group, g, sizeof(a->group));
    a->score = json_number_value(sc);
    return _attest_well_formed(a);
}

static json_t *_attest_to_json(const rep_attest_t *a)
{
    json_t *j = json_pack("{s:s, s:s, s:f, s:s, s:s, s:s}",
                          "verifier_uuid", a->verifier, "subject_uuid", a->subject,
                          "score", a->score, "channel", a->channel,
                          "evidence_digest", a->digest, "group_uuid", a->group);
    /* Only when set, so an unscoped round's payload is unchanged. */
    if (j != NULL && a->scope[0] != '\0')
        json_object_set_new(j, "attest_scope", json_string(a->scope));
    return j;
}

/* Forget every co-signature recorded for `round_key` ("<round>:<voter>"
 * keys), once the round has carried or been abandoned. */
static void _drop_cosigs_locked(map_t *sigs, const char *round_key)
{
    if (sigs == NULL || round_key == NULL)
        return;
    size_t prefix_len = strlen(round_key);
    array_t *keys = map_keys(sigs);
    size_t n = array_size(keys);
    for (size_t i = 0; i < n; i++)
    {
        data_t *kd = NULL;
        char *k = NULL;
        if (array_get(keys, (int)i, &kd) != 0 || data_string_ptr(kd, &k) != 0
            || k == NULL)
            continue;
        if (strncmp(k, round_key, prefix_len) == 0 && k[prefix_len] == ':')
            map_remove(sigs, k);
    }
    /* keys is the map's own key index (map_keys): not ours to free */
}

/****************************
 * Commit certificates (doc/architecture/reputation.md)
 *
 * Every ordinary half needs a quorum certificate: a placed entry carries its
 * halves' certificates, and that is all an acceptor has to judge them by.
 * What one proves is the round:
 * that more than a quorum of this node's own view accepted exactly this score
 * from this scorer. It cannot prove the score TRUE -- an acceptor never sees
 * the task -- so the lie it leaves open is a scorer's about its own half,
 * which is R+D.md §14.2's to answer. Mirrors the Python twin's helpers of the
 * same names.
 ****************************/

/* Do `sigs` certify `scorer`'s half? At least _round_quorum_for_group
 * distinct members of OUR view (with the scorer, a majority) must have signed
 * its commit_designation, and the
 * scorer's own signature never counts: a proposer cannot vouch for its own
 * round. Caller must NOT hold the peers lock. */
static bool _commit_cert_ok(const process_t *proc, const uuid_t scorer,
                            const uuid_t task, double score, const char *channel,
                            json_t *sigs, const char *group_uuid)
{
    if (proc == NULL || !json_is_object(sigs) || json_object_size(sigs) == 0)
        return false;
    uint8_t desig[REP_DESIG_MAX];
    size_t dlen = commit_designation(scorer, task, score, channel, desig,
                                     sizeof(desig));
    if (dlen == 0)
        return false;
    char scorer_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(scorer, scorer_str);
    /* In a group that places its order, the roster in force decides
     * (doc/architecture/reputation.md, "Who is in the group"). */
    json_t *roster = _roster_for_group(proc, group_uuid);
    size_t count = 0;
    const char *voter = NULL;
    json_t *val = NULL;
    json_object_foreach(sigs, voter, val)
    {
        if (strcasecmp(voter, scorer_str) == 0)
            continue;
        if (_verify_cosignature_in(proc, roster, voter, desig, dlen,
                                   json_string_value(val)))
            count++;
    }
    if (roster != NULL)
    {
        /* A majority of the logged roster, the scorer the remaining vote,
         * raised by the F it declares. */
        size_t members = json_array_size(roster);
        json_decref(roster);
        return _bar_met(proc, "commit", desig, dlen, count, members, 0,
                        _n_min_in_force(proc, group_uuid));
    }
    peers_read_lock(proc);
    size_t quorum = _round_quorum_for_group(proc, group_uuid);
    peers_read_unlock(proc);
    return count >= quorum;
}

/* Catch-up's half of commit certificates: in a group that requires them,
 * every ordinary half of every entry in the segment that is new to us and
 * outside the latest quorum checkpoint carries a certificate meeting our
 * quorum. Entries the checkpoint covers (the segment reproducing its root)
 * are certified by it -- which is how a chain cut before the group required
 * certificates, or by members since gone, stays acceptable once a quorum has
 * checkpointed it. Mirrors Python _commit_certs_ok. Caller must NOT hold
 * rep_state.lock or the peers lock. */
static bool _chain_json_commit_certified(const process_t *proc, json_t *arr,
                                         const char *key)
{
    const char *group = (key != NULL && key[0] != '\0') ? key : NULL;
    if (!json_is_array(arr) || json_array_size(arr) == 0)
        return true;
    tx_history_t *seg = NULL;
    if (tx_history_create(&seg) != 0 || seg == NULL)
        return false;
    tx_reconcile_result_t res = { TX_RECONCILE_NONE, -1, 0, 0, NULL };
    tx_history_reconcile(seg, arr, -1, &res);
    tx_reconcile_status_t status = res.status;
    tx_reconcile_result_free(&res);
    if (status == TX_RECONCILE_REJECTED)
    {
        tx_history_destroy(seg);
        return true;   /* not ours to judge: the merge itself refuses it */
    }

    int cov_first = -1, cov_end = -1;
    pthread_mutex_lock(&rep_state.lock);
    if (group == NULL && rep_state.final_set && rep_state.final_count > 0)
    {
        char root[TX_HASH_HEX_LEN + 1];
        if (tx_history_range_root(seg, rep_state.final_first,
                                  rep_state.final_count, root) == 0
            && strcmp(root, rep_state.final_root) == 0)
        {
            cov_first = rep_state.final_first;
            cov_end = rep_state.final_first + rep_state.final_count;
        }
    }
    pthread_mutex_unlock(&rep_state.lock);

    bool ok = true;
    for (int i = 0; ok && i < seg->chain_len; i++)
    {
        const transaction_t *t = &seg->chain[i];
        if (t->attested || !tx_is_committed(t))
            continue;
        if (t->index >= cov_first && t->index < cov_end)
            continue;
        /* Held at the same index, hashing the same: nothing new to prove. */
        transaction_t held;
        pthread_mutex_lock(&rep_state.lock);
        bool same = tx_history_by_task(_chain_for_key_locked(key), t->task_uuid,
                                       &held) == 0
            && held.index == t->index;
        if (same)
        {
            char a[TX_HASH_HEX_LEN + 1], b[TX_HASH_HEX_LEN + 1];
            transaction_entry_hash(&held, a);
            transaction_entry_hash(t, b);
            same = strcmp(a, b) == 0;
        }
        pthread_mutex_unlock(&rep_state.lock);
        if (same)
            continue;
        const uuid_t *scorers[2] = { &t->p1_uuid, &t->p2_uuid };
        const double scores[2] = { t->p1_score, t->p2_score };
        const char *chans[2] = { t->p1_channel, t->p2_channel };
        for (int k = 0; ok && k < 2; k++)
        {
            const char *text = tx_history_commit_cert(seg, t->task_uuid, *scorers[k]);
            json_t *sigs = text != NULL ? json_loads(text, 0, NULL) : NULL;
            ok = _commit_cert_ok(proc, *scorers[k], t->task_uuid, scores[k],
                                 chans[k], sigs, group);
            json_decref(sigs);
            if (!ok)
            {
                char sstr[UUID_STRING_LEN + 1];
                uuid_unparse_lower(*scorers[k], sstr);
                log_warn(proc->logger, "Reputation: entry %d has no commit "
                         "certificate for %.8s's half meeting our quorum, and "
                         "no checkpoint covers it\n", t->index, sstr);
            }
        }
    }
    tx_history_destroy(seg);
    return ok;
}

/* Canonical bytes each co-signer signs. MUST stay byte-identical to Python
 * AttestedScore.designation:
 *   "AT-ATTEST\0" verifier "|" subject "|" task "|" %.17g score "|" channel
 *   "|" digest [ "|" scope ] [ "|" group ]
 * The scope (64 hex) and the group (a uuid) each appear only when set, and
 * cannot be mistaken for each other. An unscoped designation is unchanged.
 * Excludes index and prev_hash, which differ per node until reconcile. */
static size_t _attest_designation(const rep_attest_t *a, uint8_t *out, size_t cap)
{
    static const char tag[] = "AT-ATTEST";
    size_t tag_len = sizeof(tag);   /* includes the NUL separator */
    if (a == NULL || out == NULL || cap <= tag_len)
        return 0;
    int n = snprintf((char *)out + tag_len, cap - tag_len, "%s|%s|%s|%.17g|%s|%s",
                     a->verifier, a->subject, a->task, a->score, a->channel,
                     a->digest);
    if (n < 0 || (size_t)n >= cap - tag_len)
        return 0;
    if (a->scope[0] != '\0')
    {
        int m = snprintf((char *)out + tag_len + n, cap - tag_len - (size_t)n,
                         "|%s", a->scope);
        if (m < 0 || (size_t)m >= cap - tag_len - (size_t)n)
            return 0;
        n += m;
    }
    if (a->group[0] != '\0')
    {
        int m = snprintf((char *)out + tag_len + n, cap - tag_len - (size_t)n,
                         "|%s", a->group);
        if (m < 0 || (size_t)m >= cap - tag_len - (size_t)n)
            return 0;
        n += m;
    }
    memcpy(out, tag, tag_len);
    return tag_len + (size_t)n;
}

/* Self, or a peer on our roster (processes_peer_is_member). */
static bool _is_member(const process_t *proc, const char *uuid_str)
{
    if (proc == NULL || uuid_str == NULL)
        return false;
    const identity_t *self = identity_self_identity(proc);
    if (self != NULL)
    {
        char me[UUID_STRING_LEN + 1];
        uuid_unparse_lower(self->uuid, me);
        if (strcmp(me, uuid_str) == 0)
            return true;
    }
    bool found = false;
    peers_read_lock(proc);
    for (size_t i = 0; i < proc->protocol.num_peers && !found; i++)
    {
        char p[UUID_STRING_LEN + 1];
        uuid_unparse_lower(proc->protocol.peers[i].uuid, p);
        found = strcmp(p, uuid_str) == 0
            && processes_peer_is_member(proc, &proc->protocol.peers[i]);
    }
    peers_read_unlock(proc);
    return found;
}

static bool _is_self(const process_t *proc, const char *uuid_str)
{
    const identity_t *self = identity_self_identity(proc);
    if (self == NULL || uuid_str == NULL)
        return false;
    char me[UUID_STRING_LEN + 1];
    uuid_unparse_lower(self->uuid, me);
    return strcmp(me, uuid_str) == 0;
}

/****************************
 * Conflicted co-signers (ISSUES §2.54, doc/architecture/reputation.md,
 * "Teammates do not witness for each other").
 *
 * An application that knows which nodes act for one team (Stele, from a team
 * roster whose every member consented with its own key) writes them to
 * etc/at/attest_conflicts.cfg.json as {"teams": [[uuid, ...], ...]}. Two nodes
 * in one team are CONFLICTED. A conflicted node does not co-sign an attestation
 * about its teammate, does not verify one about it, and does not count toward
 * its quorum, which is a strict majority of the members other than the subject
 * AND its teammates, and never fewer than two signatures once any teammate is
 * left out. Without the file nothing changes.
 *
 * The file is the application's, re-read when it changes; nothing in it is
 * verified here, as nothing in package_hashes.cfg.json is. Mirrors Python
 * repprocess._attest_conflicts / _conflicted.
 ****************************/
#define REP_CONFLICTS_FILE "attest_conflicts.cfg.json"

static pthread_mutex_t _conflicts_lock = PTHREAD_MUTEX_INITIALIZER;
static json_t *_conflicts_teams = NULL;       /* owned; NULL = none */
static json_t *_conflicts_override = NULL;    /* owned; tests and adapters */
static bool _conflicts_loaded = false;
static time_t _conflicts_mtime = 0;
static off_t _conflicts_size = -1;

/* {"teams": [[uuid, ...], ...]} with every uuid a string, or NULL. */
static json_t *_conflicts_parse(json_t *doc)
{
    json_t *teams = json_is_object(doc) ? json_object_get(doc, "teams") : NULL;
    if (!json_is_array(teams))
        return NULL;
    size_t i, j;
    json_t *team, *u;
    json_array_foreach(teams, i, team)
    {
        if (!json_is_array(team))
            return NULL;
        json_array_foreach(team, j, u)
            if (!json_is_string(u))
                return NULL;
    }
    return json_incref(teams);
}

/* Re-read the file when it changed. Caller holds _conflicts_lock. */
static void _conflicts_refresh_locked(void)
{
    if (_conflicts_override != NULL)
        return;
    char cfg_dir[CFG_PATH_LEN + 1] = {0};
    if (get_cfg_dir(cfg_dir, sizeof(cfg_dir)) < 0)
        return;
    char path[CFG_PATH_LEN + 64];
    snprintf(path, sizeof(path), "%s/%s", cfg_dir, REP_CONFLICTS_FILE);
    struct stat st;
    if (stat(path, &st) != 0)
    {
        json_decref(_conflicts_teams);
        _conflicts_teams = NULL;
        _conflicts_loaded = true;
        _conflicts_size = -1;
        return;
    }
    if (_conflicts_loaded && st.st_mtime == _conflicts_mtime
        && st.st_size == _conflicts_size)
        return;
    json_t *doc = json_load_file(path, 0, NULL);
    json_decref(_conflicts_teams);
    _conflicts_teams = _conflicts_parse(doc);
    json_decref(doc);
    _conflicts_loaded = true;
    _conflicts_mtime = st.st_mtime;
    _conflicts_size = st.st_size;
}

static json_t *_conflicts_current_locked(void)
{
    _conflicts_refresh_locked();
    return _conflicts_override != NULL ? _conflicts_override : _conflicts_teams;
}

int reputation_set_attest_conflicts(const char *json_text)
{
    json_t *teams = NULL;
    if (json_text != NULL)
    {
        json_t *doc = json_loads(json_text, 0, NULL);
        teams = _conflicts_parse(doc);
        json_decref(doc);
        if (teams == NULL)
            return -1;
    }
    pthread_mutex_lock(&_conflicts_lock);
    json_decref(_conflicts_override);
    _conflicts_override = teams;
    _conflicts_loaded = false;
    pthread_mutex_unlock(&_conflicts_lock);
    return 0;
}

static int _cmp_cstr(const void *x, const void *y)
{
    return strcmp(*(const char *const *)x, *(const char *const *)y);
}

/* Sort a JSON array of strings in place. */
static void _json_sort_strings(json_t *arr)
{
    size_t n = json_array_size(arr);
    if (n < 2)
        return;
    json_t *copy = json_deep_copy(arr);
    const char **v = calloc(n, sizeof(*v));
    if (copy == NULL || v == NULL)
    {
        free(v);
        json_decref(copy);
        return;
    }
    for (size_t i = 0; i < n; i++)
        v[i] = json_string_value(json_array_get(copy, i));
    qsort(v, n, sizeof(*v), _cmp_cstr);
    json_array_clear(arr);
    for (size_t i = 0; i < n; i++)
        json_array_append_new(arr, json_string(v[i]));
    free(v);
    json_decref(copy);
}

static bool _team_has(json_t *team, const char *uuid_str)
{
    size_t k;
    json_t *u;
    json_array_foreach(team, k, u)
        if (strcmp(json_string_value(u), uuid_str) == 0)
            return true;
    return false;
}

/* Are @p a and @p b two different nodes of one team? */
static bool _conflicted(const char *a, const char *b)
{
    if (a == NULL || b == NULL || strcmp(a, b) == 0)
        return false;
    bool hit = false;
    pthread_mutex_lock(&_conflicts_lock);
    json_t *teams = _conflicts_current_locked();
    size_t i;
    json_t *team;
    json_array_foreach(teams, i, team)
        if (_team_has(team, a) && _team_has(team, b))
        {
            hit = true;
            break;
        }
    pthread_mutex_unlock(&_conflicts_lock);
    return hit;
}

bool reputation_attest_conflicted(const char *a, const char *b)
{
    return _conflicted(a, b);
}

/* The members of our roster conflicted with @p subject, counted, and appended
 * to @p out (uuid strings, sorted) when it is not NULL. Caller must NOT hold
 * the peers lock. */
static size_t _conflicted_members(const process_t *proc, const char *subject,
                                  json_t *out)
{
    json_t *mates = json_array();
    pthread_mutex_lock(&_conflicts_lock);
    json_t *teams = _conflicts_current_locked();
    size_t i, k;
    json_t *team, *u;
    json_array_foreach(teams, i, team)
    {
        if (!_team_has(team, subject))
            continue;
        json_array_foreach(team, k, u)
        {
            const char *m = json_string_value(u);
            if (strcmp(m, subject) != 0 && !_team_has(mates, m))
                json_array_append_new(mates, json_string(m));
        }
    }
    pthread_mutex_unlock(&_conflicts_lock);
    size_t n = 0;
    json_array_foreach(mates, k, u)
    {
        if (!_is_member(proc, json_string_value(u)))
            continue;
        n++;
        if (out != NULL)
            json_array_append(out, u);
    }
    json_decref(mates);
    if (out != NULL)
        _json_sort_strings(out);
    return n;
}

/* The verifier's own signature plus a strict majority of the members other
 * than the subject, sized from OUR roster and counting only signatures that
 * verify. The subject's is never counted. Caller must NOT hold the peers lock. */
static bool _attest_quorum_met(const process_t *proc, const rep_attest_t *a,
                               json_t *sigs)
{
    if (!json_is_object(sigs))
        return false;
    uint8_t desig[REP_DESIG_MAX];
    size_t dlen = _attest_designation(a, desig, sizeof(desig));
    if (dlen == 0)
        return false;
    /* In a group that places its order, the roster in force decides
     * (doc/architecture/reputation.md, "Who is in the group"). */
    json_t *roster = _roster_for_group(proc, a->group[0] != '\0' ? a->group : NULL);
    size_t count = 0;
    bool verifier_signed = false;
    const char *voter = NULL;
    json_t *val = NULL;
    json_object_foreach(sigs, voter, val)
    {
        /* Neither the subject nor its teammates witness for it (§2.54). */
        if (strcmp(voter, a->subject) == 0 || _conflicted(voter, a->subject))
            continue;
        if (!_verify_cosignature_in(proc, roster, voter, desig, dlen,
                                    json_string_value(val)))
            continue;
        count++;
        if (strcmp(voter, a->verifier) == 0)
            verifier_signed = true;
    }
    if (!verifier_signed)
    {
        json_decref(roster);
        return false;
    }
    size_t members, mates, others;
    if (roster != NULL)
    {
        members = json_array_size(roster);
        mates = 0;
        size_t ri;
        json_t *rm;
        json_array_foreach(roster, ri, rm)
        {
            const char *u = json_string_value(json_array_get(rm, 0));
            if (u != NULL && strcmp(u, a->subject) != 0 && _conflicted(u, a->subject))
                mates++;
        }
        others = members - (_roster_key_of(roster, a->subject) != NULL ? 1 : 0);
        json_decref(roster);
        others = others > mates ? others - mates : 0;
        if (mates > 0 && count < 2)
            return false;
        return _bar_met(proc, "attestation", desig, dlen, count, others, 1,
                        _n_min_in_force(proc, a->group[0] != '\0' ? a->group : NULL));
    }
    peers_read_lock(proc);
    members = _member_count(proc) + 1;
    peers_read_unlock(proc);
    mates = _conflicted_members(proc, a->subject, NULL);
    others = members - (_is_member(proc, a->subject) ? 1 : 0);
    others = others > mates ? others - mates : 0;
    if (mates > 0 && count < 2)
        return false;   /* the outsiders left must be at least two */
    return count > others / 2;
}

/* Does @p chain hold an attested entry by @p verifier about @p subject? The
 * rate cap, counted from the chain itself so every node reaches the same
 * answer. Unscoped: one per (verifier, subject) pair in the resident window.
 * Scoped: one per (verifier, subject, channel, scope), so an application can
 * attest again about something new -- a fresh scan of a fixed commit -- while
 * a repeat about the same thing is still refused. Caller holds rep_state.lock. */
static bool _attest_resident_locked(const tx_history_t *chain,
                                    const rep_attest_t *a)
{
    uuid_t v, s;
    if (uuid_parse(a->verifier, v) != 0 || uuid_parse(a->subject, s) != 0)
        return false;
    for (int i = 0; i < chain->chain_len; i++)
    {
        const transaction_t *t = &chain->chain[i];
        if (!t->attested || uuid_compare(t->p1_uuid, v) != 0
            || uuid_compare(t->subject_uuid, s) != 0)
            continue;
        if (a->scope[0] == '\0')
            return true;
        if (strcmp(t->p1_channel, a->channel) == 0
            && strcmp(t->attest_scope, a->scope) == 0)
            return true;
    }
    return false;
}

/* Has @p chain ever held @p task (resident or tombstoned)? Caller holds the lock. */
static bool _task_ever_held_locked(tx_history_t *chain, const char *task)
{
    data_t *d = NULL;
    return map_get(&chain->task_map, (map_key_t)task, &d) == 0
        || map_get(&chain->evicted_set, (map_key_t)task, &d) == 0;
}

/* True when this node will vouch the attestation is admissible; otherwise
 * false with the reason in @p why. Everything is checked in THIS node's own
 * view; nothing is a judgement of the finding. */
static bool _attest_admissible(const process_t *proc, const rep_attest_t *a,
                               char *why, size_t why_cap)
{
    if (!_is_member(proc, a->verifier))
    {
        snprintf(why, why_cap, "verifier not a member");
        return false;
    }
    if (!_is_member(proc, a->subject))
    {
        snprintf(why, why_cap, "subject not a member");
        return false;
    }
    /* A teammate's finding about its own team is the team speaking about
     * itself, which is what an attestation exists to get past (§2.54). */
    if (_conflicted(a->verifier, a->subject))
    {
        snprintf(why, why_cap, "verifier is a teammate of the subject");
        return false;
    }
    /* Eligibility is the verifier's EFFECTIVE tier in this node's view: the
     * score bounded by any standing ceiling, and tier 0 once the verifier is
     * excluded. Replication needs more than the other channels, because it is
     * what lets a second voice confirm a finding, and a sybil spun up by the
     * subject must not be that voice. AT_ATTEST_MIN_REP, the older raw-score
     * knob, still sets the floor for the other channels when it is given
     * (cohorts lower it on purpose); it never relaxes replication. */
    bool replication = strcmp(a->channel, TX_CHANNEL_REPLICATION) == 0;
    int min_tier = replication
        ? (int)reputation_env_double("AT_ATTEST_REPLICATION_TIER", 3)
        : (int)reputation_env_double("AT_ATTEST_MIN_TIER", 1);
    double min_rep = 0.0;
    if (!replication && getenv("AT_ATTEST_MIN_REP") != NULL)
    {
        min_rep = reputation_env_double("AT_ATTEST_MIN_REP", 0.5);
        min_tier = 0;
    }
    uuid_t vu;
    uuid_parse(a->verifier, vu);
    bool ok = true;
    pthread_mutex_lock(&rep_state.lock);
    data_t *d = NULL;
    double rep = PREREP_NEUTRAL;
    reputations_get(&rep_state.reputations, vu, &rep);
    double ceiling = _standing_ceiling_of(vu);
    if (ceiling >= 0.0 && rep > ceiling)
        rep = ceiling;
    /* ...and by its tenure, in case the stored score predates the hold. */
    rep = _tenure_bound_locked(vu, rep);
    bool excluded = map_get(&rep_state.excluded, (map_key_t)a->verifier, &d) == 0;
    int tier = excluded ? 0 : _trust_tier(rep);
    tx_history_t *chain = _chain_for_key_locked(a->group);
    if (map_get(&rep_state.slashed, (map_key_t)a->verifier, &d) == 0)
    {
        snprintf(why, why_cap, "verifier slashed");
        ok = false;
    }
    else if (excluded)
    {
        snprintf(why, why_cap, "verifier excluded");
        ok = false;
    }
    else if (tier < min_tier || rep < min_rep)
    {
        snprintf(why, why_cap, "verifier tier %d (standing %.2f) below %d for %s",
                 tier, rep, min_tier, a->channel);
        ok = false;
    }
    else if (_task_ever_held_locked(chain, a->task))
    {
        snprintf(why, why_cap, "already held");
        ok = false;
    }
    else if (_attest_resident_locked(chain, a))
    {
        snprintf(why, why_cap, a->scope[0] != '\0'
                 ? "rate cap: this verifier already attested this subject in this scope"
                 : "rate cap: this verifier already attested this subject");
        ok = false;
    }
    pthread_mutex_unlock(&rep_state.lock);
    return ok;
}

/* Put a certified attestation in its chain's pool. It waits there for its
 * placement, which logs it and brings a checkpoint forward (_apply_placement).
 * Returns true when it was new. Mirrors Python _commit_attestation. */
static bool _commit_attestation(const process_t *proc, const rep_attest_t *a,
                                json_t *sigs)
{
    transaction_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.attested = true;
    tx.p1_set = true;
    uuid_parse(a->verifier, tx.p1_uuid);
    uuid_parse(a->subject, tx.subject_uuid);
    uuid_parse(a->task, tx.task_uuid);
    tx.p1_score = a->score;
    at_strlcpy(tx.p1_channel, a->channel, sizeof(tx.p1_channel));
    at_strlcpy(tx.evidence_digest, a->digest, sizeof(tx.evidence_digest));
    at_strlcpy(tx.attest_scope, a->scope, sizeof(tx.attest_scope));
    tx.index = -1;
    char *cert = json_dumps(sigs, JSON_COMPACT | JSON_SORT_KEYS);
    (void)proc;
    pthread_mutex_lock(&rep_state.lock);
    int rc = tx_history_pool_attested(_chain_for_key_locked(a->group), &tx, cert);
    pthread_mutex_unlock(&rep_state.lock);
    free(cert);
    return rc == 0;
}

/* (Re)start the re-propose clock for our round @p task. A full table leaves
 * the round to its one fan-out, as before. Caller holds rep_state.lock. */
static void _attest_retry_arm_locked(const char *task, double due)
{
    rep_attest_retry_t *slot = NULL;
    for (int i = 0; i < REP_ATTEST_RETRY_MAX; i++) {
        rep_attest_retry_t *r = &rep_state.attest_retries[i];
        if (r->used && strcmp(r->task, task) == 0) { slot = r; break; }
        if (!r->used && slot == NULL)
            slot = r;
    }
    if (slot == NULL)
        return;
    memset(slot, 0, sizeof(*slot));
    slot->used = true;
    at_strlcpy(slot->task, task, sizeof(slot->task));
    slot->due = due;
}

/* Forget the clock for @p task. Caller holds rep_state.lock. */
static void _attest_retry_clear_locked(const char *task)
{
    for (int i = 0; i < REP_ATTEST_RETRY_MAX; i++)
        if (rep_state.attest_retries[i].used
            && strcmp(rep_state.attest_retries[i].task, task) == 0)
            memset(&rep_state.attest_retries[i], 0, sizeof(rep_attest_retry_t));
}

/* Send @p payload as @p function to one peer (@p to) or, when NULL, to every
 * peer on our roster, as the slash finalizer is sent. */
static void _attest_send(const process_t *proc, char *function,
                         const public_identity_t *to, json_t *payload)
{
    generic_msg_t out = {0};
    out.type = NET_MESSAGE;
    strncpy(out.info.net_msg.process, "reputation", PROC_NAME_LEN);
    out.info.net_msg.function = function;
    out.info.net_msg.encrypt = true;
    strncpy(out.info.net_msg.return_to, "reputation", PROC_NAME_LEN);
    net_msg_pack_json(&out.info.net_msg, payload);
    if (to != NULL)
    {
        memcpy(&out.info.net_msg.to_whom, to, sizeof(public_identity_t));
        _rep_send_to_network(proc, &out);
    }
    else
    {
        peers_read_lock(proc);
        size_t n = proc->protocol.num_peers;
        public_identity_t *roster = calloc(n > 0 ? n : 1, sizeof(public_identity_t));
        if (roster != NULL)
            memcpy(roster, proc->protocol.peers, n * sizeof(public_identity_t));
        peers_read_unlock(proc);
        for (size_t i = 0; roster != NULL && i < n; i++)
        {
            generic_msg_t per = out;
            memcpy(&per.info.net_msg.to_whom, &roster[i], sizeof(public_identity_t));
            _rep_send_to_network(proc, &per);
        }
        free(roster);
    }
    net_msg_free_obj(&out.info.net_msg);
}

/* A local producer's attested score: sign it as its verifier and ask the group
 * to co-sign. Nothing is appended until a quorum certifies it. */
void _forward_attestation(const process_t *proc, const tx_score_msg_t *ts,
                                 const uuid_t self_uuid)
{
    rep_attest_t a;
    memset(&a, 0, sizeof(a));
    uuid_unparse_lower(self_uuid, a.verifier);
    uuid_unparse_lower(ts->peer_uuid, a.subject);
    a.score = ts->score;
    at_strlcpy(a.channel, ts->channel, sizeof(a.channel));
    at_strlcpy(a.digest, ts->evidence_digest, sizeof(a.digest));
    at_strlcpy(a.scope, ts->attest_scope, sizeof(a.scope));
    if (!_attest_well_formed(&a))
    {
        log_warn(proc->logger, "Reputation: attestation NOT proposed: malformed "
                 "(subject %.8s, channel '%s')\n", a.subject, a.channel);
        return;
    }
    if (!_is_member(proc, a.subject))
    {
        log_warn(proc->logger, "Reputation: attestation NOT proposed: subject "
                 "%.8s is not a member\n", a.subject);
        return;
    }
    pthread_mutex_lock(&rep_state.lock);
    bool capped = _attest_resident_locked(_chain_for_key_locked(a.group), &a);
    pthread_mutex_unlock(&rep_state.lock);
    if (capped)
    {
        log_warn(proc->logger, "Reputation: attestation NOT proposed: %.8s already "
                 "attested in the window\n", a.subject);
        return;
    }
    uint8_t desig[REP_DESIG_MAX];
    size_t dlen = _attest_designation(&a, desig, sizeof(desig));
    char sig_hex[REP_SIG_HEX_LEN + 1] = {0};
    if (dlen == 0 || _cosign_hex(proc, desig, dlen, sig_hex, sizeof(sig_hex)) != 0)
    {
        log_error(proc->logger, "Reputation: cannot sign attestation; not proposed\n");
        return;
    }
    json_t *rec = _attest_to_json(&a);
    char *text = rec != NULL ? json_dumps(rec, JSON_COMPACT | JSON_SORT_KEYS) : NULL;
    pthread_mutex_lock(&rep_state.lock);
    if (text != NULL)
        map_set(&rep_state.attest_pending, (map_key_t)a.task,
                string_data(text, strlen(text) + 1));
    _record_cosig_locked(&rep_state.attest_sigs, a.task, a.verifier, sig_hex);
    if (text != NULL)
        _attest_retry_arm_locked(a.task, (double)time(NULL) + REP_ATTEST_RETRY);
    pthread_mutex_unlock(&rep_state.lock);
    free(text);
    if (rec != NULL)
        _attest_send(proc, REP_PROTO_ATTEST_PROPOSE, NULL, rec);
    json_decref(rec);
    log_info(proc->logger, "Reputation: proposed attested score: subject=%.8s "
             "score=%.2f\n", a.subject, a.score);
}

/* Our attestation rounds still short of a quorum: send the propose again once
 * REP_ATTEST_RETRY has passed, up to REP_ATTEST_RETRIES times, then abandon the
 * round (ISSUES §2.40). A round whose entry is already in the chain (a final
 * from elsewhere certified it) is simply forgotten. Collect under the lock,
 * send outside it, as _retry_uncommitted_halves does. Returns the number of
 * proposes sent this pass. */
size_t _retry_pending_attestations(const process_t *proc, double present)
{
    char again[REP_ATTEST_RETRY_MAX][1024];
    int attempt_of[REP_ATTEST_RETRY_MAX];
    size_t n_again = 0;
    pthread_mutex_lock(&rep_state.lock);
    for (int i = 0; i < REP_ATTEST_RETRY_MAX; i++) {
        rep_attest_retry_t *r = &rep_state.attest_retries[i];
        if (!r->used)
            continue;
        char rec_text[1024] = {0};
        data_t *d = NULL;
        if (map_get(&rep_state.attest_pending, (map_key_t)r->task, &d) != 0
            || d == NULL || data_string(d, rec_text, sizeof(rec_text)) != 0) {
            memset(r, 0, sizeof(*r));      /* finalized or reset meanwhile */
            continue;
        }
        json_t *rec = json_loads(rec_text, 0, NULL);
        rep_attest_t a;
        bool ok = _attest_from_json(rec, &a);
        json_decref(rec);
        uuid_t task_uuid;
        transaction_t held;
        /* Certified elsewhere: in the chain, or in the pool waiting to be
         * placed. Mirrors Python _retry_pending_attestations. */
        tx_history_t *chain = _chain_for_key_locked(a.group);
        bool committed = ok && uuid_parse(a.task, task_uuid) == 0
            && (tx_history_by_task(chain, task_uuid, &held) == 0
                || tx_history_pooled(chain, task_uuid) != NULL);
        if (!ok || committed) {
            map_remove(&rep_state.attest_pending, r->task);
            _drop_cosigs_locked(&rep_state.attest_sigs, r->task);
            memset(r, 0, sizeof(*r));
            continue;
        }
        if (present < r->due)
            continue;
        if (r->attempts >= REP_ATTEST_RETRIES) {
            log_warn(proc->logger, "Reputation: attested score about %.8s never "
                     "reached a quorum after %d re-proposal(s); abandoning it\n",
                     a.subject, r->attempts);
            map_remove(&rep_state.attest_pending, r->task);
            _drop_cosigs_locked(&rep_state.attest_sigs, r->task);
            memset(r, 0, sizeof(*r));
            continue;
        }
        r->attempts++;
        r->due = present + REP_ATTEST_RETRY;
        at_strlcpy(again[n_again], rec_text, sizeof(again[n_again]));
        attempt_of[n_again++] = r->attempts;
    }
    pthread_mutex_unlock(&rep_state.lock);

    for (size_t i = 0; i < n_again; i++) {
        json_t *rec = json_loads(again[i], 0, NULL);
        if (rec == NULL)
            continue;
        const char *subj = json_string_value(json_object_get(rec, "subject_uuid"));
        log_info(proc->logger, "Reputation: attested score about %.8s has no "
                 "quorum yet; re-proposing it (attempt %d of %d)\n",
                 subj != NULL ? subj : "?", attempt_of[i], REP_ATTEST_RETRIES);
        _attest_send(proc, REP_PROTO_ATTEST_PROPOSE, NULL, rec);
        json_decref(rec);
    }
    return n_again;
}

size_t reputation_attest_pending_count(void)
{
    _ensure_init();
    pthread_mutex_lock(&rep_state.lock);
    size_t n = 0;
    for (int i = 0; i < REP_ATTEST_RETRY_MAX; i++)
        if (rep_state.attest_retries[i].used)
            n++;
    pthread_mutex_unlock(&rep_state.lock);
    return n;
}

size_t reputation_attest_cosig_count(void)
{
    _ensure_init();
    pthread_mutex_lock(&rep_state.lock);
    size_t n = map_size(&rep_state.attest_sigs);
    pthread_mutex_unlock(&rep_state.lock);
    return n;
}

static bool handle_attest_propose(const process_t *proc, directory_t *queues,
                                  generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!nmsg->verified)
    {
        log_warn(proc->logger, "Reputation: rejecting unverified attest_propose "
                 "from %s\n", nmsg->from_whom.nickname);
        return true;
    }
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
        return false;
    rep_attest_t a;
    bool ok = _attest_from_json(payload, &a);
    json_decref(payload);
    if (!ok)
    {
        log_warn(proc->logger, "Reputation: declining attest_propose from %s: "
                 "malformed\n", nmsg->from_whom.nickname);
        return true;
    }
    if (_is_self(proc, a.verifier))
        return true;   /* our own bounce-back */
    /* The verifier is the AUTHENTICATED sender, never just a claim. */
    char sender[UUID_STRING_LEN + 1];
    uuid_unparse_lower(nmsg->from_whom.uuid, sender);
    if (strcmp(sender, a.verifier) != 0)
    {
        log_warn(proc->logger, "Reputation: attest_propose names verifier %.8s but "
                 "was sent by %.8s; refused\n", a.verifier, sender);
        return true;
    }
    if (_is_self(proc, a.subject))
    {
        log_info(proc->logger, "Reputation: not co-signing an attestation about "
                 "ourselves from %s\n", nmsg->from_whom.nickname);
        return true;
    }
    {
        const identity_t *me_id = identity_self_identity(proc);
        char me_str[UUID_STRING_LEN + 1] = {0};
        if (me_id != NULL)
            uuid_unparse_lower(me_id->uuid, me_str);
        if (me_id != NULL && _conflicted(me_str, a.subject))
        {
            /* Our signature would not count (§2.54); say so rather than send it. */
            log_info(proc->logger, "Reputation: not co-signing an attestation about "
                     "a teammate from %s\n", nmsg->from_whom.nickname);
            return true;
        }
    }
    char why[128] = {0};
    if (!_attest_admissible(proc, &a, why, sizeof(why)))
    {
        log_warn(proc->logger, "Reputation: declining attest_propose from %s: %s\n",
                 nmsg->from_whom.nickname, why);
        return true;
    }
    uint8_t desig[REP_DESIG_MAX];
    size_t dlen = _attest_designation(&a, desig, sizeof(desig));
    char sig_hex[REP_SIG_HEX_LEN + 1] = {0};
    const identity_t *self = identity_self_identity(proc);
    if (self == NULL || dlen == 0
        || _cosign_hex(proc, desig, dlen, sig_hex, sizeof(sig_hex)) != 0)
    {
        log_warn(proc->logger, "Reputation: cannot sign attest_propose; declining\n");
        return true;
    }
    char me[UUID_STRING_LEN + 1];
    uuid_unparse_lower(self->uuid, me);
    json_t *ack = json_pack("{s:s, s:s, s:s}", "task", a.task,
                            "signer_uuid", me, "signature", sig_hex);
    if (ack != NULL)
    {
        _attest_send(proc, REP_PROTO_ATTEST_SIGN, &nmsg->from_whom, ack);
        json_decref(ack);
        log_info(proc->logger, "Reputation: co-signed attest_propose from %s\n",
                 nmsg->from_whom.nickname);
    }
    return true;
}

static bool handle_attest_sign(const process_t *proc, directory_t *queues,
                               generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!nmsg->verified)
    {
        log_warn(proc->logger, "Reputation: rejecting unverified attest_sign from %s\n",
                 nmsg->from_whom.nickname);
        return true;
    }
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
        return false;
    const char *task = json_string_value(json_object_get(payload, "task"));
    const char *claimed = json_string_value(json_object_get(payload, "signer_uuid"));
    const char *sig = json_string_value(json_object_get(payload, "signature"));
    char voter[UUID_STRING_LEN + 1];
    uuid_unparse_lower(nmsg->from_whom.uuid, voter);
    if (task == NULL || sig == NULL
        || (claimed != NULL && strcmp(claimed, voter) != 0))
    {
        json_decref(payload);
        return true;
    }
    char rec_text[1024] = {0};
    pthread_mutex_lock(&rep_state.lock);
    data_t *d = NULL;
    bool pending = map_get(&rep_state.attest_pending, (map_key_t)task, &d) == 0
        && d != NULL && data_string(d, rec_text, sizeof(rec_text)) == 0;
    pthread_mutex_unlock(&rep_state.lock);
    if (!pending)
    {
        json_decref(payload);
        return true;   /* not our round, or already final */
    }
    json_t *rec = json_loads(rec_text, 0, NULL);
    rep_attest_t a;
    bool ok = _attest_from_json(rec, &a);
    json_decref(rec);
    if (!ok || strcmp(voter, a.subject) == 0)
    {
        json_decref(payload);
        return true;   /* the subject's signature is never counted */
    }
    uint8_t desig[REP_DESIG_MAX];
    size_t dlen = _attest_designation(&a, desig, sizeof(desig));
    if (dlen == 0 || !_verify_cosignature(proc, voter, desig, dlen, sig))
    {
        log_warn(proc->logger, "Reputation: attest_sign from %.8s failed "
                 "verification; not counted\n", voter);
        json_decref(payload);
        return true;
    }
    pthread_mutex_lock(&rep_state.lock);
    _record_cosig_locked(&rep_state.attest_sigs, a.task, voter, sig);
    size_t count = 0;
    json_t *sigs = _cosigs_json_locked(&rep_state.attest_sigs, a.task, &count);
    pthread_mutex_unlock(&rep_state.lock);
    json_decref(payload);
    if (sigs == NULL || !_attest_quorum_met(proc, &a, sigs))
    {
        json_decref(sigs);
        return true;
    }
    pthread_mutex_lock(&rep_state.lock);
    map_remove(&rep_state.attest_pending, a.task);
    _drop_cosigs_locked(&rep_state.attest_sigs, a.task);
    _attest_retry_clear_locked(a.task);
    pthread_mutex_unlock(&rep_state.lock);
    _commit_attestation(proc, &a, sigs);
    json_t *fin = _attest_to_json(&a);
    if (fin != NULL)
    {
        json_object_set(fin, "sigs", sigs);
        _attest_send(proc, REP_PROTO_ATTEST_FINAL, NULL, fin);
        json_decref(fin);
    }
    json_decref(sigs);
    return true;
}

static bool handle_attest_final(const process_t *proc, directory_t *queues,
                                generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!nmsg->verified)
    {
        log_warn(proc->logger, "Reputation: rejecting unverified attest_final from %s\n",
                 nmsg->from_whom.nickname);
        return true;
    }
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
        return false;
    rep_attest_t a;
    if (!_attest_from_json(payload, &a))
    {
        json_decref(payload);
        return true;
    }
    pthread_mutex_lock(&rep_state.lock);
    data_t *d = NULL;
    bool held = map_get(&_chain_for_key_locked(a.group)->task_map,
                        (map_key_t)a.task, &d) == 0;
    pthread_mutex_unlock(&rep_state.lock);
    if (held)
    {
        json_decref(payload);
        return true;   /* already appended */
    }
    /* Quorum is verified HERE, against our own roster. Whether this node would
     * itself have vouched is not the question: the certificate says a majority
     * of the others did. */
    json_t *sigs = json_object_get(payload, "sigs");
    if (!_attest_quorum_met(proc, &a, sigs))
    {
        log_warn(proc->logger, "Reputation: rejecting attest_final about %.8s: its "
                 "co-signatures do not meet quorum\n", a.subject);
        json_decref(payload);
        return true;
    }
    _commit_attestation(proc, &a, sigs);
    json_decref(payload);
    return true;
}

/* Do we already hold, certified, the very attested entry @p a names (task
 * @p task)? Then catch-up has nothing to re-judge: we accepted it under the
 * quorum in force when it committed, and the group has only grown since if its
 * certificate now looks short (ISSUES §2.48). Primary chain only; a child
 * chain's entry is judged as before. */
static bool _attest_already_held(const char *task, const rep_attest_t *a)
{
    uuid_t tu;
    if (task == NULL || uuid_parse(task, tu) != 0)
        return false;
    transaction_t held;
    pthread_mutex_lock(&rep_state.lock);
    bool have = tx_history_by_task(&rep_state.history, tu, &held) == 0
        && tx_history_attest_cert(&rep_state.history, tu) != NULL;
    pthread_mutex_unlock(&rep_state.lock);
    if (!have || !held.attested)
        return false;
    char v[UUID_STRING_LEN + 1], sj[UUID_STRING_LEN + 1];
    uuid_unparse_lower(held.p1_uuid, v);
    uuid_unparse_lower(held.subject_uuid, sj);
    return strcmp(v, a->verifier) == 0 && strcmp(sj, a->subject) == 0
        && strcmp(held.p1_channel, a->channel) == 0
        && strcmp(held.evidence_digest, a->digest) == 0
        && strcmp(held.attest_scope, a->scope) == 0
        && fabs(held.p1_score - a->score) < 1e-12;
}

/* Catch-up refuses a segment carrying an attested entry whose certificate does
 * not meet our quorum: otherwise catch-up would be a way around the round. An
 * entry we already hold certified is not re-judged against today's roster
 * (_attest_already_held). Caller must NOT hold rep_state.lock or the peers
 * lock. */
static bool _chain_json_certified_all(const process_t *proc, json_t *arr,
                                      const char *key);

/* In a group that places its order, an entry a verified placement covers is
 * not re-judged: its acceptors checked each half's and each attestation's
 * certificate against the roster in force when they accepted it (the user's
 * call, 2026-10-14). A segment whose placement certificate does not verify is
 * refused whole. Mirrors Python _chain_certified. */
static bool _chain_json_certified(const process_t *proc, json_t *arr,
                                  const char *key)
{
    const char *group = (key != NULL && key[0] != '\0') ? key : NULL;
    if (!json_is_array(arr))
        return _chain_json_certified_all(proc, arr, key);
    int n = 0;
    bool refused = false;
    int *covered = _placement_certified_indices(proc, key, group, arr, &n, &refused);
    if (refused)
    {
        free(covered);
        return false;
    }
    json_t *rest = json_array();
    size_t i;
    json_t *e;
    json_array_foreach(arr, i, e)
    {
        json_t *ji = json_object_get(e, "index");
        bool in = false;
        for (int c = 0; json_is_integer(ji) && c < n && !in; c++)
            in = covered[c] == (int)json_integer_value(ji);
        if (!in)
            json_array_append(rest, e);
    }
    free(covered);
    bool ok = _chain_json_certified_all(proc, rest, key);
    json_decref(rest);
    return ok;
}

static bool _chain_json_certified_all(const process_t *proc, json_t *arr,
                                      const char *key)
{
    if (!json_is_array(arr))
        return true;
    size_t i;
    json_t *e;
    json_array_foreach(arr, i, e)
    {
        if (!json_is_true(json_object_get(e, "attested")))
            continue;
        rep_attest_t a;
        memset(&a, 0, sizeof(a));
        const char *v = json_string_value(json_object_get(e, "p1"));
        const char *s = json_string_value(json_object_get(e, "subject"));
        const char *c = json_string_value(json_object_get(e, "p1_channel"));
        const char *dg = json_string_value(json_object_get(e, "evidence_digest"));
        const char *sp = json_string_value(json_object_get(e, "attest_scope"));
        if (v == NULL || s == NULL || c == NULL || dg == NULL)
            return false;
        at_strlcpy(a.verifier, v, sizeof(a.verifier));
        at_strlcpy(a.subject, s, sizeof(a.subject));
        at_strlcpy(a.channel, c, sizeof(a.channel));
        at_strlcpy(a.digest, dg, sizeof(a.digest));
        if (sp != NULL)
            at_strlcpy(a.scope, sp, sizeof(a.scope));
        a.score = json_number_value(json_object_get(e, "p1_score"));
        if (!_attest_well_formed(&a))
            return false;
        if (key[0] == '\0'
            && _attest_already_held(json_string_value(json_object_get(e, "task")), &a))
            continue;
        if (!_attest_quorum_met(proc, &a, json_object_get(e, "attest_sigs")))
            return false;
    }
    return _chain_json_commit_certified(proc, arr, key);
}

static bool handle_slash_propose(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    /* Declining to co-sign is a disarmed node's whole contribution: it
     * neither vouches for the accusation nor argues with it, and the proposer
     * simply fails to reach quorum if enough of the group is disarmed.
     * Consumed (true) rather than passed on, so it is logged instead of
     * falling through. Mirrors Python handle_slash_propose. */
    if (!SLASH_ENABLED)
    {
        log_info(proc->logger,
                 "Reputation: not co-signing slash_propose from %s "
                 "(slashing disarmed)\n", nmsg->from_whom.nickname);
        return true;
    }
    if (!nmsg->verified)
    {
        log_warn(proc->logger,
                 "Reputation: rejecting unverified slash_propose from %s\n",
                 nmsg->from_whom.nickname);
        return true;
    }
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
        return false;
    const char *target_str =
        json_string_value(json_object_get(payload, "target_uuid"));
    double floor = json_real_value(json_object_get(payload, "floor_score"));
    int64_t epoch = json_integer_value(json_object_get(payload, "epoch"));
    const char *slasher_str =
        json_string_value(json_object_get(payload, "slasher_uuid"));
    const char *propose_reason =
        json_string_value(json_object_get(payload, "reason"));
    if (target_str == NULL)
    {
        json_decref(payload);
        return false;
    }
    /* Phase 3: refuse to co-sign a slash whose Merkle evidence does not
     * verify against our finalized checkpoint (evidence-free -> trusted). */
    /* Both spellings: the corpus and this runtime say "evidence", while
     * Python's live wire form is a serialized SlashAttestation, whose field is
     * "evidence_ref". Reading only one of them meant a Python slash carrying
     * Merkle evidence was co-signed here WITHOUT that evidence being checked. */
    if (!_verify_slash_evidence(_slash_evidence_of(payload)))
    {
        log_warn(proc->logger,
                 "Reputation: declining slash_propose, evidence failed verification\n");
        json_decref(payload);
        return true;
    }
    char key[UUID_STRING_LEN + 32];
    snprintf(key, sizeof(key), "%s:%lld", target_str, (long long)epoch);
    json_t *pending_rec = json_object();
    if (pending_rec != NULL)
    {
        json_object_set_new(pending_rec, "slasher_uuid",
                            json_string(slasher_str ? slasher_str : ""));
        json_object_set_new(pending_rec, "reason",
                            json_string(propose_reason ? propose_reason : ""));
        json_object_set_new(pending_rec, "floor_score", json_real(floor));
    }
    pthread_mutex_lock(&rep_state.lock);
    _store_pending_locked(&rep_state.slash_pending, key, pending_rec);
    pthread_mutex_unlock(&rep_state.lock);
    json_decref(pending_rec);

    /* Co-sign: sign the attestation designation with our own key and emit
     * slash_sign back to the proposer, naming ourselves. A round we cannot
     * fully identify (no slasher / no reason) cannot be signed — the
     * designation covers both fields — so decline rather than sign different
     * bytes than the proposer will verify. */
    const identity_t *self = identity_self_identity(proc);
    uint8_t desig[REP_DESIG_MAX];
    size_t dlen = (slasher_str != NULL && propose_reason != NULL)
        ? _slash_designation(slasher_str, target_str, propose_reason, floor,
                             epoch, desig, sizeof(desig))
        : 0;
    char sig_hex[REP_SIG_HEX_LEN + 1] = {0};
    if (self == NULL || dlen == 0
        || _cosign_hex(proc, desig, dlen, sig_hex, sizeof(sig_hex)) != 0)
    {
        log_warn(proc->logger,
                 "Reputation: cannot sign slash_propose (%s); declining to co-sign\n",
                 self == NULL ? "no self identity"
                              : "round not fully identified");
        json_decref(payload);
        return true;
    }
    char self_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(self->uuid, self_str);
    json_t *sign_json = json_object();
    if (sign_json == NULL)
    {
        json_decref(payload);
        return true;
    }
    json_object_set_new(sign_json, "target_uuid", json_string(target_str));
    json_object_set_new(sign_json, "epoch", json_integer(epoch));
    json_object_set_new(sign_json, "signer_uuid", json_string(self_str));
    json_object_set_new(sign_json, "signature", json_string(sig_hex));
    json_decref(payload);

    generic_msg_t sign = {0};
    sign.type = NET_MESSAGE;
    strncpy(sign.info.net_msg.process, "reputation", PROC_NAME_LEN);
    sign.info.net_msg.function = REP_PROTO_SLASH_SIGN;
    sign.info.net_msg.encrypt = true;
    memcpy(&sign.info.net_msg.to_whom, &nmsg->from_whom,
           sizeof(public_identity_t));
    strncpy(sign.info.net_msg.return_to, "reputation", PROC_NAME_LEN);
    net_msg_pack_json(&sign.info.net_msg, sign_json);
    json_decref(sign_json);
    _rep_send_to_network(proc, &sign);
    net_msg_free_obj(&sign.info.net_msg);
    /* THE SUCCESS SIDE. Every other outcome of this handler says something;
     * agreeing said nothing, so a round that worked was indistinguishable
     * from one that never started. A slash only lands once a quorum co-signs. */
    log_info(proc->logger,
             "Reputation: co-signed slash_propose from %s\n",
             nmsg->from_whom.nickname);
    return true;
}

static bool handle_slash_sign(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!nmsg->verified) {
        /* WAS SILENT. Every sibling gate in this file logs its refusal; this
         * one and handle_checkpoint_sign returned bare, so a co-signature
         * dropped here is indistinguishable from one that never arrived —
         * the quorum simply never completes and no line says why. That is the
         * shape of failure that cost four host runs in P3.3. */
        log_warn(proc->logger,
                 "Reputation: rejecting unverified slash_sign from %s\n",
                 nmsg->from_whom.nickname);
        return true;
    }
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
        return false;
    const char *target_str =
        json_string_value(json_object_get(payload, "target_uuid"));
    int64_t epoch = json_integer_value(json_object_get(payload, "epoch"));
    const char *claimed =
        json_string_value(json_object_get(payload, "signer_uuid"));
    const char *ack_sig =
        json_string_value(json_object_get(payload, "signature"));
    if (target_str == NULL)
    {
        json_decref(payload);
        return false;
    }
    char key[UUID_STRING_LEN + 32];
    snprintf(key, sizeof(key), "%s:%lld", target_str, (long long)epoch);

    /* Credit the AUTHENTICATED sender, never the uuid the payload claims. */
    char voter[UUID_STRING_LEN + 1];
    uuid_unparse_lower(nmsg->from_whom.uuid, voter);
    if (claimed != NULL && strncmp(claimed, voter, sizeof(voter)) != 0)
    {
        log_warn(proc->logger,
                 "Reputation: slash_sign claims voter %s but was sent by %s; refused\n",
                 claimed, voter);
        json_decref(payload);
        return true;
    }

    /* Rebuild the proposer's designation from the pending round and verify the
     * ack against it. An unverifiable co-signature is not a vote. */
    pthread_mutex_lock(&rep_state.lock);
    json_t *pending = _load_pending_locked(&rep_state.slash_pending, key);
    pthread_mutex_unlock(&rep_state.lock);
    if (pending == NULL)
    {
        json_decref(payload);
        return true;   /* not our round, or already finalized */
    }
    const char *slasher_str =
        json_string_value(json_object_get(pending, "slasher_uuid"));
    const char *reason_str =
        json_string_value(json_object_get(pending, "reason"));
    double floor = json_real_value(json_object_get(pending, "floor_score"));
    uint8_t desig[REP_DESIG_MAX];
    size_t dlen = _slash_designation(slasher_str, target_str, reason_str, floor,
                                    epoch, desig, sizeof(desig));
    if (dlen == 0 || !_verify_cosignature(proc, voter, desig, dlen, ack_sig))
    {
        log_warn(proc->logger,
                 "Reputation: slash_sign co-signature from %s failed verification; not counted\n",
                 voter);
        json_decref(pending);
        json_decref(payload);
        return true;
    }

    pthread_mutex_lock(&rep_state.lock);
    _record_cosig_locked(&rep_state.slash_sigs, key, voter, ack_sig);
    size_t count = 0;
    json_t *sigs = _cosigs_json_locked(&rep_state.slash_sigs, key, &count);
    pthread_mutex_unlock(&rep_state.lock);
    bool finalize = _quorum_met(proc, sigs, desig, dlen);

    /* payload and pending stay alive until the end: the strings read from
     * them above (the round's identity) are pointers INTO them. Freed here,
     * as they were, the final went out built from freed memory; live, the
     * checkpoint final lost its proposer_uuid, every member re-derived an
     * empty designation and counted "0 verified co-signature(s)", and no
     * member stored a checkpoint in any cohort run. */
    if (finalize)
    {
        json_t *final_json = json_object();
        if (final_json == NULL)
        {
            json_decref(sigs);
            json_decref(pending);
            json_decref(payload);
            return true;
        }
        json_object_set_new(final_json, "target_uuid",
                            json_string(target_str));
        json_object_set_new(final_json, "floor_score", json_real(floor));
        json_object_set_new(final_json, "epoch", json_integer(epoch));
        /* The round's identity travels too: a receiver has to re-derive this
         * designation to check the co-signatures it is being handed. */
        json_object_set_new(final_json, "slasher_uuid",
                            json_string(slasher_str ? slasher_str : ""));
        json_object_set_new(final_json, "reason",
                            json_string(reason_str ? reason_str : ""));
        json_object_set(final_json, "sigs", sigs);
        generic_msg_t bcast = {0};
        bcast.type = NET_MESSAGE;
        strncpy(bcast.info.net_msg.process, "reputation", PROC_NAME_LEN);
        bcast.info.net_msg.function = REP_PROTO_SLASH_FINAL;
        bcast.info.net_msg.encrypt = true;
        net_msg_pack_json(&bcast.info.net_msg, final_json);
        json_decref(final_json);
        peers_read_lock(proc);
        for (size_t i = 0; i < proc->protocol.num_peers; i++)
        {
            generic_msg_t per = bcast;
            memcpy(&per.info.net_msg.to_whom, &proc->protocol.peers[i],
                   sizeof(public_identity_t));
            _rep_send_to_network(proc, &per);
        }
        peers_read_unlock(proc);
        net_msg_free_obj(&bcast.info.net_msg);
    }
    json_decref(sigs);
    json_decref(pending);
    json_decref(payload);
    return true;
}

static bool handle_slash_final(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    /* A disarmed node does not apply a floor it declined to co-sign. This is
     * the half that makes the knob a real policy rather than decoration:
     * origination and co-signing can both be refused and a quorum elsewhere
     * in the group would still pin the peer here. */
    if (!SLASH_ENABLED)
    {
        log_info(proc->logger,
                 "Reputation: ignoring slash_final from %s "
                 "(slashing disarmed)\n", msg->info.net_msg.from_whom.nickname);
        return true;
    }
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!nmsg->verified)
    {
        log_warn(proc->logger,
                 "Reputation: rejecting unverified slash_final from %s\n",
                 nmsg->from_whom.nickname);
        return true;
    }
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
        return false;
    const char *target_str =
        json_string_value(json_object_get(payload, "target_uuid"));
    double floor = json_real_value(json_object_get(payload, "floor_score"));
    int64_t epoch = json_integer_value(json_object_get(payload, "epoch"));
    const char *reason =
        json_string_value(json_object_get(payload, "reason"));
    /* Function scope: the replay mark below is keyed by (target, slasher), so
     * the slasher is needed past the quorum block that first read it. */
    const char *slasher_str =
        json_string_value(json_object_get(payload, "slasher_uuid"));
    if (target_str == NULL)
    {
        json_decref(payload);
        return false;
    }
    uuid_t target_uuid;
    if (uuid_parse(target_str, target_uuid) != 0)
    {
        json_decref(payload);
        return false;
    }
    /* Phase 3: apply an evidence-bearing slash only if its inclusion proof
     * verifies against our finalized checkpoint (evidence-free -> trusted). */
    /* Both spellings: the corpus and this runtime say "evidence", while
     * Python's live wire form is a serialized SlashAttestation, whose field is
     * "evidence_ref". Reading only one of them meant a Python slash carrying
     * Merkle evidence was co-signed here WITHOUT that evidence being checked. */
    if (!_verify_slash_evidence(_slash_evidence_of(payload)))
    {
        log_warn(proc->logger,
                 "Reputation: rejecting slash_final, evidence failed verification\n");
        json_decref(payload);
        return true;
    }
    /* Quorum is verified HERE, by us, over the retained co-signatures.
     * Transport authentication says only that some admitted member sent this;
     * it says nothing about whether a majority agreed, and a slash floors a
     * peer into sticky exclusion. A finalizer carrying no verifiable
     * co-signatures is refused — the flag day noted in reputation.md. */
    {
        uint8_t desig[REP_DESIG_MAX];
        size_t dlen = (slasher_str != NULL && reason != NULL)
            ? _slash_designation(slasher_str, target_str, reason, floor, epoch,
                                 desig, sizeof(desig))
            : 0;
        json_t *sigs = json_object_get(payload, "sigs");
        if (dlen == 0 || !_quorum_met(proc, sigs, desig, dlen))
        {
            log_warn(proc->logger,
                     "Reputation: rejecting slash_final for %s: %zu verified "
                     "co-signature(s) do not meet quorum\n", target_str,
                     dlen == 0 ? (size_t)0
                               : _verified_cosigners(proc, sigs, desig, dlen));
            json_decref(payload);
            return true;
        }
    }
    /* Rehabilitation (explicit-only recovery): release the slash floor and
     * LIFT the score to PREREP_NEUTRAL (above the comm cut-off) so the peer
     * is re-admitted and must re-earn elevated trust from neutral. Mirrors
     * Python _apply_slash's REASON_REHABILITATE branch. (Python also clears
     * _consensus_ema/_consensus_last/_consensus_folded_idx so the lift is
     * visible past the slash-override; the C twin keeps no such running-EMA
     * latch — the score store is authoritative — so there is nothing to
     * clear here.) The tier recompute below drives the readmit through
     * _publish_tier_change (score above the cut-off -> exclusion_action -1). */
    if (reason != NULL && strcmp(reason, REP_SLASH_REASON_REHABILITATE) == 0)
    {
        pthread_mutex_lock(&rep_state.lock);
        /* A rehabilitation is itself a decision that must not be replayable,
         * and it takes the same mark: without this, the punitive slash it
         * supersedes could be re-presented at its own epoch and re-floor the
         * peer, and the rehab itself could be replayed to lift a LATER
         * legitimate slash. Refused when it does not advance the mark. */
        bool fresh = _slash_mark_advance_locked(target_str, slasher_str, epoch);
        if (fresh)
        {
            map_remove(&rep_state.slashed, (map_key_t)target_str);
            reputations_update(&rep_state.reputations, target_uuid,
                               PREREP_NEUTRAL);
        }
        pthread_mutex_unlock(&rep_state.lock);
        if (!fresh)
        {
            log_warn(proc->logger,
                     "Reputation: refusing rehabilitate for %s from %s: epoch "
                     "%lld not above the applied high-water (replay)\n",
                     target_str, (slasher_str == NULL) ? "?" : slasher_str,
                     (long long)epoch);
            json_decref(payload);
            return true;
        }
        _persist_slash_marks(proc);
        _publish_tier_change(proc, target_uuid, PREREP_NEUTRAL);
        _publish_reputation_change(target_uuid, PREREP_NEUTRAL);
        log_info(proc->logger,
                 "Reputation: slash lifted (rehabilitate) target=%s -> %.2f\n",
                 target_str, PREREP_NEUTRAL);
        json_decref(payload);
        return true;
    }
    pthread_mutex_lock(&rep_state.lock);
    _apply_slash_locked(target_str, slasher_str, target_uuid, floor, epoch);
    pthread_mutex_unlock(&rep_state.lock);
    _persist_slash_marks(proc);
    /* Drive the tier/exclusion publication so a sub-cut-off floor excludes
     * the peer at the network layer immediately (mirrors Python's
     * pending_tiers -> _compute_reputation -> _publish_tier_change flow). */
    _publish_tier_change(proc, target_uuid, floor);
    _publish_reputation_change(target_uuid, floor);
    log_info(proc->logger, "Reputation: slash applied target=%s floor=%.2f\n",
             target_str, floor);
    json_decref(payload);
    return true;
}

/* Do the entries we hold at the proposed indices hash to @p root?
 *
 * The range, not our whole window (ISSUES §2.29). The chain grows every second
 * or two in a busy group and each member proposes on its own phase, so by the
 * time a proposal lands the receiver has often committed one entry more (or
 * one fewer). Comparing whole windows declined every such honest proposal:
 * partition cohort part-3592107 (2026-09-29) had all four island-A nodes
 * propose epoch 12 over the SAME root, and not one proposal collected the four
 * signatures it needed. A signer that holds the range attests exactly what the
 * proposer signed, however far past it the chain has since run.
 *
 * An empty range (count 0) has no indices to look up, so it keeps the old
 * whole-window rule: it matches only an empty window. Caller holds
 * rep_state.lock. */
static bool _range_matches_locked(const char *chain_key, const char *root,
                                  int64_t first_index, int64_t count)
{
    char mine[TX_HASH_HEX_LEN + 1] = {0};
    tx_history_t *chain = _chain_for_key_locked(chain_key);
    if (count > 0)
    {
        if (first_index < 0 || first_index > INT32_MAX || count > INT32_MAX
            || tx_history_range_root(chain, (int)first_index, (int)count,
                                     mine) != 0)
            return false;   /* we do not hold every index in the range */
    }
    else
    {
        transaction_window_root(chain, mine);
    }
    return strncmp(mine, root, TX_HASH_HEX_LEN + 1) == 0;
}

/* Keep a proposal we could not co-sign on arrival, so a signer that was BEHIND
 * signs once it catches up (ISSUES §2.29). One slot per proposer and chain: a
 * proposer's newer epoch replaces its older one, which bounds the table by the
 * group's size. When every slot holds a different proposer the oldest goes.
 * Caller holds rep_state.lock. */
static void _park_cosign_locked(const char *proposer, const char *group_raw,
                                const char *root, int64_t epoch,
                                int64_t first_index, int64_t count,
                                const public_identity_t *to, double present)
{
    int slot = -1, oldest = 0;
    for (int i = 0; i < REP_PARKED_COSIGN_MAX; i++)
    {
        rep_parked_cosign_t *p = &rep_state.parked_cosigns[i];
        if (p->used && strcmp(p->proposer, proposer) == 0
            && strcmp(p->group, group_raw) == 0)
        {
            if (p->epoch > epoch)
                return;   /* a late copy of an older round */
            slot = i;
            break;
        }
        if (!p->used && slot < 0)
            slot = i;
        if (rep_state.parked_cosigns[oldest].used
            && (!p->used || p->parked_at < rep_state.parked_cosigns[oldest].parked_at))
            oldest = i;
    }
    if (slot < 0)
        slot = oldest;
    rep_parked_cosign_t *p = &rep_state.parked_cosigns[slot];
    memset(p, 0, sizeof(*p));
    p->used = true;
    at_strlcpy(p->proposer, proposer, sizeof(p->proposer));
    at_strlcpy(p->group, group_raw, sizeof(p->group));
    at_strlcpy(p->root, root, sizeof(p->root));
    p->epoch = epoch;
    p->first_index = first_index;
    p->count = count;
    p->parked_at = present;
    memcpy(&p->to, to, sizeof(public_identity_t));
}

/* Co-sign a checkpoint designation with our own key and send checkpoint_sign
 * to the proposer, naming ourselves. Shared by the propose handler and the
 * parked re-check, which must produce byte-identical acks. */
static bool _cosign_checkpoint(const process_t *proc,
                               const public_identity_t *to,
                               const char *proposer_str, const char *root,
                               int64_t epoch, int64_t first_index,
                               int64_t count_covered, const char *group_raw)
{
    const identity_t *self = identity_self_identity(proc);
    uint8_t desig[REP_DESIG_MAX];
    /* Signed over the chain name the PROPOSER used (group_raw), never our
     * locally resolved chain_key -- the proposer verifies this signature
     * against its own designation, and for a member of a child group the two
     * spellings differ. */
    size_t dlen = rep_checkpoint_designation(proposer_str, root, epoch,
                                            first_index, count_covered,
                                            group_raw, desig, sizeof(desig));
    char sig_hex[REP_SIG_HEX_LEN + 1] = {0};
    if (self == NULL || dlen == 0
        || _cosign_hex(proc, desig, dlen, sig_hex, sizeof(sig_hex)) != 0)
    {
        log_warn(proc->logger,
                 "Reputation: cannot sign checkpoint_propose; declining to co-sign\n");
        return false;
    }
    char self_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(self->uuid, self_str);
    json_t *sign_json = json_object();
    if (sign_json == NULL)
        return false;
    json_object_set_new(sign_json, "proposer_uuid", json_string(proposer_str));
    json_object_set_new(sign_json, "epoch", json_integer(epoch));
    json_object_set_new(sign_json, "signer_uuid", json_string(self_str));
    json_object_set_new(sign_json, "signature", json_string(sig_hex));
    /* The ack names the chain too — the proposer needs it to find the right
     * pending round, and it is inside the bytes just signed. Mirrors Python's
     * 5-element ack tuple; the far side treats an absent field as the primary
     * chain, so an older peer that omits it still resolves. */
    if (group_raw[0] != '\0')
        json_object_set_new(sign_json, "group_uuid", json_string(group_raw));

    generic_msg_t sign = {0};
    sign.type = NET_MESSAGE;
    strncpy(sign.info.net_msg.process, "reputation", PROC_NAME_LEN);
    sign.info.net_msg.function = REP_PROTO_CHECKPOINT_SIGN;
    sign.info.net_msg.encrypt = true;
    memcpy(&sign.info.net_msg.to_whom, to, sizeof(public_identity_t));
    strncpy(sign.info.net_msg.return_to, "reputation", PROC_NAME_LEN);
    net_msg_pack_json(&sign.info.net_msg, sign_json);
    json_decref(sign_json);
    _rep_send_to_network(proc, &sign);
    net_msg_free_obj(&sign.info.net_msg);
    /* THE SUCCESS SIDE. Every other outcome of this handler says something;
     * agreeing said nothing, so a round that worked was indistinguishable
     * from one that never started. A checkpoint only anchors evidence once a quorum co-signs. */
    log_info(proc->logger,
             "Reputation: co-signed checkpoint_propose from %s\n",
             to->nickname);
    return true;
}

size_t _recheck_parked_cosigns(const process_t *proc, double present)
{
    rep_parked_cosign_t due[REP_PARKED_COSIGN_MAX];
    size_t n_due = 0;
    double ttl = REP_CHECKPOINT_INTERVAL;
    pthread_mutex_lock(&rep_state.lock);
    for (int i = 0; i < REP_PARKED_COSIGN_MAX; i++)
    {
        rep_parked_cosign_t *p = &rep_state.parked_cosigns[i];
        if (!p->used)
            continue;
        /* By the next interval the proposer has moved on to a new epoch. */
        if (present - p->parked_at > ttl)
        {
            p->used = false;
            continue;
        }
        char chain_key[UUID_STRING_LEN + 1];
        _chain_key(proc, p->group, chain_key, sizeof(chain_key));
        if (_range_matches_locked(chain_key, p->root, p->first_index, p->count))
        {
            due[n_due++] = *p;
            p->used = false;
        }
    }
    pthread_mutex_unlock(&rep_state.lock);
    /* Signed and sent outside the lock, as the propose handler does. */
    for (size_t i = 0; i < n_due; i++)
    {
        rep_parked_cosign_t *p = &due[i];
        log_info(proc->logger,
                 "Reputation: caught up to %s's checkpoint epoch %lld after "
                 "%.1f s; co-signing it now\n",
                 p->to.nickname, (long long)p->epoch, present - p->parked_at);
        _cosign_checkpoint(proc, &p->to, p->proposer, p->root, p->epoch,
                           p->first_index, p->count, p->group);
    }
    return n_due;
}

size_t reputation_parked_cosign_count(void)
{
    size_t n = 0;
    pthread_mutex_lock(&rep_state.lock);
    for (int i = 0; i < REP_PARKED_COSIGN_MAX; i++)
        if (rep_state.parked_cosigns[i].used)
            n++;
    pthread_mutex_unlock(&rep_state.lock);
    return n;
}

/****************************
 * Phase 2: quorum-signed Merkle checkpoints
 *
 * Mirrors Python repprocess.handle_checkpoint_propose / _sign / _final +
 * _store_checkpoint. A member co-signs a proposed checkpoint only when its own
 * transaction_window_root matches the proposed root, so a finalized checkpoint
 * certifies that a quorum observed the same committed window. Wire payloads are
 * plain JSON objects (byte_pinning:false). As with slashing, C drives a single
 * rep_state per dispatcher, so the propose handler records the pending root that
 * the sign handler later finalizes.
 ****************************/

static bool handle_checkpoint_propose(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!nmsg->verified)
    {
        log_warn(proc->logger,
                 "Reputation: rejecting unverified checkpoint_propose from %s\n",
                 nmsg->from_whom.nickname);
        return true;
    }
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
        return false;
    const char *proposer_str =
        json_string_value(json_object_get(payload, "proposer_uuid"));
    const char *root =
        json_string_value(json_object_get(payload, "root"));
    int64_t epoch = json_integer_value(json_object_get(payload, "epoch"));
    int64_t first_index =
        json_integer_value(json_object_get(payload, "first_index"));
    int64_t count_covered =
        json_integer_value(json_object_get(payload, "count"));
    if (proposer_str == NULL || root == NULL)
    {
        json_decref(payload);
        return false;
    }
    /* The chain the proposal NAMES, exactly as it came off the wire. Two
     * distinct values are needed and confusing them breaks different things
     * (mirrors Python handle_checkpoint_propose):
     *
     *   group_raw   -- what the PROPOSER called this chain. It keys the round
     *                  and it is inside the bytes we sign, so both must use it
     *                  verbatim: the proposer looks its own round up by the
     *                  value it sent, and verifies our ack against a
     *                  designation built from that same value.
     *   chain_key   -- the same chain resolved to OUR local bookkeeping, used
     *                  only to pick the window to compare. _chain_key
     *                  normalizes, so a member of a child group maps that
     *                  group to its own primary "" -- correct for choosing the
     *                  window, wrong for the key and the designation, because
     *                  the proposer never said "".
     */
    const char *group_str = json_string_value(json_object_get(payload,
                                                             "group_uuid"));
    const char *group_raw = (group_str != NULL) ? group_str : "";
    char chain_key[UUID_STRING_LEN + 1];
    _chain_key(proc, group_str, chain_key, sizeof(chain_key));

    /* Round key carries the chain: a gateway's primary and child rounds
     * otherwise collide at the same epoch number, and the proposer's own
     * pending round (keyed with the chain in _originate_checkpoint) would be
     * unreachable from here. Same construction, same bound, both sides. */
    char key[UUID_STRING_LEN * 2 + 32];
    snprintf(key, sizeof(key), "%s:%lld:%.*s", proposer_str, (long long)epoch,
             (int)UUID_STRING_LEN, group_raw);

    /* Consensus check: co-sign ONLY if the entries WE hold at the proposed
     * indices produce the same Merkle root. Record the proposed round as
     * pending either way so the sign handler (driven by other nodes' co-signs
     * in conformance) can finalize the agreed value. The record carries the
     * window bounds as well as the root because the designation covers them. */
    json_t *pending_rec = json_object();
    if (pending_rec != NULL)
    {
        json_object_set_new(pending_rec, "root", json_string(root));
        json_object_set_new(pending_rec, "first_index",
                            json_integer(first_index));
        json_object_set_new(pending_rec, "count", json_integer(count_covered));
        /* The RAW name, because the sign handler rebuilds the signed
         * designation out of this record. */
        if (group_raw[0] != '\0')
            json_object_set_new(pending_rec, "group_uuid",
                               json_string(group_raw));
    }
    pthread_mutex_lock(&rep_state.lock);
    bool matches = _range_matches_locked(chain_key, root, first_index,
                                         count_covered);
    _store_pending_locked(&rep_state.checkpoint_pending, key, pending_rec);
    if (!matches)
        _park_cosign_locked(proposer_str, group_raw, root, epoch, first_index,
                            count_covered, &nmsg->from_whom, (double)time(NULL));
    pthread_mutex_unlock(&rep_state.lock);
    json_decref(pending_rec);
    if (!matches)
    {
        /* Not a refusal yet: our chain may simply not have caught up to the
         * proposer's, or be about to adopt it. Parked and re-checked every
         * pass (ISSUES §2.29). */
        log_debug(proc->logger,
                  "Reputation: checkpoint_propose range [%lld, +%lld) does not "
                  "match our chain %s yet; parked\n",
                  (long long)first_index, (long long)count_covered,
                  chain_key[0] ? chain_key : "primary");
        json_decref(payload);
        return true;
    }
    _cosign_checkpoint(proc, &nmsg->from_whom, proposer_str, root, epoch,
                       first_index, count_covered, group_raw);
    json_decref(payload);
    return true;
}

static bool handle_checkpoint_sign(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!nmsg->verified) {
        /* WAS SILENT — see the note in handle_slash_sign. A checkpoint that
         * never reaches quorum because its acks were dropped here looks
         * exactly like a checkpoint nobody answered. */
        log_warn(proc->logger,
                 "Reputation: rejecting unverified checkpoint_sign from %s\n",
                 nmsg->from_whom.nickname);
        return true;
    }
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
        return false;
    const char *proposer_str =
        json_string_value(json_object_get(payload, "proposer_uuid"));
    int64_t epoch = json_integer_value(json_object_get(payload, "epoch"));
    const char *claimed =
        json_string_value(json_object_get(payload, "signer_uuid"));
    const char *ack_sig =
        json_string_value(json_object_get(payload, "signature"));
    if (proposer_str == NULL)
    {
        json_decref(payload);
        return false;
    }
    /* Which chain this ack is for, as the proposer named it. Absent means the
     * primary chain, matching Python's length-tolerant 4-vs-5 element ack, so a
     * peer that predates the field still resolves. Keyed identically to
     * _originate_checkpoint and handle_checkpoint_propose -- same order, same
     * bound -- or a round recorded by one is unreachable from the others. */
    const char *ack_group = json_string_value(json_object_get(payload,
                                                             "group_uuid"));
    if (ack_group == NULL)
        ack_group = "";
    char key[UUID_STRING_LEN * 2 + 32];
    snprintf(key, sizeof(key), "%s:%lld:%.*s", proposer_str, (long long)epoch,
             (int)UUID_STRING_LEN, ack_group);

    /* Credit the AUTHENTICATED sender, never the payload's claim. */
    char voter[UUID_STRING_LEN + 1];
    uuid_unparse_lower(nmsg->from_whom.uuid, voter);
    if (claimed != NULL && strncmp(claimed, voter, sizeof(voter)) != 0)
    {
        log_warn(proc->logger,
                 "Reputation: checkpoint_sign claims voter %s but was sent by %s; refused\n",
                 claimed, voter);
        json_decref(payload);
        return true;
    }

    pthread_mutex_lock(&rep_state.lock);
    json_t *pending = _load_pending_locked(&rep_state.checkpoint_pending, key);
    pthread_mutex_unlock(&rep_state.lock);
    if (pending == NULL)
    {
        json_decref(payload);
        return true;   /* not our round, or already finalized */
    }
    char root[TX_HASH_HEX_LEN + 1] = {0};
    const char *pending_root =
        json_string_value(json_object_get(pending, "root"));
    if (pending_root != NULL)
    {
        strncpy(root, pending_root, TX_HASH_HEX_LEN);
        root[TX_HASH_HEX_LEN] = '\0';
    }
    int64_t first_index =
        json_integer_value(json_object_get(pending, "first_index"));
    int64_t count_covered =
        json_integer_value(json_object_get(pending, "count"));
    /* The chain came with the round when it was recorded; the co-signature was
     * made over bytes that include it. */
    const char *pending_group =
        json_string_value(json_object_get(pending, "group_uuid"));
    uint8_t desig[REP_DESIG_MAX];
    size_t dlen = rep_checkpoint_designation(proposer_str, root, epoch,
                                            first_index, count_covered,
                                            pending_group, desig,
                                            sizeof(desig));
    if (dlen == 0 || !_verify_cosignature(proc, voter, desig, dlen, ack_sig))
    {
        log_warn(proc->logger,
                 "Reputation: checkpoint_sign co-signature from %s failed "
                 "verification; not counted\n", voter);
        json_decref(pending);
        json_decref(payload);
        return true;
    }

    pthread_mutex_lock(&rep_state.lock);
    _record_cosig_locked(&rep_state.checkpoint_sigs, key, voter, ack_sig);
    size_t count = 0;
    json_t *sigs = _cosigs_json_locked(&rep_state.checkpoint_sigs, key, &count);
    pthread_mutex_unlock(&rep_state.lock);
    int f = tx_byzantine_f(_n_min_in_force(proc, NULL));
    peers_read_lock(proc);
    size_t quorum = _ckpt_quorum_for_group(proc, NULL, f);
    peers_read_unlock(proc);
    bool finalize = count > quorum;

    /* payload and pending stay alive until the end: the strings read from
     * them above (the round's identity) are pointers INTO them. Freed here,
     * as they were, the final went out built from freed memory; live, the
     * checkpoint final lost its proposer_uuid, every member re-derived an
     * empty designation and counted "0 verified co-signature(s)", and no
     * member stored a checkpoint in any cohort run. */
    if (finalize)
    {
        json_t *final_json = json_object();
        if (final_json == NULL)
        {
            json_decref(sigs);
            json_decref(pending);
            json_decref(payload);
            return true;
        }
        json_object_set_new(final_json, "proposer_uuid",
                            json_string(proposer_str));
        json_object_set_new(final_json, "root", json_string(root));
        json_object_set_new(final_json, "epoch", json_integer(epoch));
        /* The window bounds travel so a receiver can re-derive the designation
         * the co-signatures were made over. */
        json_object_set_new(final_json, "first_index",
                            json_integer(first_index));
        json_object_set_new(final_json, "count", json_integer(count_covered));
        json_object_set(final_json, "sigs", sigs);
        /* Upgrade our own stored copy from the lone self-signature to the
         * quorum map, so the evidence WE persist is attested by the group
         * rather than only by us. The proposer never stored its own finalized
         * checkpoint before this, which left it the one node in the group with
         * no record of a checkpoint it had itself driven to quorum. */
        _store_checkpoint(proc, proposer_str, root, epoch, (int)first_index,
                          (int)count_covered,
                          pending_group == NULL ? "" : pending_group, sigs);
        generic_msg_t bcast = {0};
        bcast.type = NET_MESSAGE;
        strncpy(bcast.info.net_msg.process, "reputation", PROC_NAME_LEN);
        bcast.info.net_msg.function = REP_PROTO_CHECKPOINT_FINAL;
        bcast.info.net_msg.encrypt = true;
        net_msg_pack_json(&bcast.info.net_msg, final_json);
        json_decref(final_json);
        peers_read_lock(proc);
        for (size_t i = 0; i < proc->protocol.num_peers; i++)
        {
            generic_msg_t per = bcast;
            memcpy(&per.info.net_msg.to_whom, &proc->protocol.peers[i],
                   sizeof(public_identity_t));
            _rep_send_to_network(proc, &per);
        }
        peers_read_unlock(proc);
        net_msg_free_obj(&bcast.info.net_msg);
    }
    json_decref(sigs);
    json_decref(pending);
    json_decref(payload);
    return true;
}


/* Defined with the rest of the evidence machinery below; deep resolution
 * needs it to describe a chain exactly as the persisted evidence does. */
static void _current_checkpoint_locked(const char *chain_key,
                                      rep_checkpoint_t *out);

/****************************  *
 * Deep resolution: one peer, on demand, at any depth
 * (doc/architecture/gateway-reputation-tree.md)
 *
 * Mirrors Python repprocess handle_resolve / handle_resolved / _forward_resolve /
 * _accept_resolved and reputation.py's resolve helpers. A node holds chains only for
 * groups it belongs to, so a peer two levels down is unscoreable locally. Rather than
 * enumerate the subtree -- a cost that grows with the TREE to answer about one PEER --
 * the query is relayed toward the holder and the answer returns along the reverse path
 * carrying the quorum-signed window that backs it.
 *
 * The window travels whole, not as the peer's entries with inclusion proofs: a proof
 * shows an entry IS present and says nothing about entries withheld, so a holder could
 * answer with a peer's good transactions, omit the bad ones and still verify.
 * Recomputing the root from the entries closes that. ************************** */

/* Hops a resolve may travel, and the ceiling we refuse above. Must match
 * Python RESOLVE_TTL_DEFAULT / RESOLVE_TTL_MAX -- a runtime that forwarded one
 * hop further than its twin would answer queries the other dropped. */
#define REP_RESOLVE_TTL_DEFAULT 4
#define REP_RESOLVE_TTL_MAX     8
/* Seconds a relayed or outstanding query is retained. A garbage-collection
 * bound, not a latency target. */
#define REP_RESOLVE_TTL_SECS    30.0
/* Query-ids retained for loop detection, bounded like the other dedup rings. */
#define REP_RESOLVE_SEEN_MAX    256

typedef struct {
    char   answer_to[UUID_STRING_LEN + 1];  /* neighbour to hand the answer to */
    char   peer[UUID_STRING_LEN + 1];       /* only set for queries we originated */
    char   req_proc[PROC_NAME_LEN + 1];
    double deadline;
} rep_resolve_t;

static double _resolve_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* Record a query-id, returning false if it was already seen (caller drops the
 * query). FIFO-bounded: at the cap the whole ring is cleared rather than
 * evicted one by one, because map_t has no insertion order to evict by and a
 * cleared ring only costs the re-forwarding of a query old enough to have
 * fallen out of it. Caller holds the lock. */
static bool _mark_resolve_seen_locked(const char *query_id)
{
    data_t *unused = NULL;
    if (map_get(&rep_state.resolve_seen, (map_key_t)query_id, &unused) == 0)
        return false;
    if (map_size(&rep_state.resolve_seen) >= REP_RESOLVE_SEEN_MAX)
    {
        map_free(&rep_state.resolve_seen);
        map_init(&rep_state.resolve_seen);
    }
    map_set(&rep_state.resolve_seen, (map_key_t)query_id, integer_data(1));
    return true;
}

static int _resolve_track(map_t *table, const char *query_id,
                          const char *answer_to, const char *peer,
                          const char *req_proc)
{
    rep_resolve_t *ent = calloc(1, sizeof(rep_resolve_t));
    if (ent == NULL)
        return -1;
    if (answer_to != NULL)
        snprintf(ent->answer_to, sizeof(ent->answer_to), "%s", answer_to);
    if (peer != NULL)
        snprintf(ent->peer, sizeof(ent->peer), "%s", peer);
    if (req_proc != NULL)
        snprintf(ent->req_proc, sizeof(ent->req_proc), "%s", req_proc);
    ent->deadline = _resolve_now() + REP_RESOLVE_TTL_SECS;
    data_t *d = object_ptr_data(ent, sizeof(rep_resolve_t));
    if (d == NULL || map_set(table, (map_key_t)query_id, d) != 0)
    {
        free(ent);
        return -1;
    }
    return 0;
}

/* Take an entry out of a table, copying it out. Caller holds the lock. */
static bool _resolve_take_locked(map_t *table, const char *query_id,
                                 rep_resolve_t *out)
{
    data_t *d = NULL;
    if (map_get(table, (map_key_t)query_id, &d) != 0 || d == NULL)
        return false;
    void *ptr = NULL;
    if (data_object_ptr(d, &ptr) != 0 || ptr == NULL)
        return false;
    if (out != NULL)
        memcpy(out, ptr, sizeof(rep_resolve_t));
    map_remove(table, (map_key_t)query_id);
    free(ptr);
    return true;
}

/* Expire relayed and outstanding queries. A subtree that never answers is the
 * ordinary case, not an error, and nothing else would ever clear these.
 * Mirrors Python _prune_resolve_state. */
static void _prune_resolve_state(const process_t *proc)
{
    double stamp = _resolve_now();
    map_t *tables[2] = { &rep_state.resolve_pending,
                         &rep_state.resolve_outstanding };
    pthread_mutex_lock(&rep_state.lock);
    for (int t = 0; t < 2; t++)
    {
        array_t *keys = map_keys(tables[t]);
        size_t n = array_size(keys);
        for (size_t i = 0; i < n; i++)
        {
            data_t *kd = NULL;
            map_key_t key = NULL;
            if (array_get(keys, (int)i, &kd) != 0
                || data_string_ptr(kd, &key) != 0 || key == NULL)
                continue;
            data_t *d = NULL;
            if (map_get(tables[t], key, &d) != 0 || d == NULL)
                continue;
            void *ptr = NULL;
            if (data_object_ptr(d, &ptr) != 0 || ptr == NULL)
                continue;
            rep_resolve_t *ent = (rep_resolve_t *)ptr;
            if (ent->deadline > stamp)
                continue;
            if (t == 1 && proc != NULL)
                log_info(proc->logger,
                         "Reputation: deep resolve of %.8s timed out\n",
                         ent->peer);
            map_remove(tables[t], key);
            free(ent);
        }
        /* keys is the map's own key index (map_keys): not ours to free */
    }
    pthread_mutex_unlock(&rep_state.lock);
}

/* The key of the chain whose window holds committed bilateral entries for
 * `peer_str`, or false when no chain of ours does. Primary chain first, so a
 * peer we transact with directly is answered from the chain that actually
 * knows it. Caller holds the lock. Mirrors Python _chain_holding. */
static bool _chain_holding_locked(const char *peer_str, char *out, size_t cap)
{
    array_t *child_keys = map_keys(&rep_state.child_hist);
    size_t n_child = array_size(child_keys);
    bool found = false;
    for (size_t ci = 0; ci <= n_child && !found; ci++)
    {
        const char *chain_key = "";
        if (ci > 0)
        {
            data_t *kd = NULL;
            map_key_t k = NULL;
            if (array_get(child_keys, (int)(ci - 1), &kd) != 0
                || data_string_ptr(kd, &k) != 0 || k == NULL)
                continue;
            chain_key = k;
        }
        tx_history_t *chain = _chain_for_key_locked(chain_key);
        if (chain == NULL)
            continue;
        for (int i = 0; i < chain->chain_len; i++)
        {
            const transaction_t *tx = &chain->chain[i];
            if (tx->index < 0 || !tx_is_committed(tx))
                continue;
            char p1[UUID_STRING_LEN + 1], p2[UUID_STRING_LEN + 1];
            uuid_unparse_lower(tx->p1_uuid, p1);
            /* An attested entry names its subject where p2 would be. */
            uuid_unparse_lower(tx->attested ? tx->subject_uuid : tx->p2_uuid, p2);
            if (strcmp(p1, peer_str) == 0 || strcmp(p2, peer_str) == 0)
            {
                snprintf(out, cap, "%s", chain_key);
                found = true;
                break;
            }
        }
    }
    /* child_keys is the map's own key index (map_keys): not ours to free */
    return found;
}

/* The co-signer identities an answer carries, in the DRY canonical public form
 * (public_identity_to_json). Only signers we hold an identity for: a uuid we
 * cannot produce a key for would travel as an unverifiable name, which is
 * worse than absent. Mirrors Python _resolve_signers. */
static json_t *_resolve_signers(const process_t *proc, map_t *sigs)
{
    json_t *arr = json_array();
    if (arr == NULL || sigs == NULL)
        return arr;
    array_t *voters = map_keys(sigs);
    size_t n_voters = array_size(voters);
    for (size_t vi = 0; vi < n_voters; vi++)
    {
        data_t *vd = NULL;
        map_key_t voter = NULL;
        if (array_get(voters, (int)vi, &vd) != 0
            || data_string_ptr(vd, &voter) != 0 || voter == NULL)
            continue;
        peers_read_lock(proc);
        const public_identity_t *match = NULL;
        for (size_t i = 0; i < proc->protocol.num_peers; i++)
        {
            char uuid_str[UUID_STRING_LEN + 1];
            uuid_unparse_lower(proc->protocol.peers[i].uuid, uuid_str);
            if (strcmp(uuid_str, voter) == 0
                && processes_peer_is_member(proc, &proc->protocol.peers[i]))
            {
                match = &proc->protocol.peers[i];
                break;
            }
        }
        json_t *obj = NULL;
        if (match != NULL && public_identity_to_json(match, &obj) == 0
            && obj != NULL)
            json_array_append_new(arr, obj);
        else if (obj != NULL)
            json_decref(obj);
        peers_read_unlock(proc);
    }
    /* voters is the map's own key index (map_keys): not ours to free */
    return arr;
}

/* Send an answer to one neighbour. */
static void _send_resolved(const process_t *proc,
                           const public_identity_t *to_whom, json_t *answer,
                           const char *req_proc)
{
    (void)proc;
    generic_msg_t out = {0};
    out.type = NET_MESSAGE;
    at_strlcpy(out.info.net_msg.process,
               (req_proc != NULL && req_proc[0] != '\0') ? req_proc : "reputation",
               sizeof(out.info.net_msg.process));
    out.info.net_msg.function = REP_PROTO_REP_RESOLVED;
    out.info.net_msg.encrypt = true;
    memcpy(&out.info.net_msg.to_whom, to_whom, sizeof(public_identity_t));
    net_msg_pack_json(&out.info.net_msg, answer);
    _rep_send_to_network(proc, &out);
    net_msg_free_obj(&out.info.net_msg);
}

/* Send a query one level DOWN, to every child group we gateway, with the TTL
 * decremented. Addressed to the child GROUP rather than a chosen child gateway:
 * the reputation process holds the child groups but not the rank data identity
 * picks a gateway with, and asking the group is the same answer without a
 * second, drifting copy of that derivation living here. Returns the number of
 * groups reached; 0 means this branch is a dead end. Mirrors Python
 * _forward_resolve. */
static size_t _forward_resolve(const process_t *proc, json_t *query)
{
    if (proc == NULL || proc->protocol.child_groups == NULL)
        return 0;
    int ttl = (int)json_integer_value(json_object_get(query, "ttl"));
    if (ttl <= 0)
        return 0;
    json_t *onward = json_deep_copy(query);
    if (onward == NULL)
        return 0;
    json_object_set_new(onward, "ttl", json_integer(ttl - 1));

    size_t sent = 0;
    array_t *groups = map_keys(proc->protocol.child_groups);
    size_t n_groups = array_size(groups);
    for (size_t gi = 0; gi < n_groups; gi++)
    {
        data_t *gk = NULL;
        map_key_t gkey = NULL;
        if (array_get(groups, (int)gi, &gk) != 0
            || data_string_ptr(gk, &gkey) != 0 || gkey == NULL)
            continue;
        /* Every member of that group: the holder answers, a member that is
         * itself a gateway relays deeper, and the query-id ring keeps a node
         * reached twice from acting twice. */
        peers_read_lock(proc);
        for (size_t i = 0; i < proc->protocol.num_peers; i++)
        {
            if (!_peer_in_group(proc, &proc->protocol.peers[i], gkey))
                continue;
            generic_msg_t per = {0};
            per.type = NET_MESSAGE;
            strncpy(per.info.net_msg.process, "reputation", PROC_NAME_LEN);
            per.info.net_msg.function = REP_PROTO_REP_RESOLVE;
            per.info.net_msg.encrypt = true;
            memcpy(&per.info.net_msg.to_whom, &proc->protocol.peers[i],
                   sizeof(public_identity_t));
            net_msg_pack_json(&per.info.net_msg, onward);
            _rep_send_to_network(proc, &per);
            net_msg_free_obj(&per.info.net_msg);
            sent++;
        }
        peers_read_unlock(proc);
    }
    /* groups is the map's own key index (map_keys): not ours to free */
    json_decref(onward);
    return sent;
}

/* Build the answer for a peer we hold a chain for, or NULL when that chain has
 * no finalized checkpoint. No checkpoint means no answer, deliberately: the
 * window would still be true, but a receiver two hops away cannot tell an
 * unattested truth from a fabrication, so sending one would only teach
 * requestors to accept what they cannot check. Mirrors Python _resolve_answer.
 * Caller owns the result. */
static json_t *_resolve_answer(const process_t *proc, const char *query_id,
                               const char *peer_str, const char *chain_key)
{
    pthread_mutex_lock(&rep_state.lock);
    rep_chain_ckpt_t *slot = _ckpt_slot_locked(chain_key);
    if (slot == NULL || !slot->set)
    {
        pthread_mutex_unlock(&rep_state.lock);
        log_debug(proc->logger,
                  "Reputation: resolve %.8s: chain %s has no finalized "
                  "checkpoint; no answer\n", peer_str,
                  chain_key[0] ? chain_key : "primary");
        return NULL;
    }
    rep_checkpoint_t ckpt;
    if (rep_checkpoint_init(&ckpt) != 0)
    {
        pthread_mutex_unlock(&rep_state.lock);
        return NULL;
    }
    /* Same filler the persisted evidence uses, so an answer and the file on
     * disk describe the chain identically. */
    _current_checkpoint_locked(chain_key, &ckpt);

    tx_history_t *chain = _chain_for_key_locked(chain_key);
    json_t *doc = NULL;
    int err = reputation_evidence_to_json(chain, &ckpt, &doc);
    uuid_t peer_uu;
    double score = 0.0;
    bool have_score = (uuid_parse(peer_str, peer_uu) == 0);
    if (have_score)
        score = reputation_consensus(chain, peer_uu, &rep_state.task_weights);
    json_t *signers = _resolve_signers(proc, &ckpt.sigs);
    pthread_mutex_unlock(&rep_state.lock);
    rep_checkpoint_free(&ckpt);

    if (err != 0 || doc == NULL)
    {
        if (signers != NULL)
            json_decref(signers);
        return NULL;
    }
    json_object_set_new(doc, "query_id", json_string(query_id));
    json_object_set_new(doc, "peer_uuid", json_string(peer_str));
    json_object_set_new(doc, "score",
                        have_score ? json_real(score) : json_null());
    json_object_set_new(doc, "signers", signers);
    return doc;
}

/* One accepted or refused answer, keyed by peer uuid. `reason` sits beside the
 * boolean deliberately: an operator reading "unverified" needs to know WHICH
 * gate failed, and a caller may knowingly accept a weaker answer. Mirrors
 * Python resolved_reps. */
typedef struct {
    double score;
    bool   verified;
    bool   have_score;
    char   reason[192];
} rep_resolved_t;

static void _record_resolved(const char *peer_str, double score,
                             bool have_score, bool verified,
                             const char *reason)
{
    rep_resolved_t *rec = calloc(1, sizeof(rep_resolved_t));
    if (rec == NULL)
        return;
    rec->score = score;
    rec->have_score = have_score;
    rec->verified = verified;
    snprintf(rec->reason, sizeof(rec->reason), "%s", reason ? reason : "");
    data_t *d = object_ptr_data(rec, sizeof(rep_resolved_t));
    pthread_mutex_lock(&rep_state.lock);
    data_t *old = NULL;
    if (map_get(&rep_state.resolved_reps, (map_key_t)peer_str, &old) == 0
        && old != NULL)
    {
        void *op = NULL;
        if (data_object_ptr(old, &op) == 0 && op != NULL)
            free(op);
        map_remove(&rep_state.resolved_reps, (map_key_t)peer_str);
    }
    if (d == NULL || map_set(&rep_state.resolved_reps, (map_key_t)peer_str, d) != 0)
        free(rec);
    pthread_mutex_unlock(&rep_state.lock);
}

/* An anchor verifier built from the SAME policy the identity process admits
 * peers with, so "an anchor we accept" means one thing on this node. Built on
 * first use and kept: a deep answer is rare, but rebuilding an OpenSSL store
 * per co-signature would not be.
 *
 * Only the plain policy verifier, not the per-anchor fan-out id_proc does:
 * this gate asks "is this signer anchored at all", where admission asks the
 * harder question of WHICH agency vouches for a peer, and answering the
 * narrower question with the broader machinery would put a second copy of that
 * decision here to drift. */

/* Whether a co-signer may count toward an answer's evidence: a peer we already
 * hold cleared admission, otherwise the carried identity must present a
 * credential that chains to one of OUR anchors. Without this gate an answer
 * could ship its own freshly-minted signers and satisfy every signature check.
 * Mirrors Python _resolve_trust_signer. */
static bool _resolve_trust_signer(const process_t *proc, const char *voter,
                                  const public_identity_t *carried)
{
    peers_read_lock(proc);
    for (size_t i = 0; i < proc->protocol.num_peers; i++)
    {
        char uuid_str[UUID_STRING_LEN + 1];
        uuid_unparse_lower(proc->protocol.peers[i].uuid, uuid_str);
        if (strcmp(uuid_str, voter) == 0
            && processes_peer_is_member(proc, &proc->protocol.peers[i]))
        {
            peers_read_unlock(proc);
            return true;
        }
    }
    peers_read_unlock(proc);
    /* An admission authority (ZTA: zta/zta_identity.c) may vouch for a
     * stranger whose credential chains to an anchor we accept. Without one
     * an unknown signer cannot be trusted at all: refusing is the fail-safe
     * direction, so a build that cannot check credentials accepts no
     * evidence from signers it never admitted. */
    return identity_ext_credential_anchored(proc, carried);
}

/* Verify an answer to a query we made and record the result.
 *
 * Three gates, in order of what they buy: the window must reproduce the signed
 * root (which is what makes OMISSION detectable, since any edit to the entry
 * list moves the root away from the bytes a quorum signed); the co-signatures
 * must verify; and each signer must be trusted. NOT checked, and it cannot be
 * from this side: whether the signers are a MAJORITY of the answering group.
 * Quorum sizing needs that group's membership, and an opaque subtree is
 * precisely what does not disclose it.
 *
 * The recorded score is the one WE compute from the attested window, not the
 * number the holder sent: the holder's EMA is weighted by per-capability
 * weights that live in a node-local cache and are part of no hashed entry, so
 * it cannot be re-derived here. Mirrors Python _accept_resolved. */
static void _accept_resolved(const process_t *proc, const char *peer_str,
                             json_t *doc)
{
    tx_history_t parsed;
    tx_history_init(&parsed);
    rep_checkpoint_t ckpt = {0};
    if (reputation_evidence_from_json(doc, &parsed, &ckpt) != 0)
    {
        _record_resolved(peer_str, 0.0, false, false,
                         "malformed or hash-broken evidence document");
        tx_history_free(&parsed);
        return;
    }
    if (!ckpt.present || ckpt.root[0] == '\0')
    {
        _record_resolved(peer_str, 0.0, false, false,
                         "no checkpoint: the window is unattested");
        tx_history_free(&parsed);
        rep_checkpoint_free(&ckpt);
        return;
    }
    char recomputed[TX_HASH_HEX_LEN + 1];
    transaction_window_root(&parsed, recomputed);
    if (strcmp(recomputed, ckpt.root) != 0)
    {
        _record_resolved(peer_str, 0.0, false, false,
                         "window does not reproduce the signed root "
                         "(entries added, altered or withheld)");
        tx_history_free(&parsed);
        rep_checkpoint_free(&ckpt);
        return;
    }
    uint8_t desig[REP_DESIG_MAX];
    size_t dlen = rep_checkpoint_designation(
        ckpt.proposer_uuid, ckpt.root, ckpt.epoch, ckpt.first_index,
        ckpt.count, ckpt.group_uuid, desig, sizeof(desig));

    /* Signers the answer carried, by uuid, so a requestor holding no identity
     * from the answering group can still check a signature. */
    json_t *signers = json_object_get(doc, "signers");
    size_t verified_count = 0;
    array_t *voters = map_keys(&ckpt.sigs);
    size_t n_voters = array_size(voters);
    for (size_t vi = 0; dlen > 0 && vi < n_voters; vi++)
    {
        data_t *vd = NULL;
        map_key_t voter = NULL;
        if (array_get(voters, (int)vi, &vd) != 0
            || data_string_ptr(vd, &voter) != 0 || voter == NULL)
            continue;
        {
            data_t *sd = NULL;
            string_t sig_str = NULL;
            if (map_get(&ckpt.sigs, voter, &sd) != 0 || sd == NULL
                || data_string_ptr(sd, &sig_str) != 0)
                continue;
            const char *sig_hex = sig_str;
            public_identity_t carried = {0};
            bool have_carried = false;
            if (signers != NULL && json_is_array(signers))
            {
                size_t si;
                json_t *sv = NULL;
                json_array_foreach(signers, si, sv)
                {
                    public_identity_t cand = {0};
                    if (public_identity_from_json(sv, &cand) != 0)
                        continue;
                    char cand_str[UUID_STRING_LEN + 1];
                    uuid_unparse_lower(cand.uuid, cand_str);
                    if (strcmp(cand_str, voter) == 0)
                    {
                        memcpy(&carried, &cand, sizeof(public_identity_t));
                        have_carried = true;
                        break;
                    }
                }
            }
            bool sig_ok = _verify_cosignature(proc, voter, desig, dlen, sig_hex);
            if (!sig_ok && have_carried && sig_hex != NULL
                && strnlen(sig_hex, REP_SIG_HEX_LEN + 2) == REP_SIG_HEX_LEN)
            {
                unsigned char raw[crypto_sign_BYTES];
                if (unhexlify((const unsigned char *)sig_hex, REP_SIG_HEX_LEN,
                              raw) == 0)
                    sig_ok = crypto_sign_verify_detached(
                        raw, desig, dlen, carried.signature.public) == 0;
            }
            if (!sig_ok)
                continue;
            if (!_resolve_trust_signer(proc, voter,
                                       have_carried ? &carried : NULL))
                continue;
            verified_count++;
        }
    }
    /* voters is the map's own key index (map_keys): not ours to free */
    rep_checkpoint_free(&ckpt);
    if (verified_count < 1)
    {
        _record_resolved(peer_str, 0.0, false, false,
                         "0 signer(s) verified and trusted, needed 1");
        tx_history_free(&parsed);
        return;
    }
    char reason[192];
    snprintf(reason, sizeof(reason),
             "root reproduced; %zu signer(s) verified and trusted "
             "(quorum size not checkable across a boundary)", verified_count);
    uuid_t peer_uu;
    if (uuid_parse(peer_str, peer_uu) != 0)
    {
        _record_resolved(peer_str, 0.0, false, true, reason);
        tx_history_free(&parsed);
        return;
    }
    /* NULL weights: weight 1 for everything, the unweighted consensus over the
     * same attested entries. */
    double score = reputation_consensus(&parsed, peer_uu, NULL);
    _record_resolved(peer_str, score, true, true, reason);
    log_info(proc->logger, "Reputation: deep resolve of %.8s = %.4f (%s)\n",
             peer_str, score, reason);
    tx_history_free(&parsed);
}

size_t reputation_deep_resolve(const process_t *proc, const char *query_id,
                               const char *peer_uuid, int ttl)
{
    _ensure_init();
    if (proc == NULL || peer_uuid == NULL)
        return 0;
    char qid[128];
    if (query_id != NULL && query_id[0] != '\0')
        snprintf(qid, sizeof(qid), "%s", query_id);
    else
        snprintf(qid, sizeof(qid), "%.8s-%lld", peer_uuid,
                 (long long)(_resolve_now() * 1000.0));
    json_t *query = json_object();
    if (query == NULL)
        return 0;
    json_object_set_new(query, "query_id", json_string(qid));
    json_object_set_new(query, "peer_uuid", json_string(peer_uuid));
    json_object_set_new(query, "ttl",
                        json_integer(ttl > 0 ? ttl : REP_RESOLVE_TTL_DEFAULT));
    json_object_set_new(query, "requesting_process", json_string("reputation"));
    pthread_mutex_lock(&rep_state.lock);
    _mark_resolve_seen_locked(qid);
    _resolve_track(&rep_state.resolve_outstanding, qid, NULL, peer_uuid,
                   "reputation");
    pthread_mutex_unlock(&rep_state.lock);
    size_t sent = _forward_resolve(proc, query);
    json_decref(query);
    return sent;
}

bool reputation_resolved_get(const char *peer_uuid, double *score_out,
                             bool *have_score_out, bool *verified_out,
                             char *reason_out, size_t reason_cap)
{
    _ensure_init();
    if (peer_uuid == NULL)
        return false;
    bool found = false;
    pthread_mutex_lock(&rep_state.lock);
    data_t *d = NULL;
    if (map_get(&rep_state.resolved_reps, (map_key_t)peer_uuid, &d) == 0
        && d != NULL)
    {
        void *ptr = NULL;
        if (data_object_ptr(d, &ptr) == 0 && ptr != NULL)
        {
            rep_resolved_t *rec = (rep_resolved_t *)ptr;
            if (score_out != NULL)
                *score_out = rec->score;
            if (have_score_out != NULL)
                *have_score_out = rec->have_score;
            if (verified_out != NULL)
                *verified_out = rec->verified;
            if (reason_out != NULL && reason_cap > 0)
                snprintf(reason_out, reason_cap, "%s", rec->reason);
            found = true;
        }
    }
    pthread_mutex_unlock(&rep_state.lock);
    return found;
}

size_t reputation_resolve_pending_count(void)
{
    _ensure_init();
    pthread_mutex_lock(&rep_state.lock);
    size_t n = map_size(&rep_state.resolve_pending);
    pthread_mutex_unlock(&rep_state.lock);
    return n;
}

size_t reputation_resolve_outstanding_count(void)
{
    _ensure_init();
    pthread_mutex_lock(&rep_state.lock);
    size_t n = map_size(&rep_state.resolve_outstanding);
    pthread_mutex_unlock(&rep_state.lock);
    return n;
}

/* Answer a deep query, or relay it one level down. Never blocks awaiting a
 * child: the relay records who to answer and returns, and the answer is an
 * independent message that arrives (or does not) later. Mirrors Python
 * handle_resolve. */
static bool handle_resolve(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!nmsg->verified)
    {
        log_warn(proc->logger,
                 "Reputation: rejecting unverified rep_resolve from %s\n",
                 nmsg->from_whom.nickname);
        return true;
    }
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
        return true;
    const char *qid = json_string_value(json_object_get(payload, "query_id"));
    const char *peer_str = json_string_value(json_object_get(payload, "peer_uuid"));
    json_t *ttl_j = json_object_get(payload, "ttl");
    int ttl = (int)json_integer_value(ttl_j);
    const char *req_proc =
        json_string_value(json_object_get(payload, "requesting_process"));
    /* Bounded, not clamped: TTL is attacker-controlled and an inflated one is
     * an amplification lever, so an out-of-range query is refused outright
     * (Python resolve_query_from_dict raises for the same reason). */
    if (qid == NULL || peer_str == NULL || !json_is_integer(ttl_j)
        || ttl < 0 || ttl > REP_RESOLVE_TTL_MAX)
    {
        log_warn(proc->logger, "Reputation: malformed rep_resolve; dropped\n");
        json_decref(payload);
        return true;
    }
    char sender[UUID_STRING_LEN + 1];
    uuid_unparse_lower(nmsg->from_whom.uuid, sender);

    pthread_mutex_lock(&rep_state.lock);
    bool fresh = _mark_resolve_seen_locked(qid);
    pthread_mutex_unlock(&rep_state.lock);
    if (!fresh)
    {
        json_decref(payload);
        return true;   /* already handled: a loop, or a duplicate leg */
    }

    char chain_key[UUID_STRING_LEN + 1] = {0};
    pthread_mutex_lock(&rep_state.lock);
    bool held = _chain_holding_locked(peer_str, chain_key, sizeof(chain_key));
    pthread_mutex_unlock(&rep_state.lock);
    if (held)
    {
        json_t *answer = _resolve_answer(proc, qid, peer_str, chain_key);
        if (answer != NULL)
        {
            _send_resolved(proc, &nmsg->from_whom, answer, req_proc);
            json_decref(answer);
            json_decref(payload);
            return true;
        }
        /* Held the chain but cannot attest it: fall through so a deeper node
         * that can answers instead. */
    }
    if (_forward_resolve(proc, payload) > 0)
    {
        pthread_mutex_lock(&rep_state.lock);
        _resolve_track(&rep_state.resolve_pending, qid, sender, peer_str,
                       req_proc);
        pthread_mutex_unlock(&rep_state.lock);
    }
    json_decref(payload);
    return true;
}

/* Take an answer: relay it back one hop, or accept it if it is ours. An answer
 * for a query-id we never relayed and never sent is dropped unread -- on a
 * relay path answers are unsolicited by construction, so the pending table is
 * the only thing distinguishing one we are carrying from one injected. Mirrors
 * Python handle_resolved. */
static bool handle_resolved(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!nmsg->verified)
    {
        log_warn(proc->logger,
                 "Reputation: rejecting unverified rep_resolved from %s\n",
                 nmsg->from_whom.nickname);
        return true;
    }
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
        return true;
    const char *qid = json_string_value(json_object_get(payload, "query_id"));
    const char *peer_str = json_string_value(json_object_get(payload, "peer_uuid"));
    if (qid == NULL || peer_str == NULL)
    {
        json_decref(payload);
        return true;
    }
    rep_resolve_t relay = {0};
    pthread_mutex_lock(&rep_state.lock);
    bool relaying = _resolve_take_locked(&rep_state.resolve_pending, qid, &relay);
    pthread_mutex_unlock(&rep_state.lock);
    if (relaying)
    {
        peers_read_lock(proc);
        const public_identity_t *dest = NULL;
        for (size_t i = 0; i < proc->protocol.num_peers; i++)
        {
            char uuid_str[UUID_STRING_LEN + 1];
            uuid_unparse_lower(proc->protocol.peers[i].uuid, uuid_str);
            if (strcmp(uuid_str, relay.answer_to) == 0)
            {
                dest = &proc->protocol.peers[i];
                break;
            }
        }
        /* Relayed VERBATIM: the signatures are over bytes, and a re-encode
         * that reordered a key or renormalized a float would invalidate
         * evidence this node has no business invalidating. Relays carry, they
         * do not curate. */
        if (dest != NULL)
            _send_resolved(proc, dest, payload, relay.req_proc);
        else
            log_warn(proc->logger,
                     "Reputation: cannot relay answer %.8s; %.8s no longer "
                     "known\n", qid, relay.answer_to);
        peers_read_unlock(proc);
        json_decref(payload);
        return true;
    }

    rep_resolve_t mine = {0};
    pthread_mutex_lock(&rep_state.lock);
    bool ours = _resolve_take_locked(&rep_state.resolve_outstanding, qid, &mine);
    pthread_mutex_unlock(&rep_state.lock);
    if (!ours)
    {
        log_debug(proc->logger,
                  "Reputation: unsolicited rep_resolved %.8s; dropped\n", qid);
        json_decref(payload);
        return true;
    }
    _accept_resolved(proc, peer_str, payload);
    json_decref(payload);
    return true;
}

static bool handle_checkpoint_final(const process_t *proc, directory_t *queues, generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    if (!nmsg->verified)
    {
        log_warn(proc->logger,
                 "Reputation: rejecting unverified checkpoint_final from %s\n",
                 nmsg->from_whom.nickname);
        return true;
    }
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || payload == NULL)
        return false;
    const char *root = json_string_value(json_object_get(payload, "root"));
    int64_t epoch = json_integer_value(json_object_get(payload, "epoch"));
    const char *proposer_str =
        json_string_value(json_object_get(payload, "proposer_uuid"));
    int64_t first_index =
        json_integer_value(json_object_get(payload, "first_index"));
    int64_t count_covered =
        json_integer_value(json_object_get(payload, "count"));
    if (root == NULL)
    {
        json_decref(payload);
        return false;
    }
    /* The chain this checkpoint covers, normalized through our own view (doc/architecture/gateway-reputation-tree.md).
     * Both the signed designation and the quorum size depend on it. */
    char final_chain[UUID_STRING_LEN + 1];
    _chain_key(proc, json_string_value(json_object_get(payload, "group_uuid")),
               final_chain, sizeof(final_chain));
    /* Verify the retained co-signatures before storing the root. This root is
     * the anchor _verify_slash_evidence measures slash evidence against,
     * expressly so the root is "not chosen by the accuser" — which only holds
     * if a quorum is checked here. */
    {
        uint8_t desig[REP_DESIG_MAX];
        size_t dlen = (proposer_str != NULL)
            ? rep_checkpoint_designation(proposer_str, root, epoch, first_index,
                                         count_covered, final_chain, desig,
                                         sizeof(desig))
            : 0;
        json_t *sigs = json_object_get(payload, "sigs");
        if (dlen == 0 || !_ckpt_quorum_met_for(proc, sigs, desig, dlen, final_chain))
        {
            log_warn(proc->logger,
                     "Reputation: rejecting checkpoint_final epoch=%lld: %zu "
                     "verified co-signature(s) do not meet quorum\n",
                     (long long)epoch,
                     dlen == 0 ? (size_t)0
                               : _verified_cosigners(proc, sigs, desig, dlen));
            json_decref(payload);
            return true;
        }
    }
    /* Stores the window bounds and the co-signatures alongside the root, and
     * persists the evidence: this is the instant at which the resident window
     * and an agreed root describe each other (doc/architecture/reputation.md). */
    _store_checkpoint(proc, proposer_str, root, epoch, (int)first_index,
                      (int)count_covered, final_chain,
                      json_object_get(payload, "sigs"));
    log_info(proc->logger, "Reputation: checkpoint stored epoch=%lld root=%.12s\n",
             (long long)epoch, root);

    /* Outvoted: the group finalized a window our own entries do not
     * reproduce. Ask the finalizer for its chain from the window's start, and
     * handle_update adopts it (see _outvoted_locked). Without this an order
     * fork at EQUAL length never reconciles at all: catch-up runs only when a
     * Paxos grant finds the lengths differ, and here they never do, so the
     * fork persists silently (moderation cohort mod-2537396 and mod-2538837,
     * 2026-09-23: carol forked at index 20-22 for the rest of both runs). */
    bool outvoted = false;
    if (final_chain[0] == '\0')
    {
        tx_attested_t att;
        pthread_mutex_lock(&rep_state.lock);
        outvoted = _outvoted_locked(&att);
        pthread_mutex_unlock(&rep_state.lock);
    }
    if (outvoted)
    {
        generic_msg_t req = {0};
        req.type = NET_MESSAGE;
        strncpy(req.info.net_msg.process, "reputation", PROC_NAME_LEN);
        req.info.net_msg.function = REP_PROTO_OUTDATED;
        req.info.net_msg.encrypt = true;
        memcpy(&req.info.net_msg.to_whom, &nmsg->from_whom,
               sizeof(public_identity_t));
        strncpy(req.info.net_msg.return_to, "reputation", PROC_NAME_LEN);
        /* The index to send from: a Python peer answers with era(index). */
        json_t *from = json_integer(first_index);
        net_msg_pack_json(&req.info.net_msg, from);
        json_decref(from);
        log_info(proc->logger,
                 "Reputation: our chain does not reproduce checkpoint epoch=%lld "
                 "(indices %lld-%lld); requesting %s's chain\n",
                 (long long)epoch, (long long)first_index,
                 (long long)(first_index + count_covered - 1),
                 nmsg->from_whom.nickname);
        _rep_send_to_network(proc, &req);
        net_msg_free_obj(&req.info.net_msg);
    }
    json_decref(payload);
    return true;
}

/****************************
 * Verifiable warm start (doc/architecture/reputation.md)
 *
 * Mirrors Python repprocess._persist_history / _rebuild_from_evidence /
 * _attested_ceilings / _grade_restored_reputations / _maybe_checkpoint, and
 * reads and writes the SAME `reputation-history.cfg.json` document (plain JSON,
 * schema-pinned — see reputation.h REP_EVIDENCE_*).
 ****************************/

/* --- Operational snapshot (`reputation.cfg.json`) -------------------------
 *
 * C had no reputation persistence at all before this: nothing wrote the
 * snapshot and nothing read it, so a C node always cold-started and there was
 * no warm start for the evidence above to make verifiable.
 *
 * Written as plain JSON rather than through the config-registry framework, and
 * carrying Python's `__type__` tag rather than C's `typename`, for one reason:
 * warm-start state is the SAME state in both runtimes, so a node of either kind
 * should be able to resume from a snapshot the other wrote. That is the same
 * argument that keeps the wire protocol strings byte-identical to Python's enum
 * values — the identifier is a shared constant, not a language artifact. The
 * reader tolerates the tag being absent.
 *
 * Only peers strictly above the persist threshold survive a restart, mirroring
 * Python's two-sided filter (see doc/architecture/persistent-cohort.md). Self
 * is always kept. */
#define REP_PERSIST_THRESHOLD_DEFAULT 0.5
#define REP_PERSIST_THRESHOLD \
    (reputation_env_double("AT_REP_PERSIST_THRESHOLD", \
                           REP_PERSIST_THRESHOLD_DEFAULT))
#define REP_SNAPSHOT_TYPE \
    "autonomous_trust.core._python.reputation.reputation.Reputations"

static int _snapshot_path(char *out, size_t cap)
{
    char cfg_dir[CFG_PATH_LEN + 1] = {0};
    if (get_cfg_dir(cfg_dir, sizeof(cfg_dir)) < 0)
        return -1;
    int n = snprintf(out, cap, "%s/%s%s", cfg_dir, REP_SNAPSHOT_FILE,
                     CFG_FILE_EXT);
    if (n < 0 || (size_t)n >= cap)
        return -1;
    return 0;
}

/* Load the persisted operational snapshot into rep_state.reputations.
 * Absent/unreadable is a cold start, not an error. */
static void _load_reputations(const process_t *proc)
{
    char path[CFG_PATH_LEN + 64] = {0};
    if (_snapshot_path(path, sizeof(path)) != 0)
        return;
    json_error_t jerr;
    json_t *doc = json_load_file(path, 0, &jerr);
    if (doc == NULL)
        return;
    json_t *current = json_object_get(doc, "current");
    int loaded = 0;
    if (json_is_object(current))
    {
        const char *key;
        json_t *val;
        json_object_foreach(current, key, val)
        {
            if (!json_is_number(val))
                continue;
            uuid_t u;
            if (uuid_parse(key, u) != 0)
                continue;
            pthread_mutex_lock(&rep_state.lock);
            reputations_update(&rep_state.reputations, u,
                               json_number_value(val));
            pthread_mutex_unlock(&rep_state.lock);
            loaded++;
        }
    }
    json_decref(doc);
    if (loaded > 0)
        log_info(proc->logger,
                 "Reputation: warm start loaded %d persisted peer score(s)\n",
                 loaded);
}

/* Write the operational snapshot. Failure is logged and swallowed — a node that
 * cannot persist should keep running, it simply cold-starts next time. */
static void _persist_reputations(const process_t *proc)
{
    char path[CFG_PATH_LEN + 64] = {0};
    if (_snapshot_path(path, sizeof(path)) != 0)
        return;
    json_t *current = json_object();
    if (current == NULL)
        return;
    double threshold = REP_PERSIST_THRESHOLD;
    pthread_mutex_lock(&rep_state.lock);
    map_key_t key = NULL;
    data_t *val = NULL;
    map_entries_for_each(&rep_state.reputations.scores, key, val)
    {
        double score = 0.0;
        if (data_floating_pt_dbl(val, &score) != 0)
            continue;
        if (score <= threshold)
            continue;
        json_object_set_new(current, key, json_real(score));
    }
    map_end_for_each
    pthread_mutex_unlock(&rep_state.lock);
    json_t *doc = json_pack("{s:s, s:o}", "__type__", REP_SNAPSHOT_TYPE,
                            "current", current);
    if (doc == NULL)
    {
        json_decref(current);
        return;
    }
    /* Rewritten after every score, so write-then-rename: a reader (or a
     * restart after a crash mid-write) sees the old snapshot or the new one,
     * never a truncated file that would cold-start the node. */
    char tmp[sizeof(path) + 8] = {0};
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    if (json_dump_file(doc, tmp, JSON_INDENT(2)) != 0 || rename(tmp, path) != 0)
    {
        unlink(tmp);
        log_warn(proc->logger,
                 "Reputation: could not persist snapshot to %s\n", path);
    }
    json_decref(doc);
}

/* Path of one chain's evidence document, or -1 if it does not fit.
 *
 * One file per chain rather than one file holding every chain: it mirrors the
 * group_child_<name>.cfg.json convention already used for child groups, keeps
 * the primary file's shape byte-for-byte what it was, and means a corrupt or
 * stale child file costs that subtree its attestation and nothing else. */
static int _evidence_path(const char *chain_key, char *out, size_t cap)
{
    char cfg_dir[CFG_PATH_LEN + 1] = {0};
    if (get_cfg_dir(cfg_dir, sizeof(cfg_dir)) < 0)
        return -1;
    int n;
    if (chain_key != NULL && chain_key[0] != '\0')
        n = snprintf(out, cap, "%s/%s-%s%s", cfg_dir, REP_EVIDENCE_FILE,
                     chain_key, CFG_FILE_EXT);
    else
        n = snprintf(out, cap, "%s/%s%s", cfg_dir, REP_EVIDENCE_FILE,
                     CFG_FILE_EXT);
    if (n < 0 || (size_t)n >= cap)
        return -1;
    return 0;
}

/* Snapshot one chain's finalized checkpoint. Caller holds the lock. */
static void _current_checkpoint_locked(const char *chain_key,
                                       rep_checkpoint_t *out)
{
    rep_chain_ckpt_t *slot = _ckpt_slot_locked(chain_key);
    out->present = (slot != NULL && slot->set);
    if (!out->present)
        return;
    snprintf(out->proposer_uuid, sizeof(out->proposer_uuid), "%s",
             slot->proposer);
    snprintf(out->root, sizeof(out->root), "%s", slot->root);
    snprintf(out->group_uuid, sizeof(out->group_uuid), "%s",
             (chain_key == NULL) ? "" : chain_key);
    out->epoch = slot->epoch;
    out->first_index = slot->first_index;
    out->count = slot->count;
    map_key_t key = NULL;
    data_t *val = NULL;
    map_entries_for_each(&slot->sigs_final, key, val)
    {
        string_t sig = NULL;
        if (data_string_ptr(val, &sig) == 0 && sig != NULL)
            map_set(&out->sigs, key, string_data(sig, strlen(sig)));
    }
    map_end_for_each
}

/* Write the evidence behind the reputation snapshot: the resident hash-linked
 * window plus the quorum-signed checkpoint over it.
 *
 * Called from the checkpoint-store path, and deliberately only there: at that
 * instant the resident window and the agreed root describe each other. Writing
 * on every commit would be both hotter and LESS useful, since a chain that has
 * moved past its checkpoint is exactly a chain the rebuild cannot attest.
 *
 * Failure is logged and swallowed. The evidence is an optimization of trust —
 * its absence costs a warm start its elevated tiers and nothing else — so it
 * must never be able to take down the reputation process. */
/* The evidence document for chain @p chain_key: its window, its finalized
 * checkpoint and, only when there are any, its equivocation records, so a node
 * that never saw one writes the document it always did. Mirrors Python
 * evidence_to_dict. Caller holds rep_state.lock. */
static int _evidence_doc_locked(const char *chain_key, json_t **out)
{
    rep_checkpoint_t ckpt;
    if (rep_checkpoint_init(&ckpt) != 0)
        return -1;
    _current_checkpoint_locked(chain_key, &ckpt);
    int err = reputation_evidence_to_json(_chain_for_key_locked(chain_key),
                                          &ckpt, out);
    rep_checkpoint_free(&ckpt);
    rep_chain_ckpt_t *slot = err == 0 ? _ckpt_slot_locked(chain_key) : NULL;
    if (*out != NULL && slot != NULL && json_array_size(slot->forks) > 0)
        json_object_set_new(*out, "forks", json_deep_copy(slot->forks));
    return err;
}

static void _persist_history(const process_t *proc, const char *chain_key)
{
    char path[CFG_PATH_LEN + 64] = {0};
    if (_evidence_path(chain_key, path, sizeof(path)) != 0)
    {
        log_warn(proc->logger,
                 "Reputation: cannot build evidence path; not persisting\n");
        return;
    }
    json_t *doc = NULL;
    pthread_mutex_lock(&rep_state.lock);
    int err = _evidence_doc_locked(chain_key, &doc);
    pthread_mutex_unlock(&rep_state.lock);
    if (err != 0 || doc == NULL)
    {
        log_warn(proc->logger, "Reputation: could not build evidence doc\n");
        return;
    }
    if (json_dump_file(doc, path, JSON_INDENT(2)) != 0)
        log_warn(proc->logger,
                 "Reputation: could not persist evidence to %s\n", path);
    json_decref(doc);
}

/* Path of the slash replay-mark file. */
static int _slash_marks_path(char *out, size_t cap)
{
    char cfg_dir[CFG_PATH_LEN + 1] = {0};
    if (get_cfg_dir(cfg_dir, sizeof(cfg_dir)) < 0)
        return -1;
    int n = snprintf(out, cap, "%s/%s%s", cfg_dir, REP_SLASH_MARKS_FILE,
                     CFG_FILE_EXT);
    if (n < 0 || (size_t)n >= cap)
        return -1;
    return 0;
}

/* Write the per-(target, slasher) slash high-water marks.
 *
 * Unlike the chain evidence, this is NOT an optimization of trust: the marks
 * are what stop a superseded slash from being replayed into a sticky
 * exclusion, so losing them reopens that window. A failure is therefore
 * logged at warning — but still swallowed, because the alternative is taking
 * the reputation process down over a full disk and leaving the node with no
 * reputation at all.
 *
 * The map keys are already the flat "target:slasher" form, so the document is
 * a direct dump of them. Mirrors Python _persist_slash_marks. */
static void _persist_slash_marks(const process_t *proc)
{
    char path[CFG_PATH_LEN + 64] = {0};
    if (_slash_marks_path(path, sizeof(path)) != 0)
    {
        log_warn(proc->logger,
                 "Reputation: cannot build slash-marks path; not persisting\n");
        return;
    }
    json_t *doc = json_object();
    if (doc == NULL)
        return;
    pthread_mutex_lock(&rep_state.lock);
    map_key_t key = NULL;
    data_t *val = NULL;
    map_entries_for_each(&rep_state.slash_hw, key, val)
    {
        int epoch = 0;
        if (data_integer(val, &epoch) == 0)
            json_object_set_new(doc, (const char *)key,
                                json_integer((json_int_t)epoch));
    }
    map_end_for_each
    pthread_mutex_unlock(&rep_state.lock);
    if (json_dump_file(doc, path, JSON_INDENT(2)) != 0)
        log_warn(proc->logger,
                 "Reputation: could not persist slash marks to %s\n", path);
    json_decref(doc);
}

/* Restore the marks and resume our own slash epoch past them.
 *
 * A missing file is the cold-start case and not an error: the marks are empty
 * and the first slash from any slasher is accepted, which is the only
 * behaviour a node with no history can have. A CORRUPT file is different — it
 * is refused loudly and left in place rather than being silently treated as
 * empty, because "no marks" is exactly the state an attacker would want to
 * induce.
 *
 * Resuming rep_state.slash_epoch matters as much as the marks themselves:
 * peers hold high-water marks that our restart does not reset, so a detector
 * that began again at epoch 1 would have its next slashes refused as replays
 * — the same trap _rebuild_from_evidence documents for checkpoint epochs.
 * Mirrors Python _load_slash_marks.
 *
 * NOTE: this runtime does not ORIGINATE slashes yet (nothing increments
 * rep_state.slash_epoch — there is no forward_slash twin), so the resume half
 * is currently inert while the receive guard above is not. It is written now
 * because a detector added later must not silently rewind its epochs, and
 * because a node self-applying its own slash is what puts its own epochs in
 * this file in the first place. */
static void _load_slash_marks(const process_t *proc)
{
    char path[CFG_PATH_LEN + 64] = {0};
    if (_slash_marks_path(path, sizeof(path)) != 0)
        return;
    json_error_t err;
    json_t *doc = json_load_file(path, 0, &err);
    if (doc == NULL)
        return;  /* absent (cold start) or unreadable; nothing to restore */
    if (!json_is_object(doc))
    {
        log_error(proc->logger,
                  "Reputation: slash marks malformed (%s); replay protection "
                  "for slashes starts from empty this boot\n", path);
        json_decref(doc);
        return;
    }
    uuid_t self_uuid;
    char self_str[UUID_STRING_LEN + 1] = {0};
    bool have_self = _resolve_self_uuid(proc, self_uuid);
    if (have_self)
        uuid_unparse_lower(self_uuid, self_str);

    size_t restored = 0;
    int64_t own_high = 0;
    pthread_mutex_lock(&rep_state.lock);
    const char *k = NULL;
    json_t *v = NULL;
    json_object_foreach(doc, k, v)
    {
        if (!json_is_integer(v))
            continue;
        int64_t epoch = (int64_t)json_integer_value(v);
        map_set(&rep_state.slash_hw, (map_key_t)k, integer_data((int)epoch));
        restored++;
        /* Our OWN emitted epochs are in here because a detector self-applies
         * its slashes, which is what makes one file serve both the receive
         * guard and the resume point. */
        if (have_self)
        {
            const char *sep = strrchr(k, ':');
            if (sep != NULL && strcmp(sep + 1, self_str) == 0
                && epoch > own_high)
                own_high = epoch;
        }
    }
    if (own_high > rep_state.slash_epoch)
        rep_state.slash_epoch = own_high;
    pthread_mutex_unlock(&rep_state.lock);
    json_decref(doc);
    log_debug(proc->logger,
              "Reputation: slash marks restored: %zu pair(s), own epoch "
              "resumed at %lld\n", restored, (long long)rep_state.slash_epoch);
}

/* Record a finalized checkpoint (root + window bounds + the co-signatures that
 * finalized it) and persist the evidence beside it.
 *
 * The co-signatures are retained past the live round on purpose: at boot the
 * rebuild has to verify the same quorum a live receiver does. A fuller
 * signature set for the checkpoint we already hold is an UPGRADE, not a
 * duplicate — the proposer self-stores holding only its own signature, and the
 * quorum map only exists a round later. */
/* Durable attested records (doc/architecture/reputation.md, "Verifier-attested
 * scores"): one etc/at/attested/<task>.json per attested entry a quorum-signed
 * checkpoint covers, written once and never rewritten. The resident window
 * holds MAX_CHAIN_LEN entries and the evidence file is rewritten at every
 * checkpoint, so both soon lose an attested entry; an application that shows
 * a finding for longer (Stele's repo standing) reads it from here. A record
 * carries everything a verifier needs on its own: the entry with its quorum
 * certificate, the checkpoint and its signatures, the inclusion proof, the
 * public keys of every signer THIS node held, and the group sizes both quorums
 * count against. Mirrors Python _archive_attested / attested_record, whose
 * verify_attested_record checks it. */
#define REP_ATTESTED_DIR "attested"

typedef struct {
    char        task[UUID_STRING_LEN + 1];
    char        subject[UUID_STRING_LEN + 1];
    json_t     *proof;     /* [{sibling, left}] */
    json_t     *cert;      /* {voter: sig} */
    size_t      group_size; /* the group its certificate was judged against */
} rep_archive_item_t;

static int _archive_path(const char *task, char *out, size_t cap)
{
    char cfg_dir[CFG_PATH_LEN + 1] = {0};
    if (get_cfg_dir(cfg_dir, sizeof(cfg_dir)) < 0)
        return -1;
    int n = (task == NULL)
        ? snprintf(out, cap, "%s/%s", cfg_dir, REP_ATTESTED_DIR)
        : snprintf(out, cap, "%s/%s/%s.json", cfg_dir, REP_ATTESTED_DIR, task);
    return (n < 0 || (size_t)n >= cap) ? -1 : 0;
}

/* Add @p voter's public key to @p signers when this node holds one. */
static void _archive_signer(const process_t *proc, json_t *signers,
                            const char *voter)
{
    if (json_object_get(signers, voter) != NULL)
        return;
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    if (!_cosigner_pubkey(proc, voter, pk))
        return;
    char hex[crypto_sign_PUBLICKEYBYTES * 2 + 1];
    sodium_bin2hex(hex, sizeof(hex), pk, sizeof(pk));
    json_object_set_new(signers, voter, json_string(hex));
}

static void _archive_attested(const process_t *proc, const char *chain_key)
{
    if (proc == NULL)
        return;
    bool primary = (chain_key == NULL || chain_key[0] == '\0');
    peers_read_lock(proc);
    size_t roster = _ckpt_roster_for_group(proc, primary ? NULL : chain_key);
    size_t members = _member_count(proc) + 1;
    peers_read_unlock(proc);

    rep_archive_item_t items[MAX_CHAIN_LEN];
    int n_items = 0;
    json_t *doc = NULL;
    rep_checkpoint_t ckpt;
    if (rep_checkpoint_init(&ckpt) != 0)
        return;
    pthread_mutex_lock(&rep_state.lock);
    rep_chain_ckpt_t *slot = _ckpt_slot_locked(chain_key);
    /* Only while our resident window reproduces the signed root: a node still
     * on a fork the quorum did not sign would otherwise prove its own entries
     * against that root, and a record is written once and never rewritten.
     * The next checkpoint stored after the chain converges archives them. */
    char mine[TX_HASH_HEX_LEN + 1] = {0};
    if (slot != NULL && slot->set && slot->count > 0
        && map_size(&slot->sigs_final) > (roster + 1) / 2
        && tx_history_range_root(_chain_for_key_locked(chain_key),
                                 slot->first_index, slot->count, mine) == 0
        && strcmp(mine, slot->root) == 0)
    {
        tx_history_t *chain = _chain_for_key_locked(chain_key);
        for (int i = 0; i < chain->chain_len && n_items < MAX_CHAIN_LEN; i++)
        {
            const transaction_t *t = &chain->chain[i];
            if (!t->attested || t->index < slot->first_index
                || t->index >= slot->first_index + slot->count)
                continue;
            rep_archive_item_t *it = &items[n_items];
            uuid_unparse_lower(t->task_uuid, it->task);
            char path[CFG_PATH_LEN + 128];
            if (_archive_path(it->task, path, sizeof(path)) != 0
                || access(path, F_OK) == 0)
                continue;
            const char *cert = tx_history_attest_cert(chain, t->task_uuid);
            tx_merkle_step_t steps[MAX_CHAIN_LEN];
            int n_steps = 0;
            if (cert == NULL
                || tx_history_range_proof(chain, slot->first_index, slot->count,
                                          t->index, steps, &n_steps) != 0)
                continue;
            it->cert = json_loads(cert, 0, NULL);
            if (!json_is_object(it->cert) || json_object_size(it->cert) == 0)
            {
                json_decref(it->cert);
                continue;
            }
            it->proof = json_array();
            for (int k = 0; k < n_steps; k++)
                json_array_append_new(it->proof, json_pack(
                    "{s:s, s:b}", "sibling", steps[k].sibling,
                    "left", steps[k].sibling_is_left));
            uuid_unparse_lower(t->subject_uuid, it->subject);
            /* The group the certificate was made in: the roster in force at
             * the entry's index when the chain logs one (AT §2.48), not
             * today's, which a later join has grown. A late joiner archiving
             * history certified by a smaller group otherwise wrote a size its
             * certificate never had to meet (Stele red team rt-3765724,
             * phase 7b). The live count where the chain holds no roster. */
            json_t *in_force = _roster_at_locked(chain_key, t->index);
            it->group_size = json_is_array(in_force) && json_array_size(in_force) > 0
                ? json_array_size(in_force) : members;
            json_decref(in_force);
            n_items++;
        }
        if (n_items > 0)
        {
            _current_checkpoint_locked(chain_key, &ckpt);
            if (reputation_evidence_to_json(chain, &ckpt, &doc) != 0)
                doc = NULL;
        }
    }
    pthread_mutex_unlock(&rep_state.lock);
    rep_checkpoint_free(&ckpt);

    char dir[CFG_PATH_LEN + 64];
    if (n_items > 0 && doc != NULL && _archive_path(NULL, dir, sizeof(dir)) == 0)
        (void)mkdir(dir, 0755);
    json_t *doc_chain = doc != NULL ? json_object_get(doc, "chain") : NULL;
    json_t *doc_ckpt = doc != NULL ? json_object_get(doc, "checkpoint") : NULL;
    for (int i = 0; i < n_items; i++)
    {
        rep_archive_item_t *it = &items[i];
        json_t *entry = NULL;
        size_t ci;
        json_t *ce;
        json_array_foreach(doc_chain, ci, ce)
        {
            const char *tid = json_string_value(json_object_get(ce, "task_id"));
            if (tid != NULL && strcmp(tid, it->task) == 0)
            {
                entry = ce;
                break;
            }
        }
        if (entry != NULL && json_is_object(doc_ckpt))
        {
            json_t *signers = json_object();
            const char *voter;
            json_t *v;
            json_object_foreach(it->cert, voter, v)
                _archive_signer(proc, signers, voter);
            json_object_foreach(json_object_get(doc_ckpt, "sigs"), voter, v)
                _archive_signer(proc, signers, voter);
            json_t *entry_copy = json_deep_copy(entry);
            if (json_object_get(entry_copy, "attest_sigs") == NULL)
                json_object_set(entry_copy, "attest_sigs", it->cert);
            json_t *rec = json_pack(
                "{s:s, s:o, s:O, s:O, s:o, s:I, s:I, s:b}",
                "schema", "1", "entry", entry_copy, "checkpoint", doc_ckpt,
                "proof", it->proof, "signers", signers,
                "group_size", (json_int_t)it->group_size,
                "ckpt_group_size", (json_int_t)(roster + 1),
                "subject_member", _is_member(proc, it->subject));
            /* The subject's teammates this node left out of the quorum (§2.54).
             * Informational: a reader verifies against its own team roster. */
            json_t *excluded = json_array();
            if (rec != NULL && _conflicted_members(proc, it->subject, excluded) > 0)
                json_object_set(rec, "excluded", excluded);
            json_decref(excluded);
            char path[CFG_PATH_LEN + 128], tmp[CFG_PATH_LEN + 136];
            if (rec != NULL && _archive_path(it->task, path, sizeof(path)) == 0)
            {
                snprintf(tmp, sizeof(tmp), "%s.tmp", path);
                if (json_dump_file(rec, tmp, JSON_INDENT(2)) == 0
                    && rename(tmp, path) == 0)
                    log_info(proc->logger, "Reputation: archived attested entry "
                             "%.8s (subject %.8s)\n", it->task, it->subject);
                else
                    log_warn(proc->logger, "Reputation: could not archive "
                             "attested entry %.8s\n", it->task);
            }
            json_decref(rec);
        }
        json_decref(it->proof);
        json_decref(it->cert);
    }
    json_decref(doc);
}

/* The roster a reader of etc/at/attested/ verifies against: every member
 * this node has held (uuid -> signing key, when first and last seen, the
 * effective tier last published, whether it is a member now) and the final
 * checkpoints it stored, newest last. An attested record carries the signers'
 * keys itself, and that is what a forger would write too, so a verifier that
 * takes its keys from here instead is checking the record against THIS node's
 * view of its group (doc/architecture/reputation.md, "Verifier-attested
 * scores"). A member who leaves is kept, marked, so a record it signed while a
 * member still verifies. Written after every stored checkpoint, beside the
 * archive it anchors; atomic, failure logged and swallowed. Mirrors Python
 * repprocess._persist_roster. */
#define REP_ROSTER_FILE "roster.cfg.json"
#define REP_ROSTER_CKPTS 256

static void _persist_roster(const process_t *proc, const char *chain_key)
{
    if (proc == NULL)
        return;
    char cfg_dir[CFG_PATH_LEN + 1] = {0};
    if (get_cfg_dir(cfg_dir, sizeof(cfg_dir)) < 0)
        return;
    char path[CFG_PATH_LEN + 64], tmp[CFG_PATH_LEN + 72];
    snprintf(path, sizeof(path), "%s/%s", cfg_dir, REP_ROSTER_FILE);
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);

    json_t *doc = json_load_file(path, 0, NULL);
    if (!json_is_object(doc))
    {
        json_decref(doc);
        doc = json_object();
    }
    json_t *members = json_object_get(doc, "members");
    if (!json_is_object(members))
    {
        members = json_object();
        json_object_set_new(doc, "members", members);
    }
    json_t *ckpts = json_object_get(doc, "checkpoints");
    if (!json_is_array(ckpts))
    {
        ckpts = json_array();
        json_object_set_new(doc, "checkpoints", ckpts);
    }
    json_int_t now = (json_int_t)time(NULL);
    const char *k;
    json_t *v;
    json_object_foreach(members, k, v)
        json_object_set_new(v, "member", json_false());

    char group[UUID_STRING_LEN + 1];
    uuid_unparse_lower(proc->protocol.group.uuid, group);
    json_object_set_new(doc, "schema", json_string("1"));
    json_object_set_new(doc, "group_uuid", json_string(group));

    /* Snapshot uuid -> key under the peers lock; tiers come from rep_state. */
    size_t n = 0;
    char (*ids)[UUID_STRING_LEN + 1] = NULL;
    char (*keys)[crypto_sign_PUBLICKEYBYTES * 2 + 1] = NULL;
    peers_read_lock(proc);
    size_t cap = proc->protocol.num_peers + 1;
    ids = calloc(cap, sizeof(*ids));
    keys = calloc(cap, sizeof(*keys));
    if (ids != NULL && keys != NULL)
    {
        const identity_t *self = identity_self_identity(proc);
        if (self != NULL)
        {
            uuid_unparse_lower(self->uuid, ids[n]);
            sodium_bin2hex(keys[n], sizeof(keys[n]), self->signature.public,
                           crypto_sign_PUBLICKEYBYTES);
            json_object_set_new(doc, "self", json_string(ids[n]));
            n++;
        }
        for (size_t i = 0; i < proc->protocol.num_peers && n < cap; i++)
        {
            if (!processes_peer_is_member(proc, &proc->protocol.peers[i]))
                continue;
            uuid_unparse_lower(proc->protocol.peers[i].uuid, ids[n]);
            sodium_bin2hex(keys[n], sizeof(keys[n]),
                           proc->protocol.peers[i].signature.public,
                           crypto_sign_PUBLICKEYBYTES);
            n++;
        }
    }
    peers_read_unlock(proc);

    pthread_mutex_lock(&rep_state.lock);
    for (size_t i = 0; i < n; i++)
    {
        json_t *m = json_object_get(members, ids[i]);
        const char *old = json_string_value(json_object_get(m, "pubkey"));
        if (m == NULL || (old != NULL && strcmp(old, keys[i]) != 0))
        {
            /* A new member, or a uuid whose key changed: a changed key is a
             * new identity, so its history starts again. */
            m = json_object();
            json_object_set_new(members, ids[i], m);
        }
        /* first_seen is the tenure clock's start when this node holds one for
         * this key (doc/architecture/reputation.md, "Tenure"), so the file and
         * the gate never disagree; else now, as before. */
        data_t *since_d = NULL, *key_d = NULL;
        string_t since_key = NULL;
        double since = -1.0;
        bool held = map_get(&rep_state.member_since, (map_key_t)ids[i], &since_d) == 0
            && map_get(&rep_state.member_key, (map_key_t)ids[i], &key_d) == 0
            && data_floating_pt_dbl(since_d, &since) == 0 && since >= 0.0
            && data_string_ptr(key_d, &since_key) == 0 && since_key != NULL
            && strcmp(since_key, keys[i]) == 0;
        if (held)
            json_object_set_new(m, "first_seen", json_integer((json_int_t)since));
        else if (!json_is_integer(json_object_get(m, "first_seen")))
            json_object_set_new(m, "first_seen", json_integer(now));
        json_object_set_new(m, "pubkey", json_string(keys[i]));
        json_object_set_new(m, "last_seen", json_integer(now));
        json_object_set_new(m, "member", json_true());
        int tier = -1;
        data_t *d = NULL;
        if (map_get(&rep_state.peer_tiers, (map_key_t)ids[i], &d) == 0 && d != NULL)
            data_integer(d, &tier);
        if (tier >= 0)
            json_object_set_new(m, "tier", json_integer(tier));
        else
            json_object_del(m, "tier");
    }
    rep_chain_ckpt_t *slot = _ckpt_slot_locked(chain_key);
    if (slot != NULL && slot->set)
    {
        const char *gk = (chain_key == NULL) ? "" : chain_key;
        bool dup = false;
        size_t ci;
        json_t *ce;
        json_array_foreach(ckpts, ci, ce)
        {
            const char *g = json_string_value(json_object_get(ce, "group_uuid"));
            if (json_integer_value(json_object_get(ce, "epoch")) == slot->epoch
                && g != NULL && strcmp(g, gk) == 0)
            {
                json_object_set_new(ce, "root", json_string(slot->root));
                json_object_set_new(ce, "first_index", json_integer(slot->first_index));
                json_object_set_new(ce, "count", json_integer(slot->count));
                dup = true;
                break;
            }
        }
        if (!dup)
            json_array_append_new(ckpts, json_pack(
                "{s:s, s:I, s:s, s:i, s:i}", "group_uuid", gk,
                "epoch", (json_int_t)slot->epoch, "root", slot->root,
                "first_index", slot->first_index, "count", slot->count));
        while (json_array_size(ckpts) > REP_ROSTER_CKPTS)
            json_array_remove(ckpts, 0);
    }
    pthread_mutex_unlock(&rep_state.lock);
    free(ids);
    free(keys);

    if (json_dump_file(doc, tmp, JSON_INDENT(2)) != 0 || rename(tmp, path) != 0)
        log_warn(proc->logger, "Reputation: could not write %s\n", REP_ROSTER_FILE);
    json_decref(doc);
}

static void _store_checkpoint(const process_t *proc, const char *proposer,
                              const char *root, int64_t epoch,
                              int first_index, int count,
                              const char *chain_key, json_t *sigs)
{
    if (proposer == NULL || root == NULL)
        return;
    size_t incoming = json_is_object(sigs) ? json_object_size(sigs) : 0;
    bool primary = (chain_key == NULL || chain_key[0] == '\0');
    /* Every caller has verified the signatures it passes (our own proposal
     * carries one, ours), so their number is what attests the checkpoint. */
    size_t quorum = 0;
    if (proc != NULL)
    {
        int f = tx_byzantine_f(_n_min_in_force(proc, primary ? NULL : chain_key));
        peers_read_lock(proc);
        quorum = _ckpt_quorum_for_group(proc, primary ? NULL : chain_key, f);
        peers_read_unlock(proc);
    }
    bool write = false;
    pthread_mutex_lock(&rep_state.lock);
    rep_chain_ckpt_t *slot = _ckpt_slot_locked(chain_key);
    if (slot == NULL)
    {
        pthread_mutex_unlock(&rep_state.lock);
        return;
    }
    bool same = slot->set && slot->epoch == epoch
        && strncmp(slot->proposer, proposer, UUID_STRING_LEN + 1) == 0;
    if (!same || incoming > map_size(&slot->sigs_final))
    {
        snprintf(slot->proposer, sizeof(slot->proposer), "%s", proposer);
        snprintf(slot->root, sizeof(slot->root), "%s", root);
        slot->epoch = epoch;
        slot->first_index = first_index;
        slot->count = count;
        slot->set = true;
        map_free(&slot->sigs_final);
        map_init(&slot->sigs_final);
        if (json_is_object(sigs))
        {
            const char *voter;
            json_t *sig;
            json_object_foreach(sigs, voter, sig)
            {
                const char *hex = json_string_value(sig);
                if (hex != NULL)
                    map_set(&slot->sigs_final, (map_key_t)voter,
                            string_data((string_t)hex, strlen(hex)));
            }
        }
        if (chain_key == NULL || chain_key[0] == '\0')
            _mirror_primary_ckpt_locked();
        write = true;
    }
    if (primary && incoming > quorum)
        _note_final_locked(root, first_index, count);
    pthread_mutex_unlock(&rep_state.lock);
    if (write)
    {
        _persist_history(proc, chain_key);
        _persist_roster(proc, chain_key);
        _archive_attested(proc, chain_key);
    }
}

/* Clamp each restored score to what the evidence supports for that peer: its
 * `ceilings` entry, or — for a peer the evidence does not cover at all — the
 * ceiling of REP_UNVERIFIED_RESTORE_TIER.
 *
 * Self is never clamped (our own score is not a peer judgement). Clamping is
 * one-directional, so this can only withhold standing, never confer it, and it
 * composes with the staleness decay: decay is the time-out-of-contact axis,
 * this is the "nothing here shows you earned that" axis.
 *
 * There is no separate release step — the clamped value is where the peer
 * resumes climbing, so elevation is re-earned through the ordinary scoring
 * path. Mirrors Python _grade_restored_reputations. */
static void _grade_restored_reputations(const process_t *proc, map_t *ceilings,
                                        const char *self_uuid_str)
{
    double unverified = _tier_ceiling(REP_UNVERIFIED_RESTORE_TIER);
    int clamped = 0;
    pthread_mutex_lock(&rep_state.lock);
    map_key_t key = NULL;
    data_t *val = NULL;
    map_entries_for_each(&rep_state.reputations.scores, key, val)
    {
        if (self_uuid_str != NULL && strcmp(key, self_uuid_str) == 0)
            continue;
        double score = 0.0;
        if (data_floating_pt_dbl(val, &score) != 0)
            continue;
        double ceiling = unverified;
        data_t *cd = NULL;
        if (ceilings != NULL && map_get(ceilings, key, &cd) == 0 && cd != NULL)
            data_floating_pt_dbl(cd, &ceiling);
        if (score <= ceiling)
            continue;
        map_set(&rep_state.reputations.scores, key,
                floating_pt_dbl_data(ceiling));
        /* Remember what we clamped away from: it bounds any later lift from
         * child-group evidence (doc/architecture/gateway-reputation-tree.md). */
        map_set(&rep_state.restore_clamped, key, floating_pt_dbl_data(score));
        clamped++;
    }
    map_end_for_each
    pthread_mutex_unlock(&rep_state.lock);
    if (clamped > 0)
        log_info(proc->logger,
                 "Reputation: warm start clamped %d peer score(s) to what the "
                 "evidence supports\n", clamped);
}

/* An extension's cold-start prior (reputation/rep_ext.h): applied only where
 * this node has NO reputation for the peer at all, so it can never overwrite an
 * earned value, a warm-started one, or a slashed one. Refused, not clamped,
 * outside (0, 1]. */
static void _offer_seed(void *arg, const uuid_t who, double seed, const char *what)
{
    const rep_seed_provider_t *p = ((const void **)arg)[0];
    const process_t *proc = ((const void **)arg)[1];
    char uuid_s[UUID_STRING_LEN + 1] = {0};
    uuid_unparse_lower(who, uuid_s);
    if (!(seed > 0.0 && seed <= 1.0)) {
        log_warn(proc->logger,
                 "Reputation: %s: refusing seed %g for %s (outside (0, 1])\n",
                 p->name, seed, uuid_s);
        return;
    }
    if (reputations_contains(&rep_state.reputations, who))
        return;     /* already known here; earned beats seeded */
    reputations_update(&rep_state.reputations, who, seed);
    log_info(proc->logger, "Reputation: %s: seeded %s %s at %.2f\n",
             p->name, what != NULL ? what : "peer", uuid_s, seed);
}

/* Ask every seed provider for priors that are new since its last answer. First
 * contact's seeds each VERIFIED contact (FIRST_CONTACT_PLAN.md §10.5). */
static void _apply_seeds(const process_t *proc)
{
    const rep_seed_provider_t *ps[REP_SEED_PROVIDER_MAX];
    size_t n = rep_seed_providers(ps, REP_SEED_PROVIDER_MAX);
    for (size_t i = 0; i < n; i++) {
        const void *arg[2] = { ps[i], proc };
        ps[i]->seeds(proc, _offer_seed, (void *)arg);
    }
}

/* Treat the persisted snapshot's mtime as the instant of our last AT-bounded
 * activity: seed every warm-started peer's idle clock to it and apply the
 * offline-gap decay up front, so a long-dormant cohort comes up with faded —
 * not stale-inflated — trust. No-op when there is no snapshot on disk.
 * Mirrors Python _seed_idle_from_snapshot. */
static void _seed_idle_from_snapshot(const process_t *proc,
                                     const char *self_uuid_str)
{
    char cfg_dir[CFG_PATH_LEN + 1] = {0};
    if (get_cfg_dir(cfg_dir, sizeof(cfg_dir)) < 0)
        return;
    char path[CFG_PATH_LEN + 64] = {0};
    int n = snprintf(path, sizeof(path), "%s/%s%s", cfg_dir,
                     REP_SNAPSHOT_FILE, CFG_FILE_EXT);
    if (n < 0 || (size_t)n >= sizeof(path))
        return;
    struct stat st;
    if (stat(path, &st) != 0)
        return;
    double mtime = (double)st.st_mtime;
    double idle = (double)time(NULL) - mtime;
    if (idle < 0.0)
        idle = 0.0;
    int faded = 0;
    pthread_mutex_lock(&rep_state.lock);
    map_key_t key = NULL;
    data_t *val = NULL;
    map_entries_for_each(&rep_state.reputations.scores, key, val)
    {
        if (self_uuid_str != NULL && strcmp(key, self_uuid_str) == 0)
            continue;
        map_set(&rep_state.last_interaction, key, floating_pt_dbl_data(mtime));
        double score = 0.0;
        if (data_floating_pt_dbl(val, &score) != 0)
            continue;
        double decayed = reputation_decayed_score(score, idle);
        if (fabs(decayed - score) > 1e-12)
        {
            map_set(&rep_state.reputations.scores, key,
                    floating_pt_dbl_data(decayed));
            faded++;
        }
    }
    map_end_for_each
    pthread_mutex_unlock(&rep_state.lock);
    if (faded > 0)
        log_info(proc->logger,
                 "Reputation: warm start faded %d peer score(s) over a "
                 "%.0fs offline gap\n", faded, idle);
}

/* Relax idle peers' operational reputation toward almost-neutral. Throttled to
 * REP_DECAY_SWEEP_INTERVAL. A peer with no recorded interaction is stamped
 * rather than decayed, so its idle clock starts now instead of at the epoch.
 * Mirrors Python _decay_reputations. */
static void _decay_reputations(const process_t *proc, double present)
{
    pthread_mutex_lock(&rep_state.lock);
    if (rep_state.decay_swept
        && present - rep_state.last_decay_sweep < REP_DECAY_SWEEP_INTERVAL)
    {
        pthread_mutex_unlock(&rep_state.lock);
        return;
    }
    rep_state.last_decay_sweep = present;
    rep_state.decay_swept = true;
    /* Collect the changes under the lock, publish after releasing it: the
     * tier/exclusion publication sends IPC and must not hold rep_state. */
    char changed[MAX_CHAIN_LEN][UUID_STRING_LEN + 1];
    double changed_score[MAX_CHAIN_LEN];
    int n_changed = 0;
    map_key_t key = NULL;
    data_t *val = NULL;
    map_entries_for_each(&rep_state.reputations.scores, key, val)
    {
        double score = 0.0;
        if (data_floating_pt_dbl(val, &score) != 0)
            continue;
        /* A slashed peer's floor is authoritative; decay would drift the value
         * the slash pinned. Self is never decayed. */
        data_t *sl = NULL;
        if (map_get(&rep_state.slashed, key, &sl) == 0 && sl != NULL)
            continue;
        double last = 0.0;
        data_t *ld = NULL;
        bool have_last = (map_get(&rep_state.last_interaction, key, &ld) == 0
                          && ld != NULL
                          && data_floating_pt_dbl(ld, &last) == 0);
        if (!have_last)
        {
            /* First sight of this peer: start its idle clock now rather than
             * at the epoch, which would decay it as if absent since 1970. */
            map_set(&rep_state.last_interaction, key,
                    floating_pt_dbl_data(present));
            continue;
        }
        double decayed = reputation_decayed_score(score, present - last);
        if (fabs(decayed - score) < 1e-12)
            continue;
        map_set(&rep_state.reputations.scores, key,
                floating_pt_dbl_data(decayed));
        if (n_changed < MAX_CHAIN_LEN)
        {
            strncpy(changed[n_changed], key, UUID_STRING_LEN);
            changed[n_changed][UUID_STRING_LEN] = '\0';
            changed_score[n_changed] = decayed;
            n_changed++;
        }
    }
    map_end_for_each
    pthread_mutex_unlock(&rep_state.lock);
    for (int i = 0; i < n_changed; i++)
    {
        uuid_t u;
        if (uuid_parse(changed[i], u) != 0)
            continue;
        _publish_tier_change(proc, u, changed_score[i]);
        _publish_reputation_change(u, changed_score[i]);
    }
}

/* Every peer the primary chain names, COPIED out (map_keys returns the map's
 * own key array, which the reconcile's map rebuild frees). Caller holds
 * rep_state.lock and frees the result. */
static uuid_t *_chain_peers_locked(size_t *n_out)
{
    *n_out = 0;
    size_t cap = map_size(&rep_state.history.peer_map);
    uuid_t *out = calloc(cap > 0 ? cap : 1, sizeof(uuid_t));
    if (out == NULL)
        return NULL;
    map_key_t key;
    data_t *val;
    map_entries_for_each(&rep_state.history.peer_map, key, val)
    {
        (void)val;
        if (*n_out < cap && uuid_parse(key, out[*n_out]) == 0)
            (*n_out)++;
    }
    map_end_for_each
    return out;
}

/* Stamp "we just transacted with this peer" — resets its idle clock so the
 * staleness sweep leaves an actively-interacting peer alone. */
static void _note_interaction(const uuid_t peer_uuid)
{
    char key[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer_uuid, key);
    pthread_mutex_lock(&rep_state.lock);
    map_set(&rep_state.last_interaction, (map_key_t)key,
            floating_pt_dbl_data((double)time(NULL)));
    map_set(&rep_state.rescore_due, (map_key_t)key, integer_data(1));
    pthread_mutex_unlock(&rep_state.lock);
}

/* Read each member's first_seen and key from roster.cfg.json into the tenure
 * maps, once per state reset, so a restart keeps the clock this node already
 * started. A missing or unreadable file seeds nothing: every member then
 * starts its tenure now, which errs toward holding it. Caller must hold
 * rep_state.lock. Mirrors Python _seed_tenure. */
static void _tenure_seed_locked(void)
{
    if (rep_state.tenure_seeded)
        return;
    rep_state.tenure_seeded = true;
    char cfg_dir[CFG_PATH_LEN + 1] = {0};
    if (get_cfg_dir(cfg_dir, sizeof(cfg_dir)) < 0)
        return;
    char path[CFG_PATH_LEN + 64];
    snprintf(path, sizeof(path), "%s/%s", cfg_dir, REP_ROSTER_FILE);
    json_t *doc = json_load_file(path, 0, NULL);
    const char *k;
    json_t *m;
    json_object_foreach(json_object_get(doc, "members"), k, m)
    {
        json_t *fs = json_object_get(m, "first_seen");
        const char *key = json_string_value(json_object_get(m, "pubkey"));
        data_t *d = NULL;
        if (!json_is_integer(fs) || key == NULL
            || map_get(&rep_state.member_since, (map_key_t)k, &d) == 0)
            continue;
        map_set(&rep_state.member_since, (map_key_t)k,
                floating_pt_dbl_data((double)json_integer_value(fs)));
        map_set(&rep_state.member_key, (map_key_t)k,
                string_data((string_t)key, strlen(key)));
    }
    json_decref(doc);
}

/* Start the tenure clock of a member this node has not held before, or whose
 * key changed (a new identity). Caller must hold rep_state.lock. */
static void _tenure_stamp_locked(const char *uuid_str, const char *key_hex, double now)
{
    data_t *d = NULL;
    if (map_get(&rep_state.member_key, (map_key_t)uuid_str, &d) == 0 && d != NULL)
    {
        string_t held = NULL;
        if (data_string_ptr(d, &held) == 0 && held != NULL && strcmp(held, key_hex) == 0)
            return;
    }
    else if (map_get(&rep_state.member_since, (map_key_t)uuid_str, &d) == 0)
    {
        /* A clock started without a key (a test seam): the key is this one. */
        map_set(&rep_state.member_key, (map_key_t)uuid_str,
                string_data((string_t)key_hex, strlen(key_hex)));
        return;
    }
    map_set(&rep_state.member_since, (map_key_t)uuid_str, floating_pt_dbl_data(now));
    map_set(&rep_state.member_key, (map_key_t)uuid_str,
            string_data((string_t)key_hex, strlen(key_hex)));
}

/* Rescore every peer whose chain advanced since it was last scored, and every
 * admitted peer that has never been scored, then publish the tier and the
 * app event for each. Throttled to REP_RESCORE_INTERVAL. Mirrors Python
 * _rescore_sweep.
 *
 * WITHOUT THIS NO LIVE NODE EVER RATED ANYONE. handle_rep_request was the only
 * place a score was computed and stored, and nothing in a running node sends
 * "request reputation" (the one sender is Python's task automation). A commit
 * only appended to the chain. So every peer stayed unrated, no tier was ever
 * published, every tier-gate above 0 closed for good, and a committed report
 * could never lower anyone's score. Found by moderation_cohort.sh, whose peers
 * were still unrated after eleven commits.
 *
 * An admitted peer is also included when identity has not been told its tier
 * in this process's lifetime: an unscored one, so it gets its prior (the
 * prereputation prior with no history) instead of staying unrated until it
 * happens to commit something; and one restored from the snapshot, whose
 * score survived a restart that identity's in-memory tiers did not. @p self_uuid, when known, is skipped: a node
 * holds no reputation of itself. Returns the number of peers scored. */
static int _rescore_peers(const process_t *proc, double present,
                          const uuid_t self_uuid)
{
    pthread_mutex_lock(&rep_state.lock);
    if (rep_state.rescore_swept
        && present - rep_state.last_rescore_sweep < REP_RESCORE_INTERVAL)
    {
        pthread_mutex_unlock(&rep_state.lock);
        return 0;
    }
    rep_state.last_rescore_sweep = present;
    rep_state.rescore_swept = true;
    pthread_mutex_unlock(&rep_state.lock);

    /* The admitted roster, copied before rep_state.lock is taken: the peers
     * read-lock and rep_state.lock are never held together here. */
    uuid_t roster[DEFAULT_MAX_PEERS];
    char roster_keys[DEFAULT_MAX_PEERS][crypto_sign_PUBLICKEYBYTES * 2 + 1];
    size_t n_roster = 0;
    peers_read_lock(proc);
    n_roster = proc->protocol.num_peers;
    if (n_roster > DEFAULT_MAX_PEERS)
        n_roster = DEFAULT_MAX_PEERS;
    for (size_t i = 0; i < n_roster; i++)
    {
        uuid_copy(roster[i], proc->protocol.peers[i].uuid);
        sodium_bin2hex(roster_keys[i], sizeof(roster_keys[i]),
                       proc->protocol.peers[i].signature.public,
                       crypto_sign_PUBLICKEYBYTES);
    }
    peers_read_unlock(proc);

    uuid_t due[DEFAULT_MAX_PEERS];
    double scores[DEFAULT_MAX_PEERS];
    int n_due = 0;
    pthread_mutex_lock(&rep_state.lock);
    map_key_t key;
    data_t *val;
    map_entries_for_each(&rep_state.rescore_due, key, val)
    {
        (void)val;
        uuid_t u;
        if (n_due < DEFAULT_MAX_PEERS && uuid_parse(key, u) == 0)
            uuid_copy(due[n_due++], u);
    }
    map_end_for_each
    map_free(&rep_state.rescore_due);
    map_init(&rep_state.rescore_due);
    /* Tenure: start the clock of every member not held before, and rescore
     * every held peer whose tenure is now served (or whose gate was turned
     * off), so its tier rises without waiting for its next commit. */
    _tenure_seed_locked();
    double tenure_now = (double)time(NULL);
    for (size_t i = 0; i < n_roster; i++)
    {
        char rkey[UUID_STRING_LEN + 1];
        uuid_unparse_lower(roster[i], rkey);
        _tenure_stamp_locked(rkey, roster_keys[i], tenure_now);
    }
    double min_tenure = REP_MIN_TENURE;
    map_entries_for_each(&rep_state.tenure_capped, key, val)
    {
        (void)val;
        double since = -1.0;
        data_t *d = NULL;
        if (map_get(&rep_state.member_since, key, &d) == 0 && d != NULL)
            (void)data_floating_pt_dbl(d, &since);
        uuid_t u;
        if (n_due < DEFAULT_MAX_PEERS && uuid_parse(key, u) == 0
            && (min_tenure <= 0.0 || (since >= 0.0 && tenure_now - since >= min_tenure)))
        {
            bool listed = false;
            for (int j = 0; j < n_due && !listed; j++)
                listed = (uuid_compare(due[j], u) == 0);
            if (!listed)
                uuid_copy(due[n_due++], u);
        }
    }
    map_end_for_each
    for (size_t i = 0; i < n_roster && n_due < DEFAULT_MAX_PEERS; i++)
    {
        /* Rated AND already told to identity this run: nothing to do. A peer
         * restored from the snapshot is rated but NOT told — identity's tiers
         * live in memory and start empty — so it must be included, or a
         * restarted node gates every such peer at tier 0 until its tier next
         * happens to change (moderation_cohort.sh phase 6, after a restart). */
        char rkey[UUID_STRING_LEN + 1];
        uuid_unparse_lower(roster[i], rkey);
        data_t *told = NULL;
        if (reputations_contains(&rep_state.reputations, roster[i])
            && map_get(&rep_state.peer_tiers, rkey, &told) == 0)
            continue;
        bool listed = false;
        for (int j = 0; j < n_due && !listed; j++)
            listed = (uuid_compare(due[j], roster[i]) == 0);
        if (!listed)
            uuid_copy(due[n_due++], roster[i]);
    }
    int kept = 0;
    for (int i = 0; i < n_due; i++)
    {
        if (self_uuid != NULL && uuid_compare(due[i], self_uuid) == 0)
            continue;
        if (!uuid_is_null(due[i]))
        {
            uuid_copy(due[kept], due[i]);
            scores[kept] = _score_peer_locked(proc, due[i]);
            kept++;
        }
    }
    pthread_mutex_unlock(&rep_state.lock);
    if (kept > 0)
        _persist_reputations(proc);

    for (int i = 0; i < kept; i++)
    {
        _publish_tier_change(proc, due[i], scores[i]);
        _publish_reputation_change(due[i], scores[i]);
    }
    if (kept > 0)
        log_debug(proc->logger, "Reputation: rescored %d peer(s)\n", kept);
    return kept;
}

int reputation_rescore_sweep(const process_t *proc, double present,
                             const uuid_t self_uuid)
{
    _ensure_init();
    return _rescore_peers(proc, present, self_uuid);
}

void reputation_note_interaction(const uuid_t peer_uuid)
{
    _ensure_init();
    _note_interaction(peer_uuid);
}

void reputation_set_min_tenure(double seconds)
{
    _ensure_init();
    pthread_mutex_lock(&rep_state.lock);
    rep_state.tenure_min_override = seconds;
    pthread_mutex_unlock(&rep_state.lock);
}

void reputation_set_member_since(const uuid_t peer_uuid, const char *key_hex,
                                 double since)
{
    _ensure_init();
    char u[UUID_STRING_LEN + 1];
    uuid_unparse_lower(peer_uuid, u);
    pthread_mutex_lock(&rep_state.lock);
    rep_state.tenure_seeded = true;
    map_set(&rep_state.member_since, (map_key_t)u, floating_pt_dbl_data(since));
    if (key_hex != NULL)
        map_set(&rep_state.member_key, (map_key_t)u,
                string_data((string_t)key_hex, strlen(key_hex)));
    pthread_mutex_unlock(&rep_state.lock);
}

/* At start-up, re-establish the committed history from the persisted evidence
 * and grade the restored reputations by whether that evidence VERIFIES.
 *
 * Three questions, in order, every negative answer degrading to the same safe
 * outcome rather than failing the process:
 *   1. Does the chain's hash-linkage hold? (checked inside
 *      reputation_evidence_from_json — a broken link means the file was
 *      altered or truncated.)
 *   2. Does the root recomputed over the checkpoint's window equal the root
 *      the checkpoint commits to? This is what ties the entries on disk to the
 *      thing that was signed.
 *   3. Does a quorum of co-signatures over that checkpoint verify against keys
 *      WE hold? The same test handle_checkpoint_final applies live, sized
 *      against our own roster so whoever wrote the file cannot also choose the
 *      bar it has to clear.
 *
 * Only if all three hold is the chain adopted. It is NOT adopted on failure,
 * and that is the load-bearing part: hash digests are public, so anyone can
 * produce a self-consistent chain, and adopting one would let the scoring path
 * re-derive the very elevated scores the clamp withholds. */
/* Verify and (only then) adopt ONE chain's persisted evidence, folding its
 * per-peer ceilings into @p ceilings. Returns true if the chain was adopted.
 *
 * Where two attested windows bound the same peer, the HIGHER bound wins: both
 * are quorum-attested statements about that peer and the restored score is a
 * single scalar, so letting one group's thin window suppress standing another
 * group's quorum actually witnessed would penalize the peer for our topology
 * rather than for its behaviour. */
static bool _rebuild_one_chain(const process_t *proc, const char *chain_key,
                               const char *self_uuid_str, map_t *ceilings)
{
    char path[CFG_PATH_LEN + 64] = {0};
    if (_evidence_path(chain_key, path, sizeof(path)) != 0)
        return false;
    json_error_t jerr;
    json_t *doc = json_load_file(path, 0, &jerr);
    if (doc == NULL)
    {
        /* No evidence on disk: a cold start, or a warm start from a snapshot
         * written before checkpointing ever ran. Persisted scores are
         * unattested, so they are clamped. */
        return false;
    }
    /* The equivocation records are this node's own, whatever becomes of the
     * chain beside them, so they come back first. */
    _load_fork_records(chain_key, doc);

    tx_history_t *loaded = NULL;
    rep_checkpoint_t ckpt;
    bool verified = false;
    if (tx_history_create(&loaded) == 0 && rep_checkpoint_init(&ckpt) == 0)
    {
        if (reputation_evidence_from_json(doc, loaded, &ckpt) != 0)
        {
            log_warn(proc->logger,
                     "Reputation: unusable warm-start evidence (bad schema, "
                     "malformed entry, or broken hash link); restoring at "
                     "tier %d\n", REP_UNVERIFIED_RESTORE_TIER);
        }
        else if (!ckpt.present)
        {
            log_info(proc->logger,
                     "Reputation: warm-start evidence carries no checkpoint; "
                     "restoring at tier %d\n", REP_UNVERIFIED_RESTORE_TIER);
        }
        else
        {
            char recomputed[TX_HASH_HEX_LEN + 1] = {0};
            if (reputation_checkpoint_window_root(loaded, &ckpt,
                                                  recomputed) != 0)
            {
                log_warn(proc->logger,
                         "Reputation: warm-start evidence does not cover "
                         "checkpoint window [%d, %d); restoring at tier %d\n",
                         ckpt.first_index, ckpt.first_index + ckpt.count,
                         REP_UNVERIFIED_RESTORE_TIER);
            }
            else if (strncmp(recomputed, ckpt.root, TX_HASH_HEX_LEN + 1) != 0)
            {
                log_warn(proc->logger,
                         "Reputation: warm-start evidence root mismatch "
                         "(checkpoint commits to %.12s, entries hash to "
                         "%.12s); restoring at tier %d\n", ckpt.root,
                         recomputed, REP_UNVERIFIED_RESTORE_TIER);
            }
            else
            {
                uint8_t desig[REP_DESIG_MAX];
                size_t dlen = rep_checkpoint_designation(
                    ckpt.proposer_uuid, ckpt.root, ckpt.epoch,
                    ckpt.first_index, ckpt.count, ckpt.group_uuid, desig,
                    sizeof(desig));
                /* Re-use the live path's quorum test verbatim, including its
                 * roster sizing. A roster we have not yet loaded resolves no
                 * co-signers, which fails CLOSED: capped, never forged. */
                json_t *sigs = json_object();
                map_key_t key = NULL;
                data_t *val = NULL;
                map_entries_for_each(&ckpt.sigs, key, val)
                {
                    string_t hex = NULL;
                    if (data_string_ptr(val, &hex) == 0 && hex != NULL)
                        json_object_set_new(sigs, key, json_string(hex));
                }
                map_end_for_each
                if (dlen == 0
                    || !_ckpt_quorum_met_for(proc, sigs, desig, dlen, chain_key))
                {
                    log_warn(proc->logger,
                             "Reputation: warm-start evidence epoch=%lld has "
                             "%zu verified co-signature(s), short of quorum; "
                             "restoring at tier %d\n", (long long)ckpt.epoch,
                             dlen == 0 ? (size_t)0
                                 : _verified_cosigners(proc, sigs, desig, dlen),
                             REP_UNVERIFIED_RESTORE_TIER);
                }
                else
                {
                    verified = true;
                    reputation_evidence_ceilings(loaded, &ckpt, self_uuid_str,
                                                 ceilings);
                }
                json_decref(sigs);
            }
        }

        if (verified)
        {
            pthread_mutex_lock(&rep_state.lock);
            /* Adopt the attested history, and with it the checkpoint that
             * attests it, so this node resumes with a window a peer can audit
             * and an anchor slash evidence can be measured against. */
            tx_history_t *dest = _chain_for_key_locked(chain_key);
            /* A child chain is restored late, so its pool may already hold
             * halves (or what reputation-pool restored); they wait on this
             * chain now. */
            json_t *pool = dest->pool_len > 0 ? _pool_to_json(dest) : NULL;
            unsigned rev = dest->pool_rev;
            tx_history_free(dest);
            *dest = *loaded;
            memset(loaded, 0, sizeof(*loaded));  /* ownership moved */
            dest->pool_rev = rev + 1;
            if (pool != NULL)
                (void)_pool_from_json(dest, pool);
            json_decref(pool);
            rep_chain_ckpt_t *slot = _ckpt_slot_locked(chain_key);
            if (slot != NULL)
            {
                snprintf(slot->proposer, sizeof(slot->proposer), "%s",
                         ckpt.proposer_uuid);
                snprintf(slot->root, sizeof(slot->root), "%s", ckpt.root);
                slot->epoch = ckpt.epoch;
                slot->first_index = ckpt.first_index;
                slot->count = ckpt.count;
                slot->set = true;
                map_free(&slot->sigs_final);
                map_init(&slot->sigs_final);
                map_key_t key = NULL;
                data_t *val = NULL;
                map_entries_for_each(&ckpt.sigs, key, val)
                {
                    string_t hex = NULL;
                    if (data_string_ptr(val, &hex) == 0 && hex != NULL)
                        map_set(&slot->sigs_final, key,
                                string_data(hex, strlen(hex)));
                }
                map_end_for_each
                /* Resume our OWN epoch counter past the persisted checkpoint.
                 * Peers dedup on (proposer, epoch, chain) and their rings are
                 * not reset by our restart, so a restarted proposer beginning
                 * again at 1 would have its first proposals discarded as
                 * re-broadcasts. */
                if (self_uuid_str != NULL
                    && strcmp(ckpt.proposer_uuid, self_uuid_str) == 0
                    && ckpt.epoch > slot->own_epoch)
                    slot->own_epoch = ckpt.epoch;
            }
            if (chain_key == NULL || chain_key[0] == '\0')
            {
                _mirror_primary_ckpt_locked();
                /* The rebuild verified this checkpoint's quorum. */
                _note_final_locked(ckpt.root, ckpt.first_index, ckpt.count);
            }
            int adopted = dest->committed_count;
            pthread_mutex_unlock(&rep_state.lock);
            log_info(proc->logger,
                     "Reputation: warm start VERIFIED — chain=%s, %d committed "
                     "entries, checkpoint epoch=%lld, %zu evidence-backed "
                     "peer(s)\n",
                     (chain_key != NULL && chain_key[0]) ? chain_key : "primary",
                     adopted, (long long)ckpt.epoch, map_size(ceilings));
        }
        rep_checkpoint_free(&ckpt);
    }
    if (loaded != NULL)
        tx_history_destroy(loaded);
    json_decref(doc);
    return verified;
}

/* Boot-time restore: the PRIMARY chain only, then clamp.
 *
 * A gateway's child groups arrive over IPC (CHILD_GROUP from the identity
 * process) AFTER this runs, so at this point the node does not yet know which
 * subtrees are its own -- and reading a file for a group we may not gateway is
 * exactly what must not happen. The child chains are restored by
 * _restore_child_evidence once the group set lands. */
static void _rebuild_from_evidence(const process_t *proc,
                                   const char *self_uuid_str)
{
    map_t ceilings;
    map_init(&ceilings);
    _rebuild_one_chain(proc, "", self_uuid_str, &ceilings);
    _grade_restored_reputations(proc, &ceilings, self_uuid_str);
    map_free(&ceilings);
}

/* A document must cover the chain it is NAMED for. A child document claiming
 * the primary chain (or another group's) would otherwise be adopted as that
 * chain's history on the strength of signatures made over different bytes. */
static bool _evidence_names_chain(const char *path, const char *chain_key)
{
    json_error_t jerr;
    json_t *doc = json_load_file(path, 0, &jerr);
    if (doc == NULL)
        return false;
    json_t *ck = json_object_get(doc, "checkpoint");
    bool ok = true;
    if (json_is_object(ck))
    {
        const char *claimed = json_string_value(json_object_get(ck,
                                                               "group_uuid"));
        if (claimed == NULL)
            claimed = "";
        ok = (strncmp(claimed, chain_key, UUID_STRING_LEN + 1) == 0);
    }
    json_decref(doc);
    return ok;
}

/* Restore a gateway's child-group chains once the group set has arrived, one
 * attempt per group (doc/architecture/gateway-reputation-tree.md).
 *
 * This runs late by necessity, which shapes what it may do to a live score: it
 * only ever LIFTS, and never above what was persisted. A peer attested solely
 * in a child group was clamped at boot as uncovered, and this returns it to
 * what its subtree's evidence bears out. Lowering here would be wrong twice
 * over -- the peer may have earned standing since boot, and late-arriving
 * evidence is not a reason to discount it. Mirrors Python
 * _restore_child_evidence. */
static void _restore_child_evidence(const process_t *proc,
                                    const char *self_uuid_str)
{
    if (proc == NULL || proc->protocol.child_groups == NULL)
        return;
    /* Plain iteration over the key array rather than map_entries_for_each:
     * that macro declares its own locals, so nesting it around the per-peer
     * loop below shadows them (-Werror=shadow). */
    array_t *groups = map_keys(proc->protocol.child_groups);
    size_t n_groups = array_size(groups);
    for (size_t gi = 0; gi < n_groups; gi++)
    {
        data_t *gk_dat = NULL;
        if (array_get(groups, (int)gi, &gk_dat) != 0)
            continue;
        map_key_t gkey = NULL;
        if (data_string_ptr(gk_dat, &gkey) != 0 || gkey == NULL)
            continue;
        pthread_mutex_lock(&rep_state.lock);
        data_t *seen = NULL;
        bool tried = (map_get(&rep_state.child_evidence_tried, gkey, &seen) == 0);
        if (!tried)
            map_set(&rep_state.child_evidence_tried, gkey, integer_data(1));
        pthread_mutex_unlock(&rep_state.lock);
        if (tried)
            continue;
        char path[CFG_PATH_LEN + 64] = {0};
        if (_evidence_path(gkey, path, sizeof(path)) != 0)
            continue;
        if (!_evidence_names_chain(path, gkey))
        {
            log_warn(proc->logger,
                     "Reputation: evidence for chain %s names another chain; "
                     "refusing it\n", gkey);
            continue;
        }
        map_t ceilings;
        map_init(&ceilings);
        if (_rebuild_one_chain(proc, gkey, self_uuid_str, &ceilings))
        {
            map_key_t pkey = NULL;
            data_t *pval = NULL;
            map_entries_for_each(&ceilings, pkey, pval)
            {
                double ceiling = 0.0;
                if (data_floating_pt_dbl(pval, &ceiling) != 0)
                    continue;
                uuid_t peer;
                if (uuid_parse(pkey, peer) != 0)
                    continue;
                double current = 0.0;
                double bound = ceiling;
                pthread_mutex_lock(&rep_state.lock);
                bool have = (reputations_get(&rep_state.reputations, peer,
                                             &current) == 0);
                data_t *cd = NULL;
                if (have
                    && map_get(&rep_state.restore_clamped, pkey, &cd) == 0
                    && cd != NULL)
                {
                    double persisted = 0.0;
                    if (data_floating_pt_dbl(cd, &persisted) == 0
                        && persisted < bound)
                        bound = persisted;
                }
                bool lift = have && bound > current;
                if (lift)
                    reputations_update(&rep_state.reputations, peer, bound);
                pthread_mutex_unlock(&rep_state.lock);
                if (lift)
                {
                    log_info(proc->logger,
                             "Reputation: child-group evidence lifted %s "
                             "%.3f -> %.3f\n", pkey, current, bound);
                    _publish_tier_change(proc, peer, bound);
                    _publish_reputation_change(peer, bound);
                }
            }
            map_end_for_each
        }
        map_free(&ceilings);
    }
}

/* A per-node offset into the checkpoint interval, so members do not all
 * propose on the same tick: every member co-signs every proposal, so N nodes
 * proposing together cost N² messages in one burst. Derived from our own uuid
 * rather than drawn randomly, so the phase survives a restart. Mirrors Python
 * _checkpoint_phase. */
static double _checkpoint_phase(const char *self_uuid_str)
{
    if (self_uuid_str == NULL)
        return 0.0;
    uuid_t u;
    if (uuid_parse(self_uuid_str, u) != 0)
        return 0.0;
    /* Python takes UUID.int % interval; the low-order bytes of the same uuid
     * give an equally-uniform offset without 128-bit arithmetic. The phase is
     * a load-spreading device, not a protocol value, so the two runtimes need
     * not agree on it. */
    uint64_t lo = 0;
    for (int i = 8; i < 16; i++)
        lo = (lo << 8) | (uint64_t)u[i];
    int64_t interval = (int64_t)REP_CHECKPOINT_INTERVAL;
    if (interval < 1)
        interval = 1;
    return (double)(lo % (uint64_t)interval);
}

/* Originate a checkpoint over THIS node's committed window: stamp the epoch,
 * sign, seed our own co-signature, self-store, and broadcast
 * checkpoint_propose. Mirrors Python forward_checkpoint.
 *
 * The self-store matters as much as the broadcast: a single-node group needs
 * no round trip, and it is not special-cased — at boot the same quorum rule
 * applies, so a lone self-signature attests a genuinely single-node group and
 * nothing more. */
static void _originate_checkpoint(const process_t *proc,
                                  const char *self_uuid_str,
                                  const char *chain_key)
{
    if (self_uuid_str == NULL || self_uuid_str[0] == '\0')
        return;
    if (chain_key == NULL)
        chain_key = "";
    char root[TX_HASH_HEX_LEN + 1] = {0};
    int64_t epoch = 0;
    int first_index = 0, count = 0;
    pthread_mutex_lock(&rep_state.lock);
    rep_chain_ckpt_t *slot = _ckpt_slot_locked(chain_key);
    tx_history_t *chain = _chain_for_key_locked(chain_key);
    if (slot != NULL)
    {
        slot->own_epoch++;
        epoch = slot->own_epoch;
    }
    transaction_window_root(chain, root);
    count = chain->committed_count;
    first_index = (count > 0) ? chain->first_index : chain->next_index;
    pthread_mutex_unlock(&rep_state.lock);

    uint8_t desig[REP_DESIG_MAX];
    size_t dlen = rep_checkpoint_designation(self_uuid_str, root, epoch,
                                             first_index, count, chain_key,
                                             desig, sizeof(desig));
    char sig_hex[REP_SIG_HEX_LEN + 1] = {0};
    json_t *sigs = json_object();
    if (dlen > 0 && _cosign_hex(proc, desig, dlen, sig_hex,
                                sizeof(sig_hex)) == 0)
    {
        json_object_set_new(sigs, self_uuid_str, json_string(sig_hex));
    }
    else
    {
        log_error(proc->logger,
                  "Reputation: cannot sign own checkpoint; it cannot reach "
                  "quorum\n");
    }
    /* Record the round so our own handle_checkpoint_sign can tally acks
     * against it, exactly as if a peer had proposed to us. */
    /* The round key carries the chain too: a gateway's primary and child rounds
     * can otherwise collide at the same epoch number. */
    char key[UUID_STRING_LEN * 2 + 32];
    /* Both fields are uuid strings (the chain key is a group uuid, or "" for
     * the primary chain), so the bound is the real maximum and never truncates
     * a legitimate key -- it is here because the callers pass a row of a 2-D
     * `due_keys` array, whose row length gcc cannot see through the index, so
     * -Wformat-truncation assumes the string may run to the end of the whole
     * array. */
    snprintf(key, sizeof(key), "%s:%lld:%.*s", self_uuid_str, (long long)epoch,
             (int)UUID_STRING_LEN, chain_key);
    json_t *pending = json_pack("{s:s, s:i, s:i, s:s}", "root", root,
                                "first_index", first_index, "count", count,
                                "group_uuid", chain_key);
    if (pending != NULL)
    {
        pthread_mutex_lock(&rep_state.lock);
        _store_pending_locked(&rep_state.checkpoint_pending, key, pending);
        pthread_mutex_unlock(&rep_state.lock);
        json_decref(pending);
    }
    if (sig_hex[0] != '\0')
    {
        pthread_mutex_lock(&rep_state.lock);
        _record_cosig_locked(&rep_state.checkpoint_sigs, key, self_uuid_str,
                             sig_hex);
        pthread_mutex_unlock(&rep_state.lock);
    }
    _store_checkpoint(proc, self_uuid_str, root, epoch, first_index, count,
                      chain_key, sigs);

    json_t *payload = json_pack("{s:s, s:s, s:I, s:i, s:i, s:s}",
                                "proposer_uuid", self_uuid_str,
                                "root", root,
                                "epoch", (json_int_t)epoch,
                                "first_index", first_index,
                                "count", count,
                                "group_uuid", chain_key);
    if (payload != NULL)
    {
        generic_msg_t bcast = {0};
        bcast.type = NET_MESSAGE;
        strncpy(bcast.info.net_msg.process, "reputation", PROC_NAME_LEN);
        bcast.info.net_msg.function = REP_PROTO_CHECKPOINT_PROPOSE;
        bcast.info.net_msg.encrypt = true;
        net_msg_pack_json(&bcast.info.net_msg, payload);
        json_decref(payload);
        peers_read_lock(proc);
        for (size_t i = 0; i < proc->protocol.num_peers; i++)
        {
            generic_msg_t per = bcast;
            memcpy(&per.info.net_msg.to_whom, &proc->protocol.peers[i],
                   sizeof(public_identity_t));
            _rep_send_to_network(proc, &per);
        }
        peers_read_unlock(proc);
        net_msg_free_obj(&bcast.info.net_msg);
    }
    json_decref(sigs);
    log_info(proc->logger,
             "Reputation: proposed checkpoint chain=%s epoch=%lld count=%d "
             "root=%.12s\n", chain_key[0] ? chain_key : "primary",
             (long long)epoch, count, root);
}

void reputation_force_checkpoint(const process_t *proc,
                                const char *self_uuid_str,
                                const char *chain_key)
{
    _originate_checkpoint(proc, self_uuid_str,
                          chain_key == NULL ? "" : chain_key);
}

/* Re-propose OUR halves that have waited out REP_COMMIT_TIMEOUT without
 * reaching the chain (ISSUES §2.24; see _await_commit_locked). A half now in
 * the chain or the pool, by our commit or inside a chain we adopted, is simply
 * forgotten.
 *
 * After REP_COMMIT_RETRIES the half is PARKED rather than given up (§2.60):
 * the usual reason a half outlives five retries is that no quorum is
 * reachable, as on the minority side of a partition, and the heal is when it
 * can commit. A parked half is re-proposed every REP_PARK_RETRY, or on the
 * next pass after the chain grows from a peer (_wake_parked_locked), and is
 * given up only after REP_PARK_TTL. Each step is said out loud.
 * Collect-then-act: _forward_transaction takes the lock itself. */
#define REP_COMMIT_RETRY_PER_PASS 4
typedef enum {
    REP_HALF_REPROPOSE,     /* an active half's next retry */
    REP_HALF_PARK,          /* its retries ran out: park it */
    REP_HALF_PARKED_RETRY,  /* a parked half's slow retry, or a wake */
    REP_HALF_EXPIRE,        /* parked past REP_PARK_TTL: give it up */
} rep_half_action_t;

void _retry_uncommitted_halves(const process_t *proc, double present)
{
    rep_awaiting_t due[REP_COMMIT_RETRY_PER_PASS];
    rep_half_action_t act[REP_COMMIT_RETRY_PER_PASS];
    /* Each due half's map key, so one given up is removed by the key it is
     * filed under. */
    char due_key[REP_COMMIT_RETRY_PER_PASS][UUID_STRING_LEN + 1];
    size_t members = 0;
    size_t reached = 0;
    size_t n_due = 0;
    char gone[REP_COMMIT_RETRY_PER_PASS * 2][UUID_STRING_LEN + 1];
    size_t n_gone = 0;
    double park_retry = REP_PARK_RETRY, park_ttl = REP_PARK_TTL;

    pthread_mutex_lock(&rep_state.lock);
    bool app_pending = false;
    (void)_probe_load_locked(&app_pending);
    map_key_t key = NULL;
    data_t *value = NULL;
    map_entries_for_each(&rep_state.awaiting_commit, key, value)
    {
        rep_awaiting_t *w = NULL;
        if (data_object_ptr(value, (void **)&w) != 0 || w == NULL)
            continue;
        if (_own_half_recorded_locked(w->task_uuid, w->proposer)) {
            if (n_gone < sizeof(gone) / sizeof(gone[0]))
                at_strlcpy(gone[n_gone++], key, sizeof(gone[0]));
            continue;
        }
        if (n_due >= REP_COMMIT_RETRY_PER_PASS)
            continue;
        if (w->parked_at > 0) {
            if (present - w->parked_at > park_ttl)
                act[n_due] = REP_HALF_EXPIRE;
            else if (w->deadline > present)
                continue;
            else if (app_pending && _is_probe_cap(w->capability_name)) {
                w->deadline = present + REP_COMMIT_TIMEOUT;   /* yields (§2.60) */
                continue;
            } else
                act[n_due] = REP_HALF_PARKED_RETRY;
            at_strlcpy(due_key[n_due], key, sizeof(due_key[0]));
            due[n_due++] = *w;
            continue;
        }
        if (w->deadline > present)
            continue;
        if (app_pending && _is_probe_cap(w->capability_name)) {
            /* A probe yields to a pending app half (§2.60): it waits, its
             * attempts unspent, and is looked at again a timeout later. */
            w->deadline = present + REP_COMMIT_TIMEOUT;
            continue;
        }
        if (w->attempts >= w->retries) {
            reached = _members_reachable_locked(proc, present, &members);
            if (reached * 2 > members) {
                /* Reachable, just outcompeted: give it up as before. */
                act[n_due] = REP_HALF_EXPIRE;
            } else {
                act[n_due] = REP_HALF_PARK;
                w->parked_at = present;
                w->deadline = present + park_retry;
            }
        } else {
            act[n_due] = REP_HALF_REPROPOSE;
        }
        at_strlcpy(due_key[n_due], key, sizeof(due_key[0]));
        due[n_due++] = *w;
        if (act[n_due - 1] == REP_HALF_REPROPOSE)
            w->attempts++;
    }
    map_end_for_each;
    for (size_t i = 0; i < n_gone; i++)
        map_remove(&rep_state.awaiting_commit, gone[i]);

    /* The entries of the halves being given up. A half being parked keeps
     * its entry. */
    for (size_t i = 0; i < n_due; i++)
        if (act[i] == REP_HALF_EXPIRE)
            map_remove(&rep_state.awaiting_commit, due_key[i]);
    pthread_mutex_unlock(&rep_state.lock);

    uuid_t no_subject;
    uuid_clear(no_subject);
    for (size_t i = 0; i < n_due; i++)
    {
        char task_str[UUID_STRING_LEN + 1];
        uuid_unparse_lower(due[i].task_uuid, task_str);
        switch (act[i]) {
        case REP_HALF_EXPIRE:
            if (due[i].parked_at > 0)
                log_warn(proc->logger,
                         "Reputation: our half of task %s never committed "
                         "after %d re-proposal(s) and %.0f s parked; giving "
                         "up on it\n", task_str, due[i].attempts,
                         present - due[i].parked_at);
            else
                log_warn(proc->logger,
                         "Reputation: our half of task %s never committed "
                         "after %d re-proposal(s), though %zu of %zu "
                         "member(s) are reachable; giving up on it\n",
                         task_str, due[i].attempts, reached, members);
            continue;
        case REP_HALF_PARK:
            log_info(proc->logger,
                     "Reputation: our half of task %s has no quorum after %d "
                     "re-proposal(s) (%zu of %zu member(s) reachable); parking "
                     "it until the chain grows from a peer (or every %.0f s)\n",
                     task_str, due[i].attempts, reached, members, park_retry);
            continue;
        case REP_HALF_PARKED_RETRY:
            log_info(proc->logger,
                     "Reputation: re-proposing parked half of task %s\n",
                     task_str);
            break;
        case REP_HALF_REPROPOSE:
            log_info(proc->logger,
                     "Reputation: our half of task %s is not in the chain after "
                     "%.0f s; re-proposing it (attempt %d of %d)\n",
                     task_str, REP_COMMIT_TIMEOUT, due[i].attempts + 1,
                     due[i].retries);
            break;
        }
        _forward_transaction(proc, due[i].task_uuid, due[i].proposer,
                             due[i].score,
                             due[i].capability_name[0] != '\0'
                                 ? due[i].capability_name : NULL,
                             due[i].channel[0] != '\0' ? due[i].channel : NULL,
                             no_subject, due[i].competence);
        if (act[i] == REP_HALF_PARKED_RETRY) {
            /* The next slow retry counts from this pass, whatever clock
             * _await_commit_locked read. */
            data_t *dat = NULL;
            rep_awaiting_t *w = NULL;
            pthread_mutex_lock(&rep_state.lock);
            if (map_get(&rep_state.awaiting_commit, task_str, &dat) == 0
                && data_object_ptr(dat, (void **)&w) == 0 && w != NULL)
                w->deadline = present + park_retry;
            pthread_mutex_unlock(&rep_state.lock);
        }
    }
}

/* Hand our pending halves to a member that joined after we committed them
 * (ISSUES §2.62). A join carries only bilateral entries, so a half of ours
 * committed before a member arrived never reaches it; when our counterpart's
 * half commits later, the late member holds it alone and its chain forks from
 * ours. Stele rt-2404254 split two and two that way, and an even split never
 * finalizes a checkpoint, so nothing reconciled it. Each pass at
 * REP_HANDOFF_AT seconds after a peer is first seen in the roster re-sends it
 * every one of our committed-but-unpaired halves in the primary chain's pool
 * as the same `tx committed` we broadcast at commit, certificate included.
 * Only OUR halves: a commit may write only its sender's half (§2.16). Repeated
 * because a newcomer may not hold the group key yet; a repeat is harmless, as
 * the pool refuses a second half from the same scorer. Mirrors
 * Python _hand_off_pending_halves. */
static const double REP_HANDOFF_AT[] = { 5.0, 15.0, 30.0 };
#define REP_HANDOFF_PASSES \
    ((int)(sizeof(REP_HANDOFF_AT) / sizeof(REP_HANDOFF_AT[0])))
#define REP_HANDOFF_MAX_HALVES 32

typedef struct {
    uuid_t task;
    double score;
    char   channel[TX_CHANNEL_NAMELEN + 1];
    char  *cert;   /* owned JSON text, or NULL */
} rep_handoff_half_t;

size_t _hand_off_pending_halves(const process_t *proc, double present,
                                const uuid_t self_uuid, bool have_self)
{
    if (proc == NULL || !have_self)
        return 0;

    /* Snapshot the roster: sends happen outside every lock. */
    size_t n_peers = 0;
    public_identity_t *peers = NULL;
    peers_read_lock(proc);
    if (proc->protocol.num_peers > 0)
    {
        peers = calloc(proc->protocol.num_peers, sizeof(public_identity_t));
        for (size_t i = 0; peers != NULL && i < proc->protocol.num_peers; i++)
            if (processes_peer_is_member(proc, &proc->protocol.peers[i]))
                peers[n_peers++] = proc->protocol.peers[i];
    }
    peers_read_unlock(proc);

    char (*ids)[UUID_STRING_LEN + 1] =
        calloc(n_peers > 0 ? n_peers : 1, sizeof(*ids));
    bool *due = calloc(n_peers > 0 ? n_peers : 1, sizeof(bool));
    int *pass = calloc(n_peers > 0 ? n_peers : 1, sizeof(int));
    if (ids == NULL || due == NULL || pass == NULL)
    {
        free(peers); free(ids); free(due); free(pass);
        return 0;
    }
    for (size_t i = 0; i < n_peers; i++)
        uuid_unparse_lower(peers[i].uuid, ids[i]);

    rep_handoff_half_t halves[REP_HANDOFF_MAX_HALVES];
    size_t n_halves = 0, n_due = 0;

    pthread_mutex_lock(&rep_state.lock);
    /* Forget whoever left the roster. Collected first: the map's key index
     * must not change under the walk. */
    size_t n_seen = map_size(&rep_state.handoff_seen);
    char (*gone)[UUID_STRING_LEN + 1] =
        calloc(n_seen > 0 ? n_seen : 1, sizeof(*gone));
    size_t n_gone = 0;
    if (gone != NULL)
    {
        map_key_t key = NULL;
        data_t *value = NULL;
        map_entries_for_each(&rep_state.handoff_seen, key, value)
        {
            (void)value;
            bool present_now = false;
            for (size_t i = 0; i < n_peers && !present_now; i++)
                present_now = strcmp(ids[i], key) == 0;
            if (!present_now && n_gone < n_seen)
                at_strlcpy(gone[n_gone++], key, sizeof(gone[0]));
        }
        map_end_for_each
        for (size_t g = 0; g < n_gone; g++)
        {
            map_remove(&rep_state.handoff_seen, gone[g]);
            map_remove(&rep_state.handoff_passes, gone[g]);
        }
        free(gone);
    }
    for (size_t i = 0; i < n_peers; i++)
    {
        data_t *d = NULL;
        if (map_get(&rep_state.handoff_seen, (map_key_t)ids[i], &d) != 0
            || d == NULL)
        {
            map_set(&rep_state.handoff_seen, (map_key_t)ids[i],
                    integer_data((int)present));
            map_set(&rep_state.handoff_passes, (map_key_t)ids[i],
                    integer_data(0));
            continue;
        }
        int first = 0, done = 0;
        data_integer(d, &first);
        d = NULL;
        if (map_get(&rep_state.handoff_passes, (map_key_t)ids[i], &d) == 0
            && d != NULL)
            data_integer(d, &done);
        /* Every pass whose time has come counts, but a late tick sends once. */
        int now_done = done;
        while (now_done < REP_HANDOFF_PASSES
               && present >= (double)first + REP_HANDOFF_AT[now_done])
            now_done++;
        if (now_done == done)
            continue;
        map_set(&rep_state.handoff_passes, (map_key_t)ids[i],
                integer_data(now_done));
        due[i] = true;
        pass[i] = now_done;
        n_due++;
    }
    if (n_due > 0)
    {
        /* An unpaired half waits in the pool: a placed entry is always
         * paired or attested. */
        const tx_history_t *chain = &rep_state.history;
        for (int s = 0; s < chain->pool_len
                        && n_halves < REP_HANDOFF_MAX_HALVES; s++)
        {
            const transaction_t *t = &chain->pool[s];
            if (!t->p1_set || t->p2_set || t->attested
                || uuid_compare(t->p1_uuid, self_uuid) != 0)
                continue;
            rep_handoff_half_t *h = &halves[n_halves++];
            uuid_copy(h->task, t->task_uuid);
            h->score = t->p1_score;
            at_strlcpy(h->channel, t->p1_channel, sizeof(h->channel));
            const char *cert = tx_history_pool_cert(chain, t->task_uuid, self_uuid);
            h->cert = (cert != NULL) ? strdup(cert) : NULL;
        }
    }
    pthread_mutex_unlock(&rep_state.lock);

    size_t sent = 0;
    char self_str[UUID_STRING_LEN + 1];
    uuid_unparse_lower(self_uuid, self_str);
    for (size_t i = 0; i < n_peers && n_halves > 0; i++)
    {
        if (!due[i])
            continue;
        for (size_t k = 0; k < n_halves; k++)
        {
            const rep_handoff_half_t *h = &halves[k];
            char task_str[UUID_STRING_LEN + 1];
            uuid_unparse_lower(h->task, task_str);
            json_t *commit_json = json_object();
            if (commit_json == NULL)
                continue;
            /* The same fields, spelled the same way, as handle_accepted's
             * broadcast: the primary chain carries no group_uuid. */
            json_object_set_new(commit_json, "task_uuid", json_string(task_str));
            json_object_set_new(commit_json, "peer_uuid", json_string(self_str));
            json_object_set_new(commit_json, "score", json_real(h->score));
            if (h->channel[0] != '\0')
                json_object_set_new(commit_json, "channel",
                                    json_string(h->channel));
            if (h->cert != NULL)
            {
                json_t *cert = json_loads(h->cert, 0, NULL);
                if (json_is_object(cert))
                    json_object_set_new(commit_json, "certificate", cert);
                else
                    json_decref(cert);
            }
            generic_msg_t out = {0};
            out.type = NET_MESSAGE;
            strncpy(out.info.net_msg.process, "reputation", PROC_NAME_LEN);
            out.info.net_msg.function = REP_PROTO_COMMITTED;
            out.info.net_msg.encrypt = true;
            memcpy(&out.info.net_msg.to_whom, &peers[i],
                   sizeof(public_identity_t));
            net_msg_pack_json(&out.info.net_msg, commit_json);
            json_decref(commit_json);
            if (_rep_send_to_network(proc, &out) == 0)
                sent++;
            net_msg_free_obj(&out.info.net_msg);
        }
        log_info(proc->logger,
                 "Reputation: handed %zu pending half(s) of ours to %s "
                 "(pass %d of %d)\n", n_halves, peers[i].nickname, pass[i],
                 REP_HANDOFF_PASSES);
    }
    for (size_t k = 0; k < n_halves; k++)
        free(halves[k].cert);
    free(peers);
    free(ids);
    free(due);
    free(pass);
    return sent;
}

/* Originate a checkpoint on the interval, when the window has actually moved.
 *
 * Two guards, both about not spending the group's bandwidth for nothing. An
 * empty window has nothing to attest. A window whose head has not advanced
 * since the last checkpoint is already attested — re-signing it produces a new
 * epoch committing to the same root, which no verifier can use for anything
 * the previous one could not. Mirrors Python _maybe_checkpoint. */
static void _maybe_checkpoint(const process_t *proc, double present,
                              const char *self_uuid_str)
{
    if (REP_CHECKPOINT_INTERVAL <= 0)
        return;
    pthread_mutex_lock(&rep_state.lock);
    if (!rep_state.checkpoint_phase_taken)
    {
        rep_state.next_checkpoint_at = present + _checkpoint_phase(self_uuid_str);
        rep_state.checkpoint_phase_taken = true;
        pthread_mutex_unlock(&rep_state.lock);
        return;
    }
    if (present < rep_state.next_checkpoint_at)
    {
        pthread_mutex_unlock(&rep_state.lock);
        return;
    }
    rep_state.next_checkpoint_at = present + REP_CHECKPOINT_INTERVAL;

    /* Every chain, each on its own: an idle primary chain is skipped while a
     * busy child group is checkpointed, and each round is confined to the group
     * that can actually co-sign it (doc/architecture/gateway-reputation-tree.md). Collect the due chains under the
     * lock, originate after releasing it -- origination signs and sends. */
    char due_keys[DEFAULT_MAX_PEERS + 1][UUID_STRING_LEN + 1];
    int n_due = 0;
    array_t *child_keys = map_keys(&rep_state.child_hist);
    size_t n_child = array_size(child_keys);
    for (size_t ci = 0; ci <= n_child && n_due <= DEFAULT_MAX_PEERS; ci++)
    {
        const char *chain_key = "";
        if (ci > 0)
        {
            data_t *kd = NULL;
            map_key_t k = NULL;
            if (array_get(child_keys, (int)(ci - 1), &kd) != 0
                || data_string_ptr(kd, &k) != 0 || k == NULL)
                continue;
            chain_key = k;
        }
        tx_history_t *chain = _chain_for_key_locked(chain_key);
        rep_chain_ckpt_t *slot = _ckpt_slot_locked(chain_key);
        if (chain == NULL || slot == NULL)
            continue;
        int head = -1;
        for (int i = chain->chain_len - 1; i >= 0; i--)
        {
            if (chain->chain[i].index >= 0)
            {
                head = chain->chain[i].index;
                break;
            }
        }
        if (head < 0 || head <= slot->last_head)
            continue;
        slot->last_head = head;
        snprintf(due_keys[n_due], sizeof(due_keys[0]), "%s", chain_key);
        n_due++;
    }
    pthread_mutex_unlock(&rep_state.lock);
    for (int i = 0; i < n_due; i++)
        _originate_checkpoint(proc, self_uuid_str, due_keys[i]);
}

/****************************
 * Ordered placement (doc/architecture/reputation.md, "Agreeing on an order")
 *
 * Classic Paxos decides the chain's order. Instance k decides what the chain
 * holds from index k: a batch of ready items (completed bilateral tasks and
 * attested entries). An acceptor promises and accepts per chain; a grant
 * reports the value it last accepted at k, and a proposer holding a majority
 * of grants must carry the highest-ballot one of those rather than its own. A
 * decided placement is broadcast with a quorum certificate over
 * place_designation, and every member writes it at k exactly as given. Every
 * group places its order (the half round was retired 2026-10-16).
 *
 * This is the acceptor's and learner's half. Payloads are JSON objects, one
 * shape in both runtimes. Mirrors Python reputation/placement.py.
 ****************************/

#define REP_PLACEMENT_FILE "reputation-placement"
/* The pending pool, one file per chain: committed halves and certified
 * attestations not yet placed. Without it a restart of every holder would
 * lose them (their rounds are over; nobody proposes them again). */
#define REP_POOL_FILE "reputation-pool"
#define REP_POOL_SCHEMA 1
#define REP_PLACED_AHEAD_MAX 16

/* One chain's acceptor state: the highest ballot promised, and the value last
 * accepted at each open instance ("k" -> JSON text {"ballot", "value"}), plus
 * decided placements held ahead of the chain ("k" -> JSON text {"value",
 * "sigs"}). */
typedef struct rep_place_state_s {
    char    key[UUID_STRING_LEN + 1];
    bool    broken;
    bool    have_promised;
    int64_t prom_n;
    char    prom_by[UUID_STRING_LEN + 1];
    map_t   accepted;
    map_t   ahead;
    /* The proposer's side (_maybe_place): our open round, if any. */
    bool    round_open;
    int     round_k;
    int64_t round_n;
    char    round_head[TX_HASH_HEX_LEN + 1];
    json_t *round_grants;    /* voter -> accepted {ballot, value} or null */
    json_t *round_value;     /* the value we sent, once we sent it */
    char    round_digest[TX_HASH_HEX_LEN + 1];
    json_t *round_accepts;   /* voter -> signature */
    double  round_started;
    /* The pending pool's file: restored once, and the pool_rev last written
     * (pool_saved says whether there was a write). */
    bool     pool_restored;
    bool     pool_saved;
    unsigned pool_saved_rev;
    /* When ready items appeared at ready_k, when we last heard anyone work on
     * heard_k, who placed the previous instance, and our backoff. */
    int     ready_k;
    double  ready_since;
    int     heard_k;
    double  heard_at;
    char    placer[UUID_STRING_LEN + 1];
    double  backoff_until;
    /* The instance we may place at without asking, under the ballot a
     * majority promised us at the one before (the leader's skip). */
    bool    lead_set;
    int     lead_k;
    int64_t lead_n;
} rep_place_state_t;

/* A ballot: (n, proposer uuid), compared lexicographically, so two proposers
 * minting the same n are still ordered. */
static int _ballot_cmp(int64_t n1, const char *by1, int64_t n2, const char *by2)
{
    if (n1 != n2)
        return n1 < n2 ? -1 : 1;
    return strcmp(by1, by2);
}

static bool _parse_ballot(const json_t *obj, int64_t *n,
                          char by[UUID_STRING_LEN + 1])
{
    json_t *jn = json_object_get(obj, "n");
    const char *jb = json_string_value(json_object_get(obj, "by"));
    if (!json_is_integer(jn) || jb == NULL || strlen(jb) != UUID_STRING_LEN)
        return false;
    *n = json_integer_value(jn);
    for (size_t i = 0; i <= UUID_STRING_LEN; i++)
        by[i] = (char)tolower((unsigned char)jb[i]);
    return true;
}

static json_t *_ballot_json(int64_t n, const char *by)
{
    return json_pack("{s:I, s:s}", "n", (json_int_t)n, "by", by);
}

/* Test seam: where placement state lives instead of the config directory. */
static char g_placement_dir[CFG_PATH_LEN + 1];

static int _place_file_path(const char *base, const char *key, char *out,
                            size_t cap)
{
    char cfg_dir[CFG_PATH_LEN + 1] = {0};
    if (g_placement_dir[0] != '\0')
        at_strlcpy(cfg_dir, g_placement_dir, sizeof(cfg_dir));
    else if (get_cfg_dir(cfg_dir, sizeof(cfg_dir)) < 0)
        return -1;
    int n = snprintf(out, cap, "%s/%s%s%s%s", cfg_dir, base,
                     key[0] != '\0' ? "-" : "", key, CFG_FILE_EXT);
    return (n < 0 || (size_t)n >= cap) ? -1 : 0;
}

static int _placement_path(const char *key, char *out, size_t cap)
{
    return _place_file_path(REP_PLACEMENT_FILE, key, out, cap);
}

static void _load_place_state(const process_t *proc, rep_place_state_t *st)
{
    char path[CFG_PATH_LEN + 128] = {0};
    if (_placement_path(st->key, path, sizeof(path)) != 0)
        return;
    FILE *f = fopen(path, "r");
    if (f == NULL)
        return;   /* cold start */
    json_error_t err;
    json_t *doc = json_loadf(f, 0, &err);
    fclose(f);
    json_t *prom = doc != NULL ? json_object_get(doc, "promised") : NULL;
    json_t *acc = doc != NULL ? json_object_get(doc, "accepted") : NULL;
    if (doc == NULL || !json_is_object(doc)
        || (prom != NULL && !json_is_null(prom)
            && !_parse_ballot(prom, &st->prom_n, st->prom_by))
        || (acc != NULL && !json_is_object(acc)))
    {
        if (proc != NULL)
            log_error(proc->logger, "Reputation: placement state %s is unreadable; "
                      "left in place, and this node will promise nothing until it "
                      "is repaired\n", path);
        st->broken = true;
        json_decref(doc);
        return;
    }
    st->have_promised = prom != NULL && !json_is_null(prom);
    const char *k = NULL;
    json_t *rec = NULL;
    json_object_foreach(acc, k, rec)
    {
        char *text = json_dumps(rec, JSON_COMPACT);
        if (text != NULL)
            map_set(&st->accepted, (map_key_t)k, string_data((string_t)text, strlen(text)));
        free(text);
    }
    json_decref(doc);
}

/* Write the acceptor state before answering, so a promise or an acceptance
 * this node sent is one it still holds after a restart. Atomic: written
 * beside the file and renamed over it. */
static bool _persist_place_state(const process_t *proc, const rep_place_state_t *st)
{
    char path[CFG_PATH_LEN + 128] = {0};
    char tmp[CFG_PATH_LEN + 136] = {0};
    if (_placement_path(st->key, path, sizeof(path)) != 0)
        return false;
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    json_t *doc = json_object();
    json_object_set_new(doc, "promised", st->have_promised
                        ? _ballot_json(st->prom_n, st->prom_by) : json_null());
    json_t *acc = json_object();
    map_key_t k = NULL;
    data_t *v = NULL;
    map_entries_for_each((map_t *)&st->accepted, k, v)
    {
        char *text = NULL;
        if (data_string_ptr(v, &text) == 0 && text != NULL)
        {
            json_t *rec = json_loads(text, 0, NULL);
            if (rec != NULL)
                json_object_set_new(acc, (const char *)k, rec);
        }
    }
    map_end_for_each
    json_object_set_new(doc, "accepted", acc);
    bool ok = json_dump_file(doc, tmp, JSON_COMPACT) == 0 && rename(tmp, path) == 0;
    json_decref(doc);
    if (!ok)
        log_warn(proc->logger, "Reputation: could not persist placement state to %s\n",
                 path);
    return ok;
}

/* This node's acceptor state for chain @p key, restored from disk on first
 * use. Caller holds rep_state.lock. */
static rep_place_state_t *_place_state_locked(const process_t *proc, const char *key)
{
    for (int i = 0; i < rep_state.place_len; i++)
        if (strcmp(rep_state.place[i].key, key) == 0)
            return &rep_state.place[i];
    rep_place_state_t *grown = realloc(rep_state.place,
                                       (size_t)(rep_state.place_len + 1) * sizeof(*grown));
    if (grown == NULL)
        return NULL;
    rep_state.place = grown;
    rep_place_state_t *st = &rep_state.place[rep_state.place_len++];
    memset(st, 0, sizeof(*st));
    at_strlcpy(st->key, key, sizeof(st->key));
    st->ready_k = st->heard_k = -1;
    map_init(&st->accepted);
    map_init(&st->ahead);
    _load_place_state(proc, st);
    return st;
}

static void _place_round_close(rep_place_state_t *st)
{
    json_decref(st->round_grants);
    json_decref(st->round_value);
    json_decref(st->round_accepts);
    st->round_grants = st->round_value = st->round_accepts = NULL;
    st->round_open = false;
}

static void _place_states_free(void)
{
    for (int i = 0; i < rep_state.place_len; i++)
    {
        map_free(&rep_state.place[i].accepted);
        map_free(&rep_state.place[i].ahead);
        _place_round_close(&rep_state.place[i]);
    }
    free(rep_state.place);
    rep_state.place = NULL;
    rep_state.place_len = 0;
}

/* Drop the instances below @p next from a "k" -> text map. */
static void _place_prune_below(map_t *m, int next)
{
    array_t *keys = map_keys(m);
    for (size_t i = 0; keys != NULL && i < array_size(keys); i++)
    {
        data_t *kd = NULL;
        char *kstr = NULL;
        if (array_get(keys, (int)i, &kd) == 0 && data_string_ptr(kd, &kstr) == 0
            && kstr != NULL && atoi(kstr) < next)
            map_remove(m, (map_key_t)kstr);
    }
}

static const char *_place_text(map_t *m, int k)
{
    char key[24];
    snprintf(key, sizeof(key), "%d", k);
    data_t *d = NULL;
    char *text = NULL;
    if (map_get(m, (map_key_t)key, &d) != 0 || d == NULL
        || data_string_ptr(d, &text) != 0)
        return NULL;
    return text;
}

static void _place_set_text(map_t *m, int k, const char *text)
{
    char key[24];
    snprintf(key, sizeof(key), "%d", k);
    map_set(m, (map_key_t)key, string_data((string_t)text, strlen(text)));
}

/* One placement entry from its wire form, into @p tx; its certificates (if
 * any) borrowed from @p d into @p c1 / @p c2 (halves) or @p asigs (attested).
 * Mirrors Python entry_from_dict. */
static bool _place_entry_from_json(const json_t *d, transaction_t *tx,
                                   json_t **c1, json_t **c2, json_t **asigs)
{
    memset(tx, 0, sizeof(*tx));
    tx->index = -1;
    *c1 = *c2 = *asigs = NULL;
    if (!json_is_object(d))
        return false;
    json_t *r = json_object_get(d, "roster");
    if (r != NULL)
    {
        /* A roster entry (doc/architecture/reputation.md, "Who is in the
         * group"): its member list must reproduce its digest. Mirrors Python
         * entry_from_dict. */
        const char *task = json_string_value(json_object_get(d, "task"));
        const char *op = json_string_value(json_object_get(r, "op"));
        const char *who = json_string_value(json_object_get(r, "uuid"));
        const char *dig = json_string_value(json_object_get(r, "digest"));
        char want[TX_HASH_HEX_LEN + 1];
        if (task == NULL || uuid_parse(task, tx->task_uuid) != 0
            || !tx_roster_op_valid(op) || dig == NULL
            || roster_digest(json_object_get(r, "members"), want, NULL) != 0
            || strcmp(want, dig) != 0
            || (who != NULL && uuid_parse(who, tx->roster_uuid) != 0))
            return false;
        /* The declared N_min: absent or null is none; anything but a
         * non-negative integer is malformed. */
        json_t *nm = json_object_get(r, "n_min");
        if (nm != NULL && !json_is_null(nm)
            && (!json_is_integer(nm) || json_integer_value(nm) < 0
                || json_integer_value(nm) > INT_MAX))
            return false;
        tx->roster = true;
        at_strlcpy(tx->roster_op, op, sizeof(tx->roster_op));
        at_strlcpy(tx->roster_digest, dig, sizeof(tx->roster_digest));
        tx->roster_n_min = json_is_integer(nm) ? (int)json_integer_value(nm) : 0;
        return true;
    }
    const char *task = json_string_value(json_object_get(d, "task"));
    const char *p1 = json_string_value(json_object_get(d, "p1"));
    json_t *s1 = json_object_get(d, "p1_score");
    const char *ch1 = json_string_value(json_object_get(d, "p1_channel"));
    if (task == NULL || p1 == NULL || !json_is_number(s1)
        || uuid_parse(task, tx->task_uuid) != 0 || uuid_parse(p1, tx->p1_uuid) != 0)
        return false;
    tx->p1_set = true;
    tx->p1_score = json_number_value(s1);
    if (!(tx->p1_score >= 0.0 && tx->p1_score <= 1.0))
        return false;
    if (ch1 != NULL && ch1[0] != '\0')
    {
        if (!tx_channel_valid(ch1))
            return false;
        at_strlcpy(tx->p1_channel, ch1, sizeof(tx->p1_channel));
    }
    if (json_is_true(json_object_get(d, "attested")))
    {
        const char *subj = json_string_value(json_object_get(d, "subject"));
        const char *dig = json_string_value(json_object_get(d, "evidence_digest"));
        const char *scope = json_string_value(json_object_get(d, "attest_scope"));
        if (subj == NULL || dig == NULL || uuid_parse(subj, tx->subject_uuid) != 0)
            return false;
        tx->attested = true;
        at_strlcpy(tx->evidence_digest, dig, sizeof(tx->evidence_digest));
        if (scope != NULL)
            at_strlcpy(tx->attest_scope, scope, sizeof(tx->attest_scope));
        *asigs = json_object_get(d, "attest_sigs");
        return true;
    }
    const char *p2 = json_string_value(json_object_get(d, "p2"));
    json_t *s2 = json_object_get(d, "p2_score");
    const char *ch2 = json_string_value(json_object_get(d, "p2_channel"));
    if (p2 == NULL || !json_is_number(s2) || uuid_parse(p2, tx->p2_uuid) != 0)
        return false;
    tx->p2_set = true;
    tx->p2_score = json_number_value(s2);
    if (!(tx->p2_score >= 0.0 && tx->p2_score <= 1.0))
        return false;
    if (ch2 != NULL && ch2[0] != '\0')
    {
        if (!tx_channel_valid(ch2))
            return false;
        at_strlcpy(tx->p2_channel, ch2, sizeof(tx->p2_channel));
    }
    *c1 = json_object_get(d, "p1_cert");
    *c2 = json_object_get(d, "p2_cert");
    return true;
}

/* --- pool persistence --------------------------------------------------- */

/* The certificate JSON text kept under @p key in @p m, parsed, or NULL. */
static json_t *_pool_cert_json(const map_t *m, const char *key)
{
    data_t *d = NULL;
    char *text = NULL;
    if (map_get((map_t *)m, (map_key_t)key, &d) != 0 || d == NULL
        || data_string_ptr(d, &text) != 0 || text == NULL)
        return NULL;
    return json_loads(text, 0, NULL);
}

/* The pool as persisted (reputation-pool[-<chain>].cfg.json), oldest first. A
 * half keeps its scorer, score, channel and commit certificate; an attested
 * entry is written as a placement writes it. Mirrors Python
 * TransactionHistory.pool_to_dict. */
static json_t *_pool_to_json(const tx_history_t *h)
{
    json_t *items = json_array();
    for (int i = 0; i < h->pool_len; i++)
    {
        const transaction_t *tx = &h->pool[i];
        char t[UUID_STRING_LEN + 1];
        uuid_unparse_lower(tx->task_uuid, t);
        json_t *d = json_object();
        json_object_set_new(d, "task", json_string(t));
        if (tx->attested)
        {
            char a[UUID_STRING_LEN + 1], sj[UUID_STRING_LEN + 1];
            uuid_unparse_lower(tx->p1_uuid, a);
            uuid_unparse_lower(tx->subject_uuid, sj);
            json_object_set_new(d, "attested", json_true());
            json_object_set_new(d, "p1", json_string(a));
            json_object_set_new(d, "p1_score", json_real(tx->p1_score));
            json_object_set_new(d, "p1_channel", json_string(tx->p1_channel));
            json_object_set_new(d, "subject", json_string(sj));
            json_object_set_new(d, "evidence_digest", json_string(tx->evidence_digest));
            if (tx->attest_scope[0] != '\0')
                json_object_set_new(d, "attest_scope", json_string(tx->attest_scope));
            json_t *cert = _pool_cert_json(&h->pool_certs, t);
            if (cert != NULL)
                json_object_set_new(d, "attest_sigs", cert);
            json_array_append_new(items, d);
            continue;
        }
        json_t *halves = json_array();
        for (int side = 0; side < 2; side++)
        {
            if (!(side == 0 ? tx->p1_set : tx->p2_set))
                continue;
            char by[UUID_STRING_LEN + 1];
            uuid_unparse_lower(side == 0 ? tx->p1_uuid : tx->p2_uuid, by);
            const char *chan = side == 0 ? tx->p1_channel : tx->p2_channel;
            json_t *half = json_object();
            json_object_set_new(half, "by", json_string(by));
            json_object_set_new(half, "score",
                                json_real(side == 0 ? tx->p1_score : tx->p2_score));
            if (chan[0] != '\0')
                json_object_set_new(half, "channel", json_string(chan));
            char key[2 * UUID_STRING_LEN + 2];
            snprintf(key, sizeof(key), "%s|%s", t, by);
            json_t *cert = _pool_cert_json(&h->pool_certs, key);
            if (cert != NULL)
                json_object_set_new(half, "cert", cert);
            json_array_append_new(halves, half);
        }
        json_object_set_new(d, "halves", halves);
        json_array_append_new(items, d);
    }
    return json_pack("{s:i, s:o}", "schema", REP_POOL_SCHEMA, "pool", items);
}

/* Put back what _pool_to_json wrote, through tx_history_record_half and
 * tx_history_pool_attested, so a task since placed or tombstoned stays out. An
 * item that does not parse is skipped. Returns how many items are pooled
 * afterwards, or -1 when @p doc is not a pool document. Mirrors Python
 * TransactionHistory.pool_from_dict. */
static int _pool_from_json(tx_history_t *h, const json_t *doc)
{
    json_t *items = json_object_get(doc, "pool");
    json_t *schema = json_object_get(doc, "schema");
    if (!json_is_integer(schema) || json_integer_value(schema) != REP_POOL_SCHEMA
        || !json_is_array(items))
        return -1;
    size_t i;
    json_t *item;
    json_array_foreach(items, i, item)
    {
        if (!json_is_object(item))
            continue;
        if (json_is_true(json_object_get(item, "attested")))
        {
            transaction_t tx;
            json_t *c1, *c2, *as;
            if (!_place_entry_from_json(item, &tx, &c1, &c2, &as))
                continue;
            char *cert = json_is_object(as) ? json_dumps(as, JSON_COMPACT) : NULL;
            (void)tx_history_pool_attested(h, &tx, cert);
            free(cert);
            continue;
        }
        const char *task = json_string_value(json_object_get(item, "task"));
        uuid_t task_uuid;
        if (task == NULL || uuid_parse(task, task_uuid) != 0)
            continue;
        size_t j;
        json_t *half;
        json_array_foreach(json_object_get(item, "halves"), j, half)
        {
            const char *by = json_string_value(json_object_get(half, "by"));
            json_t *score = json_object_get(half, "score");
            const char *chan = json_string_value(json_object_get(half, "channel"));
            json_t *cert = json_object_get(half, "cert");
            uuid_t by_uuid;
            if (by == NULL || uuid_parse(by, by_uuid) != 0 || !json_is_number(score)
                || !(json_number_value(score) >= 0.0 && json_number_value(score) <= 1.0))
                continue;
            char *text = json_is_object(cert) ? json_dumps(cert, JSON_COMPACT) : NULL;
            (void)tx_history_record_half(h, task_uuid, by_uuid, json_number_value(score),
                                         chan, text);
            free(text);
        }
    }
    return h->pool_len;
}

/* Put chain @p key's persisted pool back, once per chain, before its pool is
 * next written. A broken file is logged and the pool starts empty. Caller
 * holds rep_state.lock. */
/* A chain that holds entries but no roster was written before membership
 * went in the chain (doc/architecture/reputation.md, "Who is in the group"),
 * or by a group that did not place its order before that mode was retired
 * (2026-10-16): nothing in it can be judged by a roster in force. It exists
 * only in development and cohort directories, so it is cleared -- chain,
 * placement state and pool -- and the group founds it anew (the user's
 * calls, 2026-10-14 and 2026-10-16). Primary chain; runs at boot before anything reads the
 * placement state. Caller holds rep_state.lock. Mirrors Python
 * _reset_pre_roster_chain. */
static bool _reset_pre_roster_chain_locked(const process_t *proc)
{
    tx_history_t *chain = &rep_state.history;
    if (tx_history_len(chain) == 0
        || tx_history_roster_at(chain, chain->next_index, NULL) == 0)
        return false;
    log_warn(proc->logger, "Reputation: placing chain primary holds %d entries "
             "and no roster: resetting it, its placement state and its pool\n",
             tx_history_len(chain));
    tx_history_free(chain);
    tx_history_init(chain);
    char path[CFG_PATH_LEN + 128];
    if (_place_file_path(REP_PLACEMENT_FILE, "", path, sizeof(path)) == 0)
        unlink(path);
    if (_place_file_path(REP_POOL_FILE, "", path, sizeof(path)) == 0)
        unlink(path);
    rep_place_state_t *st = _place_state_locked(proc, "");
    if (st != NULL)
    {
        _place_round_close(st);
        st->have_promised = false;
        st->lead_set = false;
        map_free(&st->accepted);
        map_init(&st->accepted);
        map_free(&st->ahead);
        map_init(&st->ahead);
    }
    return true;
}

static void _restore_pool_locked(const process_t *proc, const char *key)
{
    rep_place_state_t *st = _place_state_locked(proc, key);
    if (st == NULL || st->pool_restored)
        return;
    st->pool_restored = true;
    char path[CFG_PATH_LEN + 128] = {0};
    if (_place_file_path(REP_POOL_FILE, key, path, sizeof(path)) != 0)
        return;
    FILE *f = fopen(path, "r");
    if (f == NULL)
        return;
    json_error_t err;
    json_t *doc = json_loadf(f, 0, &err);
    fclose(f);
    int held = doc != NULL ? _pool_from_json(_chain_for_key_locked(key), doc) : -1;
    json_decref(doc);
    if (proc == NULL)
        return;
    if (held < 0)
        log_error(proc->logger, "Reputation: placement pool %s is unreadable; "
                  "starting with an empty pool\n", path);
    else
        log_info(proc->logger, "Reputation: placement pool restored for chain %s: "
                 "%d item(s)\n", key[0] != '\0' ? key : "primary", held);
}

/* Write chain @p key's pool if it has changed since it was last written.
 * Caller holds rep_state.lock. */
static void _persist_pool_locked(const process_t *proc, const char *key)
{
    _restore_pool_locked(proc, key);
    rep_place_state_t *st = _place_state_locked(proc, key);
    tx_history_t *chain = _chain_for_key_locked(key);
    if (st == NULL || (st->pool_saved && st->pool_saved_rev == chain->pool_rev))
        return;
    char path[CFG_PATH_LEN + 128] = {0};
    char tmp[CFG_PATH_LEN + 136] = {0};
    if (_place_file_path(REP_POOL_FILE, key, path, sizeof(path)) != 0)
        return;
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    json_t *doc = _pool_to_json(chain);
    bool ok = doc != NULL && json_dump_file(doc, tmp, JSON_COMPACT) == 0
        && rename(tmp, path) == 0;
    json_decref(doc);
    if (ok)
    {
        st->pool_saved = true;
        st->pool_saved_rev = chain->pool_rev;
    }
    else if (proc != NULL)
        log_warn(proc->logger, "Reputation: could not persist placement pool to %s\n",
                 path);
}

/* Write each placing chain's pool when it has changed. Runs on the process
 * loop. Mirrors Python PlacementMixin._persist_pools. */
static void _persist_pools(const process_t *proc)
{
    pthread_mutex_lock(&rep_state.lock);
    _persist_pool_locked(proc, "");
    array_t *keys = map_keys(&rep_state.child_hist);
    for (size_t i = 0; keys != NULL && i < array_size(keys); i++)
    {
        data_t *kd = NULL;
        char *key = NULL;
        if (array_get(keys, (int)i, &kd) == 0 && data_string_ptr(kd, &key) == 0
            && key != NULL && key[0] != '\0')
            _persist_pool_locked(proc, key);
    }
    pthread_mutex_unlock(&rep_state.lock);
}

/* A value's entries, or -1 when it is malformed. */
static int _place_value_from_json(const json_t *value, transaction_t *out)
{
    if (!json_is_array(value) || json_array_size(value) < 1
        || json_array_size(value) > PLACE_BATCH_MAX)
        return -1;
    for (size_t i = 0; i < json_array_size(value); i++)
    {
        json_t *c1, *c2, *as;
        if (!_place_entry_from_json(json_array_get(value, i), &out[i], &c1, &c2, &as))
            return -1;
    }
    return (int)json_array_size(value);
}

/* ---- Who is in the group: proposing and accepting roster entries -------
 *
 * The members deciding instance k are those of the roster logged before it
 * (doc/architecture/reputation.md, "Who is in the group"). A placing chain's
 * first entry is a genesis roster, decided by every member it lists; after
 * that, each member it does not yet list is added by one roster entry,
 * decided by a majority of the roster before it, and a roster about to leave
 * the resident window is restated. Rosters only grow (the user's call,
 * 2026-10-14). A roster entry is placed alone and ahead of any ready item.
 * Mirrors the "who is in the group" part of Python PlacementMixin. */

static bool _place_peer_in_chain(const process_t *proc,
                                 const public_identity_t *peer, const char *key);

/* This node and the live members of chain @p key's group, each with its
 * signing key, canonical (a new reference), or NULL. Caller must NOT hold the
 * peers lock. Mirrors Python _live_roster. */
static json_t *_live_roster(const process_t *proc, const char *key)
{
    const identity_t *self = identity_self_identity(proc);
    if (self == NULL)
        return NULL;
    json_t *raw = json_array();
    char u[UUID_STRING_LEN + 1], k[2 * crypto_sign_PUBLICKEYBYTES + 1];
    uuid_unparse_lower(self->uuid, u);
    sodium_bin2hex(k, sizeof(k), self->signature.public, crypto_sign_PUBLICKEYBYTES);
    json_array_append_new(raw, json_pack("[s, s]", u, k));
    peers_read_lock(proc);
    for (size_t i = 0; i < proc->protocol.num_peers; i++)
    {
        const public_identity_t *p = &proc->protocol.peers[i];
        if (!_place_peer_in_chain(proc, p, key) || uuid_compare(p->uuid, self->uuid) == 0)
            continue;
        uuid_unparse_lower(p->uuid, u);
        sodium_bin2hex(k, sizeof(k), p->signature.public, crypto_sign_PUBLICKEYBYTES);
        json_array_append_new(raw, json_pack("[s, s]", u, k));
    }
    peers_read_unlock(proc);
    json_t *norm = NULL;
    char d[TX_HASH_HEX_LEN + 1];
    if (roster_digest(raw, d, &norm) != 0)
        norm = NULL;
    json_decref(raw);
    return norm;
}

/* A roster entry on the placement wire (borrowing @p members), declaring
 * @p n_min when it is > 0. */
static json_t *_roster_entry_json(const uuid_t task, const char *op,
                                  const char *who, const char *digest,
                                  json_t *members, int n_min)
{
    char t[UUID_STRING_LEN + 1];
    uuid_unparse_lower(task, t);
    json_t *r = json_object();
    json_object_set_new(r, "op", json_string(op));
    json_object_set_new(r, "uuid", who != NULL ? json_string(who) : json_null());
    json_object_set_new(r, "digest", json_string(digest));
    json_object_set(r, "members", members);
    if (n_min > 0)
        json_object_set_new(r, "n_min", json_integer(n_min));
    json_t *e = json_object();
    json_object_set_new(e, "task", json_string(t));
    json_object_set_new(e, "roster", r);
    return e;
}

/* The roster in force for the next instance of chain @p key (copied to
 * @p r), its member list (a new reference, or NULL), the chain's next index
 * and length. Caller must NOT hold rep_state.lock. */
static json_t *_roster_now(const char *key, transaction_t *r, bool *have,
                           int *next, int *len)
{
    pthread_mutex_lock(&rep_state.lock);
    tx_history_t *chain = _chain_for_key_locked(key);
    *next = chain->next_index;
    *len = tx_history_len(chain);
    *have = tx_history_roster_at(chain, chain->next_index, r) == 0;
    const char *mt = *have ? tx_history_roster_members(chain, r->roster_digest) : NULL;
    json_t *cur = mt != NULL ? json_loads(mt, 0, NULL) : NULL;
    pthread_mutex_unlock(&rep_state.lock);
    return cur;
}

/* ---- The declared N_min (RD_13.2 plan section 0.4) -----------------------
 *
 * A roster entry may declare the group's N_min, and with it the F the
 * certificate rounds are sized for. A genesis declares none. Each member
 * reports its configured value in every place_accepted, and the member
 * leading a placement restates the roster with value X once a strict majority
 * of the roster in force has reported X, whatever it is configured for
 * itself: a leader proposing its own value could have it accepted by itself
 * alone, and every later proposer at that index would then have to carry a
 * value most acceptors refuse. An acceptor takes a value only if it is the one
 * in force or the one it is configured for. Mirrors Python placement.py,
 * "the declared N_min". */

/* AT_REP_N_MIN: 0 when unset or empty, the value, or -1 when it is not a
 * non-negative integer (fatal at reputation_run). Mirrors Python _env_n_min. */
static int _env_n_min(void)
{
    const char *raw = getenv("AT_REP_N_MIN");
    if (raw == NULL)
        return 0;
    while (isspace((unsigned char)*raw))
        raw++;
    if (*raw == '\0')
        return 0;
    char *end = NULL;
    errno = 0;
    long v = strtol(raw, &end, 10);
    while (end != NULL && isspace((unsigned char)*end))
        end++;
    if (errno != 0 || end == raw || end == NULL || *end != '\0' || v < 0
        || v > INT_MAX)
        return -1;
    return (int)v;
}

/* The N_min this node is configured for, 0 for none. */
static int _n_min_config(void)
{
    int n = _env_n_min();
    return n > 0 ? n : 0;
}

/* Is there an N_min a strict majority of @p roster's members reports (this
 * node's configuration standing for its own report)? Writes it to @p out.
 * Caller does not hold rep_state.lock. Mirrors Python _n_min_majority. */
static bool _n_min_majority(const process_t *proc, const char *key,
                            const json_t *roster, int *out)
{
    char me[UUID_STRING_LEN + 1] = {0};
    uuid_t self_u;
    if (_resolve_self_uuid(proc, self_u))
        uuid_unparse_lower(self_u, me);
    size_t listed = json_array_size(roster);
    if (listed == 0)
        return false;
    int *vals = calloc(listed, sizeof(int));
    if (vals == NULL)
        return false;
    size_t n = 0, i;
    json_t *m;
    pthread_mutex_lock(&rep_state.lock);
    json_t *seen = json_object_get(rep_state.place_n_min_seen, key);
    json_array_foreach((json_t *)roster, i, m)
    {
        const char *u = json_string_value(json_array_get(m, 0));
        if (u == NULL)
            continue;
        if (strcmp(u, me) == 0)
            vals[n++] = _n_min_config();
        else
        {
            json_t *v = json_object_get(seen, u);
            if (json_is_integer(v))
                vals[n++] = (int)json_integer_value(v);
        }
    }
    pthread_mutex_unlock(&rep_state.lock);
    bool found = false;
    for (size_t a = 0; a < n && !found; a++)
    {
        size_t count = 0;
        for (size_t b = 0; b < n; b++)
            if (vals[b] == vals[a])
                count++;
        if (count >= listed / 2 + 1)
        {
            *out = vals[a];
            found = true;
        }
    }
    free(vals);
    return found;
}

/* The roster entry this node would place next on chain @p key (wire form, a
 * new reference), or NULL: a genesis of its live view on an empty chain, an
 * add of the first live member the roster in force lacks, or a restatement
 * of a roster half a window old. Mirrors Python _roster_item. */
static json_t *_roster_item(const process_t *proc, const char *key)
{
    json_t *live = _live_roster(proc, key);
    if (live == NULL)
        return NULL;
    transaction_t r;
    bool have = false;
    int next = 0, len = 0;
    json_t *cur = _roster_now(key, &r, &have, &next, &len);
    json_t *out = NULL;
    char d[TX_HASH_HEX_LEN + 1];
    uuid_t t;
    if (!have)
    {
        if (next == 0 && len == 0 && json_array_size(live) >= 2
            && roster_digest(live, d, NULL) == 0)
        {
            tx_roster_task_uuid(NULL, "genesis", NULL, d, t);
            out = _roster_entry_json(t, "genesis", NULL, d, live, 0);
        }
    }
    else if (cur != NULL)
    {
        const char *who = NULL, *wk = NULL;
        size_t i;
        json_t *m;
        json_array_foreach(live, i, m)
        {
            const char *u = json_string_value(json_array_get(m, 0));
            if (u != NULL && _roster_key_of(cur, u) == NULL)
            {
                who = u;
                wk = json_string_value(json_array_get(m, 1));
                break;
            }
        }
        if (who != NULL)
        {
            json_t *members = json_deep_copy(cur), *norm = NULL;
            json_array_append_new(members, json_pack("[s, s]", who, wk));
            uuid_t wu;
            if (roster_digest(members, d, &norm) == 0 && uuid_parse(who, wu) == 0)
            {
                tx_roster_task_uuid_n(r.task_uuid, "add", wu, d, r.roster_n_min, t);
                out = _roster_entry_json(t, "add", who, d, norm, r.roster_n_min);
            }
            json_decref(norm);
            json_decref(members);
        }
        else
        {
            /* A strict majority of the roster reports another N_min: restate
             * the roster declaring it, whatever our own configuration. */
            int target = 0;
            bool change = _n_min_majority(proc, key, cur, &target)
                && target != r.roster_n_min;
            if (change || (r.index >= 0 && next - r.index >= MAX_CHAIN_LEN / 2))
            {
                int n_min = change ? target : r.roster_n_min;
                tx_roster_task_uuid_n(r.task_uuid, "restate", NULL, r.roster_digest,
                                      n_min, t);
                out = _roster_entry_json(t, "restate", NULL, r.roster_digest, cur,
                                         n_min);
            }
        }
    }
    json_decref(cur);
    json_decref(live);
    return out;
}

/* Has chain @p key a roster in force? Nothing but a genesis is placed,
 * accepted or learned before. Caller holds rep_state.lock. Mirrors Python
 * _founded. */
static bool _founded_locked(const char *key)
{
    tx_history_t *chain = _chain_for_key_locked(key);
    return tx_history_roster_at(chain, chain->next_index, NULL) == 0;
}

/* The members of @p value if it is a single genesis roster entry (canonical,
 * a new reference), else NULL. */
static json_t *_value_genesis(const json_t *value)
{
    if (!json_is_array(value) || json_array_size(value) != 1)
        return NULL;
    json_t *r = json_object_get(json_array_get(value, 0), "roster");
    const char *op = json_string_value(json_object_get(r, "op"));
    if (op == NULL || strcmp(op, "genesis") != 0)
        return NULL;
    json_t *norm = NULL;
    char d[TX_HASH_HEX_LEN + 1];
    const char *dig = json_string_value(json_object_get(r, "digest"));
    if (roster_digest(json_object_get(r, "members"), d, &norm) != 0
        || dig == NULL || strcmp(d, dig) != 0)
    {
        json_decref(norm);
        return NULL;
    }
    return norm;
}

/* Why a value holding a roster entry cannot be accepted on chain @p key now,
 * or NULL when it can. A declared N_min must be the one in force (none
 * before the genesis) or, with @p config_check, the one this node is
 * configured for. Mirrors Python _roster_value_ok. */
static const char *_roster_value_why(const process_t *proc, const char *key,
                                     const json_t *value, bool config_check)
{
    if (json_array_size(value) != 1)
        return "a roster entry is placed alone";
    json_t *e = json_array_get(value, 0);
    json_t *ro = json_object_get(e, "roster");
    const char *op = json_string_value(json_object_get(ro, "op"));
    const char *who = json_string_value(json_object_get(ro, "uuid"));
    const char *dig = json_string_value(json_object_get(ro, "digest"));
    const char *task = json_string_value(json_object_get(e, "task"));
    json_t *members = NULL;
    char d[TX_HASH_HEX_LEN + 1];
    uuid_t tu, want, wu;
    if (!tx_roster_op_valid(op) || dig == NULL || task == NULL
        || uuid_parse(task, tu) != 0
        || roster_digest(json_object_get(ro, "members"), d, &members) != 0
        || strcmp(d, dig) != 0)
    {
        json_decref(members);
        return "roster members do not match their digest";
    }
    json_t *nm = json_object_get(ro, "n_min");
    if (nm != NULL && !json_is_null(nm)
        && (!json_is_integer(nm) || json_integer_value(nm) < 0
            || json_integer_value(nm) > INT_MAX))
    {
        json_decref(members);
        return "a malformed n_min";
    }
    int n_min = json_is_integer(nm) ? (int)json_integer_value(nm) : 0;
    json_t *live = _live_roster(proc, key);
    transaction_t r;
    bool have = false;
    int next = 0, len = 0;
    json_t *cur = _roster_now(key, &r, &have, &next, &len);
    char me[UUID_STRING_LEN + 1] = {0};
    uuid_t self_u;
    if (_resolve_self_uuid(proc, self_u))
        uuid_unparse_lower(self_u, me);
    const char *why = NULL;
    size_t i;
    json_t *m;
    int in_force = have ? r.roster_n_min : 0;
    if (n_min != in_force && config_check && n_min != _n_min_config())
        why = "a declared n_min that is neither ours nor the one in force";
    if (strcmp(op, "genesis") == 0)
    {
        if (why != NULL)
            ;
        else if (have || next != 0)
            why = "genesis on a chain that has one";
        else if (_roster_key_of(members, me) == NULL)
            why = "a genesis that leaves us out";
        else
            json_array_foreach(members, i, m)
            {
                const char *u = json_string_value(json_array_get(m, 0));
                const char *lk = live != NULL ? _roster_key_of(live, u) : NULL;
                if (lk == NULL || strcmp(lk, json_string_value(json_array_get(m, 1))) != 0)
                    why = "a genesis naming a member we do not see";
            }
        tx_roster_task_uuid_n(NULL, "genesis", NULL, dig, n_min, want);
    }
    else if (!have || cur == NULL)
        why = "a roster change with no roster in force";
    else if (strcmp(op, "add") == 0)
    {
        if (why != NULL)
            ;
        else if (who == NULL || uuid_parse(who, wu) != 0 || _roster_key_of(cur, who) != NULL)
            why = "an add of nobody new";
        else if (n_min != in_force)
            why = "an add that changes the declared n_min";
        else if (json_array_size(members) != json_array_size(cur) + 1)
            why = "an add that changes more than one member";
        else
        {
            json_array_foreach(cur, i, m)
            {
                const char *u = json_string_value(json_array_get(m, 0));
                const char *mk = _roster_key_of(members, u);
                if (mk == NULL || strcmp(mk, json_string_value(json_array_get(m, 1))) != 0)
                    why = "an add that changes more than one member";
            }
            const char *nk = _roster_key_of(members, who);
            const char *lk = live != NULL ? _roster_key_of(live, who) : NULL;
            if (why == NULL && (nk == NULL || lk == NULL || strcmp(nk, lk) != 0))
                why = "an add of a member we do not see";
        }
        if (who != NULL && uuid_parse(who, wu) == 0)
            tx_roster_task_uuid_n(r.task_uuid, "add", wu, dig, n_min, want);
    }
    else
    {
        if (why != NULL)
            ;
        else if (strcmp(dig, r.roster_digest) != 0)
            why = "a restatement that changes the roster";
        else if (n_min == in_force && (r.index < 0 || next - r.index < MAX_CHAIN_LEN / 2))
            why = "a restatement too early";
        tx_roster_task_uuid_n(r.task_uuid, "restate", NULL, dig, n_min, want);
    }
    if (why == NULL && uuid_compare(want, tu) != 0)
        why = "a roster entry with the wrong task id";
    json_decref(members);
    json_decref(live);
    json_decref(cur);
    return why;
}

/* Why @p value cannot be placed on the chain at @p key now, or NULL when it
 * can: one of each task, by task id; nothing already held; every half
 * certified; every attestation well formed, on its quorum and under its rate
 * cap. Checked against this node's own prefix and its own view of the group,
 * before accepting, so a decided value is valid by construction. Mirrors
 * Python PlacementMixin._place_value_ok. */
static const char *_place_value_why(const process_t *proc, const char *key,
                                    const json_t *value, const char *group,
                                    bool config_check)
{
    size_t vi;
    json_t *ve;
    json_array_foreach((json_t *)value, vi, ve)
        if (json_object_get(ve, "roster") != NULL)
            return _roster_value_why(proc, key, value, config_check);
    pthread_mutex_lock(&rep_state.lock);
    bool founded = _founded_locked(key);
    pthread_mutex_unlock(&rep_state.lock);
    if (!founded)
        return "nothing is placed before the genesis";
    transaction_t *entries = calloc(PLACE_BATCH_MAX, sizeof(transaction_t));
    if (entries == NULL)
        return "out of memory";
    const char *why = NULL;
    int n = _place_value_from_json(value, entries);
    if (n < 0)
        why = "malformed";
    for (int i = 0; why == NULL && i < n; i++)
    {
        transaction_t *tx = &entries[i];
        char task_str[UUID_STRING_LEN + 1], prev[UUID_STRING_LEN + 1];
        uuid_unparse_lower(tx->task_uuid, task_str);
        if (i > 0)
        {
            uuid_unparse_lower(entries[i - 1].task_uuid, prev);
            if (strcmp(prev, task_str) >= 0)
            {
                why = "not one of each task, by task id";
                break;
            }
        }
        pthread_mutex_lock(&rep_state.lock);
        tx_history_t *chain = _chain_for_key_locked(key);
        data_t *d = NULL;
        int slot = -1;
        bool held = (map_get(&chain->task_map, (map_key_t)task_str, &d) == 0
                     && data_integer(d, &slot) == 0 && slot >= 0
                     && slot < chain->chain_len
                     && tx_is_committed(&chain->chain[slot]))
            || map_get(&chain->evicted_set, (map_key_t)task_str, &d) == 0;
        bool resident = false;
        rep_attest_t a;
        memset(&a, 0, sizeof(a));
        if (tx->attested)
        {
            uuid_unparse_lower(tx->p1_uuid, a.verifier);
            uuid_unparse_lower(tx->subject_uuid, a.subject);
            a.score = tx->p1_score;
            at_strlcpy(a.channel, tx->p1_channel, sizeof(a.channel));
            at_strlcpy(a.digest, tx->evidence_digest, sizeof(a.digest));
            at_strlcpy(a.scope, tx->attest_scope, sizeof(a.scope));
            resident = _attest_well_formed(&a) && _attest_resident_locked(chain, &a);
        }
        pthread_mutex_unlock(&rep_state.lock);
        if (held)
        {
            why = "a task is already held";
            break;
        }
        json_t *c1, *c2, *as;
        (void)_place_entry_from_json(json_array_get(value, (size_t)i), tx, &c1, &c2, &as);
        if (tx->attested)
        {
            uuid_t want;
            tx_attest_task_uuid(tx->p1_uuid, tx->subject_uuid, tx->evidence_digest, want);
            if (!_attest_well_formed(&a) || uuid_compare(want, tx->task_uuid) != 0)
                why = "malformed attestation";
            else if (!_attest_quorum_met(proc, &a, as))
                why = "an attestation lacks its quorum";
            else if (resident)
                why = "an attestation is over its rate cap";
            continue;
        }
        char a1[UUID_STRING_LEN + 1], a2[UUID_STRING_LEN + 1];
        uuid_unparse_lower(tx->p1_uuid, a1);
        uuid_unparse_lower(tx->p2_uuid, a2);
        if (strcmp(a1, a2) >= 0)
            why = strcmp(a1, a2) == 0 ? "an entry is not bilateral"
                                      : "an entry's halves are out of order";
        else if (!_commit_cert_ok(proc, tx->p1_uuid, tx->task_uuid, tx->p1_score,
                                  tx->p1_channel, c1, group)
                 || !_commit_cert_ok(proc, tx->p2_uuid, tx->task_uuid, tx->p2_score,
                                     tx->p2_channel, c2, group))
            why = "a half is not certified";
    }
    free(entries);
    return why;
}

static void _note_place_heard(const process_t *proc, const char *key, int k);

static void _place_send(const process_t *proc, char *function,
                        const public_identity_t *to, json_t *payload)
{
    _attest_send(proc, function, to, payload);
}

/* Is @p peer a member of chain @p key's group? Every peer for the primary
 * chain, or for a child chain whose group we no longer hold. Caller holds the
 * peers read lock. Mirrors Python PlacementMixin._place_members. */
static bool _place_peer_in_chain(const process_t *proc,
                                 const public_identity_t *peer, const char *key)
{
    if (key == NULL || key[0] == '\0' || _child_group_locked(proc, key) == NULL)
        return processes_peer_is_member(proc, peer);
    return _peer_in_group(proc, peer, key);
}

/* A round's broadcast: to chain @p key's group, so a child chain's round
 * reaches that group's members alone. Mirrors Python _place_target. */
static void _place_broadcast(const process_t *proc, char *function,
                             const char *key, json_t *payload)
{
    if (key == NULL || key[0] == '\0')
    {
        _attest_send(proc, function, NULL, payload);
        return;
    }
    peers_read_lock(proc);
    size_t n = proc->protocol.num_peers, m = 0;
    public_identity_t *members = calloc(n > 0 ? n : 1, sizeof(public_identity_t));
    for (size_t i = 0; members != NULL && i < n; i++)
        if (_place_peer_in_chain(proc, &proc->protocol.peers[i], key))
            members[m++] = proc->protocol.peers[i];
    peers_read_unlock(proc);
    for (size_t i = 0; members != NULL && i < m; i++)
        _attest_send(proc, function, &members[i], payload);
    free(members);
}

/* The payload of a placement message and the chain it is for, or NULL when
 * it is malformed, unverified, or for a chain that does not place. Caller owns
 * the payload. */
static json_t *_place_payload(const process_t *proc, net_msg_t *nmsg,
                              char key[UUID_STRING_LEN + 1],
                              const char **group, int *k)
{
    if (!nmsg->verified)
    {
        log_warn(proc->logger, "Reputation: rejecting unverified %s from %s\n",
                 nmsg->function, nmsg->from_whom.nickname);
        return NULL;
    }
    json_t *payload = NULL;
    if (net_msg_unpack_json(nmsg, &payload) != 0 || !json_is_object(payload))
    {
        json_decref(payload);
        return NULL;
    }
    json_t *jk = json_object_get(payload, "k");
    if (!json_is_integer(jk) || json_integer_value(jk) < 0
        || json_integer_value(jk) > INT32_MAX)
    {
        json_decref(payload);
        return NULL;
    }
    *k = (int)json_integer_value(jk);
    *group = json_string_value(json_object_get(payload, "group"));
    if (*group != NULL && (*group)[0] == '\0')
        *group = NULL;
    _chain_key(proc, *group, key, UUID_STRING_LEN + 1);
    return payload;
}

static bool _from_proposer(const net_msg_t *nmsg, const char *by)
{
    char sender[UUID_STRING_LEN + 1];
    uuid_unparse_lower(nmsg->from_whom.uuid, sender);
    return strcmp(sender, by) == 0;
}

static void _place_nack(const process_t *proc, net_msg_t *nmsg, json_t *payload,
                        int k, int next, const rep_place_state_t *st,
                        const char *why)
{
    log_debug(proc->logger, "Reputation: placement %d from %s refused: %s\n",
              k, nmsg->from_whom.nickname, why);
    json_t *nack = json_object();
    const char *group = json_string_value(json_object_get(payload, "group"));
    json_object_set_new(nack, "group", json_string(group != NULL ? group : ""));
    json_object_set_new(nack, "k", json_integer(k));
    json_t *ballot = json_object_get(payload, "ballot");
    json_object_set(nack, "ballot", ballot != NULL ? ballot : json_null());
    json_object_set_new(nack, "next", json_integer(next));
    if (st->have_promised)
        json_object_set_new(nack, "promised", _ballot_json(st->prom_n, st->prom_by));
    _place_send(proc, REP_PROTO_PLACE_NACK, &nmsg->from_whom, nack);
    json_decref(nack);
}

/* Instance k is open here only once everything below it is applied, and only
 * on the same prefix. Otherwise refuse, and catch up when we are behind.
 * Takes and releases rep_state.lock. */
static bool _place_position_ok(const process_t *proc, net_msg_t *nmsg,
                               json_t *payload, const char *key, int k)
{
    pthread_mutex_lock(&rep_state.lock);
    tx_history_t *chain = _chain_for_key_locked(key);
    int next = chain->next_index;
    char head[TX_HASH_HEX_LEN + 1];
    at_strlcpy(head, chain->head_hash, sizeof(head));
    rep_place_state_t *live = _place_state_locked(proc, key);
    rep_place_state_t snapshot = live != NULL ? *live : (rep_place_state_t){0};
    pthread_mutex_unlock(&rep_state.lock);
    if (live == NULL)
        return false;
    const char *theirs = json_string_value(json_object_get(payload, "head"));
    if (k != next)
    {
        _place_nack(proc, nmsg, payload, k, next, &snapshot, "not our next index");
        if (k > next)
            _request_chain_for(proc, &nmsg->from_whom, key);
        return false;
    }
    if (strcmp(theirs != NULL ? theirs : "", head) != 0)
    {
        _place_nack(proc, nmsg, payload, k, next, &snapshot, "extends another head");
        return false;
    }
    return true;
}

static bool handle_place_request(const process_t *proc, directory_t *queues,
                                 generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    char key[UUID_STRING_LEN + 1];
    const char *group = NULL;
    int k = 0;
    json_t *payload = _place_payload(proc, nmsg, key, &group, &k);
    if (payload == NULL)
        return true;
    int64_t n;
    char by[UUID_STRING_LEN + 1];
    char self_str[UUID_STRING_LEN + 1] = {0};
    uuid_t self_u;
    if (_resolve_self_uuid(proc, self_u))
        uuid_unparse_lower(self_u, self_str);
    if (!_parse_ballot(json_object_get(payload, "ballot"), &n, by)
        || !_from_proposer(nmsg, by)
        || !_place_deciders_ok(proc, key, k, self_str, by))
    {
        json_decref(payload);
        return true;
    }
    _note_place_heard(proc, key, k);
    if (!_place_position_ok(proc, nmsg, payload, key, k))
    {
        json_decref(payload);
        return true;
    }
    pthread_mutex_lock(&rep_state.lock);
    rep_place_state_t *st = _place_state_locked(proc, key);
    if (st == NULL || st->broken)
    {
        pthread_mutex_unlock(&rep_state.lock);
        json_decref(payload);
        return true;
    }
    if (st->have_promised && _ballot_cmp(n, by, st->prom_n, st->prom_by) <= 0)
    {
        rep_place_state_t snapshot = *st;
        int next = _chain_for_key_locked(key)->next_index;
        pthread_mutex_unlock(&rep_state.lock);
        _place_nack(proc, nmsg, payload, k, next, &snapshot, "outranked");
        json_decref(payload);
        return true;
    }
    st->have_promised = true;
    st->prom_n = n;
    at_strlcpy(st->prom_by, by, sizeof(st->prom_by));
    bool kept = _persist_place_state(proc, st);
    const char *held = _place_text(&st->accepted, k);
    json_t *accepted = held != NULL ? json_loads(held, 0, NULL) : NULL;
    pthread_mutex_unlock(&rep_state.lock);
    if (kept)
    {
        json_t *grant = json_object();
        json_object_set_new(grant, "group", json_string(group != NULL ? group : ""));
        json_object_set_new(grant, "k", json_integer(k));
        json_object_set_new(grant, "ballot", _ballot_json(n, by));
        if (accepted != NULL)
            json_object_set(grant, "accepted", accepted);
        _place_send(proc, REP_PROTO_PLACE_GRANT, &nmsg->from_whom, grant);
        json_decref(grant);
    }
    json_decref(accepted);
    json_decref(payload);
    return true;
}

static bool handle_place(const process_t *proc, directory_t *queues,
                         generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    char key[UUID_STRING_LEN + 1];
    const char *group = NULL;
    int k = 0;
    json_t *payload = _place_payload(proc, nmsg, key, &group, &k);
    if (payload == NULL)
        return true;
    int64_t n;
    char by[UUID_STRING_LEN + 1];
    char self_str[UUID_STRING_LEN + 1] = {0};
    uuid_t self_u;
    if (_resolve_self_uuid(proc, self_u))
        uuid_unparse_lower(self_u, self_str);
    if (!_parse_ballot(json_object_get(payload, "ballot"), &n, by)
        || !_from_proposer(nmsg, by)
        || !_place_deciders_ok(proc, key, k, self_str, by))
    {
        json_decref(payload);
        return true;
    }
    _note_place_heard(proc, key, k);
    if (!_place_position_ok(proc, nmsg, payload, key, k))
    {
        json_decref(payload);
        return true;
    }
    pthread_mutex_lock(&rep_state.lock);
    rep_place_state_t *st = _place_state_locked(proc, key);
    bool broken = st == NULL || st->broken;
    bool outranked = !broken && st->have_promised
        && _ballot_cmp(n, by, st->prom_n, st->prom_by) < 0;
    rep_place_state_t snapshot = broken ? (rep_place_state_t){0} : *st;
    int next = _chain_for_key_locked(key)->next_index;
    pthread_mutex_unlock(&rep_state.lock);
    if (broken || outranked)
    {
        if (outranked)
            _place_nack(proc, nmsg, payload, k, next, &snapshot, "outranked");
        json_decref(payload);
        return true;
    }
    json_t *value = json_object_get(payload, "value");
    const char *why = _place_value_why(proc, key, value, key[0] != '\0' ? group : NULL,
                                       true);
    if (why != NULL)
    {
        log_warn(proc->logger, "Reputation: not accepting placement %d from %s: %s\n",
                 k, nmsg->from_whom.nickname, why);
        json_decref(payload);
        return true;
    }
    transaction_t *entries = calloc(PLACE_BATCH_MAX, sizeof(transaction_t));
    int m = entries != NULL ? _place_value_from_json(value, entries) : -1;
    char digest[TX_HASH_HEX_LEN + 1] = {0};
    if (m > 0)
        place_value_digest(entries, m, k, digest);
    free(entries);

    pthread_mutex_lock(&rep_state.lock);
    tx_history_t *chain = _chain_for_key_locked(key);
    char head[TX_HASH_HEX_LEN + 1];
    at_strlcpy(head, chain->head_hash, sizeof(head));
    bool moved = chain->next_index != k
        || (st->have_promised && _ballot_cmp(n, by, st->prom_n, st->prom_by) < 0);
    bool kept = false;
    if (!moved && digest[0] != '\0')
    {
        st->have_promised = true;
        st->prom_n = n;
        at_strlcpy(st->prom_by, by, sizeof(st->prom_by));
        _place_prune_below(&st->accepted, k);
        json_t *rec = json_object();
        json_object_set_new(rec, "ballot", _ballot_json(n, by));
        json_object_set(rec, "value", value);
        char *text = json_dumps(rec, JSON_COMPACT);
        json_decref(rec);
        if (text != NULL)
        {
            _place_set_text(&st->accepted, k, text);
            free(text);
            kept = _persist_place_state(proc, st);
        }
    }
    pthread_mutex_unlock(&rep_state.lock);
    if (!kept)
    {
        json_decref(payload);
        return true;
    }
    uint8_t desig[PLACE_DESIG_MAX];
    size_t dlen = place_designation(k, head, digest, desig, sizeof(desig));
    char sig[REP_SIG_HEX_LEN + 1] = {0};
    if (dlen == 0 || _cosign_hex(proc, desig, dlen, sig, sizeof(sig)) != 0)
    {
        log_error(proc->logger, "Reputation: handle_place: cannot sign; not accepting\n");
        json_decref(payload);
        return true;
    }
    json_t *ok = json_object();
    json_object_set_new(ok, "group", json_string(group != NULL ? group : ""));
    json_object_set_new(ok, "k", json_integer(k));
    json_object_set_new(ok, "ballot", _ballot_json(n, by));
    json_object_set_new(ok, "digest", json_string(digest));
    json_object_set_new(ok, "sig", json_string(sig));
    if (_n_min_config() > 0)   /* our report (see "The declared N_min") */
        json_object_set_new(ok, "n_min", json_integer(_n_min_config()));
    _place_send(proc, REP_PROTO_PLACE_ACCEPTED, &nmsg->from_whom, ok);
    json_decref(ok);
    json_decref(payload);
    return true;
}

/* Does @p sigs certify @p value at @p k after @p head? A strict majority of
 * the group, counted from our own view, must have signed its
 * place_designation. Must NOT hold the peers lock. */
static bool _placement_certified(const process_t *proc, const transaction_t *entries,
                                 int m, int k, const char *head, json_t *sigs,
                                 const char *group)
{
    char digest[TX_HASH_HEX_LEN + 1];
    place_value_digest(entries, m, k, digest);
    uint8_t desig[PLACE_DESIG_MAX];
    size_t dlen = place_designation(k, head, digest, desig, sizeof(desig));
    if (digest[0] == '\0' || dlen == 0)
        return false;
    /* The roster in force for k decides, with the keys it records; the live
     * view only while the chain holds none. Mirrors Python
     * _placement_certified. */
    json_t *roster = _roster_at(group != NULL ? group : "", k);
    if (roster == NULL && m == 1 && entries[0].roster
        && strcmp(entries[0].roster_op, "genesis") == 0)
    {
        /* A genesis is decided by every member it lists. */
        pthread_mutex_lock(&rep_state.lock);
        const char *gt = tx_history_roster_members(
            _chain_for_key_locked(group != NULL ? group : ""), entries[0].roster_digest);
        json_t *g = gt != NULL ? json_loads(gt, 0, NULL) : NULL;
        pthread_mutex_unlock(&rep_state.lock);
        bool ok = g != NULL
            && _verified_cosigners_in(proc, g, sigs, desig, dlen) == json_array_size(g);
        json_decref(g);
        return ok;
    }
    if (roster != NULL)
    {
        bool ok = _verified_cosigners_in(proc, roster, sigs, desig, dlen)
            >= _roster_majority(roster);
        json_decref(roster);
        return ok;
    }
    return false;               /* nothing but a genesis before the roster */
}

/* _placement_certified for catch-up: the roster in force for @p k is the
 * latest below it among our own entries AND the segment @p arr's (its member
 * list checked against its digest), so a node can follow a roster change it
 * does not hold yet. Mirrors Python _placement_certified_indices. */
static bool _placement_certified_seg(const process_t *proc, const char *key,
                                     json_t *arr, const transaction_t *entries,
                                     int m, int k, const char *head, json_t *sigs,
                                     const char *group)
{
    transaction_t ours;
    int ours_at = -1;
    pthread_mutex_lock(&rep_state.lock);
    if (tx_history_roster_at(_chain_for_key_locked(key), k, &ours) == 0)
        ours_at = ours.index;
    pthread_mutex_unlock(&rep_state.lock);
    json_t *best = NULL;
    int best_at = ours_at;
    size_t i;
    json_t *e;
    json_array_foreach(arr, i, e)
    {
        json_t *ji = json_object_get(e, "index");
        const char *dig = json_string_value(json_object_get(e, "roster_digest"));
        json_t *members = json_object_get(e, "roster_members");
        char want[TX_HASH_HEX_LEN + 1];
        if (!json_is_integer(ji) || dig == NULL
            || !tx_roster_op_valid(json_string_value(json_object_get(e, "roster_op"))))
            continue;
        int at = (int)json_integer_value(ji);
        if (at >= k || at <= best_at || roster_digest(members, want, NULL) != 0
            || strcmp(want, dig) != 0)
            continue;
        best = members;
        best_at = at;
    }
    if (best == NULL && m == 1 && entries[0].roster
        && strcmp(entries[0].roster_op, "genesis") == 0)
    {
        /* A genesis is decided by every member it lists: its own list, from
         * the segment, checked against its digest. */
        json_array_foreach(arr, i, e)
        {
            json_t *ji = json_object_get(e, "index");
            if (json_is_integer(ji) && (int)json_integer_value(ji) == k)
                best = json_object_get(e, "roster_members");
        }
        json_t *g = NULL;
        char gd[TX_HASH_HEX_LEN + 1];
        char digest[TX_HASH_HEX_LEN + 1];
        place_value_digest(entries, m, k, digest);
        uint8_t desig[PLACE_DESIG_MAX];
        size_t dlen = place_designation(k, head, digest, desig, sizeof(desig));
        bool ok = best != NULL && roster_digest(best, gd, &g) == 0
            && strcmp(gd, entries[0].roster_digest) == 0 && dlen > 0
            && _verified_cosigners_in(proc, g, sigs, desig, dlen) == json_array_size(g);
        json_decref(g);
        return ok;
    }
    if (best == NULL)
        return _placement_certified(proc, entries, m, k, head, sigs, group);
    json_t *roster = NULL;
    char d[TX_HASH_HEX_LEN + 1];
    if (roster_digest(best, d, &roster) != 0 || roster == NULL)
        return false;
    char digest[TX_HASH_HEX_LEN + 1];
    place_value_digest(entries, m, k, digest);
    uint8_t desig[PLACE_DESIG_MAX];
    size_t dlen = place_designation(k, head, digest, desig, sizeof(desig));
    bool ok = digest[0] != '\0' && dlen > 0
        && _verified_cosigners_in(proc, roster, sigs, desig, dlen) >= _roster_majority(roster);
    json_decref(roster);
    return ok;
}

/* --- equivocation (R+D.md §14.1) --------------------------------------------
 *
 * Two certificates for different values at one index mean two quorums of the
 * roster signed both, and the members in both signed twice. We keep ours
 * either way. The record holds both certificates, so this node can prove it
 * later; it is never sent and never scored (the user's calls, 2026-10-21, D3 B
 * and D4 B). Mirrors the Python PlacementMixin. */
#define REP_FORKS_MAX 32

static int _str_cmp(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* One side of an equivocation: the placement at @p k after the entry whose
 * hash is @p prev, its value digest, its signatures, and who among them
 * verifies against the roster in force for @p k (our live view while the
 * chain holds none). A new object, or NULL. Takes no lock on entry. */
static json_t *_fork_cert(const process_t *proc, const char *key, int k,
                          const transaction_t *entries, int m, json_t *sigs,
                          const char *prev)
{
    char digest[TX_HASH_HEX_LEN + 1];
    place_value_digest(entries, m, k, digest);
    uint8_t desig[PLACE_DESIG_MAX];
    size_t dlen = place_designation(k, prev, digest, desig, sizeof(desig));
    if (digest[0] == '\0' || dlen == 0 || !json_is_object(sigs))
        return NULL;
    json_t *roster = _roster_at(key, k);
    json_t *lower = json_object();
    const char *names[256];
    size_t n_names = 0;
    const char *voter;
    json_t *sig;
    json_object_foreach(sigs, voter, sig)
    {
        char u[UUID_STRING_LEN + 1];
        at_strlcpy(u, voter, sizeof(u));
        for (char *c = u; *c; c++)
            if (*c >= 'A' && *c <= 'Z')
                *c = (char)(*c - 'A' + 'a');
        if (json_is_string(sig))
            json_object_set(lower, u, sig);
        json_t *one = json_pack("{s:O}", voter, sig);
        size_t ok = one == NULL ? 0
            : roster != NULL ? _verified_cosigners_in(proc, roster, one, desig, dlen)
                             : _verified_cosigners(proc, one, desig, dlen);
        json_decref(one);
        if (ok == 1 && n_names < sizeof(names) / sizeof(names[0]))
            names[n_names++] = voter;
    }
    json_decref(roster);
    char (*keys)[UUID_STRING_LEN + 1] = calloc(n_names > 0 ? n_names : 1,
                                                sizeof(*keys));
    const char **order = calloc(n_names > 0 ? n_names : 1, sizeof(*order));
    json_t *signers = json_array();
    for (size_t i = 0; keys != NULL && order != NULL && i < n_names; i++)
    {
        at_strlcpy(keys[i], names[i], sizeof(keys[i]));
        for (char *c = keys[i]; *c; c++)
            if (*c >= 'A' && *c <= 'Z')
                *c = (char)(*c - 'A' + 'a');
        order[i] = keys[i];
    }
    if (keys != NULL && order != NULL)
    {
        qsort(order, n_names, sizeof(*order), _str_cmp);
        for (size_t i = 0; i < n_names; i++)
            json_array_append_new(signers, json_string(order[i]));
    }
    free(order);
    free(keys);
    return json_pack("{s:i, s:s, s:s, s:o, s:o}", "k", k, "prev",
                     prev != NULL ? prev : "", "digest", digest,
                     "sigs", lower, "signers", signers);
}

/* Our own certificate for the placement holding index @p f, or NULL when it
 * is not resident in full. Mirrors Python _own_fork_cert. */
static json_t *_own_fork_cert(const process_t *proc, const char *key, int f)
{
    tx_place_batch_t *b = calloc(1, sizeof(*b));
    if (b == NULL)
        return NULL;
    json_t *sigs = NULL;
    pthread_mutex_lock(&rep_state.lock);
    int rc = tx_history_own_place_batch(_chain_for_key_locked(key), f, b, &sigs);
    pthread_mutex_unlock(&rep_state.lock);
    json_t *out = rc == 0 && b->n > 0
        ? _fork_cert(proc, key, b->k, b->entries, b->n, sigs, b->entries[0].prev_hash)
        : NULL;
    json_decref(sigs);
    free(b);
    return out;
}

/* Keep one equivocation record for chain @p key and persist it. Takes
 * ownership of @p ours and @p theirs. */
static void _note_equivocation(const process_t *proc, const char *key, int f,
                               const char *source, const uuid_t *sender,
                               json_t *ours, json_t *theirs)
{
    const char *od = json_string_value(json_object_get(ours, "digest"));
    const char *td = json_string_value(json_object_get(theirs, "digest"));
    if (od == NULL || td == NULL || strcmp(od, td) == 0)
    {
        json_decref(ours);
        json_decref(theirs);
        return;
    }
    json_t *both = json_array();
    size_t i, j;
    json_t *a, *b;
    json_array_foreach(json_object_get(ours, "signers"), i, a)
        json_array_foreach(json_object_get(theirs, "signers"), j, b)
            if (json_equal(a, b))
                json_array_append(both, a);
    char from[UUID_STRING_LEN + 1] = {0};
    if (sender != NULL)
        uuid_unparse_lower(*sender, from);
    pthread_mutex_lock(&rep_state.lock);
    rep_chain_ckpt_t *slot = _ckpt_slot_locked(key);
    bool fresh = slot != NULL;
    if (slot != NULL && slot->forks == NULL)
        slot->forks = json_array();
    json_array_foreach(slot != NULL ? slot->forks : NULL, i, a)
    {
        const char *ro = json_string_value(json_object_get(json_object_get(a, "ours"), "digest"));
        const char *rt = json_string_value(json_object_get(json_object_get(a, "theirs"), "digest"));
        if (json_integer_value(json_object_get(a, "index")) == f && ro != NULL
            && rt != NULL && strcmp(ro, od) == 0 && strcmp(rt, td) == 0)
            fresh = false;
    }
    size_t n_both = json_array_size(both);
    if (fresh)
    {
        json_t *rec = json_pack("{s:i, s:s, s:o, s:I, s:O, s:O, s:O}",
                                "index", f, "source", source,
                                "from", sender != NULL ? json_string(from) : json_null(),
                                "at", (json_int_t)time(NULL),
                                "ours", ours, "theirs", theirs, "both", both);
        if (rec != NULL)
            json_array_append_new(slot->forks, rec);
        while (json_array_size(slot->forks) > REP_FORKS_MAX)
            json_array_remove(slot->forks, 0);
    }
    pthread_mutex_unlock(&rep_state.lock);
    json_decref(both);
    json_decref(ours);
    json_decref(theirs);
    if (!fresh)
        return;
    log_error(proc->logger,
              "Reputation: equivocation recorded on chain %s at index %d (%s): "
              "%zu member(s) signed both values\n",
              key[0] != '\0' ? key : "primary", f, source, n_both);
    _persist_history(proc, key);
}

/* Catch-up returned EQUIVOCATION at @p f: record our certificate and the
 * segment's. Mirrors Python _record_catchup_equivocation. */
static void _record_catchup_equivocation(const process_t *proc, const char *key,
                                         json_t *arr, int f, const uuid_t *sender)
{
    tx_place_batch_t *batches = NULL;
    int nb = 0;
    json_t *theirs = NULL;
    pthread_mutex_lock(&rep_state.lock);
    int rc = tx_history_place_batches(_chain_for_key_locked(key), arr, &batches, &nb);
    pthread_mutex_unlock(&rep_state.lock);
    for (int i = 0; rc == 0 && i < nb && theirs == NULL; i++)
        if (batches[i].n > 0 && batches[i].k <= f && f < batches[i].k + batches[i].n)
            theirs = _fork_cert(proc, key, batches[i].k, batches[i].entries,
                                batches[i].n, (json_t *)batches[i].sigs,
                                batches[i].entries[0].prev_hash);
    free(batches);
    _note_equivocation(proc, key, f, "catchup", sender,
                       _own_fork_cert(proc, key, f), theirs);
}

/* A `placed` for an index we already hold. The same value is a late
 * duplicate. A different value whose certificate verifies after our own entry
 * at k-1 is an equivocation, recorded at the first index where the two differ.
 * Mirrors Python _check_placed_equivocation. */
static void _check_placed_equivocation(const process_t *proc, const char *key,
                                       int k, json_t *value, json_t *sigs,
                                       const uuid_t *sender)
{
    transaction_t *theirs = calloc(PLACE_BATCH_MAX, sizeof(transaction_t));
    transaction_t *ours = calloc(PLACE_BATCH_MAX, sizeof(transaction_t));
    int m = theirs != NULL && ours != NULL ? _place_value_from_json(value, theirs) : -1;
    char prev[TX_HASH_HEX_LEN + 1] = {0};
    bool held = m > 0;
    pthread_mutex_lock(&rep_state.lock);
    const tx_history_t *chain = _chain_for_key_locked(key);
    for (int i = 0; held && i < m; i++)
    {
        const transaction_t *t = tx_history_committed_at(chain, k + i);
        if (t == NULL)
            held = false;
        else
            ours[i] = *t;
    }
    if (held && k > 0)
    {
        const transaction_t *before = tx_history_committed_at(chain, k - 1);
        if (before == NULL)
            held = false;
        else
            transaction_entry_hash(before, prev);
    }
    pthread_mutex_unlock(&rep_state.lock);
    char od[TX_HASH_HEX_LEN + 1], td[TX_HASH_HEX_LEN + 1];
    if (held)
    {
        place_value_digest(ours, m, k, od);
        place_value_digest(theirs, m, k, td);
        held = strcmp(od, td) != 0
            && _placement_certified(proc, theirs, m, k, prev, sigs,
                                    key[0] != '\0' ? key : NULL);
    }
    if (held)
    {
        int f = k;
        for (int i = 0; i < m; i++)
        {
            place_value_digest(&ours[i], 1, k + i, od);
            place_value_digest(&theirs[i], 1, k + i, td);
            if (strcmp(od, td) != 0)
            {
                f = k + i;
                break;
            }
        }
        _note_equivocation(proc, key, f, "placed", sender,
                           _own_fork_cert(proc, key, f),
                           _fork_cert(proc, key, k, theirs, m, sigs, prev));
    }
    free(theirs);
    free(ours);
}

/* Take back the records an evidence document holds for chain @p key. */
static void _load_fork_records(const char *key, const json_t *doc)
{
    json_t *raw = json_object_get((json_t *)doc, "forks");
    if (!json_is_array(raw))
        return;
    json_t *keep = json_array();
    size_t i;
    json_t *r;
    json_array_foreach(raw, i, r)
        if (json_is_integer(json_object_get(r, "index"))
            && json_is_object(json_object_get(r, "ours"))
            && json_is_object(json_object_get(r, "theirs")))
            json_array_append(keep, r);
    while (json_array_size(keep) > REP_FORKS_MAX)
        json_array_remove(keep, 0);
    pthread_mutex_lock(&rep_state.lock);
    rep_chain_ckpt_t *slot = _ckpt_slot_locked(key);
    if (slot != NULL)
    {
        json_decref(slot->forks);
        slot->forks = keep;
        keep = NULL;
    }
    pthread_mutex_unlock(&rep_state.lock);
    json_decref(keep);
}

json_t *reputation_fork_records(const char *key)
{
    pthread_mutex_lock(&rep_state.lock);
    rep_chain_ckpt_t *slot = _ckpt_slot_locked(key != NULL ? key : "");
    json_t *out = slot != NULL && slot->forks != NULL
        ? json_deep_copy(slot->forks) : json_array();
    pthread_mutex_unlock(&rep_state.lock);
    return out;
}

/* Verify and write one decided placement at the chain's next index. */
static bool _apply_placement(const process_t *proc, const char *key, int k,
                             json_t *value, json_t *sigs, const char *group)
{
    transaction_t *entries = calloc(PLACE_BATCH_MAX, sizeof(transaction_t));
    if (entries == NULL)
        return false;
    int m = _place_value_from_json(value, entries);
    pthread_mutex_lock(&rep_state.lock);
    tx_history_t *chain = _chain_for_key_locked(key);
    /* A roster entry's member list first (its digest was checked when it was
     * parsed): judging a genesis needs it. */
    for (int i = 0; i < m; i++)
        if (entries[i].roster)
            (void)tx_history_roster_put(chain, json_object_get(json_object_get(
                json_array_get(value, (size_t)i), "roster"), "members"), NULL);
    char head[TX_HASH_HEX_LEN + 1];
    at_strlcpy(head, chain->head_hash, sizeof(head));
    bool at_next = chain->next_index == k;
    pthread_mutex_unlock(&rep_state.lock);
    if (m < 0 || !at_next || !_placement_certified(proc, entries, m, k, head, sigs, group))
    {
        if (m >= 0 && at_next)
            log_warn(proc->logger, "Reputation: refusing placement %d: its "
                     "certificate does not meet our quorum\n", k);
        free(entries);
        return false;
    }
    /* Each half's commit certificate travels in the value; keep it with the
     * entry, as a commit would. */
    char *sigs_text = json_dumps(sigs, JSON_COMPACT | JSON_SORT_KEYS);
    uuid_t self_uuid;
    bool have_self = _resolve_self_uuid(proc, self_uuid);
    pthread_mutex_lock(&rep_state.lock);
    chain = _chain_for_key_locked(key);
    bool applied = chain->next_index == k && strcmp(chain->head_hash, head) == 0
        && tx_history_apply_placed(chain, k, entries, m, sigs_text) == TX_PLACE_APPLIED;
    for (int i = 0; applied && i < m; i++)
    {
        json_t *c1, *c2, *as;
        transaction_t scratch;
        (void)_place_entry_from_json(json_array_get(value, (size_t)i), &scratch,
                                     &c1, &c2, &as);
        const transaction_t *tx = &entries[i];
        char task_str[UUID_STRING_LEN + 1];
        uuid_unparse_lower(tx->task_uuid, task_str);
        /* The line a commit used to log when it completed an entry; under
         * ordered placement an entry is completed here, so it is logged here
         * (cohorts and operators watch for it). */
        if (!tx->roster && !tx->attested && tx->p1_set && tx->p2_set)
            log_info(proc->logger, "Reputation: task %s is bilateral (index %d)\n",
                     task_str, k + i);
        if (tx->roster)
        {
            /* Its member list, checked against its digest when parsed. */
            (void)tx_history_roster_put(chain, json_object_get(json_object_get(
                json_array_get(value, (size_t)i), "roster"), "members"), NULL);
            continue;
        }
        if (tx->attested)
        {
            char *t = json_is_object(as) ? json_dumps(as, JSON_COMPACT | JSON_SORT_KEYS) : NULL;
            if (t != NULL)
                map_set(&chain->attest_certs, (map_key_t)task_str,
                        string_data((string_t)t, strlen(t)));
            free(t);
            /* What _commit_attestation does for a chain that does not place:
             * a checkpoint soon, so the entry is archived before a busy chain
             * can evict it, and the line cohorts watch for. */
            double soon = (double)time(NULL)
                + reputation_env_double("AT_REP_ATTEST_CHECKPOINT_SEC", 10.0);
            if (rep_state.checkpoint_phase_taken && rep_state.next_checkpoint_at > soon)
                rep_state.next_checkpoint_at = soon;
            char verifier[UUID_STRING_LEN + 1], subject[UUID_STRING_LEN + 1];
            uuid_unparse_lower(tx->p1_uuid, verifier);
            uuid_unparse_lower(tx->subject_uuid, subject);
            log_info(proc->logger,
                     "Reputation: attested score committed: verifier=%.8s "
                     "subject=%.8s score=%.2f channel=%s signers=%zu (index %d)\n",
                     verifier, subject, tx->p1_score, tx->p1_channel,
                     json_is_object(as) ? json_object_size(as) : (size_t)0, k + i);
        }
        else
        {
            for (int side = 0; side < 2; side++)
            {
                json_t *c = side == 0 ? c1 : c2;
                const unsigned char *scorer = side == 0 ? scratch.p1_uuid : scratch.p2_uuid;
                char *t = json_is_object(c) ? json_dumps(c, JSON_COMPACT | JSON_SORT_KEYS) : NULL;
                if (t != NULL)
                    (void)tx_history_attach_commit_cert(chain, tx->task_uuid, scorer, t);
                free(t);
            }
        }
        if (have_self && ((tx->p1_set && uuid_compare(tx->p1_uuid, self_uuid) == 0)
                          || (tx->p2_set && uuid_compare(tx->p2_uuid, self_uuid) == 0)))
            map_remove(&rep_state.awaiting_commit, (map_key_t)task_str);
    }
    int next = chain->next_index;
    rep_place_state_t *st = applied ? _place_state_locked(proc, key) : NULL;
    if (st != NULL)
        _place_prune_below(&st->accepted, next);
    pthread_mutex_unlock(&rep_state.lock);
    free(sigs_text);
    if (applied)
    {
        for (int i = 0; i < m; i++)
        {
            const transaction_t *tx = &entries[i];
            if (tx->p1_set && !(have_self && uuid_compare(tx->p1_uuid, self_uuid) == 0))
                _note_interaction(tx->p1_uuid);
            if (tx->p2_set && !(have_self && uuid_compare(tx->p2_uuid, self_uuid) == 0))
                _note_interaction(tx->p2_uuid);
            if (tx->attested)
                _note_interaction(tx->subject_uuid);
        }
        log_info(proc->logger, "Reputation: placed %d entr%s at %d on chain %s "
                 "(next %d)\n", m, m == 1 ? "y" : "ies", k,
                 key[0] != '\0' ? key : "primary", next);
    }
    free(entries);
    return applied;
}

static bool handle_placed(const process_t *proc, directory_t *queues,
                          generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    char key[UUID_STRING_LEN + 1];
    const char *group = NULL;
    int k = 0;
    json_t *payload = _place_payload(proc, nmsg, key, &group, &k);
    if (payload == NULL)
        return true;
    json_t *value = json_object_get(payload, "value");
    json_t *sigs = json_object_get(payload, "sigs");
    if (!json_is_array(value) || !json_is_object(sigs))
    {
        json_decref(payload);
        return true;
    }
    const char *chain_group = key[0] != '\0' ? group : NULL;
    pthread_mutex_lock(&rep_state.lock);
    int next = _chain_for_key_locked(key)->next_index;
    if (k > next)
    {
        /* Ahead of us: hold it until the chain reaches k, and catch up. */
        rep_place_state_t *st = _place_state_locked(proc, key);
        if (st != NULL && (map_size(&st->ahead) < REP_PLACED_AHEAD_MAX
                           || _place_text(&st->ahead, k) != NULL))
        {
            json_t *rec = json_pack("{s:O, s:O}", "value", value, "sigs", sigs);
            char *text = rec != NULL ? json_dumps(rec, JSON_COMPACT) : NULL;
            if (text != NULL)
                _place_set_text(&st->ahead, k, text);
            free(text);
            json_decref(rec);
        }
    }
    pthread_mutex_unlock(&rep_state.lock);
    if (k > next)
    {
        _request_chain_for(proc, &nmsg->from_whom, key);
        json_decref(payload);
        return true;
    }
    if (k < next)
        _check_placed_equivocation(proc, key, k, value, sigs, &nmsg->from_whom.uuid);
    if (k < next || !_apply_placement(proc, key, k, value, sigs, chain_group))
    {
        json_decref(payload);
        return true;
    }
    json_decref(payload);
    pthread_mutex_lock(&rep_state.lock);
    rep_place_state_t *placed_st = _place_state_locked(proc, key);
    if (placed_st != NULL)
    {
        uuid_unparse_lower(nmsg->from_whom.uuid, placed_st->placer);
        placed_st->lead_set = false;
    }
    pthread_mutex_unlock(&rep_state.lock);
    _apply_ahead(proc, key, chain_group);
    return true;
}

/* Write the decided placements held ahead of chain @p key that now follow
 * it, in order, and forget any it has passed. Caller holds no lock. Mirrors
 * Python _apply_ahead. */
static void _apply_ahead(const process_t *proc, const char *key,
                         const char *chain_group)
{
    for (;;)
    {
        pthread_mutex_lock(&rep_state.lock);
        rep_place_state_t *st = _place_state_locked(proc, key);
        int at = _chain_for_key_locked(key)->next_index;
        const char *held = st != NULL ? _place_text(&st->ahead, at) : NULL;
        json_t *rec = held != NULL ? json_loads(held, 0, NULL) : NULL;
        if (st != NULL)
            _place_prune_below(&st->ahead, at + (rec != NULL ? 1 : 0));
        pthread_mutex_unlock(&rep_state.lock);
        if (rec == NULL)
            break;
        bool more = _apply_placement(proc, key, at, json_object_get(rec, "value"),
                                     json_object_get(rec, "sigs"), chain_group);
        json_decref(rec);
        if (!more)
            break;
    }
}

/* The indices of segment @p arr whose placement certificates verify against
 * OUR view of the group, or, with *@p refused set, nothing: a certificate
 * over entries the segment carries in full that does not verify refuses the
 * segment whole. A placement carried only in part that we cannot complete
 * from our own entries (or complete differently) is just uncertified.
 * Returns a malloc'd array (NULL when empty) of *@p n_out indices. Caller
 * holds no lock. Mirrors Python _placement_certified_indices. */
/* May a node that knows no roster of chain @p key take segment entry @p r
 * (the segment's latest roster entry, catch-up wire form) as the group's?
 * It must differ from the group as identity shows it to us by at most one
 * member (perhaps ourselves), list the same keys for the members both know,
 * and carry a placement certificate signed by a majority of the roster before
 * it, counting only members we know and verifying their signatures with the
 * keys identity holds. A history invented by an insider fails one of these.
 * Mirrors Python _roster_anchor_ok. */
static bool _roster_anchor_ok(const process_t *proc, const char *key, json_t *r)
{
    const char *op = json_string_value(json_object_get(r, "roster_op"));
    const char *who = json_string_value(json_object_get(r, "roster_uuid"));
    const char *dig = json_string_value(json_object_get(r, "roster_digest"));
    const char *task = json_string_value(json_object_get(r, "task"));
    const char *prev = json_string_value(json_object_get(r, "prev_hash"));
    json_t *ji = json_object_get(r, "index");
    json_t *jf = json_object_get(r, "place_from");
    json_t *sigs = json_object_get(r, "place_sigs");
    json_t *members = NULL;
    char d[TX_HASH_HEX_LEN + 1];
    if (!tx_roster_op_valid(op) || dig == NULL || task == NULL
        || !json_is_integer(ji) || !json_is_integer(jf)
        || json_integer_value(jf) != json_integer_value(ji) || !json_is_object(sigs)
        || roster_digest(json_object_get(r, "roster_members"), d, &members) != 0
        || strcmp(d, dig) != 0)
    {
        json_decref(members);
        return false;
    }
    json_t *live = _live_roster(proc, key);
    bool ok = live != NULL;
    size_t diff = 0, i;
    json_t *m;
    json_array_foreach(live, i, m)
    {
        const char *u = json_string_value(json_array_get(m, 0));
        const char *mk = _roster_key_of(members, u);
        if (mk == NULL)
            diff++;
        else if (strcmp(mk, json_string_value(json_array_get(m, 1))) != 0)
            ok = false;
    }
    json_array_foreach(members, i, m)
        if (_roster_key_of(live, json_string_value(json_array_get(m, 0))) == NULL)
            diff++;
    if (diff > 1)
        ok = false;
    /* The roster before it: an add's, without the member it adds. */
    size_t before = json_array_size(members);
    bool is_add = strcmp(op, "add") == 0 && who != NULL;
    if (is_add && _roster_key_of(members, who) != NULL)
        before--;
    transaction_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.index = -1;
    tx.roster = true;
    at_strlcpy(tx.roster_op, op, sizeof(tx.roster_op));
    at_strlcpy(tx.roster_digest, dig, sizeof(tx.roster_digest));
    if (uuid_parse(task, tx.task_uuid) != 0 || (who != NULL && uuid_parse(who, tx.roster_uuid) != 0))
        ok = false;
    int k = (int)json_integer_value(ji);
    char digest[TX_HASH_HEX_LEN + 1];
    place_value_digest(&tx, 1, k, digest);
    uint8_t desig[PLACE_DESIG_MAX];
    size_t dlen = place_designation(k, prev != NULL ? prev : "", digest, desig, sizeof(desig));
    size_t signers = 0;
    const char *voter;
    json_t *val;
    json_object_foreach(sigs, voter, val)
    {
        if (!ok || dlen == 0 || _roster_key_of(members, voter) == NULL
            || (is_add && strcasecmp(voter, who) == 0))
            continue;
        if (_verify_cosignature_in(proc, live, voter, desig, dlen, json_string_value(val)))
            signers++;
    }
    ok = ok && signers >= before / 2 + 1;
    json_decref(members);
    json_decref(live);
    return ok;
}

static int *_placement_certified_indices(const process_t *proc, const char *key,
                                         const char *group, json_t *arr,
                                         int *n_out, bool *refused)
{
    *n_out = 0;
    *refused = false;
    /* We know no roster of this chain (a newcomer, or a node far behind):
     * anchor on the segment's latest roster entry. What precedes it is taken
     * by its hash links; what follows, by the rosters it leads to. */
    pthread_mutex_lock(&rep_state.lock);
    tx_history_t *own = _chain_for_key_locked(key);
    bool know = tx_history_roster_at(own, own->next_index, NULL) == 0;
    pthread_mutex_unlock(&rep_state.lock);
    json_t *anchor = NULL;
    int anchor_at = -1;
    size_t ai;
    json_t *ae;
    json_array_foreach(arr, ai, ae)
    {
        json_t *ji = json_object_get(ae, "index");
        if (!know && json_is_integer(ji) && json_object_get(ae, "roster_op") != NULL
            && (int)json_integer_value(ji) > anchor_at)
        {
            anchor = ae;
            anchor_at = (int)json_integer_value(ji);
        }
    }
    int *anchored = NULL;
    int n_anchored = 0;
    if (anchor != NULL)
    {
        if (!_roster_anchor_ok(proc, key, anchor))
        {
            *refused = true;
            return NULL;
        }
        anchored = calloc(json_array_size(arr) + 1, sizeof(int));
        json_array_foreach(arr, ai, ae)
        {
            json_t *ji = json_object_get(ae, "index");
            if (anchored != NULL && json_is_integer(ji)
                && (int)json_integer_value(ji) <= anchor_at)
                anchored[n_anchored++] = (int)json_integer_value(ji);
        }
    }
    tx_place_batch_t *batches = NULL;
    int nb = 0;
    pthread_mutex_lock(&rep_state.lock);
    int rc = tx_history_place_batches(_chain_for_key_locked(key), arr,
                                      &batches, &nb);
    pthread_mutex_unlock(&rep_state.lock);
    if (rc != 0 || nb == 0)
    {
        free(batches);
        if (anchored != NULL && n_anchored > 0)
        {
            *n_out = n_anchored;
            return anchored;
        }
        free(anchored);
        return NULL;
    }
    int *out = calloc((size_t)nb * PLACE_BATCH_MAX + (size_t)n_anchored + 1, sizeof(int));
    if (out == NULL)
    {
        free(batches);
        free(anchored);
        *refused = true;
        return NULL;
    }
    for (int i = 0; i < n_anchored; i++)
        out[(*n_out)++] = anchored[i];
    free(anchored);
    for (int b = 0; b < nb; b++)
    {
        tx_place_batch_t *bt = &batches[b];
        if (bt->n <= 0 || (anchor != NULL && bt->k <= anchor_at))
            continue;
        if (_placement_certified_seg(proc, key, arr, bt->entries, bt->n, bt->k,
                                     bt->entries[0].prev_hash, (json_t *)bt->sigs,
                                     group))
        {
            for (int i = 0; i < bt->n; i++)
                out[(*n_out)++] = bt->k + i;
        }
        else if (bt->whole)
        {
            *refused = true;
            break;
        }
    }
    free(batches);
    if (*refused || *n_out == 0)
    {
        free(out);
        *n_out = 0;
        return NULL;
    }
    return out;
}

/* ---- Ordered placement: the proposer ---------------------------------
 *
 * The node that placed the previous instance on a chain leads the next one,
 * so in a quiet group one node drives every placement and nobody duels.
 * Every other member with ready items waits REP_PLACE_READY_WAIT, plus
 * REP_PLACE_RANK_STEP per place it holds in this instance's ranking, before
 * taking over; hearing anyone else work on the instance resets that wait. A
 * round that stalls for REP_PLACE_ROUND_TIMEOUT is dropped, and a refused one
 * backs off a random interval, so rival proposers spread out instead of
 * colliding again. Mirrors Python PlacementMixin's proposer. */

#define REP_PLACE_READY_WAIT    3.0
#define REP_PLACE_RANK_STEP     0.3
#define REP_PLACE_ROUND_TIMEOUT 5.0

static int64_t g_place_seen_n;

static double _mono(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static double _place_backoff(void)
{
    return 0.5 + (double)randombytes_uniform(1500) / 1000.0;
}

/* Note that someone is working on instance @p k of chain @p key. */
static void _note_place_heard(const process_t *proc, const char *key, int k)
{
    pthread_mutex_lock(&rep_state.lock);
    rep_place_state_t *st = _place_state_locked(proc, key);
    if (st != NULL)
    {
        st->heard_k = k;
        st->heard_at = _mono();
    }
    pthread_mutex_unlock(&rep_state.lock);
}

/* Is @p voter this node or a peer on our roster? */
static bool _place_member(const process_t *proc, const char *voter)
{
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    return _cosigner_pubkey(proc, voter, pk);
}

/* Does @p voter decide instance @p k of chain @p key? A member of the roster
 * in force for it, or, while the chain holds none, this node or a peer.
 * Mirrors Python _place_voter / _place_members. */
static bool _place_member_at(const process_t *proc, const char *key, int k,
                             const char *voter)
{
    json_t *roster = _roster_at(key, k);
    if (roster == NULL)
        return _place_member(proc, voter);
    bool in = _roster_key_of(roster, voter) != NULL;
    json_decref(roster);
    return in;
}

/* How many signatures, the proposer's own included, decide instance @p k: a
 * strict majority of the roster in force, or of the live view while there is
 * none. Mirrors Python _place_majority. */
static size_t _place_majority(const process_t *proc, const char *key, int k,
                              const char *group)
{
    json_t *roster = _roster_at(key, k);
    if (roster != NULL)
    {
        size_t n = _roster_majority(roster);
        json_decref(roster);
        return n;
    }
    pthread_mutex_lock(&rep_state.lock);
    bool unfounded = k == 0 && !_founded_locked(key);
    pthread_mutex_unlock(&rep_state.lock);
    if (unfounded)
    {
        /* The genesis: every member it will list. */
        json_t *live = _live_roster(proc, key);
        size_t n = json_array_size(live);
        json_decref(live);
        return n;
    }
    peers_read_lock(proc);
    size_t q = _round_quorum_for_group(proc, group);
    peers_read_unlock(proc);
    return q + 1;
}

/* Do this node (@p me) and the proposer (@p by) both decide instance @p k?
 * Once the chain holds a roster only its members promise, accept or propose
 * there. Mirrors Python _place_deciders_ok. */
static bool _place_deciders_ok(const process_t *proc, const char *key, int k,
                               const char *me, const char *by)
{
    return _place_member_at(proc, key, k, me) && _place_member_at(proc, key, k, by);
}

/* blake2b(uuid|k), 16 bytes, hex: a member's place in instance k's order. */
static void _rank_hash(const char *uuid, int k, char out[33])
{
    char in[UUID_STRING_LEN + 24];
    unsigned char h[16];
    snprintf(in, sizeof(in), "%s|%d", uuid, k);
    crypto_generichash(h, sizeof(h), (const unsigned char *)in, strlen(in), NULL, 0);
    sodium_bin2hex(out, 33, h, sizeof(h));
}

/* Where this node stands in instance @p k's takeover order on chain @p key:
 * the members deciding k by blake2b(uuid|k), 16 bytes, hex. -1 when @p me is
 * not one of them. */
static int _place_rank(const process_t *proc, const char *key, const char *me,
                       int k)
{
    char mine[33];
    char in[UUID_STRING_LEN + 24];
    unsigned char h[16];
    _rank_hash(me, k, mine);
    json_t *roster = _roster_at(key, k);
    if (roster != NULL)
    {
        int rank = _roster_key_of(roster, me) != NULL ? 0 : -1;
        size_t i;
        json_t *m;
        json_array_foreach(roster, i, m)
        {
            char theirs[33];
            const char *u = json_string_value(json_array_get(m, 0));
            if (rank < 0 || u == NULL)
                continue;
            _rank_hash(u, k, theirs);
            if (strcmp(theirs, mine) < 0)
                rank++;
        }
        json_decref(roster);
        return rank;
    }
    int rank = 0;
    peers_read_lock(proc);
    for (size_t i = 0; i < proc->protocol.num_peers; i++)
    {
        char u[UUID_STRING_LEN + 1], theirs[33];
        if (!_place_peer_in_chain(proc, &proc->protocol.peers[i], key))
            continue;
        uuid_unparse_lower(proc->protocol.peers[i].uuid, u);
        snprintf(in, sizeof(in), "%s|%d", u, k);
        crypto_generichash(h, sizeof(h), (const unsigned char *)in, strlen(in), NULL, 0);
        sodium_bin2hex(theirs, sizeof(theirs), h, sizeof(h));
        if (strcmp(theirs, mine) < 0)
            rank++;
    }
    peers_read_unlock(proc);
    return rank;
}

/* Our own ready items @p value (owned), kept only where an acceptor will take
 * them. One it would refuse (a half whose certificate falls short of our
 * quorum, say) leaves the pool, or it would sink every round that carries it.
 * Returns the kept value, or NULL when nothing is left. Caller holds no lock.
 * Mirrors Python handle_place_grant. */
static json_t *_place_own_value_valid(const process_t *proc, const char *key,
                                      json_t *value, const char *group)
{
    json_t *kept = json_array();
    size_t i;
    json_t *e;
    json_array_foreach(value, i, e)
    {
        json_t *one = json_array();
        json_array_append(one, e);
        /* Our own value: a roster item we build follows the majority's
         * reports, not our configuration (Python leaves it unchecked). */
        const char *why = _place_value_why(proc, key, one, group, false);
        json_decref(one);
        if (why == NULL)
        {
            json_array_append(kept, e);
            continue;
        }
        const char *task = json_string_value(json_object_get(e, "task"));
        uuid_t tu;
        if (task != NULL && uuid_parse(task, tu) == 0)
        {
            pthread_mutex_lock(&rep_state.lock);
            (void)tx_history_pool_drop(_chain_for_key_locked(key), tu);
            pthread_mutex_unlock(&rep_state.lock);
        }
        log_warn(proc->logger, "Reputation: placement: dropping %.8s from the "
                 "pool: %s\n", task != NULL ? task : "?", why);
    }
    json_decref(value);
    if (json_array_size(kept) == 0)
    {
        json_decref(kept);
        return NULL;
    }
    return kept;
}

static json_t *_place_ready_value_locked(const tx_history_t *chain);

/* What we would place next on chain @p key (wire entries, a new reference),
 * or NULL: a roster entry alone when one is due, else our ready items --
 * none before the chain is founded. Caller must NOT hold rep_state.lock.
 * Mirrors Python _own_place_value. */
static json_t *_place_own_value(const process_t *proc, const char *key)
{
    json_t *item = _roster_item(proc, key);
    if (item != NULL)
    {
        json_t *v = json_array();
        json_array_append_new(v, item);
        return v;
    }
    pthread_mutex_lock(&rep_state.lock);
    json_t *v = _founded_locked(key)
        ? _place_ready_value_locked(_chain_for_key_locked(key)) : NULL;
    pthread_mutex_unlock(&rep_state.lock);
    return v;
}

/* The value of our ready items on chain @p key, as wire entries. Caller holds
 * rep_state.lock. */
static json_t *_place_ready_value_locked(const tx_history_t *chain)
{
    transaction_t *items = calloc(PLACE_BATCH_MAX, sizeof(transaction_t));
    if (items == NULL)
        return NULL;
    int n = tx_history_ready_items(chain, items, PLACE_BATCH_MAX);
    json_t *value = n > 0 ? json_array() : NULL;
    for (int i = 0; value != NULL && i < n; i++)
    {
        const transaction_t *tx = &items[i];
        json_t *d = json_object();
        char t[UUID_STRING_LEN + 1], a[UUID_STRING_LEN + 1];
        uuid_unparse_lower(tx->task_uuid, t);
        uuid_unparse_lower(tx->p1_uuid, a);
        json_object_set_new(d, "task", json_string(t));
        json_object_set_new(d, "p1", json_string(a));
        json_object_set_new(d, "p1_score", json_real(tx->p1_score));
        if (tx->attested)
        {
            char s[UUID_STRING_LEN + 1];
            uuid_unparse_lower(tx->subject_uuid, s);
            json_object_set_new(d, "attested", json_true());
            json_object_set_new(d, "p1_channel", json_string(tx->p1_channel));
            json_object_set_new(d, "subject", json_string(s));
            json_object_set_new(d, "evidence_digest", json_string(tx->evidence_digest));
            if (tx->attest_scope[0] != '\0')
                json_object_set_new(d, "attest_scope", json_string(tx->attest_scope));
            data_t *cd = NULL;
            char *text = NULL;
            if (map_get((map_t *)&chain->pool_certs, (map_key_t)t, &cd) == 0
                && data_string_ptr(cd, &text) == 0 && text != NULL)
                json_object_set_new(d, "attest_sigs", json_loads(text, 0, NULL));
        }
        else
        {
            char b[UUID_STRING_LEN + 1];
            uuid_unparse_lower(tx->p2_uuid, b);
            json_object_set_new(d, "p2", json_string(b));
            json_object_set_new(d, "p2_score", json_real(tx->p2_score));
            if (tx->p1_channel[0] != '\0')
                json_object_set_new(d, "p1_channel", json_string(tx->p1_channel));
            if (tx->p2_channel[0] != '\0')
                json_object_set_new(d, "p2_channel", json_string(tx->p2_channel));
            for (int side = 0; side < 2; side++)
            {
                char key[2 * UUID_STRING_LEN + 2];
                snprintf(key, sizeof(key), "%s|%s", t, side == 0 ? a : b);
                data_t *cd = NULL;
                char *text = NULL;
                if (map_get((map_t *)&chain->pool_certs, (map_key_t)key, &cd) == 0
                    && data_string_ptr(cd, &text) == 0 && text != NULL)
                    json_object_set_new(d, side == 0 ? "p1_cert" : "p2_cert",
                                        json_loads(text, 0, NULL));
            }
        }
        json_array_append_new(value, d);
    }
    free(items);
    return value;
}

/* Open a round for chain @p key's next instance: promise our own ballot,
 * then ask the group. */
static void _start_place_round(const process_t *proc, const char *key, const char *me)
{
    pthread_mutex_lock(&rep_state.lock);
    rep_place_state_t *st = _place_state_locked(proc, key);
    tx_history_t *chain = _chain_for_key_locked(key);
    if (st == NULL || st->broken)
    {
        pthread_mutex_unlock(&rep_state.lock);
        return;
    }
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    int64_t n = (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
    if (n <= g_place_seen_n)
        n = g_place_seen_n + 1;
    if (st->have_promised && st->prom_n >= n)
        n = st->prom_n + 1;
    g_place_seen_n = n;
    st->have_promised = true;
    st->prom_n = n;
    at_strlcpy(st->prom_by, me, sizeof(st->prom_by));
    if (!_persist_place_state(proc, st))
    {
        pthread_mutex_unlock(&rep_state.lock);
        return;
    }
    int k = chain->next_index;
    _place_round_close(st);
    st->round_open = true;
    st->round_k = k;
    st->round_n = n;
    at_strlcpy(st->round_head, chain->head_hash, sizeof(st->round_head));
    st->round_grants = json_object();
    const char *held = _place_text(&st->accepted, k);
    json_object_set_new(st->round_grants, me,
                        held != NULL ? json_loads(held, 0, NULL) : json_null());
    st->round_accepts = json_object();
    st->round_started = _mono();
    json_t *req = json_object();
    json_object_set_new(req, "group", json_string(key));
    json_object_set_new(req, "k", json_integer(k));
    json_object_set_new(req, "ballot", _ballot_json(n, me));
    json_object_set_new(req, "head", json_string(st->round_head));
    pthread_mutex_unlock(&rep_state.lock);
    _place_broadcast(proc, REP_PROTO_PLACE_REQUEST, key, req);
    json_decref(req);
}

/* Start a placement round on chain @p key if its ready items are ours to
 * place now. */
static void _place_unasked(const process_t *proc, const char *key,
                           const char *me, int64_t n);

static void _maybe_place_chain(const process_t *proc, const char *key,
                               const char *me)
{
    double clock = _mono();
    json_t *item = _roster_item(proc, key);
    bool roster_due = item != NULL;
    json_decref(item);
    pthread_mutex_lock(&rep_state.lock);
    rep_place_state_t *st = _place_state_locked(proc, key);
    tx_history_t *chain = _chain_for_key_locked(key);
    if (st == NULL)
    {
        pthread_mutex_unlock(&rep_state.lock);
        return;
    }
    int k = chain->next_index;
    if (st->round_open && st->round_k != k)
        _place_round_close(st);
    if (st->round_open)
    {
        if (clock - st->round_started > REP_PLACE_ROUND_TIMEOUT)
        {
            _place_round_close(st);
            st->lead_set = false;
            st->backoff_until = clock + _place_backoff();
        }
        pthread_mutex_unlock(&rep_state.lock);
        return;
    }
    transaction_t probe;
    bool ready = clock >= st->backoff_until
        && (roster_due || (tx_history_ready_items(chain, &probe, 1) > 0
                           && _founded_locked(key)));
    if (!ready)
    {
        if (clock >= st->backoff_until)
            st->ready_k = -1;
        pthread_mutex_unlock(&rep_state.lock);
        return;
    }
    if (st->ready_k != k)
    {
        st->ready_k = k;
        st->ready_since = clock;
    }
    bool busy = st->heard_k == k && clock - st->heard_at < REP_PLACE_ROUND_TIMEOUT;
    char placer[UUID_STRING_LEN + 1];
    at_strlcpy(placer, st->placer, sizeof(placer));
    double since = st->ready_since;
    /* Our ballot still carries k when it is the one a majority promised us at
     * k - 1, we have promised no other since, and hold nothing accepted at k. */
    bool lead = st->lead_set && st->lead_k == k && !st->broken
        && st->have_promised && st->prom_n == st->lead_n
        && strcmp(st->prom_by, me) == 0 && _place_text(&st->accepted, k) == NULL;
    int64_t lead_n = st->lead_n;
    pthread_mutex_unlock(&rep_state.lock);
    if (busy)
        return;
    int rank = _place_rank(proc, key, me, k);
    if (rank < 0)
        return;                         /* not a member of the roster in force */
    if (placer[0] != '\0' && !_place_member_at(proc, key, k, placer))
        placer[0] = '\0';
    bool leader = placer[0] != '\0' ? strcmp(placer, me) == 0 : rank == 0;
    double wait = leader ? 0.0 : REP_PLACE_READY_WAIT + rank * REP_PLACE_RANK_STEP;
    if (clock - since < wait)
        return;
    if (leader && lead)
    {
        _place_unasked(proc, key, me, lead_n);
        return;
    }
    pthread_mutex_lock(&rep_state.lock);
    rep_place_state_t *again = _place_state_locked(proc, key);
    if (again != NULL)
        again->lead_set = false;
    pthread_mutex_unlock(&rep_state.lock);
    _start_place_round(proc, key, me);
}

/* Start a placement round on any chain whose ready items are ours to place
 * now: the primary, then each child chain a gateway holds whose group places.
 * Runs on the process loop. Mirrors Python PlacementMixin._maybe_place. */
static void _maybe_place(const process_t *proc)
{
    uuid_t self_uuid;
    if (!_resolve_self_uuid(proc, self_uuid))
        return;
    char me[UUID_STRING_LEN + 1];
    uuid_unparse_lower(self_uuid, me);
    _maybe_place_chain(proc, "", me);
    /* The child chains' keys, copied: the index is the map's own and a
     * round may materialize another chain while we walk. */
    pthread_mutex_lock(&rep_state.lock);
    array_t *keys = map_keys(&rep_state.child_hist);
    size_t n = keys != NULL ? array_size(keys) : 0, m = 0;
    char (*chains)[UUID_STRING_LEN + 1] = calloc(n > 0 ? n : 1, sizeof(*chains));
    for (size_t i = 0; chains != NULL && i < n; i++)
    {
        data_t *kd = NULL, *live = NULL;
        char *key = NULL;
        if (array_get(keys, (int)i, &kd) == 0 && data_string_ptr(kd, &key) == 0
            && key != NULL && key[0] != '\0'
            && map_get(&rep_state.child_hist, (map_key_t)key, &live) == 0)
            at_strlcpy(chains[m++], key, sizeof(chains[0]));
    }
    pthread_mutex_unlock(&rep_state.lock);
    for (size_t i = 0; chains != NULL && i < m; i++)
        _maybe_place_chain(proc, chains[i], me);
    free(chains);
}

/* The round a reply is for, or NULL. Caller holds rep_state.lock. */
static rep_place_state_t *_place_round_for_locked(const process_t *proc,
                                                  const char *key, int k,
                                                  json_t *payload)
{
    rep_place_state_t *st = _place_state_locked(proc, key);
    int64_t n;
    char by[UUID_STRING_LEN + 1];
    if (st == NULL || !st->round_open || st->round_k != k
        || !_parse_ballot(json_object_get(payload, "ballot"), &n, by)
        || n != st->round_n || strcmp(by, st->prom_by) != 0)
        return NULL;
    return st;
}

/* Phase 2 of our round at instance @p k under (@p n, @p me): accept @p value
 * ourselves, durably, then ask chain @p key's group to. Shared by a round
 * whose majority granted (handle_place_grant) and the leader's skip
 * (_place_unasked). Mirrors Python PlacementMixin._send_place. */
static void _send_place(const process_t *proc, const char *key, int k,
                        int64_t n, const char *me, const char *head,
                        json_t *value)
{
    transaction_t *entries = calloc(PLACE_BATCH_MAX, sizeof(transaction_t));
    int m = entries != NULL ? _place_value_from_json(value, entries) : -1;
    char digest[TX_HASH_HEX_LEN + 1] = {0};
    if (m > 0)
        place_value_digest(entries, m, k, digest);
    free(entries);
    uint8_t desig[PLACE_DESIG_MAX];
    size_t dlen = place_designation(k, head, digest, desig, sizeof(desig));
    char sig[REP_SIG_HEX_LEN + 1] = {0};
    bool signed_ok = digest[0] != '\0' && dlen > 0
        && _cosign_hex(proc, desig, dlen, sig, sizeof(sig)) == 0;

    pthread_mutex_lock(&rep_state.lock);
    rep_place_state_t *st = _place_state_locked(proc, key);
    bool kept = false;
    if (st != NULL && st->round_open && st->round_k == k && st->round_n == n
        && st->round_value == NULL && signed_ok
        && !(st->have_promised && _ballot_cmp(n, me, st->prom_n, st->prom_by) < 0))
    {
        /* Our own acceptance, durable before anyone hears of it. */
        _place_prune_below(&st->accepted, k);
        json_t *rec = json_object();
        json_object_set_new(rec, "ballot", _ballot_json(n, me));
        json_object_set(rec, "value", value);
        char *text = json_dumps(rec, JSON_COMPACT);
        json_decref(rec);
        if (text != NULL)
        {
            _place_set_text(&st->accepted, k, text);
            free(text);
            kept = _persist_place_state(proc, st);
        }
        if (kept)
        {
            st->round_value = json_incref(value);
            at_strlcpy(st->round_digest, digest, sizeof(st->round_digest));
            json_object_set_new(st->round_accepts, me, json_string(sig));
        }
    }
    pthread_mutex_unlock(&rep_state.lock);
    if (kept)
    {
        json_t *place = json_object();
        json_object_set_new(place, "group", json_string(key));
        json_object_set_new(place, "k", json_integer(k));
        json_object_set_new(place, "ballot", _ballot_json(n, me));
        json_object_set_new(place, "head", json_string(head));
        json_object_set(place, "value", value);
        _place_broadcast(proc, REP_PROTO_PLACE, key, place);
        json_decref(place);
    }
}

/* Lead instance k under the ballot a majority promised us at k - 1: straight
 * to `place`, with our own ready items (the leader's skip; see "Who
 * proposes"). Mirrors Python PlacementMixin._place_unasked. */
static void _place_unasked(const process_t *proc, const char *key,
                           const char *me, int64_t n)
{
    pthread_mutex_lock(&rep_state.lock);
    rep_place_state_t *st = _place_state_locked(proc, key);
    tx_history_t *chain = _chain_for_key_locked(key);
    if (st == NULL || st->broken || st->round_open)
    {
        pthread_mutex_unlock(&rep_state.lock);
        return;
    }
    int k = chain->next_index;
    st->round_open = true;
    st->round_k = k;
    st->round_n = n;
    at_strlcpy(st->round_head, chain->head_hash, sizeof(st->round_head));
    st->round_grants = json_object();
    st->round_accepts = json_object();
    st->round_started = _mono();
    char head[TX_HASH_HEX_LEN + 1];
    at_strlcpy(head, st->round_head, sizeof(head));
    pthread_mutex_unlock(&rep_state.lock);
    json_t *value = _place_own_value(proc, key);
    if (value != NULL)
        value = _place_own_value_valid(proc, key, value, key[0] != '\0' ? key : NULL);
    if (value == NULL)
    {
        pthread_mutex_lock(&rep_state.lock);
        rep_place_state_t *again = _place_state_locked(proc, key);
        if (again != NULL)
            _place_round_close(again);
        pthread_mutex_unlock(&rep_state.lock);
        return;
    }
    _send_place(proc, key, k, n, me, head, value);
    json_decref(value);
}

static bool handle_place_grant(const process_t *proc, directory_t *queues,
                               generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    char key[UUID_STRING_LEN + 1];
    const char *group = NULL;
    int k = 0;
    json_t *payload = _place_payload(proc, nmsg, key, &group, &k);
    if (payload == NULL)
        return true;
    char voter[UUID_STRING_LEN + 1];
    uuid_unparse_lower(nmsg->from_whom.uuid, voter);
    if (!_place_member_at(proc, key, k, voter))
    {
        json_decref(payload);
        return true;
    }
    uuid_t self_uuid;
    char me[UUID_STRING_LEN + 1] = {0};
    if (_resolve_self_uuid(proc, self_uuid))
        uuid_unparse_lower(self_uuid, me);
    size_t majority = _place_majority(proc, key, k, key[0] != '\0' ? group : NULL);

    pthread_mutex_lock(&rep_state.lock);
    rep_place_state_t *st = _place_round_for_locked(proc, key, k, payload);
    if (st == NULL || st->round_value != NULL)
    {
        pthread_mutex_unlock(&rep_state.lock);
        json_decref(payload);
        return true;
    }
    json_t *acc = json_object_get(payload, "accepted");
    json_object_set(st->round_grants, voter, json_is_object(acc) ? acc : json_null());
    if (json_object_size(st->round_grants) < majority)
    {
        pthread_mutex_unlock(&rep_state.lock);
        json_decref(payload);
        return true;
    }
    /* A majority promised. Carry the highest-ballot value any of them
     * accepted at k, or, if none did, our own ready items. */
    json_t *best = NULL;
    int64_t best_n = 0;
    char best_by[UUID_STRING_LEN + 1] = {0};
    const char *v = NULL;
    json_t *g = NULL;
    json_object_foreach(st->round_grants, v, g)
    {
        int64_t gn;
        char gb[UUID_STRING_LEN + 1];
        if (!json_is_object(g) || !json_is_array(json_object_get(g, "value"))
            || !_parse_ballot(json_object_get(g, "ballot"), &gn, gb))
            continue;
        if (best == NULL || _ballot_cmp(gn, gb, best_n, best_by) > 0)
        {
            best = json_object_get(g, "value");
            best_n = gn;
            at_strlcpy(best_by, gb, sizeof(best_by));
        }
    }
    json_t *value = best != NULL ? json_incref(best) : NULL;
    int64_t n = st->round_n;
    char head[TX_HASH_HEX_LEN + 1];
    at_strlcpy(head, st->round_head, sizeof(head));
    pthread_mutex_unlock(&rep_state.lock);
    if (best == NULL)
        value = _place_own_value(proc, key);
    if (best == NULL && value != NULL)
        value = _place_own_value_valid(proc, key, value,
                                       key[0] != '\0' ? group : NULL);
    if (value == NULL
        || (best != NULL && _place_value_why(proc, key, value,
                                             key[0] != '\0' ? group : NULL,
                                             false) != NULL))
    {
        if (best != NULL)
            log_warn(proc->logger, "Reputation: placement %d: the value to carry "
                     "is not valid here; dropping the round\n", k);
        pthread_mutex_lock(&rep_state.lock);
        rep_place_state_t *again = _place_state_locked(proc, key);
        if (again != NULL)
            _place_round_close(again);
        pthread_mutex_unlock(&rep_state.lock);
        json_decref(value);
        json_decref(payload);
        return true;
    }
    _send_place(proc, key, k, n, me, head, value);
    json_decref(value);
    json_decref(payload);
    return true;
}

static bool handle_place_accepted(const process_t *proc, directory_t *queues,
                                  generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    char key[UUID_STRING_LEN + 1];
    const char *group = NULL;
    int k = 0;
    json_t *payload = _place_payload(proc, nmsg, key, &group, &k);
    if (payload == NULL)
        return true;
    char voter[UUID_STRING_LEN + 1];
    uuid_unparse_lower(nmsg->from_whom.uuid, voter);
    const char *digest = json_string_value(json_object_get(payload, "digest"));
    const char *sig = json_string_value(json_object_get(payload, "sig"));
    pthread_mutex_lock(&rep_state.lock);
    {
        /* The sender's N_min report, from any acceptance it sends: a round
         * closes on its majority, and the reports of the rest would go stale.
         * Keyed by the authenticated sender; only roster members' reports are
         * ever counted (_n_min_majority). 0 for none; a malformed one is
         * dropped. A hint only: each acceptor holds its own configuration. */
        json_t *nm = json_object_get(payload, "n_min");
        json_t *seen = json_object_get(rep_state.place_n_min_seen, key);
        if (seen == NULL)
        {
            seen = json_object();
            json_object_set_new(rep_state.place_n_min_seen, key, seen);
        }
        if (nm == NULL || json_is_null(nm))
            json_object_set_new(seen, voter, json_integer(0));
        else if (json_is_integer(nm) && json_integer_value(nm) >= 0
                 && json_integer_value(nm) <= INT_MAX)
            json_object_set_new(seen, voter, json_integer(json_integer_value(nm)));
        else
            json_object_del(seen, voter);
    }
    rep_place_state_t *st = _place_round_for_locked(proc, key, k, payload);
    bool ours = st != NULL && st->round_value != NULL && digest != NULL
        && strcmp(digest, st->round_digest) == 0;
    char head[TX_HASH_HEX_LEN + 1] = {0};
    json_t *genesis = NULL;
    if (ours)
    {
        at_strlcpy(head, st->round_head, sizeof(head));
        genesis = _value_genesis(st->round_value);
    }
    pthread_mutex_unlock(&rep_state.lock);
    uint8_t desig[PLACE_DESIG_MAX];
    size_t dlen = ours ? place_designation(k, head, digest, desig, sizeof(desig)) : 0;
    json_t *roster = ours ? _roster_at(key, k) : NULL;
    if (roster != NULL)
    {
        json_decref(genesis);
        genesis = NULL;
    }
    /* A genesis is decided by every member it lists, with their keys. */
    bool verified = ours && dlen > 0
        && _verify_cosignature_in(proc, roster != NULL ? roster : genesis, voter,
                                  desig, dlen, sig);
    json_decref(roster);
    if (!verified)
    {
        json_decref(genesis);
        json_decref(payload);
        return true;
    }
    size_t majority = genesis != NULL ? json_array_size(genesis)
        : _place_majority(proc, key, k, key[0] != '\0' ? group : NULL);
    json_decref(genesis);
    json_t *placed = NULL;
    int64_t won_n = 0;
    pthread_mutex_lock(&rep_state.lock);
    st = _place_round_for_locked(proc, key, k, payload);
    if (st != NULL && st->round_value != NULL)
    {
        json_object_set_new(st->round_accepts, voter, json_string(sig));
        if (json_object_size(st->round_accepts) >= majority)
        {
            /* Decided. Tell everyone, and write it here. */
            placed = json_object();
            json_object_set_new(placed, "group", json_string(key));
            json_object_set_new(placed, "k", json_integer(k));
            json_object_set(placed, "value", st->round_value);
            json_object_set(placed, "sigs", st->round_accepts);
            won_n = st->round_n;
            _place_round_close(st);
        }
    }
    pthread_mutex_unlock(&rep_state.lock);
    if (placed != NULL)
    {
        _place_broadcast(proc, REP_PROTO_PLACED, key, placed);
        if (_apply_placement(proc, key, k, json_object_get(placed, "value"),
                             json_object_get(placed, "sigs"),
                             key[0] != '\0' ? group : NULL))
        {
            uuid_t self_uuid;
            pthread_mutex_lock(&rep_state.lock);
            rep_place_state_t *s2 = _place_state_locked(proc, key);
            if (s2 != NULL && _resolve_self_uuid(proc, self_uuid))
            {
                uuid_unparse_lower(self_uuid, s2->placer);
                /* Our ballot still carries the next instance (the leader's
                 * skip) -- unless the group changed: a promise given under
                 * the old roster is asked for again. */
                bool roster_placed = false;
                size_t pi;
                json_t *pe;
                json_array_foreach(json_object_get(placed, "value"), pi, pe)
                    if (json_object_get(pe, "roster") != NULL)
                        roster_placed = true;
                s2->lead_set = !roster_placed;
                s2->lead_k = _chain_for_key_locked(key)->next_index;
                s2->lead_n = won_n;
            }
            pthread_mutex_unlock(&rep_state.lock);
        }
        json_decref(placed);
    }
    json_decref(payload);
    return true;
}

static bool handle_place_nack(const process_t *proc, directory_t *queues,
                              generic_msg_t *msg)
{
    (void)queues;
    net_msg_t *nmsg = &msg->info.net_msg;
    char key[UUID_STRING_LEN + 1];
    const char *group = NULL;
    int k = 0;
    json_t *payload = _place_payload(proc, nmsg, key, &group, &k);
    if (payload == NULL)
        return true;
    int64_t pn;
    char pb[UUID_STRING_LEN + 1];
    json_t *jnext = json_object_get(payload, "next");
    /* Only a member deciding the instance can refuse it: a node the roster
     * does not list yet -- one waiting to be added, still behind -- would
     * otherwise end every round that adds it. */
    char sender[UUID_STRING_LEN + 1];
    uuid_unparse_lower(nmsg->from_whom.uuid, sender);
    bool member = _place_member_at(proc, key, k, sender);
    pthread_mutex_lock(&rep_state.lock);
    if (_parse_ballot(json_object_get(payload, "promised"), &pn, pb) && pn > g_place_seen_n)
        g_place_seen_n = pn;
    rep_place_state_t *st = member ? _place_round_for_locked(proc, key, k, payload) : NULL;
    bool behind = false;
    if (st != NULL)
    {
        _place_round_close(st);
        st->lead_set = false;
        st->backoff_until = _mono() + _place_backoff();
        behind = json_is_integer(jnext)
            && json_integer_value(jnext) > _chain_for_key_locked(key)->next_index;
    }
    pthread_mutex_unlock(&rep_state.lock);
    if (behind)
        _request_chain_for(proc, &nmsg->from_whom, key);
    json_decref(payload);
    return true;
}

int reputation_register_handlers(process_t *proc)
{
    if (proc == NULL) return -1;
    process_register_handler(proc, REP_PROTO_RETIRED_REQUEST,  (handler_ptr_t)handle_retired);
    process_register_handler(proc, REP_PROTO_RETIRED_GRANT,    (handler_ptr_t)handle_retired);
    process_register_handler(proc, REP_PROTO_RETIRED_NACK,     (handler_ptr_t)handle_retired);
    process_register_handler(proc, REP_PROTO_RETIRED_BACKDATE, (handler_ptr_t)handle_retired);
    process_register_handler(proc, REP_PROTO_TX,        (handler_ptr_t)handle_transaction);
    process_register_handler(proc, REP_PROTO_PLACE_REQUEST, (handler_ptr_t)handle_place_request);
    process_register_handler(proc, REP_PROTO_PLACE,     (handler_ptr_t)handle_place);
    process_register_handler(proc, REP_PROTO_PLACED,    (handler_ptr_t)handle_placed);
    process_register_handler(proc, REP_PROTO_PLACE_GRANT, (handler_ptr_t)handle_place_grant);
    process_register_handler(proc, REP_PROTO_PLACE_ACCEPTED, (handler_ptr_t)handle_place_accepted);
    process_register_handler(proc, REP_PROTO_PLACE_NACK, (handler_ptr_t)handle_place_nack);
    process_register_handler(proc, REP_PROTO_ACCEPTED,  (handler_ptr_t)handle_accepted);
    process_register_handler(proc, REP_PROTO_COMMITTED, (handler_ptr_t)handle_committed);
    process_register_handler(proc, REP_PROTO_OUTDATED,  (handler_ptr_t)handle_outdated);
    process_register_handler(proc, REP_PROTO_UPDATE,    (handler_ptr_t)handle_update);
    process_register_handler(proc, REP_PROTO_REP_REQ,   (handler_ptr_t)handle_rep_request);
    process_register_handler(proc, REP_PROTO_REP_RESP,  (handler_ptr_t)handle_rep_response);
    process_register_handler(proc, REP_PROTO_CONSENSUS_REP_REQ,
                             (handler_ptr_t)handle_consensus_rep_request);
    process_register_handler(proc, REP_PROTO_CONSENSUS_REP_BATCH_REQ,
                             (handler_ptr_t)handle_consensus_rep_batch_request);
    process_register_handler(proc, REP_PROTO_LOCAL_QUERY, (handler_ptr_t)handle_local_rep_query);
    process_register_handler(proc, REP_PROTO_APP_ROSTER, (handler_ptr_t)handle_app_roster_request);
    process_register_handler(proc, REP_PROTO_SLASH_PROPOSE, (handler_ptr_t)handle_slash_propose);
    process_register_handler(proc, REP_PROTO_SLASH_SIGN,    (handler_ptr_t)handle_slash_sign);
    process_register_handler(proc, REP_PROTO_SLASH_FINAL,   (handler_ptr_t)handle_slash_final);
    process_register_handler(proc, REP_PROTO_ATTEST_PROPOSE, (handler_ptr_t)handle_attest_propose);
    process_register_handler(proc, REP_PROTO_ATTEST_SIGN,    (handler_ptr_t)handle_attest_sign);
    process_register_handler(proc, REP_PROTO_ATTEST_FINAL,   (handler_ptr_t)handle_attest_final);
    process_register_handler(proc, REP_PROTO_CHECKPOINT_PROPOSE, (handler_ptr_t)handle_checkpoint_propose);
    process_register_handler(proc, REP_PROTO_CHECKPOINT_SIGN,    (handler_ptr_t)handle_checkpoint_sign);
    process_register_handler(proc, REP_PROTO_CHECKPOINT_FINAL,   (handler_ptr_t)handle_checkpoint_final);
    process_register_handler(proc, REP_PROTO_REP_RESOLVE,        (handler_ptr_t)handle_resolve);
    process_register_handler(proc, REP_PROTO_REP_RESOLVED,       (handler_ptr_t)handle_resolved);
    at_extensions_register_handlers(proc, "reputation");
    return 0;
}

/* ---- Conformance test hooks (see rep_proc_priv.h doc) ---------------------- */

void reputation_set_synchronous_dispatch(bool enabled)
{
    _ensure_init();
    pthread_mutex_lock(&rep_state.lock);
    rep_state.synchronous_dispatch = enabled;
    pthread_mutex_unlock(&rep_state.lock);
}

void reputation_reset_state(int num_peers)
{
    _ensure_init();
    /* Kept one-shot frames are this process's too (utilities/send_retry.h). */
    at_send_retry_reset();
    pthread_mutex_lock(&rep_state.lock);
    /* Tear down + reinit. Preserve synchronous_dispatch so the harness
     * doesn't have to set it on every reset. */
    bool was_sync = rep_state.synchronous_dispatch;
    if (rep_state.paxos.initialized)
        paxos_destroy(&rep_state.paxos);
    /* Clear my_requests; entries are smrt_ptr-backed tx_score_t. */
    map_free(&rep_state.my_requests);
    map_init(&rep_state.my_requests);
    map_free(&rep_state.awaiting_commit);
    map_init(&rep_state.awaiting_commit);
    map_free(&rep_state.heard);
    map_init(&rep_state.heard);
    map_free(&rep_state.handoff_seen);
    map_init(&rep_state.handoff_seen);
    map_free(&rep_state.handoff_passes);
    map_init(&rep_state.handoff_passes);
    map_free(&rep_state.updates);
    map_init(&rep_state.updates);
    for (int i = 0; i < REP_PAGE_BUFS; i++)
        _page_buf_clear(&rep_state.page_bufs[i]);
    rep_state.page_seq = 0;
    rep_state.update_page_bytes = 0;
    array_free(&rep_state.requested_reps);
    array_init(&rep_state.requested_reps);
    /* History reset: free contents + reinit. tx_history_destroy
     * additionally `free()`s the container, which would corrupt the
     * heap when the container is the embedded `rep_state.history`
     * member (never malloc'd). tx_history_free clears contents only. */
    tx_history_free(&rep_state.history);
    tx_history_init(&rep_state.history);
    /* Child chains are heap-allocated per group; free the histories before
     * dropping the map or their chains leak. */
    {
        map_key_t ck = NULL;
        data_t *cv = NULL;
        map_entries_for_each(&rep_state.child_hist, ck, cv)
        {
            void *hp = NULL;
            if (data_object_ptr(cv, &hp) == 0 && hp != NULL)
            {
                tx_history_free((tx_history_t *)hp);
                free(hp);
            }
        }
        map_end_for_each
    }
    map_free(&rep_state.child_hist);
    map_init(&rep_state.child_hist);
    {
        map_key_t sk = NULL;
        data_t *sv = NULL;
        map_entries_for_each(&rep_state.chain_ckpts, sk, sv)
        {
            void *sp = NULL;
            if (data_object_ptr(sv, &sp) == 0 && sp != NULL)
            {
                map_free(&((rep_chain_ckpt_t *)sp)->sigs_final);
                json_decref(((rep_chain_ckpt_t *)sp)->forks);
                free(sp);
            }
        }
        map_end_for_each
    }
    map_free(&rep_state.chain_ckpts);
    map_init(&rep_state.chain_ckpts);
    map_free(&rep_state.round_group);
    map_init(&rep_state.round_group);
    map_free(&rep_state.peer_tiers);
    map_init(&rep_state.peer_tiers);
    map_free(&rep_state.committed_paxos_rounds);
    map_init(&rep_state.committed_paxos_rounds);
    /* doc/architecture/zta-integration.md. Must reset with the rest: the conformance harness resets rep_state
     * between steps, so a ceiling left behind here would bound a peer in a
     * later scenario that never capped it -- and an unwind anchor left behind
     * would silently change how far a later failure reaches back. */
    map_free(&rep_state.peer_ceilings);
    map_init(&rep_state.peer_ceilings);
    map_free(&rep_state.peer_proved_index);
    map_init(&rep_state.peer_proved_index);
    map_free(&rep_state.peer_acted);
    map_init(&rep_state.peer_acted);
    map_free(&rep_state.member_since);
    map_init(&rep_state.member_since);
    map_free(&rep_state.member_key);
    map_init(&rep_state.member_key);
    map_free(&rep_state.tenure_capped);
    map_init(&rep_state.tenure_capped);
    rep_state.tenure_seeded = false;
    rep_state.tenure_min_override = -1.0;
    rep_state.committed_paxos_ring_head = 0;
    rep_state.committed_paxos_ring_len = 0;
    map_free(&rep_state.coop_mode);
    map_init(&rep_state.coop_mode);
    map_free(&rep_state.task_weights);
    map_init(&rep_state.task_weights);
    rep_state.task_weights_ring_head = 0;
    rep_state.task_weights_ring_len = 0;
    memset(rep_state.task_weights_ring, 0, sizeof(rep_state.task_weights_ring));
    map_free(&rep_state.task_tiers);   /* lockstep with task_weights (doc/architecture/network-wire-format.md) */
    map_init(&rep_state.task_tiers);
    map_free(&rep_state.task_channels);   /* same lockstep */
    map_init(&rep_state.task_channels);
    map_free(&rep_state.slashed);
    map_init(&rep_state.slashed);
    map_free(&rep_state.slash_sigs);
    map_init(&rep_state.slash_sigs);
    map_free(&rep_state.slash_pending);
    map_init(&rep_state.slash_pending);
    map_free(&rep_state.attest_pending);
    map_init(&rep_state.attest_pending);
    map_free(&rep_state.attest_sigs);
    map_init(&rep_state.attest_sigs);
    map_free(&rep_state.commit_sigs);
    map_init(&rep_state.commit_sigs);
    json_decref(rep_state.place_n_min_seen);
    rep_state.place_n_min_seen = json_object();
    json_decref(rep_state.bar_warned);
    rep_state.bar_warned = json_object();
    map_free(&rep_state.round_acceptors);
    map_init(&rep_state.round_acceptors);
    map_free(&rep_state.round_granters);
    map_init(&rep_state.round_granters);
    _place_states_free();
    memset(rep_state.attest_retries, 0, sizeof(rep_state.attest_retries));
    rep_state.slash_epoch = 0;
    map_free(&rep_state.slash_hw);
    map_init(&rep_state.slash_hw);
    map_free(&rep_state.excluded);
    map_init(&rep_state.excluded);
    map_free(&rep_state.checkpoint_sigs);
    map_init(&rep_state.checkpoint_sigs);
    map_free(&rep_state.checkpoint_pending);
    map_init(&rep_state.checkpoint_pending);
    rep_state.checkpoint_root[0] = '\0';
    rep_state.checkpoint_epoch = 0;
    rep_state.checkpoint_set = false;
    map_free(&rep_state.checkpoint_sigs_final);
    map_init(&rep_state.checkpoint_sigs_final);
    rep_state.checkpoint_first_index = 0;
    rep_state.checkpoint_count = 0;
    rep_state.final_set = false;
    rep_state.checkpoint_proposer[0] = '\0';
    rep_state.checkpoint_own_epoch = 0;
    rep_state.next_checkpoint_at = 0.0;
    rep_state.checkpoint_phase_taken = false;
    rep_state.last_checkpoint_head = -1;
    map_free(&rep_state.last_interaction);
    map_init(&rep_state.last_interaction);
    rep_state.last_decay_sweep = 0.0;
    rep_state.decay_swept = false;
    map_free(&rep_state.rescore_due);
    map_init(&rep_state.rescore_due);
    rep_state.last_rescore_sweep = 0.0;
    rep_state.rescore_swept = false;
    map_free(&rep_state.child_evidence_tried);
    map_init(&rep_state.child_evidence_tried);
    map_free(&rep_state.restore_clamped);
    map_init(&rep_state.restore_clamped);
    memset(rep_state.parked_cosigns, 0, sizeof(rep_state.parked_cosigns));
    rep_state.num_updates = REP_CATCHUP_QUORUM;
    rep_state.num_peers = num_peers;
    paxos_init(&rep_state.paxos, num_peers, NULL);
    rep_state.synchronous_dispatch = was_sync;
    pthread_mutex_unlock(&rep_state.lock);
}

void reputation_install_task_weight(const uuid_t task_uuid, int weight)
{
    _ensure_init();
    char task_str[UUID_STRING_LEN + 1] = {0};
    uuid_unparse_lower(task_uuid, task_str);
    pthread_mutex_lock(&rep_state.lock);
    _record_task_weight_locked(task_str, weight);
    pthread_mutex_unlock(&rep_state.lock);
}

void reputation_set_chain_len(int len)
{
    _ensure_init();
    /* Stage the CHAIN, not the counter — the counter is derived from it now
     * (see _sync_chain_index). Python's history_len fixture does exactly
     * this: "append N zero-Transaction stubs so len(history) returns the
     * expected value" (harness/python/adapters/reputation.py:526). Setting
     * paxos.chain_len directly would be staging a cache the production code
     * overwrites, which is how the two drifted apart unnoticed. */
    pthread_mutex_lock(&rep_state.lock);
    uuid_t stub_task, p1, p2;
    uuid_clear(p1);
    uuid_clear(p2);
    p1[15] = 1;
    p2[15] = 2;
    /* BOTH sides per stub: tx_history_len counts only BILATERAL entries
     * (reputation.c:856 — a unilateral tx sitting in chain[] is deliberately
     * not counted), so a one-sided stub would leave the length at zero and
     * the fixture would quietly stage nothing. */
    for (int i = tx_history_len(&rep_state.history); i < len; i++)
    {
        uuid_clear(stub_task);
        /* A distinct task per stub, so each appends instead of merging. */
        stub_task[0] = (unsigned char)((i + 1) & 0xFF);
        stub_task[1] = (unsigned char)(((i + 1) >> 8) & 0xFF);
        tx_history_update(&rep_state.history, stub_task, p1, 0.0, NULL);
        tx_history_update(&rep_state.history, stub_task, p2, 0.0, NULL);
    }
    rep_state.paxos.chain_len = tx_history_len(&rep_state.history);
    pthread_mutex_unlock(&rep_state.lock);
}

void reputation_set_update_page_bytes(size_t bytes)
{
    _ensure_init();
    pthread_mutex_lock(&rep_state.lock);
    rep_state.update_page_bytes = bytes;
    pthread_mutex_unlock(&rep_state.lock);
}

void reputation_set_num_updates(int n)
{
    _ensure_init();
    pthread_mutex_lock(&rep_state.lock);
    rep_state.num_updates = n;
    pthread_mutex_unlock(&rep_state.lock);
}

void reputation_install_proposal(int64_t id1, int64_t id2, double score,
                                 const uuid_t task_uuid, const char *channel)
{
    _ensure_init();
    pthread_mutex_lock(&rep_state.lock);
    /* What _forward_transaction leaves behind for handle_accepted: the round's
     * score in paxos.proposals and the task's channel. The round binds to no
     * group, which handle_accepted reads as our primary one. */
    paxos_record_grant(&rep_state.paxos, id1, id2, score);
    if (task_uuid != NULL && channel != NULL && channel[0] != '\0')
    {
        char task_str[UUID_STRING_LEN + 1];
        uuid_unparse_lower(task_uuid, task_str);
        _record_task_channel_locked(task_str, channel);
    }
    pthread_mutex_unlock(&rep_state.lock);
}

int reputation_get_chain_len(void)
{
    if (!rep_state.initialized) return -1;
    pthread_mutex_lock(&rep_state.lock);
    int len = rep_state.paxos.chain_len;
    pthread_mutex_unlock(&rep_state.lock);
    return len;
}

int reputation_get_committed_tx_count(void)
{
    if (!rep_state.initialized) return -1;
    pthread_mutex_lock(&rep_state.lock);
    int len = tx_history_len(&rep_state.history);
    pthread_mutex_unlock(&rep_state.lock);
    return len;
}

void reputation_get_commit_cert_counts(int *halves_held, int *certified_halves)
{
    int held = 0, certified = 0;
    if (rep_state.initialized)
    {
        pthread_mutex_lock(&rep_state.lock);
        const tx_history_t *h = &rep_state.history;
        for (int i = 0; i < h->chain_len; i++)
        {
            const transaction_t *t = &h->chain[i];
            if (t->attested)
                continue;
            if (t->p1_set)
            {
                held++;
                if (tx_history_commit_cert(h, t->task_uuid, t->p1_uuid) != NULL)
                    certified++;
            }
            if (t->p2_set)
            {
                held++;
                if (tx_history_commit_cert(h, t->task_uuid, t->p2_uuid) != NULL)
                    certified++;
            }
        }
        /* And the halves waiting in the pool for their placement. Mirrors
         * the Python adapter. */
        for (int i = 0; i < h->pool_len; i++)
        {
            const transaction_t *t = &h->pool[i];
            if (t->attested)
                continue;
            if (t->p1_set)
            {
                held++;
                if (tx_history_pool_cert(h, t->task_uuid, t->p1_uuid) != NULL)
                    certified++;
            }
            if (t->p2_set)
            {
                held++;
                if (tx_history_pool_cert(h, t->task_uuid, t->p2_uuid) != NULL)
                    certified++;
            }
        }
        pthread_mutex_unlock(&rep_state.lock);
    }
    if (halves_held != NULL) *halves_held = held;
    if (certified_halves != NULL) *certified_halves = certified;
}

void reputation_set_placement_dir(const char *dir)
{
    at_strlcpy(g_placement_dir, dir != NULL ? dir : "", sizeof(g_placement_dir));
}

void reputation_install_place_promise(int64_t n, const uuid_t by)
{
    _ensure_init();
    pthread_mutex_lock(&rep_state.lock);
    rep_place_state_t *st = _place_state_locked(NULL, "");
    if (st != NULL)
    {
        st->have_promised = true;
        st->prom_n = n;
        uuid_unparse_lower(by, st->prom_by);
    }
    pthread_mutex_unlock(&rep_state.lock);
}

bool reputation_get_place_promise(int64_t *n, uuid_t by)
{
    if (!rep_state.initialized)
        return false;
    bool have = false;
    pthread_mutex_lock(&rep_state.lock);
    for (int i = 0; i < rep_state.place_len; i++)
        if (rep_state.place[i].key[0] == '\0' && rep_state.place[i].have_promised)
        {
            *n = rep_state.place[i].prom_n;
            have = uuid_parse(rep_state.place[i].prom_by, by) == 0;
        }
    pthread_mutex_unlock(&rep_state.lock);
    return have;
}

int reputation_get_chain_tasks(uuid_t *out, int max)
{
    if (!rep_state.initialized || out == NULL)
        return 0;
    int n = 0;
    pthread_mutex_lock(&rep_state.lock);
    const tx_history_t *h = &rep_state.history;
    for (int i = 0; i < h->chain_len && n < max; i++)
        if (tx_is_committed(&h->chain[i]))
            uuid_copy(out[n++], h->chain[i].task_uuid);
    pthread_mutex_unlock(&rep_state.lock);
    return n;
}

int reputation_get_pool_tasks(uuid_t *out, int max)
{
    if (!rep_state.initialized || out == NULL)
        return 0;
    int n = 0;
    pthread_mutex_lock(&rep_state.lock);
    const tx_history_t *h = &rep_state.history;
    for (int i = 0; i < h->pool_len && n < max; i++)
        uuid_copy(out[n++], h->pool[i].task_uuid);
    pthread_mutex_unlock(&rep_state.lock);
    return n;
}

void reputation_persist_pools(const process_t *proc)
{
    _ensure_init();
    _persist_pools(proc);
}

bool reputation_reset_pre_roster(const process_t *proc)
{
    _ensure_init();
    pthread_mutex_lock(&rep_state.lock);
    bool reset = _reset_pre_roster_chain_locked(proc);
    pthread_mutex_unlock(&rep_state.lock);
    return reset;
}

void reputation_restore_pool(const process_t *proc)
{
    _ensure_init();
    pthread_mutex_lock(&rep_state.lock);
    _restore_pool_locked(proc, "");
    pthread_mutex_unlock(&rep_state.lock);
}

char *reputation_pool_json(void)
{
    _ensure_init();
    pthread_mutex_lock(&rep_state.lock);
    json_t *doc = _pool_to_json(&rep_state.history);
    pthread_mutex_unlock(&rep_state.lock);
    char *text = doc != NULL ? json_dumps(doc, JSON_COMPACT) : NULL;
    json_decref(doc);
    return text;
}

int reputation_pool_load_json(const char *text)
{
    _ensure_init();
    json_t *doc = text != NULL ? json_loads(text, 0, NULL) : NULL;
    if (doc == NULL)
        return -1;
    pthread_mutex_lock(&rep_state.lock);
    int held = _pool_from_json(&rep_state.history, doc);
    pthread_mutex_unlock(&rep_state.lock);
    json_decref(doc);
    return held;
}

unsigned reputation_pool_rev(void)
{
    _ensure_init();
    return rep_state.history.pool_rev;
}

int reputation_install_chain_json(const json_t *arr)
{
    _ensure_init();
    if (!json_is_array(arr))
        return -1;
    size_t n = json_array_size(arr);
    int *idx = calloc(n > 0 ? n : 1, sizeof(int));
    if (idx == NULL)
        return -1;
    int m = 0;
    size_t i;
    json_t *e;
    json_array_foreach((json_t *)arr, i, e)
    {
        json_t *ix = json_object_get(e, "index");
        if (json_is_integer(ix))
            idx[m++] = (int)json_integer_value(ix);
    }
    pthread_mutex_lock(&rep_state.lock);
    int rc = tx_history_reconcile_placed(&rep_state.history, arr, -1, NULL,
                                         idx, m, NULL);
    pthread_mutex_unlock(&rep_state.lock);
    free(idx);
    return rc;
}

int reputation_record_half(const uuid_t task, const uuid_t scorer, double score,
                           const char *channel, const char *cert_json)
{
    return reputation_record_half_on("", task, scorer, score, channel, cert_json);
}

int reputation_record_half_on(const char *chain_key, const uuid_t task,
                              const uuid_t scorer, double score,
                              const char *channel, const char *cert_json)
{
    _ensure_init();
    pthread_mutex_lock(&rep_state.lock);
    int rc = tx_history_record_half(_chain_for_key_locked(chain_key), task, scorer,
                                    score, channel, cert_json);
    pthread_mutex_unlock(&rep_state.lock);
    return rc;
}

void reputation_place_start(const process_t *proc)
{
    uuid_t self_uuid;
    if (proc == NULL || !_resolve_self_uuid(proc, self_uuid))
        return;
    char me[UUID_STRING_LEN + 1];
    uuid_unparse_lower(self_uuid, me);
    _start_place_round(proc, "", me);
}

int reputation_set_roster_anchor(const json_t *members)
{
    _ensure_init();
    pthread_mutex_lock(&rep_state.lock);
    char digest[TX_HASH_HEX_LEN + 1];
    int rc = tx_history_roster_put(&rep_state.history, members, digest);
    if (rc == 0)
        at_strlcpy(rep_state.history.roster_anchor, digest,
                   sizeof(rep_state.history.roster_anchor));
    pthread_mutex_unlock(&rep_state.lock);
    return rc;
}

void reputation_maybe_place(const process_t *proc)
{
    if (proc != NULL)
        _maybe_place(proc);
}

void reputation_get_head_hash(char *out)
{
    out[0] = '\0';
    if (!rep_state.initialized)
        return;
    pthread_mutex_lock(&rep_state.lock);
    at_strlcpy(out, rep_state.history.head_hash, TX_HASH_HEX_LEN + 1);
    pthread_mutex_unlock(&rep_state.lock);
}

void reputation_get_window_root(char *out)
{
    if (!rep_state.initialized)
    {
        out[0] = '\0';
        return;
    }
    pthread_mutex_lock(&rep_state.lock);
    transaction_window_root(&rep_state.history, out);
    pthread_mutex_unlock(&rep_state.lock);
}

void reputation_get_checkpoint_root(char *out)
{
    if (!rep_state.initialized)
    {
        out[0] = '\0';
        return;
    }
    pthread_mutex_lock(&rep_state.lock);
    if (rep_state.checkpoint_set)
    {
        strncpy(out, rep_state.checkpoint_root, TX_HASH_HEX_LEN);
        out[TX_HASH_HEX_LEN] = '\0';
    }
    else
    {
        out[0] = '\0';
    }
    pthread_mutex_unlock(&rep_state.lock);
}

int reputation_get_evidence_doc(json_t **out)
{
    if (out == NULL) return -1;
    *out = NULL;
    if (!rep_state.initialized) return -1;
    pthread_mutex_lock(&rep_state.lock);
    /* The PRIMARY chain's document — what the corpus pins. A gateway's child
     * chains each have their own file; those are exercised by the unit tests
     * rather than the scenario snapshot. */
    int err = _evidence_doc_locked("", out);
    pthread_mutex_unlock(&rep_state.lock);
    return err;
}

int reputation_get_evidence_ceiling(const uuid_t self_uuid,
                                    const uuid_t peer_uuid, double *out)
{
    if (out == NULL || !rep_state.initialized) return -1;
    /* Self is excluded, as it is in production and in the Python twin: our own
     * score is not a peer judgement. */
    char self_key[UUID_STRING_LEN + 1];
    uuid_unparse_lower(self_uuid, self_key);
    /* Bound over the RESIDENT window, treating it as the attested one: the
     * assertion is about the arithmetic, and a scenario that has not run a
     * checkpoint round has no attested subrange to name. */
    rep_checkpoint_t ckpt;
    if (rep_checkpoint_init(&ckpt) != 0) return -1;
    map_t ceilings;
    if (map_init(&ceilings) != 0)
    {
        rep_checkpoint_free(&ckpt);
        return -1;
    }
    pthread_mutex_lock(&rep_state.lock);
    ckpt.present = true;
    ckpt.count = rep_state.history.committed_count;
    ckpt.first_index = (ckpt.count > 0) ? rep_state.history.first_index
                                        : rep_state.history.next_index;
    int err = reputation_evidence_ceilings(&rep_state.history, &ckpt, self_key,
                                           &ceilings);
    pthread_mutex_unlock(&rep_state.lock);
    if (err == 0)
    {
        char key[UUID_STRING_LEN + 1];
        uuid_unparse_lower(peer_uuid, key);
        data_t *d = NULL;
        if (map_get(&ceilings, (map_key_t)key, &d) == 0 && d != NULL)
            err = data_floating_pt_dbl(d, out);
        else
            err = -1;
    }
    map_free(&ceilings);
    rep_checkpoint_free(&ckpt);
    return err;
}

int reputation_apply_peer_standing(const process_t *proc,
                                   const peer_standing_msg_t *standing)
{
    if (!rep_state.initialized || proc == NULL || standing == NULL) return -1;
    _handle_peer_standing(proc, standing);
    return 0;
}

double reputation_unverified_ceiling(void)
{
    return _tier_ceiling(REP_UNVERIFIED_RESTORE_TIER);
}

int reputation_get_peer_ceiling(const uuid_t peer_uuid, double *out)
{
    if (!rep_state.initialized || out == NULL) return -1;
    pthread_mutex_lock(&rep_state.lock);
    double ceiling = _standing_ceiling_of(peer_uuid);
    pthread_mutex_unlock(&rep_state.lock);
    if (ceiling < 0.0) return -1;
    *out = ceiling;
    return 0;
}

void reputation_install_tx_pair(const uuid_t task_uuid,
                                const uuid_t p1_uuid, double p1_score,
                                const uuid_t p2_uuid, double p2_score)
{
    /* No channel: an untagged entry is what every pre-channel fixture
     * means. */
    reputation_install_tx_pair_tagged(task_uuid, p1_uuid, p1_score, NULL,
                                      p2_uuid, p2_score, NULL);
}

void reputation_install_tx_pair_tagged(const uuid_t task_uuid,
                                       const uuid_t p1_uuid, double p1_score,
                                       const char *p1_channel,
                                       const uuid_t p2_uuid, double p2_score,
                                       const char *p2_channel)
{
    _ensure_init();
    pthread_mutex_lock(&rep_state.lock);
    /* A committed entry is written whole here: since every group places its
     * order, a `tx committed` waits in the pool, so a scenario that needs a
     * tagged entry in the chain stages it. Mirrors the Python adapter's
     * TransactionHistory.update pair. */
    tx_history_update(&rep_state.history, task_uuid, p1_uuid, p1_score, p1_channel);
    tx_history_update(&rep_state.history, task_uuid, p2_uuid, p2_score, p2_channel);
    pthread_mutex_unlock(&rep_state.lock);
}

int reputation_install_tx_attested(const uuid_t verifier_uuid, double score,
                                   const char *channel,
                                   const uuid_t subject_uuid,
                                   const char *evidence_digest)
{
    return reputation_install_tx_attested_scoped(verifier_uuid, score, channel,
                                                 subject_uuid, evidence_digest,
                                                 NULL, NULL);
}

void reputation_test_store_checkpoint(const process_t *proc, const char *proposer,
                                      const char *root, int64_t epoch,
                                      int first_index, int count,
                                      const char *chain_key, json_t *sigs)
{
    _ensure_init();
    _store_checkpoint(proc, proposer, root, epoch, first_index, count,
                      chain_key, sigs);
}

int reputation_install_tx_attested_scoped(const uuid_t verifier_uuid,
                                          double score, const char *channel,
                                          const uuid_t subject_uuid,
                                          const char *evidence_digest,
                                          const char *scope,
                                          const char *cert_json)
{
    _ensure_init();
    transaction_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.attested = true;
    tx.p1_set = true;
    uuid_copy(tx.p1_uuid, verifier_uuid);
    tx.p1_score = score;
    if (channel != NULL)
        at_strlcpy(tx.p1_channel, channel, sizeof(tx.p1_channel));
    uuid_copy(tx.subject_uuid, subject_uuid);
    if (evidence_digest != NULL)
        at_strlcpy(tx.evidence_digest, evidence_digest, sizeof(tx.evidence_digest));
    if (scope != NULL)
        at_strlcpy(tx.attest_scope, scope, sizeof(tx.attest_scope));
    tx_attest_task_uuid(verifier_uuid, subject_uuid, tx.evidence_digest, tx.task_uuid);
    tx.index = -1;
    pthread_mutex_lock(&rep_state.lock);
    int rc = tx_history_append_attested(&rep_state.history, &tx, cert_json);
    pthread_mutex_unlock(&rep_state.lock);
    return rc;
}

int reputation_install_pooled_attested(const uuid_t verifier_uuid,
                                       double score, const char *channel,
                                       const uuid_t subject_uuid,
                                       const char *evidence_digest)
{
    _ensure_init();
    transaction_t tx;
    memset(&tx, 0, sizeof(tx));
    tx.attested = true;
    tx.p1_set = true;
    uuid_copy(tx.p1_uuid, verifier_uuid);
    tx.p1_score = score;
    if (channel != NULL)
        at_strlcpy(tx.p1_channel, channel, sizeof(tx.p1_channel));
    uuid_copy(tx.subject_uuid, subject_uuid);
    if (evidence_digest != NULL)
        at_strlcpy(tx.evidence_digest, evidence_digest, sizeof(tx.evidence_digest));
    tx_attest_task_uuid(verifier_uuid, subject_uuid, tx.evidence_digest, tx.task_uuid);
    tx.index = -1;
    pthread_mutex_lock(&rep_state.lock);
    int rc = tx_history_pool_attested(&rep_state.history, &tx, NULL);
    pthread_mutex_unlock(&rep_state.lock);
    return rc;
}

void reputation_install_tx_single(const uuid_t task_uuid,
                                  const uuid_t peer_uuid, double score)
{
    _ensure_init();
    pthread_mutex_lock(&rep_state.lock);
    tx_history_update(&rep_state.history, task_uuid, peer_uuid, score, NULL);
    pthread_mutex_unlock(&rep_state.lock);
}

void reputation_install_peer_reputation(const uuid_t peer_uuid, double score)
{
    _ensure_init();
    pthread_mutex_lock(&rep_state.lock);
    reputations_update(&rep_state.reputations, peer_uuid, score);
    pthread_mutex_unlock(&rep_state.lock);
}

void reputation_install_coop_mode(const uuid_t peer_uuid, bool in_coop)
{
    _ensure_init();
    char key[UUID_STRING_LEN + 1] = {0};
    uuid_unparse_lower(peer_uuid, key);
    pthread_mutex_lock(&rep_state.lock);
    map_set(&rep_state.coop_mode, key, integer_data(in_coop ? 1 : 0));
    pthread_mutex_unlock(&rep_state.lock);
}

void reputation_install_checkpoint(const char *root, int64_t epoch)
{
    reputation_install_checkpoint_window(root, epoch, 0, 0);
}

/* As reputation_install_checkpoint, with the window it covers: the finality
 * line chain reconciliation must not cross (ISSUES.md §2.15). */
void reputation_install_checkpoint_window(const char *root, int64_t epoch,
                                          int first_index, int count)
{
    _ensure_init();
    pthread_mutex_lock(&rep_state.lock);
    if (root != NULL && root[0] != '\0')
    {
        /* Seed the PRIMARY chain's slot, not just the flat mirror: slash
         * evidence is verified against the finalized slots (any chain's root
         * may anchor it since doc/architecture/gateway-reputation-tree.md), so a fixture that only wrote the mirror
         * would leave the evidence unverifiable. */
        rep_chain_ckpt_t *slot = _ckpt_slot_locked("");
        if (slot != NULL)
        {
            snprintf(slot->root, sizeof(slot->root), "%s", root);
            slot->epoch = epoch;
            slot->first_index = first_index;
            slot->count = count;
            slot->set = true;
        }
        _mirror_primary_ckpt_locked();
        /* A fixture checkpoint stands for a finalized one. */
        _note_final_locked(root, first_index, count);
    }
    pthread_mutex_unlock(&rep_state.lock);
}

int reputation_get_peer_reputation(const uuid_t peer_uuid, double *out)
{
    if (!rep_state.initialized || out == NULL) return -1;
    pthread_mutex_lock(&rep_state.lock);
    int rc = reputations_get(&rep_state.reputations, peer_uuid, out);
    pthread_mutex_unlock(&rep_state.lock);
    return rc == 0 ? 0 : -1;
}

/* Frama-C: skipped — [solver-timeout] state-cascade through paxos_init +
 * process_register_handler stubs prevents WP from discharging
 * valid_rw(proc) and valid_rd(signal) at downstream call sites */
/* This node's own identity UUID (identity_self_identity). Returns true and
 * fills out_uuid on success; false if identity isn't resolvable yet. */
static bool _resolve_self_uuid(const process_t *proc, uuid_t out_uuid)
{
    const identity_t *self = identity_self_identity(proc);
    if (self == NULL)
        return false;
    uuid_copy(out_uuid, self->uuid);
    return true;
}

/* Handle a locally-submitted TransactionScore. Another process on this node
 * (e.g. the data-source's producer-side dod.sensor-report score) posts a
 * TRANSACTION_SCORE generic message to our queue; we are the proposer, so we
 * start a Paxos round under our own identity. Mirrors Python automate.py
 * putting a TransactionScore on the reputation queue → repprocess._start_paxos.
 *
 * The generic run_message_handlers cannot dispatch this — it only routes
 * net_msg payloads by function name — which is why such messages were silently
 * dropped before (and _forward_transaction was dead code).
 *
 * Only real (non-zero task_uuid) scores are forwarded. A zero task_uuid is the
 * legacy ZTA/config "system score" sentinel (zta_process.c:124) whose bilateral
 * semantics are out of scope here; it stays a no-op, unchanged from before. */
static void _handle_local_tx_score(const process_t *proc,
                                   const generic_msg_t *msg,
                                   const uuid_t self_uuid, bool have_self)
{
    const tx_score_msg_t *ts = &msg->info.tx_score;
    if (ts->attested)
    {
        /* A verifier-attested score: no Paxos round with the subject; the
         * group certifies it instead (doc/architecture/reputation.md). Its
         * task id is derived, so the zero-task sentinel below does not apply. */
        if (!have_self)
            log_warn(proc->logger,
                     "Reputation: dropping local attestation — self identity unavailable\n");
        else
            _forward_attestation(proc, ts, self_uuid);
        return;
    }
    uuid_t zero;
    uuid_clear(zero);
    if (uuid_compare(ts->task_uuid, zero) == 0)
    {
        log_debug(proc->logger,
                  "Reputation: ignoring system TRANSACTION_SCORE (zero task)\n");
        return;
    }
    if (!have_self)
    {
        log_warn(proc->logger,
                 "Reputation: dropping local score — self identity unavailable\n");
        return;
    }
    /* doc/architecture/reputation.md: a LOCAL submitter off the scale is a bug in that submitter, so it is
     * refused here too rather than forwarded into a Paxos round. The Python twin
     * raises ValueError at this point (TransactionScore's constructor); C has no
     * exception to raise into an app, so it logs and drops. */
    if (!tx_score_in_range(ts->score))
    {
        log_warn(proc->logger,
                 "Reputation: dropping local TRANSACTION_SCORE: score %f is off "
                 "the [%g, %g] scale\n", ts->score, TX_SCORE_MIN, TX_SCORE_MAX);
        return;
    }
    /* A LOCAL submitter naming a channel AT does not know is a bug in that
     * submitter -- the same judgment as an off-scale score above -- so it is
     * refused here rather than forwarded into a Paxos round where peers would
     * drop it anyway. An unset channel is absence, not error, and resolves to
     * TX_CHANNEL_TASK_OUTCOME inside _forward_transaction. */
    if (ts->channel[0] != '\0' && !tx_channel_valid(ts->channel))
    {
        log_warn(proc->logger,
                 "Reputation: dropping local TRANSACTION_SCORE: unknown "
                 "evidence channel '%s'\n", ts->channel);
        return;
    }
    /* ts->peer_uuid is the SUBJECT: the peer this score is about, stamped by
     * the producer that knows it (neg_proc's handle_results, config_proc's
     * identity-modification penalty). Zero == not attributable to one peer,
     * which is the honest answer for a fan-out. */
    /* ts->competence is the learned EMA weight multiplier (R+D.md §12.5),
     * measured by the producer that observed the peer's forecasts. Unvalidated
     * on purpose, unlike the score and the channel above: it arrives only over
     * IPC from our own subsystems, it is bounded at the source by the declared
     * weight band, and a non-positive value is read as absence rather than
     * refused -- a zeroed struct from a producer predating the field means
     * "the authored weight, verbatim". */
    /* Probe backpressure (§2.60): AT's probes yield to app halves. */
    if (!_admit_new_half(proc, ts->task_uuid, ts->capability_name))
        return;
    _forward_transaction(proc, ts->task_uuid, self_uuid, ts->score,
                         ts->capability_name, ts->channel, ts->peer_uuid,
                         ts->competence);
}

int reputation_run(process_t *proc, directory_t *queues, queue_id_t signal, logger_t *logger)
{
    _ensure_init();

    /* A misread N_min would quietly size every certificate round for the
     * wrong F, so a malformed one is fatal. */
    if (_env_n_min() < 0)
    {
        log_error(logger, "Reputation: AT_REP_N_MIN=%s is not a non-negative "
                  "integer; not starting\n", getenv("AT_REP_N_MIN"));
        return -1;
    }

    /* rep_state.num_peers is the paxos instance's size and nothing more. The
     * grant and acceptance thresholds do NOT read it: it is sampled here,
     * before discovery has found anybody, so it is 0 in production. They are
     * sized per round against the live roster (_round_quorum_locked). */
    peers_read_lock(proc);
    rep_state.num_peers = (int)proc->protocol.num_peers;
    peers_read_unlock(proc);
    /* Ballots carry a per-node id in their low 16 bits, so two nodes minting
     * in the same millisecond do not propose equal ballots. */
    uint16_t node_id = 0;
    uuid_t node_uuid;
    if (_resolve_self_uuid(proc, node_uuid))
        node_id = (uint16_t)(((node_uuid[0] ^ node_uuid[14]) << 8)
                             | (node_uuid[1] ^ node_uuid[15]));
    paxos_init_with_node(&rep_state.paxos, rep_state.num_peers, node_id, logger);

    reputation_register_handlers(proc);
    proc->protocol.phase = 1;

    /* Custom loop (mirrors data_source_run): intercept locally-submitted
     * TRANSACTION_SCORE messages and start a Paxos round for them; everything
     * else flows through the registered net_msg handlers exactly as
     * process_loop would. Without this, a node could only participate in
     * transactions other peers initiate, never propose its own. */
    process_ctx_t ctx = {0};
    int err = process_setup(proc, signal, logger, &ctx);
    if (err != 0)
        return err;

    uuid_t self_uuid;
    bool have_self = _resolve_self_uuid(proc, self_uuid);
    char self_str[UUID_STRING_LEN + 1] = {0};
    if (have_self)
        uuid_unparse_lower(self_uuid, self_str);

    /* Warm start, in the order the pieces depend on each other: load the
     * persisted operational snapshot, fade it by the gap we spent out of
     * contact, then adopt the persisted history if its checkpoint verifies and
     * clamp every score the evidence does not bear out. See doc/architecture/reputation.md and
     * doc/architecture/reputation.md. */
    _load_reputations(proc);
    /* Extensions' trust seeds (first contact's verified contacts), after the
     * snapshot so a persisted value always wins, and before the idle fade so a
     * seed ages like any other prior. */
    _apply_seeds(proc);
    _seed_idle_from_snapshot(proc, have_self ? self_str : NULL);
    _rebuild_from_evidence(proc, have_self ? self_str : NULL);
    /* Ordered placement's pending pool, after the chain it waits on -- and a
     * chain from before rosters, reset first. */
    pthread_mutex_lock(&rep_state.lock);
    (void)_reset_pre_roster_chain_locked(proc);
    _restore_pool_locked(proc, "");
    pthread_mutex_unlock(&rep_state.lock);
    /* Slash replay marks, before the loop can handle a slash_final. Also
     * resumes our own slash epoch, so it must precede the first origination. */
    _load_slash_marks(proc);

    while (keep_running(proc, &ctx.sig_q, logger))
    {
        sleep_until(proc, cadence);

        /* Periodic work, throttled internally: relax idle peers toward
         * almost-neutral, commit to our own window so the persisted evidence
         * carries a quorum-signed root, and keep the snapshot current. */
        double present = (double)time(NULL);
        /* Expire deep-resolution state. A relayed query whose subtree never
         * answers is the ordinary case, not an error, and this is the only
         * thing that clears it. Mirrors Python's call in process(). */
        _prune_resolve_state(proc);
        /* A contact verified since boot gets its seed here; first contact's
         * provider is guarded by the contacts file's mtime, so the usual pass
         * is one stat() and nothing else. Mirrors Python's call in process(). */
        _apply_seeds(proc);
        _decay_reputations(proc, present);
        if (!have_self)
        {
            have_self = _resolve_self_uuid(proc, self_uuid);
            if (have_self)
                uuid_unparse_lower(self_uuid, self_str);
        }
        /* Score whoever the chain moved for; see _rescore_peers for why this
         * is the only thing that rates a peer in a running node. */
        _rescore_peers(proc, present, have_self ? self_uuid : NULL);
        _maybe_checkpoint(proc, present, have_self ? self_str : NULL);
        /* Our halves that went out and never came back (ISSUES §2.24). */
        _retry_uncommitted_halves(proc, present);
        /* Our unpaired halves, to members that joined after we committed
         * them (ISSUES §2.62). */
        _hand_off_pending_halves(proc, present, self_uuid, have_self);
        /* Checkpoint proposals that arrived before our chain held their
         * range (ISSUES §2.29). */
        _recheck_parked_cosigns(proc, present);
        /* Our attestation rounds whose propose went missing (ISSUES §2.40). */
        _retry_pending_attestations(proc, present);
        /* Ordered placement: propose the next instance if it is ours now. */
        _maybe_place(proc);
        /* A gateway's child groups arrive over IPC (CHILD_GROUP) after this
         * process was constructed, so their persisted evidence is restored
         * here rather than at boot. Idempotent per group. */
        if (proc->protocol.child_groups != NULL)
            _restore_child_evidence(proc, have_self ? self_str : NULL);
        /* After the child chains are restored, so their pools wait on them. */
        _persist_pools(proc);

        /* Drain what is queued rather than one per tick: the per-pass work
         * above keeps its cadence, but a reputation burst (every peer's
         * transaction traffic arrives at once during a cohort bootstrap)
         * otherwise overflows this queue and is dropped at the sender, which
         * logs 'Failed to route message to process reputation' on the network
         * side and nothing at all here. See PROC_DRAIN_MAX. */
        generic_msg_t buf = {0};
        for (int taken = 0; taken < PROC_DRAIN_MAX; taken++)
        {
            messaging_recv_release(&buf);   /* the previous pass's */
            int rerr = messaging_recv(&buf);
            if (rerr == -1 || rerr == ENOMSG)
                break;

            if (buf.type == PEER_STANDING)
            {
                /* An authority's finding about a peer (doc/architecture/zta-integration.md). Handled
                 * here rather than via run_message_handlers for the same reason
                 * TRANSACTION_SCORE is: that dispatcher routes net_msg payloads by
                 * function name, and this is a local struct. */
                _handle_peer_standing(proc, &buf.info.peer_standing);
            }
            else if (buf.type == TRANSACTION_SCORE)
            {
                /* Self identity may not have been loaded at startup; resolve
                 * lazily on first use so an early submission isn't lost. */
                if (!have_self)
                    have_self = _resolve_self_uuid(proc, self_uuid);
                _handle_local_tx_score(proc, &buf, self_uuid, have_self);
            }
            else
            {
                /* Who is reachable, for parking (§2.60). */
                if (buf.type == NET_MESSAGE)
                    reputation_note_heard(buf.info.net_msg.from_whom.uuid,
                                          (double)time(NULL));
                run_message_handlers(proc, queues, buf.type, &buf);
            }
        }
        messaging_recv_release(&buf);
    }

    /* Final flush on the way out, so a clean shutdown leaves a snapshot the
     * next start can warm-start from (mirrors Python's SIGTERM flush). The
     * evidence file is already current — it is rewritten at every checkpoint
     * store — so only the operational scores need saving here. */
    _persist_reputations(proc);

    /* The daemon's directory, shared by every subsystem thread in-process. */
    if (!messaging_in_process())
        array_free(queues);
    if (ctx.fd1 > 0)
        close(ctx.fd1);
    if (ctx.fd2 > 0)
        close(ctx.fd2);
    return 0;
}
DECLARE_PROCESS(reputation, rep_proc, reputation_run);
