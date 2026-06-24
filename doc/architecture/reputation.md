[< Task Negotiation](negotiation.md)

# Reputation Consensus

The reputation subsystem uses a leaderless Byzantine Multi-Paxos protocol to reach consensus on transaction scores across all peers. It builds on the assumption that the Identity protocol has already succeeded (permissioned consensus).

## Protocol Messages

| Message | Constant | Direction | Purpose |
|---------|----------|-----------|---------|
| `ask permission` | `request` | proposer -> group | Phase 1: request the floor with a unique proposal ID |
| `permission granted` | `grant` | peer -> proposer | Phase 1: grant with last-seen ID + chain length |
| `try again` | `nack` | peer -> proposer | Phase 1: reject (timestamp too old) |
| `out of date` | `backdate` | peer -> proposer | Phase 1: proposer's index is behind |
| `transaction` | `transaction` | proposer -> group | Phase 2: propose transaction score |
| `tx accepted` | `accepted` | peer -> proposer | Phase 2: accept the proposed transaction |
| `tx committed` | `committed` | proposer -> group | Phase 3: announce commit so acceptors update their history |
| `update needed` | `outdated` | behind-peer -> top-n peers | Sync: request missing history |
| `latest update` | `update` | peer -> behind-peer | Sync: send history segment |
| `request reputation` | `rep_req` | any process -> reputation | Query: compute a peer's score |
| `reputation response` | `rep_resp` | reputation -> requester | Query: return computed score |

## Proposal ID

Each Paxos round uses a unique proposal ID composed of:

- `id1`: Timestamp in milliseconds (`int(now().timestamp() * 1000)`)
- `id2`: Chain index (`len(history) + 1`)
- `peer_id`: Proposer's UUID

These are combined into a float index: `id1 + (id2 / 10^len(str(id2)))` for tracking.

## Paxos Consensus Flow

The diagram below is generated from `conformance/scenarios/reputation/reputation-canonical.yaml` by `scripts/build-docs.sh` — it cannot drift from the executable corpus. The canonical pins the Phase 1 happy path; the rest of the protocol (Phase 2, nack/backdate/sync branches) is documented as separate scenarios linked below.

<!-- at_diagram:start protocol=reputation scenario=reputation-canonical -->
```mermaid
sequenceDiagram
    participant alice as proposer
    participant bob as acceptor
    alice->>+bob: ask permission
    Note right of alice: Phase 1 — alice broadcasts an ask-permission ballot on the encrypted group channel. (id1, id2, proposer) uniquely tags the round; id1 is a millisecond timestamp, id2 is the proposer's chain index.
    bob-->>-alice: permission granted (re: 1)
    Note right of bob: Phase 1 — bob's last_id is None and chain is empty, so the strict-inequality guard passes; handle_request emits a grant ack back to alice. (Out-of-band nack / backdate / sync branches are documented in separate scenarios.)
```
<!-- at_diagram:end -->

**Channel semantics.** All Paxos messages (`ask permission`, `permission granted`, `try again`, `out of date`, `transaction`, `tx accepted`) travel on the **encrypted group channel**. The sync messages (`update needed`, `latest update`) are sent **peer-to-peer, encrypted**, addressed to the proposer's top-3 most-trusted peers.

**Phase 1 alternate branches** (not in the canonical, pinned by separate scenarios):

- **Nack — `try again`.** If the acceptor's `last_id` is greater-than-or-equal to the proposed `id1`, the strict-inequality guard fails and `handle_request` emits a `try again` instead of `permission granted`. The proposer applies exponential backoff (1.5× starting at 2s, capped at 90s) and retries with a fresher timestamp. Trace: [`request-nacked-stale.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/request-nacked-stale.yaml).
- **Backdate — `out of date`.** If the proposer's chain index is behind the acceptor's recorded chain length, the acceptor emits `out of date` carrying its own `chain_len`. The proposer triggers the sync sub-protocol. Trace: [`request-backdated-chain-mismatch.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/request-backdated-chain-mismatch.yaml).

**Phase 2 — Accept.** Once the proposer reaches majority grants (`> peers/2`), it emits a `transaction` carrying the score, keyed by the same `(id1, id2, proposer)` tuple. Each acceptor verifies the round was previously granted (`paxos_has_granted_id` on the C side; `my_requests` lookup on Python) and emits `tx accepted`. The proposer commits to history on majority acceptance. Trace: [`transaction-accepted.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/transaction-accepted.yaml).

**Phase 3 — Commit broadcast.** After the proposer commits to its own history, it broadcasts `tx committed` carrying `(task_id, proposer_id, score)` to the group. Each acceptor writes the same entry to its own history; the proposer skips its own bounce-back. Without this phase, every peer's local history would contain only its own submissions — when peer A and peer B independently score the same task, A's history would have `(task_id, A, A_score)` only and B's would have `(task_id, B, B_score)` only, and CTFT's bilateral check (`p1==peer && p2==self`) could never match. Phase 3 is what makes a single bilateral Transaction appear in *every* peer's view. Trace: [`transaction-committed-bilateral.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/transaction-committed-bilateral.yaml).

**Sync sub-protocol.** When a proposer falls behind (signalled by `out of date`), it sends `update needed` to its top-3 most-trusted peers (encrypted peer-to-peer) carrying its current chain length. Each recipient responds with `latest update` carrying any history segment beyond the proposer's chain length. The proposer majority-votes across the 3 responses and catches up. Traces: [`chain-outdated-notification.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/chain-outdated-notification.yaml), [`chain-replay-update.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/chain-replay-update.yaml).

**Internal steps not on the wire** (omitted from the diagram, but part of the protocol):

- The proposer's `Main Orchestrator` (the per-process queue from the application layer) hands `TransactionScore(task_uuid, score)` to the local reputation process, which records the pending request before broadcasting `ask permission`.
- After each `permission granted` arrives, `handle_grant` increments the grant count and checks for majority before moving to Phase 2.
- After each `tx accepted`, `handle_accepted` increments the acceptance count and commits the score to history on majority.

**Replay invariants.** Both Phase 1 (`ask-permission-replay-rejected.yaml`, `ask-permission-lower-id-rejected.yaml`) and the chain-update path (`chain-replay-update.yaml`) are pinned against re-delivery — Paxos `last_id` advances on grant, so duplicate or out-of-order ballots are rejected idempotently. See BUGS.md §P6 for the closure of the original `last_id`-advance divergence.

## Reputation Computation

When a reputation query arrives (`rep_req`), the score is computed using one of two strategies based on the peer's current standing. The mode switch uses **hysteresis** to prevent oscillation (a peer hovering near the boundary used to flip modes every tick — e.g. 0.9 ↔ 0.4): a peer must climb above `COOP_ENTER = 0.55` to enter Cooperation Mode and must fall below `COOP_EXIT = 0.45` to drop back to Tit-for-Tat. Within the `[0.45, 0.55]` band the previously-selected mode is retained.

### Cooperation Mode (`prior > COOP_ENTER` to enter, retained until `prior <= COOP_EXIT`)

Pure reputation: a weighted average of every transaction score involving this peer. Each transaction score is weighted by **two** factors — the counterparty's own reputation and the transaction's capability `transaction_weight` (a higher-tier capability counts for more):

```
score = Σ (counterparty_score · counterparty_rep · task_weight) / Σ task_weight
```

(returns the neutral `0.5` when there is no weighted history). The `transaction_weight` factor ties this directly into the tiered-transaction model — see [Trust Tiers §5](trust-tiers.md).

### Tit-for-Tat Mode (`prior <= COOP_EXIT` to enter, retained until `prior > COOP_ENTER`)

Contrite Tit-for-Tat: examines the bilateral transaction history between the local node and the queried peer.

- If the peer defected (score < 0.5) but local standing is poor: cooperate (score >= 0.51)
- If the peer defected and local standing is fine: defect (score <= 0.49)
- Otherwise: cooperate

This encourages mutual recovery from low-trust situations while punishing sustained defection.

## Warm-start and cold-start baseline

**Warm-start** is precisely this: *a memory of a peer's prior AT-bounded
activity that becomes operational again at machine start-up.* It is not a grant
of trust and not a configured allow-list — it is the reputation a peer **already
earned** through observed, AT-mediated transactions, persisted to disk
(`reputation.cfg.json`) and reloaded into the live `self.reputations` store when
the node restarts. Because that score is bound to the same cryptographic
identity and remains subject to continuous re-evaluation (every subsequent
transaction can move it, and the slashing fast-path can floor it), a
warm-started peer is in exactly the same regime as any other peer — it simply
does not have to re-earn standing from neutral on every reboot. The safety of
that shortcut rests on the staleness decay below: re-loaded trust is *stale*
trust, and stale trust fades.

A peer with no bilateral transaction history would otherwise read as the flat
neutral `0.5` ("forming…") until enough rounds accumulate. Two mechanisms avoid
that dead zone:

- **Seeded warm-start.** At startup the process loads any persisted/seeded
  reputation snapshot (`self.configs.get(CfgIds.reputation)`). A seeded prior
  overrides the flat `0.5` for known-trusted peers so they read "trusted"
  immediately rather than spending the warm-up window looking untrusted. See
  [Persistent Cohort](persistent-cohort.md) for how the snapshot is written and
  restored.
- **Consensus baseline.** When a peer has no transactions on the chain,
  `_consensus_reputation` falls back to `_consensus_baseline()` instead of the
  neutral default, deriving a starting score from available consensus state.

The dod_mission demo layers a domain-specific **warm-start cohort** on top of
this for constrained-duration assets (squad, microdrones, jet) that may be
present too briefly to build consensus history: `is_pre_trusted` /
`is_warm_start_member` gate which peers receive seeded priors, and
`reconcile_rep_score` returns the seeded `(score, tier)` for a warm-start member
whose only readings are neutral. This lives in `examples/dod_mission`
(`reputation_warmstart.py`, `tools/seed_dod_cohort.py`), not in core, but is the
reference pattern for warm-starting brief-lived peers.

## Staleness decay (why warm-start is safe)

Earned reputation is a memory, and memory must fade — otherwise a warm-started
score would be trusted forever on the strength of activity that may be hours or
days old. `ReputationProcess` therefore relaxes an idle peer's **operational**
reputation toward *almost-but-not-quite neutral* as a function of time since the
last transaction with that peer (`_decay_reputations`, swept periodically from
the process loop; `_decayed_score` is the pure function). The relevant constants
(`REPUTATION_DECAY_*` in `repprocess.py`) are tunable:

- **Asymptote** (`0.51`, just above neutral `0.50`). A long-dormant peer relaxes
  toward — but never reaches — neutral, so a previously-known asset stays
  faintly preferred over a true stranger while its *elevated* trust tier
  (tiers 2–4) lapses and must be re-earned on contact.
- **Onset** grace period before any decay begins, so a brief out-of-range gap
  costs nothing.
- **Half-life** sets how fast the gap above the asymptote then shrinks.

The decay is **asymmetric by design**: it only erodes reputation *above* the
asymptote. A score at or below it — a distrusted or corrupt node — is left
untouched, because mere absence must never rehabilitate a bad actor (this
preserves the sticky-low-reputation intent noted at `self._consensus_last`).
Slashed peers (whose floor is authoritative) and self are never decayed.

**Across a restart**, the time a peer spent out of contact while we were down is
counted: `_seed_idle_from_snapshot` treats the persisted snapshot's mtime as the
instant of last activity, seeds each loaded peer's idle clock to it, and applies
the offline-gap decay up front — so a cohort that warm-starts after a long
dormancy comes up with appropriately faded, not stale-inflated, trust. This is
local-view only: decay is wall-clock driven and never serialized onto the wire,
so it is invisible to the Python↔C conformance corpus.

### Planned hardening: floor, not full restoration

**Status: design, not yet implemented.** Today warm-start reloads the persisted
operational reputation scalar (subject to the decay above), so a *recently*-active
peer with little decay is restored to whatever tier that scalar maps to —
including an elevated tier — the instant it passes admission. The decay axis
covers *time out of contact*, but not the orthogonal *"this session hasn't
re-validated you yet"* axis.

The hardening: warm-start should restore only **low-tier** standing (presence /
communication) immediately, and require **fresh in-session behavioral evidence**
before re-granting **elevated or safety-critical tiers**. Rationale: an
*authenticated-but-compromised* asset passes ZTA admission *by definition* (it
holds valid credentials — the headline threat), and for a short-lived asset there
is no time for behavioral re-evaluation to catch it before its window closes; so
restoring its historically-earned high tier instantly re-opens, for short-lived
assets, exactly the compromised-but-credentialed hole the system exists to close.
Implementation sketch: at `_seed_idle_from_snapshot` (and on readmission), clamp
the restored operational reputation to the tier-1 ceiling until the peer accrues
N fresh committed in-session transactions, then let it climb normally. Decay and
this floor compose (one is the time axis, the other the in-session axis). Pairs
with the human-on-the-loop carve-out for safety-critical capabilities.

## Expiration

Pending requests and proposals expire after 300 seconds to prevent unbounded memory growth.

[Node Lifecycle >](node-lifecycle.md)
