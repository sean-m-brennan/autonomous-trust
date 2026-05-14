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

**Sync sub-protocol.** When a proposer falls behind (signalled by `out of date`), it sends `update needed` to its top-3 most-trusted peers (encrypted peer-to-peer) carrying its current chain length. Each recipient responds with `latest update` carrying any history segment beyond the proposer's chain length. The proposer majority-votes across the 3 responses and catches up. Traces: [`chain-outdated-notification.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/chain-outdated-notification.yaml), [`chain-replay-update.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/chain-replay-update.yaml).

**Internal steps not on the wire** (omitted from the diagram, but part of the protocol):

- The proposer's `Main Orchestrator` (the per-process queue from the application layer) hands `TransactionScore(task_uuid, score)` to the local reputation process, which records the pending request before broadcasting `ask permission`.
- After each `permission granted` arrives, `handle_grant` increments the grant count and checks for majority before moving to Phase 2.
- After each `tx accepted`, `handle_accepted` increments the acceptance count and commits the score to history on majority.

**Replay invariants.** Both Phase 1 (`ask-permission-replay-rejected.yaml`, `ask-permission-lower-id-rejected.yaml`) and the chain-update path (`chain-replay-update.yaml`) are pinned against re-delivery — Paxos `last_id` advances on grant, so duplicate or out-of-order ballots are rejected idempotently. See BUGS.md §P6 for the closure of the original `last_id`-advance divergence.

## Reputation Computation

When a reputation query arrives (`rep_req`), the score is computed using one of two strategies based on the peer's current standing:

### Cooperation Mode (prior score > 0.5)

Pure reputation: weighted average of all transaction scores involving this peer, where each score is weighted by the scoring peer's own reputation.

### Tit-for-Tat Mode (prior score <= 0.5)

Contrite Tit-for-Tat: examines the bilateral transaction history between the local node and the queried peer.

- If the peer defected (score < 0.5) but local standing is poor: cooperate (score >= 0.51)
- If the peer defected and local standing is fine: defect (score <= 0.49)
- Otherwise: cooperate

This encourages mutual recovery from low-trust situations while punishing sustained defection.

## Expiration

Pending requests and proposals expire after 300 seconds to prevent unbounded memory growth.

[Node Lifecycle >](node-lifecycle.md)
