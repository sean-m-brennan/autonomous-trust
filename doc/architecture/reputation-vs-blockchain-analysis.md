# Identity & Reputation vs. Typical Blockchain: Architecture

> Status: Implemented. Describes the **current** state of the code, grounded in
> `src/autonomous-trust/autonomous_trust/core/_python/{identity,reputation,structures}`
> and the C twin `src/c/autonomous_trust/reputation/`, cross-checked by the
> conformance corpus (`src/autonomous-trust/conformance/`).
> Companion docs: `doc/architecture/{reputation,identity-protocol,gateway-reputation-tree,trust-tiers}.md`.
>
> History: this began as a review of how the reputation subsystem compared to
> "typical" blockchains, prompted by the dod_mission "mq800 stuck at 0.5"
> reputation bug. The three improvements it recommended for the reputation chain
> (slashing-style fast penalties, hash/Merkle-linking, and a quorum-signed
> finality artifact) have since been implemented (Phases 0-3 below). This
> document now records what the code does and why, rather than proposing it.

## Key distinction up front

The **identity** chain is, and always was, cryptographically blockchain-grade:
a Merkle tree (`MerkleTree`, `root_digest`, `inclusion_proof`/`audit` in
`structures/merkle.py`) over a StepDAG of Merkle-root history with Ed25519-signed
steps.

The **reputation** chain is a deliberately different animal (a bounded,
evicting, derive-on-read evidence log) but it is **no longer cryptographically
naked**. A committed `Transaction` now carries a `prev_hash` (hash-linked
chain), the resident window has an RFC 6962 Merkle root (`window_root`) that a
quorum co-signs into a `Checkpoint`, and provable misbehavior is punished by a
fast, evidence-gated slashing channel. The remaining differences from a typical
L1 (bounded/evicting, group-scoped, derive-on-read) are intentional CAP choices,
not gaps.

---

## 1. How the algorithms differ from a "typical" blockchain

It helps to split "typical blockchain" into the **public-Nakamoto** model
(Bitcoin/Ethereum) vs. the **permissioned-BFT** model (Tendermint/PBFT/Hyperledger),
because the system sits in neither cleanly.

### Reputation consensus (`repprocess.py`, `doc/architecture/reputation.md`)

- **Leaderless Byzantine Multi-Paxos**, 3-phase (prepare / accept / commit-broadcast),
  majority quorum `> peers/2`. This is the **permissioned-BFT family**, not Nakamoto.
  Finality is *immediate on majority-accept*, not probabilistic-after-N-confirmations.
  No mining, no token, no gas, no fork-choice-by-work.
- **Group-scoped, not global.** Each group keeps its *own* chain (`self.history`,
  plus `child_histories` for gateways). There is no single canonical world-state:
  the "ledger" is plural and local.
- **Bounded, evicting chain.** A blockchain is append-only-forever and immutable;
  this is a *sliding window that forgets* (`max_chain_len`, `_evict_oldest`,
  `_evicted_task_ids` tombstones). The sticky cache (`_consensus_last`) survives
  eviction.
- **State is derived, not stored.** The chain stores raw bilateral `TransactionScore`
  evidence; the reputation number is *computed on read* (EMA / CTFT / pure). That's
  event-sourcing, not account-state.
- **Bilateral, mutual attestations.** A `Transaction` commits only with *both* `p1`
  and `p2` scores: a two-party handshake, not a single-signer transfer.
- **Integrity now rests on the artifact as well as the live protocol.** Entries are
  admitted by signed Paxos votes *and* are hash-linked (`Transaction.prev_hash` =
  `entry_hash` of the predecessor), so the catch-up sync verifies link continuity
  before merging (verifiable, not merely social). A quorum-signed Merkle
  `Checkpoint` commits to the whole resident window. See §2.

### Identity consensus (`doc/architecture/identity-protocol.md`, `identity/history/`)

This side is close to blockchain norms and well-built:

- Merkle-committed DAG of admission steps; longest-history fork choice (Nakamoto-ish).
- Pluggable PoW / PoS / PoA sybil resistance (`IdentityByWork/Stake/Authority`),
  selected per-identity via `block_impl`. **Default: PoA** (`AgreementImpl.POA`,
  `core/_python/system.py`; `idprocess.py` builds `IdentityByAuthority(..., 2)`).
  The default PoA is **reputation-tied** (BUGS.md §P2): authority weight auto-rises
  as a peer earns rank, a reputation feedback loop even in the default.
- Ed25519-signed votes; key/UUID collision rejection; group-key rotation.
- **PoS uses reputation as stake weight** (`reputation_fn` → stake): reputation
  already feeds back into identity admission.
- The Merkle layer provides **SPV-style light proofs** (`inclusion_proof` / `audit`).

### Summary

| | Identity | Reputation |
|---|---|---|
| Consensus | Merkle-DAG + PoW/PoS/PoA voting, longest-history | Leaderless Byzantine Multi-Paxos (BFT) |
| Scope | Group identity history | Per-group transaction chain(s) |
| Integrity | Merkle root + signatures + inclusion proofs | Paxos votes **+ hash-linked entries + quorum-signed Merkle checkpoints** |
| Persistence | DAG history | **Bounded + evicting** (lossy, by design) |
| State model | Membership DAG | **Derive-on-read** evidence log |

**identity ≈ a permissioned Merkle-DAG blockchain; reputation ≈ a per-group
BFT-replicated, bounded, derive-on-read evidence log that is now hash-linked,
Merkle-checkpointed, and slashing-capable.**

---

## 2. What was adopted from "typical" blockchains (implemented)

The reputation chain borrows three things from typical implementations. All three
are live in both the Python reference and the C twin, and are pinned by the
conformance corpus.

### 2.1 Hash-linking and Merkle checkpoints

The committed reputation chain is now tamper-evident on its own, and the catch-up
sub-protocol is *verifiable* rather than merely social:

- **Per-entry hash link (Phase 1).** When a `Transaction` goes bilateral and is
  appended, `TransactionHistory` sets `tx.prev_hash` to the running head digest and
  advances `_head_hash = tx.entry_hash()`. `entry_hash` is
  `blake2b(canonical_bytes ‖ prev_hash)` over a language-agnostic serialization
  (pipe-joined fields, `%.17g` floats, lowercase-hyphenated UUIDs). `verify_chain_links`
  rejects any segment whose adjacent `prev_hash`/`entry_hash` linkage is broken, and
  `catchup()` runs it before replaying a received segment, so a peer (or a corrupted
  transfer) cannot slip an altered committed entry past the sync. C twin:
  `transaction_entry_hash` / `tx_verify_chain_links` (byte-identical).

- **Ordered Merkle root (Phase 2).** `window_root()` computes the RFC 6962 Merkle
  Tree Hash over the resident window's `entry_hash` leaves (domain-separated `0x00`
  leaf / `0x01` node prefixes, which defeat the CVE-2012-2459 duplicate-subtree
  ambiguity). It is a pure function of the ordered leaf digests, so it is
  byte-identical to the C twin `transaction_window_root`. `inclusion_proof(index)` /
  `verify_inclusion()` (C: `transaction_window_proof` / `tx_merkle_verify`) give an
  `O(log n)` membership proof, the primitive a gateway parent uses to verify a
  child-group score without holding the whole child chain, and the anchor for the
  slash evidence of §2.3.

- **Quorum-signed checkpoints (Phase 2).** A node proposes a `Checkpoint` over its
  `window_root` (`checkpoint_propose`); a member co-signs (`checkpoint_sign`) **only
  if its own `window_root` matches**, so a finalized `SignedCheckpoint`
  (`checkpoint_final`) certifies that a quorum observed the same committed window: a
  lightweight finality gadget over the BFT chain, and the trust anchor for slash
  evidence. State: `_checkpoint` / `_checkpoint_sigs` / `_checkpoint_pending`. C twin:
  `REP_PROTO_CHECKPOINT_*` handlers + `checkpoint_root`/`checkpoint_sigs`/`checkpoint_pending`.

  Note: the red-black `MerkleTree` (identity side) is intentionally **not** reused for
  the reputation window. Its root depends on insertion order and rotations, which is
  the wrong primitive for an ordered sequence and infeasible to reproduce
  byte-identically in C; the dedicated ordered MTH above is.

### 2.2 Slashing-style fast penalties (the mq800 fix)

In PoS, *provable* misbehavior triggers an immediate, heavily-weighted penalty: it
does not wait for a slow average to drift. The reputation EMA (`CONSENSUS_EMA_HALF_LIFE`,
~20 txs) is the opposite, and could never react to a ~30-second rogue: the original
"mq800 stuck at 0.5" symptom.

A **slashing fast-path (Phase 0)** fixes this. A detector broadcasts a
`SlashAttestation` (`slash_propose`); members co-sign (`slash_sign`); on quorum the
detector broadcasts a `SignedSlash` (`slash_final`) and every node *floors* the
target's reputation at the top of `_consensus_reputation` / `_compute_reputation`,
bypassing the chain/EMA entirely. Reasons: `sustained_anomaly`, `peer_exclude`,
`invalid_tx`, `rehabilitate`. Rehabilitation deliberately lifts only the hard floor
(`_slashed`): the floored value persists in `self.reputations` as the cold-start
prior, so a rehabilitated peer must *earn* its standing back through new committed
transactions rather than snapping to neutral. C twin: `_apply_slash_locked` +
`REP_PROTO_SLASH_*` handlers. This is the principled "detection-driven floor": a
PoS-style penalty / PKI-style revocation, not a tuning tweak.

### 2.3 Evidence-gated slashing (Merkle proof verification)

A slash is only as trustworthy as its evidence. **Phase 3** ties the fast penalty to
the Merkle checkpoint: `SlashAttestation.evidence_ref = {task_id, leaf, proof, root}`
carries an inclusion proof of the offending committed transaction. Before co-signing
or applying an evidence-bearing slash, a node runs `_verify_slash_evidence`: the proof
must fold to a root that **this node has itself finalized as a checkpoint** (not a root
chosen by the accuser), via `verify_inclusion` / `tx_merkle_verify`. Malformed,
tampered, or mismatched evidence is refused. Evidence-free slashes keep the Phase 0
trust-the-detector fallback, so legacy flows are unaffected. `build_slash_evidence`
constructs evidence from the live window. Pinned by the `slash-evidence-verified` /
`slash-evidence-rejected` conformance scenarios.

### What was deliberately NOT adopted

Global immutable ledger, PoW, single canonical world-state, permanent history. The
domain (edge / space / DoD mesh: intermittent links, partitions, small-memory nodes)
is the textbook case where those are *wrong*. The bounded evicting chain,
group-scoping, and AP-leaning gossip are correct CAP choices. The bounded chain is a
**feature**, and its consequence (reputation history is lossy) is exactly why the
slashing fast-path for negative evidence exists, rather than relying on the chain to
"remember and average."

---

## 3. Layer-2+ for faster reputation distribution

**Framing caveat: L2 buys throughput and scale, not responsiveness.** Rollups /
optimistic settlement *add* finality latency (challenge windows) in exchange for
batching. So L2 is the right answer for "score 100 field peers through 2 gateway
hops," and the *wrong* answer for "make the rogue crater in 30 s" (that was the
slashing fast-path of §2.2, now implemented).

The scale and throughput directions:

- **Gateway reputation tree.** Child-group chains roll up into a parent.
  On the Merkle checkpoints of phase 2, a gateway can post a child chain's
  **quorum-signed `window_root`** to the parent, and the parent can verify a child
  score by inclusion proof (`verify_inclusion`) instead of holding child history: a
  validity-rollup in all but name. See `doc/architecture/gateway-reputation-tree.md`.
- **State channels (future).** Peer ⇄ coordinator could exchange signed score deltas
  off-chain and settle a checkpoint periodically, collapsing N decimated Paxos rounds
  into one commit. Fits the bilateral-transaction model; not built, and carried in
  [`ISSUES.md`](../../ISSUES.md) §10.4.
- **Anti-entropy gossip / CRDTs (future).** Push committed-tx digests, pull missing
  entries, CRDT-merge observations: converges faster than the top-3 sync and ties into
  the partition-recovery work.
- **ZK / verifiable-credential "reputation passports" (future).** The ZKP build path
  exists; a signed, verifiable attestation of standing (checkable without chain replay)
  would speed cross-group and post-partition warm-start.

---

## Synthesis

The reputation system stays non-blockchain where that is a deliberate CAP choice
(bounded, group-scoped, derive-on-read), while having adopted the three things from
"typical" implementations that genuinely help here:

1. **Hash-linking + Merkle checkpoints** (Phase 1-2): reputation history is now
   auditable and the catch-up sync is verifiable; checkpoints give inclusion proofs for
   the gateway rollup.
2. **A quorum-signed finality artifact** (`Checkpoint`/`SignedCheckpoint`) over the
   committed window.
3. **Slashing-style fast penalties** (Phase 0), hardened with **checkpoint-verified
   Merkle evidence** (Phase 3): the principled resolution of the mq800
   "short-lived rogue never drops off baseline" bug.

**L2 patterns** (Merkle-root gateway rollup, state channels, gossip/CRDT, ZK passports)
remain the path for *scale and propagation*; the rollup direction is unblocked by the
Phase 2 checkpoints, the rest are future work.

All of the above is implemented in both the Python reference and the C twin and is
enforced cross-language by the conformance corpus (hash-link, `window_root`, checkpoint,
and slash-evidence scenarios under `conformance/scenarios/reputation/`).
