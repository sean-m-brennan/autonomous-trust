# Tiered Transactions, Bootstrap Corpus, and Tier-Gated Access

This design answers a specific failure seen in the DoD demo: reputations sat
flat, because every TransactionScore contributed equally and there was no
baby-steps corpus for peers to "get acquainted" before consequential operations
began. Tier fields, weighted reputation, the bootstrap corpus
(`BootstrapWorker`), tier-gated negotiation, and Proof-of-Trust threshold
filtering are all specified here and mirrored in both runtimes with symmetric
conformance pins.
This document specifies a tiered-transaction mechanism, an AT-core
bootstrap corpus, and tier-gated capability access: closing the gap
between AT's TFT-to-cooperation premise and what the code actually
supports today.

## 1. Terminology: rank vs trust tier

The presentation at `doc/tekfive/presentation/index.html` describes four
levels of access (Network presence → Communication → Services →
Data-sharing). The code in `reputation/repprocess.py:52-57` defines a
`RANK_TIERS` table mapping reputation 0..1 → integer 0..4 and publishes
the result as `peer._rank`. Reading the code together with the
presentation, it is easy to assume "rank" means "trust level". **It
does not.**

In AT, **rank is a network-topology concept**:

> Rank indicates one-hop reachability via gateways. A node of rank 1 can
> send a message via a gateway to a node of rank 2. Gateways act as a
> means of building network trees, and rank indicates tree level. Leaves
> (rank 1) can send messages up the tree but not up-then-down to reach
> otherwise-unreachable rank-1 nodes.

A gateway is, by definition, a more capable node: better connectivity,
more compute, longer uptime, more available bandwidth. Rank reflects
*what a peer can do at the network layer*, not *how much we believe its
behavior*. The existing reputation-to-`peer._rank` pathway therefore
misuses the name. This doc renames it to **trust tier**.

The two axes are independent:

| Axis | Source | What it gates | Algorithm class |
|---|---|---|---|
| **Rank** (`peer._rank`) | Static config in `identity.json` at deployment | Message routing, partition-leader selection, Proof-of-Authority votes | `AgreementByAuthority` (PoA) |
| **Trust tier** (`peer._tier`) | Reputation-derived via `TIER_FLOORS` | Capability access, transaction weighting, Proof-of-Trust votes | `AgreementByTrust` (PoT), new |

A rank-1 leaf node can hold trust tier 4 (fully trusted, accessible
through its gateway). A rank-3 gateway can hold trust tier 0 (in the
network topology, no behavioral track record yet). Both are valid; the
two axes do not interact except where a domain policy chooses to make
them.

This document is exclusively about the **trust-tier** axis. Rank is
mentioned only to disambiguate. The topology rank source and any
dynamic rank computation are out of scope here (the immediate fix
is static config in `identity.json`; dynamic adaptation belongs to a
separate design).

## 2. Problem

AT's nominal trust path is: peers interact, transactions accumulate,
reputation rises through `_pure_reputation` (weighted average) above the
hysteresis band, and full cooperation kicks in. Before that, CTFT
governs (`_contrite_tit_for_tat`). This works only if there is a
**stream of bilateral transactions** to score against. Today, three
things break that premise:

1. **No bootstrap corpus.** AT ships no built-in capabilities that
   peers can exercise to seed reputation. Every domain has to invent
   its own. In the DoD demo, the only TS-producing flow is sensor
   reporting, which is also the load-bearing consequential operation,
   so there is no separation between "build trust" and "act on trust".
2. **Transactions are equally weighted.** A successful delivery of a
   trivial heartbeat contributes identically to a successful delivery
   of mission-critical sensor fusion. There is no notion of stakes.
   This contradicts the canonical TFT intuition: meaningful
   transactions (where defection is materially costly) should move
   reputation faster than trivial ones.
3. **Tier-gating is implicit.** The negotiation layer has one coarse
   gate (`peer_level == 0 → refuse`) and that is the entirety of
   trust-based access control. The four access tiers in the slides
   exist only as a conceptual framing; the code has no mechanism to
   honor them.

The explicit TODO at `reputation/repprocess.py:576` (*"can we use the
transaction memory to do better than CTFT before reputation kicks
in?"*) is the same gap, surfaced from inside the reputation code.

## 3. Goals & non-goals

**Goals.**

- Define an extensible corpus of low-stakes, AT-core transactions
  every peer can engage in immediately after admission.
- Make transactions weighted by their consequence: meaningful
  operations move reputation faster than trivial ones.
- Provide a deterministic mechanism for promoting a peer through
  trust tiers and revoking access on demotion (both directions
  symmetric).
- Allow each domain (DoD demo, multi-agency, future) to declare its
  own tier-to-capability mapping without forking the core.
- Python↔C parity from day one. No skewed-only-on-one-side trust math.
- No change to paxos / CTFT semantics. The bilateral pairing invariant
  in `Transaction.add` and `TransactionHistory.update` stays as-is.

**Non-goals.**

- Redefining rank or deriving it from observed topology. That work,
  if needed, is a separate design doc.
- Cross-domain tier portability (a peer in two trust ladders
  simultaneously). Not in v1.
- ZKP-strength proof of execution for the bootstrap corpus. The v1
  sketch uses signed nonces; harder integrity proofs are follow-up.

## 4. Data model

### 4.1 Capability: tier metadata

Extend `Capability` (`src/autonomous-trust/autonomous_trust/core/_python/capabilities.py`)
with two fields, both backwards-compatible:

```python
class Capability(Configuration):
    def __init__(self, name, function=None, arg_names=None, keywords=None,
                 required_tier: int = 0, transaction_weight: int = 1):
        ...
        self.required_tier = required_tier
        self.transaction_weight = transaction_weight
```

- `required_tier` (default 0): the minimum `peer._tier` a peer must
  hold to be invited to perform this capability, and the minimum the
  inviter must hold to be accepted. Tier 0 means "any admitted peer".
- `transaction_weight` (default 1): the multiplier applied to TS
  scores from this capability in `_pure_reputation`. Default
  schedule: `1, 2, 4, 8` for tiers 1..4 (tunable). Tier-0 transactions
  carry weight 1: they accumulate slowly but reliably as the
  bootstrap signal.

The protobuf wire format
(`src/autonomous-trust/autonomous_trust/core/protobuf/processes/capabilities.proto`)
gets two new optional fields. `sync_to_message` / `sync_from_message`
plumb them through. Existing peers that don't carry the new fields
default to tier 0 / weight 1: they remain interoperable.

### 4.2 Peer: trust tier attribute

`peer._tier: int` (default 0) is where the reputation-derived value lives;
`peer._rank` does not hold it. The rename is mechanical:

- `RANK_TIERS` (`repprocess.py:52`) → `TIER_FLOORS`. Values unchanged
  (`0.50→1, 0.65→2, 0.80→3, 0.90→4`).
- `_rank_tier` → `_trust_tier`.
- `_publish_rank_change` → `_publish_tier_change`. Cache map
  `peer_ranks` → `peer_tiers`.
- `IdentityProtocol.rank_update` → `tier_update`. Add new
  `IdentityProtocol.tier_lost` (see §7).
- `handle_rank_update` → `handle_tier_update` (mutates `peer._tier`).

Tier 0 corresponds to "admitted only: Network presence" in the slides.
Tiers 1-4 map to Communication, Services, Data-sharing (read), and
Data-sharing (write) respectively.

### 4.3 Topology rank: what's left

After the rename, `peer._rank` keeps its topology semantic. It is
populated from `identity.json` at startup (`Identity.__init__` already
accepts `_rank` as a constructor arg). The reputation process no longer
mutates it. Existing readers (`_select_partition_leader`,
`AgreementByAuthority._count_vote`, `_authority_effective_threshold`)
continue to read `peer._rank` and are unaffected, except that the value
is now static for the life of the process unless a deployment-side
change re-issues the identity. Dynamic topology adaptation is out of scope.

### 4.4 TransactionScore: capability linkage

To weight a TS in `_pure_reputation`, the reputation process needs to
know which capability produced it. Today, `TransactionScore(task_id,
score)` carries no such handle. Three options:

- **(a) Add a `capability_name: str` field to `TransactionScore`.**
  Smallest workable change. Single string on the wire. The capability's
  `transaction_weight` is then looked up locally at scoring time.
- **(b) Look up by `task_id` via the negotiation task tracker.**
  Avoids wire changes but creates a tight reputation↔negotiation
  coupling and a synchronisation hazard if the tracker hasn't yet
  recorded the task on the scoring node.
- **(c) Cache the `transaction_weight` itself on the TS.**
  Even smaller than (a) but loses the capability identity, which we
  may want for future auditing / per-capability consensus aggregation.

This document chooses **(a)**. The wire-format delta is one optional
string; the protobuf bump is the same one that adds the Capability
tier fields, so peers either understand both or neither.

## 5. Weighting math

Two consumers care about the weight:

### 5.1 `_pure_reputation` (`repprocess.py:540-ish`)

Current form (paraphrased):

```python
def _pure_reputation(self, peer):
    total, valid = 0.0, 0
    for tx in self.history.by_peer(peer.uuid):
        reporter_score = ...
        if reporter_score is None: continue
        # peer's own score in this bilateral transaction
        peer_score = tx.p1_score if tx.p1_id == peer.uuid else tx.p2_score
        total += reporter_score * peer_score
        valid += 1
    if valid == 0: return 0.2  # PREREP_NEUTRAL
    return total / valid
```

New form, weighted:

```python
def _pure_reputation(self, peer):
    total, total_w = 0.0, 0
    for tx in self.history.by_peer(peer.uuid):
        reporter_score = ...
        if reporter_score is None: continue
        peer_score = tx.p1_score if tx.p1_id == peer.uuid else tx.p2_score
        w = self._tx_weight(tx)  # transaction_weight from cached capability
        total += reporter_score * peer_score * w
        total_w += w
    if total_w == 0: return 0.2  # PREREP_NEUTRAL
    return total / total_w
```

`_tx_weight(tx)` returns the `transaction_weight` of the capability
named on the originating TransactionScore. If the capability is
unknown locally, weight falls back to 1 (the conservative default:
matches a tier-0 baseline). CTFT is unchanged.

### 5.2 `_consensus_reputation` (EMA channel for dashboard)

Same multiplier, applied at the per-update step. The EMA half-life
(`CONSENSUS_EMA_HALF_LIFE = 20`) is interpreted as "half-life in
*weight units*", not transactions. A single tier-4 hit moves the EMA
8× faster than a tier-1 hit.

### 5.3 Conformance pin

New scenario `reputation/pure-reputation-weighted-by-tier.yaml` pins
the math: identical inputs at weight 1 vs weight 4 produce the
expected score differential. This is the single scenario that catches
any future regression in the weighted aggregator.

**Parity:** weight-aware on both adapters and pinned by conformance.

* Python `_pure_reputation` and `_consensus_reputation` weight each tx
  by the cached `transaction_weight`; the cache is populated at
  `_start_paxos` and `handle_transaction` and bounded at
  `2 × TransactionHistory.DEFAULT_MAX_CHAIN_LEN`.
* C `reputation_pure` and `reputation_consensus` accept a `task_weights`
  map argument and apply the same per-tx weighting; `rep_proc.c` threads
  `&rep_state.task_weights` through on the `rep_req` handler's pure
  branch (rep_proc.c:1388).
* C unit test `test_reputation_pure_weighted_by_task` pins the math
  in-process (`src/c/test/reputation3_test.c`).
* Conformance scenario `reputation/pure-reputation-weighted-by-tier.yaml`
  runs the rep_req path end-to-end on both adapters and asserts the
  weighted aggregator result (`0.4*1 + 0.9*4) / 5 = 0.8`); an
  unweighted regression would produce `(0.4 + 0.9) / 2 = 0.65` and
  trip the 1e-3 tolerance.

The conformance pin required two follow-up fixes to land: (a) widening
Python `_compute_reputation` / `_pure_reputation` / `_contrite_tit_for_tat`
to accept a bare uuid string from the rep_req wire path (the canonical
`{peer_uuid: <str>, ...}` form parses to a string, not a UUID/Peer);
(b) extending the C `rep_proc_priv.h` test surface and the C reputation
adapter with the install/get hooks (`reputation_install_tx_pair`,
`reputation_install_peer_reputation`, `reputation_install_coop_mode`,
`reputation_get_peer_reputation`) and the corresponding fixture keys
(`tx_history`, `reputations`, `task_weights`, `coop_mode`) plus
`expected_state.reputation_of`. The Python adapter mirrors these.

## 6. Bootstrap corpus

AT ships three tier-0 capabilities under the `at.*` namespace. They
are always available on every peer immediately after admission; they
exist to give the reputation algorithm something to score.

### 6.1 `at.handshake`

Peer A picks peer B from the cohort, sends a 32-byte challenge nonce.
B signs `H(nonce | B.identity.uuid)` with its identity key and returns
the signature. A verifies; on success A submits
`TransactionScore(task_id, 0.9, capability_name="at.handshake")`; on
failure 0.1. B independently submits the bilateral pair from its side.

Defection surface: B can refuse to respond (A scores 0.1), respond
with a wrong signature (A scores 0.1), or respond with the wrong
identity (A scores 0.1).

### 6.2 `at.time-attest`

Peer A asks peer B for `B.now()`. A scores against its own clock with
a tolerance (default ±200 ms: well above network RTT noise, well
below "the peer is lying"). Within tolerance → 0.9; outside → 0.5;
unreachable / timeout → 0.1.

Defection surface: B can be slow, lie about its clock (deliberately
or due to drift), or refuse. The tolerance band makes occasional
honest drift forgivable; sustained skew is detected.

### 6.3 `at.echo-challenge`

Peer A sends a small random payload (signed by A); B echoes it
verbatim, prefixing its own signature. A verifies both signatures and
that the payload bytes match. This is the canonical "did you actually
do what I asked, or did you tamper" transaction. Score 0.9 / 0.1.

Defection surface: B can drop bits, substitute bytes, or refuse to
echo. The defection is non-trivial to commit accidentally: a
malicious modification has to survive the signature check, which
forces it to be a real attack rather than a transmission glitch.

### 6.4 `BootstrapWorker`

A new core Worker, registered by default in `AutonomousTrust.__init__`.
On admission, it begins a ~30 s window of random pairwise interactions
across all admitted peers, picking capability uniformly from the three
above. Configuration:

- `AT_BOOTSTRAP_DURATION_SEC` (default 30)
- `AT_BOOTSTRAP_PAIRS` (default 20: per-peer interactions in the
  window)
- `AT_BOOTSTRAP_DISABLED=1` skips the bootstrap entirely (for unit
  tests that want a quiet network)

After the window closes, the worker stops scheduling new pairs;
in-flight transactions complete normally. Reputation has, by then,
accumulated enough bilateral entries that the rank ladder begins
moving peers off tier 0.

### 6.5 Conformance pin

The contract (freshly-admitted peer triggers the worker, picks a
partner, and runs at least one round of each of the three
capabilities) is pinned by the unit test
`tests/a_unit/test_bootstrap_worker.py::TestBootstrapCoverage::test_all_three_caps_exercised_over_a_run`
under a fixed `AT_BOOTSTRAP_SEED` **and**, since 2026-06-03, by the
cross-language conformance scenario
`bootstrap/bootstrap-corpus-runs-on-admission.yaml`. A new `bootstrap`
conformance protocol + adapter was added on both harnesses; the observable
is the RNG-agnostic coverage set (`bootstrap_caps_fired == 3`,
`pairs_issued == 30`), so Python's `random.Random` and C's splitmix64 need
not produce identical selection sequences. Pins symmetrically (137/137 each
side, 0 asymmetric).

**What each runtime carries:**

* All three at.* capabilities are defined and auto-registered on every
  Python `AutonomousTrust` instance (`bootstrap_capabilities.py`;
  auto-call in `automate.py:__init__` gated on `AT_BOOTSTRAP_DISABLED`).
  Server-side functions + client-side verifiers ship as v1 sketches:
  no signed-nonce / ZKP-echo strength yet (see §12).
* `BootstrapWorker` (`bootstrap_worker.py`) is a real Process subclass
  auto-registered in `AutonomousTrust.__init__` (`automate.py`, same
  AT_BOOTSTRAP_DISABLED gate). It opens a window when peers first
  appear, paces Task invitations over `AT_BOOTSTRAP_DURATION_SEC`
  (default 30 s) up to `AT_BOOTSTRAP_PAIRS` (default 20), and stops
  scheduling when either limit is hit. `AT_BOOTSTRAP_SEED` is honored
  so tests and scenarios get deterministic sequences.
* C parity: `src/c/autonomous_trust/bootstrap/`
  (`bootstrap_capabilities.{c,h}`, the 3 at.* server fns + verifiers with
  matching scoring, name registry, `register_bootstrap_capabilities`; and
  `bootstrap_worker.{c,h}`, seeded splitmix64 selection, paced window,
  counts-by-cap, env handling). Unit tests `bootstrap_capabilities_test` +
  `bootstrap_worker_test` (C suite 77/77). The conformance pin runs the C
  worker via the `bootstrap` adapter, symmetric with Python (§6.5).

## 7. Tier-up and tier-down transitions

### 7.1 Promotion (tier-up)

The existing publication mechanism handles this with only a rename.
`ReputationProcess._publish_tier_change` (formerly
`_publish_rank_change`) fires whenever the score crosses a
`TIER_FLOORS` boundary; the message
`IdentityProtocol.tier_update(peer_uuid, new_tier)` lands on the
identity queue; `handle_tier_update` mutates `peer._tier`. No new
plumbing.

The new behavioral piece is in negotiation:
`NegotiationProcess.handle_invite` gates on
`sender_peer._tier >= cap.required_tier`. The existing coarse gate
(`sender_level == 0 → refuse`) becomes `sender_level <
cap.required_tier → refuse`, with `sender_level` now meaning
`sender_peer._tier`. The existing `peer_levels` test fixture
(`neg_proc.c:81-90, 206-215`) is removed, production code reads the
real `peer._tier`.

Conformance pin:
`negotiation/invite-refuse-below-required-tier.yaml`. The existing
`invite-refuse-low-rep.yaml` stays valid because tier 0 still refuses
any required-tier > 0.

### 7.2 Demotion (tier-down): task cancellation

Demotion is more interesting because of in-flight tasks. When a peer's
tier drops below the required tier of a capability that peer is
currently executing on someone else's behalf (or whose results
someone else is currently waiting on), that work must be cancelled,
not allowed to complete and silently exfiltrate data.

Mechanism:

1. `_publish_tier_change` detects `new_tier < old_tier`.
2. It emits a new local IPC message
   `IdentityProtocol.tier_lost(peer_uuid, new_tier)` onto the
   negotiation queue, in addition to the normal `tier_update`.
3. `NegotiationProcess.handle_tier_lost` walks
   `my_tasks` + `JobQueue`:
   - For every task where the affected peer is a participant AND
     `task.capability.required_tier > new_tier`, the task is
     cancelled.
   - Cancellation: remove from `JobQueue`, emit
     `TaskStatus(cancelled)` to the originator, send `nack` to the
     other participants, delete the `my_tasks` entry so further
     `report_results` for this task are rejected.
4. The cancellation event is recorded for the dashboard / event log
   path. In a recorded run, it appears alongside the `ANOMALY` /
   `COMPROMISE_DETECT` markers that triggered the tier loss in the
   first place.

Symmetry with promotion is critical: the same `peer._tier` mutation
that opens capability access on the way up closes it on the way
down, in the same code path, in the same process. There is no
asymmetric "stale cached access" surface.

Conformance pin: `negotiation/tier-loss-cancels-running-task.yaml`.

### 7.3 Hysteresis

`COOP_ENTER = 0.55` / `COOP_EXIT = 0.45` (existing) governs CTFT ↔
pure-reputation dispatch. Tier transitions also need hysteresis, or a
peer hovering near a tier boundary will flap. The simplest robust
choice is to apply a fixed ε of 0.02 to each `TIER_FLOORS` floor on
the way down: promotion happens at the floor, demotion happens at
floor − 0.02. This keeps the floor-as-published value stable for
documentation and adds a quiet 2-point buffer in the implementation.

### 7.4 Communication cut-off (exclusion): below tier 0

The trust tiers sit on a `[0, 1]` scale (no negatives). Below tier 0 there is
one further threshold that is **not a tier**: the communication cut-off
`COMM_CUTOFF = 0.1` (`AT_REP_COMM_CUTOFF`). A peer whose reputation falls below
it is **excluded**: dropped at the network layer, not merely demoted to tier 0.

Because 0.1 lies *inside* tier 0 (`[0, 0.5)`), a 0.15 → 0.05 move is a
tier-0 → tier-0 no-op for the ladder yet must still exclude the peer.
`_publish_tier_change` therefore checks the cut-off crossing **before** its
tier early-return, updating the exclusion set and emitting a `Network.exclude` /
`Network.readmit` control message to the network process. Recovery is
explicit-only (a `REASON_REHABILITATE` slash-lift restores the score to
`PREREP_NEUTRAL = 0.2` and re-admits), and the excluded state persists across a
restart. See [Reputation § Communication cut-off enforcement](reputation.md#communication-cut-off-enforcement)
for the full mechanism. Note the neutral / cold-start reputation is now
`0.2` (`PREREP_NEUTRAL`, `AT_REP_NEUTRAL`), a small leeway above the cut-off, so
the slash floor can sit at `0.0`.

## 8. Domain specification: trustLadder YAML

Each scenario declares a `trust_ladder.yaml` alongside its
`scenario.yaml`. The loader maps capability names to required tier
and transaction weight, and parameterises the bootstrap worker.
Defaults (everything tier 0, weight 1, bootstrap on) apply when the
file is absent.

```yaml
# examples/dod_mission/trust_ladder.yaml
version: 1
bootstrap:
  duration_sec: 30
  pairs: 20
capabilities:
  at.handshake:       { required_tier: 0, transaction_weight: 1 }
  at.time-attest:     { required_tier: 0, transaction_weight: 1 }
  at.echo-challenge:  { required_tier: 0, transaction_weight: 1 }
  dod.network-presence: { required_tier: 1, transaction_weight: 2 }
  dod.sensor-report:    { required_tier: 2, transaction_weight: 4 }
  dod.fusion-validate:  { required_tier: 3, transaction_weight: 8 }
  dod.command-issue:    { required_tier: 4, transaction_weight: 8 }
tier_demotion_epsilon: 0.02
```

Capability tier and weight come from this YAML at registration time
(in the participant / coordinator startup path). Domain code never
hard-codes either. A new demo adds its own
`<example>/trust_ladder.yaml` and the rest of the mechanism applies
automatically. The loader is Python-side (`core/_python/trust_ladder.py`);
the C runtime registers capabilities in code, which is the one asymmetry
in §9's mirror and is tracked in [`ISSUES.md`](../../ISSUES.md).

## 9. Python↔C parity

Every Python change has a C mirror:

| Python | C |
|---|---|
| `Capability.required_tier`, `transaction_weight` | `capability_t::required_tier`, `transaction_weight` in `capabilities.h` |
| `TIER_FLOORS`, `_trust_tier` | `TIER_FLOORS[]`, `_trust_tier` in `rep_proc.c` |
| `_publish_tier_change`, `tier_update` | identical names in `rep_proc.c` / `id_proc.c` |
| `peer._tier` | `peer_t::tier` |
| `handle_tier_lost`, task cancellation | `handle_tier_lost` in `neg_proc.c`, walks the same `my_tasks` map |
| `BootstrapWorker` | `bootstrap_worker_t` in `src/c/autonomous_trust/bootstrap/` |
| `AgreementByTrust` (PoT), new | `_trust_count_vote` and friends added to `agreement.c` alongside the existing `_authority_count_vote` |
| `at.handshake`, `at.time-attest`, `at.echo-challenge` | identical C implementations registered by the C runtime's bootstrap |

The existing C `peer_levels` map (`neg_proc.c:81-90, 206-215`) was
introduced solely as a test fixture for `invite-refuse-low-rep`. It
disappears: production code reads `peer._tier` directly.

## 10. Proof of trust (PoT) agreement class

`AgreementByAuthority` (PoA) reads `peer._rank` and is the right shape
for capability-gated decisions ("only gateways can vote on this"). It
stays as-is.

`AgreementByTrust` (PoT) is a parallel class that reads `peer._tier`.
Use it when an agreement's correctness depends on behavioral track
record rather than inherent node capability: e.g., authorising a
data-sharing operation where any well-behaved peer should be eligible
to vote, regardless of whether it's a gateway. The class lives in
`algorithms/trust.py` and mirrors `authority.py` in shape, differing
only in the attribute it reads and the threshold field name
(`threshold_tier` vs `threshold_rank`). Conformance pin:
`agreement/pot-threshold-tier-filter.yaml`.

PoT does not replace PoA: they coexist, and any given Agreement uses
one or the other based on what the consequence depends on.

## 11. Conformance impact

New scenarios:

- `bootstrap/bootstrap-corpus-runs-on-admission.yaml`
- `negotiation/invite-refuse-below-required-tier.yaml`
- `negotiation/tier-loss-cancels-running-task.yaml`
- `reputation/pure-reputation-weighted-by-tier.yaml`
- `agreement/pot-threshold-tier-filter.yaml`

Existing scenarios that survive unchanged:

- `negotiation/invite-refuse-low-rep.yaml`: tier 0 still refuses any
  required-tier > 0, which is the same observable behavior.
- `agreement/poa-threshold-rank-filter.yaml` and the rest of the POA
  family: PoA semantics unchanged.

Existing scenarios that need an update:

- Any scenario that asserts a specific `peer_ranks` or `rank_update`
  in its trace must rename to `peer_tiers` / `tier_update`. This is
  mechanical.

## 12. Open / out-of-scope

- **Capability namespace versioning.** `at.handshake-v1` vs
  `at.handshake`: versioning would let the bootstrap corpus evolve
  without breaking older peers. Recommended yes, but the v1 names ship
  without a version suffix and the migration is a follow-up.
- **ZKP-strength `at.echo-challenge`.** The current sketch uses signed
  nonces, which is sufficient for v1 but doesn't preclude all forms of
  collusion. Stronger constructions are a follow-up.
- **Cross-domain tier portability.** A peer participating in two
  trust ladders simultaneously (different `trust_ladder.yaml` per
  group) is undefined behavior in v1.
- **Topology rank source.** Statically configured in `identity.json`
  for v1. Dynamic adaptation (observe paths, downgrade on gateway
  loss) is not addressed here.
- **Per-tier consensus aggregation.** A peer's reputation could be
  computed separately at each tier ("trusted at tier 1 with score
  0.92, untrusted at tier 3 with score 0.41"). The single-score
  model in this doc collapses that to one number. Per-tier scoring
  is a strictly larger redesign and is not addressed here.

## 13. Related references

- `doc/architecture/reputation.md`: the paxos protocol and CTFT
  semantics this doc rides on.
- `doc/architecture/negotiation.md`: the task lifecycle that
  produces TransactionScores.
- `doc/architecture/partition-recovery.md`: template for this doc's
  style; also the prior example of a same-shape extension to
  identity-side bookkeeping.
- `doc/tekfive/presentation/index.html`: the four access categories
  this doc operationalises.

[Reputation Consensus < ](reputation.md) | [Negotiation > ](negotiation.md)
