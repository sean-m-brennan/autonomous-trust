# Tree-structured reputation blockchain for gateway nodes

> Status: Design (approved 2026-05-29). Implementation in progress.

## Context

**Problem (the reputation-roster gap).** In the dod_mission demo the coordinator's reputations
panel only ever scores the gateway it directly peers with (rq86-1), never the squad/microdrones —
even though their telemetry reaches the map. The root cause is structural, not a bug:

- Each node holds **one** linear reputation chain (`self.history`, `repprocess.py`) scoped to
  **one** group (`self.group`, reassigned never extended).
- Consensus reputation (`_consensus_reputation`, `repprocess.py`) is a **pure EMA over that one
  chain** — it can only score a peer whose bilateral transactions are *in that chain*.
- The field peers live in a **different group's chain** that nothing replicates upward, so the
  coordinator's chain never contains them → they can't be scored. The panel falls back to the
  "forming…" placeholder for every unscored peer.

**Topology (this scenario).** A 2-level cohort tree:

```
command (coordinator, top)
  ├─ rq86-1  (rank 2 gateway)
  └─ rq86-2  (rank 2 gateway)
        └─ field group  (ONE shared rank-1 group: squad×4 + microdrone×4)
```

squad + microdrones share **one** group so they interact directly. Both rq86 gateways are members
of **both** the command group and the field group (N=1 child group here; the design stays general
for N children and deeper trees).

**Goal.** Gateways (rank > 1) become **multi-group members**, maintain a **tree of reputation
chains** (one per group they belong to), and answer a `consensus_rep_req` with the **full recursive
subtree roster**. The coordinator querying rq86-1 then gets back rq86-1 + every field peer in one
reply — closing the gap without papering it with default 0.5 scores. Gateways also **continue to
blind-relay** opaque traffic for groups they don't hold keys to (preserved, not removed).

## Key decisions

1. **Multi-group membership** — `self.group` stays the primary/parent group; add `child_groups`
   (+ child chains) for cohorts the node gateways. Additive: rank-1 leaves keep empty maps and
   behave **exactly** as today.
2. **Full recursive subtree** reply (gateway + children + grandchildren, flattened).
3. **Runtime rank-based discovery** of the tree (`peer._rank` vs `self.identity._rank`).
4. squad + microdrones = one field group.

**Relay vs participate — both supported, orthogonal.** They key on whether the gateway holds the
destination group's key:

| Destination group | Holds key? | Behavior |
|---|---|---|
| A group the gateway is a **member** of (command, field) | yes | decrypt → deliver → **participate** (build reputation, run that group's Paxos) |
| A group the gateway only **transits** | no | **relay opaque** (blind forward, no decryption) |
| A member-group that **spans two segments** | yes | **both** — decrypt locally *and* relay onward |

- *Participate* is **net-new** work (Python identity/network/reputation).
- *Relay* lives only in the **C** layer (`net_proc.c` `AT_NET_GROUP_FORWARD`) and is **preserved by
  not touching it**. The pure-Python demo runs all peers on one shared broadcast channel, so relay
  isn't exercised there — what a node sees is decided purely by which group key it holds.

**Runtime path / C-twin.** The demo runs **pure-Python** reputation + network (the `_native`
backend re-exports the Python `ReputationProcess`; demo containers are Python). So the Python
changes need **no** lockstep with C at runtime; C-twin + `scripts/test-conformance.sh` byte-parity
is a **follow-up**.

## Design (phased)

### Phase 0 — Multi-group key holding (identity + IPC + network)

**Data model (additive).**
- `identity/idprocess.py`: add `self.child_groups: dict[str,Group] = {}`,
  `self.parent_gateway: str|None = None`.
- `protocol.py`: add `self.child_groups: dict[str,Group] = {}`.
- `identity/group.py`: `Group` reused **unchanged** per cohort — each holds its own `_encryptor`.

**Runtime rank discovery (reuse existing admission/welcoming handlers — no new wire msgs).**
With `R_self = getattr(self.identity,'_rank',0)`, `R_peer = getattr(peer,'_rank',0)`:
- `R_peer < R_self` and `R_self > 1` → peer's cohort is a **child**; gateway holds that group's key
  as a `child_group` (mint it if gateway-originated, else adopt the arriving group).
- `R_peer > R_self` → record `self.parent_gateway = peer.uuid` (newest, mirroring the
  `_select_partition_leader` tiebreak).
- `R_peer == R_self` → same cohort (today's path).
- Triggers: `_peer_accepted`/`_add_peer`, `choose_group`/`receive_history`, `welcoming_committee`.
- **Overwrite-prevention**: at the group-assignment sites in `choose_group`/`_merge_to_mesh`,
  classify the arriving group — a child-classified group goes to `child_groups`, **never** to
  `self.group` or `_merge_to_mesh`.

**Cross-process propagation.** The single-`Group` fan-out (`protocol.run_message_handlers`,
`processes.update`) clobbers the one slot. Add a `ChildGroupSet` IPC carrier + a
`_record_child_groups(queues)` helper (sibling to `_record_group`); add one
`isinstance(message, ChildGroupSet)` branch in `run_message_handlers` that sets
`self.child_groups`. The existing `Group` branch is untouched.

**Network layer — multi-key receive (the linchpin for the demo).** `network/netprocess.py` today
checks one group (`accept_group_message`, group drain, `self.group.decrypt`). Change the
group-channel drain to: find the group in `{self.group} ∪ self.child_groups.values()` whose
`addresses` contains `from_addr`, and decrypt with **that** group's key. Keep the
`from_addr in self.group.addresses → self.group.decrypt` path as the first check so leaves
(empty `child_groups`) are byte-identical. Do **not** add relay to Python; do **not** touch C
`net_proc.c`.

### Phase 1 — Reputation chain tree (`reputation/repprocess.py`)

- Keep `self.history` (primary chain). Add `self.child_histories: dict[str,TransactionHistory] = {}`
  keyed by group-uuid, plus `self.child_groups` (fed by the same `ChildGroupSet` carrier). Reuse
  `TransactionHistory` unchanged per chain.
- Helper `_chain_for_group(group_uuid)` → matching child chain, **defaulting to `self.history`**
  (back-compat: unknown/None → primary).
- **Route commits to the right chain.** Stamp the originating `group_uuid` into the Paxos payloads
  (`request`/`transaction`/`committed`); readers parse it with a **length-tolerant unpack**
  (`x[3] if len(x)>3 else None`) so legacy tuples resolve to the primary chain. Route
  `self.history.update(...)` through `self._chain_for_group(group_uuid).update(...)`.
- **Per-group quorum.** `len(self.peers.all)//2` conflates groups once a gateway joins two. Add
  `_quorum_for_group(group_uuid)` sized by that group's membership (derive members by filtering
  peers against the group's `_address_map` — see R1).
- **Catch-up routing.** Thread `group_uuid` through `outdated`/`update` so a child chain catches up
  independently; default to primary when absent.

### Phase 2 — Recursive subtree consensus reply

- `_consensus_reputation(peer_uuid, chain=None)` — add optional `chain`, default `self.history`.
  Pure per chain. The local-trust family (`_compute_reputation`/`_pure_reputation`/
  `_contrite_tit_for_tat`) stays on `self.history`, untouched.
- New `_subtree_roster(gateway_uuid) -> list[Reputation]`: own score vs primary chain, plus a
  `Reputation` for every uuid in each child chain (`list(chain._peer_mapping.keys())`) scored vs
  that child chain. **Demo (depth 2):** returns gateway + all field peers — complete.
  **Grandchildren** (a child that is itself a gateway): **deferred** — recursive forward +
  aggregate with timeout; for now cap at direct children (correct for this scenario).
- `_compute_consensus_reputation` appends the **roster list** to `self.requested_reps`.
- **Polymorphic `rep_resp`** (`forward_reputation`): a list payload serializes as a JSON array of
  `Reputation`; a single `Reputation` (and 1-element leaf roster) stays a bare object →
  byte-identical for leaves. `automate.py` rep_resp handler wraps
  `reps = rep if isinstance(rep,list) else [rep]` (also handles the JSON-array-string case) and
  runs the existing per-`Reputation` body in a loop.
- **Coordinator** `_query_reputations` (`examples/dod_mission/coordinator.py`): **no change
  required** — querying the gateways now returns the whole field roster.

### Phase 3 — Deferred / follow-up
- C-twin parity for the new `group_uuid` payload field + conformance corpus.
- Persistence of `child_groups` / child chains across gateway restart (today only primary persists).
- Partition-recovery reconciliation (see R2).
- Grandchild recursive aggregation (depth > 2).

## Critical files
- `src/autonomous-trust/autonomous_trust/core/_python/identity/idprocess.py` — data model, rank
  discovery, child-group classification/routing.
- `src/autonomous-trust/autonomous_trust/core/_python/protocol.py` — `ChildGroupSet` propagation.
- `src/autonomous-trust/autonomous_trust/core/_python/network/netprocess.py` — multi-key receive.
- `src/autonomous-trust/autonomous_trust/core/_python/reputation/repprocess.py` — chain tree,
  per-group routing/quorum, `_subtree_roster`, polymorphic reply.
- `src/autonomous-trust/autonomous_trust/core/_python/reputation/reputation.py` — reuse
  `TransactionHistory`/`Reputation` (no structural change expected).
- `src/autonomous-trust/autonomous_trust/core/_python/automate.py` — iterate roster replies.
- `examples/dod_mission/coordinator.py` — verify panel; loop unchanged.
- Reuse `_reputations_view()` / `_render_reputations` (already render "forming…" placeholders) —
  the roster now fills those in.

## Risks / open items
- **R1 (correctness, Phase 1):** authoritative per-group membership for `_quorum_for_group`.
  `Group` carries `_address_map`, not a uuid roster; `self.peers.all` conflates groups. Likely
  derive members by filtering peers against each group's `_address_map`.
- **R2:** multi-group gateways re-enter partition-recovery logic they were excluded from (gateways
  were "zero groups"). Gate any partition signal on "not in primary **and** not in any child group"
  before firing; reconcile with the C `is_gateway` exclusion. (Current Python netprocess drops
  unknown-sender frames silently — no partition signal — so demo risk is low; flag for C/production.)
- **R3:** child-group `group_update` must not enter the primary convergence/tiebreak path; route by
  uuid.
- **R4:** C-twin payload parity (Phase 3).

## Verification
1. **Unit:** `_chain_for_group` routing; `_consensus_reputation(chain=...)` purity; `_subtree_roster`
   returns gateway + all field peers from a seeded field chain; polymorphic `rep_resp` round-trips
   a roster and a bare `Reputation`; leaf node still emits a bare `Reputation`.
2. **Multi-key receive:** a gateway with command+field keys decrypts a field-group frame whose
   sender is only in the field `addresses`; a leaf with empty `child_groups` is unchanged.
3. **End-to-end:** run the dod_mission demo, watch the dashboard reputations panel — within the
   warm-up window it should show **scored** entries for squad/microdrones (supplied via the rq86
   gateway rosters), not just "forming…". Grep the coordinator `_query_reputations` diag to confirm
   `latest_reputation` now covers the full field roster.
4. **Non-regression:** existing `examples/*/test_rank_gate.py`, `test_trust_ladder.py`, and the
   reputation tests still pass; `scripts/test-conformance.sh` shows only the expected (deferred)
   C-parity diff on the new `group_uuid` field.
