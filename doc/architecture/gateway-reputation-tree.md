*Previous: [Persistent cohort](persistent-cohort.md)*

# Tree-structured reputation blockchain for gateway nodes

> Phases 0-2 are what the code carries; phase 3 (C parity and persistence) is
> specified below and tracked in [`ISSUES.md`](../../ISSUES.md) §10.2. The phasing
> described here is the design, not a plan of work.

## Context

**Problem (the reputation-roster gap).** In the dod_mission demo the reputations
panel on the coordinator only ever scores the gateway it directly peers with
(rq86-1), never the squad or the microdrones, even though their telemetry
reaches the map. The root cause is structural, not a bug.

- Each node holds **one** linear reputation chain (`self.history`, `repprocess.py`) scoped to
 **one** group (`self.group`, reassigned never extended).
- Consensus reputation (`_consensus_reputation`, `repprocess.py`) is a **pure EMA over that one
 chain**, so it can only score a peer whose bilateral transactions are *in that chain*.
- The field peers live in a chain belonging to a **different group** that nothing replicates
 upward, so the chain held by the coordinator never contains them → they can't be scored. The
 panel falls back to the "forming…" placeholder for every unscored peer.

**Topology (this scenario).** The deployment is a 2-level cohort tree.

```
command (coordinator, top)
  ├─ rq86-1  (rank 2 gateway)
  └─ rq86-2  (rank 2 gateway)
        └─ field group  (ONE shared rank-1 group: squad×4 + microdrone×4)
```

Squad and microdrones share **one** group so they interact directly. Both rq86
gateways are members of **both** the command group and the field group (N=1
child group here; the design stays general for N children and deeper trees).

**Goal.** Gateways (rank > 1) become **multi-group members**, maintain a **tree
of reputation chains** (one per group they belong to), and answer a
`consensus_rep_req` with the **full recursive subtree roster**. The coordinator
querying rq86-1 then gets back rq86-1 plus every field peer in one reply,
closing the gap without papering it with default neutral (`PREREP_NEUTRAL`, 0.2)
scores. Gateways also **continue to blind-relay** opaque traffic for groups they
don't hold keys to (preserved, not removed).

## Key decisions

1. **Multi-group membership.** `self.group` stays the primary/parent group; add `child_groups`
 (+ child chains) for cohorts the node gateways. Additive: rank-1 leaves keep empty maps and
 behave **exactly** as today.
2. **Full recursive subtree** reply (gateway + children + grandchildren, flattened).
3. **Runtime rank-based discovery** of the tree (`peer._rank` vs `self.identity._rank`).
4. squad + microdrones = one field group.
5. **Communication cut-off is enforced along the tree.** Reputation is on a
 `[0, 1]` scale with neutral/cold-start at `PREREP_NEUTRAL = 0.2` and a
 communication cut-off at `COMM_CUTOFF = 0.1`. When the aggregate reputation of
 a field peer drops below the cut-off it is **excluded**. Its gateway stops
 forwarding for it (the outbound-skip gate) and drops its inbound frames, so
 an excluded subtree member falls out of the recursive roster the gateway
 reports. Recovery is explicit-only (`REASON_REHABILITATE` lifts to 0.2 and
 re-admits) and the excluded state survives a restart. See
 [Reputation § Communication cut-off enforcement](reputation.md#communication-cut-off-enforcement).

**Relay and participate are both supported, and they are orthogonal.** They key
on whether the gateway holds the key of the destination group.

| Destination group | Holds key? | Behavior |
|---|---|---|
| A group the gateway is a **member** of (command, field) | yes | decrypt, deliver, and **participate** (build reputation, run Paxos for that group) |
| A group the gateway only **transits** | no | **relay opaque** (blind forward, no decryption) |
| A member-group that **spans two segments** | yes | **both**, decrypt locally *and* relay onward |

- *Participate* is **net-new** work (Python identity, network, and reputation).
- *Relay* lives only in the **C** layer (`net_proc.c` `AT_NET_GROUP_FORWARD`) and is **preserved by
 not touching it**. The pure-Python demo runs all peers on one shared broadcast channel, so relay
 is not exercised there. What a node sees is decided purely by which group key it holds.

**Runtime path / C-twin.** The demo runs **pure-Python** reputation and network
(the `_native` backend re-exports the Python `ReputationProcess`; demo
containers are Python). So the Python changes need **no** lockstep with C at
runtime, and C-twin plus `scripts/test-conformance.sh` byte-parity is a
**follow-up**. The two runtimes are held aligned on content, ordering, and
bytes.

## Design (phased)

### Phase 0: multi-group key holding (identity + IPC + network)

**Data model (additive).**
- `identity/idprocess.py` adds `self.child_groups: dict[str,Group] = {}` and
 `self.parent_gateway: str|None = None`.
- `protocol.py` adds `self.child_groups: dict[str,Group] = {}`.
- `identity/group.py` reuses `Group` **unchanged** per cohort; each holds its own `_encryptor`.

**Runtime rank discovery, reusing the existing admission and welcoming handlers
with no new wire messages.** With `R_self = getattr(self.identity,'_rank',0)`
and `R_peer = getattr(peer,'_rank',0)`:
- `R_peer < R_self` and `R_self > 1` → the cohort of the peer is a **child**, and the gateway
 holds the key of that group as a `child_group` (mint it if gateway-originated, else adopt the
 arriving group).
- `R_peer > R_self` → record `self.parent_gateway = peer.uuid` (newest, mirroring the
 `_select_partition_leader` tiebreak).
- `R_peer == R_self` → same cohort (current path).
- The triggers are `_peer_accepted`/`_add_peer`, `choose_group`/`receive_history`, and
 `welcoming_committee`.
- **Overwrite-prevention.** At the group-assignment sites in `choose_group`/`_merge_to_mesh`,
 classify the arriving group, a child-classified group goes to `child_groups`, **never** to
 `self.group` or `_merge_to_mesh`.

**Cross-process propagation.** The single-`Group` fan-out
(`protocol.run_message_handlers`, `processes.update`) clobbers the one slot. Add
a `ChildGroupSet` IPC carrier and a `_record_child_groups(queues)` helper
(sibling to `_record_group`), then add one `isinstance(message, ChildGroupSet)`
branch in `run_message_handlers` that sets `self.child_groups`. The existing
`Group` branch is untouched.

**Network layer: multi-key receive (the linchpin for the demo).**
`network/netprocess.py` today checks one group (`accept_group_message`, group
drain, `self.group.decrypt`). Change the group-channel drain so that it finds
the group in `{self.group} ∪ self.child_groups.values()` whose `addresses`
contains `from_addr`, and decrypts with the key of **that** group. Keep the
`from_addr in self.group.addresses → self.group.decrypt` path as the first check
so leaves (empty `child_groups`) are byte-identical. Do **not** add relay to
Python, and do **not** touch C `net_proc.c`.

### Phase 1: reputation chain tree (`reputation/repprocess.py`)

- Keep `self.history` (primary chain). Add `self.child_histories: dict[str,TransactionHistory] = {}`
 keyed by group-uuid, plus `self.child_groups` (fed by the same `ChildGroupSet` carrier). Reuse
 `TransactionHistory` unchanged per chain.
- Helper `_chain_for_group(group_uuid)` → matching child chain, **defaulting to `self.history`**,
 so that an unknown or absent group resolves to the primary chain.
- **Route commits to the right chain.** Stamp the originating `group_uuid` into the Paxos payloads
 (`request`/`transaction`/`committed`); readers parse it with a **length-tolerant unpack**
 (`x[3] if len(x)>3 else None`) so legacy tuples resolve to the primary chain. Route
 `self.history.update(...)` through `self._chain_for_group(group_uuid).update(...)`.
- **Per-group quorum.** `len(self.peers.all)//2` conflates groups once a gateway joins two. Add
 `_quorum_for_group(group_uuid)` sized by the membership of that group (derive members by
 filtering peers against the `_address_map` of the group, see R1).
- **Catch-up routing.** Thread `group_uuid` through `outdated`/`update` so a child chain catches up
 independently; default to primary when absent.

### Phase 2: recursive subtree consensus reply

- `_consensus_reputation(peer_uuid, chain=None)` takes an optional `chain`, defaulting to
 `self.history`. Pure per chain. The local-trust family (`_compute_reputation`/`_pure_reputation`/
 `_contrite_tit_for_tat`) stays on `self.history`, untouched.
- New `_subtree_roster(gateway_uuid) -> list[Reputation]`: own score vs primary chain, plus a
 `Reputation` for every uuid in each child chain (`list(chain._peer_mapping.keys())`) scored vs
 that child chain. **Demo (depth 2)** returns gateway plus all field peers, complete.
 **Grandchildren** (a child that is itself a gateway) are **not covered**. That wants a
 recursive forward and aggregate with timeout, and the depth is capped at direct
 children, which is correct for this scenario.
- `_compute_consensus_reputation` appends the **roster list** to `self.requested_reps`.
- **Polymorphic `rep_resp`** (`forward_reputation`): a list payload serializes as a JSON array of
 `Reputation`; a single `Reputation` (and 1-element leaf roster) stays a bare object →
 byte-identical for leaves. `automate.py` rep_resp handler wraps
 `reps = rep if isinstance(rep,list) else [rep]` (also handles the JSON-array-string case) and
 runs the existing per-`Reputation` body in a loop.
- **Coordinator** `_query_reputations` (`examples/dod_mission/coordinator.py`) needs **no change**,
 since querying the gateways now returns the whole field roster.

### Deep resolution replaces grandchild aggregation (2026-08-13)

The "recursive forward and aggregate with timeout" sketched below for depth > 2
was **not built, and deliberately not**. Aggregation costs the size of the TREE
on every query to answer a question about one PEER, and interactions deep in a
hierarchy are rare. Although a full rollup would answer every later question at
once, the cost of it is paid on every query. The targeted alternative is
cheaper, simpler, and bounded by depth. Instead a targeted query (`rep_resolve`) is relayed toward
whoever holds the chain and the answer (`rep_resolved`) returns along the
reverse path carrying the quorum-signed window that backs it, O(depth) messages,
per interaction.

Two properties carry it, and both were decisions rather than defaults.

- **Opaque both directions.** The query names no originator, and the answer retraces the path of
 the query. The only state at each relay is a TTL'd `query_id -> neighbour` entry. Nothing blocks
 awaiting a child, so the non-blocking model above is preserved.
- **The answer proves itself, whole.** It carries the full committed window and the verifier
 recomputes the root. Inclusion proofs were rejected for this. They show what is present
 and say nothing about what was withheld, and a gateway flattering its own subtree omits
 rather than invents. The accepted cost is that the requestor sees every transaction in
 that window, not only the one it queried.

The score a requestor records is the one IT computes from the attested window,
and the value the holder reports is a cross-check, because per-capability
transaction weights live in a node-local cache that no hashed entry covers.
Signers ride along in the canonical public identity form (a requestor two
boundaries away holds no identity from the answering group) and must chain to an
anchor we accept. What cannot be checked from outside the boundary, whether
those signers are a majority of that group, is reported as a count rather than
assumed.

See `ISSUES.md` §10.2, `tests/a_unit/test_deep_resolution.py`,
`src/c/test/rep_resolve_test.c`, and the corpus scenarios
`deep-resolution-evidence` / `deep-resolution-withheld-entry-refused`.

### Phase 3: not built (see `ISSUES.md` §10.2)
- C-twin parity for the new `group_uuid` payload field + conformance corpus.
- Persistence of `child_groups` / child chains across gateway restart (today only primary persists).
- Partition-recovery reconciliation (see R2).
- ~~Grandchild recursive aggregation (depth > 2).~~ Superseded by deep resolution above
 (2026-08-13). Aggregation was rejected as unscalable, and the need is met per-interaction.

## Critical files
- `src/autonomous-trust/autonomous_trust/core/_python/identity/idprocess.py`: data model, rank
 discovery, child-group classification/routing.
- `src/autonomous-trust/autonomous_trust/core/_python/protocol.py`: `ChildGroupSet` propagation.
- `src/autonomous-trust/autonomous_trust/core/_python/network/netprocess.py`: multi-key receive.
- `src/autonomous-trust/autonomous_trust/core/_python/reputation/repprocess.py`: chain tree,
 per-group routing/quorum, `_subtree_roster`, polymorphic reply.
- `src/autonomous-trust/autonomous_trust/core/_python/reputation/reputation.py`: reuse
 `TransactionHistory`/`Reputation` (no structural change expected).
- `src/autonomous-trust/autonomous_trust/core/_python/automate.py`: iterate roster replies.
- `examples/dod_mission/coordinator.py`: verify panel; loop unchanged.
- Reuse `_reputations_view()` / `_render_reputations` (already render "forming…" placeholders):
the roster now fills those in.

## Risks / open items
- **R1 (correctness, Phase 1).** Authoritative per-group membership for `_quorum_for_group`.
 `Group` carries `_address_map`, not a uuid roster, and `self.peers.all` conflates groups. Likely
 derive members by filtering peers against the `_address_map` of each group.
- **R2.** Multi-group gateways re-enter partition-recovery logic they were excluded from (gateways
 were "zero groups"). Gate any partition signal on "not in primary **and** not in any child group"
 before firing, and reconcile with the C `is_gateway` exclusion. The current Python netprocess
 drops unknown-sender frames silently, so there is no partition signal and demo risk is low,
 though it should be flagged for C and production.
- **R3.** Child-group `group_update` must not enter the primary convergence/tiebreak path; route by
 uuid.
- **R4.** C-twin payload parity (Phase 3).

## Verification
1. **Unit.** `_chain_for_group` routing; `_consensus_reputation(chain=...)` purity; `_subtree_roster`
 returns gateway + all field peers from a seeded field chain; polymorphic `rep_resp` round-trips
 a roster and a bare `Reputation`; leaf node still emits a bare `Reputation`.
2. **Multi-key receive.** A gateway with command+field keys decrypts a field-group frame whose
 sender is only in the field `addresses`; a leaf with empty `child_groups` is unchanged.
3. **End-to-end.** Run the dod_mission demo and watch the dashboard reputations panel. Within the
 warm-up window it should show **scored** entries for squad/microdrones (supplied via the rq86
 gateway rosters), not just "forming…". Grep the coordinator `_query_reputations` diag to confirm
 `latest_reputation` now covers the full field roster.
4. **Non-regression.** Existing `examples/*/test_rank_gate.py`, `test_trust_ladder.py`, and the
 reputation tests still pass, and `scripts/test-conformance.sh` shows only the C-parity
 diff on the new `group_uuid` field, which belongs to phase 3.

---

# Subtree member-roster enumeration (identity process)

A **lean, membership-only** capability, deliberately **decoupled from the
reputation chain tree above**. Given a gateway, it returns the flattened set of
**member identities** (uuid + public naming fields) across its whole subtree, at
**arbitrary depth**. It was built because the `ethne` polity tier needs the full
membership roll of a community to ratify a founding boundary, and AT is
hierarchical, so a member gateway hides a cohort behind it and the flat local
peer view does not reveal everyone. It carries **no reputation**, which stays in
the Phase 1-3 chain tree and is still local-depth-2.

The capability is homed in the **identity** process, because it is membership,
and identity already holds `child_groups`, the address maps, and the conformance
`identity` adapter.

## Design: requestor-side BFS (not gateway-side recursion)

Each gateway answers only about itself, and it stays stateless, cheap, and
local.

- `handle_roster_request` replies with the **local** members of this node
 (self + primary group + each gatewayed child group, from the `address_map` of every group)
 **plus the uuids of its child gateways** to recurse into.
- The **requestor** drives the walk (`aggregate_subtree_roster`), a
 breadth-first pass over a per-gateway `fetch` that flattens, dedupes, and sorts
 by uuid (the canonical cross-language ordering), cycle- and
 fan-out-guarded (`SUBTREE_ROSTER_MAX_NODES`).

Although the gateway-side "forward to children and await" model is the shape the
reputation skeleton *looks* like, that skeleton is in fact **local depth-2
only**. There is no existing precedent for a recursive network forward-and-await,
and blocking a handler awaiting child responses violates the AT single-threaded
process loop. Requestor-side BFS is the clean non-blocking design for a
distributed recursive query, and it composes to any depth because each gateway is
independently seeded with its *direct* children. (Decision: 2026-07-23,
overriding the original gateway-side wording of the plan.)

Partial and failure semantics are separate from privacy. A gateway that is
unreachable or never answers leaves the roster **incomplete**. What comes back is
partial, explicit, and safe to reuse, and the walk never hangs.

### Reply routing: the requestor names its return process

`roster_req` carries **`requesting_process`** and the gateway addresses its
`roster_resp` to that process, defaulting to `main`. This follows the convention
of `rep_req` (`requesting_process`, netprocess `_msg_to_queue`).

It is load-bearing, not decoration. Inbound messages are routed **only** by
`Message.process` / `net_msg.process`. While `return_to` looks like a routing
hint, it is a local field used by the ping path and never read off the wire. The BFS aggregation that consumes a
`roster_resp` lives in the **main loop** of the requestor
(`AutonomousTrust._consume_roster_resp`), and its identity process registers no
`roster_resp` handler.

An earlier version replied to its own process name (`identity`), which delivered
every answer into the identity process of the requestor, where it was never
handled and accumulated in `self.messages` indefinitely. Because both sides sit
in one address space in unit tests, and the conformance scenario drives the walk
through a local fetch, the enumeration looked correct everywhere it was tested
and would simply never complete on a real multiprocess node. Fixed 2026-07-27,
with the routing pinned in `test_subtree_roster.py` and `subtree_roster_test.c`
on both sides of the contract (requestor names it, responder honors it, absent ⇒
`main`).

## Child-gateway discovery: by rank

The roster response of a gateway names the **child gateways** to recurse into.
Those are not carried on the wire per-peer. They are **derived** at response
time, one per gatewayed child group.

> the child gateway is the **highest-rank member** of that child group,
> **excluding self**, ties broken by the **lexicographically greater uuid**.

The uuid tiebreak makes the derivation **deterministic and identical in both
languages** with no shared state. Although two runtimes could each pick a
defensible winner, only one of them can be the answer a roster query recurses
into. An explicit `child_gateways[cg]` entry, when
present, **overrides** discovery: used by tests and pinned topologies.
(Decision: 2026-07-23, rank-based discovery chosen over a config-seeded child
list, so live enumeration can go past depth-2 without a new seeding mechanism.)

**Rank source.** Python peers already carry rank (`effective_rank`, else
`_rank`), so `_member_rank` reads it directly. Although C peers carry no rank of
their own, being stored as `public_identity_t`, which drops it, the gap is
closed on the C side. C therefore keeps a
**`peer_ranks` map** on the `protocol` struct and `_roster_member_rank` reads it
(default `0`/unknown). Because a single non-self member wins regardless of rank,
a single-member child group resolves identically in both languages with no rank
data at all.

**How rank reaches a C peer: the message envelope.** Rank enters the system at
self-announce, which rides the **message envelope** (`from_whom`), not the
identity payload. The JSON wire envelope carries a **`from_rank`** field
(`net_message.c` pack/unpack ⟂ Python `Message.__bytes__` /
`_identity_from_wire`), sourced from the rank of the sending node, in C stamped
by the network process from the local `identity_t` (`net_proc.c`), and in Python
read from `from_whom._rank`. This mirrors long-standing behaviour in Python,
where rank has always ridden the envelope and `_identity_from_wire` now
reconstructs it. `from_rank` sits outside the signed pre-image
(`process|function|data`) and outside the ciphertext, so it affects neither
signatures nor encryption, and an absent field (older peer) reads back as `0`. On
the C side the identity process captures it into `peer_ranks` at admission
(`_peer_accepted` (rank argument) and the `request_access` potential-store) via
`identity_set_peer_rank`. Only a known (non-zero) rank is stored, so an unknown
`0` never clobbers a prior value.

## Opt-out: private networks (`AT_ROSTER_PRIVATE`)

Any gateway (**including the top one**) can refuse disclosure via the AT config
option **`AT_ROSTER_PRIVATE`** (`_env_bool` in Python, `getenv` in C; per-node,
one node = one process). A private node replies with a **`private` marker**
carrying no members and no child gateways, so the enumeration stops there as an
**intentional opaque boundary**, recorded separately from an unreachable node
(privacy ≠ incompleteness). A refusal is deliberate, recorded, and distinct from
a failure. A private **top** gateway therefore yields an
**empty-but-complete** roster, since a fully private network or subtree opts out
of being mapped at all, and `ethne` falls back to its `ManualFounding` path. This
is enforced **only at the disclosure boundary** (`handle_roster_request` /
`_roster_response`), and `enumerate_local_members` stays pure, because a node
always knows its own members locally.

## Implementations (C ⟂ Python parity)

- **Python** (`identity/idprocess.py`): `enumerate_local_members`,
 `_child_gateway_uuids` (+ `_discover_child_gateway` / `_member_rank`),
 `_roster_response`, `handle_roster_request`, module-level
 `aggregate_subtree_roster` → `(members, complete, private_boundaries)`;
 `roster_private` from `AT_ROSTER_PRIVATE`; `roster_req`/`roster_resp` in
 `identity/protocol.py`. App-facing async emit/consume in `automate.py`
 (`request_subtree_roster` + `_consume_roster_resp`, resolving child gateways
 through the peer table of the requestor, graceful partial when unroutable).
- **C** (`identity/id_proc.c`, declared in `id_proc_priv.h`):
 `identity_enumerate_local_members`, `identity_roster_response`
 (+ `_roster_child_gateway_array` / `_roster_discover_child_gateway` /
 `_roster_member_rank`), `handle_roster_request`,
 `identity_aggregate_subtree_roster` (fetch-callback BFS),
 `identity_add_child_group` / `identity_set_roster_private` /
 `identity_set_peer_rank`; `child_groups`/`child_gateways`/`peer_ranks`/
 `roster_private` on the `protocol` struct (`processes/processes.h`);
 `ID_ROSTER_QUERY`/`ID_ROSTER_RESPONSE`. Live rank propagation via the envelope
 `from_rank` field (`net_message.c`, `net_proc.c`, `msg_types.h`,
 `net_message.h`) captured at admission (`id_proc.c`).
- Both the wire handler and the conformance/aggregation fetch call the **same**
 roster-response helper (`_roster_response` / `identity_roster_response`), so
 the two paths and the two languages emit identical content.

## Verification

- **Python unit.** `tests/a_unit/test_subtree_roster.py` covers local enumeration,
 handler, and walk (BFS flatten/dedup/cycle/cap/partial), opt-out, **rank-based
 discovery** (higher-rank / uuid-tiebreak / explicit-override / self-exclusion),
 and in-process integration over a real ≥3-level cohort. `tests/a_unit/test_automate_roster.py`
 covers the requestor-side async walk.
- **C unit.** `test/subtree_roster_test.c` (enumerate, handler + opt-out,
 aggregate flatten/private-boundary/partial/cycle, config-file seeding, and the
 four **rank-based discovery** cases mirroring Python).
- **Conformance.** `scenarios/identity/subtree-member-roster.yaml`, a 3-level
 `cohort_tree` whose child gateways are **discovered by rank** (no `gateway`
 pin), a `trigger_subtree_roster` pseudo-step, and
 `expected_state.top.subtree_roster` compared as sorted **participant ids**
 (each roster uuid mapped back to its participant, so the check is
 language-agnostic). Exercising discovery rather than an explicit pin means the
 rank derivation itself is held to cross-language parity. Diff: **0 asymmetric**.

## Verification (rank propagation)

- **C unit.** `test/net_message_test.c`, `from_rank` survives the wire
 round-trip, and a legacy envelope without the field parses to `0`.
- **Python unit.** `tests/a_unit/test_message.py`. The envelope carries
 `from_rank` onto a reconstructed `from_whom`, and an absent field defaults to
 `0`.
- **Conformance.** The seven `message-envelope-*` byte-pinned wire vectors were
 regenerated for the new envelope, and both languages emit identical bytes
 (cross-language diff **0 asymmetric**).

## Runtime hierarchy roots (protocol step 7)

The tree used to exist only in seeded config. It is now DISCOVERED at runtime,
in two halves that are deliberately different in kind.

- **Derived, our own parent.** The highest-rank member of our primary group whose rank
 *exceeds* ours and which can prove gateway authority for a boundary we share
 (`_derive_parent_gateway`, C twin of the same name). Never accepted from a peer: a node
 that could name itself our parent would insert itself into every rollup we perform. The
 rank comparison is the one place this differs from `_discover_child_gateway`, there we
 pick the leader of somebody else, here we ask who leads us, so the top node of a cohort
 is the root rather than somebody's child.
- **Advertised, everybody else's position.** `hierarchy` / `hierarchy_query` on the
 encrypted group channel: each node states which cohorts it gateways, whom it federates
 through, and its rank, when that view changes and on request, so a late joiner converges
 without waiting for the next change from somebody else. Recorded only from peers that prove
 a shared anchor, the recorded value is what a roster query recurses into. A claim naming
 somebody other than its sender is refused.

`_child_gateway_uuids` therefore has three sources, most authoritative first.
They stay distinct, namely config, advertisement, and inference. The
advertisement outranks inference because "I gateway cohort X" is direct evidence
where "it is the highest-rank member of X" is a guess.

**No group key ever moves.** An advertisement confers no membership and carries
no key; child-group keys remain operator-provisioned. A runtime cross-group
*join*, a node acquiring a second cohort's key over the wire, is a separate
question, because that key is the confidentiality boundary of the whole system.
It is tracked in `ISSUES.md` §10.2.

Rank note: the membership of a cohort is an **address map**, so a node can know a
member, and need its rank to decide who leads it, before it holds the Identity of
that member. Both runtimes therefore read rank from a `peer_ranks` seam as well
as from a materialized peer. C has had this from the start, and Python gained it
with this work.

## Not built

- **C app-facing carrier + async wire-unroll.** New `message_type_t`
 `ROSTER_QUERY`/`ROSTER_RESPONSE` + `autonomous_trust.c` `extern_q`/`q_out`
 routing, and the C twin of the emit/consume in `automate.py`. This is the
 surface `ethne-at` reads, and it is not needed for scenario-observable
 conformance.

C child-group seeding is built. `identity_load_child_groups` reads
`group_child_*.cfg.json` through the Python `Group`-schema bridge, unit-tested.
Child *gateways* need no seeding at all, being derived by rank at response time.

---

*Next: [Reputation against blockchain](reputation-vs-blockchain-analysis.md)*
