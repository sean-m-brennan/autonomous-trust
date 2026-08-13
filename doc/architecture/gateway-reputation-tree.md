# Tree-structured reputation blockchain for gateway nodes

> Phases 0-2 are what the code carries; phase 3 (C parity and persistence) is
> specified below and tracked in [`ISSUES.md`](../../ISSUES.md) §10.2. The phasing
> described here is the design, not a plan of work.

## Context

**Problem (the reputation-roster gap).** In the dod_mission demo the coordinator's reputations
panel only ever scores the gateway it directly peers with (rq86-1), never the squad/microdrones:
even though their telemetry reaches the map. The root cause is structural, not a bug:

- Each node holds **one** linear reputation chain (`self.history`, `repprocess.py`) scoped to
  **one** group (`self.group`, reassigned never extended).
- Consensus reputation (`_consensus_reputation`, `repprocess.py`) is a **pure EMA over that one
  chain**: it can only score a peer whose bilateral transactions are *in that chain*.
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
reply: closing the gap without papering it with default neutral (`PREREP_NEUTRAL`, 0.2) scores. Gateways also **continue to
blind-relay** opaque traffic for groups they don't hold keys to (preserved, not removed).

## Key decisions

1. **Multi-group membership**: `self.group` stays the primary/parent group; add `child_groups`
   (+ child chains) for cohorts the node gateways. Additive: rank-1 leaves keep empty maps and
   behave **exactly** as today.
2. **Full recursive subtree** reply (gateway + children + grandchildren, flattened).
3. **Runtime rank-based discovery** of the tree (`peer._rank` vs `self.identity._rank`).
4. squad + microdrones = one field group.
5. **Communication cut-off is enforced along the tree.** Reputation is on a
   `[0, 1]` scale with neutral/cold-start at `PREREP_NEUTRAL = 0.2` and a
   communication cut-off at `COMM_CUTOFF = 0.1`. When a field peer's aggregate
   reputation drops below the cut-off it is **excluded**: its gateway stops
   forwarding for it (the outbound-skip gate) and drops its inbound frames, so
   an excluded subtree member falls out of the recursive roster the gateway
   reports. Recovery is explicit-only (`REASON_REHABILITATE` lifts to 0.2 and
   re-admits) and the excluded state survives a restart. See
   [Reputation § Communication cut-off enforcement](reputation.md#communication-cut-off-enforcement).

**Relay vs participate: both supported, orthogonal.** They key on whether the gateway holds the
destination group's key:

| Destination group | Holds key? | Behavior |
|---|---|---|
| A group the gateway is a **member** of (command, field) | yes | decrypt → deliver → **participate** (build reputation, run that group's Paxos) |
| A group the gateway only **transits** | no | **relay opaque** (blind forward, no decryption) |
| A member-group that **spans two segments** | yes | **both**, decrypt locally *and* relay onward |

- *Participate* is **net-new** work (Python identity/network/reputation).
- *Relay* lives only in the **C** layer (`net_proc.c` `AT_NET_GROUP_FORWARD`) and is **preserved by
  not touching it**. The pure-Python demo runs all peers on one shared broadcast channel, so relay
  isn't exercised there: what a node sees is decided purely by which group key it holds.

**Runtime path / C-twin.** The demo runs **pure-Python** reputation + network (the `_native`
backend re-exports the Python `ReputationProcess`; demo containers are Python). So the Python
changes need **no** lockstep with C at runtime; C-twin + `scripts/test-conformance.sh` byte-parity
is a **follow-up**.

## Design (phased)

### Phase 0: multi-group key holding (identity + IPC + network)

**Data model (additive).**
- `identity/idprocess.py`: add `self.child_groups: dict[str,Group] = {}`,
  `self.parent_gateway: str|None = None`.
- `protocol.py`: add `self.child_groups: dict[str,Group] = {}`.
- `identity/group.py`: `Group` reused **unchanged** per cohort; each holds its own `_encryptor`.

**Runtime rank discovery (reuse existing admission/welcoming handlers: no new wire msgs).**
With `R_self = getattr(self.identity,'_rank',0)`, `R_peer = getattr(peer,'_rank',0)`:
- `R_peer < R_self` and `R_self > 1` → peer's cohort is a **child**; gateway holds that group's key
  as a `child_group` (mint it if gateway-originated, else adopt the arriving group).
- `R_peer > R_self` → record `self.parent_gateway = peer.uuid` (newest, mirroring the
  `_select_partition_leader` tiebreak).
- `R_peer == R_self` → same cohort (today's path).
- Triggers: `_peer_accepted`/`_add_peer`, `choose_group`/`receive_history`, `welcoming_committee`.
- **Overwrite-prevention**: at the group-assignment sites in `choose_group`/`_merge_to_mesh`,
  classify the arriving group, a child-classified group goes to `child_groups`, **never** to
  `self.group` or `_merge_to_mesh`.

**Cross-process propagation.** The single-`Group` fan-out (`protocol.run_message_handlers`,
`processes.update`) clobbers the one slot. Add a `ChildGroupSet` IPC carrier + a
`_record_child_groups(queues)` helper (sibling to `_record_group`); add one
`isinstance(message, ChildGroupSet)` branch in `run_message_handlers` that sets
`self.child_groups`. The existing `Group` branch is untouched.

**Network layer: multi-key receive (the linchpin for the demo).** `network/netprocess.py` today
checks one group (`accept_group_message`, group drain, `self.group.decrypt`). Change the
group-channel drain to: find the group in `{self.group} ∪ self.child_groups.values()` whose
`addresses` contains `from_addr`, and decrypt with **that** group's key. Keep the
`from_addr in self.group.addresses → self.group.decrypt` path as the first check so leaves
(empty `child_groups`) are byte-identical. Do **not** add relay to Python; do **not** touch C
`net_proc.c`.

### Phase 1: reputation chain tree (`reputation/repprocess.py`)

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
  peers against the group's `_address_map`, see R1).
- **Catch-up routing.** Thread `group_uuid` through `outdated`/`update` so a child chain catches up
  independently; default to primary when absent.

### Phase 2: recursive subtree consensus reply

- `_consensus_reputation(peer_uuid, chain=None)`: add optional `chain`, default `self.history`.
  Pure per chain. The local-trust family (`_compute_reputation`/`_pure_reputation`/
  `_contrite_tit_for_tat`) stays on `self.history`, untouched.
- New `_subtree_roster(gateway_uuid) -> list[Reputation]`: own score vs primary chain, plus a
  `Reputation` for every uuid in each child chain (`list(chain._peer_mapping.keys())`) scored vs
  that child chain. **Demo (depth 2):** returns gateway + all field peers, complete.
  **Grandchildren** (a child that is itself a gateway) are **not covered**: that wants a
  recursive forward and aggregate with timeout, and the depth is capped at direct
  children, which is correct for this scenario.
- `_compute_consensus_reputation` appends the **roster list** to `self.requested_reps`.
- **Polymorphic `rep_resp`** (`forward_reputation`): a list payload serializes as a JSON array of
  `Reputation`; a single `Reputation` (and 1-element leaf roster) stays a bare object →
  byte-identical for leaves. `automate.py` rep_resp handler wraps
  `reps = rep if isinstance(rep,list) else [rep]` (also handles the JSON-array-string case) and
  runs the existing per-`Reputation` body in a loop.
- **Coordinator** `_query_reputations` (`examples/dod_mission/coordinator.py`): **no change
  required**, querying the gateways now returns the whole field roster.

### Deep resolution replaces grandchild aggregation (2026-08-13)

The "recursive forward and aggregate with timeout" sketched below for depth > 2 was **not
built, and deliberately not**. Aggregation costs the size of the TREE on every query to
answer a question about one PEER, and interactions deep in a hierarchy are rare. Instead a
targeted query (`rep_resolve`) is relayed toward whoever holds the peer's chain and the
answer (`rep_resolved`) returns along the reverse path carrying the quorum-signed window
that backs it — O(depth) messages, per interaction.

Two properties carry it, and both were decisions rather than defaults:

- **Opaque both directions.** The query names no originator; the answer retraces the query's
  path. Each relay's only state is a TTL'd `query_id -> neighbour` entry. Nothing blocks
  awaiting a child, so the non-blocking model above is preserved.
- **The answer proves itself, whole.** It carries the full committed window and the verifier
  recomputes the root. Inclusion proofs were rejected for this: they show what is present
  and say nothing about what was withheld, and a gateway flattering its own subtree omits
  rather than invents. The accepted cost is that the requestor sees every transaction in
  that window, not only the queried peer's.

The score a requestor records is the one IT computes from the attested window; the holder's
value is a cross-check, because per-capability transaction weights live in a node-local
cache that no hashed entry covers. Signers ride along in the canonical public identity form
(a requestor two boundaries away holds no identity from the answering group) and must chain
to an anchor we accept. What cannot be checked from outside the boundary — whether those
signers are a majority of that group — is reported as a count rather than assumed.

See `ISSUES.md` §10.2, `tests/a_unit/test_deep_resolution.py`, `src/c/test/rep_resolve_test.c`,
and the corpus scenarios `deep-resolution-evidence` /
`deep-resolution-withheld-entry-refused`.

### Phase 3: not built (see `ISSUES.md` §10.2)
- C-twin parity for the new `group_uuid` payload field + conformance corpus.
- Persistence of `child_groups` / child chains across gateway restart (today only primary persists).
- Partition-recovery reconciliation (see R2).
- ~~Grandchild recursive aggregation (depth > 2).~~ Superseded by deep resolution above
  (2026-08-13): aggregation was rejected as unscalable, and the need is met per-interaction.

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
- **R1 (correctness, Phase 1):** authoritative per-group membership for `_quorum_for_group`.
  `Group` carries `_address_map`, not a uuid roster; `self.peers.all` conflates groups. Likely
  derive members by filtering peers against each group's `_address_map`.
- **R2:** multi-group gateways re-enter partition-recovery logic they were excluded from (gateways
  were "zero groups"). Gate any partition signal on "not in primary **and** not in any child group"
  before firing; reconcile with the C `is_gateway` exclusion. (Current Python netprocess drops
  unknown-sender frames silently: no partition signal, so demo risk is low; flag for C/production.)
- **R3:** child-group `group_update` must not enter the primary convergence/tiebreak path; route by
  uuid.
- **R4:** C-twin payload parity (Phase 3).

## Verification
1. **Unit:** `_chain_for_group` routing; `_consensus_reputation(chain=...)` purity; `_subtree_roster`
   returns gateway + all field peers from a seeded field chain; polymorphic `rep_resp` round-trips
   a roster and a bare `Reputation`; leaf node still emits a bare `Reputation`.
2. **Multi-key receive:** a gateway with command+field keys decrypts a field-group frame whose
   sender is only in the field `addresses`; a leaf with empty `child_groups` is unchanged.
3. **End-to-end:** run the dod_mission demo, watch the dashboard reputations panel, within the
   warm-up window it should show **scored** entries for squad/microdrones (supplied via the rq86
   gateway rosters), not just "forming…". Grep the coordinator `_query_reputations` diag to confirm
   `latest_reputation` now covers the full field roster.
4. **Non-regression:** existing `examples/*/test_rank_gate.py`, `test_trust_ladder.py`, and the
   reputation tests still pass; `scripts/test-conformance.sh` shows only the C-parity
   diff on the new `group_uuid` field, which is phase 3's.

---

# Subtree member-roster enumeration (identity process)

A **lean, membership-only** capability, deliberately **decoupled from the
reputation chain tree above**: given a gateway, return the flattened set of
**member identities** (uuid + public naming fields) across its whole subtree,
at **arbitrary depth**. Built because the `ethne` polity tier needs a
community's full membership roll to ratify a founding boundary, and AT is
hierarchical: a member gateway hides a cohort behind it, so the flat local
peer view does not reveal everyone. It carries **no reputation** (that stays in
the Phase 1-3 chain tree, which is still local-depth-2).

Homed in the **identity** process (it is membership; identity already holds
`child_groups`, the address maps, and the conformance `identity` adapter).

## Design: requestor-side BFS (not gateway-side recursion)

Each gateway answers **only about itself** and stays **stateless and
non-blocking**:

- `handle_roster_request` replies with this node's **local** members
  (self + primary group + each gatewayed child group, from every group's
  `address_map`) **plus the uuids of its child gateways** to recurse into.
- The **requestor** drives the walk (`aggregate_subtree_roster`): a
  breadth-first flatten over a per-gateway `fetch`, deduping members by uuid
  and sorting by uuid (the canonical cross-language ordering), cycle- and
  fan-out-guarded (`SUBTREE_ROSTER_MAX_NODES`).

This was chosen over the gateway-side "forward to children and await" model
(the shape the reputation skeleton *looks* like) because that skeleton is in
fact **local depth-2 only**: there is no existing precedent for a recursive
network forward-and-await, and blocking a handler awaiting child responses
violates AT's single-threaded process loop. Requestor-side BFS is the clean
non-blocking design for a distributed recursive query, and it composes to any
depth because each gateway is independently seeded with its *direct* children.
(Decision: 2026-07-23, overriding the plan's original gateway-side wording.)

Partial/failure semantics: a gateway that is unreachable / never answers leaves
the roster **incomplete** (returned partial, never hangs). This is distinct
from privacy (below).

### Reply routing: the requestor names its return process

`roster_req` carries **`requesting_process`** and the gateway addresses its
`roster_resp` to that process, defaulting to `main`. This is `rep_req`'s
convention (`requesting_process`, netprocess `_msg_to_queue`).

It is load-bearing, not decoration. Inbound messages are routed **only** by
`Message.process` / `net_msg.process`: `return_to` is a local field used by the
ping path and is not a wire routing hint. The BFS aggregation that consumes a
`roster_resp` lives in the requestor's **main loop**
(`AutonomousTrust._consume_roster_resp`); its identity process registers no
`roster_resp` handler.

An earlier version replied to the responder's *own* process name (`identity`),
which delivered every answer into the requestor's identity process, where it
was never handled and accumulated in `self.messages` indefinitely. Because both
sides sit in one address space in unit tests and the conformance scenario
drives the walk through a local fetch, the enumeration looked correct
everywhere it was tested and would simply never complete on a real
multiprocess node. Fixed 2026-07-27, with the routing pinned in
`test_subtree_roster.py` and `subtree_roster_test.c` on both sides of the
contract (requestor names it, responder honors it, absent ⇒ `main`).

## Child-gateway discovery: by rank

A gateway's roster response names the **child gateways** to recurse into. Those
are not carried on the wire per-peer; they are **derived** at response time, one
per gatewayed child group:

> the child gateway is the **highest-rank member** of that child group,
> **excluding self**, ties broken by the **lexicographically greater uuid**.

The uuid tiebreak makes the derivation **deterministic and identical in both
languages** with no shared state. An explicit `child_gateways[cg]` entry, when
present, **overrides** discovery: used by tests and pinned topologies.
(Decision: 2026-07-23, rank-based discovery chosen over a config-seeded child
list, so live enumeration can go past depth-2 without a new seeding mechanism.)

**Rank source.** Python peers already carry rank (`effective_rank`, else
`_rank`), so `_member_rank` reads it directly. **C peers do not**: they are
stored as `public_identity_t`, which drops rank. C therefore keeps a
**`peer_ranks` map** on the `protocol` struct and `_roster_member_rank` reads it
(default `0`/unknown). Because a single non-self member wins regardless of rank,
a single-member child group resolves identically in both languages with no rank
data at all.

**How rank reaches a C peer: the message envelope.** Rank enters the system at
self-announce, which rides the **message envelope** (`from_whom`), not the
identity payload. The JSON wire envelope carries a **`from_rank`** field
(`net_message.c` pack/unpack ⟂ Python `Message.__bytes__` / `_identity_from_wire`),
sourced from the sender's own rank: in C stamped by the network process from
the local `identity_t` (`net_proc.c`), in Python read from `from_whom._rank`.
This mirrors Python's long-standing behaviour (rank has always ridden the
envelope there; `_identity_from_wire` now reconstructs it). `from_rank` sits
outside the signed pre-image (`process|function|data`) and outside the
ciphertext, so it affects neither signatures nor encryption, and an absent field
(older peer) reads back as `0`. On the C side the identity process captures it
into `peer_ranks` at admission (`_peer_accepted` (rank argument) and the
`request_access` potential-store) via `identity_set_peer_rank`. Only a known
(non-zero) rank is stored, so an unknown `0` never clobbers a prior value.

## Opt-out: private networks (`AT_ROSTER_PRIVATE`)

Any gateway (**including the top one**) can refuse disclosure via the AT
config option **`AT_ROSTER_PRIVATE`** (`_env_bool` in Python, `getenv` in C;
per-node, one node = one process). A private node replies with a **`private`
marker** carrying no members and no child gateways: the enumeration stops there
as an **intentional opaque boundary**, recorded separately from an unreachable
node (privacy ≠ incompleteness). A private **top** gateway therefore yields an
**empty-but-complete** roster: a fully private network/subtree opts out of
being mapped at all, and `ethne` falls back to its `ManualFounding` path.
Enforced **only at the disclosure boundary** (`handle_roster_request` /
`_roster_response`); `enumerate_local_members` stays pure (a node always knows
its own members locally).

## Implementations (C ⟂ Python parity)

- **Python** (`identity/idprocess.py`): `enumerate_local_members`,
  `_child_gateway_uuids` (+ `_discover_child_gateway` / `_member_rank`),
  `_roster_response`, `handle_roster_request`, module-level
  `aggregate_subtree_roster` → `(members, complete, private_boundaries)`;
  `roster_private` from `AT_ROSTER_PRIVATE`; `roster_req`/`roster_resp` in
  `identity/protocol.py`. App-facing async emit/consume in `automate.py`
  (`request_subtree_roster` + `_consume_roster_resp`, resolving child gateways
  via the requestor's peer table, graceful partial when unroutable).
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

- **Python unit:** `tests/a_unit/test_subtree_roster.py` (local enum, handler,
  BFS flatten/dedup/cycle/cap/partial, opt-out, **rank-based discovery**
  (higher-rank / uuid-tiebreak / explicit-override / self-exclusion), + in-process
  integration over a real ≥3-level cohort) and `tests/a_unit/test_automate_roster.py`
  (the requestor-side async walk).
- **C unit:** `test/subtree_roster_test.c` (enumerate, handler + opt-out,
  aggregate flatten/private-boundary/partial/cycle, config-file seeding, and the
  four **rank-based discovery** cases mirroring Python).
- **Conformance:** `scenarios/identity/subtree-member-roster.yaml`, a 3-level
  `cohort_tree` whose child gateways are **discovered by rank** (no `gateway`
  pin), a `trigger_subtree_roster` pseudo-step, and
  `expected_state.top.subtree_roster` compared as sorted **participant ids**
  (each roster uuid mapped back to its participant, so the check is
  language-agnostic). Exercising discovery (not an explicit pin) means the
  rank derivation itself is held to cross-language parity. Diff: **0 asymmetric**.

## Verification (rank propagation)

- **C unit:** `test/net_message_test.c`, `from_rank` survives the wire
  round-trip, and a legacy envelope without the field parses to `0`.
- **Python unit:** `tests/a_unit/test_message.py`. The envelope carries
  `from_rank` onto a reconstructed `from_whom`, and an absent field defaults to
  `0`.
- **Conformance:** the seven `message-envelope-*` byte-pinned wire vectors were
  regenerated for the new envelope; both languages emit identical bytes
  (cross-language diff **0 asymmetric**).

## Runtime hierarchy roots (protocol step 7)

The tree used to exist only in seeded config. It is now DISCOVERED at runtime, in two
halves that are deliberately different in kind:

- **Derived — our own parent.** The highest-rank member of our primary group whose rank
  *exceeds* ours and which can prove gateway authority for a boundary we share
  (`_derive_parent_gateway`, C twin of the same name). Never accepted from a peer: a node
  that could name itself our parent would insert itself into every rollup we perform. The
  rank comparison is the one place this differs from `_discover_child_gateway` — there we
  pick somebody else's leader, here we ask who leads us, so a cohort's top node is the root
  rather than somebody's child.
- **Advertised — everybody else's position.** `hierarchy` / `hierarchy_query` on the
  encrypted group channel: each node states which cohorts it gateways, whom it federates
  through, and its rank, when that view changes and on request (so a late joiner converges
  without waiting for somebody else's next change). Recorded only from peers that prove a
  shared anchor — the recorded value is what a roster query recurses into. A claim naming
  somebody other than its sender is refused.

`_child_gateway_uuids` therefore has three sources, most authoritative first: explicit
config, a peer's own advertised claim, then rank inference. The advertisement outranks
inference because "I gateway cohort X" is direct evidence where "it is the highest-rank
member of X" is a guess.

**No group key ever moves.** An advertisement confers no membership and carries no key;
child-group keys remain operator-provisioned. A runtime cross-group *join* — a node
acquiring a second cohort's key over the wire — is a separate question, because that key is
the confidentiality boundary of the whole system. It is tracked in `ISSUES.md` §10.2.

Rank note: a cohort's membership is an **address map**, so a node can know a member — and
need its rank to decide who leads it — before it holds that member's Identity. Both runtimes
therefore read rank from a `peer_ranks` seam as well as from a materialized peer; C has had
this from the start, Python gained it with this work.

## Not built

- **C app-facing carrier + async wire-unroll**: new `message_type_t`
  `ROSTER_QUERY`/`ROSTER_RESPONSE` + `autonomous_trust.c` `extern_q`/`q_out`
  routing, and the C twin of `automate.py`'s emit/consume. This is the surface
  `ethne-at` reads; it is not needed for scenario-observable conformance.

C child-group seeding is built: `identity_load_child_groups` reads
`group_child_*.cfg.json` through the Python `Group`-schema bridge, unit-tested.
Child *gateways* need no seeding at all, being derived by rank at response
time.
