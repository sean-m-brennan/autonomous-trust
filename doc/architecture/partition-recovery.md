# Group Partition Recovery

Status: **Design — not yet implemented.** Drafted 2026-05-20 in response to
the dod_mission demo split-brain (`project_dod_demo_status.md` — coordinator
forms a size-1 group and rejects squad traffic as "not in group").

This document specifies an extension to the Identity protocol that lets a
peer detect it is in a different group than one or more of its neighbors
and converge on a single group via the existing `_merge_to_mesh` machinery.

## 1. Problem

The Identity protocol uses simultaneous multicast announce + an opportunistic
"first peer to receive a quorum" group bootstrap. When two or more peers come
up nearly simultaneously and don't all see each other's announces before
their own `choose_group` timeout, each falls into the `from_scratch = True`
branch (`idprocess.py:332`) and constructs its own one-peer group. They are
now in different groups with different group keys, but on the same multicast
domain.

Once both groups have ≥1 admitted member, normal group-encrypted traffic
flows on the group channel. Each peer's `NetProcess` receives the other
group's traffic and drops it:

- **Python** (`netprocess.py:628`): `from_addr not in self.group.addresses`
  → log `"Recvd transmission from X - not in group. Ignoring."` and drop.
- **C** (`net_proc.c:1295`): `group_decrypt` fails (wrong key) → log
  `"Network: group decrypt failed (%d) from %s"` and drop.

Neither side ever escalates this to the Identity layer. The existing
`_merge_to_mesh` logic (`idprocess.py:1135-1150`) handles size-based merge
*only* when triggered by `full_history` exchange or
`group_key_update`, which never happens in the split-brain case because
neither side initiates `request_access` against the other (each thinks
it's already in a fully-formed group).

The dod_mission demo surfaces this reliably because the compose stack
brings up 16+ peers within a 1-second window. Real deployments with
slower peer arrival are unlikely to hit this, but the gap is real and
the demo cannot proceed without it.

The TODO at `netprocess.py:652-654` (*"Query other group members for the
unknown sender's identity — they may have admitted this peer while we
were partitioned"*) is the right instinct but solves the wrong case:
when the partitioned peer is in a size-1 group (the dod_mission
coordinator), there are no other group members to query. The fix has to
probe across the partition.

## 2. Goals & non-goals

**Goals.**

- Two or more groups on a shared multicast domain converge to a single
  group within ~5-10 seconds of first cross-group traffic.
- No new ports, no new transports — reuse the existing unsecured-broadcast
  channel (the same one `request_access` uses).
- Reuse `_merge_to_mesh` for the actual adoption; the new protocol only
  *initiates* a normal join flow.
- No change to wire-format of existing identity messages.
- Python/C parity from day one (no skewed-only-on-one-side merge logic).
- Bounded: no broadcast-storm risk even under deliberately adversarial
  partition signaling.

**Non-goals.**

- Wire compatibility with pre-existing AT deployments. The decision
  recorded for this work is: all peers upgrade together (see prompt
  on 2026-05-20). The new message types become required parts of the
  protocol; older peers simply won't participate in partition recovery.
- General partition tolerance across network partitions (firewalls,
  unicast-only links). This design assumes both groups can still
  reach each other on the unsecured multicast channel — i.e. the
  "partition" here is purely a *group-state* partition, not a network
  partition. Network-partition recovery is a separate problem.
- Byzantine merge under active attack. The existing
  welcoming-committee + voting already gates new-peer admission; this
  design adds no weakening of that path. But we also do not attempt
  to *resist* a partition-recovery probe — see §6.

## 3. Existing primitives we build on

| Primitive | Role in this design |
|---|---|
| `IdentityProtocol.announce` (`'request_access'`) | After we identify a peer in the larger group, we already know how to ask to join it. |
| `IdentityProtocol.history` (`'full_history'`) | The larger-group peer responds to our `request_access` with `full_history` including their group; our existing `receive_history` calls `choose_group`/`_merge_to_mesh`. |
| `_merge_to_mesh` (`idprocess.py:1125-1151`) | Already implements "larger group wins, uuid tiebreak". We just need to feed it a remote group reference at the right moment. |
| Unsecured multicast channel | We send the partition-probe and response here because cross-group peers cannot decrypt each other's group channel. |
| `Group.uuid`, `Group.publish()` | Group identity (uuid) and a public-only view (`publish()` returns a `Group` with `_public_only=True`) — sufficient for declaring "this is which group I'm in" without exposing the private key. |
| `Identity.encryptor.private` / `.public` | Per-peer signing keys; we sign probe/response payloads with our identity key so a Sybil can't forge "I'm a member of group X". |

## 4. Protocol additions

Two new identity-protocol messages, both carried on the **unsecured
broadcast channel** (same as `request_access`):

### 4.1 `group_partition_probe`

Sent by a peer that has just seen unrecognized group traffic and wants
to discover what the *other* group looks like.

```
msg.obj = {
    "from_uuid":         <sender peer uuid, str>,
    "from_address":      <sender ip:port, str>,
    "my_group_uuid":     <sender's local group uuid, str>,
    "my_group_size":     <int, len(self.group.addresses)>,
    "signature":         <Ed25519 sig of (my_group_uuid || my_group_size)
                          under sender's identity private key, bytes>,
}
```

The signature binds the sender's claim ("I see you as not in my group;
my group looks like this") to their identity. A Sybil with no real
identity can still send this, but they cannot impersonate a known peer
— and the response (4.2) carries the responder's *real* group's
information, which is what the recipient acts on.

### 4.2 `group_partition_response`

Sent by any peer that receives a `partition_probe` from a peer it does
not recognize as a group member.

```
msg.obj = {
    "from_uuid":         <responder peer uuid, str>,
    "from_address":      <responder ip:port, str>,
    "in_response_to":    <probe sender uuid, str>,
    "my_group_uuid":     <responder's local group uuid, str>,
    "my_group_size":     <int>,
    "my_group_leader":   <uuid of one peer in responder's group that
                          can act as welcoming-committee entry, str>,
    "my_group_leader_address": <ip:port of that peer, str>,
    "signature":         <as above>,
}
```

`my_group_leader` is *any* admitted peer in the responder's group — it
doesn't need to be a special "leader" role. Its purpose is to give the
probe sender a known address to direct a `request_access` to. Choosing
the responder itself is simplest; an optimization could choose the
peer with the highest peer-rank in the responder's hierarchy.

## 5. State machine

### 5.1 NetProcess side (cross-process signal)

Both Python and C network processes already have the drop site:

- Python: `netprocess.py:648-651` (`else:` of the `from_addr in addresses` check)
- C: `net_proc.c:1304-1307` (`group_decrypt` failure)

Replace the silent drop with a rate-limited `Message` push onto the
**existing identity queue** (`queues[CfgIds.identity]`), with
`function=IdentityProtocol.partition_signal` and `obj=from_addr`. This
matches the existing pattern for internal-only IPC events
(`IdentityProtocol.rank_update` at `protocol.py:78` is the precedent —
ReputationProcess uses the same approach to nudge IdentityProcess
without a wire round-trip). No new `CfgIds` entry or new queue is
needed; the Identity process's existing `Protocol.run_message_handlers`
dispatch picks it up by function name. This is a design refinement
from the first-draft "new CfgIds entry" approach; it's identical in
effect and substantially smaller in surface area.

Rate limiting: at most **one signal per `from_addr` per 5 seconds**.
The NetProcess keeps a small LRU dict (`from_addr → last_signal_ts`).
This bound is independent of the probe-rate bound in 5.2; it stops
NetProcess flooding IdentityProcess if the other group is chatty.

### 5.2 IdentityProcess side (probe dispatch)

A new handler `handle_partition_signal(self, queues)` drains
`queues[CfgIds.partition_signal]`. For each signal:

1. If `self.group is None` or `self.choosing`: ignore — we're still
   in initial bootstrap, the normal flow will catch up.
2. If we've already sent a probe to this `from_addr` within the last
   **10 seconds**: ignore (per-addr probe cooldown).
3. If we are already merging (see 5.4): ignore.
4. Build a `partition_probe` (4.1) and send via unsecured multicast.
   The probe is **not** directed; any peer in any group can receive
   and respond. (We don't need to unicast because we don't yet have
   a trusted endpoint for the other group.)

The probe cooldown bounds emitted probes to ≤6/minute per
`(self, from_addr)` pair. If the other group has N peers all sending
us group traffic, our cooldown is per *from_addr*, so we'd send up to
N probes per cooldown window — still bounded.

### 5.3 IdentityProcess side (probe receipt)

A new handler `handle_partition_probe(self, queues, message)`:

1. Verify `signature` against `message.from_whom.encryptor.public` (the
   sender's identity public key). Reject if invalid — but **do not log
   loudly** (would let an attacker burn our log volume).
2. Look up `message.from_whom.uuid` in `self.peers`:
   - If they are already in `self.peers` and in `self.group.addresses`
     → they're in our group, just slow to update their local view;
     send a normal `group_key_update` (existing message type) directed
     at them and return. This shouldn't normally happen but is a
     graceful no-op.
   - Otherwise, build a `partition_response` (4.2) and send via
     unsecured multicast. Pick `my_group_leader` as the most recently
     admitted peer in our group whose `peer_rank` ≥ ours (so newer
     peers don't get hammered).
3. Rate limit: at most **one response per probing peer uuid per 30
   seconds**. Prevents a malicious flood-probe from forcing us to
   re-sign and re-broadcast.

### 5.4 IdentityProcess side (response receipt — the merge initiator)

A new handler `handle_partition_response(self, queues, message)`:

1. Verify signature (as in 5.3).
2. Check that `in_response_to == self.identity.uuid` — discard if not
   addressed to us (we may receive responses to other peers' probes).
3. Compare `my_group_size` (theirs) to `len(self.group.addresses)`
   (ours):
   - If theirs > ours, or theirs == ours and `theirs.uuid < ours.uuid`
     → we should adopt theirs. Mark `self._partition_recovery_in_progress
     = (their_group_uuid, when=now())` and proceed.
   - Otherwise → ignore; they will reach the same conclusion when
     they receive *our* probe and respond, and they'll initiate the
     merge.
4. If we're adopting: construct a `request_access` (the existing
   `IdentityProtocol.announce` message — same machinery `announce_identity`
   uses) directed at `my_group_leader_address`. This re-enters the
   normal welcoming-committee path on the responder's side, which
   eventually returns `access_granted` + `full_history` carrying the
   responder's `Group`. Our existing `receive_history` →
   `_merge_to_mesh` adopts it.
5. Set a timeout on `_partition_recovery_in_progress`: if `full_history`
   hasn't arrived within **15 seconds**, clear the flag and allow new
   probes. Without the timeout, a lost-packet `request_access` would
   wedge us indefinitely.

### 5.5 Successful merge

When `_merge_to_mesh` runs (via the normal `receive_history` path)
and adopts the remote group:

- `self.group` is replaced by the remote `Group` (including the
  remote group key)
- `self.peers` is populated with the remote peers from `full_history`
- All previously-dropped group traffic from those peers will now
  decrypt correctly
- `self._partition_recovery_in_progress` is cleared
- The local NetProcess `from_addr → last_signal_ts` LRU is purged of
  any addresses now in `self.group.addresses` (otherwise the cooldown
  would prevent re-probing in a future re-partition)

## 6. Security considerations

**Sybil-amplified merge.** An attacker can spawn N Sybil peers all
claiming to be in a giant group of size M. If we naively accept any
`partition_response` claiming larger size, the attacker drags us into
their group. But:

- Their `partition_response` only tells us "send a request_access here."
- The actual merge happens via `full_history` after their welcoming
  committee accepts us. The welcoming committee runs the existing
  POA voting; a single attacker can't unilaterally admit anyone.
- The full_history payload they send to us must be signed by their
  group key. If their group is genuinely just Sybils, those signatures
  are still cryptographically valid — but every "member" we see in
  their history is a peer we have to evaluate via the reputation system
  before granting them weight. The reputation cold-start (new peers
  default low) limits the damage.

This is no weaker than the status quo: the same Sybil attack works
today against a fresh peer's normal `request_access`. The new protocol
just makes it work against an *existing* peer too. Treat the residual
risk as identical to the existing welcoming-committee Sybil exposure;
hardening the welcoming-committee is out of scope here.

**Probe amplification.** A single attacker sending a stream of
`partition_probe` messages can elicit a `partition_response` from us.
The 30-second per-peer-uuid cooldown (§5.3) bounds the response rate.
With M honest peers in our group, an attacker probing all of them
elicits at most M responses per 30s — bounded by group size, not by
probe rate.

**Cross-deployment leakage.** If two unrelated AT deployments
accidentally share a multicast domain (e.g. a misconfigured staging
+ prod), they will now actively try to merge. This is mostly a
configuration concern, but worth flagging: the multicast group ID and
the AT deployment ID should be different. Today they aren't — there's
no "deployment ID" concept. Out of scope here; file as a follow-up.

## 7. Python implementation outline

Files affected:

- `src/autonomous-trust/autonomous_trust/core/_python/identity/protocol.py`
  - Add `partition_probe = 'group_partition_probe'`
  - Add `partition_response = 'group_partition_response'`
- `src/autonomous-trust/autonomous_trust/core/_python/identity/idprocess.py`
  - Add `_partition_probe_cooldown: dict[str, datetime]` (per-addr probe cooldown)
  - Add `_partition_response_cooldown: dict[uuid_str, datetime]` (per-peer response cooldown)
  - Add `_partition_recovery_in_progress: Optional[tuple[str, datetime]]`
  - Add `handle_partition_signal(queues)` — drains the new internal queue
  - Add `handle_partition_probe(queues, message)`
  - Add `handle_partition_response(queues, message)`
  - Register the handlers in the message-dispatch table (look for how
    `announce` / `accept` / `history` are wired in `process()`)
  - Hook merge-completion: clear `_partition_recovery_in_progress` and
    purge stale entries from the NetProcess LRU
- `src/autonomous-trust/autonomous_trust/core/_python/network/netprocess.py`
  - Add `_partition_signal_lru: dict[str, datetime]` (per-from_addr 5s cooldown)
  - In the `else:` at line 648 (Python) — push signal onto
    `queues[CfgIds.partition_signal]` if cooldown is satisfied;
    keep the existing `_probes.counter` call
  - The error log can be downgraded to debug once the recovery path
    fires (or keep at error for one cycle then quiet — measure first)
- `src/autonomous-trust/autonomous_trust/core/_python/system.py`
  - **No change needed.** The partition signal is routed via the
    existing `CfgIds.identity` queue using `IdentityProtocol.partition_signal`
    as the message function name (see §5.1 design refinement and the
    `rank_update` precedent in `protocol.py:73-78`).

Tests:

- `src/autonomous-trust/autonomous_trust/core/_python/tests/test_partition_recovery.py`
  (new file) — two `IdentityProcess` instances in the same Python
  process, each with its own `self.group`. Simulate cross-group
  message → verify probe/response/request_access sequence → verify
  merged state.

## 8. C implementation outline

Files affected:

- `src/c/autonomous_trust/identity/id_proc.c` and `id_proc_priv.h`
  - Add `static char ID_PROTO_PARTITION_PROBE[] = "group_partition_probe";`
  - Add `static char ID_PROTO_PARTITION_RESPONSE[] = "group_partition_response";`
  - Add the three cooldown maps (`map_t` from `utilities/map.h`) and
    the in-progress sentinel to `proc_id_t`
  - Add C handlers mirroring §5.2-§5.4 logic
  - Register in the message-dispatch table (look at how `welcoming_committee`
    and `handle_acceptance` get wired)
  - Update `proc_id_init` to allocate the maps and the
    `proc_id_finalize` to release them (use `map_destroy` /
    `map_free_values` consistently with how `committed_paxos_rounds`
    is handled in `rep_proc.c` — see the memory `project_dod_demo_status`
    for the conformance work where that map was added).
- `src/c/autonomous_trust/network/net_proc.c`
  - At the `group_decrypt` failure log (line 1305), push a signal
    onto a new internal queue (mirror Python's
    `CfgIds.partition_signal`). The cross-process signal mechanism
    already exists for things like `proc_event_queue`; reuse it.
  - Add the same 5-second per-addr LRU bound.
- `src/c/autonomous_trust/identity/id_protocol.h`
  - If protocol-string headers exist (per the memory
    `project_proto_string_arrays`, they switched from `#define` to
    `extern char X[]`), follow that pattern for the two new strings.

Tests:

- `src/c/test/partition_recovery_test.c` — equivalent of the Python
  test, using whatever fixture pattern the existing identity tests use.

## 9. Conformance corpus impact

Per the memory `project_conformance_corpus`, the corpus pins v1 at
114/114 each side. This protocol extension is a corpus-bumping change.
Concrete deltas:

- New scenario file under `src/conformance/scenarios/`:
  `group_partition_recovery_basic.yaml` — two-peer setup with
  forced split-brain, expected message sequence:
  - peer_A sends group msg → peer_B drops → peer_B emits probe
  - peer_A receives probe → sends response
  - peer_B receives response → sends request_access to peer_A
  - peer_A welcomes (existing flow) → full_history → merge
- New scenario: `group_partition_recovery_size_tie.yaml` — same as above
  but groups are equal size; verify uuid-tiebreak deterministically
  picks the same winner on both sides.
- New scenario: `group_partition_recovery_signal_cooldown.yaml` — flood
  of cross-group traffic from one peer; verify probe rate is bounded
  by the 10s per-addr cooldown (count: <=2 probes in a 15s window).
- Bump the corpus schema string from `"1"` to `"2"` in the README and
  emit a corresponding update in the C and Python parsers (the schema
  pin lives in `src/conformance/schemas/` per the existing layout).
- Synchronous-dispatch hooks (memory `feedback_synchronous_dispatch_pattern`):
  add hook points in both Python and C for the new probe/response handlers
  so conformance tests can drive them deterministically.

Expected end state: 117/117 (or whatever the new total is) each side,
0 asymmetric, `--strict-coverage` clean — same bar as v1.

## 10. Sequencing & owner notes

Implementation order (one commit chain, but multiple sessions):

1. Python side wire-up (§7) — protocol constants, handlers, internal
   queue, NetProcess signal push.
2. Python tests (`test_partition_recovery.py`) — must pass before
   moving on.
3. C side wire-up (§8). Mirror everything from step 1; spot-check
   `id_proc_priv.h` field ordering matches the canonical layout
   (per `feedback_synchronous_dispatch_pattern`, ordering matters
   for memcmp-based test fixtures).
4. C tests — same shape as Python.
5. Conformance corpus updates (§9). At this point both sides should
   produce identical synchronous-dispatch traces; the corpus is the
   tie-breaker if they drift.
6. End-to-end validation: re-run the dod_mission demo and verify the
   coordinator's `cohort.peers` populates within ~10s of stack startup.
   This is the original symptom — its disappearance is the integration
   test.

Approximate effort (subject to revision once we start):

- Steps 1–2: ~half a focused session
- Steps 3–4: ~one focused session (the C-side dispatch table is denser
  and the map lifecycle needs to match `committed_paxos_rounds`)
- Step 5: ~half a session
- Step 6: minutes if the framework work is right; longer if it isn't

## 11. Open questions

- Should `partition_probe` carry the *full* address list of our group,
  not just the size? Doing so lets the responder skip the
  request_access round-trip and immediately send `full_history` to a
  larger-group sender. But it leaks our group composition over
  unsecured multicast — visible to anyone on the link, not just our
  group. **Tentative answer: no, just the size.** The extra round-trip
  is cheap and the unsecured-channel hygiene is worth it.

- Should the merge tiebreaker use group uuid (current convention in
  `_merge_to_mesh`) or first-admitted-peer timestamp (more robust
  against uuid-spamming attacks)? Current convention wins for
  consistency with the existing flood guard; switching it would touch
  the flood guard too. **Tentative answer: keep uuid tiebreak for now,
  re-evaluate if Sybil resistance becomes a priority.**

- How does this interact with the cross-group gateway forwarding
  in `net_proc.c:1237-1265` (`AT_NET_GROUP_FORWARD`)? A gateway is
  intentionally in *zero* groups but forwards between configured legs.
  Should gateways respond to `partition_probe`? **Tentative answer:
  no — gateways skip the probe/response handlers entirely. The
  `is_gateway` check at `net_proc.c:1233-1234` already exists; use
  the same gate.**
