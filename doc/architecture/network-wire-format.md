*Previous: [TCP connection pooling](network-connection-pooling.md)*

<!--
 Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
 Licensed under the Apache License, Version 2.0.
-->

# Network wire format

**Status (2026-08-18): BUILT in both runtimes. Gateway boundary enforced
2026-09-03.** This document is the reference for the wire format; source
comments point here. Format *detection* — a node working out which format a peer
is speaking — is **not built and not needed**: under the two invariants in
[The gateway boundary](#the-gateway-boundary) every frame's format is known
before the frame is read. That closed `R+D.md` §2.5.

An inter-host AT message is an envelope around a payload. The envelope has
carried the same eleven fields since the beginning; what changed is that it can
now be encoded two ways.

| | JSON envelope | Proto envelope |
|---|---|---|
| Encoding | `{"process":…}` via jansson / `json.dumps` | packed `network/net_message.proto` |
| Payload | base64 text | raw bytes |
| Public keys | 64 hex chars each | 32 raw bytes each |
| Signature | 128 hex chars | 64 raw bytes |
| Sender uuid | hyphenated string | 16 raw bytes |
| Leading byte | `{` (0x7B) | `0xAB` marker |

The saving is the reason it exists: a small signed `request_access` goes from 554
bytes to 241, and the keys plus signature alone cost 320 bytes of hex on every
signed message. On a DDIL link that is not a rounding error.

## Two invariants

**1. The signature pre-image is not the envelope.** Both forms sign the same
canonical string:

```
<process>|<function>|<base64(data)>
```

base64 of the payload, *even in the proto form where the payload rides raw*. So
one message has one signature whichever way it is encoded, and re-encoding it
cannot invalidate that signature. Signing the packed protobuf instead would have
been the obvious choice and is wrong: protobuf encoding is not canonical, so two
conformant encoders may emit different bytes for the same message and each would
then reject the other's signature. `wire_signable_content` (C) and
`Message._signable_content` (Python) are the one copy of this rule per runtime,
shared by both encodings.

**2. A packed envelope is never on the wire bare.** It is prefixed with one
byte, `0xAB`. A JSON envelope always begins `{`, so one byte decides which
parser a frame is *eligible* for — before any parser runs. The marker is also
the version slot: an incompatible future envelope takes `0xAC` and is
distinguishable rather than guessed.

## The format belongs to the group

Not to the node, and not to the peer pair.

```
group.wire_format = json | proto        # travels with the group key at admission
```

A cohort in which two members disagree cannot talk, and nothing reconciles a
disagreement after the fact. So the format is a property of the group: it rides
the canonical group wire form (`wire_format`, the same lowercase name in both
runtimes) and `identity.proto`'s `Group.wire_format`, and a joining node
**adopts** it at admission rather than applying its own preference.

`AT_NET_WIRE_MODE=json|proto` (default `json`) applies at exactly one moment:
the group a node **mints**. An operator stands up a proto cohort by setting it on
whichever node forms the group; every joiner inherits it. Python:
`system.resolve_net_wire_mode` → `Group.initialize`. C:
`net_wire_mode_resolve` → the genesis mint in `id_proc.c`'s `choose_group`.

On a merge, the surviving group's format comes along with its uuid and address
map (`adopt_membership` / C `handle_group_update`). The merge winner is already
decided by size → age → uuid, so the format needs no tiebreaker of its own.

**A group's format never changes in place.** An update for the group a node
already holds (same uuid) brings membership and keys, never a format: the
node keeps its own. The update announcing a change would reach the members in
the format they cannot yet read, and the cohort would split with nothing to
bring it back. A format change takes a new group. Pinned by
`identity/group-update-same-uuid-keeps-format`.

**A proto group refuses a group that names no format.** An absent (or
unrecognized) `wire_format` reads as JSON, which is right in a JSON cohort and
for every group from a peer that predates the field. In a proto cohort it is
wrong in a way nothing surfaces: a member that took such a group would speak
JSON to peers that refuse it, and silence is not scored. So a node whose own
group is proto refuses the group instead: in a group update, a solicited join
answer, and the merge out of a self-bootstrap (whose peers still count). A
node holding a JSON group, or none, reads it as JSON as before. The rule is
`Group.refuses_formatless` / C `group_refuses_formatless`, counted as
`id.group/formatless_refused`. Pinned by
`identity/group-update-formatless-refused-by-proto` and its control
`identity/group-update-formatless-read-as-json`.

### Selection, both directions

| Traffic | Format |
|---|---|
| Broadcast / discovery | **JSON**, always |
| Peer we can place in a group we hold | that group's format |
| Peer we cannot place (stranger, pre-admission) | **JSON** |
| Group channel | the group whose key opens it |
| Gateway → child cohort | that cohort's format |

**Bootstrap is JSON unconditionally.** Discovery happens before there is a group
to consult, and its receivers include nodes holding no group at all. That is what
keeps a proto cohort joinable by any node — and what makes this shippable without
a flag day.

The lookup is `NetworkProcess._wire_format_for_addr` and
`_wire_format_for_group` in Python, `wire_format_for_address` in `net_proc.c` on
the C side. Both are group lookups, and neither of them looks at the arriving
bytes.

## Receiving is strict

A receiver is **told** which format to expect and refuses a frame whose marker
disagrees:

- Python raises `WireFormatMismatch` (a `ValueError` subclass, so existing
  refusal handling still classifies it), and `_msg_to_queue` counts
  `net.wire/drop/foreign_format` with a rate-limited log.
- C returns `ENET_WIRE_FORMAT` (233), readable off `_exception.errnum`.

Two things fall out of that, both deliberate:

- On a JSON-format node, **the protobuf parser is never handed peer-supplied
  bytes**, and vice versa. Half the attack surface of carrying two formats is
  simply not reachable.
- A misprovisioned cohort is **diagnosable**. Without a distinct refusal it
  presents as one peer having silently gone quiet; the counter is the only thing
  that says why.

### Except where the bytes are not known to be an envelope

One receive path gets the marker's verdict but not its *meaning*: the
point-to-point frame from a sender we cannot yet place. There the bytes are as
likely to be ciphertext awaiting the sender's admission as they are an
envelope — and ciphertext is uniform bytes, so **one such frame in 256 opens
with `0xAB` by chance**. Read as a foreign-format drop, those frames were
discarded instead of deferred, which surfaced as an intermittent
`Dropping point-to-point frame ... refusing a proto envelope` on a cohort where
both nodes speak JSON (`tests/b_integration/test_two_node.py`).

So on that path a refusal means only "not a plaintext JSON envelope", the same
verdict a `UnicodeDecodeError` carries, and the frame is deferred for retry once
the sender is known. Python: `_msg_to_queue(..., opaque=True)` re-raises rather
than counting a drop, and the caller defers. C already did this — every parse
failure in `handle_inbound_peer`'s unknown-sender branch reaches
`defer_message`. Everywhere the bytes *are* known to be an envelope — a frame
that decrypted, or the multicast/discovery channel, which never carries
ciphertext — the refusal keeps its counter and its rate-limited log.

The proto parser is additionally strict about emptiness: a frame must carry a
non-empty `process` and `function`. Protobuf decodes plenty of arbitrary byte
strings into an all-defaults message, and without that check a corrupt frame
becomes a message addressed to process `""` that routes nowhere with no
diagnostic.

## The gateway boundary

Two invariants, both **normative**. They are assumptions the rest of this
document rests on, and until 2026-09-03 they were only implicit — which is why
they are written down here rather than left to be inferred from the code.

> **G. A group stops at the gateway.** A gateway is a full **member** of each
> cohort it bridges. No group spans a gateway, so no address but the gateway's
> own may appear in two of the groups it holds.
>
> **B. Bootstrap does not cross the gateway.** The pre-admission handshake —
> `request_access`, `access_granted`, `full_history` — is domain-local.

B is what **enforces** G. The only way a group comes to span a gateway is for a
node on one side to be *admitted* by a cohort on the other, and those three
verbs are the only ones that move membership. Everything else crosses freely:
`group_key_update` moves membership but not admission, and the partition pair
deliberately spans a group-*key* boundary
([partition recovery](partition-recovery.md)) while staying inside one domain.

### What they buy: detection is unnecessary, not merely deferred

With both invariants held, the case analysis on an arriving frame is **total**:

| The sender is… | The format is… | How we know |
|---|---|---|
| a member of a group we hold | that group's format | address → group lookup |
| a local unadmitted node | JSON | the bootstrap rule |

There is no third case. Cross-domain traffic reaches a node only from a gateway
that is *itself a member of that node's group*, so it arrives in the group's own
format like any other member's traffic; and bootstrap never traverses the
boundary, so a remote domain cannot reach a node's pre-admission path at all.

That is a stronger statement than the one this document used to make. Format
**detection** was previously described as risky and deferred, with its open
questions parked in `R+D.md` §2.5. Under G and B it is not needed: every frame's
format is already known before the frame is read. §2.5 is closed on that basis —
what remains open there is not detection but the residual items listed below.

It also narrows the one surface two formats cannot avoid. Bootstrap is
unconditionally JSON, so every node runs the JSON parser no matter what its
cohort speaks; B confines the population that can exercise it to nodes **on the
local segment**, rather than anyone who can route to a gateway.

### A case that works without anyone designing it

Two groups with *different* formats can still complete a merge. `_update_group`
addresses a peer in another group, which the lookup cannot place → JSON; the
receiver cannot place the sender either → it expects JSON. Both sides fall to
JSON independently and the `group_key_update` gets through.

This is worth stating because it is load-bearing and accidental-looking. Without
it a cross-format merge would **deadlock**: the message that tells a node to
switch formats would itself be encoded in the format that node cannot yet read.
Pinned by `network/cross-group-format-fallback`.

### How they are enforced

Refusals are counted and logged (rate-limited) rather than silent, for the same
reason the foreign-format drop is: a boundary violation presents downstream as a
peer having gone quiet, and the counter is the only thing that says why.

| Check | Python | C |
|---|---|---|
| Bootstrap never rides the group channel | `_msg_to_queue`, `rcvd_by == 'group'` | `handle_inbound_group` |
| Bootstrap not accepted from a cohort we gateway | `_msg_to_queue` + `_crosses_gateway` | `handle_inbound_peer` + `address_crosses_gateway` |
| Bootstrap not sent to a cohort we gateway | outbound peer branch | outbound send path |
| No address in two groups we hold | `_groups_containing` on group send + group receive | `held_groups_containing` on the send path |

Probe counters: `net.boundary/drop/{bootstrap_on_group_channel,
bootstrap_across_gateway, group_spans_gateway}`. Every one of these is a
**gateway-only** gate — `_crosses_gateway` is false without child groups, and
the two-group count cannot exceed one on a leaf — so a leaf node takes exactly
the historical path.

The verb set itself is two hand-maintained lists in two languages
(`identity.protocol.BOOTSTRAP_VERBS`, C `ID_BOOTSTRAP_VERBS`), so its membership
and size are pinned by `network/gateway-boundary-verbs`. Its sibling, the
plaintext set, has two halves: the core's nine (`CORE_UNENCRYPTED_VERBS`, C
`ID_UNENCRYPTED_VERBS`) and the extension verbs that `unencrypted_verbs.cfg.json`
grants (see [Plaintext verbs](extensions.md#plaintext-verbs-processesplaintext_verbsh-plaintext_verbspy)).
It is pinned by `network/unencrypted-verbs`, which also holds the one
relationship between the two sets that matters: they overlap on the two verbs that run before a key
exists, but `full_history` is bootstrap and must **never** be accepted in
plaintext, because it hands over the group key.

### The one configuration that can violate G

Decided 2026-10-20 (the user's call, `ISSUES.md` §2.12 shape 4): forwarding is
allowed only in a JSON deployment. A node with `group_forward` on never mints
a proto group: `net_filters_check_config` refuses to start it when
`AT_NET_WIRE_MODE` resolves to `proto`, the only input to the format of a group
it mints. That keeps a forwarded frame's format knowable without a lookup,
since it can only be JSON, but only while the cohorts on both legs are JSON
too. The forwarding node cannot check that: it holds none of the groups it
forwards for. The operator has to keep those cohorts JSON.

`group_forward` (a network-config switch of libat_gateway, **off** unless the
node's network config sets it alongside `"envelope": true`) lets a gateway relay
opaque group ciphertext across transport legs by operator-configured
`dst_uuid → leg` route (the gateway's group-channel filter,
`src/c/extensions/gateway/gateway.c`, at-over-dtn stage F). It forwards
precisely *because* it is not in the group, which is a group spanning a gateway
by construction — and with it a foreign-format frame can reach internal nodes,
putting every §2.5 question back on the table. Enabling it is therefore not a
transport tuning decision; it is a decision to give up invariant G and the
"detection is unnecessary" argument that rests on it.

Note the boundary gates above do **not** catch it: they key on address→group
maps and on bootstrap verbs, and a forwarded frame is opaque ciphertext from an
address in no group we hold, so it takes the forward branch and returns before
any check runs.

## What a frame may carry, by its path

Every inbound frame reaches its process through one funnel, C
`route_to_process` and Python `_msg_to_queue`, and the funnel knows which path
the frame came in on. Before routing it asks `net_wire_verb_admitted` (Python
`wire_verb_admitted`) whether the frame's process and function may arrive that
way (ISSUES §2.17):

| Path | What it may carry |
|---|---|
| any | never an `app_*` verb: those are the local app's commands, and no node sends one to another |
| any | to the network process, only a remote `stats_req`: an `exclude` from the wire would gate peers for us, and any other function was re-sent stamped as ours |
| plaintext from an address we cannot place; relayed from a uuid we do not hold | only the plaintext verbs (core and granted) |
| broadcast | the plaintext verbs, plus the identity verbs sent with no recipient: `group_key_update`, `peer_accepted`, `propose_peer` (C `ID_BROADCAST_ONLY_VERBS`, Python `BROADCAST_ONLY_VERBS`) |
| from a peer we hold, or group-encrypted from one | anything the first two rows do not refuse |

The check is made on the frame's names, never on the sender it claims. On a
stranger's paths `from_whom` is the envelope's claim, and a stranger chooses
it: leaving out `from_uuid`, or claiming ours, passed every handler's
local-origin check (`identity_is_local_app_verb`). That check stays in every
app verb's handler, core and social, as a second line.

The group channel reads a frame as from the peer we hold at its address (or,
through a gateway, at its source uuid), and drops one from anybody else.
Before §2.17 C took the envelope's claim there with no lookup, so anyone
holding the group key could say it was anyone; Python already dropped a
non-peer.

A refusal is logged at INFO, the first 20 and then every 100th (`refusing
<process>.<function> from <address> on the <path> path: <why>`), so a
legitimate verb the lists miss shows in the first cohort log.

## What is pinned

Conformance (`protocol: network`), both runtimes:

| Case | What it holds
|---|---|
| `message-envelope-proto-roundtrip` | exact proto bytes, inline hex |
| `message-envelope-proto-empty-obj` | exact bytes for an absent (proto3-default) payload |
| `message-envelope-format-parity` | the two encodings decode to the same message |
| `wire-format-mismatch-refused` | the strict gate both ways, and that the refusal is format-specific |
| `wire-mode-resolution` | the `AT_NET_WIRE_MODE` table, including refusals |
| `group-wire-format-canonical` | the group field's name, both values, and the absent/unknown readings |
| `cross-group-format-fallback` | a group answers JSON for any address it cannot place — the cross-format merge handshake |
| `gateway-boundary-verbs` | the membership AND size of the pre-admission verb set, both runtimes |
| `unencrypted-verbs` | the plaintext allowlist, its size, and that `full_history` is bootstrap yet never plaintext |
| `wire-verb-policy` | what a frame may carry on each path: 24 cases, both directions |
| `transport-binds-the-recipient` | the envelope's `from_*` claim is read ONLY with no transport peer — both formats |

The proto bytes are pinned as **inline hex in the vector**, not a fixture file,
so a change in wire shape shows up in a diff a reviewer reads. They are compared
**literally**, unlike the JSON pins' JCS-canonical comparison: protobuf has no
canonical form to normalize toward, and that strictness is the point — field
order and default-value handling drifting between the runtimes is exactly the
risk worth pinning.

C unit coverage lives in `test/net_message_test.c` (round trip, the size saving
measured rather than assumed, cross-format signature identity, the mismatch
gate, garbage behind a forged marker, binary identity round trip, format names).

---

*Next: [Partition recovery](partition-recovery.md)*
