*Previous: [TCP Connection Pooling](network-connection-pooling.md)*

<!--
 Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
 Licensed under the Apache License, Version 2.0.
-->

# Network Wire Format

**Status (2026-08-18): BUILT in both runtimes.** This document is the reference
for the wire format; source comments point here. Format *detection* — a node
working out which format a peer is speaking — is deliberately **not** built. The
open questions are `R+D.md` §2.5, and
[Why detection is not here](#why-detection-is-not-here) says why.

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

Python: `NetworkProcess._wire_format_for_addr` / `_wire_format_for_group`.
C: `wire_format_for_address` in `net_proc.c`. Both are group lookups. Neither
looks at the arriving bytes.

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

The proto parser is additionally strict about emptiness: a frame must carry a
non-empty `process` and `function`. Protobuf decodes plenty of arbitrary byte
strings into an all-defaults message, and without that check a corrupt frame
becomes a message addressed to process `""` that routes nowhere with no
diagnostic.

## Why detection is not here

The obvious next step — let a node work out a peer's format from the frame — was
scoped and then **declined for now**, because it turns the format marker from a
guard into an input. The questions it opens are not implementation details:

- Which nodes may sniff at all? (A gateway bridging two cohorts has a reason to;
  an internal node does not.)
- May an internal node **opt in** to reading a foreign format from a foreign
  sender, and what counts as foreign — an unplaced first-contact sender, a
  member of another known group, or both?
- If it reads one, does it **reply in kind** (per-peer local state, never
  serialized) or always answer in its own group's format?
- Should the exception be scoped to identity/negotiation traffic, so a foreign
  format can get a node admitted but cannot inject payloads into data or
  application processes?

Those are recorded as `R+D.md` §2.5. **Do not add sniffing to either runtime
without settling them** — the strict gate above is what makes the current design
safe, and it is one `if` away from not being.

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
