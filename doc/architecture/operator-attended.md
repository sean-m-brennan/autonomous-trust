# The operator-attended signal: which nodes have a human behind them

> Status: Implemented. Durable half (`operator_bound`) shipped in `3effa38`.
> Attended-now half (`operator_attested_at`, consumer-pull) completes it: the
> live IPC gap and the peer-refresh gap described below are closed, in Python
> and C, pinned by three cross-language conformance scenarios.
>
> A **third** signal, `operator_pubkey`, names *which* human — opt-in, off by
> default, and described in "The guardian identity" below.

## Context

[ethne](../../../ethne/doc/design.md), the polity tier above AutonomousTrust, needs a **guardian
edge** per machine member (design item D8): which nodes have a human answerable for them. A polity
that cannot tell an attended workstation from an unattended drone cannot place responsibility
anywhere.

AT answers with two distinct signals, both carried per node and per peer:

| Signal | Question | Lifetime |
|---|---|---|
| `operator_bound` | Does this node have a human guardian at all? | **Durable** — set once at operator activation, persisted with the identity |
| `operator_attested_at` | Is a human at its console **right now**? | **Live** — an epoch stamp, meaningless the moment it ages |

The two answer different questions and fail differently. A node can be `operator_bound` with nobody
at the keyboard for a week; that is a normal state, not an error. What the guardian edge must never
do is read the first as if it were the second.

Neither signal is taken on a peer's word. Both are derived by the receiver from verifying the
operator's actual credential against a **distinct operator trust anchor** — see
[operator-access.md](operator-access.md) for the credential itself (PIV/CAC + MFA) and
[zta-python-parity.md](zta-python-parity.md) for the verification chain. A node that simply asserts
`operator_bound: true` and cannot produce a credential that chains to the operator anchor is
recorded as `false`; that neutralization is pinned by the `operator-bound-lying-rejected`
conformance scenario.

## The problem this design solves

The durable half worked from the start. The live half did not — for two structural reasons, neither
of which showed up in unit tests.

**1. The stamp was always zero on a real node.** Attendance is derived from a live
`OperatorSession`, which the console app builds in its own process. But `IdentityProcess` — the
process that assembles every outgoing attestation — runs in a *separate* `multiprocessing`
subprocess and cannot see that object. `set_operator_session()` existed, but on a real
multiprocess node nothing could ever call it with the real session. `operator_attested_at` was
structurally pinned at 0, forever. Worse, a reader could not distinguish that from an honest "no
one is attending".

**2. Nothing ever refreshed a peer's stamp.** An attestation crossed to a peer exactly once, inside
the `request_access` / `peer_accepted` admission payload. After admission it was never updated. A
consumer reading a peer's `operator_attested_at` was reading *history* — the moment that peer
joined — and mistaking it for attendance.

The fix for (1) turned out to be cheap because of a structural accident: the node's main loop runs
in a **daemon thread of the console app's process** (`bridge.py` → `run_forever`). The main loop
therefore *already shares an address space with the live session*. The only missing hop was
main-loop → identity-subprocess, and that hop had an established pattern — local-only IPC verbs
(`tier_update`, `partition_signal`) that never reach the wire.

## Key decisions

**Consumer-pull, not keepalive.** Freshness is established when someone asks, not by re-announcing
on a cadence. A periodic re-announce was considered and rejected: it puts constant attestation
traffic on an idle network to answer a question nobody asked, and it *still* serves a stamp that is
up to one interval stale. Pull inverts that — an idle network carries no attestation traffic at
all, and staleness is bounded by a round trip taken at the moment of asking.

**No cached session mirror.** The identity process stores no copy of the session state. It could
have — that would make answering a pull instant — but a cached mirror is precisely a thing that can
be stale, and this signal exists to not be stale. The cost is a local round trip per pull and a
pending-pull state machine; the benefit is that there is no stale state to serve.

**The nonce is load-bearing.** Each pull mints a nonce; the answer echoes it; the requestor retires
it on receipt. Without it, a signed attestation could be captured once and re-presented forever,
which would make "attended now" mean "attended at some point" — the exact failure the signal
exists to prevent. An answer is good exactly once.

**Verification lives with the verifier.** The pull is issued and checked by `IdentityProcess`, not
by the main loop, because an attestation is worth nothing until its credential is re-verified
against the operator anchor — and that anchor lives in the identity process beside the admission
gate. The process that *can* verify is the process that asks. The main loop keeps only the
consumer-facing API and the answer table.

**Silence resolves to an answer.** Every pull, in both directions, has a deadline. A node whose
console never replies, or a peer that has gone quiet, resolves to *not attended* rather than
hanging. For a guardian edge, "cannot confirm a human is present" and "no human is present" are the
same operational answer; an unbounded wait is the only genuinely useless outcome.

## The guardian identity (`operator_pubkey`) — opt-in

The two signals above answer *whether* a human stands behind a node and *when* one was last there.
Neither says **which** human, and for a long time nothing did: the operator credential is a PIV/CAC
X.509, which holds no ed25519 key that could become a `did:key`. That mattered more than a missing
field usually would, because ethne's chartered node→guardian edge (**D15**) requires a guardian to
*co-sign* — a guardian who cannot sign is unusable, so a chartered rule was running with no live
source at all.

A node may now advertise `operator_pubkey`, the guardian's ed25519 public key, together with
`operator_key_binding`, a signature by that operator's PIV private key over

    "at-operator-binding-v1" || uuid (16) || node signing key (32) || operator key (32)

verified at admission against the credential's own public key — the same credential the gate has
already classified operator-class against the distinct operator anchor. Both halves are required
and neither substitutes for the other: **a chain without a binding names no human, and a binding
whose credential is not operator-class is a human with no standing to name one.**

**Opting out is free, and that is a rule, not a default.** AT never requires a guardian identity. A
node that declines is admitted identically, keeps `operator_bound` and its attendance stamp, and
serializes byte-for-byte as it did before this field existed — both fields are emitted only when
non-default, so a declining node puts nothing on the wire. A consumer that *requires* a guardian is
applying its own rule; that is ethne's business, and there absence means "unguarded machine", never
an error.

The reason to protect that is specific. **One key per operator, stable across every node that human
guards** — per-node keys would let one person present as N guardians, which is ethne D24's chorus
moved down a layer. But a stable key is a persistent pseudonym: anyone watching two cohorts can link
an operator's nodes to each other. That is a real cost, paid by a real person, so it is theirs to
choose. Off by default is the mitigation, and the CLI is where the choice is made
(`--bind-operator-key` on activation) rather than the TUI's recurring unlock screen — a decision
that de-anonymizes a whole fleet does not belong on a daily login prompt.

The pre-image names the node deliberately. Without the uuid and signing key inside the signed
bytes, a `(key, binding)` pair lifted from another node's clear-text announce would let any node
claim that human, and a count of guardians would mean nothing. This also gives ISSUES.md §1.5 a
narrow, honest answer for opted-in operator nodes — and none at all for anyone else.

**What a bad binding costs.** Absent: no guardian key, nothing else changes. Present but invalid —
forged, naming another node, wrong length — the key is refused and the peer is stored without one.
`operator_bound` is **not** demoted: it was earned independently from the anchor, and node key
rotation legitimately stales a binding, so demotion would turn an honest re-keying into a lost
credential. Losing a guardian edge is the failure mode; losing admission is not.

Two limits worth stating. The operator's ed25519 key is software-held, so a stolen keystore
impersonates that human on every node they guard — hardware-held ed25519 is the successor. And
distinct guardian keys are still not distinct humans; ethne must not count them as such without an
independence attestation (its D24 finding), which is not built here.

## Protocol

Four verbs (`identity/protocol.py`), two on the wire and two local-only:

| Verb | Scope | Payload |
|---|---|---|
| `attest_req` (`operator_attest_query`) | wire | `{nonce}` |
| `attest_resp` (`operator_attest_response`) | wire | `{nonce, operator_attested_at, ...attestation}` |
| `attest_trigger` (`operator_attest_trigger`) | local | `{target}` — consumer asks its own node to pull a peer |
| `operator_state_req/resp` (`operator_state_query/response`) | local | `{}` / `{attended, epoch, have_session}` |

A pull, end to end:

```
 consumer                    node A (puller)                        node B (target)
 ────────                    ───────────────                        ───────────────
                             main loop        identity proc         identity proc       main loop
 request_peer_attestation ──▶ attest_trigger ─▶ mint nonce
                                                └── attest_req ─────▶ record pending
                                                    (wire)           └─ operator_state_req ─▶
                                                                     ◀── operator_state_resp ─┘
                                                                        (reads OperatorSession)
                                               ◀─── attest_resp ─────┘ stamp + echo nonce
                                                verify: nonce,
                                                credential, window
                             peer_attestations ◀┘ record verdict
```

`operator_attested_at` is **always present** in the answer, including as an explicit `0.0`. "Asked,
and nobody is attending" is a real answer and must not be confusable with "declined to say".

### What the requestor checks

Three independent checks, all of which must pass before a stamp is recorded:

1. **Nonce** — one we minted and have not retired. Kills replay.
2. **Credential** — chains to the distinct operator anchor, with its hash recomputed from the
   actual bytes (`_is_operator_credential`, the same gate admission uses). Kills a node talking
   itself into operator class.
3. **Window** — the stamp sits within `_ATTEST_WINDOW_SEC` (120s) of our clock. Kills a peer minting
   permanent freshness by stamping far ahead.

Any failure records *not attended* rather than raising. Note that (2) and (3) are independent: a
peer that verifies but reports `0` is genuinely operator-bound hardware with nobody at the console,
and is recorded exactly that way — `operator_bound: true`, `operator_attested_at: 0`.

## Python / C asymmetry (deliberate)

C has no `OperatorSession` and no console app — there is no PIV/MFA in C, by design. So:

- **Python** derives attendance by polling the live session, reached via the local
  `operator_state_query` round trip to the main loop.
- **C** answers from the `identity_set_operator_attended()` seam in one hop.

The asymmetry is confined to *where the attended state comes from*. The verb shape, the payload,
the always-present zero, the nonce state machine, and all three verification checks are identical.
The single definition of "attended" for Python lives in `operator/session.py::is_attended`, shared
by both the in-process seam and the main loop so the two cannot drift.

## Verification

Unit tests: `tests/a_unit/test_operator_attestation.py` (63 cases — data model, admission gate,
responder round trip, requestor verification incl. replay/imposter/window edges),
`src/c/test/operator_attestation_test.c` (10 cases), and bridge wiring in
`autonomous-trust-operator/tests/a_unit/test_operator_tui.py`.

Cross-language conformance (`conformance/scenarios/identity/`):

| Scenario | Pins |
|---|---|
| `attest-pull-attended` | ACTIVE session ⇒ the pinned epoch |
| `attest-pull-unattended` | LOCKED session ⇒ explicit `0.0` |
| `attest-pull-replay-rejected` | re-presented answer refused; recorded stamp unchanged |
| `operator-bound-verified` | operator credential ⇒ `operator_bound: true` |
| `operator-bound-lying-rejected` | asserted claim on a non-operator credential ⇒ `false` |
| `operator-key-bound-verified` | a binding signed by the presented credential ⇒ the guardian key is kept |
| `operator-key-binding-forged-rejected` | same everything, signed by an unrelated key ⇒ refused, `operator_bound` still true |
| `operator-key-bound-to-another-identity-rejected` | a perfect signature naming a *different* node ⇒ refused (ISSUES §1.5's harvested credential) |
| `operator-key-absent-is-normal` | the opt-out: bound, attended, no guardian, no penalty |

Those four bindings are **signed at scenario time** by both adapters from
`testdata/zta/certs/operator_leaf.key`, not pinned as recorded blobs. That is deliberate: a pinned
signature would hold the two implementations to one of them having saved its own output, whereas
signing live holds them to the same pre-image and the same scheme. RSA PKCS#1 v1.5 over SHA-256 is
deterministic, so they agree byte for byte or the scenario fails. The leaf's private key is
committed for exactly this reason — it is a test anchor with standing nowhere.

The clock is **pinned** in these scenarios (`fixtures.operator_session.clock`), never wall-clock: a
live stamp could not match across two runs, let alone two languages.

## Consuming the signal

```python
node.request_peer_attestation(queues, peer)        # hand-off; returns immediately
...
stamp = node.peer_attestations.get(str(peer.uuid), 0.0)
attended_now = stamp > 0.0                         # already verified when it lands
```

The pull is asynchronous: the answer arrives on `peer_attestations` when it arrives, or resolves to
`0.0` at the deadline. A consumer should treat "not yet answered" and "answered zero" the same way
— which the deadline guarantees it can, since every pull terminates.

`ethne` reads this through its own node rather than talking to AT peers directly; the ethne-side
adapter is out of scope here.
