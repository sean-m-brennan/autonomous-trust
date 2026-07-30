# The app-facing peer carrier: what a hosting application learns about peers

> Status: Implemented (C). Two local-IPC message types, a pull verb, a flat
> app-facing ABI, and fixes to five independent breaks in the app-facing path.
> The `ethne` adapter that consumes this is the next slice.

## Context

[ethne](../../../ethne/doc/design.md), the polity tier above AutonomousTrust,
builds its view of the machine substrate from AT's peers. Its adapter needs six
facts per peer: a stable identity, a topology rank, both operator signals, and
earned reputation with an honest "unrated" case.

AT had all six. None of them reached an application.

## The problem this design solves

The app-facing path was broken in five independent places. Any one of them
would have been enough to deliver nothing, which is why the path had never
worked and why nothing had noticed.

**1. Nothing produced peer data.** No process sent anything peer-shaped toward
the daemon's queue. This is the gap the carrier itself fills.

**2. Two of the three app-bound routing arms had no reachable producer.** The
daemon forwarded `TRANSACTION_SCORE` outward, but every producer sent that
message to the *reputation* process instead. `TASK_RESULT` was worse: the
negotiation process sent it to `"main"` — a queue name `messaging_init` is
never called with anywhere in the tree, so those datagrams addressed a socket
path that does not exist. Only the fleet process's `UPDATE_ACCEPTED` was
actually addressed to the daemon.

**3. The drain built a batch and threw it away.** The loop appended each
app-bound message to a local `extern_msgs` array, then never sent or freed it —
sending, instead, the *last message the loop happened to receive*. With at most
one message in flight per iteration that coincided with correct behaviour,
which is why it survived: the bug was invisible exactly as long as the traffic
was too sparse to expose it. Two messages in one iteration meant one delivery.

**4. Nothing was listening.** The daemon sends to the `q_out` name it was
launched with; `at_node_start` bound `config.app_name`. The shipped example set
those to different strings, so the daemon's datagrams went to an unbound path.
Nothing errored on the app side — there was simply never anything to receive.

**5. The drain switched on the payload, not the type.** The loop queued its
message with `object_ptr_data(&result_msg.info, ...)` — a pointer to the
*union* — and the drain read each entry back as a whole `generic_msg_t` and
switched on `->type`. `info` sits at offset 16, so `->type` read the first
eight bytes of the payload. For an `UPDATE_ACCEPTED` that is the front half of
a UUID: measured at `-6366218896703053408` where `12` was meant. The one arm
with a live producer could not match either, and a message whose payload
happened to begin with a small integer was misrouted to a sibling process.

Together: the app-facing stream carried nothing at all.

## Key decisions

**Two messages, joined by the consumer.** `PEER_OBSERVED` comes from the
identity process (uuid, signing key, rank, both operator signals);
`PEER_REPUTATION` comes from the reputation process (score, rated). The split
follows process ownership, not consumer convenience. The alternative — one
assembled message — needs the score pushed into the identity process, which
means a cached second copy of the score store living where nothing reads it,
and a rank pushed into every process that the comments say only identity reads.
Joining two facts on a uuid is the consumer's job and costs it a small table.

**Emitted to the daemon queue, not to the app.** A sub-process does not know
the app's queue name. It sends to `AT_MAIN_QUEUE` and the main loop owns the
outward hop — the route `UPDATE_ACCEPTED` already took.

**`rated` is a separate field, not a sentinel.** AT scores are anchored by
fixed constants rather than normalized across the population, so the number
crosses as-is. But an unrated peer reads as exactly `PREREP_NEUTRAL`, which is
also a score a peer can genuinely earn, so no numeric value can mean "no
information". The flag carries it, and the score is zeroed when unrated so a
consumer that ignores the flag cannot read a plausible number by accident.

**`rated=false` can only cross on a pull.** Every change-driven emission is by
construction rated — the process just committed a score. The roster pull walks
the peer table instead, so it is the only path that reports a peer AT has never
scored. That makes the pull load-bearing for the distinction, not merely a
convenience.

**Consumer-pull for the full view.** The carrier is event-driven, which shows a
late-attaching consumer nothing. A pull re-emits everything currently held.
Same reasoning as the attestation verb: freshness is established when someone
asks, and an idle network carries no traffic to answer a question nobody asked.

**One inbound verb, allowlisted, at a fixed pair of processes.** The pull is a
`NET_MESSAGE` function string, following the established local-only-verb
pattern (`tier_update`, `attest_trigger`, `local_rep_query`) — typed messages
dispatch through one shared switch that cannot reach process-specific code.
The daemon accepts exactly this one function from an app and forwards it only
to identity and reputation. Forwarding a `net_msg` to whatever process it names
would hand an application AT's entire internal verb surface.

**The attendance stamp is gated on the verified binding.** `operator_bound`
false means the stamp is emitted as `0`, at the emitter and again in the ABI
decoder. An attendance claim from a node whose operator credential never
verified attests to nothing, and a consumer that received one would have to
know to distrust it.

**A flat ABI for foreign consumers.** `app_events.h` exposes fixed-width
structs and four functions. A consumer outside C should not reproduce
`generic_msg_t`: it is a tagged union whose size and offsets depend on
`public_identity_t`, `group_t`, `net_msg_t` and the ZTA build flag, so a
hand-written mirror would corrupt silently the first time any of those changed.

## Protocol

| Message | Direction | Producer | Payload |
|---|---|---|---|
| `PEER_OBSERVED` | AT → app | identity | uuid, ed25519 signing key, rank, `operator_bound`, `operator_attested_at` |
| `PEER_REPUTATION` | AT → app | reputation | uuid, score, `rated` |
| `app_roster_request` | app → AT | — | none (a `NET_MESSAGE` function) |

Both carrier types are **local IPC only**, the same standing as
`PEER_RTT_UPDATE`: they are not part of `identity.proto` or
`public_identity_t` network serialization, so this slice changes no wire format
and needs no cross-language conformance scenario. (A judgment call, on the
`PEER_RTT_UPDATE` precedent.)

```
 identity proc ──PEER_OBSERVED────┐
                                  ├──▶ AT_MAIN_QUEUE ──▶ drain ──▶ q_out ──▶ app
 reputation proc ──PEER_REPUTATION┘         (main loop)                  (joins on uuid)

 app ──app_roster_request──▶ q_in ──▶ {identity, reputation} ──▶ re-emit everything held
```

Emission points: a peer is added (provisional or confirmed — two-phase
admission gates the group key, not visibility); its rank is recorded; an
operator attestation is verified; a score is committed (compute, slash, or
rehabilitation); or the app pulls.

## Honest limits

**The live feed is upsert-only.** Nothing anywhere removes an entry from
`protocol.peers[]`, so there is no departure event to emit and none is defined.
A consumer grades absence by staleness against its own clock — which is what
ethne's cohesion machinery already does. Reputation's communication cut-off is
a network exclusion, not a roster departure, and is not reported as one.

**The view is this node's admitted peers, not the gateway subtree.** The
subtree roster (`identity_aggregate_subtree_roster`) carries uuid, nickname and
address — no signing keys — so it cannot feed a key-identified peer. An
opaque-boundary signal is likewise not emitted: it would only be meaningful
alongside a subtree view this carrier does not provide.

**There is no guardian identity.** `operator_bound` says a human exists and
`operator_attested_at` says when one was last verified present, but AT never
carries *which* human: the credential is a PIV/CAC X.509 with no ed25519 key to
become a `did:key`. A consumer needing a guardian that can *sign* — ethne's
chartered node→guardian edge requires guardian co-signature — cannot build one
from this carrier. Closing that means binding an operator ed25519 key with the
PIV credential and advertising it: a wire-protocol change, and its own slice.

**No dead fields.** None of the three limits above is represented by a field or
message type that nothing sets. A carrier field with no producer is
indistinguishable, to a consumer, from one whose producer is broken.

## Verification

`src/c/test/app_events_test.c` — 20 cases, 134 checks, driven through the
messaging test hook, plus two that use real unix sockets because a hook cannot
see a queue-name mismatch (break #4's failure mode), and three that enter
through an admission path (see "Two further breaks" below).

Each break is pinned by a test that was **confirmed to fail** when the defect
was reintroduced:

| Break | Regression test | Reintroduced ⇒ |
|---|---|---|
| #3 batch discarded | `drain_sends_every_app_bound_message` | 21 failures; `accept_count 22 != 11` — only the last message left |
| #5 payload-as-tag | `drain_routes_on_the_type_tag_not_the_payload` | 21 failures; the message routed to `reputation` |
| #4 wrong queue name | `app_bound_to_the_wrong_name_receives_nothing` | paired with the real-socket delivery test, so neither passes vacuously |

Negative controls run: no app attached; a never-scored peer; an unverified
operator's stamp suppressed; `EAGAIN` mid-batch not abandoning the rest; an
unroutable type dropped without a send; an empty roster pull emitting nothing;
a non-allowlisted inbound verb refused.

Full suite: **82/82** (`ctest`), library **0 warnings**, up from an 81/81
baseline.

**Not verifiable in-sandbox:** a live-daemon end-to-end run. The daemon aborts
with `*** stack smashing detected ***` during startup here — including on the
unmodified `at_demo -g` path, which touches none of this code — so break #4's
fix is verified at the mechanism level (real sockets, matching and mismatched
names) but not against a running daemon. See ISSUES.md §2.1.1, which records
that the abort does not reproduce on a host machine.

**Verified on a host, 2026-07-30:** the end-to-end run this blocked is done — a
3-node cohort, all seven breaks confirmed fixed against a live daemon. See "What
the cohort then measured" below.

## Observing the carrier on a live cohort

`at_demo` carries the same three pieces as the integrator's reference
(`src/c/example.c`): the first-tick roster pull, and a log line per
`PEER_OBSERVED` / `PEER_REPUTATION`. It reports through the logger rather than
stdout so the lines land in the same stream as the admission and reputation logs
they are meant to be read against, and `Dockerfile-c` installs `at_demo` alone —
so a container cohort reports the carrier with no image or entrypoint change:

```bash
tilt up -- --variant=c --num-nodes=3
```

A single host cannot run two C nodes: `COMM_PORT` is fixed (`network.h:28`) and
`ping.c` / `ntp.c` bind `INADDR_ANY` on the derived ports, so peering needs a
container or a machine per node. This is why the demos are containerized.

**An empty roster emits nothing, which is indistinguishable from break #4
returning.** Read a `peer observed` line only against the admission it should
correspond to — a uuid the node logged admitting. Silence on its own is not a
result either way. `unrated` is the other load-bearing observation: it can only
cross on the pull, since every change-driven emission is rated by construction,
so a run that never shows one has not exercised that path.

## Two further breaks, found by the first live cohort (2026-07-30)

The first 3-node run reported no observations, no roster-verb line, and no
`unrated` — while logging a sybil-collision refusal, which fires from *inside*
the loop over `protocol.peers[]` and therefore proves the table was not empty.
Peers existed and the app was told nothing.

**#6 — the pull raced the daemon and lost, every time.** `at_node_run` does
`iteration++` before the tick, so `at_node_iteration(node) == 1` is the first
tick, and `at_node_start` forks the daemon and returns with **no readiness
handshake**. The identity and reputation processes have not bound their queues
yet, so a single-shot request is dropped, and nothing retried it. Fixed by
retrying until `messaging_send` succeeds (capped, one warning at the cap).

The honest scope: this race belongs to *every* app-to-AT verb, not just the
roster pull, and the retry is a workaround at the app. A daemon-readiness signal
is the real fix and is not built.

**#7 — three of the four paths that admit a peer emitted nothing.** Only
`_add_peer` did. `handle_acceptance` — the path by which a *joining* node records
the peer that accepted it, and so the first peer a fresh cohort can report at
all — `_populate_peers_from_history`, and `handle_identity_response` all appended
to `peers[]` silently. All three now emit, outside the peers lock.

**Why the existing suite stayed green through both.** Every case entered through
an emitter or through the routing; none entered where a peer actually arrives.
The three new admission tests do, and with the emissions removed again they fail
6 assertions while every `num_peers == 1` check still passes — the shape of the
bug itself.

## What the cohort then measured — the pull answers "now"

Both fixes were confirmed on the next run. The uuid-exact check passed: the
observation and the sybil-collision refusal name the same peer, 7 ms apart, the
announcement first.

But the two pull confirmations read **zero**, and the timeline says why:

| Time | Line |
|---|---|
| 15:45:47.263 | `Identity: peer roster request -> 0 observation(s)` |
| 15:45:47.664 | `Reputation: peer roster request -> 0 reputation(s)` |
| 15:46:10.528 | `peer observed: 5b4f3fbd-… rank=0 key=f29f..8d operator=none attended_at=0` |
| 15:46:10.535 | `Identity: refusing vote — candidate 5b4f3fbd-… collides … (sybil)` |

The pull landed on both halves **23 seconds before the first peer existed**, and
`0` was the correct answer. Retrying until `messaging_send` succeeds fires the
request at the earliest instant the queues allow, which on a cold node is the
least useful one — and nothing pulled again, so the `unrated` reputation, which
crosses on the pull *alone*, could never appear.

So a pull reports what AT knows **at that moment**; it is not a request for
"tell me once you know something". Both `at_demo` and `example.c` now re-pull
every ~30 s after the first one lands, and the ABI's `@warning` says so for a
foreign host, whose loop is its own. Repeats cost one message per peer and are
harmless by construction, the feed being upsert-only.

**Confirmed on the following run:** `Identity: peer roster request -> 2
observation(s)`, `Reputation: … -> 2 reputation(s)`, and the `unrated` lines with
them. So on a 3-node cohort each node reports both peers, and a peer with no score
is reported *as* unrated rather than as a placeholder number. That is the whole
carrier verified end to end against a live daemon — and the first live observation
of the signal ethne's `MemberCandidate` depends on (D18: `reputation: None` must
mean unrated, not rated-low).

Two honest notes. The refresh lives in the demo and the reference, not the
library — the cadence is the host's, so there is no library-side test for it, and
the `unrated` path is pinned by
`reputation_pull_reports_unrated_peers_as_unrated` rather than by a live check.
And a pull can also return nothing because `reputation_emit_all` returns early
while `rep_state.initialized` is false, which is the same lesson arriving by a
second route.
