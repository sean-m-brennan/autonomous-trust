*Previous: [Standing turned into capability](trust-tiers.md)*

# The human behind the machine

Everything so far has been about machines judging machines. This chapter is
about the one question a machine cannot answer about itself, which is whether a
person stands behind it, and if so, whether that person is there now.

The question matters because responsibility has to land somewhere. A network of
autonomous nodes that misbehaves has misbehaved on somebody's account, and a
polity that cannot tell an attended workstation from an unattended drone cannot
place responsibility anywhere at all. The tier above AutonomousTrust needs a
guardian edge for every machine member, meaning a named human answerable for it,
and that edge has to be fed by something the machines can actually observe.

AutonomousTrust supplies two signals, and keeping them apart is the whole
design.

| Signal | Question | Lifetime |
|---|---|---|
| `operator_bound` | Does this node have a human guardian at all? | Durable, set once at operator activation, persisted with the identity |
| `operator_attested_at` | Is a human at its console right now? | Live, an epoch stamp, meaningless the moment it ages |

They answer different questions and they fail differently. A node can be bound
to a guardian with nobody at the keyboard for a week, and that is a normal state
rather than an error. What a guardian edge must never do is read the first as if
it were the second. One is a fact about the node, the other a fact about the
minute, and conflating them puts responsibility in the wrong place.

Neither signal is taken on the word of a peer. Both are derived by the receiver
from verifying the actual credential of the operator against a distinct operator
trust anchor. A node that simply asserts it is operator-bound and cannot produce
a credential chaining to that anchor is recorded as false, and the
neutralization is pinned by its own conformance scenario.

## Two structural failures the live half had

The durable signal worked from the start. The live one did not, for two reasons
that were structural rather than accidental, and neither showed up in unit
tests.

*The stamp was always zero on a real node.* Attendance is derived from a live
operator session, which the console application builds in its own process. The
identity process, which assembles every outgoing attestation, runs in a separate
subprocess and cannot see that object. A setter existed, and on a real
multiprocess node nothing could ever call it with the real session, so the stamp
was structurally pinned at zero forever. Worse, a reader could not distinguish
that from an honest report that nobody was attending.

*Nothing ever refreshed the stamp of a peer.* An attestation crossed to a peer
exactly once, inside the admission payload, and after admission it was never
updated. A consumer reading the attendance stamp of a peer was reading history,
being the moment that peer joined, and mistaking it for attendance.

The first fix turned out to be cheap because of a structural accident. The main
loop of a node runs in a daemon thread of the console application process, so it
already shares an address space with the live session. The only missing hop was
from the main loop to the identity subprocess, and that hop had an established
pattern in the local-only messages that never reach the wire.

## Five decisions

Firstly, *consumer-pull rather than keepalive*. Freshness is established when
somebody asks, not by re-announcing on a cadence. A periodic re-announce was
considered and rejected, because it puts constant attestation traffic on an idle
network to answer a question nobody asked, and it still serves a stamp that is
up to one interval stale. Pull inverts that. An idle network carries no
attestation traffic at all, and staleness is bounded by a round trip taken at
the moment of asking.

Second, *no cached session mirror*. The identity process stores no copy of the
session state. It could, and that would make answering a pull instant, and a
cached mirror is precisely a thing that can be stale, which is what this signal
exists not to be. The cost is a local round trip per pull and a pending-pull
state machine. The benefit is that there is no stale state to serve.

Third, *the nonce is load-bearing*. Each pull mints a nonce, the answer echoes
it, and the requestor retires it on receipt. Without that, a signed attestation
could be captured once and re-presented forever, which would make attended-now
mean attended-at-some-point, being the exact failure the signal exists to
prevent. An answer is good exactly once.

Fourth, *verification lives with the verifier*. The pull is issued and checked
by the identity process rather than by the main loop, because an attestation is
worth nothing until its credential is re-verified against the operator anchor,
and that anchor lives in the identity process beside the admission gate. The
process that can verify is the process that asks. The main loop keeps only the
consumer-facing interface and the answer table.

Lastly, *silence resolves to an answer*. Every pull, in both directions, has a
deadline. A node whose console never replies, or a peer that has gone quiet,
resolves to not attended rather than hanging. For a guardian edge, being unable
to confirm that a human is present and knowing that no human is present are the
same operational answer, and an unbounded wait is the only genuinely useless
outcome.

## Naming which human, by choice

The two signals above answer whether a human stands behind a node and when one
was last there. Neither says which human, and for a long time nothing did, since
the operator credential is an X.509 certificate holding no key of the kind an
identity would need. That mattered more than a missing field usually would,
because the chartered node-to-guardian edge one tier up requires a guardian to
co-sign, and a guardian who cannot sign is unusable, so a chartered rule was
running with no live source at all.

A node may now advertise a guardian public key together with a binding, being a
signature by the private key of that operator over

    "at-operator-binding-v1" || uuid (16) || node signing key (32) || operator key (32)

verified at admission against the public key of the credential itself, which is
the same credential the gate has already classified as operator-class against
the distinct operator anchor. Both halves are required and neither substitutes
for the other. A chain without a binding names no human, and a binding whose
credential is not operator-class is a human with no standing to name one.

*Opting out is free, and that is a rule rather than a default.* The framework
never requires a guardian identity. A node that declines is admitted
identically, keeps its bound flag and its attendance stamp, and serializes byte
for byte as it did before the field existed, since both fields are emitted only
when non-default and a declining node puts nothing on the wire. A consumer that
requires a guardian is applying a rule of its own, which is the business of the
tier above, and there an absence means an unguarded machine rather than an
error.

The reason to protect that is specific. There is one key per operator, stable
across every node that human guards, because per-node keys would let one person
present as several guardians, which is the sockpuppet problem moved down a
layer. Although stability is what makes the count meaningful, a stable key is
also a persistent pseudonym, so anyone watching two cohorts can link the nodes
of an operator to each other. That is a real cost paid by a real person, so it
is theirs to choose. Off by default is the mitigation, and the choice is made on
the command line at activation rather than on the recurring unlock screen,
because a decision that de-anonymizes a whole fleet does not belong on a daily
login prompt.

The pre-image names the node deliberately. Without the identifier and the
signing key inside the signed bytes, a key and binding pair lifted from the
clear-text announcement of another node would let any node claim that human, and
a count of guardians would mean nothing. The bytes therefore bind a key, a node,
and a human together, and none of the three travels alone.

*What a bad binding costs.* When absent, there is no guardian key and nothing
else changes. When present but invalid, whether forged, naming another node, or
of the wrong length, the key is refused and the peer is stored without one. The
bound flag is not demoted, because it was earned independently from the anchor,
and node key rotation legitimately stales a binding, so demotion would turn an
honest re-keying into a lost credential. Losing a guardian edge is the failure
mode here; losing admission is not.

Two limits are worth stating. The guardian key is software-held, so a stolen
keystore impersonates that human on every node they guard, and hardware-held
keys are the successor. And distinct guardian keys are still not distinct
humans, so the tier above must not count them as such without an independence
attestation, which is not built here.

## The protocol

Four verbs, two on the wire and two local only.

| Verb | Scope | Payload |
|---|---|---|
| `attest_req` (`operator_attest_query`) | wire | `{nonce}` |
| `attest_resp` (`operator_attest_response`) | wire | `{nonce, operator_attested_at, ...attestation}` |
| `attest_trigger` (`operator_attest_trigger`) | local | `{target}`, a consumer asking its own node to pull a peer |
| `operator_state_req/resp` (`operator_state_query/response`) | local | `{}` and `{attended, epoch, have_session}` |

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

The stamp is always present in the answer, including as an explicit zero. Having
asked and learned that nobody is attending is a real answer, and it must not be
confusable with a refusal to say.

*What the requestor checks.* Three independent checks, all of which must pass
before a stamp is recorded. Firstly the nonce, which must be one this node
minted and has not retired, killing replay. Second the credential, which must
chain to the distinct operator anchor with its hash recomputed from the actual
bytes, using the same gate admission uses, killing a node talking itself into
operator class. Lastly the window, which requires the stamp to sit within one
hundred twenty seconds of the local clock, killing a peer that mints permanent
freshness by stamping far ahead.

Any failure records not-attended rather than raising. The second and third
checks are independent, and the case that separates them matters: a peer that
verifies and reports zero is genuinely operator-bound hardware with nobody at
the console, and it is recorded exactly that way, bound and unattended.

## A deliberate asymmetry between the runtimes

The C runtime has no operator session and no console application, since there is
no hardware-credential path in C by design. So the Python side derives
attendance by polling the live session through the local round trip to the main
loop, and the C side answers from a single seam in one hop.

The asymmetry is confined to where the attended state comes from. The verb
shape, the payload, the always-present zero, the nonce state machine, and all
three verification checks are identical. The single definition of attended on
the Python side lives in one function shared by both the in-process seam and the
main loop, so the two cannot drift.

## Pinned scenarios

Unit coverage runs to sixty-three cases on the Python side, covering the data
model, the admission gate, the responder round trip, and the requestor
verification including replay, imposter, and window edges, plus ten cases on the
C side and the bridge wiring in the operator package.

Cross-language conformance scenarios live under the identity protocol:

| Scenario | Pins |
|---|---|
| `attest-pull-attended` | an active session yields the pinned epoch |
| `attest-pull-unattended` | a locked session yields an explicit zero |
| `attest-pull-replay-rejected` | a re-presented answer is refused, and the recorded stamp is unchanged |
| `operator-bound-verified` | an operator credential yields a bound flag of true |
| `operator-bound-lying-rejected` | an asserted claim on a non-operator credential yields false |
| `operator-key-bound-verified` | a binding signed by the presented credential keeps the guardian key |
| `operator-key-binding-forged-rejected` | the same everything signed by an unrelated key is refused, and the bound flag stays true |
| `operator-key-bound-to-another-identity-rejected` | a perfect signature naming a different node is refused |
| `operator-key-absent-is-normal` | the opt-out, being bound and attended with no guardian and no penalty |

The four bindings are signed at scenario time by both adapters from a committed
test key rather than pinned as recorded blobs. That is deliberate. A pinned
signature would hold the two implementations to one of them having saved its own
output, where signing live holds them to the same pre-image and the same scheme.
The signature algorithm is deterministic, so they agree byte for byte or the
scenario fails. The private key of the test leaf is committed for exactly this
reason, being a test anchor with standing nowhere.

The clock is pinned in these scenarios and never read from the wall, since a
live stamp could not match across two runs, let alone across two languages.

## Consuming the signal

```python
node.request_peer_attestation(queues, peer)        # hand-off; returns immediately
...
stamp = node.peer_attestations.get(str(peer.uuid), 0.0)
attended_now = stamp > 0.0                         # already verified when it lands
```

The pull is asynchronous. The answer arrives on the attestation table when it
arrives, or resolves to zero at the deadline. A consumer should treat not yet
answered and answered zero the same way, which the deadline guarantees it can,
since every pull terminates.

The polity tier reads this through its own node rather than talking to peers
directly, and the adapter on that side is the subject of a later chapter.

## Further reading

- [Operator access](operator-access.md): the credential itself, the session
  lifecycle, and the request-only operator node.
- [Zero Trust parity in Python](zta-python-parity.md): the verification chain the
  operator anchor sits in.
- [Which human answers for which machine](../../../ethne/doc/guardianship.md):
  what the tier above does with these two signals, and why it treats an
  unguarded machine as an honest state rather than a missing value.

---

*Next: [A worked scenario](../example-application.md)*
