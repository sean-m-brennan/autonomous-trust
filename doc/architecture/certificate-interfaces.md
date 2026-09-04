# Certificate-Carrying Task Interfaces

*Build-order step 2 of the [verification oracle](../verification_oracle.md);
tracked as R+D.md §12.3.*

For a large fraction of computational work, **checking is asymptotically
cheaper than producing**. Requiring every answer to arrive with a witness
converts peer judgement into running a checker, and the oracle stops being
statistical: a verified witness means the answer is *right*, and a failed one
means it is *wrong*. Neither is an inference about the peer's character.

This is the certifying-algorithms program (McConnell, Mehlhorn, Näher and
Schweitzer, "Certifying algorithms", *Computer Science Review*, 2011) applied to
peer work.

## The one layer that can say something good

Every other evidence layer in AT is negative or neutral. The physics layer
([Physical Consistency](physical-consistency.md)) *only* refutes — surviving a
feasibility test means "not refuted", never "correct". Completion scoring says a
task came back. Probes say a known answer was matched, but only for the handful
of capabilities whose answers are known in advance.

A certificate is different in kind, and the design leans on that:

| Verdict | Score | Channel | Means |
|---|---|---|---|
| `valid` | 0.9 | `certificate` | The answer is **proved right** |
| `invalid` | 0.1 | `certificate` | The answer is **proved wrong** |
| `absent` | 0.3 | `certificate` | Declared to certify, and did not |
| `indeterminate` | — | — | **Our** inputs cannot support a check |
| `none` | — | — | Undeclared, or declared uncertifiable |

0.9 is the number a correct known-answer probe earns, because it is the same
kind of fact. 0.1 is the number a tampered probe earns, for the same reason. And
`indeterminate` never reaches a score at all: if our own retained record of the
problem is missing or malformed, that is this node's failure, and charging a
peer for it would punish honest work.

## The integrity property

**The checker's inputs come from the requestor's own retained task, never from
the reply.**

This is the same property that makes a honeypot probe worth issuing
(R+D.md §12.7), and it matters more here rather than less. A checker that read
the matrices, the CNF or the graph out of the peer's response would be verifying
that the peer can solve a problem *of its own choosing* — which every peer can,
trivially, by choosing an easy one and reporting it as the hard one. The answer
and the witness are the only things the peer supplies; the problem comes from
`requested_kwargs`, stamped by the requestor's negotiation process from the task
it kept.

The one apparent exception proves the rule. Freivalds' matrix check needs
randomness, and its soundness depends on the prover not knowing the challenge
vector. Deriving that vector from the matrices — a hash of the inputs, say —
destroys the guarantee outright: the prover chooses `C`, so it can grind
candidate answers until one passes a challenge it can compute itself. So the
seed comes from the requestor's own entropy, at check time, after the answer is
already in hand.

## The checkers

Eight kinds, one per row of the oracle doc's table. All eight exist in both
runtimes and are pinned against each other by the `certificate` conformance
protocol.

| Kind | Witness | What the check costs |
|---|---|---|
| `matrix_product` | none — the verifier's own randomness | O(n²) against O(n^ω) |
| `linear_solve` | none — the answer certifies itself | one matrix-vector product |
| `lp` | the dual, or a Farkas vector | evaluate constraints and the gap |
| `sat` | an assignment, or a DRAT refutation | linear, or proof-length |
| `path` | a feasible potential | one pass over the edges |
| `flow` | a min cut | linear in edges |
| `schedule` | the makespan | linear in jobs |
| `state_estimation` | none — the innovation sequence | a whiteness test |

Three of these deserve their own note, because each has a naive form that looks
right and certifies nothing.

### `path`: a bound needs its own witness

The standard phrasing is "the path, plus an admissible lower bound for the
optimality claim". As stated, that is not checkable. A peer returning a detour
can *assert* a bound equal to its own cost and call itself optimal; nothing in
the answer contradicts it.

What is checkable is the bound's own witness — a **feasible potential**, which is
the LP dual of shortest path. Node prices `π` satisfying `π[v] − π[u] ≤ w(u,v)`
on *every* edge make `π[target] − π[source]` a valid lower bound on any
source-target path, verifiable in one pass. A path whose cost meets that bound is
optimal, and nothing is taken on trust. A bare `{"lower_bound": 5}` is refused.

### `sat`: UNSAT is the claim a liar gets for free

Satisfiability is certified in one line: exhibit the assignment, evaluate the
clauses. Unsatisfiability admits no such object, and "I searched and found
nothing" costs a dishonest peer exactly nothing to say.

DRAT is what makes it cost something. The peer emits the lemmas its solver
derived; the checker replays them, confirming each is either **RUP** (assume its
literals false, unit-propagate, reach a conflict) or **RAT** on its first literal
(every resolvent against a clause containing the negated pivot is itself RUP),
and that the sequence ends at the empty clause.

That last condition is the single most important check in the file. A proof of a
hundred sound lemmas that never derives the empty clause has proved nothing about
satisfiability, and accepting it would let a peer claim UNSAT by emitting
arbitrary valid inferences.

### `flow` and `schedule`: feasible is not optimal

A feasible flow certifies only that the peer returned *a* flow. The cut is what
makes it maximum — max-flow min-cut means a flow and a cut that agree are
simultaneously both. Likewise a legal schedule with an under-reported makespan is
a peer claiming a better schedule than it produced, which is invisible unless the
claim is checked against the schedule rather than believed.

## The declaration

`certificates.json`, canonical JSON, one file read by both runtimes — the
arrangement [Trust Tiers](trust-tiers.md) §8 settled for the trust ladder and
`physics.json` reused for §12.2. `AT_CERTIFICATES` names it;
`config/cfg/certificates.example.json` is the shared example. Unset means an
empty model and an inert layer.

Three declared states, and the distinction between the second and third is the
point:

```json
"demo.route":  {"checker": "path", "required": true}
"demo.assess": {"checker": null, "note": "a human judgement call"}
```

- **A checker named** — answers carry a witness of that kind.
- **`checker: null`** — declared **uncertifiable**. Somebody looked and concluded
  no witness exists. No verdict is ever produced.
- **Absent from the file** — nobody has considered it. Also no verdict, but an
  *unexamined* capability rather than an examined one.

An unknown checker name is **refused at load**, never degraded to
"uncertifiable". A typo that quietly turned a certified capability into an
unchecked one would be the worst possible failure of this layer, and it would
look exactly like a deliberate `null`.

`required` (default true) is what makes an absent witness evidence rather than a
shrug. Set it false while a domain is migrating and a missing witness falls
through instead.

## The inventory

The oracle doc asks that "a capability whose result cannot be certified should be
recognized as the expensive case rather than treated as the normal one".
Recognition is not automatic: a node that silently falls through to completion
scoring for everything it cannot check looks, from outside, exactly like a node
that is checking everything.

So each runtime emits an inventory once, when the layer initialises:

```
certificate inventory: 8 exactly checkable, 1 optional,
                       1 acknowledged uncertifiable, 2 never examined
  unexamined     at.handshake -- not mentioned in the declaration
  uncertifiable  demo.assess -- a human judgement call; no witness exists
  optional       demo.migrating via linear_solve
  certified      demo.route via path
```

Worst-known first, because `unexamined` is the state that accumulates silently
and is the one an operator most needs to see.

## Carrying the witness

The witness rides in its **own field** on the reply, beside the answer — not
inside it, and not in the ZKP `proof` field.

Three artifacts, three fields, because they are three different claims:
`result` is the answer, `certificate` is what makes the answer checkable, and
`proof` is a ZK-STARK attesting the bytes were not altered in transit. Folding
the witness into the result would make every certified capability's return type
a convention, and a reader that did not know the checker would see a wrapper
where it expected an answer. Folding it into `proof` would leave a reader
sniffing bytes to tell a witness from a STARK — the format detection R+D.md §2.5
spent a whole entry proving unnecessary.

Unlike `requested_kwargs` and `executor_uuid`, the certificate **is** the
executor's to assert and is serialized. That is safe precisely because it is
checked rather than believed: a peer can choose its witness, but not the problem
the witness has to satisfy.

Producers wrap: Python capabilities return `Certified(answer, witness)`, C
capabilities write `{"at_certified": {"value": …, "certificate": …}}`, and each
runtime's executor splits the two apart before they go on the wire. An explicit
wrapper rather than a convention, because the split must never be a guess — an
answer that legitimately carried those keys would otherwise be torn in half, and
the checker would verify the wrong object.

## Where it sits in the scorer

```
score_task_result:
    known-answer probe   →  probe
    physical consistency →  physical / swarm_disagreement
    CERTIFICATE          →  certificate  0.9 / 0.1 / 0.3
    ZKP proof            →  certificate  (the STARK arm)
    completion           →  task_outcome
```

After physics, because a witness proves the answer satisfies the problem *as
stated*, which says nothing about whether the statement was physically coherent.
Before the ZKP arm, because that asks only whether the bytes were altered, and an
exact check of the answer outranks an attestation about its transport.

## Cross-runtime parity

Both runtimes grade the same peers off the same declaration, so a witness one
accepts and the other rejects would make a peer's reputation depend on which
implementation happened to ask — and here it would do so in *both* directions,
since this layer both rewards and punishes.

The two cannot share a call site (Python checks from
`automate.score_task_result`, C from `negotiation_score_task_result`), so the
`certificate` conformance protocol pins the **rules**: a declaration and a claim
sequence through each runtime's own verifier, asserting the verdict *and* the
score per row. The verdict matters separately because three of the five produce
no score, and a runtime that collapsed `absent` into `indeterminate` would look
identical on the numbers alone.

Numerically: sums run in index order, comparisons are against the declaration's
tolerance, and both runtimes draw the Freivalds challenge from the same
`SplitMix64` stream.

**A bound worth stating.** ISSUES §2.9 records that C and Python negotiation
payloads do not interoperate today, so a C worker's witness does not in fact
reach a Python requestor. What is established here is that the two runtimes
*judge* a witness identically — which is what a peer's reputation depends on —
not that a witness crosses between them. Closing §2.9 is what would make the
second true.

## See also

- [The Verification Oracle](../verification_oracle.md) — the whole programme, and
  why certificates are step 2.
- [Physical Consistency](physical-consistency.md) — step 1, the layer above this
  one in the scorer.
- [Reputation Consensus](reputation.md) — the algebra these verdicts feed.
