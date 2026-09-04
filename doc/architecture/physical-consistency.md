# Physical Consistency

*Build-order step 1 of the [verification oracle](../verification_oracle.md);
tracked as R+D.md §12.2.*

AT's reputation machinery aggregates scores, weights them by capability, reaches
consensus on them, decays them, and quantizes the result into tiers. That algebra
is domain-independent. What produces the score in the first place is not — and
before any of that algebra runs, there is a class of claims that can be rejected
outright, with no history, no training data, and no appeal to what other peers
think.

A claim that violates conservation, dimensional coherence, or kinematic
feasibility is not *improbable*. It is **refuted**. This layer is the machinery
that says so, and the evidence channel that keeps the difference legible
downstream.

## What it is not

Three properties are easy to lose and expensive to get back.

**It never says a peer is good.** Passing physics earns nothing. A claim outside
the feasible set is refuted; a claim inside it is merely not-refuted. Returning a
favourable score for surviving the check would turn a falsification layer into a
plausibility grade, and the scorer would then be rewarding peers for being
unremarkable. The checker returns a verdict or it returns silence, and silence is
the common case.

**It is opt-in and inert by default.** With no `physics.json` configured the
model is empty and every check is silence. A physical refutation is the hardest
evidence AT produces — the `physical` channel carries three times the weight of
an ordinary task outcome (R+D.md §12.8) — so a checker that guessed at
undeclared quantities would be manufacturing exactly the evidence that most
needs to be earned.

**It does not accuse where it cannot attribute.** Most inconsistency between
peers does not identify a culprit, and the design goes out of its way to say so
rather than round it off. See [Diagnosis](#diagnosis-who-not-just-what).

## Where the verdict enters

The carrier is a returned task result, checked on the requestor side:

```
score_task_result:
    known-answer probe   →  probe          (R+D.md §12.7)
    PHYSICAL CONSISTENCY →  physical  0.1  /  swarm_disagreement  0.3
    certificate / ZKP    →  certificate
    completion           →  task_outcome
```

The probe arm keeps its precedence because a known answer strictly subsumes
asking whether an answer is *possible*: for a capability whose right answer is
already in hand, plausibility is not the question.

Physics sits above the certificate arms deliberately. A proof attests that a
computation was performed, not that its output is physically coherent — a valid
proof over a refuted claim is still a refuted claim. Everything below this layer
is a judgment about completion or provenance, which is what
[the oracle doc](../verification_oracle.md) means by running the claim against
physics *first*.

## The two files, and why they are two

`units` is **code**. The SI base quantities, the symbol table, the grammar: these
are the axioms, and they live in
`src/autonomous-trust/autonomous_trust/core/_python/physics/units.py` and
`src/c/autonomous_trust/physics/units.c`. An operator who could redefine what a
newton is could refute any peer by declaration, which is precisely the failure
mode the layer exists to avoid. This is the sense in which the axiom set is
"small, closed and uncontested" — it is closed because nothing outside the source
tree can open it.

`physics.json` is **declaration**. It says which capability reports which
physical quantity, what range and rate that quantity is capable of, and which
conservation relations tie several quantities together. It is a separate file
from `trust_ladder.json` because the two answer different questions — the ladder
says how much a capability counts and who may run it, this says what its answer
*means* — and a scenario may well want one without the other.

Canonical form is JSON, and **one file feeds both runtimes**: this loader and the
C twin's jansson parser, with no conversion step and nothing to drift. That is
the same decision the trust ladder made (see [Trust Tiers](trust-tiers.md) §8).
`config/cfg/physics.example.json` is the shared example both suites read. Set
`AT_PHYSICS` to a path to turn the layer on.

A malformed declaration is an **operator error** and is fatal at load. It is
never degraded to "check the parts that parsed": a physics layer that quietly
stopped checking is worse than one that was never turned on, because the operator
believes the claims are being verified. At the scoring path the failure is
recorded once and the layer stays off, which is the same end state as never
having configured it.

## The checks

Each produces **conflicts** — sets of peers who cannot all be reporting honestly
— which the diagnosis then resolves.

### Dimensional coherence

A claim may name its own unit. It must be *dimensionally equal* to the declared
one: same exponent vector over (m, kg, s, A, K, mol, cd), whatever the scale. A
prefix is a conversion (0.5 kW is 500 W, checked on equal terms with a peer
reporting watts); a mismatch is a refutation. Kilograms of thermal margin is not
improbable, it is meaningless.

Affine units (`degC`, `degF`) are accepted only as a whole expression. `degC/s`
is refused, because the offset does not distribute over the quotient and
silently dropping it would turn a 20 °C claim into 20 K and refute an honest
peer. For the same reason a *rate* bound converts by scale alone — using the
full affine map would add 273.15 K/s to every Celsius rate limit.

### Range feasibility

Componentwise, in SI. A declared range is a bounding box, so a position north of
the pole is refuted whatever its distance from the origin.

### Kinematic feasibility

Not "is this value possible" but "could it have got there from where this peer
last said it was". `max_rate` bounds |Δv|/Δt and `max_accel` the change in the
velocity *vector* (so a reversal is not read as no change); for a vector
quantity both are magnitudes, because a speed limit is on the vector and not on
its axes. A peer contradicting its own previous claim is a conflict of size one,
so it is refuted outright.

Out-of-order or same-instant claims say nothing about a rate and are not a
refutation: clock skew and queue reordering are ordinary.

### Set-membership intersection

Where errors are bounded rather than stochastic, the intersection of the interval
constraints is a guaranteed feasible set, and a claim outside it is refuted
rather than improbable (Milanese; Jaulin). Each peer's claim becomes
`[v − tolerance, v + tolerance]`; two peers whose intervals are disjoint form a
conflict of size two.

Pairs suffice — on the line, a family of intervals has a common point exactly
when every pair of them does (Helly in one dimension) — so this finds every
conflict without enumerating subsets.

**Opt-in per quantity via `tolerance`.** At zero width every distinct float is a
conflict, which would report disagreement between two honest sensors of the same
thing, so an unset tolerance skips the check entirely.

### Parity relations

The residual form from the aerospace fault-detection tradition (Isermann; Blanke
et al.), restricted to the linear case:

```
r = constant + Σ (coefficient × value_in_SI)
```

which vanishes under consistency and does not under a fault. Linear is not a
shortcut: conservation of mass, energy, momentum and charge are all sums of
signed flows, and it is what lets the residual be computed identically in two
languages with no expression evaluator to keep in step.

Every term of a relation must share one dimension, checked **at load**. Summing a
power and a temperature has no physical content, and finding that out at load is
the difference between an operator error and a peer refuted by arithmetic on
nonsense. Terms are summed in a fixed (name-sorted) order, because floating-point
addition is not associative and the two runtimes must not land on opposite sides
of a tolerance.

The freshest value per quantity is used regardless of which peer supplied it — a
conservation law constrains the quantities, not the reporters — and the conflict
is the set of peers that contributed. A relation whose every term came from one
peer is therefore a conflict of size one, and that peer is refuted: nothing about
the arithmetic changed, only who was standing behind it.

A residual over missing or stale terms is not evaluated at all. Doing so invents
violations out of ordinary change.

## Diagnosis: who, not just what

Substituting "peer" for "component" in the GDE formulation (Reiter 1987; de Kleer
and Williams 1987) gives peer fault isolation directly. A **diagnosis** is a
minimal hitting set over the conflicts — a smallest set of peers whose dishonesty
would explain every conflict at once — and the verdict on a given peer is:

| The peer is in… | Verdict | Score | Channel |
|---|---|---|---|
| **every** minimal diagnosis | refuted | 0.1 | `physical` |
| **some** minimal diagnosis | implicated | 0.3 | `swarm_disagreement` |
| **no** minimal diagnosis | cleared | — | — |

Every single-claim refutation above is the singleton case of exactly this: the
conflict is `{peer}`, so the peer is in every hitting set trivially. One
mechanism, not two.

### Subset-minimal, not cardinality-minimal

This is the design decision most worth defending. The usual GDE refinement
prefers the *smallest* diagnosis. Under it, conflicts `{A,C}` and `{B,C}` — C
disagreeing with A and B, who agree with each other — would resolve to `{C}` and
convict the outlier.

AT keeps **every** subset-minimal diagnosis, so that case yields `{C}` *and*
`{A,B}`, and C comes out implicated rather than refuted. Preferring the smaller
one is majority rule wearing physics' clothes: three colluding peers would be
able to refute an honest one, on the hardest evidence channel AT has. R+D.md
§12.8 is explicit that a majority is not an oracle, and `swarm_disagreement`
sits at the baseline channel weight for exactly this reason — it is the honest
weight for one peer's reading of one event.

The implicated verdict is a poor score with a reason attached, not an accusation.
Consistent with §12.8's closure, nothing here levies a penalty on a fast path
around consensus: the score enters the algebra as an ordinary
`TransactionScore`, every peer sees both the number and the channel, and each
judges for itself.

### Bounded search

Minimal hitting set is NP-hard in general. Real conflict sets here are a handful,
so the enumeration is exhaustive under a cap (16 conflicts, 64 peers) and both
runtimes run it over bitmasks — Python ints, C `uint64_t` — so neither can
enumerate a set the other does not. Past the cap the verdict degrades to the
singleton test: refuted only if the peer forms a conflict by itself. That is
strictly the *narrower* answer, so an overloaded window costs evidence rather
than manufacturing it.

## The observation store

Per (quantity, peer), a bounded ring of recent SI values with their observation
times. It lives in the single process that holds the requestor's record of what
it asked — Python's main process, C's negotiation process — and every value in it
was observed by this node. Nothing here is consensus.

Two rules carry weight:

- **A refuted observation is never stored.** The store feeds the intersection and
  the residuals, so admitting a claim already known to be impossible would let
  one liar manufacture conflicts against honest peers.
- **An unattributed result stores nothing.** A fan-out is answered by several
  peers and only the last reply carries the object that gets scored, so there is
  no single subject. The checks that need no identity still run (shape, unit,
  arity, bounds); filing several peers' claims under one key would manufacture
  conflicts between a peer and itself.

Observations older than `window_sec` are not comparable with fresh ones. Peers
legitimately disagree about a quantity that has moved on, and calling that a
conflict refutes honest peers.

## Cross-runtime parity

Both runtimes grade the same peers off the same declaration, so a claim one
refutes and the other waves through would make a peer's reputation depend on
which implementation happened to ask — and would do so on the channel where that
matters most.

The two cannot share a call site: Python checks from
`automate.score_task_result`, C from `negotiation_score_task_result`, because
that is where each runtime keeps the requestor's record of what it asked (the
same split probe scoring has, R+D.md §12.7). So what is pinned is the **rules**.
The `physics` conformance protocol feeds a declaration and a claim sequence
through each runtime's own checker and asserts the verdict, the score and the
channel per row — the verdict alongside the score, because "no verdict" is not
"scored zero", and a runtime returning `implicated` with a refutation's score
would otherwise look identical to one that refuted.

Scale accumulation in the unit parser uses repeated multiplication and a single
divide rather than `pow`, so both languages land on the same bits.

## Where this sits in the build order

Step 1 of eight. The layers above it in
[the oracle doc](../verification_oracle.md) — certificate-carrying interfaces,
conformal coverage audit, prequential scoring, self-consistency over the claim
archive, sampled replication, off-policy scoring, peer prediction — are all
statistics or interface design. This one is neither: it needs no history, no
training data, and no assumption about the honest fraction, which is why it goes
first and why its verdicts are qualitatively different from everything that
follows.

## See also

- [The Verification Oracle](../verification_oracle.md) — the whole programme, and
  why physics is step 1.
- [Reputation Consensus](reputation.md) — the algebra these verdicts feed.
- [Trust Tiers](trust-tiers.md) — capability weighting, and the declaration file
  this one is modelled on.
