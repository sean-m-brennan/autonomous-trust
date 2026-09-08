# Calibration Audit

*Build-order step 3 of the [verification oracle](../verification_oracle.md);
tracked as R+D.md §12.4.*

A scalar reputation conflates two things that come apart in exactly the case
that matters:

* **Competence** — the peer's prediction sets are tight.
* **Honesty about its own limits** — the sets cover as often as it advertises.

A peer that is frequently wrong but properly humble is safe to work with; you
plan around its stated uncertainty and the plan holds. A peer that is *usually
right and systematically overconfident* scores well on every averaged measure
right up until the first time being wrong matters. Averaged reputation cannot
see that peer coming. This layer can, because it audits the peer's own stated
coverage against the record.

The instrument is conformal prediction (Vovk, Gammerman and Shafer,
*Algorithmic Learning in a Random World*, 2005), used only for its audit half:
a peer emits prediction sets at a claimed coverage, and the observer checks
realized coverage with finite-sample validity and no distributional assumption.

## Falsification only

| Verdict | Score | Channel | Means |
|---|---|---|---|
| `overconfident` | 0.1 | `calibration` | The record **rejects** the claimed coverage |
| `absent` | 0.3 | `calibration` | Declared predictive, attached nothing usable |
| `none` | — | — | Undeclared, too little evidence, or nothing to say |

Like the physics layer ([Physical Consistency](physical-consistency.md)) and
unlike the certificate layer
([Certificate-Carrying Interfaces](certificate-interfaces.md)), a *passing*
audit earns nothing. There is no score for "has not yet been caught
over-claiming". Certificates remain the one oracle layer entitled to say
something good, because only a verified witness proves an answer right.

**Why 0.1 and not a softer number.** `verification_oracle.md` asks that a
physical refutation demote a peer decisively where a drifting calibration score
demotes gradually. That gradient already exists, and it is the **channel
weight**, not the score: `physical` weighs 3 against `calibration` at the
baseline 1 (R+D.md §12.8). Reproducing the gradient a second time — scoring a
rejected claim at 0.3 — would double-count it. A rejected coverage claim is a
proven-false statement the peer made about itself, and it scores like one.

`absent` is 0.3 for the same reason the certificate layer's "declared to
certify and did not" is: it is a fact about the *claim*, not about the answer,
and not evidence of dishonesty.

## The test

A peer claims coverage `c` and the record holds `k` hits in `n` resolved
predictions. Under the null hypothesis that its true coverage is at least `c`,
the hit count is stochastically at least `Binomial(n, c)`, so

```
p = P(X <= k),  X ~ Binomial(n, c)
```

is a valid p-value against the one-sided alternative "true coverage is below
what was claimed". Reject — call the peer overconfident — when
`p < audit_alpha`.

This is exact and finite-sample: no asymptotics, and no distributional
assumption beyond independence of the resolutions. That is what makes it the
right instrument for a peer that has made thirty predictions rather than thirty
thousand. It is the hypothesis-test dual of the Clopper–Pearson interval, taken
in preference to the interval itself because the tail sum needs nothing but
logarithms, where an interval needs an inverse incomplete beta that C has no
library for and that would have to be reimplemented and kept in step.

### One-sided on purpose

An over-*cautious* peer, whose sets cover far more often than advertised, is
not penalised here. Its sets are wide and therefore useless, and that shows up
as poor competence wherever competence is measured — but it is not dishonest
about its own limits, and separating the two is the entire reason this layer
exists. Penalising it would collapse the distinction the layer was built to
draw.

### Silence, not leniency

Below `min_samples` resolutions the audit returns **no verdict**. "Not enough
evidence" is the honest report, and finite-sample validity is the whole reason
to use an exact test: an audit that guessed early would trade the one property
that makes it worth having.

### Independence, honestly

The exact test assumes the resolutions are independent draws. Successive
predictions about one slowly-varying quantity are not, and a peer whose sets
are too narrow produces *runs* of misses rather than scattered ones. The
consequence is that the test is anti-conservative in exactly the case it is
meant to catch — it will reject an overconfident peer somewhat sooner than the
nominal `audit_alpha` promises — and conservative about clearing one. The
direction is the safe one, but the nominal level is a guide rather than a
guarantee, which is why the default is a conservative 0.05 rather than
something tighter.

## Resolution: two paths, physics-declared by default

A coverage audit needs `(set, realized outcome)` pairs, and **the outcome must
not come from the peer being audited**. Two paths supply it.

**The default path is the physics declaration.** A prediction names a declared
quantity, and the ordinary way it comes true is that some later task result
reports that quantity — the same observation stream the physics checker
consumes, mapped through `physics.json`'s `capability` field. No application
involvement, and nothing new to wire: the resolutions fall out of traffic AT is
already scoring.

**The override is `resolve(quantity, value)`**, for a ground truth AT never
sees as a task result. A domain whose truth arrives on a serial port is not
thereby unauditable.

**A peer's own report never settles its own prediction.** That would be the
peer supplying the truth it is audited against, and it would make the whole
layer self-graded — an overconfident peer would simply report the outcome its
own set predicted. Such a report leaves the prediction outstanding for some
other observer to settle.

**An expired prediction is dropped, not counted as a miss.** Past its horizon
nothing was observed, so there is no evidence either way, and counting silence
against a peer would let a quiet sensor convict an honest forecaster.

## Where the verdict enters

The layer is **two halves at two different points** in
`score_task_result`, because they answer different questions.

```
probe  →  physics  →  [ calibration: SETTLE ]  →  certificate
                                               →  [ calibration: ASSESS ]
                                               →  ZKP arms  →  completion
```

**`settle` runs immediately after the physics arm.** It asks *is this result
evidence about the world*, and the answer stops being yes the moment physics
refutes the claim: settling an honest forecaster's prediction against a refuted
observation would let a lying reporter convict it. Everything past the physics
arm is un-refuted and usable — including a result whose own certificate arm is
about to score it, because a wrong answer to *this* task is still a
measurement of the quantity it reports.

**`assess` runs after the certificate arm.** It asks *is the peer's claim about
its own accuracy borne out*, and an exact check of this answer outranks a
statistical claim about a hundred of them: where a capability is both certified
and predictive, the witness settles what happened here, and `calibration`
carries the baseline weight against `certificate`'s 3. It sits above the ZKP
arms for the same reason physics does — an attestation that bytes were not
altered says nothing about whether the peer's account of its own limits is
true.

Resolution before assessment, in that order, so that a peer predicting the same
quantity it just reported is judged against a record including everything this
result settled.

## The declaration

`calibration.json`, canonical JSON read directly by both runtimes with no
conversion step — the arrangement `physics.json` and `certificates.json` use,
which in turn is the one `trust-tiers.md` §8 settled for the trust ladder.
`AT_CALIBRATION` names it; `config/cfg/calibration.example.json` is the shared
example.

```json
{
  "version": 1,
  "min_samples": 30,
  "audit_alpha": 0.05,
  "max_outcomes": 256,
  "max_outstanding": 32,
  "horizon_sec": 60.0,
  "capabilities": {
    "demo.thermal-forecast": {
      "quantity": "demo.bus-temp",
      "horizon_sec": 120.0,
      "min_coverage": 0.5,
      "max_coverage": 0.99,
      "tolerance": 0.5
    }
  }
}
```

`quantity` is the link to `physics.json`, and it is what lets an ordinary
result resolve a prediction with no application involvement. The name need not
appear in a physics declaration — with no physics model loaded, or a quantity
absent from it, the automatic path simply never fires and only the explicit
call resolves it.

What the declaration deliberately does **not** contain is the arithmetic. The
binomial tail and the membership rule are code in both runtimes, for the reason
the physics units table is: an operator who could redefine the test could
convict any peer by declaration.

### Why the claimed coverage is bounded

A peer free to claim any coverage it likes passes this audit forever by
advertising 0.01 — sets that are almost never required to contain anything are
trivially well calibrated. `min_coverage` is the operator saying "offer this
capability and you are claiming at least this much"; honesty about one's limits
is only meaningful against a floor. `max_coverage` is the mirror: a claim of
1.0 asserts a set that must never miss, which no finite sample can support and
which the test would reject on the first miss forever after.

### Opt-in and inert by default

With `AT_CALIBRATION` unset the model is empty and every call returns no
verdict, so nothing that has not opted in changes behaviour. A malformed
declaration is **fatal at load** — never degraded to "audit the capabilities
that parsed", because an operator who configured the layer believes the claims
are being checked. At the scoring path a rejected declaration is recorded once
and leaves the layer off.

One consistency rule is enforced at load rather than discovered at runtime:
`max_outcomes` below `min_samples` is refused, since the outcome ring could
then never hold enough resolutions for the audit to speak and the layer would
be silently inert.

## Carrying the prediction

The set rides in its own field on the reply, beside the answer and the witness:

```
result       the answer
certificate  what makes the answer checkable   (§12.3)
proof        attests the bytes were not altered
prediction   the peer's claim about how often answers of this kind
             land inside the set it quotes                    (§12.4)
```

Four artifacts, four fields, because they are four different claims. Only the
last is a claim about the **peer** rather than about this answer, which is why
the check that reads it is historical where the others are per-result.

Shape: `{"quantity": str, "coverage": float, "lo": [...], "hi": [...]}`. The
set is a **box** — a conformal set for a real-valued target is an interval, and
for a vector target the natural multi-output form is the product of
per-component intervals. A miss on any component is a miss.

Like `certificate` and unlike `requested_*`, this field is the executor's to
assert and is serialized: the whole point is that the peer commits to a
coverage *in advance*. That is safe because it is audited rather than believed
— the outcomes it is checked against are resolved by the requestor, never by
the peer.

## The record

Per-node, process-local and unsynchronised, for the same reason the physics
observation store is: every outcome it counts was resolved by this node, and
the verdict enters consensus as an ordinary `TransactionScore` that every peer
judges on its own terms.

Two bounded stores. Outstanding predictions are keyed by **quantity**, not by
peer, because a single observation settles every peer's outstanding prediction
about that quantity at once. Resolved outcomes are a per-`(peer, capability)`
ring, which makes the audit a **sliding window**: a peer that was badly
calibrated a year ago and has since been corrected ages out of the verdict.
The C twin holds the ring as a bitset; Python holds a bounded `deque`.

## Cross-runtime parity

Both runtimes grade the same peers off the same declaration, and a peer that
one rejects and the other clears would make the judgment depend on which
implementation happened to be asking. So the arithmetic is identical, not
merely equivalent, and one thing had to be given up to make that true.

**The binomial tail is summed without `lgamma`.** The obvious implementation
takes each log-binomial coefficient from `lgamma`, but CPython's `math.lgamma`
is *its own implementation*, not a call into libm, so the two runtimes disagree
in the last few ulp and the identical-arithmetic claim would be false. Both
sides therefore build the coefficient by the multiplicative recurrence, whose
only primitives are `log` and `log1p` on exact small integers — and those do go
straight to libm on both sides. Verified bit-identical over the pinned grid and
over four thousand randomized `(k, n, p)` triples.

**The terms are summed in log space with a max-shift.** `(1 - c)^n` underflows
to zero for the coverages that matter — `0.1 ** 512` is not representable — and
a naive recurrence from that term returns a tail of exactly zero, i.e.
"reject", for *every* peer. The comparison against `audit_alpha` is made in log
space too, so nothing underflows on either side.

The two runtimes cannot share a call site — Python audits from its main
process, C from its negotiation process, the same split probe scoring has
(R+D.md §12.7) — so what the corpus pins is the rules. The `calibration`
conformance protocol replays a declaration and an event sequence through each
runtime's own auditor and asserts the verdict, the score and the channel per
row, covering both resolution paths, the honest / overconfident / over-cautious
trio, self-resolution, horizon expiry and vector sets.

## Where this sits in the build order

`verification_oracle.md` orders the layers by what they need. Physics needs
only a declaration; certificates need only a checker; this one needs a *record*,
which means it is the first layer whose verdict depends on history. It is
placed third for that reason, and it is why its failure mode is silence rather
than a guess.

Step 4 (prequential scoring with per-region competence, R+D.md §12.5) builds on
the same resolution stream, and the sleeping-experts framing there is the
natural home for the competence half this layer deliberately does not score.

## See also

* [Physical Consistency](physical-consistency.md) — step 1, and the source of
  the `quantity` declarations this layer resolves against
* [Certificate-Carrying Interfaces](certificate-interfaces.md) — step 2, and
  the only layer that can return a good score
* [Prequential Competence](prequential-competence.md) — step 4, which scores
  the *tightness* of the same `prediction` box this layer audits the *honesty*
  of, and so completes the one-sidedness this layer is deliberately limited to
* [Task Negotiation](negotiation.md) — the task lifecycle the prediction rides on
* [Reputation Consensus](reputation.md) — where the verdict lands
* [The Verification Oracle](../verification_oracle.md) — the full research framing
