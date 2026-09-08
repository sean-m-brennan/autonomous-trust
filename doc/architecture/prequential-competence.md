# Prequential Competence

*Build-order step 4 of the [verification oracle](../verification_oracle.md);
tracked as R+D.md §12.5.*

The [coverage audit](calibration-audit.md) separates two things a scalar
reputation conflates, and then deliberately scores only one of them:

* **Honesty about one's own limits** — the sets cover as often as advertised.
  §12.4 audits this, and falsifies a peer that over-claims.
* **Competence** — the sets are *tight*. §12.4 says explicitly that an
  over-cautious peer is not penalised there: its sets are useless, but that is
  a competence problem and not a dishonest one.

This layer is where the competence half lands. It scores a peer only on its
sequential record of forecasts against outcomes — Dawid's **prequential
principle** (1984): a forecaster is assessed by its record, and never by
anything about its internals.

## What it produces: a weight, not a verdict

Every other oracle layer returns `(score, channel)` and lands in the
reputation algebra as a `TransactionScore`. This one returns **no score at
all.** It produces a per-`(peer, capability)` **competence multiplier** that
changes how much a peer's evidence counts, and adds no evidence of its own.

That is the shape the design calls for, and there are three reasons it is not
merely a smaller version of the other layers:

1. **Poor competence is not a defection.** A peer whose forecasts are wide or
   wrong has told no lie; scoring it 0.1 on some `prequential` channel would
   put it in the same bucket as a physically impossible claim, and the whole
   point of §12.4's one-sidedness was to stop conflating the two.
2. **R+D.md §12.8's channel enum is closed and pre-declared.** It carries
   `self_consistency` and `replication` for build-order steps 5 and 6 and
   deliberately no `prequential`. A channel is part of the committed fact, so
   adding one is a flag day: an older acceptor refuses a score whose channel it
   does not know, and drops the message.
3. **Weighting is exactly what §12.5 asks for.** "A direct generalization of
   the authored per-capability weights in the trust ladder, learned rather than
   authored" is a statement about the *weight*, not about a new score. (The
   entry said `trust_ladder.yaml` and warned that a learned weight would need
   a path to C other than "the YAML loader that has no C mirror". That was
   already stale: ISSUES.md §10.1 closed, the ladder is canonical JSON, and
   `src/c/autonomous_trust/config/trust_ladder.c` parses it. In the event the
   learned weight does not travel through the ladder at all — it is measured
   per node and never declared.)

So the output composes with the two multipliers already in the EMA:

```
EMA weight  =  transaction_weight        (authored, trust_ladder.json)
            ×  competence multiplier     (learned, this layer)
            ×  channel weight            (authored, §12.8, local evidence only)
```

### Bounded band, authored weight as the anchor

The multiplier is confined to a declared band around 1.0 — `weight_band`, with
`min ≤ 1 ≤ max` enforced at load. The authored `transaction_weight` stays the
anchor and the operator's number remains the centre of the range: learned
competence can move a capability's weight within the band the operator allowed
and can never leave it. A peer with an excellent record on a trivial region
cannot thereby inflate its say on a heavy one.

Concretely, with mean loss `L̄ ∈ [0, 1]`:

```
m  =  band_max − (band_max − band_min) · L̄
w  =  max(1, floor(transaction_weight · m + 0.5))
```

**One honest limitation.** The EMA applies weights by folding a score in that
many times (`consensus_score_from_window`), so weights are small integers and
1 is the floor. A capability authored at `transaction_weight: 1` therefore
cannot be demoted by competence — there is nothing below 1 — and only its
*promotion* half of the band is reachable. Competence bites where the operator
authored a weight above 1, which is the same place the operator said the
capability mattered. Recorded here rather than worked around: making the fold
fractional would change every existing weighted EMA.

### Silence before evidence

Under `min_samples` resolutions the multiplier is exactly 1.0 — the authored
weight, verbatim. Same rule as §12.4's silence: a layer whose failure mode is
a guess is worse than one that says nothing.

## The loss: the interval score, at the operator's level

A proper scoring rule needs a predictive *distribution*, and the reply already
carries one artifact of that kind: §12.4's `prediction` box
`{quantity, coverage, lo[], hi[]}`. Nothing new goes on the wire.

The rule is the **Winkler interval score** (Winkler 1972; Gneiting and Raftery
2007 §6.2), which is proper for a central prediction interval at level
`1 − α`. For an interval `[l, u]` and outcome `y`:

```
IS  =  (u − l)  +  (2/α)·max(0, l − y)  +  (2/α)·max(0, y − u)
```

It is exactly the decomposition this layer needs: the first term is
**sharpness** and the other two are the **miss penalty**, so a peer cannot
score well by being vague (wide interval, first term large) *or* by being
overconfident (narrow interval that misses, second term large). A degenerate
"cover everything" interval, which §12.4 is required to forgive, is penalised
here — which is precisely the division of labour between the two layers.

For a vector box the score is the **mean over components**, so a 3-vector
forecast is not three times worse than a scalar one.

A declared `tolerance` forgives a **miss** within measurement error and does
not enlarge the sharpness term. The tolerance models what is unknown about
`y`, which can only bear on whether `y` fell outside the interval; the width
is the peer's own declaration and is known exactly. Charging the widened width
would bill every peer on a coarsely measured quantity for our instrument, and
would put a floor of `2·tolerance/scale` under a perfect forecaster's loss —
making "a flawless record earns `band_max`" unreachable on any capability that
declared a tolerance at all.

### α is declared, not claimed

The level the loss uses is the **operator's** `alpha`, per capability, and not
the peer's `coverage` field. A peer free to pick its own level would lower it
to make misses cheap — `2/α` is the whole miss penalty — and keep its
intervals narrow. It would also make competence incomparable: two peers scored
at different levels are not being scored on the same rule, and both the
weighting and the regret bound below depend on one common rule.

The peer's claimed coverage remains §12.4's business, where it is bounded and
audited. This layer does not read it, and works on a prediction that carries
no coverage field at all.

### Normalized to [0, 1]

`IS` has the units of the quantity, so a raw score is neither comparable across
quantities nor usable by the aggregation below, which requires bounded losses.
Each capability declares a `scale` in the quantity's units and

```
loss  =  min(1, IS / scale)
```

Saturation at 1 is deliberate. A forecast that misses by ten times the scale is
not usefully worse than one that misses by five: "impossible" is the physics
layer's verdict to render, and Hedge's regret bound requires losses in `[0, 1]`.

## Sleeping experts, and a bound AT does not otherwise have

Peers opine on different rounds. The **specialists / sleeping-experts**
reduction (Freund, Schapire, Singer and Warmuth, 1997) scores a peer only on
the rounds it actually spoke, which is what yields *regional* competence — a
peer trusted on thermal and distrusted on attitude — with nobody declaring the
regions in advance.

Per quantity, the estimator keeps a cumulative loss `L_i` per peer and runs
exponential weights (Hedge) restricted to the awake set:

```
awake A     = the peers whose forecast this observation resolved
p_i         = exp(−η L_i) / Σ_{j∈A} exp(−η L_j)          for i ∈ A
mixture ℓ   = Σ_{i∈A} p_i ℓ_i
then         L_i += ℓ_i                                   for i ∈ A
```

The weights are computed in log space with a max-shift, because `exp(−η L)`
underflows for the cumulative losses that a long run produces.

**The guarantee.** What Hedge bounds is the **mixture** loss — the loss of
following one peer drawn according to the weights — and it needs no assumption
about the domain, the peer population, or the honest fraction:

```
Σ_t ℓ_mix(t)  ≤  L_i  +  ln N / η  +  η·T_i / 8      for every peer i
```

where `T_i` is the number of rounds peer `i` was awake and `N` the number of
peers that have ever forecast the quantity. This holds against **arbitrary,
adversarial** peers, which is the one thing reputation averaging cannot give at
any sample size. `regret(quantity)` reports the realized left-hand side minus
each peer's own `L_i` over that peer's own awake rounds — the sleeping-experts
quantity, since the guarantee is against each specialist on the rounds it
spoke — alongside the bound, so the claim is measurable rather than asserted.
The conformance corpus checks it against an adversarial sequence.

**The aggregate forecast.** `combine(quantity)` returns the `p`-weighted
combination of the forecasts currently outstanding about that quantity —
endpoint-wise (vincentized): `lo = Σ p_i lo_i`, `hi = Σ p_i hi_i`. A point
forecast is what an application can actually use, and on the **raw** interval
score it inherits the mixture's guarantee: `IS` is convex in `(l, u)` — a
linear width term plus two positively scaled hinges — so by Jensen its loss is
at most the weighted average of the peers'.

That inheritance stops at the normalization. `min(1, IS/scale)` is **not**
convex, and once several peers saturate, averaging their endpoints can land the
combined interval somewhere that scores worse than the capped average of their
scores. This is a real property of a bounded loss and not a defect to paper
over, so `regret()` reports the aggregate total, the mixture total, and
`saturated_rounds` — the rounds where any awake forecast hit the ceiling. The
corpus pins the inequality on an unsaturated sequence and the inversion on a
saturated one, because a reader who found the totals crossed and no explanation
would reasonably conclude the implementation was wrong.

`η` is declared. The bound's two terms trade off at `η = sqrt(8 ln N / T)`, so
an operator who knows the horizon it cares about can tune it; the default of
1.0 is the sane anytime choice for the run lengths a mesh actually sees.

**Nothing in AT core consumes the aggregate.** It is an API for an
application that wants the mesh's best estimate of a quantity, and it is the
claimant for the bound. No core path depends on it.

## Where it enters

```
probe → physics → [ calibration: SETTLE ]
                → [ prequential: SETTLE, then OBSERVE ]
                → certificate → [ calibration: ASSESS ] → ZKP → completion
```

Both prequential calls sit with calibration's `settle`, immediately after the
physics arm, and for two reasons:

* **After physics**, because a refuted observation must not resolve an honest
  forecaster's prediction — the same rule, and the same reason, as §12.4. A
  refuted result records no forecast of its own either: a claim physics has
  refuted is not evidence in either direction.
* **Before every early return**, because this layer renders no verdict and
  therefore has no place in the arm *order*. A forecast attached to a reply
  whose certificate arm is about to score it still has to be recorded, or the
  record would silently depend on which other layer happened to speak.

`settle` runs before `observe` so that a peer forecasting the same quantity it
just reported is weighted against a record including everything this result
settled.

The multiplier is read where the `TransactionScore` is built, not inside
`score_task_result`: the layer contributes no score, so the scoring function's
signature is unchanged and a reader of it sees only the arms that can speak.

### Crossing the process boundary

The record lives in the process that observes the traffic — Python's main
process, C's negotiation process — and the EMA weight is applied in the
reputation process. So the multiplier travels with the score, as
`TransactionScore.competence` (Python) and `tx_score_msg_t.competence` (C).

Both are **local-only by construction**, exactly like `subject_uuid`:
`to_dict` drops the Python field, and the C struct is IPC-only. That is not
tidiness. A remote peer that could stamp its own competence multiplier would
hold a lever on every EMA it appears in — the same reason `tx_channel_weight`
is applied to locally-produced evidence only (§12.8). Absent (`None`, or a
non-positive double from a zeroed struct) means 1.0, which is what every
producer predating this field meant.

## The record

Per-node, process-local, unsynchronised — for the same reason as the physics
window and the coverage audit's rings: every loss it holds was resolved by
this node, and what leaves the node is an ordinary weighted score that every
peer judges on its own terms.

Outstanding forecasts are keyed by **quantity**, because one observation
resolves every peer's outstanding forecast about it at once. Resolved losses
are a per-`(peer, capability)` ring, which makes the multiplier a sliding
window: a peer that forecast badly a year ago and has since improved ages out.

The ring is **slot-ordered in both runtimes**. C holds a fixed array with a
head index, and Python mirrors that layout rather than using a `deque`,
because the mean is a floating-point sum and summation *order* is part of the
answer if the two runtimes are to agree to the last bit.

## The declaration

`prequential.json`, canonical JSON read directly by both runtimes — the
arrangement `physics.json`, `certificates.json` and `calibration.json` use.
`AT_PREQUENTIAL` names it; `config/cfg/prequential.example.json` is the shared
example.

```json
{
  "version": 1,
  "min_samples": 8,
  "max_outcomes": 64,
  "max_outstanding": 32,
  "horizon_sec": 60.0,
  "eta": 1.0,
  "weight_band": {"min": 0.5, "max": 2.0},
  "capabilities": {
    "demo.thermal-forecast": {
      "quantity": "demo.bus-temp",
      "scale": 20.0,
      "alpha": 0.1,
      "horizon_sec": 120.0
    }
  }
}
```

`quantity` is the link to `physics.json`, as in §12.4: it is what lets an
ordinary later result resolve a forecast with no application involvement.
`resolve()` is the same explicit override, for a truth that never arrives as a
task result.

What the declaration deliberately does **not** contain is the arithmetic: the
interval score, the normalization and the band map are code in both runtimes,
for the reason the physics units table and the binomial tail are. An operator
who could redefine the loss could weight any peer by declaration.

### Opt-in, inert, and fatal on malformed

With `AT_PREQUENTIAL` unset the model is empty, every multiplier is 1.0 and
nothing that has not opted in changes behaviour. A malformed declaration is
fatal at load and never degraded to "learn the capabilities that parsed".
Three consistency rules are enforced there rather than discovered at runtime:

* `max_outcomes < min_samples` — the ring could never reach the threshold, so
  the layer would be silently inert.
* a `weight_band` that does not contain 1.0 — the authored weight would no
  longer be reachable, so the operator's number would not be the anchor it is
  documented to be.
* two capabilities forecasting the same `quantity` with different `alpha` or
  `scale` — the aggregate is a single interval and so has a single level, and
  the mixture loss adds peers' losses together, which means nothing if they
  were divided by different scales. Two peers scored at different levels for
  one quantity are not being compared at all, which is the same argument that
  makes `alpha` the operator's to declare.

## Cross-runtime parity

Both runtimes weight the same peers off the same declaration, and a peer one
weights at 2 and the other at 1 would make the EMA depend on which
implementation happened to be scoring. So the arithmetic is identical, not
merely equivalent:

* the interval score's operation order is fixed and shared;
* the ring mean sums in slot order on both sides;
* the Hedge weights use `exp`/`log` with a max-shift — both go straight to
  libm, unlike the `lgamma` §12.4 had to abandon
  ([calibration-audit.md](calibration-audit.md));
* the integer weight rounds by `floor(x + 0.5)`, not by either language's
  native rounding (Python's `round` is banker's, C's `lround` is
  half-away-from-zero, and they disagree at exactly 0.5).

The two runtimes cannot share a call site, so what the corpus pins is the
rules. The `prequential` conformance protocol replays a declaration and an
event sequence through each runtime's own estimator and asserts the loss, the
multiplier, the resolved record, the aggregate forecast and the realized
regret bound per row.

## See also

* [Calibration Audit](calibration-audit.md) — step 3, the other half of the
  same `prediction` artifact, and the layer whose one-sidedness this completes
* [Physical Consistency](physical-consistency.md) — step 1, and the source of
  the `quantity` declarations both layers resolve against
* [Trust Tiers](trust-tiers.md) — §8, where the authored `transaction_weight`
  this multiplier is anchored to is declared
* [Reputation Consensus](reputation.md) — where the weighted score lands
* [The Verification Oracle](../verification_oracle.md) — the full research framing
