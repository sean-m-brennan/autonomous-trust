*Previous: [Correctness proofs](correctness-proofs.md)*

# The Verification Oracle

The AT reputation machinery is a trust *algebra*. It takes a stream of
`TransactionScore` values, weights them by capability, aggregates them across
peers under Paxos, decays them with staleness, and quantizes the result into
trust tiers that gate capability access. That algebra is domain-independent and
it works.

What the algebra does not supply is the score itself. Something upstream has to
decide that a given interaction went well or badly, and today that something is
a human. The `trust_ladder.yaml` in each scenario declares which capabilities
exist, what tier each requires, and how heavily each transaction counts. Behind
that file sits a further human act: somebody decided what "correct" means for
`dod.fusion-validate`, and wrote the acceptance bound into the domain code that
emits the score.

This document is about that upstream step. Call it the **verification oracle**:
the function that maps an observed interaction to evidence about a peer. It is
the piece that has to become machine-general before AT can judge peers in a
domain nobody characterized in advance.

## Why the knowledge-representation route fails

The intuitive approach is to give the machine enough world knowledge to evaluate
claims on their merits. That is the Cyc program, and after four decades of
hand-axiomatized common sense it did not yield a usable general evaluator.
OpenCyc is gone and the residue is thin.

The failure is structural, not a matter of insufficient effort. Axiomatizing an
open domain is unbounded work, the axioms are contested at exactly the points
where evaluation matters, and the resulting system is brittle against inputs
outside the axiomatized fragment. An adversarial peer will find that fragment's
edge, because finding it is cheaper than respecting it.

Two fragments of that tradition did survive, and both survived because they gave
up generality in the right direction. **Qualitative physics** (Forbus's
Qualitative Process Theory, 1984; de Kleer and Brown's confluences, 1984)
axiomatizes physical processes rather than common sense, which is a closed and
agreed domain. **Consistency-based diagnosis** (Reiter's theory of diagnosis
from first principles, 1987; de Kleer and Williams' General Diagnostic Engine,
1987) does not evaluate claims at all: it takes a component model plus
observations and computes minimal sets of components whose failure would explain
the discrepancy. Both are used below. Neither requires knowing what the peers
are talking about in any general sense.

## The reframe

Do not attempt to judge whether a peer *knows* things. Judge whether its
**commitments pay off**.

Every peer utterance that matters is required to reduce to a dated, falsifiable
claim over observables in a state space the peers share. The verification oracle
then never needs a domain ontology. It needs a clock, a log, and a scoring rule.
A log-loss does not care what the domain was.

For an embodied system this reframe is close to free, because time supplies
ground truth continuously and without a human in the loop. The physics is the
shared latent state. A peer that claims a thermal margin, an ephemeris, a
resource level, or a link budget has committed to something the world will
adjudicate on its own schedule.

## Classifying a claim by what makes it checkable

The oracle is not one mechanism. It is a dispatch over five claim classes,
ordered by how cheaply they can be checked. The dispatch itself is the
architecture.

| Class | What the claim is | How it gets checked | Cost |
|---|---|---|---|
| A | Has a physically observable consequence | Wait, then score the prediction | Free, delayed |
| B | Computation admitting a certificate | Check the certificate | Sublinear to linear |
| C | Reproducible only by redoing the work | Sampled replication, dispute game | Expensive, reducible |
| D | Correlated only with other peers' private signals | Peer prediction, unsupervised fusion | Statistical, no hard verdict |
| E | No fact of the matter | Not an epistemic question | Route to governance |

The design discipline is to push claims leftward. A task interface that returns
a bare answer is class C. The same task redesigned to return an answer plus a
certificate is class B, and the check may be orders of magnitude cheaper than
the work. Most of the engineering value here is in interface design rather than
in the scoring algorithms.

## Class A: claims with physical consequences

### Layer 1: physical consistency as cheap hard falsification

Before any statistics, run the claim against physics. Conservation of mass,
energy, and momentum; dimensional and unit coherence; kinematic and geometric
feasibility; thermodynamic bounds. This axiom set is small, closed, and
uncontested, which is precisely what Cyc's was not.

Two techniques make it operational:

- **Analytical redundancy and parity relations**, the deployed aerospace
 fault-detection tradition (Isermann; Blanke et al., *Diagnosis and
 Fault-Tolerant Control*). Given a physical model and a redundant set of
 reports, form residuals that vanish under consistency and do not vanish under
 a fault, then isolate which report is responsible.
- **Set-membership and interval estimation** (Milanese; Jaulin's interval
 analysis). Where errors are bounded rather than stochastic, the intersection
 of interval constraints is a guaranteed feasible set. A claim outside it is
 *refuted*, not merely improbable.

The output of this layer is qualitatively different from everything below it. A
physics violation is a hard falsification and should carry a different
consequence than a poor statistical score. See "Keep the channels separate."

**Built, both runtimes, 2026-09-03.** Dimensional coherence, range and
kinematic feasibility, set-membership intersection and linear parity relations,
with the diagnosis below, feeding the `physical` channel at 0.1 and the
`swarm_disagreement` channel at 0.3. Declared in a `physics.json` that both
runtimes read; the units table is code in both and is deliberately not
declarable, since an operator who could redefine a newton could refute any peer.
It is opt-in and silent by default, and it never returns a good score --
surviving the check earns nothing, because a claim inside the feasible set is
merely not-refuted. See `doc/architecture/physical-consistency.md` and R+D.md
§12.2.

Substituting "peer" for "component" in the GDE formulation gives peer fault
isolation directly: conflicts are sets of peers who cannot all be reporting
honestly, and the diagnosis is a minimal hitting set over those conflicts. This
needs no reputation history and no learned model.

One refinement had to be *declined* in the build. The usual GDE move is to
prefer the cardinality-minimal diagnosis, which would convict a lone outlier
whenever two other peers corroborate each other -- conflicts {A,C} and {B,C}
resolve to {C} rather than to {C} *and* {A,B}. That is majority rule wearing
physics' clothes, and it would let three colluding peers refute an honest one on
the hardest channel in the system. Every subset-minimal diagnosis is kept
instead, so a peer in all of them is refuted and a peer in some is only
implicated. The distinction between those two is what keeps this layer from
becoming a vote.

### Layer 2: prequential scoring and regret-bounded weighting

For claims that survive layer 1, score them sequentially and never look inside
the peer. This is Dawid's **prequential principle** (1984): a forecaster is
assessed only by its record of predictions against outcomes.

Score with a proper scoring rule (logarithmic or Brier) applied to the peer's
predictive *distribution*, not its point estimate. Proper scoring rules are
uniquely maximized by honest reporting of the actual belief, which is the
property that makes them an oracle rather than merely a metric.

Aggregate with the prediction-with-expert-advice machinery: weighted majority
(Littlestone and Warmuth, 1994), Vovk's aggregating algorithm, and the general
treatment in Cesa-Bianchi and Lugosi, *Prediction, Learning, and Games* (2006).
This buys something AT does not currently have and cannot get from reputation
averaging: a **provable bound against arbitrary adversarial peers**, with no
assumption about the domain, the peer population, or the fraction that is
honest. Aggregate loss stays within O(sqrt(T log N)) of the best single peer in
hindsight.

The variant that matters for a peer mesh is **sleeping experts**, also called
specialists (Freund, Schapire, Singer and Warmuth, 1997), where a peer opines
only on some rounds and is scored only on those. This yields regional
competence, a peer trusted on thermal and distrusted on attitude, without anyone
declaring the regions in advance. That is a direct generalization of the
per-capability weighting in the trust ladder, learned rather than authored.

**Built, both runtimes, 2026-09-08.** Three things about the build differ from
what this section proposes, and each is deliberate.

The rule is the **Winkler interval score**, not log-loss or Brier. Those need a
predictive distribution, and what a reply actually carries is layer 3's
`prediction` box -- a central interval at a level. The interval score is proper
for exactly that object, and it decomposes into sharpness plus a miss penalty,
so a peer scores badly for being vague *or* for being confidently wrong. That
is the division of labour with layer 3, which is required to forgive the
over-cautious peer: the useless-but-honest forecaster is penalised here and
nowhere else. Nothing new went on the wire.

It **modulates** the authored per-capability weight rather than replacing it.
The learned multiplier is confined to a band the operator declares which must
contain 1.0, so the authored `transaction_weight` stays the anchor and a peer
with an excellent record on a trivial region cannot inflate its say on a heavy
one. Silent -- exactly 1.0 -- below `min_samples`.

And it is the one layer here that renders **no verdict at all**: no score, no
evidence channel. A peer whose forecasts are wide or wrong has told no lie, and
scoring it like a physically impossible claim would undo the distinction layer
3 exists to draw. What it produces is a weight.

The aggregation half was built with a claimant: `combine()` returns the
Hedge-weighted vincentized forecast and `regret()` reports the realized gap
against every peer beside `ln N / eta + eta T / 8`, so the O(sqrt(T log N))
guarantee this section claims is measured rather than asserted. Nothing in AT
core consumes the aggregate -- it is an API for an application that wants the
mesh's best estimate. See `doc/architecture/prequential-competence.md` and
R+D.md §12.5.

### Layer 3: calibration audit

**Conformal prediction** (Vovk, Gammerman and Shafer, *Algorithmic Learning in a
Random World*, 2005) requires a peer to emit prediction *sets* at a claimed
coverage level, and lets the observer audit realized coverage with finite-sample
validity and no distributional assumptions.

This separates two things reputation systems routinely conflate:

- **Competence.** The sets are tight.
- **Honesty about one's own limits.** The sets cover as advertised.

A peer that is frequently wrong but properly humble is safe to work with. A peer
that is usually right and systematically overconfident will eventually be
catastrophic, and an averaged reputation score will not see it coming until it
does. This layer is small to implement and needs no training data, which makes
it the best value per line of code in the whole stack.

As built it is falsification-only, like the physics layer: a rejected coverage
claim scores 0.1 on its own `calibration` channel and a passing audit earns
nothing, since covering as advertised is the least a peer can do. The gradualism
this section asks for -- a physical refutation should demote faster than a
drifting calibration score -- is the channel WEIGHT rather than a softened
number, `physical` at 3 against `calibration` at the baseline 1. The test is the
exact binomial tail, one-sided, so an over-cautious peer is not penalised: its
sets are useless, which is a competence problem, not a dishonest one. Below
`min_samples` resolutions it is silent rather than lenient. Predictions are
resolved by ANOTHER peer's later report of the same declared quantity, through
the `physics.json` mapping, with an explicit `resolve()` for truth that never
arrives as a task result. Declared in a `calibration.json` both runtimes read;
the arithmetic, like the units table, is code in both. See
`doc/architecture/calibration-audit.md` and R+D.md §12.4.

## Non-sensory work

The layers above depend on a shared observable state, and a large share of what
peers do has no such state. A peer plans, allocates, solves, decides, and
schedules. Nothing in the world immediately disagrees with a bad plan. The
concern that replicating identical tasks across peers is the only recourse is
correct as far as it goes, but replication is class C, and class C is the last
resort among the verifiable classes rather than the first.

### Certificates: exploit verification asymmetry

For a large fraction of computational work, checking is asymptotically cheaper
than producing. The discipline is to require every answer to arrive with a
witness that makes the check cheap. This is the **certifying algorithms**
program (McConnell, Mehlhorn, Naeher and Schweitzer, "Certifying algorithms,"
*Computer Science Review*, 2011).

| Work | Certificate | Check |
|---|---|---|
| Constrained optimization | Primal solution plus dual, or a Farkas certificate of infeasibility | Evaluate constraints and duality gap |
| SAT | Satisfying assignment; DRAT or LRAT refutation for UNSAT | Linear, or proof-length |
| Route or path planning | The path itself, plus an admissible lower bound for the optimality claim | Linear in path length |
| Linear solve | Residual norm, or an interval enclosure of the solution | One matrix-vector product |
| Matrix product | None needed: Freivalds' randomized check | O(n^2) against O(n^omega) |
| Scheduling | Schedule plus slack witness | Linear in tasks |
| Matching, flow | The matching plus an LP dual or min-cut witness | Linear |
| State estimation | Innovation sequence | Whiteness test |

Where a certificate exists, peer judgment reduces to running the checker, and
the oracle becomes exact rather than statistical. Where one does not exist yet,
redesigning the task interface to produce one is usually a better investment
than any amount of reputation modelling.

**Built, both runtimes, 2026-09-03.** All eight rows, checked exactly and pinned
against each other by the `certificate` conformance protocol. This is the only
layer in the oracle that returns a GOOD score --- a verified witness means the
answer is proved right, where surviving the physics layer means only that it was
not refuted --- so it both rewards and punishes, and a disagreement between
runtimes would matter in both directions.

Two rows needed their naive form rejected. "The path plus an admissible lower
bound" is not checkable as stated, because a peer returning a detour can assert
a bound equal to its own cost; what is checkable is the bound's own witness, a
feasible potential (the LP dual), verified in one pass over the edges. And a
DRAT replay must insist the proof reaches the EMPTY CLAUSE: a hundred sound
lemmas that never do prove nothing about satisfiability, and accepting them
would let a peer claim UNSAT by emitting arbitrary valid inferences.

The declaration also carries the negative case, which is what makes the last
paragraph above actionable: `checker: null` marks a capability somebody examined
and found uncertifiable, distinct from one nobody has considered, and each node
reports the inventory of both. See
`doc/architecture/certificate-interfaces.md` and R+D.md §12.3.

### Replication, made affordable

For work that genuinely resists certification, replication is correct. Three
things make it far cheaper than replicating everything:

**Sample rather than replicate.** Duplicate a random fraction p of tasks instead
of all of them. If detection costs the peer a multiplicative reputation loss L
and a completed task gains it g, cheating is unprofitable whenever p * L > g. In
the AT terms L is a tier demotion or exclusion, which is large, so p can be
small. This is the volunteer-computing argument (BOINC and its descendants) and
it transfers directly.

**Scale replication to consequence, not uniformly.** A `tier 4`
`command-issue`-class task warrants three-way replication; a routine query
warrants none. The capability weights already in `trust_ladder.yaml` are the
natural scaling parameter.

**Resolve disputes by bisection, not by re-execution.** When two replicas
disagree about a long computation, do not re-run it. Require a hash-chained
trace of intermediate states, then binary-search the trace for the first
divergent step and adjudicate that single step. Cost is logarithmic in the
computation length rather than linear. This is the verification-game structure
from Truebit and the fraud proofs of optimistic rollups, and it is the single
technique that makes replication practical for expensive work. It requires
deterministic replay, which is a real constraint on how peer tasks are written.

Two honest caveats. Independently developed replicas fail in correlated ways;
Knight and Leveson (1986) demonstrated this against the central assumption of
N-version programming, and the result has held up. Replication also buys nothing
against peers that are sincerely wrong in the same way, which is the normal case
when they share a library, a model, or a calibration source. Diversity has to be
engineered deliberately, and where it cannot be, replication detects malice but
not error.

### Force a sensory consequence

The strongest general move is to refuse to let claims stay non-sensory. Require
every consequential non-sensory output to carry at least one dated, observable
prediction: not just "here is the plan" but "if you execute this, expect state X
within tolerance Y at time t plus tau."

This is a message-schema requirement rather than an algorithm, and it converts
class C and class D claims into class A over time. The cost is latency in the
evidence. The prediction cannot gate the decision being made now, but it does
gate the standing for every decision after t plus tau, which is what a
reputation system is for. Most of the "no correlation" worry dissolves under
this requirement, because in an embodied system almost nothing is truly
non-sensory. The problem is delayed credit assignment, not absent ground truth.

A related point about stochastic work. Some tasks legitimately fail, and scoring
raw outcomes punishes bad luck and rewards recklessness. The fix is again the
proper scoring rule: require the peer to state its own success probability, and
score the stated distribution. A peer that says "70 percent within budget" and
delivers 70 percent of the time is an excellent peer.

### Score the advice you did not take

If only the accepted recommendation ever generates evidence, reputation becomes
self-confirming: the currently trusted peer keeps getting scored, its rivals
stay frozen at their priors, and a peer that degrades quietly while remaining
top-ranked is invisible.

**Off-policy evaluation** breaks this. Doubly robust estimators (Dudik, Langford
and Li, 2011; Jiang and Li, 2016) estimate what the outcome would have been
under a rejected peer's recommendation, using the logged decisions and outcomes
AT already keeps. Combined with a small deliberate exploration budget, this
yields counterfactual evidence about peers whose advice was never followed.

*Correction, 2026-08-21:* "the logged decisions AT already keeps" overstates
what exists. AT does not choose among peers at all. A requestor announces a task
to every capable peer and every peer that accepts is enrolled, so there is no
rejected recommendation, no action selected from alternatives, and no propensity
to divide by — the estimator has nothing to be off-policy about. This is a
missing mechanism rather than a missing log, and the mechanism (a requestor
selecting among willing peers) has consequences of its own for redundancy and
for how bilateral history accumulates. R+D.md §12.7 carries the design.

### Self-consistency over a claim archive

The cheapest oracle of all requires no peers, no physics, and no domain
knowledge: check a peer against its own past claims. A hash-chained, signed
claim log gives non-repudiation, and contradiction detection over that log is a
hard falsification. The archive machinery on the kith-covenant and ethne side
already provides the log shape this needs.

Two signals fall out of the same structure. A peer whose claims contradict each
other over time is falsified outright. A peer whose claims are never cashable
into anything checkable, always hedged, always past the horizon, is itself
exhibiting a signal, and an oracle that only scores checkable claims will rate
it neutral forever unless unfalsifiability is scored explicitly.

### Attestation as a shortcut

Where the identity and ZTA machinery can attest the binary and its inputs, the
output does not need verification at all. This is the cheapest path where the
hardware supports it. Its limit is worth stating plainly: attestation proves
that the intended code ran on the intended inputs. It says nothing about whether
that code is correct, and it is therefore a substitute for replication but not
for the class A layers.

### The residue is not an epistemic problem

Some disagreements have no fact of the matter: priorities, risk appetite,
allocation among legitimate competing claims, what the mission is for. No oracle
resolves these, and judgment aggregation is formally obstructed anyway (List and
Pettit's doctrinal paradox and the impossibility results around it).

The oracle's obligation for this class is to *recognize* it and route it out
rather than manufacture a score. A confidence number attached to a value
disagreement is worse than no number, because it launders a political question
into a technical one and gives the winning faction a machine-issued warrant.
This class belongs to the polity tier. Where the disagreement still needs
structured handling below governance, Dung's abstract argumentation frameworks
(1995) compute grounded and preferred extensions over an attack relation without
requiring any truth oracle.

## Anchoring and the adversarial fraction

Every mechanism above has a breaking point in the fraction of the population
that is adversarial. The Byzantine-robust aggregation literature is explicit
about it: Krum (Blanchard et al., 2017), coordinate-wise median and trimmed mean
(Yin et al., 2018), Bulyan (El Mhamdi et al., 2018), and the impossibility of
beating a majority without an external reference.

The escape is a small trusted anchor. FLTrust (Cao et al., 2021) shows that a
tiny root of verified data restores robustness well past where unanchored
aggregation fails. The embodied analogue is the **honeypot probe**: occasionally
assign a peer a task whose answer is already known or independently cheap to
verify. The AT bootstrap corpus (`at.handshake`, `at.time-attest`,
`at.echo-challenge`) is already this pattern applied at cold start; the
generalization is to keep probing throughout the relationship rather than only
during bootstrap.

Probe allocation is a best-arm-identification problem, not a uniform sampling
problem. Spend probes where the posterior over a peer's quality is widest and
the capability weight is highest.

**Implemented, 2026-08-21, with one correction to the above.** The bootstrap
corpus now probes throughout the relationship rather than only at cold start,
allocating by the rule in this paragraph, and — the part that turned out to
matter most — it now actually *checks the answers*. The known-answer verifiers
had been present in both runtimes since the corpus shipped and were called by
nothing, so the pattern this section treats as already-applied-at-cold-start was
not applied at all: a peer that tampered with an echo scored what an honest peer
scored. The anchor was nominal.

The correction concerns the allocation rule as stated. "Widest posterior" is
implemented as the UCB1 exploration term over per-peer probe counts, which is
the honest reading given that probe *outcomes* are scored elsewhere and do not
return to the prober; a Beta posterior would need feedback that does not exist
yet. And "capability weight is highest" cannot be combined with the uncertainty
term multiplicatively, which is the obvious implementation: because the UCB
bonus falls off as the inverse square root of the count, weight times bonus
allocates probes proportional to weight *squared*, so at a weight of 8 a light
capability is not selected until the heavy one has been probed 64 times more.
Capabilities are therefore allocated by weight over count, which settles at
counts proportional to weight and keeps the whole corpus exercised. Peers and
capabilities get different rules because they are different problems: for a peer
there is a bad arm to identify, and for a capability there is only a budget to
divide.

**Both runtimes now score a probe end to end** (a later pass, same entry). The
C side had three separate gaps rather than one: a serialized task carried no
invocation arguments, so the challenge could not reach a responder; the C
capability signature returns void, so an answer could not be collected even
after the work ran; and nothing drained the queue of accepted jobs at all. All
three are closed, and the C requestor now judges a reply against the challenge
it retained and submits the score with its evidence channel. The scoring lives
in C's negotiation process rather than its main process, because that is where
that runtime keeps the requestor's record of what it asked — so what the
conformance corpus pins across the two is the scoring *rules*, fed through each
runtime's own scorer. See `doc/architecture/trust-tiers.md` §6 for the shape and
R+D.md §12.7 for what remains, which is now the off-policy half and its
dependency on AT having no peer-selection decision to be off-policy about.

All of this presumes identity is costly. Without that, an adversary answers a
bad reputation by acquiring a new one (Douceur, 2002), and the AT identity layer
is what holds that door shut.

## Skeptical inference over silence

A design constraint rather than an algorithm, and cheap enough to be worth
stating on its own. When claims are verifiable and *withholding is detectable*,
rational skepticism drives full disclosure as an equilibrium: this is the
unraveling result from the disclosure literature (Grossman, 1981; Milgrom and
Roberts, 1986). A peer that declines to report knows it will be treated as
having reported the worst plausible value, so it reports.

The engineering consequence is that non-report must be structurally visible.
Absence of evidence has to become evidence, or the cheapest evasion available to
a degrading peer is to stop speaking. This is the same failure mode found on the
erosion-legibility side: act-triggered measures cannot see a polity that merely
stopped, and only absolute measures catch it.

## Keep the channels separate

The four oracle layers plus the non-sensory mechanisms produce evidence of
different kinds, and collapsing them into one scalar before it reaches the
reputation algebra destroys information the escalation path needs.

"Refuted by conservation of energy," "poorly calibrated over the last hundred
predictions," "disagrees with the swarm," "failed a replicated task," and
"contradicted its own archive" have different diagnoses and warrant different
responses. A physics refutation should be able to demote a peer faster than a drifting
calibration score does; swarm disagreement was expected to want a dispute rather
than a penalty. Feeding them as separate evidence channels into the existing
consensus keeps the tier machinery unchanged while making the demotion reason
legible. What that came to in practice is below, and the third response turned
out not to be needed.

**The channel, 2026-08-21.** `TransactionScore` now carries a `channel` naming
which of these produced the score, on both runtimes and across the wire. The
vocabulary is the build order below: `task_outcome` (the default), `physical`,
`certificate`, `calibration`, `self_consistency`, `replication`,
`swarm_disagreement`, plus `probe` from step 7. It is a closed set — an unknown
spelling is refused rather than graded — and it is defined once per language, in
`src/c/autonomous_trust/reputation/tx_channel.h` and the Python `TX_CHANNEL_*`
twin.

**Gradual versus decisive decay, 2026-09-01.** A per-channel multiplier on the
consensus average, composed with the per-capability weight, on both runtimes.
`calibration` sits at the baseline, exactly as the paragraph above asks; a
verdict that needs no history at all (`physical`, `certificate`,
`self_consistency`) counts triple; evidence corroborated by construction
(`replication`, `probe`) counts double. It applies only to evidence the scoring
node produced itself: the scorer picks its own tag, so honouring a remote peer's
channel would let any peer treble the weight of a score it fabricated against
any other.

**The reason became part of the committed fact, 2026-09-02.** This section asked
for the reason to be *legible*; it was not yet *durable*. The commit broadcast
carried a bare score, so every acceptor wrote the number and dropped the reason,
which survived only in the scorer's own log. A chain entry now carries each
side's channel and the canonical bytes cover it, so the entry hash, the chain
link, the window root and the quorum-signed checkpoint over it all cover it too
— and the reason travels with the entry onto the catch-up wire, into the
persisted evidence a warm start verifies, and into the answers deep resolution
returns. The block is appended to the canonical bytes only when a channel other
than `task_outcome` is present, which is what keeps every stored chain and every
byte-pinned root valid; stripping a real channel still changes the bytes.

**No immediate demotion, and no dispute.** The two mechanisms this section
anticipated are both gone, for one reason.

For a day (2026-09-01 to 2026-09-02) a defection-grade score on a hard
falsification channel *proposed* a slash, pinning the peer below the tier-1
floor. That was removed at the user's direction, and the argument generalizes:
a transaction is scored poorly **with its reason given**, every peer sees both,
and each judges for itself. Discipline is then the consensus average and the
tier machinery at their own pace — graduated by construction — rather than one
detector's verdict on a fast path around them. What remains of slashing is the
deliberate act (the behaviour governor's human-on-the-loop path, an operator's
exclude or rehabilitate), and its protocol is opt-in to match.

With no verdict levied, there is nothing to dispute. `swarm_disagreement` needs
no adjudicator, and none is planned for either runtime; it sits at the baseline
multiplier, which is the honest weight for one peer's reading of one event.
Weighting it like a hard channel would have been precisely the wrong reading of
this section, since a majority is not an oracle. Step 6's bisection would still
be a way to *resolve a disagreement about a replicated computation* — that is a
falsification procedure, not an adjudication of standing, and it lands on the
`replication` channel like any other finding. See R+D.md §12.8 for the forks
settled at each step.

## On LLMs

The judgment that textual inference is the wrong tool for the online control
loop is right. Latency, determinism, and the absence of any grounding in the
physical state all argue against it, and the layers above deliberately require
none of it.

One narrow role does survive: **offline schema alignment**. Translating peer A's
claim vocabulary into a predicate peer B's checker can evaluate is the brittle
joint in any multi-agent epistemology, it is genuinely a language problem, and
it happens at commissioning time rather than in the loop. The embodied
competence itself belongs to learned forward models, which are then scored
prequentially like any other predictor.

## Build order

Cheapest and most general first:

1. **Physical consistency and dimensional refutation.** No history, no training
 data, hard verdicts. **DONE 2026-09-03**, both runtimes, pinned by the
 `physics` conformance protocol.
2. **Certificate-carrying task interfaces.** Interface work, not algorithm work,
 and it collapses most of the non-sensory problem. **DONE 2026-09-03**, both
 runtimes, all eight rows of the table above, pinned by the `certificate`
 conformance protocol.
3. **Conformal coverage audit.** Small, distribution-free, and catches the
 overconfident peer that averaged reputation cannot see. **DONE 2026-09-04**,
 both runtimes, pinned by the `calibration` conformance protocol.
4. **Prequential log-loss with sleeping-expert weights.** Replaces authored
 per-capability weights with learned regional competence. **DONE 2026-09-08**,
 both runtimes, pinned by the `prequential` conformance protocol — and it
 *modulates* the authored weights rather than replacing them, within a band
 the operator declares, so the operator's number stays the anchor. It is the
 only layer here that renders no verdict: what it produces is a weight.
5. **Self-consistency checking over the signed claim archive.** Nearly free
 given the archive already exists.
6. **Sampled replication with bisection dispute resolution**, for what remains.
   **BUILT 2026-09-08** at the conformance level (A sampling, B agreement
   adjudication, C the bisection game), both runtimes, pinned by the
   `replication` protocol; live replica dispatch stays gated on deterministic
   replay. See `doc/architecture/replication.md`.
7. **Off-policy scoring and honeypot probes**, to break reputation lock-in and
 anchor against a large adversarial fraction.
8. **Peer prediction** for the unverifiable residue, if any survives step 3.

Steps 1 and 2 are where the leverage is. Steps 7 and 8 are the ones that need
real statistical care, and they are needed least often.

Steps 1 through 4 are now built in both runtimes (2026-09-03 through
2026-09-08). Step 5, self-consistency checking over the signed claim archive,
is next in this order.

## References

Trust aggregation and reputation
- Josang, *Subjective Logic*.
- Douceur, "The Sybil Attack," IPTPS 2002.

Diagnosis and physical consistency
- Reiter, "A Theory of Diagnosis from First Principles," *Artificial
 Intelligence* 32(1), 1987.
- de Kleer and Williams, "Diagnosing Multiple Faults," *Artificial Intelligence*
 32(1), 1987.
- Forbus, "Qualitative Process Theory," *Artificial Intelligence* 24, 1984.
- de Kleer and Brown, "A Qualitative Physics Based on Confluences," *Artificial
 Intelligence* 24, 1984.
- Blanke, Kinnaert, Lunze and Staroswiecki, *Diagnosis and Fault-Tolerant
 Control*.
- Jaulin, Kieffer, Didrit and Walter, *Applied Interval Analysis*.

Prequential assessment and online aggregation
- Dawid, "Present Position and Potential Developments: Some Personal Views.
 Statistical Theory: The Prequential Approach," *JRSS-A* 147, 1984.
- Littlestone and Warmuth, "The Weighted Majority Algorithm," *Information and
 Computation* 108, 1994.
- Cesa-Bianchi and Lugosi, *Prediction, Learning, and Games*, 2006.
- Freund, Schapire, Singer and Warmuth, "Using and Combining Predictors That
 Specialize," STOC 1997.

Calibration
- Vovk, Gammerman and Shafer, *Algorithmic Learning in a Random World*, 2005.

Elicitation without verification
- Dawid and Skene, "Maximum Likelihood Estimation of Observer Error-Rates Using
 the EM Algorithm," *JRSS-C* 28(1), 1979.
- Miller, Resnick and Zeckhauser, "Eliciting Informative Feedback: The
 Peer-Prediction Method," *Management Science* 51(9), 2005.
- Prelec, "A Bayesian Truth Serum for Subjective Data," *Science* 306, 2004.
- Dasgupta and Ghosh, "Crowdsourced Judgement Elicitation with Endogenous
 Proficiency," WWW 2013.
- Shnayder, Agarwal, Frongillo and Parkes, "Informed Truthfulness in Multi-Task
 Peer Prediction," EC 2016.
- Radanovic and Faltings, Peer Truth Serum.

Certification and verifiable computation
- McConnell, Mehlhorn, Naeher and Schweitzer, "Certifying Algorithms," *Computer
 Science Review* 5(2), 2011.
- Freivalds, "Probabilistic Machines Can Use Less Running Time," IFIP 1977.
- Knight and Leveson, "An Experimental Evaluation of the Assumption of
 Independence in Multiversion Programming," *IEEE TSE* SE-12(1), 1986.

Byzantine-robust aggregation and anchoring
- Blanchard, El Mhamdi, Guerraoui and Stainer, "Machine Learning with
 Adversaries: Byzantine Tolerant Gradient Descent," NeurIPS 2017.
- Yin, Chen, Ramchandran and Bartlett, "Byzantine-Robust Distributed Learning,"
 ICML 2018.
- El Mhamdi, Guerraoui and Rouault, "The Hidden Vulnerability of Distributed
 Learning in Byzantium," ICML 2018.
- Cao, Fang, Liu and Gong, "FLTrust: Byzantine-robust Federated Learning via
 Trust Bootstrapping," NDSS 2021.

Counterfactual scoring
- Dudik, Langford and Li, "Doubly Robust Policy Evaluation and Learning," ICML
 2011.
- Jiang and Li, "Doubly Robust Off-policy Value Evaluation for Reinforcement
 Learning," ICML 2016.

Disclosure and aggregation limits
- Grossman, "The Informational Role of Warranties and Private Disclosure about
 Product Quality," *Journal of Law and Economics* 24, 1981.
- Milgrom and Roberts, "Relying on the Information of Interested Parties," *RAND
 Journal of Economics* 17, 1986.
- List and Pettit, "Aggregating Sets of Judgments: An Impossibility Result,"
 *Economics and Philosophy* 18, 2002.
- Dung, "On the Acceptability of Arguments and its Fundamental Role in
 Nonmonotonic Reasoning, Logic Programming and n-Person Games," *Artificial
 Intelligence* 77, 1995.

## See also

- [Reputation Consensus](architecture/reputation.md): the trust algebra this
 oracle feeds.
- [Trust Tiers](architecture/trust-tiers.md): capability weighting, the
 bootstrap corpus, and the `trust_ladder.yaml` the oracle is meant to
 generalize.
- [Concept](concept.md): why behavioral evaluation rather than authored policy.
- [Physical Consistency](architecture/physical-consistency.md): step 1 as built
 -- the checks, the diagnosis, and the declaration format.
- [Certificate-Carrying Interfaces](architecture/certificate-interfaces.md):
 step 2 as built -- the eight checkers, the three declared states, and the
 inventory.
- [Calibration Audit](architecture/calibration-audit.md): step 3 as built -- the
 exact test, the two resolution paths, and why a passing audit earns nothing.
- [Prequential Competence](architecture/prequential-competence.md): step 4 as
 built -- the interval score, the bounded weight band, and the one layer here
 that renders no verdict.
- [Adversarial Testing](architecture/adversarial-testing.md): the attack side of
 the same problem.

---

*Next: [Testing approach](testing.md)*
