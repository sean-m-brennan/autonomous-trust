*Previous: [Prequential competence](prequential-competence.md)*

# Sampled replication with bisection dispute resolution

*Build-order step 6 of the [verification oracle](../verification_oracle.md);
tracked as R+D.md §12.6.*

The layers before this one all exploit some asymmetry that lets a claim be
checked more cheaply than it was produced: a certificate that verifies in one
pass, a coverage record that accumulates for free, a physical law that a
fabrication violates. For work that offers no such handle, the only recourse
left is to **do the work again** — replication — and the reason it sits last in
the build order is that it is the expensive recourse. This layer is the three
things that make it affordable enough to keep, and the game that makes a
disagreement cheap to resolve.

The outcome lands on the `replication` [evidence channel](reputation.md) like
any other finding — a falsification procedure, **not** an adjudication of
standing (R+D.md §12.8). The channel already weighs a replication finding twice,
because a result an independent executor reproduced is corroborated by
construction. Nothing here proposes a slash or a demotion; it produces a
`TransactionScore`, every peer sees it with its reason, and the tier machinery
moves at its own graduated pace.

## Three affordances

**Sample rather than replicate.** Duplicate a random fraction `p` of completed
tasks, not all of them. If detecting a cheat costs the peer a multiplicative
reputation loss `L` and a completed task gains it `g`, cheating is unprofitable
whenever `p · L > g`. In AT terms `L` is a tier demotion or an exclusion, which
is large, so `p` can be small — the volunteer-computing argument (BOINC and its
descendants), which transfers directly.

**Scale to consequence, not uniformly.** A tier-4 `command-issue`-class task
warrants replication a routine query does not. The natural scaling parameter is
the capability weight the operator already authors in `trust_ladder.json`, but
this layer does not *derive* the probability from that weight: a derived number
would decide, opaquely, how closely a peer is watched. The operator sets
`replicate_prob` per capability in the declaration, in proportion to
consequence, the same authored-anchor discipline the `transaction_weight` and
the calibration level follow.

**Resolve a disagreement by bisection, not re-execution.** When two executors
disagree about a long computation, do not re-run it. Localize the fault to a
single step of a hash-chained trace by binary search, and adjudicate that one
step. The cost is logarithmic in the length of the computation rather than
linear — the verification-game structure of Truebit and the fraud proofs of
optimistic rollups.

## The declaration

`config/cfg/replication.example.json`, schema version 1:

```json
{
  "version": 1,
  "default_prob": 0.05,
  "capabilities": {
    "demo.command-issue": {"replicate_prob": 0.5},
    "demo.query":         {"replicate_prob": 0.0, "tolerance": 0.0}
  }
}
```

Probabilities are validated into `[0, 1]` on load — a bad authored number is a
mistake to surface, not to paper over. `tolerance` (default `0.0`, exact) is the
per-capability numeric agreement bound the adjudicator uses for a task's final
result. `default_prob` covers a capability the declaration does not name.

## Sampling

The decision is one draw against the probability:

```
draw   = uniform_unit(seed)          # top 53 bits of SplitMix64(seed), in [0,1)
sample = draw < clamp(prob, 0, 1)    # strict: p=0 never, p=1 always
```

The **seed** is the verifier's own randomness at check time, exactly as it is
for the Freivalds challenge in the [certificate layer](certificate-interfaces.md):
it must be unpredictable to the executor — so a cheat cannot confine itself to
the tasks it knows will go unchecked — and reproducible for the corpus, both of
which hold when the seed is a parameter rather than derived from the task. The
draw keeps the high 53 bits (a double's mantissa) so `(u >> 11) · 2⁻⁵³` is exact
and the two runtimes decide identically.

## Adjudication by agreement

Once a task is replicated, several executors return a result and the adjudicator
renders a per-executor verdict, in the same two-method shape as the certificate
verifier — `adjudicate` returns the finding, `verify` maps a verdict to a
`(score, channel)` or to nothing:

| verdict | when | score on `replication` |
|---|---|---|
| `corroborated` | agrees with a strict majority (or all agree) | 0.9 — proved right |
| `outvoted` | in the minority against a strict majority | 0.1 — proved wrong |
| `dispute` | **no** strict majority (the common two-way case) | *none* — goes to the game |
| `single` | fewer than two results — nothing was replicated | *none* |

The majority must be *strict* — held by more than half, `2 · count > n` — so a
2-2 split is a dispute, not a coin toss. Two numeric results agree within the
capability's tolerance; anything else agrees only on exact equality, and a
numeric result never agrees with a non-numeric one (Python's `42 == "42"` is
false, and the C twin keeps the two apart for the same reason). **A dispute
scores nobody**: a majority is not an oracle, and one replica's word must never
let it defame the executor it was checking. That is exactly the case the game
resolves.

## The bisection game

Each executor commits to a chained digest over its trace:

```
h₀ = H(s₀)                 h_i = H(h_{i-1} ‖ s_i)
```

`H` is the codebase's Merkle primitive — blake2b, 64-char lowercase hex — so a
committed root is identical in both runtimes and an executor's commitment
verifies against itself across a boundary. The chaining is the whole point:
because `h_i` depends on every state up to `i`, **"the two chains differ at
index i" is monotonic** — once they differ they differ forever — and a binary
search finds the *first* divergent step in `O(log n)` challenges without either
executor revealing more than one digest per round. A bare list of states admits
no such search: two states can differ at `k` and agree again at `k+1`, and a
binary search over it could convict the honest executor.

At the first divergent step the pre-state is agreed (both chains match up to
there), so re-executing that one step from it yields the correct next state. The
executor that reproduced it is `corroborated`; one that did not is `outvoted`.
Both can be outvoted — two executors wrong in different ways at the same step —
which is the honest outcome, not a tie. Two identical traces never diverge and
are not a dispute at all.

## Live replication

The sampling, the adjudication and the game are pinned bit for bit across both
runtimes by the `replication` conformance protocol (`scenarios/replication/`),
and since 2026-10-22 they run live (`RD_12.6_LIVE_REPLICATION_PLAN.md`, the
user's calls in §0.1, the wire in §3.7).

**What is replicated.** Only a capability the operator's declaration
(`$AT_REPLICATION`) gives a `replay` object: one whose code follows the step
contract, so that its executor can commit to a hash-chained trace (`max_steps`,
at most 256; `max_state_bytes`, 4096 by default). Its probability is its own
`replicate_prob`, else `default_prob`. Every other capability's live
probability is 0. A declaration the node cannot read stops it at start.

**The executor (core).** A replayable capability runs step by step: Python
`Capability(..., replay=Replayable(init, step, encode, result, decode))`, C
`capability_t.replay` (`capability_table_set_replay`). Its `TaskResult`
carries `trace_root` and `trace_len`, and the executor keeps the states for
60 s to answer the task's requestor, and nobody else, about any step
(`replay challenge` for a digest, `replay reveal` for h(k-2), s(k-1), s(k)).

**The requestor (this layer).** It attaches to the negotiation process
through the core's result hook. When a result of a replayable capability
arrives it draws once from fresh verifier entropy; if sampled, it holds the
result's score (the application still gets the answer) and sends the same task
to one other capable peer, drawn uniformly. Agreement within the declared
tolerance scores both 0.9 on `replication`. A disagreement between two
committed traces goes to the game, which the requestor settles by
re-executing the one divergent step with its own step contract; the honest
executor scores 0.9 and the other 0.1, and the 0.1 also goes out as a
verifier-attested entry so a cheater cannot keep it off the chain by
withholding its own half. Without a commitment or a step contract the dispute
is left to the ordinary arms. Everything is settled within twice the commit
timeout: a replica that never answered releases the primary to the ordinary
arms; an executor that goes quiet mid-game is not scored, and the one that
kept answering is settled by re-running its whole trace.

## Two honest caveats

Independently developed replicas fail in **correlated** ways — Knight and
Leveson (1986) demonstrated this against the central assumption of N-version
programming, and it has held up. Replication also buys nothing against peers
that are **sincerely wrong in the same way**, the normal case when they share a
library, a model, or a calibration source: the game localizes a *disagreement*,
and two executors that agree on a wrong answer present none. Diversity has to be
engineered deliberately, and where it cannot be, replication detects malice but
not shared error.

## Where the code is

* Python: `autonomous_trust.oracle.replication` — `sampling`, `adjudication`,
  `bisection` (with the live `ChallengeSession`), `model`, `live` (the
  requestor). The executor's half is core:
  `autonomous_trust.core._python.negotiation.replay` and `negprocess`.
* C twin: `src/c/extensions/replication/` — `sampling`, `adjudication`,
  `bisection`, `replication` (the declaration), `replication_live` (the
  requestor). Core: `negotiation/neg_replay.{h,c}`, the verbs and the result
  hook in `negotiation/neg_proc.c` / `neg_ext.h`.
* Conformance: `scenarios/replication/{sampling,adjudication,bisection,
  declaration,challenge-session}.yaml` and
  `scenarios/negotiation/replay-challenge-answered-by-the-executor.yaml`.
  The requestor's loop is tested in process by
  `tests/a_unit/test_replication_live.py` and
  `src/c/extensions/replication/test/replication_live_test.c`.

---

*Next: [Testing approach](../testing.md)*
