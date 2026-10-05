*Previous: [Getting work done](negotiation.md)*

# Earning standing

Reputation in AutonomousTrust is a number between zero and one that answers one
question. Given everything this node has seen, and everything its peers have
attested and it has agreed to, how much is this peer worth dealing with right
now?

Three properties separate it from the scores most systems carry. Nobody issues
it, since no authority exists to do the issuing. It is agreed rather than merely
held, because peers run a consensus round over each transaction score so that
all of them end up with the same history rather than each with a private
opinion. And it fades, because a score is a memory of past conduct, and a memory
that never faded would let a peer trade forever on one good week.

Those three properties cost a great deal of machinery, and this chapter is
mostly that machinery. The order runs from the outside in: what the numbers
mean, how a score is computed from a history, how peers come to share one
history at all, what happens across a restart, and lastly the attestation that
keeps any of it from being simply asserted.

## What the numbers mean

Reputation lives on a scale from zero to one, and there are no negative values.
The per-transaction scores feeding the arithmetic sit around 0.8 for a clean
result, 0.3 for an anomaly or a tamper, and 0.9 for a good one. Separately from
those, a small set of interpretation thresholds define the operating bands.
These constants are the single source of truth and are mirrored between the two
implementations.

| Value | Name | Meaning | Env override (default) |
|-------|------|---------|------------------------|
| 1.0 | n/a | maximally trusted | n/a |
| 0.5 | tier-1 floor and pivot | elevated-trust floor, and the per-transaction cooperate or defect pivot | n/a |
| 0.2 | `PREREP_NEUTRAL` | neutral, meaning no information yet | `AT_REP_NEUTRAL` (0.2) |
| 0.1 | `COMM_CUTOFF` | communication cut-off, below which a peer is excluded | `AT_REP_COMM_CUTOFF` (0.1) |
| 0.0 | slash floor | catastrophic failure, the floor a slash imposes | n/a |
| n/a | decay asymptote | idle-decay floor, just above neutral | `AT_REP_DECAY_ASYMPTOTE` (0.21) |
| n/a | persist gate | trusted-cohort persist threshold | `AT_REP_PERSIST_THRESHOLD` (0.5) |

The gap between neutral at 0.2 and the cut-off at 0.1 is the load-bearing part
of that table. We left it there precisely so the slash floor could sit at zero
with the participation cut-off just above it. A peer nobody knows anything about
starts at neutral, a small leeway above the cut-off, and only a peer that has
actively earned a sub-cut-off score is excluded. Ignorance and misconduct are
therefore different states rather than the same one.

All four thresholds honor environment overrides, read once at startup, and the
inspector dashboard reads the same cut-off variable, so its displayed line
tracks a re-adjusted backend rather than a compiled-in assumption.

### Where a score came from

A score says how well a peer did, and it does not, on its own, say how we know.
Those are different facts. "The proof it returned was invalid" and "the task
came back empty" can both be 0.3, and until 2026-08-21 nothing downstream could
tell them apart, because the number was all that crossed the wire.

Each `TransactionScore` therefore also carries an **evidence channel**, naming
which kind of finding produced it.

| Channel | What it means |
|---|---|
| `task_outcome` | ordinary grading of a completed task; the default |
| `physical` | refuted by a conservation law or dimensional analysis |
| `certificate` | a certificate-carrying interface checked out, or failed to |
| `calibration` | coverage or calibration drift, rather than a wrong answer |
| `self_consistency` | contradicted the peer's own signed claim archive |
| `replication` | outcome of sampled replication of the peer's work |
| `swarm_disagreement` | disagrees with the swarm |
| `probe` | failed or passed a challenge whose answer we already knew |

`probe` is worth separating from the rest even though it is also, mechanically,
a completed task. It is the only channel that does not weaken as the adversarial
fraction of a cohort rises. Every other channel is ultimately an aggregate over
peers, and a majority cannot be beaten without an external reference, so a probe
is that reference. It is also distinct from `certificate`, and the difference is
who chose the question. A certificate is a proof the peer supplies about its own
work; a probe is a question the verifier authored and already knows the answer
to, which a peer cannot tell from real work. The bootstrap corpus is where these
come from; see [Trust tiers](trust-tiers.md) §6.

Where these scores come from is worth stating once, because the two runtimes
place it differently and both places are correct for the runtime they are in.
The peer that *ran* the work submits its own half, being its claim to have done
the job. The peer that *asked* submits the judgment: a known-answer probe
checked against the challenge it retained, or, failing that, a completion score.
Python does the judging in its orchestrator, which is also where it verifies any
proof attached to the result. C does it in its negotiation process, because that
is where C keeps the requestor's record of what it asked, and it attaches no
proofs, so it always takes the arm Python takes when proofs are unavailable. See
[Getting work done](negotiation.md).

The set is closed. A channel that is present but unrecognized is refused and the
proposal dropped, on the same reasoning as an off-scale score. The whole value
of the field is that a demotion reason means one agreed thing on both sides of
the wire, and an unrecognized spelling passed through, or quietly recorded as
`task_outcome`, would forfeit exactly that. Matching is case-sensitive. An
*absent* channel is a different matter and is not an error, since it means a
peer or an app predating the field, which was grading a task outcome by
construction, so it normalizes to `task_outcome` and every earlier producer
keeps its meaning.

The channel is part of the committed chain entry rather than only of the score
that produced it. It rides the commit broadcast, is written to every acceptor's
history, and enters the entry's canonical bytes. See [The reason is part of the
committed fact](#the-reason-is-part-of-the-committed-fact) for why, and for the
one condition keeping it from being a chain migration.

### What a channel does

Two things, and only for evidence this node produced itself.

**It weights the consensus average.** Each channel carries an integer
multiplier, composed with the per-capability `transaction_weight` from [Trust
tiers](trust-tiers.md). They multiply, so a heavy capability refuted on physics
counts as both. The multiplier is applied the same way the capability weight is,
by folding the score into the EMA that many times, which is why these are small
integers.

A third factor sits between those two when it has anything to say, being the
peer's learned competence on this capability ([Prequential
competence](prequential-competence.md)), a multiplier confined to an
operator-declared band around 1.0. So the full composition on the local path is
`transaction_weight x competence x channel`, rounded by `floor(x + 0.5)` and
floored at one fold. It is exactly 1.0, the authored weight verbatim, whenever
that layer is off, the capability is undeclared, or the peer's record is too
short to say anything, which is every case predating it. Like the channel
multiplier, it applies to locally-produced evidence only, and for the same
reason: a peer that could stamp its own competence would hold a lever on every
average it appears in.

| Multiplier | Channels | Why |
|---|---|---|
| 1 | `task_outcome`, `calibration`, `swarm_disagreement` | one peer's reading of one event |
| 2 | `replication`, `probe` | corroborated by construction — a replication has several executors, a probe is checked against an answer the verifier authored |
| 3 | `physical`, `certificate`, `self_consistency` | a verdict that needs no history at all |

These are a ranking of how much one observation tells you rather than a tuning
surface. `calibration` sits at 1 on purpose, because it is the channel that
should decay a peer *gradually*. An unrecognized spelling weighs 1 and never
more, so adding a channel on one side of the wire cannot silently amplify it on
the other.

The multiplier is not a ranking of how *trustworthy* a channel is, which is why
`probe` sits below the three above it despite being the channel that survives an
adversarial majority. Those are different virtues. A probe's strength is that
the aggregate cannot be captured by a colluding cohort, while a physics
refutation's strength is that one observation settles the question outright, and
the multiplier measures the second.

**It is retained as the reason.** See the next section. The channel enters the
committed entry, so every peer holding the chain holds the reason a score was
poor rather than only the number.

There is deliberately no third response, and in particular no automatic
accusation. Between 2026-09-01 and 2026-09-02 a defection-grade score on one of
the three hard-falsification channels *proposed* a slash, pinning the peer's
reputation from outside the consensus average on one detector's verdict. We
removed that, and the reasoning is the reasoning of this whole section. A
transaction is scored poorly **with its reason given**, every peer sees both,
and each judges for itself. Discipline is then the consensus average and the
tier machinery working at their own pace, which is graduated by construction,
rather than a fast path around them.

That also disposes of the question this section used to leave open. Since no
channel levies a verdict, there is nothing to dispute, so `swarm_disagreement`
needs no adjudicator and none is planned for either runtime. (A majority is not
an oracle, which is why weighting it like a hard channel would have been the
wrong answer too; it sits at the baseline multiplier.)

`physical`, `certificate` and `self_consistency` remain distinguished, because
they are *falsifications* rather than grades, and the peer did not do poorly so
much as assert something untrue. What that buys them is the top multiplier and a
legible reason, not an accusation.

What survives of slashing is the deliberate act, being the behaviour governor's
human-on-the-loop path and an operator's explicit exclude or rehabilitate. The
protocol they use is now opt-in to match. With `AT_SLASH_ENABLED` unset, which
is the default, a node originates no slash, declines to co-sign a peer's
proposal, and ignores a finalized one rather than applying its floor. Arm it
fleet-wide if you arm it at all, since a group where only some members are armed
will disagree about the floor, which is inherent to slashing being a policy
rather than a fact.

### The reason is part of the committed fact

A response consisting of "every peer judges for itself" only works if every peer
*retains* what it is judging. Until 2026-09-02 the channel stopped at the chain
boundary. The commit broadcast carried a bare score, so an acceptor wrote the
number and dropped the reason, and the reason survived only in the scorer's own
log and in flight, where a relay could alter it undetected.

So a chain entry now carries the channel of each side's score, and
`Transaction._canonical_bytes` covers it, which means the entry hash covers it,
and therefore so do the chain link, the window root, and the quorum-signed
checkpoint over that root. Stripping a refutation off an entry breaks the link.
The reason also travels wherever the entry does: the catch-up wire, the
persisted evidence document a warm start verifies, and the evidence-backed
answers deep resolution returns.

The one condition, which is what makes this an additive change rather than a
chain migration, is that the `|p1_channel|p2_channel` block is appended **only
when at least one side carries a channel other than `task_outcome`**. Three
consequences, each load-bearing:

- The same fact still hashes to the same bytes. An absent channel and an
  explicit `task_outcome` are the same claim, and both omit the block, so two
  nodes cannot disagree about an entry's hash because one of them received the
  default spelled out.
- Every entry committed before the field keeps its hash. Entry hashes chain and
  roll up into roots that are already signed, so appending unconditionally would
  have invalidated every stored chain, every finalized checkpoint and every
  byte-pinned corpus vector at once.
- The tampering that matters is still caught. Stripping a real channel changes
  the bytes; adding `task_outcome` to an untagged entry is a no-op because it
  asserts nothing.

An unknown spelling arriving on the commit path drops the whole commit rather
than being coerced to the default. Coercing would either fork this node's entry
hash away from the group's or silently rewrite the reason, and a peer sending
one is speaking a vocabulary this node does not have, which is exactly what the
closed set exists to catch.

`capability_name` deliberately did *not* travel with the channel. It would
publish a per-peer record of which capability every transaction exercised, and
per-capability weighting stays local.

### Only your own evidence counts

The *multiplier* applies only to a score this node produced. The scorer chooses
its own tag, so honoring a remote peer's channel would hand every peer a lever
on every other peer's reputation, since a fabricated 0.0 tagged `physical` would
land with triple weight. A score arriving from the wire keeps its channel, being
retained, committed and legible, which is the point, and is weighted by
capability alone.

Retention and weighting are different powers, and only the second is withheld. A
peer's claim about how it knows something is worth recording. It is not worth
letting that peer decide how heavily this node folds it in.

The cost is that two nodes can compute slightly different consensus averages for
the same peer. That is already true of the per-capability weights, since a
verifier across a trust boundary cannot reproduce them either, so this adds a
term to an existing local-view divergence rather than introducing one.

### What is still missing

Nothing in the channel machinery itself. The vocabulary, the multiplier and the
retention are all in place on both runtimes, and the third response the design
once called for, a dispute, was answered by deciding there is no verdict to
dispute.

What is missing is *producers*, and by now most of them exist. Six of the eight
channels are emitted by both runtimes: `task_outcome` and `probe` from the
scoring path itself, `certificate` from the certificate-carrying interfaces
(R+D.md §12.3), and `physical` plus `swarm_disagreement` from the
physical-consistency layer (§12.2), the first for a claim it refutes outright
and the second for a peer a conflict implicates without naming uniquely.
`calibration` arrived with the coverage audit (§12.4).

Two remain vocabulary waiting for the oracle layers that would emit them, being
`self_consistency` (build-order step 5, over the signed claim archive) and
`replication` (step 6, sampled re-execution).

We do not expect the set to grow to meet every layer. Prequential competence
(§12.5) deliberately emits **no** channel. It produces the learned weight
multiplier described above rather than evidence of its own, because a peer whose
forecasts are wide or wrong has told no lie, and a channel is part of the
committed fact, so adding one is a flag day: an acceptor that does not know a
spelling drops the score carrying it. See R+D.md section 12 and [the
verification oracle](../verification_oracle.md).

## Computing a score

When a reputation query arrives, the node computes the score by one of two
strategies, chosen by the current standing of the peer.

The mode switch uses hysteresis, which we added because a peer hovering near the
boundary used to flip modes on every tick, swinging between 0.9 and 0.4. A peer
must climb above 0.55 to enter cooperation mode and must fall below 0.45 to drop
back. Inside that band the previously selected mode is retained.

In *cooperation mode*, the score is pure reputation, being a weighted average of
every transaction score involving this peer. Each score carries two weights, the
reputation of the counterparty and the capability weight of the transaction, so
that a higher-tier capability counts for more.

```
score = Σ (counterparty_score · counterparty_rep · task_weight) / Σ task_weight
```

With no weighted history the computation returns neutral. The capability weight
is what ties this arithmetic directly to the tiered transaction model of the
next chapter.

In *tit-for-tat mode*, the strategy is contrite tit-for-tat over the bilateral
history between this node and the queried peer. If the peer defected, meaning
scored below the pivot, but local standing is itself poor, the response is to
cooperate. If the peer defected and local standing is fine, the response is to
defect. Otherwise cooperate. The contrition is the middle case, and it exists so
that two peers in a mutual downward spiral have a path out rather than a
ratchet.

## Agreeing on a history

Computing a score from a history presumes the peers share one. They do, and the
mechanism is a leaderless Byzantine Multi-Paxos protocol that runs a round per
transaction score. It assumes the identity protocol has already succeeded, so
consensus here is permissioned rather than open.

| Message | Constant | Direction | Purpose |
|---------|----------|-----------|---------|
| `ask permission` | `request` | proposer to group | Phase 1: request the floor with a unique proposal ID |
| `permission granted` | `grant` | peer to proposer | Phase 1: grant, with last-seen ID and chain length |
| `try again` | `nack` | peer to proposer | Phase 1: reject, timestamp too old |
| `out of date` | `backdate` | peer to proposer | Phase 1: the proposer index is behind |
| `transaction` | `transaction` | proposer to group | Phase 2: propose the transaction score |
| `tx accepted` | `accepted` | peer to proposer | Phase 2: accept the proposal |
| `tx committed` | `committed` | proposer to group | Phase 3: announce the commit |
| `update needed` | `outdated` | behind-peer to top peers | Sync: request missing history |
| `latest update` | `update` | peer to behind-peer | Sync: send a history segment |
| `request reputation` | `rep_req` | any process to reputation | Query: compute a score |
| `reputation response` | `rep_resp` | reputation to requester | Query: return the score |

Each round carries a unique proposal identifier built from a millisecond
timestamp, the chain index of the proposer, and the UUID of the proposer. These
combine into a float index for tracking.

The diagram below is generated from a conformance scenario by the documentation
build. It pins the Phase 1 happy path; the branches are documented as separate
scenarios.

<!-- at_diagram:start protocol=reputation scenario=reputation-canonical -->
```mermaid
sequenceDiagram
    participant alice as proposer
    participant bob as acceptor
    alice->>+bob: ask permission
    Note right of alice: Phase 1 — alice broadcasts an ask-permission ballot on the encrypted group channel. (id1, id2, proposer) uniquely tags the round; id1 is a millisecond timestamp, id2 is the proposer's chain index.
    bob-->>-alice: permission granted (re: 1)
    Note right of bob: Phase 1 — bob's last_id is None and chain is empty, so the strict-inequality guard passes; handle_request emits a grant ack back to alice. (Out-of-band nack / backdate / sync branches are documented in separate scenarios.)
```
<!-- at_diagram:end -->

All Paxos messages travel on the encrypted group channel. The two sync messages
are sent peer-to-peer, encrypted, addressed to the three most trusted peers of
the proposer.

*Phase 1 branches.* When the last identifier held by the acceptor is greater
than or equal to the proposed one, the strict-inequality guard fails and the
acceptor emits `try again` rather than a grant. The proposer then applies
exponential backoff, starting at two seconds and multiplying by 1.5 up to a
ninety-second cap, and retries with a fresher timestamp. Separately, when the
chain index of the proposer is behind the chain length the acceptor has
recorded, the acceptor emits `out of date` carrying its own length, which
triggers the sync sub-protocol.

*Phase 2, accept.* Once the proposer holds grants from a majority, it emits the
transaction carrying the score, keyed by the same round tuple. Each acceptor
verifies that the round was previously granted before emitting acceptance, and
the proposer commits to history on majority acceptance.

Both thresholds are sized per round from the round's own group as it stands
then, `n = len(peers)`, this node excluded: a round carries at `n // 2` grants or
more, and commits at more than `n // 2` acceptances. Both runtimes ask exactly
that. C used to compare against `n / 2 + 1` of a count read once at start-up,
before discovery had found anybody, so in production one grant and one
acceptance carried every round however large the group grew. The acceptance
test was already Python's (`>= n/2 + 1` is `> n // 2` in integers); only the
count was frozen. The grant test was one stricter than Python's.

*Phase 3, commit broadcast.* After committing to its own history, the proposer
broadcasts the commit carrying the task identifier, the proposer identifier, and
the score. Each acceptor writes the same entry to its own history, and the
proposer skips its own bounce-back. This phase looks redundant and is not.
Without it, the local history of every peer would contain only its own
submissions. When peers A and B independently score the same task, the history
at A would hold only the entry from A and the history at B only the entry from
B, and the bilateral check that contrite tit-for-tat performs could never match.
Phase 3 is what makes a single bilateral transaction appear in the view of every
peer.

*Sync sub-protocol.* A proposer that has fallen behind sends `update needed` to
its three most trusted peers, encrypted peer-to-peer, carrying its current chain
length. Each recipient responds with any history segment beyond that length, and
the proposer majority-votes across the three responses before catching up.

*Replay invariants.* Both Phase 1 and the chain-update path are pinned against
re-delivery. The Paxos last-identifier advances on grant, so a duplicate or
out-of-order ballot is rejected idempotently.

Pending requests and proposals expire after three hundred seconds, which bounds
memory growth for rounds that never completed.

## Warm start, and why it is safe

A node that restarts should not have to re-earn everything from zero. Warm start
is exactly that, being the memory of a peer's prior conduct becoming operational
again at startup. It is not a grant of trust and not a configured allow-list. It
is the reputation a peer already earned through observed transactions, persisted
to disk and reloaded into the live store.

Because that score is bound to the same cryptographic identity and remains
subject to continuous re-evaluation, a warm-started peer sits in exactly the
same regime as any other. It simply does not have to climb from neutral on every
reboot.

Two mechanisms keep a peer with no bilateral history out of the dead zone it
would otherwise sit in. A *seeded warm start* loads any persisted snapshot at
startup, so known-trusted peers read as trusted immediately rather than spending
the warm-up window looking untrusted. And a *consensus baseline* derives a
starting score from available consensus state when a peer has no transactions on
the chain at all, rather than falling back to the flat neutral value.

The safety of the shortcut rests on decay. Reloaded trust is stale trust, and
stale trust fades. The reputation process relaxes the operational score of an
idle peer toward almost-but-not-quite neutral as a function of time since the
last transaction with it, swept periodically. Three constants govern the curve.
The *asymptote*, defaulting to 0.21, sits just above neutral and well above the
cut-off, so a long-dormant peer relaxes toward but never reaches neutral,
staying faintly preferred over a true stranger while its elevated tier lapses
and must be re-earned on contact. The *onset* is a grace period before any decay
begins, so a brief gap out of range costs nothing. And the *half-life* sets how
fast the gap above the asymptote then shrinks.

The decay is asymmetric by design. It erodes reputation only above the
asymptote. A score at or below it, meaning a distrusted or corrupt node, is left
untouched, because mere absence must never rehabilitate a bad actor. Slashed
peers, whose floor is authoritative, and the node itself are never decayed.

Across a restart, the time a peer spent out of contact while this node was down
is counted. The modification time of the persisted snapshot is treated as the
instant of last activity, each loaded peer has its idle clock seeded to it, and
the offline gap is applied up front. A cohort that warm-starts after a long
dormancy therefore comes up appropriately faded rather than stale-inflated. This
is a local-view computation, wall-clock driven and never serialized onto the
wire, so it is invisible to the cross-runtime conformance corpus.

## Evidence, not just durability

The persisted score file records a conclusion, being a peer and a number, and
nothing about how we reached it. Reloading it makes trust durable and does not
make it verifiable. On its own the file says only that some process with write
access to the configuration directory believed a number, which is exactly as
true of a hand-edited file as of an earned one.

Decay covers the time axis. This is the orthogonal question of whether the score
was ever earned at all.

So the evidence is persisted beside the conclusion, in a separate history file
holding the hash-linked committed window plus the quorum-signed Merkle
checkpoint over it. The file is plain JSON rather than a configuration dump,
because one file is read by both runtimes and the configuration encoder emits
keys naming Python classes. Its schema is pinned, so a future shape change
becomes a refusal to rebuild rather than a misparse.

*When it is written.* At the moment the resident window and an agreed root
describe each other. Writing on every commit would be both hotter, at roughly
sixteen a second in the reference demo, and less useful, since a chain that has
moved past its checkpoint is precisely a chain the rebuild cannot attest. A
fuller co-signature set for a checkpoint already stored counts as an upgrade
rather than a duplicate and rewrites the file, because the proposer self-stores
holding only its own signature and the quorum map exists only a round later.

Checkpoint origination is periodic, defaulting to every three hundred seconds,
skipping intervals in which the window head has not moved. Before that it was
reactive only, requiring something outside the process to put a checkpoint on
the queue, and nothing ever did, so no deployment held a checkpoint and no warm
start could have verified anything. Proposals are phase-offset by the UUID of
each node so members do not all propose on the same tick, since every member
co-signs every proposal and simultaneous proposals from N nodes cost N squared
messages in one burst.

*What is checked at boot*, with each negative answer degrading to the same safe
outcome rather than raising. Firstly, hash-linkage of the persisted chain, since
a broken link means the file was altered or truncated. Second, root agreement,
meaning the Merkle root recomputed over the window of the checkpoint, selected
by absolute index because the chain may legitimately run past its checkpoint,
must equal the root the checkpoint commits to. Lastly, quorum, meaning more than
the computed threshold of distinct co-signatures over that checkpoint must
verify against keys this node holds, sized against its own roster so whoever
wrote the file cannot also choose the bar it must clear.

The chain is adopted only if all three hold, and that restriction is
load-bearing rather than cautious. Hash digests are public, so anyone can
produce a self-consistent chain. Adopting an unattested one would let the
scoring path re-derive the very elevated scores the clamp below withholds, which
would make the clamp decorative.

## The evidence bounds the value

Verifying that a peer appears in an attested window is not enough. The peer
really does transact, so presence alone would still restore a score typed into
the file by hand, which is the original hole left unclosed. The evidence
therefore bounds the value as well as the fact.

A peer *covered by the attested window* gets a ceiling equal to the mean of the
counterparty-side scores that the window records for it, shrunk toward neutral
by a shrinkage constant. Shrinkage is the security parameter here. It is what
makes two entries at 0.9 worth little, so a forger cannot mint the shortest
window that verifies. It is computed from the window and nothing else, since
deriving it from state that the persisted file feeds would let the file vouch
for itself.

A peer *not covered* gets the tier-1 ceiling, meaning presence and communication
only. The reason is exact. An authenticated-but-compromised asset passes
credential admission by definition, since credentials are what it holds, so
restoring a historically earned high tier the instant it is admitted re-opens
exactly the hole the system exists to close. For a short-lived asset there is no
time for behavioral re-evaluation to catch it first.

Restoration is the minimum of the persisted value and the ceiling. It is
one-directional, so it can only withhold standing and never confer it, and an
excluded peer is not quietly lifted. The node itself is never clamped. There is
no separate release step, because the clamped value is simply where the peer
resumes climbing, and elevation is re-earned through the ordinary scoring path.
Decay and this clamp compose cleanly, one being the time axis and the other the
axis of whether anything shows the standing was earned.

*A gateway checkpoints each chain separately.* A gateway keeps one transaction
history per child group beside its primary one, and each gets its own
checkpoints, meaning its own epoch counter, quorum sized against the members of
that group, and its own evidence file. Before this, checkpoint rounds covered
only the primary chain, so subtree standing could not be attested and therefore,
by the rule above, could not be restored.

A group identifier selects the chain, with the empty string meaning primary, and
it is appended to the signed designation only when non-empty. That does two
things at once. A primary-chain designation stays byte-identical to what it was
before child chains existed, so every existing co-signature and pinned scenario
keeps verifying. And a child-chain designation can never collide with a primary
one, so a co-signature harvested from a child-group round cannot be replayed as
agreement about the primary chain, which it otherwise could, since two chains
can perfectly well produce the same root, epoch, and bounds.

Two consequences are worth knowing. The child restore runs late and therefore
only ever lifts, because the child-group set arrives over the queue after the
reputation process has been constructed, so a boot-time rebuild cannot know
which subtrees belong to this node, and reading a file for a group this node may
not gateway is precisely what must not happen. And slash evidence may anchor on
any finalized root, because a transaction that offended inside a child group is
anchored in the root of that group, and accepting only the primary root would
refuse every legitimate subtree slash while adding no security, since each root
cleared the same quorum test.

*Consequence for seeded cohorts.* A seeded prior with no evidence beside it
restores at tier 1. The cohort seeding tool therefore writes evidence too,
having generated the keys it holds, sizing the seeded window so the seeded
reputation clears the seeded tier under the shrinkage above, and reporting the
tier the window actually supports when the resident chain cap binds. The
reference demo warm-starts through the verification path rather than around it.
Those transactions are seeded rather than observed, and they fold into the
consensus average at startup, so the consensus line of a seeded peer begins
partway up from neutral.

## Exclusion, enforced rather than displayed

A peer whose aggregate reputation falls below the cut-off is excluded, and the
exclusion is enforced at the network layer rather than merely reflected in a
score.

*Detection.* The tier-change publisher checks the cut-off crossing before its
tier early-return, because the cut-off at 0.1 lies inside tier 0, which spans
zero to 0.5. A move from 0.15 to 0.05 is a tier-0 to tier-0 no-op for the tier
logic and must still exclude the peer. On a crossing, the process resolves the
address of the peer and sends an exclude or readmit control message to the
network process.

*Enforcement.* The network process registers handlers that add or remove the
address from a rejected set. An inbound-drop gate discards frames from an
excluded address, and an outbound-skip gate stops forwarding to it, so gateways
stop relaying for an excluded peer.

*Boot and sync.* Exclusions re-seeded at boot from the persisted snapshot are
flushed to the network process once, on the first process iteration, since no
queues exist at construction time.

*Recovery.* Because an excluded peer is ignored, it cannot transact its way
back. Recovery is explicit only, through a rehabilitating slash-lift that
restores the score to neutral and re-admits it, after which elevated trust must
be re-earned from neutral. The excluded state persists across a restart, so a
reboot cannot silently rehabilitate a bad actor.

## Quorum attestation

Both quorum rounds, being slashing and Merkle checkpoints, follow the same three
phases. A node proposes, members co-sign only if they agree, and the proposer
broadcasts a finalizer once more than half the members have signed. What makes
the finalizer worth anything is that its recipients can check the quorum
themselves.

Each co-signer signs a designation, being canonical domain-separated bytes
naming everything the decision consists of, mirrored byte for byte between the
two implementations. The proposer keeps the signature bytes keyed by voter, the
finalizer carries the whole map, and every receiver re-derives the designation
and verifies each signature against the member key it holds, counting distinct
verified signers against its own view of the group.

Three properties, and each one is separate because it closes something the
others do not. A co-signature must verify to count, since otherwise the tally
counts assertions and any member can assert anything. A vote belongs to the
authenticated sender rather than to the voter the payload names, which
additionally stops a genuine signature harvested off a finalizer, where such
signatures travel in the clear, from being relayed by somebody else under the
name of its signer. And quorum is sized by the receiver from its own roster, so
the finalizer cannot also choose the bar it must clear.

A finalizer with no verifiable co-signatures is refused, which makes this a flag
day: a node built before the change cannot finalize a slash or a checkpoint for
a node built after it. There is no lenient mode, by design, since an attacker
would simply select it.

### The vulnerability this closed

Before this change, both rounds collected the co-signature bytes and threw them
out. The signing handler credited the voter identifier claimed in the payload,
the finalizer went out with an empty signature map, and the finalizing handler
applied whatever arrived on transport authentication alone. The three-phase
quorum was therefore enforced only inside the head of the proposer, and a
receiver could not distinguish a quorum-finalized decision from the unilateral
claim of one member.

Concretely, any admitted member could do two things. It could broadcast an
evidence-free slash finalizer naming any other peer and have every receiver
floor it, and because a floored score sits below the cut-off, that is network
exclusion which is sticky and recoverable only by explicit rehabilitation. A
permanent-exclusion primitive, network-wide, on demand. And it could broadcast a
checkpoint finalizer over a root of its choosing and have every receiver store
it. Since slash evidence anchors on that root precisely so the root is not
chosen by the accuser, this also made fabricated Merkle evidence verify
perfectly.

It needed a credentialed insider rather than an outsider, and that is the
authenticated-but-compromised case the framework exists to contain rather than
an argument that it did not matter. The C side was thinner still. Its co-sign
acknowledgement reported the nil identifier as its signer and carried no
signature, and its tally was a bare count with no voter identity, so replaying a
single acknowledgement drove the count past quorum.

The fix is pinned by unit tests in both runtimes and by conformance scenarios
covering a sub-quorum finalizer, forged co-signatures, and an unattested root.
Both adapters mint the co-signatures at scenario time, so the two runtimes are
held to the same pre-image and scheme rather than to the recorded output of one
side.

## Verifier-attested scores

A committed entry counts only when both halves exist, and each half is
submitted by one of the two parties. That is the property that keeps a horde
from forging evidence about an honest node (`R+D.md` §14.2), and it carries
the cost that section names in its fourth open question: a peer can **withhold**
its half to keep a poor score about itself off the chain. For most evidence
this is acceptable, because a transaction it refuses to complete is one it
never benefits from either. It is not acceptable for an audit. A verifier that
checks a peer's published work and finds it unsafe has a finding the peer will
never countersign, and the finding must still land.

A **verifier-attested score** is the answer, and the only one-sided entry the
chain admits. The verifier submits its half alone. The entry commits once a
quorum of the group co-signs it, and the subject's consent is neither needed nor
counted.

**What the co-signers vouch for.** Admissibility, never truth. Each co-signer
checks, in its own view of the group, that:

- the verifier is an eligible author: its reputation in this node's view is at
  least `AT_ATTEST_MIN_REP` (0.5 by default), and it is neither excluded nor
  slashed;
- the verifier is not the subject, and the subject is a member;
- the channel is one a verifier can author (`probe`, for now);
- the entry is well-formed, its task id is the one derived from its content,
  and it is not a duplicate;
- the verifier has not already attested this subject within the resident
  window (one per pair, counted from the chain itself, so every node reaches the
  same answer).

None of that is a judgement about the finding. This keeps the rule from the
start of this document intact: no channel becomes an accusation several nodes
co-sign into a verdict. The quorum certifies that an eligible verifier said
this, on this channel, with this reason. Whether the subject did poorly is still
each peer's own reading of an entry it holds, folded like any other.

**The entry.** It is an ordinary `Transaction` with three more fields, so it
shares the chain, its index and links, the window root, checkpoints, the
persisted evidence document and catch-up. The verifier occupies `p1`; `p2` is
never set. The added fields name the **subject** (an ordinary entry names only
its two scorers, and the subject is "the other side", which a one-sided entry
does not have) and an **evidence digest**, the hash of the document the
verifier's finding rests on, which the application that produced it publishes.
The task id is derived from verifier, subject and digest, so a duplicate is
recognizable on sight and an attestation cannot borrow a live round's id. A
plain `committed` naming an attested task id is refused, so nothing can later
fill the other half.

Its canonical bytes extend the existing form rather than replacing it. Every
attested entry carries a non-default channel, so the channel block is always
present, and a final block `|attested|<subject>|<evidence_digest>` follows it.
No ordinary entry has `p2` unset at commit time, so the two forms cannot
collide, and every entry committed before the change keeps its bytes and its
hash.

**The round.** A fourth three-phase quorum, shaped like slashing and
checkpoints rather than like the Paxos commit:

| Wire function | Direction | Carries |
|---|---|---|
| `attest propose` | verifier → group | verifier, subject, task id, score, channel, evidence digest, the verifier's signature |
| `attest sign` | member → verifier | task id, the member's signature |
| `attest final` | verifier → group | the entry and the map of verified co-signatures |

Each signer signs the designation
`"AT-ATTEST\0" verifier|subject|task|score|channel|evidence_digest[|group]`,
which excludes index and `prev_hash` because those differ per node until the
chains reconcile. A receiver of the finalizer counts distinct verified signers
under the rules of the previous section, with two more: the verifier's own
signature is required, and the subject's is never counted. The bar is a strict
majority of the members other than the subject, sized from the receiver's own
roster. In a group of three, both non-subjects must sign.

The certificate stays outside the entry hash, as a checkpoint's co-signatures
stay outside its root. It travels with the entry wherever the entry goes: on
catch-up, in the evidence document, and in deep-resolution answers. A catch-up
segment carrying an attested entry without a certificate that verifies is
refused, since otherwise catch-up would be a way around the round.

**A lost propose is sent again.** The propose is a one-shot fan-out, and a
saturated network queue can drop one member's copy (Stele `st-660084`). When the
member who lost it is needed for the quorum, the round can never certify. So a
round still short of a quorum re-sends its propose every 15 s
(`AT_REP_ATTEST_RETRY_SEC`), up to 5 times, and is then abandoned. A round whose
entry is already in the chain, certified by a final from elsewhere, is simply
forgotten. A repeat cannot fork the round, because the task id is derived from
(verifier, subject, evidence digest): it is the same round, and a co-signer signs
the same designation again (ISSUES §2.40).

**What the subject cannot do.** Block it, because its signature is not
counted. Strip it, because the entry is hash-linked into a window root that a
checkpoint quorum signs. Fork it away: when a node adopts a chain that dropped
a certified attested entry, it re-appends the entry, which verifies on its own
and does not depend on its position. Pair it, because the half it would fill is
refused.

**How it is folded.** For the subject, an attested entry contributes the
verifier's score as one consensus observation at capability weight one. The
`probe` multiplier applies only on the verifier's own node, exactly as in
"Only your own evidence counts": a quorum certifies admissibility and does not
raise a remote channel's weight. The verifier gains nothing from the entry.
Attested entries are not bilateral history, so CTFT leaves them out. Decay is
unchanged, which means a poor attested score is never lifted by the passage of
time alone; only fresh evidence moves it.

**What it opens, and what bounds it.** A malicious verifier can now place a poor
score about a peer that peer cannot veto. Four things bound that. Every
co-signer requires the verifier to be in good standing in its own view. One
attestation per verifier and subject fits in the resident window. A remote node
folds it at weight one. And the verifier's key and the quorum's are on a
committed entry, so the slander is attributable, and peers judge the verifier
by it in turn. There is still no dispute mechanism, for the reason given above:
nothing here levies a verdict.

The application decides what an audit means and what score it earns; AT
decides only who may author one and what makes it stick. Stele
(`apps/stele/`) is the first producer, scoring a repository owner's node on a
vulnerability scan of its published commit.

## Commit certificates

A `committed` half is written by its sender, and since the provenance rule
(pinned by `committed-writes-only-the-senders-half`) only by its sender: a
member can no longer write another member's half. What it
can still do is write its own half without any round having happened. Nothing
on an ordinary commit shows that a quorum accepted it, so the effective
Byzantine threshold on the chain is one member, not the majority the Paxos path
is sized for.

A group can close that by declaring **commit certificates**. Then every
ordinary half carries the signatures of more than a quorum of acceptors over
exactly what it writes, and no node writes one without them.

**What a certificate proves, and what it does not.** It proves the round: that
more than `n // 2` members of the receiver's own view accepted this score, from
this scorer, on this channel, for this task. It does not prove the score is
true. An acceptor never sees the task; it signs what the proposer tells it. So
the lie a certificate leaves open is a scorer's about its own half, which is
`R+D.md` §14.2's question (bilateral evidence), not this one's. What it buys is
round existence, non-equivocation (every node writes the score a quorum saw),
an entry that can be checked offline, and a per-entry cost of a quorum's
participation.

**The declaration is the group's.** `Group.commit_certificates` (C
`group_t.commit_certificates`), default off. Two members that disagreed about
it would write different commits and fork their chains, so it travels with the
group, as `wire_format` does: in the canonical group form (emitted only when
true, so an undeclared group's bytes are unchanged), in `identity.proto`
`Group.commit_certificates`, and through a merge, where the absorbed node
adopts the surviving group's value. `AT_COMMIT_CERTIFICATES` stamps only a
group the node mints; a joiner adopts its group's value. Turning it on for an
existing cohort means minting a new group, the same constraint `wire_format`
has.

**What is signed.** One certificate per half, so two per entry, because the two
halves are committed by two rounds:

    "AT-COMMIT\0" scorer "|" task "|" %.17g score "|" channel

Lowercase uuids, and the channel normalized, so an absent channel and an
explicit `task_outcome` are one claim with one signature, as they are one entry
hash. Byte-identical in both runtimes (`commit_designation`), and pinned by a C
unit test against Python's bytes.

The group is not covered. An acceptor is never told which of a gateway's chains
the round lands in, and a group's uuid changes when a merge absorbs it, which
would orphan every certificate cut before. A certificate replayed into another
chain still has to clear that group's quorum with signers the receiver
resolves, so what it leaves is a scorer re-filing its own certified half.

**The round.**

1. In a declaring group, the proposer's `transaction` asks for certification
   (Python appends `True`; C sets `"certify": true`).
2. Each acceptor signs the half's designation, but only when the proposal comes
   from the scorer it names. A relayed proposal is accepted unsigned.
3. The proposer counts only acceptances whose signature verifies, attributed to
   their authenticated sender, and commits once they clear the bar a receiver
   will hold them to. The certificate rides on `committed` (Python: element
   six; C: `"certificate"`).
4. A receiver in a declaring group writes the half only if more than
   `_quorum_for_group` distinct members of **its own** view signed it. The
   scorer's own signature never counts.

A receiver whose group does not declare them still keeps a valid certificate it
is handed, so a chain cut before the group declared them can be served to one
that does.

**Where they are kept.** Beside the entry and outside its hash, as a
checkpoint's co-signatures sit outside its root: `Transaction.commit_sigs` in
Python, `tx_history_t.commit_certs` in C. They travel on the catch-up wire and
in the evidence document as `commit_sigs`, `{scorer: {voter: signature}}`,
omitted when there are none. A fork that drops an entry drops its
certificates.

**Catch-up.** In a declaring group, a segment is refused unless every ordinary
half of every entry in it that is new to this node carries a certificate
meeting this node's quorum. Two kinds of entry are exempt:

- **Entries a quorum checkpoint covers.** If the segment holds the whole window
  of the latest quorum-attested primary checkpoint and reproduces its root,
  the checkpoint certifies those entries. This is how a chain cut before its
  group declared certificates, or certified by members since gone, stays
  acceptable once a quorum has checkpointed it. Only the uncheckpointed tail
  has to show certificates, and the tail is checked against the current
  roster.
- **Entries already held identically**, at the same index with the same hash.
  Repeating them tells the receiver nothing new.

Pinned by the `commit-cert-*` scenarios below, `tests/a_unit/test_commit_certificates.py`
and `src/c/test/rep_commit_cert_test.c`.

## Asking others what they think

A score computed here is one node's view. An observer dashboard wants the whole
matrix — every observer's view of every subject — and that is what makes the
*shape* of the request matter rather than only its arithmetic.

Two verbs answer it. `request consensus reputation` names one subject and
returns one score (or, from a gateway, that subject plus every member of the
child groups it bridges — see [Gateway reputation
tree](gateway-reputation-tree.md)). `request consensus reputation batch` names
many subjects and returns one roster. Both compute each entry through the same
consensus path, so the batch verb changes what a round *costs*, never what it
says: in C the arithmetic is factored into `_consensus_score_for` precisely so a
second copy could not drift into being a scoring change, and in Python both
verbs run `_subtree_roster`.

The cost is the reason it exists. An observer-by-subject sweep over N peers is
N(N-1) messages with the single-subject verb — at N=80 that is 6320 requests and
6320 signed replies per round, each with its own chain walk — while the answers
were always a roster the reply path already knew how to read. Batched, the same
round is N requests and N replies:

| Peers | Single-subject | Batched |
|---|---|---|
| 10 | 90 requests + 90 replies | 10 + 10 |
| 40 | 1560 + 1560 | 40 + 40 |
| 80 | 6320 + 6320 | 80 + 80 |

Three properties make the batched form behave:

1. **Subjects are named by uuid, not as identities.** The responder reads only
 `peer.uuid` off the request, and sending N full identities to N observers
 would trade N-squared messages for N-squared bytes.
2. **The responder skips its own uuid, and answers at most once per subject.** A
 self-pair is not part of an observer-by-subject sweep. Skipping it
 responder-side is also what makes one request body correct for every
 observer, which in turn means a round carries one signature rather than one
 per recipient (`Message.for_recipient`; the signature pre-image
 `process|function|base64(data)` never covered the recipient, so a readdressed
 copy is already valid). Deduplication matters because a repeated entry would
 be read as two observations of one pair.
3. **The named-subject count is bounded** (`MAX_REP_BATCH_SUBJECTS` /
 `AT_MAX_REP_BATCH_SUBJECTS`, 256). Each subject costs a chain walk, so an
 unbounded list would let one small message ask for arbitrary work. Over the
 bound the request is truncated and logged rather than refused — a legitimately
 oversized cohort still gets a partial answer, and the log is what keeps the
 cause visible instead of presenting as a silently incomplete graph.

### The reply, and where it goes

A `reputation response` carries `Reputation` objects — one, or an array of them
for a roster — and both runtimes now write the same form: the `__type__` tag,
`peer_id`, `score`, and nothing else. Each part of that is load-bearing.

The **tag** is what makes a requestor rebuild a `Reputation` instead of handing
its caller a bare mapping. C omitted it and sent `{peer_uuid, score,
requesting_process}` instead, so a Python requestor deserialized a dict, reached
for `.peer_id`, and raised out of its message loop — meaning a C peer's view of
the cohort reached neither `latest_reputation` nor `latest_reputation_pairs`.
The symptom was an inspector trust graph with no C opinions in it and nothing
saying why. C carries the tag for the same reason the warm-start snapshot does:
this is the same state in both runtimes, so the identifier is a shared constant
rather than a language artifact.

**Nothing else** in the body, because the requestor reconstructs the object by
keyword — a stray field is a `TypeError` there, not a value it ignores. That is
why `requesting_process` is not in the payload.

It belongs in the **envelope** instead, as the reply's `process`, because that
is the field a requestor routes an inbound message by. C named `"reputation"` at
all three reply sites, which delivered every reply to the requestor's
*reputation* process — where Python has no `rep_resp` handler — rather than to
the process that asked. Shape and routing had to be fixed together: either alone
leaves the answer undelivered or unreadable. An absent or empty requesting
process falls back to `"reputation"` so a malformed request produces a
deliverable reply rather than one addressed to nothing.

The consumer no longer trusts the shape it is handed either. A mapping with
`peer_id` (or the older `peer_uuid`) and a numeric score is accepted, anything
else is dropped with a warning that names the sender, and neither can raise:
that loop services every message the node receives, so one peer's malformed
reply must not be able to stop the rest. A mixed-version cohort keeps working
while it catches up.

Pinned on both sides: `src/c/test/rep_resp_shape_test.c` asserts the emitted
tag, the exact key set, and the routed envelope for all three verbs;
`tests/a_unit/test_rep_resp_interop.py` asserts the consumer reads the tagged
form, the legacy C form, and refuses the rest.

## What only a live cohort could show

Consensus here was "passing" for as long as it had existed, in both runtimes and
across the whole conformance corpus, and it had never once worked between real
processes. Thirty preserved cohort runs record rounds starting constantly and
`Reputation: Transaction committed` appearing exactly nowhere. Five separate
defects stood between a proposal and a commit, and the reason none of them was
caught is the same in every case. What was wrong lived in the gap between two
components, and every test held one side of that gap fixed.

**The verdict did not survive the hop inward.** `net_msg_to_proto` carried
neither `verified` nor `has_signature` across the network-to-sibling IPC hop, so
all thirteen handlers gated on a verified signature rejected everything in live
operation. The conformance adapter sets the flag by hand and dispatches
in-process, which is precisely the hop that was broken.

**The pending round was filed under a key nobody looked up.** The proposer
stored it by task identifier; the grant handler looked it up by peer identifier.
Every grant fell into the already-completed-or-unknown branch. Python keys both
sides by the ballot `(id1, id2)`. Every test in either runtime *stages* the
pending round and then dispatches a grant — staging writes the key the reader
expects, so the writer's key was never on trial. A test that never runs the
proposer cannot watch the proposer disagree with anybody.

**A refused round was abandoned rather than retried.** The nack handler computed
a backoff nothing ever read. Python sleeps that backoff and re-proposes. With
one proposer the difference is invisible; with three, every member proposes on
the same probe in the same millisecond and most requests are refused, so most
rounds simply vanished.

**The ballot index drifted from the chain.** The index came from a private
counter advanced only on a round this node proposed and won, while every node's
chain grows on every commit it *learns of*. Python takes the number from the
chain on both sides. The counters scatter within seconds of a second proposer
appearing, ballots stop matching, and the group falls into a catch-up loop that
never settles. The conformance fixture for this staged the counter — the cache
the production code overwrites — which is exactly how the drift stayed
invisible; it now stages the chain, as Python's does.

**A user's action was scored though it never left the node.** Sends are
non-blocking into a queue that holds ten datagrams, and a transaction burst
fills it. The directed application senders discarded the result, so a reaction
reported success, accrued the reactor's half of a *bilateral* score, and never
reached the wire — leaving a transaction that could never complete and a score
claimed for an interaction the other party never had. The same trap has bitten
twice before in other shapes — receive loops that took one message per tick, and
a queue close that unlinked by name — and the reasoning for each sits at its fix
site, in `processes/processes.h` and `utilities/message.c`.

The first fix was a bounded retry, 10 tries 20 ms apart, and that 200 ms was
not enough either. On 2026-10-02 a queue stayed full for longer, and a joiner's
history, a direct message and an attestation propose were each given up on. A
frame still refused after the inline tries is now kept and retried on the
process tick for up to 30 s (`utilities/send_retry.h`). Since ISSUES §2.14 closed, that
holds in every process, so reputation's own state frames, its `tier_lost` and
its local replies are kept too, not just identity's one-shots. Because a kept frame
may still be given up on, "the send returned 0" no longer means "it went". So
the reaction and the report score their bilateral half in an on-sent callback
that hears whether the frame really left. A frame that never leaves is never
scored (ISSUES §2.40).

The pattern worth remembering is not any one of these. It is that a
single-process conformance harness, however complete, is structurally blind to
disagreements between processes, and that a fixture which installs internal
state replaces exactly the code whose agreement with the reader is in question.
Both blind spots are cheap to close once named: drive the real originator, and
put two processes on a real wire.

### Why the chains would not converge

Once rounds committed, a second cohort found the chains drifting apart and never
settling, and that drift, not any single refused round, was what kept a report
from ever moving a score. Four defects sat behind it, found one per run in the
Agora moderation cohort on 2026-09-23. Each hid behind the one before it, which
is why a test for any single one could not have found the rest.

**Catch-up could never apply.** A node that fell behind asked its peers for
their chain and merged the answer only once it held three matching reports,
stored one per sender. A node in a three-member group has two peers, so the
threshold was unreachable and no chain was ever merged. The miss was silent: the
"unable to agree" error sits behind the same threshold. Since a grant needs the
proposer's next slot to match the acceptor's, drifting lengths meant that after
a restart nobody granted anybody. The quorum is now one, in both runtimes. That
is safe because the merge verifies the segment's hash links before loading any
of it and appends only past what the node already holds, so one peer cannot
rewrite another's history. In a group that does not declare commit
certificates a commit already lands on one member's word, so this does not lower
the chain's effective threshold; in one that does, catch-up checks the
certificates itself (see [Commit certificates](#commit-certificates)).

**C appended what it already had.** A peer answers "update needed" with its
whole history. Python's catch-up loads only entries past its own next index; C's
loaded every one, so the first merge that ever ran would have doubled the chain.

**C kept committed entries in arrival order.** C's chain array holds pending
entries at the slot where their first half arrived, but a transaction takes its
index and hash link when its second half lands. Two interleaved tasks therefore
committed out of array order, and everything that walks the array as "the
committed sequence" (the catch-up wire, the checkpoint window, the evidence
export, the link check) read a sequence whose links failed. One node's persisted
chain read its indices as `[3, 0, 2, 1]`, and every peer rejected its catch-up
whole. Python's chain only ever holds committed entries, appended as they
commit, so it never had this. C now moves an entry to the end of the array when
it commits, and sorts an incoming segment by index before checking it.

**C made a second copy of a task it was waiting on.** When a catch-up arrived
for a task whose other half this node was still waiting for, C appended the
peer's committed copy in a new slot. When the local half committed later, the
task existed twice, and that node's chain was two entries longer than anyone
else's for the rest of the run. Python completes the pending entry in place; C
now does too.

With all four fixed, the cohort passed end to end, and a report committed on
both sides and moved the reporter's view of the reported peer. Chains now carry
no duplicates and are always in index order. They still did not converge,
though, and the fifth cause is structural rather than a defect in either
runtime.

**Chains forked by order.** Each node numbers an entry when its second half
lands, so two nodes can commit different tasks at the same index. Catch-up
appended only past a node's own next index, so once that happened nothing
reconciled them. In run 11 the three chains ended at 10, 13 and 15 entries,
sharing a prefix of three; in run 12 carol shared no prefix with either peer.
Since a grant needs the proposer's next slot to match the acceptor's chain
length, Paxos then stalled for good, and a report filed after the fork could not
commit. The catch-up churn it caused (ada answered 718 update requests in about
160 s) is also what kept filling the reputation queues.

Both runtimes now reconcile by the **longest verified chain**
(`tx_history_reconcile` in C, `TransactionHistory.reconcile` in Python, step for
step):

1. The peer's segment must verify its own hash links, or it is rejected whole.
2. The fork point is the first index where the two chains differ by entry hash,
   or where only the peer has an entry. The peer's entry there must link to our
   entry before it, so its suffix really continues our prefix.
3. With no divergence, the peer's entries past ours are appended.
4. On a divergence, the peer wins only with the higher tip: last index plus one,
   then the lower head entry hash on a tie. Every node orders tips the same way,
   so a group converges on one chain and cannot flap between two. One
   exception outranks the tip: when a quorum finalized a window this node's own
   entries do not reproduce, a peer segment that holds every index of that
   window and hashes to its root wins, whatever the tips
   (`tx_history_reconcile_attested` in C, `reconcile(attested=...)` in Python).
   The quorum already chose that side; the tiebreak is only for forks it has
   not ruled on.
5. Nothing inside this node's finalized checkpoint window is rewritten. A fork
   there is refused, with a warning naming the peer, the fork index and where
   the window ends. Finalized means two things. A quorum attested the window:
   a node's own proposal is stored the moment it is made, holding only its own
   signature, and that does not count. And this node's own entries over the
   window still hash to the attested root: a node the quorum outvoted holds
   nothing final there, so it reconciles like any other.
6. Adopting drops our committed entries from the fork on and loads the peer's
   verbatim (index, previous hash, scores, channels), completing in place any
   task we held pending. Verbatim, so two nodes that agree become byte-identical
   and compute the same window root. Python's catch-up used to replay entries
   through `update()`, which renumbers them locally; it now loads them as C
   does.

Where a node loses, the entries only it held past the fork are dropped, both
halves of each. They are not tombstoned, so a later catch-up from a peer that
holds them brings them back. Pending halves are never dropped, and they commit
on top of the adopted chain. The process layer logs every adoption (`adopted
chain from X at index f: dropped d, added a`) and marks the peers of every added
and dropped entry for rescoring.

**What an adoption drops is re-proposed** (2026-09-25, Agora Phase 4 DDIL).
Across a partition, the entries only the losing side held are every transaction
the smaller island committed while it was split, and nobody else holds them, so
no catch-up would bring them back: the island's reputation from the split was
simply gone. Now the result of a reconcile carries the dropped entries
(`tx_reconcile_result_t.dropped_entries`, `ReconcileResult.dropped`), and at
both adoption sites each node re-submits ITS OWN half of each through the
normal round (`_repropose_dropped`, logged as `re-proposing N dropped
transaction(s)`), as `_retry_nacked_rounds` does for a nacked round. The
counterpart, which dropped the same entry, re-submits its half, so the pair
re-forms bilaterally on top of the adopted chain. Nothing new is trusted: a node
vouches only for the score it gave. Skipped are entries that are not ours, tasks
the adopted chain already holds (committed or pending), and tasks we already
have a round under way for. The entry does not carry the capability name or the
learned weight, so a re-proposal carries the authored default weight; the
channel is kept. Pinned by `chain-fork-dropped-own-half-reproposed`,
`chain-fork-dropped-task-already-adopted-not-reproposed` and
`chain-fork-peer-half-not-reproposed`.

**A half that never reaches the chain is proposed again** (2026-09-29, ISSUES
§2.24). A round can vanish in two ways that neither the nack retry nor the DDIL
re-proposal sees. A granted round leaves `my_requests` when its transaction goes
out, so if the acceptors never commit it, because another round took the slot,
it is gone. A round nobody answers gets no nack, so no retry is ever armed. Each
node now follows its own halves by task (`awaiting_commit`) from proposal until
the chain holds them. Every proposal files or refreshes an entry, and committing
our half clears it. The process loop's `_retry_uncommitted_halves` re-proposes
any half not in the chain `AT_REP_COMMIT_TIMEOUT_SEC` (default 15 s) after its
last proposal. It first retires any round still filed for the task, so a late
grant cannot race the fresh ballot, and logs `our half of task T is not in the
chain after N s; re-proposing it (attempt k of 5)`. After five re-proposals it
warns and gives up. A half found in any chain, including one adopted, is
forgotten without a re-proposal. Pinned by `rep_commit_retry_test` and
`test_repprocess_commit_retry.py`.

**A member co-signs the proposed range, and signs late rather than never**
(2026-09-29, ISSUES.md §2.29). A member co-signs when its entries at the
proposal's `[first_index, first_index + count)` hash to the proposed root. It no
longer requires its whole window to match. A chain that grows every second or
two, with members proposing on their own phases, means a proposal usually lands
on members one entry ahead or behind. A proposal that cannot be matched on
arrival is parked, one per proposer and chain, and re-checked every pass. It is
co-signed once the member's chain holds the range with that root, and dropped
after one checkpoint interval. A range the member holds but that hashes
differently is never signed. Together with the whole-group majority below, this
is what lets a four-of-six island finalize at all: every member has to sign the
same proposal.

**Checkpoint finality needs a majority of the WHOLE group** (2026-09-25). The
threshold was `num_peers / 2`, the Paxos sizing, which counts the roster without
this node, so an even-sized group finalized one signature short of a majority.
Two of a four-member group qualified, and so did the proposer alone in a
two-member one. Both halves of an even partition could therefore finalize their
own windows, and at the heal each refused to rewrite inside its finality (step
5), so the chains could never converge. The checkpoint threshold is now
`(num_peers + 1) / 2`, with more than that many required
(`_ckpt_quorum_for_group` in C, `_checkpoint_quorum` in Python), at the
proposer, the receiver of a final, the store and the warm-start rebuild. Odd
sizes are unchanged, and Paxos grants and slashing are not touched: they keep
`len(peers) // 2`, which C now sizes per round from the live roster as Python
does (see [Commit certificates](#commit-certificates)). Pinned by `checkpoint-final-even-group-half-refused`
and `checkpoint-final-even-group-majority-stored`.

The first host runs with the rule in place (mod-2481048 and mod-2483539,
2026-09-23) failed on the finality guard alone, and for two reasons. Every node
treated its own unsigned proposal as final, so each pinned its own fork. And no
member had ever stored a checkpoint: C's `handle_checkpoint_sign` freed the
ack's payload before building the final from strings that pointed into it, so
the final left without its `proposer_uuid`, and every member re-derived an empty
designation and logged "0 verified co-signature(s)". The logs of every earlier
moderation run show the same rejection and no stored checkpoint. The slash final
had the same use-after-free. The tests that should have caught it each held half
the path (a hand-built signature map is accepted; a proposer emits a final), and
`rep_quorum_test.c` now hands a member the final a proposer really emitted.

The outvoted node also has to hear the winning chain. Catch-up ran only when a
Paxos grant found the chain lengths differ, so an order fork at EQUAL length
never reconciled at all: in moderation runs mod-2537396 and mod-2538837
(2026-09-23) carol held a different order at indices 20 to 22 for the rest of
both runs, and the lower head hash could as well have kept the side the quorum
outvoted. Now a stored quorate checkpoint our own chain does not reproduce sends
the finalizer a chain request from the window's first index, and the reply is
reconciled against that attestation. A checkpoint our chain matches sends
nothing.

Unit tests in both runtimes (`src/c/test/reputation_fork_test.c`,
`TestChainForkReconcile`, `TestFinalityNeedsQuorum`, and the finality cases in
`rep_quorum_test.c`) cover each branch, including that the tiebreak is
symmetric: A hearing B and B hearing A pick the same winner. Twelve mutations
fail them: always or never adopting on a tie, no finality guard, Python
replaying through `update()`, a guard that reads the checkpoint slot, a proposal
counting as final on its own signature, no root match, freeing the ack before
building the final, each in the runtimes it applies to, and, for the outvoted
case, removing the quorum-chain rule or the chain request in either runtime.

The same runs tightened three neighboring hand-offs that dropped data when a
queue was full, being the group multicast of a post, identity's hand-off of a
social score to reputation, and its hand-off of an app-decided standing. All
three now retry for a bounded time, like the directed senders before them
(ISSUES.md §2.14).

### What the injected phase does and does not prove

Two flows — slashing and deep resolution, five gates between them — have **no
production originator**. Nothing outside the conformance corpus and
`rep_quorum_test.c` has ever sent those verbs. Deciding when a node should
accuse a peer is a design question that remains open, so rather than invent an
answer we have the cohort inject the messages through a test-only tool that
hands them to a node's own network process by queue name. The node signs them
with its own identity and encrypts them to the target, so the receiver sees a
genuine signature from a peer it knows.

That proves the gate opens, the handler runs, and the round-trip works across
two real processes on a real wire. It proves **nothing** about whether a
deployment would ever send such a message, because today none would. The
synthetic traffic is labeled as such in the cohort's own output, and the gap it
stands over is documented rather than papered over.

## Pinned scenarios

| Behavior | Scenario |
|---|---|
| Phase 1 happy path | [`reputation-canonical.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/reputation-canonical.yaml) |
| Nack on a stale ballot | [`request-nacked-stale.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/request-nacked-stale.yaml) |
| Backdate on a chain mismatch | [`request-backdated-chain-mismatch.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/request-backdated-chain-mismatch.yaml) |
| Phase 2 acceptance | [`transaction-accepted.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/transaction-accepted.yaml) |
| Phase 3 bilateral commit | [`transaction-committed-bilateral.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/transaction-committed-bilateral.yaml) |
| Evidence channel carried; a channel from a peer changes nothing | [`transaction-channel-carried.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/transaction-channel-carried.yaml) |
| A refutation from a peer accuses nobody | [`remote-refutation-cannot-accuse.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/remote-refutation-cannot-accuse.yaml) |
| Sync, outdated notification | [`chain-outdated-notification.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/chain-outdated-notification.yaml) |
| Sync, replay of an update | [`chain-replay-update.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/chain-replay-update.yaml) |
| Catch-up at the production quorum, from one peer | [`chain-catchup-default-quorum.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/chain-catchup-default-quorum.yaml) |
| Out-of-order commits keep the window in commit order | [`chain-out-of-order-commit-window.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/chain-out-of-order-commit-window.yaml) |
| A fork adopts the peer's longer chain verbatim | [`chain-fork-adopts-longer.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/chain-fork-adopts-longer.yaml) |
| A fork keeps our chain when the peer's is shorter | [`chain-fork-keeps-own-when-peer-shorter.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/chain-fork-keeps-own-when-peer-shorter.yaml) |
| A fork at equal length goes to the lower head hash | [`chain-fork-equal-length-tiebreak.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/chain-fork-equal-length-tiebreak.yaml) |
| A fork inside the finalized checkpoint is refused | [`chain-fork-refused-inside-checkpoint.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/chain-fork-refused-inside-checkpoint.yaml) |
| An equal-length fork goes to the chain the quorum attested | [`chain-fork-quorum-chain-wins-tiebreak.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/chain-fork-quorum-chain-wins-tiebreak.yaml) |
| A finalized checkpoint our chain lost does not guard it | [`chain-fork-adopts-when-outvoted-by-checkpoint.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/chain-fork-adopts-when-outvoted-by-checkpoint.yaml) |
| Replay of a ballot refused | [`ask-permission-replay-rejected.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/ask-permission-replay-rejected.yaml) |
| Lower ballot identifier refused | [`ask-permission-lower-id-rejected.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/ask-permission-lower-id-rejected.yaml) |
| Evidence document and ceilings | [`warmstart-evidence-document.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/warmstart-evidence-document.yaml) |
| Sub-quorum slash finalizer refused | [`slash-final-sub-quorum-refused.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/slash-final-sub-quorum-refused.yaml) |
| Forged co-signatures refused | [`slash-final-forged-cosignatures-refused.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/slash-final-forged-cosignatures-refused.yaml) |
| Unattested checkpoint root refused | [`checkpoint-final-unattested-root-refused.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/checkpoint-final-unattested-root-refused.yaml) |
| Single-subject reputation request | [`request-reputation-cross-process.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/request-reputation-cross-process.yaml) |
| Batched consensus request, self skipped and duplicates collapsed | [`consensus-reputation-batch.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/consensus-reputation-batch.yaml) |
| An attested entry hashes the same in both runtimes, and links | [`attest-entry-canonical-bytes.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/attest-entry-canonical-bytes.yaml) |
| A certified attestation commits without its subject | [`attest-final-commits-without-the-subject.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/attest-final-commits-without-the-subject.yaml) |
| The subject's own node appends it | [`attest-final-the-subject-cannot-refuse-it.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/attest-final-the-subject-cannot-refuse-it.yaml) |
| The subject's signature is not counted | [`attest-final-subject-signature-not-counted.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/attest-final-subject-signature-not-counted.yaml) |
| Sub-quorum or forged attestation certificates refused | [`attest-final-sub-quorum-refused.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/attest-final-sub-quorum-refused.yaml) |
| An attestation needs its verifier's signature | [`attest-final-without-the-verifier-refused.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/attest-final-without-the-verifier-refused.yaml) |
| Admissibility: floor, self, channel, rate cap | [`attest-propose-low-rep-verifier-declined.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/attest-propose-low-rep-verifier-declined.yaml) |
| A commit writes only its sender's half (ISSUES §2.16) | [`committed-writes-only-the-senders-half.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/committed-writes-only-the-senders-half.yaml) |
| A certified commit is written beside its certificate | [`commit-cert-certified-commit-written.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/commit-cert-certified-commit-written.yaml) |
| A declaring group refuses an uncertified commit | [`commit-cert-uncertified-commit-refused.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/commit-cert-uncertified-commit-refused.yaml) |
| A sub-quorum certificate is refused | [`commit-cert-sub-quorum-refused.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/commit-cert-sub-quorum-refused.yaml) |
| The scorer's own signature is not counted | [`commit-cert-proposer-signature-not-counted.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/commit-cert-proposer-signature-not-counted.yaml) |
| A forged certificate is refused | [`commit-cert-forged-refused.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/commit-cert-forged-refused.yaml) |
| A certificate binds the score | [`commit-cert-other-score-refused.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/commit-cert-other-score-refused.yaml) |
| An undeclared group writes as ever and keeps a valid certificate | [`commit-cert-undeclared-group-keeps-certificate.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/commit-cert-undeclared-group-keeps-certificate.yaml) |
| An acceptor signs, and the proposer commits on its signature | [`commit-cert-acceptor-signs-and-proposer-commits.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/commit-cert-acceptor-signs-and-proposer-commits.yaml) |
| An unsigned acceptance is not counted | [`commit-cert-unsigned-acceptance-not-counted.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/commit-cert-unsigned-acceptance-not-counted.yaml) |
| Catch-up refuses an uncertified segment | [`commit-cert-catchup-uncertified-refused.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/commit-cert-catchup-uncertified-refused.yaml) |
| Catch-up accepts a certified segment and keeps its certificates | [`commit-cert-catchup-certified-accepted.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/commit-cert-catchup-certified-accepted.yaml) |

Unit coverage for the attestation rules lives in
`tests/a_unit/test_repprocess_quorum_attestation.py` on the Python side and
`src/c/test/rep_quorum_test.c` on the C side. Verifier-attested scores have their own:
`tests/a_unit/test_attested_scores.py` (the round end to end on real keys,
catch-up's certificate gate, the re-append after a fork, folding) and
`src/c/test/rep_attest_test.c` (the entry on the catch-up wire, in the evidence
document, and handed back by a fork). The child-chain checkpoint work is
described in [Gateway reputation tree](gateway-reputation-tree.md), and the
closure of the original last-identifier divergence in `BUGS.md` section P6.

## Further reading

- [Reputation against blockchain](reputation-vs-blockchain-analysis.md): the
  hash-linking, Merkle checkpoint, and slashing design compared against a chain,
  and why this is not one.
- [The gateway reputation tree](gateway-reputation-tree.md): multi-group
  membership and recursive subtree reputation, which the per-chain checkpoints
  above serve.
- [Persistent cohort](persistent-cohort.md): how the snapshot is written and
  restored, and the two-sided persist filter.
- [Standing turned into capability](trust-tiers.md): what a score actually
  permits.

---

*Next: [Standing turned into capability](trust-tiers.md)*
