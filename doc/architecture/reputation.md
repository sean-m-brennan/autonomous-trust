*Previous: [Getting work done](negotiation.md)*

# Earning standing

Reputation in AutonomousTrust is a number between zero and one that answers one
question. Given everything this node has seen, and everything its peers have
attested and it has agreed to, how much is this peer worth dealing with right
now?

Three properties distinguish it from the scores most systems carry. It is not
issued by anybody, since no authority exists to issue it. It is agreed rather
than merely held, because peers run a consensus round over each transaction
score so that all of them end up with the same history rather than each with a
private opinion. And it fades, because a score is a memory of past conduct and a
memory that never fades would let a peer trade forever on a week of good
behavior.

Those three properties cost a great deal of machinery, and this chapter is
mostly that machinery. The order runs from the outside in. First what the
numbers mean, then how a score is computed from a history, then how peers come
to share one history at all, then what happens across a restart, and lastly the
attestation that keeps any of it from being simply asserted.

## What the numbers mean

Reputation lives on a scale from zero to one, and there are no negative values.
The per-transaction scores that feed the arithmetic sit around 0.8 for a clean
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
of that table. It exists precisely so the slash floor can sit at zero with the
participation cut-off just above it. A peer nobody knows anything about starts
at neutral, a small leeway above the cut-off, and only a peer that has actively
earned a sub-cut-off score is excluded. Ignorance and misconduct are therefore
different states rather than the same one.

All four thresholds honor environment overrides, read once at startup, and the
inspector dashboard reads the same cut-off variable so its displayed line tracks
a re-adjusted backend rather than a compiled-in assumption.

### Where a score came from

A score says how well a peer did. It does not, on its own, say how we know — and
those are different facts. "The proof it returned was invalid" and "the task came
back empty" can both be 0.3, and until 2026-08-21 nothing downstream could tell
them apart, because the number was all that crossed the wire.

Each `TransactionScore` therefore also carries an **evidence channel**, naming
which kind of finding produced it:

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
fraction of a cohort rises: every other channel is ultimately an aggregate over
peers, and a majority cannot be beaten without an external reference. A probe is
that reference. It is also distinct from `certificate`, and the difference is who
chose the question — a certificate is a proof the peer supplies about its own
work, while a probe is a question the verifier authored and already knows the
answer to, which a peer cannot tell from real work. The bootstrap corpus is
where these come from; see [Trust tiers](trust-tiers.md) §6.

Where these scores come from is worth stating once, because the two runtimes
place it differently and both places are correct for the runtime they are in.
The peer that *ran* the work submits its own half — its claim to have done the
job. The peer that *asked* submits the judgment: a known-answer probe checked
against the challenge it retained, or, failing that, a completion score.
Python does the judging in its orchestrator, which is also where it verifies any
proof attached to the result. C does it in its negotiation process, because that
is where C keeps the requestor's record of what it asked, and it attaches no
proofs, so it always takes the arm Python takes when proofs are unavailable.
See [Getting work done](negotiation.md).

The set is closed. A channel that is present but unrecognized is refused and the
proposal dropped, on the same reasoning as an off-scale score: the value of the
field is that a demotion reason means one agreed thing on both sides of the wire,
and an unrecognized spelling passed through, or quietly recorded as
`task_outcome`, would forfeit exactly that. Matching is case-sensitive. An
*absent* channel is a different matter and is not an error — it means a peer or
an app predating the field, which was grading a task outcome by construction, so
it normalizes to `task_outcome` and every earlier producer keeps its meaning.

The channel is part of the committed chain entry, not only of the score that
produced it: it rides the commit broadcast, is written to every acceptor's
history, and enters the entry's canonical bytes. See
[The reason is part of the committed fact](#the-reason-is-part-of-the-committed-fact)
for why, and for the one condition that keeps it from being a chain migration.

### What a channel does

Two things, and only for evidence this node produced itself.

**It weights the consensus average.** Each channel carries an integer multiplier,
composed with the per-capability `transaction_weight` from
[Trust tiers](trust-tiers.md) — they multiply, so a heavy capability refuted on
physics counts as both. The multiplier is applied the same way the capability
weight is, by folding the score into the EMA that many times, which is why these
are small integers.

| Multiplier | Channels | Why |
|---|---|---|
| 1 | `task_outcome`, `calibration`, `swarm_disagreement` | one peer's reading of one event |
| 2 | `replication`, `probe` | corroborated by construction — a replication has several executors, a probe is checked against an answer the verifier authored |
| 3 | `physical`, `certificate`, `self_consistency` | a verdict that needs no history at all |

These are a ranking of how much one observation tells you, not a tuning surface.
`calibration` sits at 1 on purpose: it is the channel that should decay a peer
*gradually*. An unrecognized spelling weighs 1 and never more, so adding a
channel on one side of the wire cannot silently amplify it on the other.

The multiplier is not a ranking of how *trustworthy* a channel is, which is why
`probe` sits below the three above it despite being the channel that survives an
adversarial majority. Those are different virtues: a probe's strength is that the
aggregate cannot be captured by a colluding cohort, while a physics refutation's
strength is that one observation settles the question outright. The multiplier
measures the second.

**It is retained as the reason.** See the next section: the channel enters the
committed entry, so every peer that holds the chain holds the reason a score was
poor, not just the number.

There is deliberately no third response, and in particular no automatic
accusation. Between 2026-09-01 and 2026-09-02 a defection-grade score on one of
the three hard-falsification channels *proposed* a slash, pinning the peer's
reputation from outside the consensus average on one detector's verdict. That was
removed at the user's direction, and the reasoning is the reasoning of this whole
section: a transaction is scored poorly **with its reason given**, every peer sees
both, and each judges for itself. Discipline is then the consensus average and the
tier machinery working at their own pace — which is graduated by construction —
rather than a fast path around them.

That also disposes of the question this section used to leave open. Since no
channel levies a verdict, there is nothing to dispute, so `swarm_disagreement`
needs no adjudicator and none is planned for either runtime. (A majority is not
an oracle, which is why weighting it like a hard channel would have been the
wrong answer too; it sits at the baseline multiplier.)

`physical`, `certificate` and `self_consistency` remain distinguished — they are
*falsifications* rather than grades, and the peer did not do poorly so much as
assert something untrue — but what that buys them is the top multiplier and a
legible reason, not an accusation.

What survives of slashing is the deliberate act: the behaviour governor's
human-on-the-loop path, and an operator's explicit exclude or rehabilitate. The
protocol they use is now opt-in to match. With `AT_SLASH_ENABLED` unset — the
default — a node originates no slash, declines to co-sign a peer's proposal, and
ignores a finalized one rather than applying its floor. Arm it fleet-wide if you
arm it at all: a group where only some members are armed will disagree about the
floor, which is inherent to slashing being a policy rather than a fact.

### The reason is part of the committed fact

A response that consists of "every peer judges for itself" only works if every
peer *retains* what it is judging. Until 2026-09-02 the channel stopped at the
chain boundary: the commit broadcast carried a bare score, so an acceptor wrote
the number and dropped the reason, and the reason survived only in the scorer's
own log and in flight (where a relay could alter it undetected).

So a chain entry now carries the channel of each side's score, and
`Transaction._canonical_bytes` covers it — which means the entry hash covers it,
and therefore so do the chain link, the window root, and the quorum-signed
checkpoint over that root. Stripping a refutation off an entry breaks the link.
The reason also travels wherever the entry does: the catch-up wire, the persisted
evidence document a warm start verifies, and the evidence-backed answers deep
resolution returns.

The one condition, which is what makes this an additive change rather than a
chain migration: the `|p1_channel|p2_channel` block is appended **only when at
least one side carries a channel other than `task_outcome`**. Three consequences,
each load-bearing:

- The same fact still hashes to the same bytes. An absent channel and an explicit
  `task_outcome` are the same claim, and both omit the block, so two nodes cannot
  disagree about an entry's hash because one of them received the default spelled
  out.
- Every entry committed before the field keeps its hash. Entry hashes chain and
  roll up into roots that are already signed, so appending unconditionally would
  have invalidated every stored chain, every finalized checkpoint and every
  byte-pinned corpus vector at once.
- The tampering that matters is still caught. Stripping a real channel changes
  the bytes; adding `task_outcome` to an untagged entry is a no-op because it
  asserts nothing.

An unknown spelling arriving on the commit path drops the whole commit rather
than being coerced to the default. Coercing would either fork this node's entry
hash away from the group's or silently rewrite the reason — and a peer sending
one is speaking a vocabulary this node does not have, which is exactly what the
closed set exists to catch.

`capability_name` deliberately did *not* travel with the channel. It would
publish a per-peer record of which capability every transaction exercised, and
per-capability weighting stays local.

### Only your own evidence counts

The *multiplier* applies only to a score this node produced. The scorer chooses
its own tag, so honouring a remote peer's channel would hand every peer a lever
on every other peer's reputation: tag a fabricated 0.0 as `physical` and it would
land with triple weight. A score that arrived from the wire keeps its channel —
it is retained, committed and legible, which is the point — and is weighted by
capability alone.

Retention and weighting are different powers, and only the second is withheld. A
peer's claim about how it knows something is worth recording; it is not worth
letting that peer decide how heavily this node folds it in.

The cost is that two nodes can compute slightly different consensus averages for
the same peer. That is already true of the per-capability weights — a verifier
across a trust boundary cannot reproduce them either — so this adds a term to an
existing local-view divergence rather than introducing one.

### What is still missing

Nothing in the channel machinery itself: the vocabulary, the multiplier and the
retention are all in place on both runtimes, and the third response the design
once called for (a dispute) was answered by deciding there is no verdict to
dispute.

What is missing is *producers*. Only `task_outcome`, `certificate` and `probe`
have any: `physical`, `calibration`, `self_consistency`, `replication` and
`swarm_disagreement` are vocabulary waiting for the oracle layers that would emit
them. See R+D.md section 12 and
[the verification oracle](../verification_oracle.md).

## Computing a score

When a reputation query arrives, the score is computed by one of two strategies,
selected by the current standing of the peer.

The mode switch uses hysteresis, and it was added because a peer hovering near
the boundary used to flip modes on every tick, swinging between 0.9 and 0.4. A
peer must climb above 0.55 to enter cooperation mode and must fall below 0.45 to
drop back. Inside that band the previously selected mode is retained.

In *cooperation mode*, the score is pure reputation, being a weighted average of
every transaction score involving this peer. Each score is weighted twice over,
by the reputation of the counterparty and by the capability weight of the
transaction, so that a higher-tier capability counts for more.

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
    Note right of alice: Phase 1, alice broadcasts an ask-permission ballot on the encrypted group channel. (id1, id2, proposer) uniquely tags the round; id1 is a millisecond timestamp, id2 is the proposer's chain index.
    bob-->>-alice: permission granted (re: 1)
    Note right of bob: Phase 1, bob's last_id is None and chain is empty, so the strict-inequality guard passes; handle_request emits a grant ack back to alice. (Out-of-band nack / backdate / sync branches are documented in separate scenarios.)
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
is precisely a memory of the prior activity of a peer becoming operational again
at startup. It is not a grant of trust and not a configured allow-list. It is
the reputation a peer already earned through observed transactions, persisted to
disk and reloaded into the live store.

Because that score is bound to the same cryptographic identity and remains
subject to continuous re-evaluation, a warm-started peer sits in exactly the
same regime as any other. It simply does not have to climb from neutral on every
reboot.

Two mechanisms avoid the dead zone a peer with no bilateral history would
otherwise sit in. A *seeded warm start* loads any persisted snapshot at startup,
so known-trusted peers read as trusted immediately rather than spending the
warm-up window looking untrusted. And a *consensus baseline* derives a starting
score from available consensus state when a peer has no transactions on the
chain at all, rather than falling back to the flat neutral value.

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
nothing about how it was reached. Reloading it makes trust durable and does not
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

Three properties, and the reason each is separate. A co-signature must verify to
count, since otherwise the tally counts assertions and any member can assert
anything. A vote belongs to the authenticated sender rather than to the voter
the payload names, which additionally stops a harvested genuine signature, and
they travel in the clear on every finalizer, from being relayed under the name
of its signer by somebody else. And quorum is sized by the receiver from its own
roster, so the finalizer cannot also choose the bar it must clear.

A finalizer with no verifiable co-signatures is refused, which makes this a flag
day: a node built before the change cannot finalize a slash or a checkpoint for
a node built after it. There is no lenient mode, by design, since an attacker
would simply select it.

### The vulnerability this closed

Before this change, both rounds collected the co-signature bytes and threw them
away. The signing handler credited the voter identifier claimed in the payload,
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

It needed a credentialed insider rather than an outsider, which is the
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
the cohort reached neither `latest_reputation` nor `latest_reputation_pairs`. The
symptom was an inspector trust graph with no C opinions in it and nothing saying
why. C carries the tag for the same reason the warm-start snapshot does: this is
the same state in both runtimes, so the identifier is a shared constant rather
than a language artifact.

**Nothing else** in the body, because the requestor reconstructs the object by
keyword — a stray field is a `TypeError` there, not a value it ignores. That is
why `requesting_process` is not in the payload.

It belongs in the **envelope** instead, as the reply's `process`, because that is
the field a requestor routes an inbound message by. C named `"reputation"` at all
three reply sites, which delivered every reply to the requestor's *reputation*
process — where Python has no `rep_resp` handler — rather than to the process that
asked. Shape and routing had to be fixed together: either alone leaves the answer
undelivered or unreadable. An absent or empty requesting process falls back to
`"reputation"` so a malformed request produces a deliverable reply rather than one
addressed to nothing.

The consumer no longer trusts the shape it is handed either. A mapping with
`peer_id` (or the older `peer_uuid`) and a numeric score is accepted, anything
else is dropped with a warning that names the sender, and neither can raise: that
loop services every message the node receives, so one peer's malformed reply must
not be able to stop the rest. A mixed-version cohort keeps working while it
catches up.

Pinned on both sides: `src/c/test/rep_resp_shape_test.c` asserts the emitted tag,
the exact key set, and the routed envelope for all three verbs;
`tests/a_unit/test_rep_resp_interop.py` asserts the consumer reads the tagged
form, the legacy C form, and refuses the rest.

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
| Replay of a ballot refused | [`ask-permission-replay-rejected.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/ask-permission-replay-rejected.yaml) |
| Lower ballot identifier refused | [`ask-permission-lower-id-rejected.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/ask-permission-lower-id-rejected.yaml) |
| Evidence document and ceilings | [`warmstart-evidence-document.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/warmstart-evidence-document.yaml) |
| Sub-quorum slash finalizer refused | [`slash-final-sub-quorum-refused.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/slash-final-sub-quorum-refused.yaml) |
| Forged co-signatures refused | [`slash-final-forged-cosignatures-refused.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/slash-final-forged-cosignatures-refused.yaml) |
| Unattested checkpoint root refused | [`checkpoint-final-unattested-root-refused.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/checkpoint-final-unattested-root-refused.yaml) |
| Single-subject reputation request | [`request-reputation-cross-process.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/request-reputation-cross-process.yaml) |
| Batched consensus request, self skipped and duplicates collapsed | [`consensus-reputation-batch.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/consensus-reputation-batch.yaml) |

Unit coverage for the attestation rules lives in
`tests/a_unit/test_repprocess_quorum_attestation.py` on the Python side and
`src/c/test/rep_quorum_test.c` on the C side. The child-chain checkpoint work is
described in [Gateway reputation tree](gateway-reputation-tree.md), and the closure of the
original last-identifier divergence in `BUGS.md` section P6.

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
