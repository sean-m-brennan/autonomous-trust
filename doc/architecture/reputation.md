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

## Pinned scenarios

| Behavior | Scenario |
|---|---|
| Phase 1 happy path | [`reputation-canonical.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/reputation-canonical.yaml) |
| Nack on a stale ballot | [`request-nacked-stale.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/request-nacked-stale.yaml) |
| Backdate on a chain mismatch | [`request-backdated-chain-mismatch.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/request-backdated-chain-mismatch.yaml) |
| Phase 2 acceptance | [`transaction-accepted.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/transaction-accepted.yaml) |
| Phase 3 bilateral commit | [`transaction-committed-bilateral.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/transaction-committed-bilateral.yaml) |
| Sync, outdated notification | [`chain-outdated-notification.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/chain-outdated-notification.yaml) |
| Sync, replay of an update | [`chain-replay-update.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/chain-replay-update.yaml) |
| Replay of a ballot refused | [`ask-permission-replay-rejected.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/ask-permission-replay-rejected.yaml) |
| Lower ballot identifier refused | [`ask-permission-lower-id-rejected.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/ask-permission-lower-id-rejected.yaml) |
| Evidence document and ceilings | [`warmstart-evidence-document.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/warmstart-evidence-document.yaml) |
| Sub-quorum slash finalizer refused | [`slash-final-sub-quorum-refused.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/slash-final-sub-quorum-refused.yaml) |
| Forged co-signatures refused | [`slash-final-forged-cosignatures-refused.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/slash-final-forged-cosignatures-refused.yaml) |
| Unattested checkpoint root refused | [`checkpoint-final-unattested-root-refused.yaml`](../../src/autonomous-trust/conformance/scenarios/reputation/checkpoint-final-unattested-root-refused.yaml) |

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
