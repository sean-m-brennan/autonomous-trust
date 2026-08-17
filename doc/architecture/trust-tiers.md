*Previous: [Earning standing](reputation.md)*

# Standing turned into capability

A reputation score is a number, and a number by itself changes nothing. What
makes trust operational is the mapping from that number to what a peer is
actually permitted to do, and the machinery that opens access as standing rises
and closes it again the moment standing falls.

That mapping is the trust tier. Five bands, from tier 0 meaning merely admitted
up to tier 4 meaning fully trusted, each unlocking a class of capability. Tier 0
is network presence. The bands above it are communication, services, reading
shared data, and writing it.

Three mechanisms make the ladder work, and each answers a failure the framework
actually exhibited. Transactions are *weighted*, so a mission-critical exchange
moves reputation faster than a heartbeat does, because equal weighting made
every score contribute identically and reputations sat flat. A *bootstrap
corpus* of small built-in exchanges gives a freshly admitted peer something
harmless to be scored on, because otherwise the only scoring flow was the
consequential operation itself, and there was no separation between building
trust and acting on it. And *tier gating* runs in both directions symmetrically,
so demotion cancels work in flight rather than letting an authorization outlive
the standing that granted it.

Section numbering below is retained because other documents cite these sections
by number.

## 1. Rank is not trust tier

Two integers attach to a peer and they mean entirely different things. Confusing
them is the single most common misreading of this subsystem, and the code once
encouraged the confusion by storing the second in a field named for the first.

*Rank* is a network-topology concept. It indicates one-hop reachability through
gateways: a node of rank 1 can send a message via a gateway to a node of rank 2.
Gateways build network trees and rank indicates the level in that tree. Leaves
at rank 1 can send messages up the tree but not up and then down to reach
otherwise unreachable rank-1 nodes. A gateway is by definition a more capable
node, having better connectivity, more compute, longer uptime, and more
available bandwidth, so rank reflects what a peer can do at the network layer.

*Trust tier* reflects how much its behavior is believed.

| Axis | Source | What it gates | Algorithm class |
|---|---|---|---|
| Rank (`peer._rank`) | Static configuration at deployment | Message routing, partition-leader selection, Proof-of-Authority votes | `AgreementByAuthority` |
| Trust tier (`peer._tier`) | Reputation-derived through `TIER_FLOORS` | Capability access, transaction weighting, Proof-of-Trust votes | `AgreementByTrust` |

Although both are integers attached to the same peer, the two axes are
independent. A rank-1 leaf can hold trust tier 4, being fully trusted and
reachable through its gateway. A rank-3 gateway can hold trust tier 0, being
well placed in the topology with no behavioral track record yet. Both are valid,
and the axes do not interact except where a domain policy chooses to make them.

The reputation process no longer mutates rank. Rank is populated from identity
configuration at startup and stays static for the life of the process unless a
deployment-side change re-issues the identity. Readers of rank, being the
partition-leader selector and the authority-agreement vote counter, are
unaffected. Deriving rank dynamically from observed topology is a separate
design and out of scope here.

## 2. The problem this closed

The nominal trust path is that peers interact, transactions accumulate,
reputation rises above the hysteresis band, and full cooperation begins, with
contrite tit-for-tat governing until then. That works only when there is a
stream of bilateral transactions to score against, and three things broke the
premise.

Firstly, there was *no bootstrap corpus*. The framework shipped no built-in
capabilities peers could exercise to seed reputation, so every domain had to
invent its own. In the reference mission demo the only score-producing flow was
sensor reporting, which is also the load-bearing consequential operation, so
building trust and acting on trust were the same activity.

Second, *transactions were equally weighted*. Successful delivery of a trivial
heartbeat contributed identically to successful delivery of mission-critical
sensor fusion. There was no notion of stakes, which contradicts the tit-for-tat
intuition the whole design rests on: exchanges where defection is materially
costly should move reputation faster than trivial ones.

Lastly, *tier gating was implicit*. The negotiation layer had one coarse gate,
refusing when the peer level was zero, and that was the entirety of trust-based
access control. The four access tiers existed as a conceptual framing with no
mechanism to honor them.

## 3. What this does and does not do

The goals were to define an extensible corpus of low-stakes exchanges every peer
can engage in immediately after admission, to make transactions weighted by
their consequence, to provide a deterministic mechanism for promotion and for
symmetric revocation on demotion, to let each domain declare its own
tier-to-capability mapping without forking the core, and to reach parity between
the two runtimes from the start rather than leaving trust arithmetic skewed on
one side. The consensus and tit-for-tat semantics are untouched, and the
bilateral pairing invariant in the transaction history stays as it was.

Four things are deliberately not addressed. Redefining rank or deriving it from
observed topology is a separate design. Cross-domain tier portability, meaning a
peer in two trust ladders at once, is undefined in this version. Zero-knowledge
strength proof of execution for the bootstrap corpus is a follow-up, since the
current construction uses signed nonces. And per-tier consensus aggregation,
where a peer would carry a separate score at each tier, is a strictly larger
redesign.

## 4. Data model

*Capability tier metadata.* A capability carries two fields, both
backwards-compatible.

```python
class Capability(Configuration):
    def __init__(self, name, function=None, arg_names=None, keywords=None,
                 required_tier: int = 0, transaction_weight: int = 1):
        ...
        self.required_tier = required_tier
        self.transaction_weight = transaction_weight
```

The `required_tier`, defaulting to 0, is the minimum tier a peer must hold to be
invited to perform this capability, and the minimum the inviter must hold to be
accepted. Tier 0 means any admitted peer. The `transaction_weight`, defaulting
to 1, multiplies scores from this capability in the reputation aggregate, on a
default schedule of 1, 2, 4, 8 for tiers 1 through 4. Tier-0 transactions carry
weight 1, accumulating slowly but reliably as the bootstrap signal.

The wire format gains two optional fields, plumbed through the message
synchronization path. Peers that do not carry them default to tier 0 and weight
1, so they remain interoperable.

*Peer trust tier.* The reputation-derived value lives in `peer._tier`,
defaulting to 0, and rank no longer holds it. The floors are unchanged from the
values the old rank table carried, being 0.50 for tier 1, 0.65 for tier 2, 0.80
for tier 3, and 0.90 for tier 4. Tier 0 corresponds to admitted only, and tiers
1 through 4 map to communication, services, reading shared data, and writing it.

*Transaction score linkage.* Weighting a score requires knowing which capability
produced it, and a bare score carries no such handle. Three options were
available: adding a capability name to the score, looking the capability up by
task identifier through the negotiation tracker, or caching the weight itself on
the score. The first was chosen. It costs one optional string on the wire, where
the second creates a tight coupling between reputation and negotiation plus a
synchronization hazard when the tracker has not yet recorded the task on the
scoring node, and the third loses the capability identity that future auditing
and per-capability aggregation would want.

## 5. Weighting arithmetic

Two consumers care about the weight.

The *pure reputation* aggregate becomes a weighted average rather than a plain
one.

```python
def _pure_reputation(self, peer):
    total, total_w = 0.0, 0
    for tx in self.history.by_peer(peer.uuid):
        reporter_score = ...
        if reporter_score is None: continue
        peer_score = tx.p1_score if tx.p1_id == peer.uuid else tx.p2_score
        w = self._tx_weight(tx)  # transaction_weight from cached capability
        total += reporter_score * peer_score * w
        total_w += w
    if total_w == 0: return 0.2  # PREREP_NEUTRAL
    return total / total_w
```

The weight function returns the transaction weight of the capability named on
the originating score. When the capability is unknown locally, the weight falls
back to 1, which is the conservative default and matches a tier-0 baseline.
Contrite tit-for-tat is unchanged.

The *consensus average* driving the dashboard applies the same multiplier at
each update step, and its half-life is interpreted in weight units rather than
in transactions. A single tier-4 result therefore moves the average eight times
faster than a tier-1 result.

Both runtimes are weight-aware and the arithmetic is pinned. On the Python side
both aggregates weight each transaction by the cached capability weight, with
the cache populated at consensus start and at transaction handling, bounded at
twice the default maximum chain length. On the C side both take a weight map
argument and apply the same per-transaction weighting, threaded through on the
pure branch of the query handler. A C unit test pins the arithmetic in process,
and a conformance scenario runs the query path end to end on both adapters,
asserting that weighted inputs produce 0.8 where an unweighted regression would
produce 0.65, which trips the tolerance.

Landing that pin required two follow-up fixes. The Python computation path had
to accept a bare identifier string from the wire, since the canonical query form
parses to a string rather than to a peer object. And the C test surface needed
install and get hooks plus the corresponding fixture keys, mirrored on the
Python adapter.

## 6. The bootstrap corpus

Three tier-0 capabilities ship in the core under a reserved namespace. They are
available on every peer immediately after admission, and they exist for one
reason, which is to give the reputation algorithm something to score.

*Handshake.* Peer A picks peer B from the cohort and sends a 32-byte challenge
nonce. B signs a hash over the nonce and its own identifier with its identity
key and returns the signature. A verifies, scoring 0.9 on success and 0.1 on
failure, and B independently submits the bilateral pair from its own side. The
defection surface is that B can refuse to respond, respond with a wrong
signature, or respond under the wrong identity, and all three score 0.1.

*Time attestation.* Peer A asks peer B for its current time and scores the
answer against its own clock with a tolerance of two hundred milliseconds by
default, which sits well above network round-trip noise and well below the
threshold at which a peer is lying. Within tolerance scores 0.9, outside scores
0.5, and unreachable scores 0.1. The band makes occasional honest drift
forgivable while sustained skew is detected.

*Echo challenge.* Peer A sends a small random payload signed by A, and B echoes
it verbatim with its own signature prefixed. A verifies both signatures and that
the payload bytes match. This is the canonical did-you-actually-do-what-I-asked
transaction, scoring 0.9 or 0.1. The defection is hard to commit accidentally,
since a malicious modification has to survive the signature check, which forces
it to be a real attack rather than a transmission glitch.

*The worker.* A core worker, registered by default, opens a window of roughly
thirty seconds of random pairwise interactions across all admitted peers on
admission, picking uniformly among handshake, attestation, and echo. Three
environment variables configure it, being the window duration defaulting to
thirty seconds, the per-peer interaction count defaulting to twenty, and a
disable flag for unit tests that want a quiet network. A seed variable is
honored so tests and scenarios get deterministic sequences. After the window
closes the worker stops scheduling new pairs and in-flight transactions complete
normally, by which point reputation has accumulated enough bilateral entries to
move peers off tier 0.

Both runtimes carry the corpus. The Python side auto-registers all three
capabilities on every instance, with server-side functions and client-side
verifiers shipping as first-version constructions rather than
zero-knowledge-strength ones. The C side carries matching implementations, a
name registry, and a seeded worker using its own pseudorandom generator. The
conformance pin uses an observable that is agnostic to the generator, being the
coverage set rather than the selection sequence, so the two runtimes need not
produce identical orderings to be held to the same contract.

## 7. Moving up and moving down

*Promotion.* The publication mechanism handles this with no new plumbing. The
tier-change publisher fires whenever a score crosses a floor, the update message
lands on the identity queue, and the handler mutates the tier on the peer. The
new behavioral piece is in negotiation, where the invitation handler gates on
the tier of the sender against the required tier of the capability. The old
coarse gate becomes that comparison. A test fixture in the C negotiation process
that had supplied synthetic peer levels was removed, so production code reads
the real tier.

*Demotion.* This is the more interesting direction because of tasks in flight.
When the tier of a peer drops below the required tier of a capability that peer
is currently executing for somebody else, or whose results somebody else is
waiting on, that work has to be cancelled rather than allowed to complete and
silently exfiltrate data.

The mechanism runs in four steps. The tier-change publisher detects that the new
tier is lower than the old. It emits a tier-lost message onto the negotiation
queue in addition to the ordinary update. The negotiation handler walks the
tracked tasks and the job queue, cancelling every task where the affected peer
is a participant and the required tier now exceeds what the peer holds.
Cancellation means removing the job from the queue, reporting the cancellation
to the originator, sending a refusal to the other participants, and deleting the
tracker entry so later results for that task are rejected. The event is recorded
for the dashboard and event log, appearing alongside the anomaly markers that
triggered the tier loss in the first place.

Symmetry here is what matters. Although the two directions look like separate
features, the same tier mutation opens capability access on the way up and
closes it on the way down, in one code path and one process, so no asymmetric
surface exists where stale cached access survives.

*Hysteresis.* The cooperation-mode band already prevents scoring-mode flapping,
and tier transitions need the same protection or a peer hovering near a boundary
will oscillate. A fixed epsilon of 0.02 applies to each floor on the way down,
so promotion happens at the floor and demotion at the floor less 0.02. This
keeps the published floor stable for documentation while adding a quiet buffer
in the implementation.

*Below the ladder.* One threshold sits below tier 0 and is not a tier. The
communication cut-off at 0.1 excludes a peer at the network layer rather than
merely demoting it. Because 0.1 lies inside tier 0, which spans zero to 0.5, a
move from 0.15 to 0.05 is a no-op for the ladder and must still exclude the
peer, so the publisher checks the crossing before its tier early-return.
Recovery is explicit only, and the excluded state persists across a restart. The
full mechanism is in [Earning
standing](reputation.md#exclusion-enforced-rather-than-displayed).

## 8. Declaring a ladder

Each deployment declares its own mapping in a trust-ladder file alongside its
scenario configuration. The loader maps capability names to required tier and
transaction weight and parameterizes the bootstrap worker. Defaults apply when
the file is absent, meaning everything at tier 0 and weight 1 with bootstrap on.

```yaml
version: 1
bootstrap:
  duration_sec: 30
  pairs: 20
capabilities:
  at.handshake:       { required_tier: 0, transaction_weight: 1 }
  at.time-attest:     { required_tier: 0, transaction_weight: 1 }
  at.echo-challenge:  { required_tier: 0, transaction_weight: 1 }
  dod.network-presence: { required_tier: 1, transaction_weight: 2 }
  dod.sensor-report:    { required_tier: 2, transaction_weight: 4 }
  dod.fusion-validate:  { required_tier: 3, transaction_weight: 8 }
  dod.command-issue:    { required_tier: 4, transaction_weight: 8 }
tier_demotion_epsilon: 0.02
```

Capability tier and weight come from this file at registration time, and domain
code never hard-codes either. A new deployment adds its own ladder and the rest
of the mechanism applies automatically.

Both runtimes load the ladder from one JSON file. The C side parses it with a
JSON library and the Python side needs no change, since YAML is a superset of
JSON, and a shared example file is what both test suites assert identical
numbers against. One behavioral difference is inherent to the two registries.
Python creates capabilities from the ladder, where the C capabilities are
declared in code, so the C apply step overrides the tier and weight of those
already present and leaves unlisted ones alone. A scenario file that only feeds
the Python loader of a particular demo still parses; a ladder meant for both
runtimes should be JSON.

## 9. Parity between the runtimes

Every Python element has a C mirror.

| Python | C |
|---|---|
| `Capability.required_tier`, `transaction_weight` | `capability_t::required_tier`, `transaction_weight` |
| `TIER_FLOORS`, `_trust_tier` | `TIER_FLOORS[]`, `_trust_tier` in `rep_proc.c` |
| `_publish_tier_change`, `tier_update` | identical names in `rep_proc.c` and `id_proc.c` |
| `peer._tier` | `peer_t::tier` |
| `handle_tier_lost`, task cancellation | `handle_tier_lost` in `neg_proc.c`, walking the same map |
| `BootstrapWorker` | `bootstrap_worker_t` |
| `AgreementByTrust` | `_trust_count_vote` and friends in `agreement.c` |
| The three bootstrap capabilities | identical C implementations, registered by the C bootstrap |

## 10. Proof of trust

The authority agreement class reads rank and is the right shape for
capability-gated decisions, meaning cases where only gateways should vote. It is
unchanged.

The trust agreement class is a parallel one that reads tier. It applies when the
correctness of an agreement depends on behavioral track record rather than on
inherent node capability, as when authorizing a data-sharing operation where any
well-behaved peer should be eligible to vote regardless of whether it is a
gateway. It mirrors the authority class in shape, differing only in the
attribute it reads and the name of its threshold field.

The two coexist rather than one replacing the other, and any given agreement
uses whichever matches what its consequence actually depends on. Rank answers
what a node can reach, tier answers how it has behaved, and neither substitutes
for the other.

## 11. Conformance impact

New scenarios cover the bootstrap corpus running on admission, refusal below a
required tier, tier loss cancelling a running task, weighted pure reputation,
and the trust-agreement threshold filter.

Existing scenarios survive unchanged where the observable behavior is the same.
The old low-reputation refusal still holds, because tier 0 still refuses any
required tier above zero. The whole authority-agreement family is unaffected.

Scenarios that asserted specific rank fields or rank-update messages in their
traces were renamed to the tier equivalents, which is mechanical.

## 12. Open and out of scope

*Capability namespace versioning.* Versioned names would let the bootstrap
corpus evolve without breaking older peers. Recommended, and the current names
ship without a version suffix, so the migration is a follow-up.

*Stronger echo challenge.* The current construction uses signed nonces, which is
sufficient for this version and does not preclude all forms of collusion.

*Cross-domain tier portability.* A peer participating in two ladders at once,
with a different file per group, is undefined behavior.

*Topology rank source.* Statically configured for now. Dynamic adaptation, such
as observing paths and downgrading on gateway loss, is not addressed.

*Per-tier consensus aggregation.* A peer could in principle carry a separate
score at each tier, being trusted at tier 1 with 0.92 and untrusted at tier 3
with 0.41. The single-score model collapses that to one number, and separating
it is a larger redesign.

## Further reading

- [Earning standing](reputation.md): the consensus protocol and the scoring
  semantics this rides on.
- [Getting work done](negotiation.md): the task lifecycle that produces the
  scores, and the gate this chapter supplies.
- [Partition recovery](partition-recovery.md): the prior example of a same-shape
  extension to identity-side bookkeeping.

---

*Next: [The human behind the machine](operator-attended.md)*
