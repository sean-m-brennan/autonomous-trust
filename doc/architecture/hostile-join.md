# Joining a hostile cohort

A node joining a cohort learns almost everything about it from the cohort: the
history it adopts, the members it is introduced to, the reputation entries
those members wrote about each other. If the cohort is honest, that is the
fastest way in. If most of it colludes, the joiner believes whatever the
colluders agreed to say. They can vouch for each other, slander the honest
members, and outvote the joiner on every entry it writes.

The **join policy** is the opt-in defense. It does not try to out-vote a
colluding majority, which cannot be done from inside it. It changes what the
joiner believes on the cohort's word alone, gets it evidence of its own
quickly, and lets the honest nodes that know each other keep their evidence
among themselves. Design and decisions: `RD_14.4_HOSTILE_JOIN_PLAN.md`
(R+D.md §14.4).

## The declaration

The policy is a file named by `$AT_JOIN_POLICY`; absent, every path below is
inert and a node joins exactly as before. A file that does not validate stops
the node at start rather than leaving the defense silently off.

```json
{
  "version": 1,
  "enabled": true,
  "anchors": ["verified_contact", "zta", "operator"],
  "told_tier": 1,
  "own_evidence_min": 3,
  "burst_k": 3,
  "burst_interval_sec": 5,
  "burst_budget_factor": 4,
  "anchored_cohort_min": 1
}
```

`anchors` names which out-of-band evidence makes an identity one the joiner
trusts before the cohort tells it anything: a first-contact contact whose
safety number was compared (`verified_contact`), a ZTA credential chained to
our trust anchors (`zta`), a node under this node's operator key
(`operator`). `unverified_contact` is accepted and left out of the example: a
forwarded invitation link is enough to hold one. Each class needs the
extension that answers it, or the node refuses to start. The example is
`config/cfg/join_policy.example.json`; both runtimes parse it the same way
(`identity/join_policy.py`, `identity/join_policy.c`).

## Choosing which cohort to join

A node that hears several histories while it waits picks one. Without the
policy it takes the longest. Under it, a history **offered by an anchor**
wins first; among those, the longest. What a history *contains* proves
nothing, since a cohort can list any public identity in its address map, so
the test is who offered it. With no anchor's offer the old rule runs
unchanged. See [Identity protocol](identity-protocol.md#joining).

Members the joiner learned only from the adopted history are marked
provisional, and the chain entries that arrived by catch-up are marked told.
Neither mark leaves the node; both persist, so a restart does not launder
them.

## Brought and told

Under the policy a node keeps two scores per peer. **Told** is the stored
score, as always: every entry on the chain, whoever wrote it. **Brought** is
scored by the same rules over this node's own evidence alone: its halves of
bilateral transactions, physics and calibration findings, and probe
verdicts. Each reader names which it reads:

- **Decisions** (tier, the app carrier, `rep_resp`, delegation) read the
  bounded score: the brought score once the peer has `own_evidence_min` own
  entries, otherwise the told score capped at `told_tier`. An anchored peer
  reads told uncapped until then, and brought after, like any other. Told
  uncapped for good let the colluders' low scores of an anchor pull an honest
  joiner from 0.9 to 0.573 in the live run of 2026-11-04, while every
  transaction between the two joiners scored 0.9.
- **Exclusion** reads brought (or told, for a slashed peer), so the cohort's
  word alone never excludes anyone.
- **The prior** for a peer this node has no bilateral history with skips the
  catch-up-marked entries, so an unprobed member of the cohort reads exactly
  neutral.

So a colluding cohort can still say what it likes, but what it says alone
holds a member at tier 1 at most. See [Reputation](reputation.md#tenure).

## Seeds beat told scores

A verified contact's trust seed normally yields to any score the node already
holds. Under the policy it replaces a score that exists only because of told
evidence (no own entry, not warm-started, not slashed), so a cohort cannot
pre-empt a contact's seed by slandering it before the joiner arrives. A seed
still never overrides an earned, warm-started or slashed score. See
[First contact](first-contact.md#the-seed-reaches-reputation).

## The join burst

Evidence of the joiner's own is what lifts the bound, and continuous probing
gathers it at one probe a minute: a joiner facing forty members needs forty
minutes to probe each once. Under the policy the bootstrap worker runs one
**join burst**. Reputation tells it which peers it reads under the told
ceiling and how many probe verdicts it holds about each; the worker probes
each until it holds `burst_k` verdicts, one probe per `burst_interval_sec`,
spending at most `burst_budget_factor` × N × k over the N targets. A probe
verdict is full own evidence, so with the defaults a peer's third verdict both
ends its part of the burst and lifts its bound. Once every target holds its
verdicts or the budget is spent, the burst ends and UCB carries on. A peer
first listed short after that opens the burst again, with its own share of
the budget. At 32 colluders a joiner that knew one peer when its burst began
had already given that peer three verdicts from its window probes, so the
burst ended within a second, and the 32 peers it learned of next were never
probed.

A verdict counts as soon as the joiner records it, without the probed peer's
half. Until 2026-11-06 it counted only once the bilateral entry committed,
which needs that half too. At 18 nodes the colluders sat at the probe-half cap
and dropped 90 of their halves, so the burst spent about 107 probes for 48
verdicts, and a peer that never writes its half was never graded at all. Now
the joiner keeps each verdict aside as a **lone verdict**, before the cap can
drop its own half. Every reader of own evidence takes it: the count against
`own_evidence_min`, the burst's counts, the brought score and the told
tit-for-tat. No score of the joiner stands behind a lone verdict, so it never
counts as a defection. It is never placed and never told; when the bilateral
entry for the same task reaches a chain, that entry is read instead. Lone
verdicts are kept in `reputation-verdicts`, beside the retained entries, at
most 64 per peer, and they count under the policy only.

The counts travel locally (`ProbeCounts` in Python, `PEER_PROBE_COUNT` in C),
never on the wire.

## The anchored cohort

Two honest nodes that know each other out of band are still members of the
hostile cohort, and every entry they write about each other is received,
co-signed and placed by colluders. Under the policy they form an **anchored
cohort**: a second group beside the cohort, with its own key, chain and
quorum, and no gateway.

- **Forming.** A node holding a primary group counts the members it counts as
  anchors. With at least `anchored_cohort_min` of them, the lowest uuid among
  itself and them mints the group and invites them; the rest wait for it.
- **Consent.** A node accepts an invitation only under the policy, when it is
  listed, when the sender and every other listed member are anchors it
  counts, and when it holds no other anchored cohort. Refusing an update of
  the cohort it holds is leaving it.
- **Coordination.** The lowest-uuid member adds an anchor that is not yet a
  member, drops a member that refused or did not answer within 60 s, and on
  either rotates the key and re-invites everyone. It never offers a peer the
  membership that peer refused, which would otherwise trade two members in
  and out forever.
- **What rides it.** A reputation half whose counterparty is a member names
  the anchored cohort, goes only to its members, and commits to its chain
  with its quorum. A half naming the anchored cohort from a non-member is
  refused, and so, under the policy, is one naming a group the node does not
  hold. The scorers read the anchored chain beside the primary one, so
  moving the evidence costs none of it. Traffic between two members is
  already pairwise-encrypted, so what keeps it from the cohort is who
  receives it, not which key encrypts it. The chain's placement rounds go the
  same way, pairwise to its members, and only they decide them: its genesis
  lists the members and nobody else. A round once went out as a group frame
  under the cohort's key, and a member, who belongs to the primary group too,
  opened it with the primary key and failed, so the hostile-join run of
  2026-11-04 placed nothing on the cohort's chain.

Two verbs, point to point: `anchored_cohort_invite` carries the group's
canonical form, key included; `anchored_cohort_reply` answers
`[group uuid, key epoch, accepted]`. Identity tells reputation which cohort it
holds over a local carrier (`AnchoredCohort`, `ANCHORED_COHORT`). The group
persists as `anchored_cohort.cfg.json`.

## What it buys

`autonomous_trust.evaluation.scenarios.hostile_join` simulates a joiner (a
real Python reputation process) entering a cohort whose members inflate each
other and slander its verified contact, with probes, work and the seed on a
simulated clock. Run it with
`python -m autonomous_trust.evaluation.scenarios.hostile_join`:

| colluders | adversary | policy | contact trusted | colluders below tier 1 | tier on the cohort's word alone |
|---|---|---|---|---|---|
| 4 | fail probes | off | 900 s | not within the hour | 4 |
| 4 | fail probes | on | 120 s | 55 s | 1 |
| 8 | fail probes | off | 960 s | not within the hour | 4 |
| 8 | fail probes | on | 120 s | 115 s | 1 |
| 16 | fail probes | off | 1020 s | not within the hour | 4 |
| 16 | fail probes | on | 180 s | 235 s | 1 |
| 32 | fail probes | off | 1020 s | not within the hour | 4 |
| 32 | fail probes | on | 180 s | 475 s | 1 |

Against colluders that pass every probe (the careful adversary) the contact
is trusted at the same times as against those that fail them, and the
policy's effect is in the last two columns: tier 1 rather than 4 for a member
vouched for only by the cohort, and the contact trusted in two or three
minutes rather than fifteen or more.

Two things to read out of it. Without the policy, a colluding cohort keeps
its members trusted for as long as it likes: in the cooperation regime their
scores of each other, weighted by their own inflated reputations, outweigh
the joiner's failed probes. And without the policy the slander of the
contact costs the joiner a quarter of an hour: decisions read the told score,
in which the cohort's word weighs against the joiner's own evidence. Under the
policy they read what the joiner brought, and contrite tit-for-tat lifts the
contact only as fast as that record grows, so a handful of good transactions
is no longer a tier-4 track record (it was 60 s in both arms before the rule
shrank a short record toward neutral). The simulation leaves out network
latency and the bootstrap window's fan-out pairs, in both arms alike.

### Live

`autonomous_trust.evaluation.redteam.colluding_cohort` runs the same attack
as containers: eight colluders and two joiners, each joiner the other's
verified contact, for 20 minutes. A time counts only if it holds to the end
of the run; the first time the condition was met is in parentheses. Python
backend, three runs to an arm, of 2026-11-05:

| adversary | policy | contact trusted | colluders below tier 1 | tier on the cohort's word alone |
|---|---|---|---|---|
| fail probes | on | 60–61 s | 168–227 s (median 224 s) | 0 |
| fail probes | off | 121–182 s (60–121 s) | 433–736 s in two runs, never in the third | 0–2 |
| pass probes | on | 60–63 s | n/a | 0–1 |
| pass probes | off | 63–64 s in two runs, 181 s (60 s) in the third | n/a | 0–4 |

With the policy on, the contact is trusted sooner than in the simulation,
since the two joiners exchange about forty transactions in their first
minute, and it stays trusted for the whole run on the anchored cohort's chain.
The colluders take about twice as long to sink as simulated.

Without the policy, the runs of 2026-11-04 trusted the contact at about a
minute and lost it within three, for good. Two things took it away, neither
in the simulation, and both are now fixed in both runtimes:

- **The cohort's traffic flushed the joiners' evidence.** The primary chain
  keeps 200 entries, and ten nodes' probes and tasks fill it in minutes. The
  joiners' early transactions with each other were evicted, and those of the
  contact fell from 35 to 2. The anchored cohort's chain carries only its
  members' traffic, so under the policy nothing evicts them. A node now keeps
  its own evicted entries aside, and its scores read them
  ([Reputation](reputation.md#verifier-attested-scores), "Own entries outlive the
  window").
- **The score alternated between regimes.** Contrite tit-for-tat over the
  joiners' own transactions scored the contact 0.84, which entered the
  cooperation regime; the cooperation regime's mean over everyone's entries,
  the cohort's slander included, scored it 0.34, which left it. Each
  rescore, once a minute, flipped the regime and the tier with it. A peer is
  now scored in the cooperation regime only while its mean there holds at or
  above the exit, so the joiners' own evidence wins
  ([Reputation](reputation.md#computing-a-score)).

What is left without the policy is the cohort's word acting on the told
score, which is what the policy is for. About two minutes in, the mean over
everyone's entries still sits between the exit and the contact's tit-for-tat
score, so for one rescore the contact reads that mean (0.49 to 0.72) and
loses a tier or more, until the slander takes the mean below the exit and
own evidence takes over. Against failing colluders, the cohort held one of
its eight at tier 2 to the end of one run, in the cooperation regime on its
members' scores of it, though the joiner's own probes of it failed. Against
colluders that pass, the cohort's word alone gave a colluder tier 4 in two
runs of three.

The simulation's arms without the policy trust the contact far later, at
900 s and more, and never sink the colluders. [TODO: why the simulation and
the live runs disagree without the policy.]

## What it does not do

It does not take a cohort back from a colluding majority, change who is in
the cohort's quorum, or hide the joiner's traffic with non-members. It
bounds what the cohort's word buys, speeds up the evidence that replaces it,
and gives the honest nodes a chain the cohort cannot touch.

## Further reading

- `RD_14.4_HOSTILE_JOIN_PLAN.md` — the decisions, phase by phase.
- [Identity protocol](identity-protocol.md), [Reputation](reputation.md),
  [First contact](first-contact.md), [Trust tiers](trust-tiers.md).
- [Gateway reputation tree](gateway-reputation-tree.md) — the child chains
  the anchored cohort's chain sits beside.
