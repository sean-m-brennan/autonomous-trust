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
  reads told uncapped.
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
ends its part of the burst and lifts its bound. The burst runs once; UCB
carries on after it.

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
  receives it, not which key encrypts it.

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
| 4 | fail probes | off | 60 s | not within the hour | 4 |
| 4 | fail probes | on | 60 s | 55 s | 1 |
| 8 | fail probes | off | 60 s | not within the hour | 4 |
| 8 | fail probes | on | 60 s | 115 s | 1 |
| 16 | fail probes | off | 60 s | not within the hour | 4 |
| 16 | fail probes | on | 60 s | 235 s | 1 |
| 32 | fail probes | off | 60 s | not within the hour | 4 |
| 32 | fail probes | on | 60 s | 475 s | 1 |

Against colluders that pass every probe (the careful adversary) the contact
is again trusted at 60 s either way, and the policy's whole effect is the last
column: tier 1 rather than 4 for a member vouched for only by the cohort.

Two things to read out of it. Without the policy, a colluding cohort keeps
its members trusted for as long as it likes: in the cooperation regime their
scores of each other, weighted by their own inflated reputations, outweigh
the joiner's failed probes. And the slander of the contact never mattered
much: once the joiner holds bilateral evidence with it, CTFT reads that, and
the slander only ever fed the prior. The simulation leaves out network
latency and the bootstrap window's fan-out pairs, in both arms alike.

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
