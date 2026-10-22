# Selective assignment

A requestor normally invites every capable peer to every task. Selective
assignment lets it give a task to k of those N peers instead, by a draw whose
probabilities it records. Because the probabilities are on record, it can
later estimate what peers it did not ask would have done. This is R+D.md §12.7,
"Score the advice you did not take" in [the verification oracle](../verification_oracle.md).
The plan, with every design call and the date it was made, is
`RD_12.7_SELECTIVE_ASSIGNMENT_PLAN.md`.

The feature lives in the oracle extension: Python
`autonomous_trust.oracle.selection`, C `libat_selection`
(`src/c/extensions/selection/`). It stays inert until `$AT_SELECTION` names a
declaration. With no declaration, every task fans out exactly as before and
the prober keeps its deterministic choice.

## What is drawn

Two kinds of task are drawn:

- **An ordinary task whose capability the declaration gives a `k`.** The
  invitees are drawn from the capable, present peers, weighted by `1 + tier`.
  A capability the declaration leaves at `k: null` (the default) fans out.
- **A directed probe, when the declaration has a `probe` block.** The probe's
  target is drawn from every capable, present peer, weighted by the UCB1 bonus
  of the layer's own probe counts. The prober's own choice is overridden, so
  both runtimes draw from the same counts wherever their prober runs.

Nothing else is drawn. The window-phase broadcasts of the bootstrap
capabilities are never drawn, and neither is a task addressed to one peer by
anything but the prober (a live-replication replica, for instance).

`k = 1` is one categorical draw from `p_i = floor + (1 - n*floor) * w_i / W`.
For `k > 1` each peer is included independently with probability
`pi_i = clamp(k * p_i, floor, 1)`. If that round comes up empty, one
categorical draw picks a peer instead, and the logged inclusion probability is
the exact `pi_i + E * p_i`. So `k` is the mean set size, not a fixed one. A
floor that no distribution can meet (`n * floor > 1`) degrades the draw to
uniform, and the log says so.

A drawn peer that declines is a non-event for its reputation. The requestor
records the decline and draws its replacement, as a second decision, from the
peers not yet asked.

## The declaration

```json
{
  "version": 1,
  "default": {"k": null, "floor": 0.05},
  "probe": {"floor": 0.05},
  "capabilities": {
    "demo.query": {"k": 1, "floor": 0.1},
    "demo.command-issue": {"k": null}
  },
  "log_records": 4096
}
```

`floor` is the least selection probability any eligible peer has. Zero is
legal and means "never explored". A malformed declaration is fatal when the
node starts. The example is `config/cfg/selection.example.json`.

## Auditable draws

A draw seeded from anything the requestor picks per task could be ground, so
the seed comes from a committed hash chain. The requestor draws a secret
`root` and commits to `head = H^65536(root)`, where H is SHA-256. Draw n is
seeded by `link(n) = H^(65536-n)(root)`, from its first eight bytes. Every
decision takes one index, including a probe's and a re-draw's.

Every drawn invitation carries `draw: {head, index, link}`. The draw is in the
JSON form only, and absent when nothing drew the invitee. The invited peer
checks that the link hashes to the head and that the index went up. A jump in
the index shows it the draws it was not shown, and it asks about them with a
signed `selection audit` query. The answer gives only the asker's own row:
whether it was eligible, its propensity, whether it was selected, and the
stream offset and interval its coin had to fall in. The asker recomputes the
coin from the link. A failed check is logged and counted per requestor, and
the invitation is served anyway. Selection never refuses work and never
touches reputation.

The audit proves that the coin was the committed one and that the stated
propensities give the stated selection. It cannot prove that the stated
candidate set and weights are true. Those are the requestor's own claims.

A chain lasts 65,536 draws. A new head is accepted only with the old chain's
root, which closes the old chain. Rotating early lets a requestor re-roll once,
and every rotation is in its log.

## The log and the estimate

The requestor keeps two files in its configuration directory.
`selection-<proc>.json` holds the chain, the next index and the probe counts,
and is written before a link is used, so a restart never reuses one.
`selection-log-<proc>.json` holds the last `log_records` decisions, each with
its eligible peers, propensities, selections, and the outcome joined in when
the result is scored. Python scores in its main process and echoes the score
back to negotiation as a local `ScoreEcho`. C scores in negotiation itself.

Every five minutes, and on demand, a doubly robust estimator runs over the
log. Its reward model is each peer's mean probe outcome, never its
reputation, which is the very thing being checked. For each capability it
reports the value of the logged, uniform and greedy assignment policies and
the logged policy's regret against the other two. That is a diagnostic only.
Feeding it back into the requestor's own weights, or into a new evidence
channel, are later decisions (plan D7).

## Pinned scenarios

`conformance/scenarios/selection/` pins the declaration, the draw, the chain,
the audit and the estimate rule by rule.
`negotiation/spawn-task-selects-k`, `selected-peer-declines-redraw`,
`k-null-fans-out`, `probe-target-drawn` and `invitation-draw-checked` pin the
behavior inside a running negotiation process. Requestor-side refusal handling
is pinned by `negotiation/refusal-drops-participant` and
`refusal-unverified-keeps-participant`.
