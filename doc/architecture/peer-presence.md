*Previous: [App-facing peer carrier](app-peer-carrier.md)*

# Peer presence: local soft-absence

> Status: Implemented (C and Python), 2026-10-09. Unit-tested in both runtimes.
> Not yet run on a live cohort.

## Context

Nothing in AT noticed that a peer had gone quiet. The cohort roster is
upsert-only: a member that stops answering stays in `peers[]`, in every group
address map and in every quorum count. That is deliberate (see "What this does
not do"), but it left two gaps:

- **An app could not tell.** The peer carrier ([app-peer-carrier.md](app-peer-carrier.md))
  reports who a peer is and what it has earned. It said nothing about whether
  the peer was still there.
- **Work kept going to the silent.** Negotiation invited a stopped peer to every
  task its capabilities matched, and the probe worker kept choosing it. Each
  invitation waited out its timeout.

## Key decisions

All four were the user's call (2026-10-09).

**1. Local and advisory, never membership.** A node marks a peer *absent* on its
own observation. The roster, the group key and every quorum are untouched. An
absent peer is still a member, and one frame from it makes it present again.
Nothing is agreed with anybody, so a partition cannot use this to shrink a
quorum on both sides.

**2. The network process owns it.** Every inbound frame passes one choke point
(`route_to_process` in C, `_msg_to_queue` in Python), so the network process
stamps the sender there. It also stamps every frame it sends. It evaluates both
clocks once a second and tells the other processes when a peer's state flips.

**3. An idle-only heartbeat.** There was no keepalive: once a cohort converges,
identity sends nothing on a timer, and the only steady traffic is continuous
probing, which can be turned off. Without a heartbeat an idle cohort would mark
everyone absent. So a node that has sent nothing to some member for
`AT_PRESENCE_HEARTBEAT_SEC` (default 30) sends one *presence* frame to the
group. A busy node never sends one.

**4. Invitations and probes skip an absent peer; the app is told.** Those are
the only consumers. Reputation consensus, attestations, checkpoints and group key
updates still go to every member, because a member that missed a key rotation
while quiet could not read the cohort when it came back.

## Protocol

**Thresholds** (wall-clock seconds, read at network start):

| Variable | Default | Meaning |
|---|---|---|
| `AT_PRESENCE_HEARTBEAT_SEC` | 30 | Send a presence frame after this long with nothing sent to some member |
| `AT_PRESENCE_ABSENT_SEC` | 90 | A peer heard from nothing for longer than this is absent |

A value that is not a positive number keeps the default. The absent threshold
is held at or above the heartbeat, since a peer cannot be absent before it was
due to speak. A peer new to the roster gets the full grace: silence is measured
from the later of when it joined and its last frame.

**Heard.** Any frame routed from a peer on the roster counts, whatever it
carries. A frame from a uuid that is not on the roster is ignored: it is not
evidence about a member.

**Sent.** A directed frame counts toward its one recipient. A group frame or a
broadcast counts toward everyone. Talking to one member says nothing to the
others, so a heartbeat is owed as soon as *any* member has had nothing from us
for the interval.

**The presence frame** is an encrypted group message with process `identity`,
function `presence` and an empty JSON object as its body. It is labelled for
identity, not network, so a node built before presence existed drops it as an
unknown identity verb. Labelled `network`, it would reach that node's own
outbound loop and be broadcast again. A node that knows the verb consumes it at
the choke point after stamping the sender, and never routes it. A node without
the group's private key cannot multicast and sends none. The heartbeat goes out
through the network process's own queue, so it takes the same gates as any other
group message. It is stamped when it is queued, so a slow drain cannot queue one
per second.

**Transitions** go to the sibling processes and the app:

| | C | Python |
|---|---|---|
| Message | `PEER_PRESENCE` (`peer_presence_msg_t`: uuid, `present`, `last_heard`) | `PeerPresence` (an `AppEvent`) |
| Sibling state | `protocol.peer_absent[]`, parallel to `peers[]` | `Protocol.absent_peers` (set of uuid strings) |
| Recipients | every sibling queue, and `AT_MAIN_QUEUE` | negotiation and main |
| App event | `AT_APP_EVENT_PEER_PRESENCE` (100), `at_app_presence_t` | `PeerPresence` on `external_feedback` |

`last_heard` is epoch seconds of the last frame, 0 for none. The app's roster
pull also answers one presence row per peer, so a lost transition is repaired by
the next pull. In C the network process already answered the pull (for RTT).
Python's main loop now forwards the pull to the network process as well as to
reputation.

**Skipping.** C negotiation skips `peer_absent[i]` in `_announce_task_locked`,
and hands the probe selector a snapshot of it as `bootstrap_worker_t.skip_peer`.
The selector never chooses a skipped peer. When every peer is skipped it returns
"nobody", and no probe is issued or counted. Without that skip the selector
would choose the absent peer, negotiation would refuse to send, the unsent probe
would not be counted, and the next interval would choose the same peer: nobody
would ever be probed.

Python negotiation drops absent peers from `start_task`'s participants. The
Python probe worker runs in its own process and does not read its queue, so it
cannot see presence. Its probe counts rise when the probe is queued, so an absent
target only loses its turn. A probe addressed to an absent peer is dropped
without a result, because a `no_peers` result is scored. An app task whose only
capable peers are absent still gets `no_peers`, so the app is not left waiting.

## What this does not do

- **No eviction and no quorum change.** A commit still needs a quorum sized from
  the whole roster. A cohort with dead members can still be unable to commit;
  that is ISSUES §2.52, a separate question.
- **No agreement.** Two nodes can disagree about whether a third is absent. That
  is fine for whom to invite, and it is why nothing that needs agreement reads it.
- **Not authenticated beyond the frame.** A C group frame is attributed to the
  uuid its envelope names. A peer that can forge a group frame can make itself
  look present, but it can already send everything else under that uuid.
- **No partition signal.** An island marks the far side absent and invites only
  its own members, which is the intended effect. It does not detect the split or
  recover from it.

## Verification

- C: `test/net_presence_test.c` (thresholds, strangers, heartbeat debt, roster
  churn, configuration, the sibling flag across a removal, and the app decode
  through the real IPC serializer); `send_retry_test`
  `test_a_presence_frame_is_heard_and_consumed`; `neg_send_keep_test`
  `test_an_absent_peer_is_not_invited`; `bootstrap_worker_test`
  `test_a_skipped_peer_is_never_probed_and_starves_nobody`; `app_node_test`'s
  forward list.
- Python: `tests/a_unit/test_peer_presence.py`, the same cases plus the network
  process's step (changes to negotiation and main, one heartbeat, none without
  the key) and the roster pull.
- Mutations that fail a test: no negotiation skip (C), `>=` for `>` on the
  absent threshold (C), and routing the presence frame instead of consuming it
  (Python).
- No conformance scenario: the tracker is driven by the clock, like the commit
  retry sweep.

---

*Next: [Extensions](extensions.md)*
