# Persistent Cohort State

How a node's identity, peer table, and reputation survive a restart,
and how the DoD mission demo pre-seeds the squad / microdrone / jet
cohort with mutual trust so they boot in a high-trust network.

**What "warm-start" means.** A warm-started peer is one whose reputation
is *a memory of its prior AT-bounded activity that becomes operational
again at machine start-up*: the score it already earned through observed
AT-mediated transactions, persisted here and reloaded into the live
reputation store on restart, rather than re-earned from neutral on every
reboot. It is not a trust grant and not an allow-list; the reloaded score
is bound to the same cryptographic identity and stays under continuous
re-evaluation (any transaction can move it; the slashing fast-path can
floor it). What keeps the shortcut honest is that **re-loaded trust is
stale trust, and stale trust decays** toward almost-neutral with time out
of contact, see §3.1 and [Reputation › Staleness decay](reputation.md).

## 1. What gets persisted

Every AT node already writes five files under `$AUTONOMOUS_TRUST_ROOT/etc/at/`
on each relevant state change:

| File | Owning process | When it's written | What it carries |
|---|---|---|---|
| `identity.cfg.json` | `IdentityProcess` | First boot only (preserved on restart) | Self UUID + Ed25519 signing keypair + X25519 encryption keypair + address |
| `group.cfg.json` | `IdentityProcess._record_group` | On group adoption / merge | Group UUID + group key + per-peer address map + identity-history DAG |
| `peers.cfg.json` | `IdentityProcess._record_peers` | On peer-table mutation | Peer hierarchy (3 levels) + valuation tiers (10 levels), each holding `Identity` objects |
| `peer-capabilities.cfg.json` | `IdentityProcess._record_peers` | On capability announcement | `{capability_name: [peer_uuids]}` |
| `reputation.cfg.json` | `ReputationProcess._persist_reputations` | After every `_compute_reputation()` call | `{peer_uuid: float}` |

JSON is pretty-printed (`indent=2`): diff-friendly, hand-editable for
debugging.

## 2. The >0.5 reputation gate

`ReputationProcess` filters `reputation.cfg.json` to peers strictly
above `REPUTATION_PERSIST_THRESHOLD = 0.5` (defined in
[`repprocess.py`](../../src/autonomous-trust/autonomous_trust/core/_python/reputation/repprocess.py)).
Self is always included regardless of score.

`IdentityProcess._remember_activity` mirrors that gate on
`peers.cfg.json` and `peer-capabilities.cfg.json` via
`PERSIST_TIER_FLOOR = 1` (defined in
[`idprocess.py`](../../src/autonomous-trust/autonomous_trust/core/_python/identity/idprocess.py)).
Tier 1 corresponds to score ≥ 0.50 per `ReputationProcess.TIER_FLOORS`,
so the on-disk snapshots agree on which peers count as "trusted".

The in-memory peer table is *not* filtered: only the saved snapshot
is. A peer that drifts below 0.5 mid-session is still tracked +
scored in the live process; it just doesn't survive a restart.

## 3. Shutdown flush

The previous design relied entirely on event-driven saves: reputation
flushed after each transaction, peers after each mutation. That covers
crash-safety for *committed* state but loses anything in flight when
the process exits.

`automate.py:run_forever` now installs a `SIGTERM` handler that pushes
`Process.sig_quit` to every subprocess's signal queue. Each subprocess
exits its `while self.keep_running(signal):` loop cleanly, then runs a
tail-of-loop persistence:

- `ReputationProcess.process` → final `_persist_reputations()` flush
- `IdentityProcess.process` → final `_record_group()` + `_record_peers()`

`SIGINT` (Ctrl-C) was already handled via `KeyboardInterrupt` in the
autonomous loop; SIGTERM is the new path: `kubectl delete pod`,
`docker stop`, `tilt down`, supervisor restart all go through it.

### 3.1 Staleness: warm-start memory fades

A reloaded reputation is a *memory*, so it is not trusted indefinitely.
`ReputationProcess` relaxes an idle peer's operational reputation toward
*almost-but-not-quite neutral* (`0.51`, just above `0.50`) as a function
of time since the last transaction with that peer: eroding earned trust
above the asymptote while leaving a distrusted/corrupt node's low score
untouched (decay is asymmetric: absence never rehabilitates a bad actor;
slashed peers and self are never decayed). The time the peer spent out of
contact **while the node was down counts**: `_seed_idle_from_snapshot`
reads `reputation.cfg.json`'s mtime as the instant of last activity and
applies the offline-gap decay at start-up, so a long-dormant cohort warm-
starts with faded (not stale-inflated) trust. A peer's *elevated* tier
(2-4) thus lapses over a long absence and must be re-earned on contact,
while tier 1 (presence) persists. Tunable via `REPUTATION_DECAY_*` in
`repprocess.py`. Local-view only (wall-clock driven, never on the wire),
so the conformance corpus is unaffected. Full rationale in
[Reputation › Staleness decay](reputation.md).

**Planned hardening: floor, not full restoration (design, not yet
implemented).** Decay covers *time out of contact* but not the orthogonal
*"this session hasn't re-validated you yet"* axis: a recently-active peer
with little decay is restored to its full earned tier the instant it is
re-admitted. Because an *authenticated-but-compromised* asset passes
admission by definition and a short-lived asset gives behavioral
re-evaluation no time to bite, warm-start should restore only **low-tier**
(presence/communication) standing instantly and require **fresh in-session
evidence** before re-granting **elevated/safety-critical** tiers. See
[Reputation › Planned hardening](reputation.md) for the implementation
sketch; pairs with the human-on-the-loop safety carve-out.

## 4. The DoD demo's warm-start cohort

The mission scenario has three groups of peers that ought to know each
other before the first tick:

| Group | Why pre-trusted |
|---|---|
| `squad-*` (captain + warrant + intel + ops + ...) | A real ODA team; they trained together, they have shared keys before the mission |
| `microdrone-*` | Squad-launched assets; same operator, same chain of custody |
| `jet-*` | Friendly air support; cohort membership pre-arranged before the strike window |

Everyone else cold-bootstraps:

| Group | Why kept cold |
|---|---|
| `rq-86-*` (recon drones) | Overhead asset that joins the cohort during the mission |
| `mq-800-*` (armed drone) | **Compromised**; the demo's headline contradiction beat depends on it joining the network and getting caught lying. Pre-trusting it would defeat the storyline. |
| `ground-sensor-*` | Two are hacked (forged identities); the Sybil-rejection beat needs them to handshake so the welcoming committee can reject them. |
| `command-node` | Remote node, joins via partition-recovery flow |

### 4.1 Generating the seed

`tools/seed_dod_cohort.py` writes each pre-trusted peer's persistent
dir before the demo brings any containers up. For every peer in
{`squad-*`, `microdrone-*`, `jet-*`}:

1. Generate (or reload: idempotent unless `--force`) a fresh Ed25519
   + X25519 keypair, write `identity.cfg.json`.
2. Construct one shared `Group` with all seeded peers in its
   address map; write its `group.cfg.json` into every seeded peer's dir
   (so each peer agrees on group UUID + group key).
3. Write `peers.cfg.json` containing the OTHER seeded peers'
   Identities, each `_tier`-bumped to 2 ("affirmed").
4. Write `reputation.cfg.json` with `{other_uuid: 0.7}` for each other
   seeded peer.
5. Write `peer-capabilities.cfg.json` advertising the canonical
   bootstrap capability list per peer.

```bash
# Default: writes to .demo-state/dod-mission/
python -m tools.seed_dod_cohort

# Custom out + larger swarm
python -m tools.seed_dod_cohort --out /tmp/seed --swarm-size 24

# Blow away existing keys + regenerate
python -m tools.seed_dod_cohort --force
```

Address-on-disk is the peer name as a placeholder; at runtime the
network process announces with the actual interface IP and the
receivers' peer tables update accordingly.

### 4.2 Wiring the seed into the containers

| Backend | How the seed reaches the container |
|---|---|
| `docker compose` (`run-demo.sh --variant=dod-mission --compose`) | `generate_compose.py` bind-mounts `.demo-state/dod-mission/<peer>/` → `/app/config/<peer>/` for every peer; the seed populates the host side before `docker compose up` |
| `kubectl` / Tilt (`--variant=dod-mission`, default) | `generate_k8s.py --seed-root .demo-state/dod-mission` emits one `at-seed-<peer>` ConfigMap per seeded peer; the per-peer InitContainer copies the CM contents into the emptyDir at `/app/config/<peer>/etc/at/` on first start. Non-seeded peers reference their CM with `optional: true`, so missing CMs are tolerated. |

### 4.3 Disabling the seed

Set `AT_PRESEED=0` before `run-demo.sh` to skip the seed step entirely:
useful for testing the bare handshake / Sybil-rejection paths without
the warm start. Set `AT_PRESEED_FORCE=1` to regenerate identities even
on a re-run (default is to preserve so warm restarts stay consistent).

## 5. Persistence across pod recreation

**v1: pod-lifetime only on k8s.** The k8s manifests use `emptyDir` for
the per-peer state volume, which survives container restart within a
pod but is wiped on pod recreation. For real cross-recreation
persistence, swap `emptyDir: {}` for a PVC reference in the volume
spec (`generate_k8s.py`). The compose path bind-mounts a host
directory so it survives `docker compose down/up`.

The current scope is the user's requested behaviour: "if a node
reboots/restarts everything starts from scratch" → no longer true
within a pod's lifetime. PVCs are the upgrade path for cluster-wide
persistence.

## 6. Reproducing locally

```bash
# 1. Seed
python -m tools.seed_dod_cohort --out .demo-state/dod-mission

# 2. Inspect a peer's state
ls .demo-state/dod-mission/squad-captain/etc/at/
cat .demo-state/dod-mission/squad-captain/etc/at/reputation.cfg.json

# 3. Run the unit tests against the seed
PYTHONPATH=src/autonomous-trust:src/autonomous-trust-services:src/autonomous-trust-inspector:src/autonomous-trust-evaluation:src/autonomous-trust-simulator:. \
  src/autonomous-trust/.venv/bin/python -m pytest \
    examples/dod_mission/test_persistent_cohort.py -v

# 4. Bring the demo up: peers warm-start from the seed.
scripts/run-demo.sh --variant=dod-mission --tilt
```

## 7. Code map

| What | Where |
|---|---|
| Threshold gate (reputation) | [`repprocess.py:_persist_reputations`](../../src/autonomous-trust/autonomous_trust/core/_python/reputation/repprocess.py) |
| Staleness decay (idle + offline-gap) | [`repprocess.py`](../../src/autonomous-trust/autonomous_trust/core/_python/reputation/repprocess.py): `_decay_reputations`, `_decayed_score`, `_seed_idle_from_snapshot`, `_note_interaction`, `REPUTATION_DECAY_*` |
| Threshold gate (peers + caps) | [`idprocess.py:_trusted_uuids_for_persist`](../../src/autonomous-trust/autonomous_trust/core/_python/identity/idprocess.py) |
| `filtered_for_persist` impls | [`reputation.py`](../../src/autonomous-trust/autonomous_trust/core/_python/reputation/reputation.py), [`peers.py`](../../src/autonomous-trust/autonomous_trust/core/_python/identity/peers.py), [`capabilities.py`](../../src/autonomous-trust/autonomous_trust/core/_python/capabilities.py) |
| Shutdown flush | [`automate.py:run_forever`](../../src/autonomous-trust/autonomous_trust/core/_python/automate.py) (SIGTERM handler) + end of each subprocess's `process()` |
| Per-peer volume + InitContainer wiring | [`generate_compose.py`](../../examples/dod_mission/deploy/generate_compose.py), [`generate_k8s.py`](../../examples/dod_mission/deploy/generate_k8s.py) |
| Seed generator | [`tools/seed_dod_cohort.py`](../../tools/seed_dod_cohort.py) |
| Tests | [`examples/dod_mission/test_persistent_cohort.py`](../../examples/dod_mission/test_persistent_cohort.py) |
| Launcher integration | [`scripts/run-demo.sh`](../../scripts/run-demo.sh) (dod-mission variant), [`tilt/dod_mission.tiltfile`](../../tilt/dod_mission.tiltfile) |
