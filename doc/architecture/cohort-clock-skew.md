<!--
 Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
 Licensed under the Apache License, Version 2.0.
-->
[< Node Lifecycle](node-lifecycle.md)

# Cohort Clock Skew and Peer Reference Clocks

**Status (2026-08-12): Stage 0 BUILT in both runtimes. Stages 1–3 recorded and
deliberately not chosen.** This document is the design behind ISSUES.md §2.4.5.
It extends [Clock discipline](node-lifecycle.md#clock-discipline), which is
built: AT reads what a stock daemon achieved via `ntp_adjtime(modes = 0)` and
declines to run on a clock nothing is steering.

## The question

AT's own hierarchy could serve as a time source for its cohort. The objection
that peer sources cannot be arranged "at config time" is right about config time
only: chrony ≥ 4.2 has `sourcedir` plus `chronyc reload sources`, so on admission
a node could write a `.sources` file and reload, adding a peer reference clock at
**runtime** without restarting chrony. Symmetric `peer` mode would let a cohort
discipline itself with no external stratum at all — the interesting case for a
deployment with no route to a public pool.

## Why this is not merely an authentication problem

Peers as time sources is a trust dependency pointed straight at the thing every
other trust decision is ordered by. The obvious mitigations are authentication
(NTS or symmetric keys) and a bound on how far the cohort may drag a clock.
Both are necessary. Neither is sufficient:

- **Authentication does not help against a captured majority.** An authenticated
  captured peer is still captured. NTS proves *which* peer spoke, not that what
  it said about time is true.
- **A per-step bound does not stop slow drag.** An adversary who stays under the
  bound moves the clock indefinitely, one increment per poll.

The sharper problem is **circularity**. Reputation is ordered by timestamps. If
timestamps are disciplined by peers selected on reputation, then moving a node's
notion of "now" moves every comparison that would have detected the move —
including the reputation evidence about the peers doing the moving. The loop has
no outside term.

## The invariant

> Cohort time may never influence the clock that orders trust decisions, and
> time-source eligibility may never be earned.

The second clause is what breaks the circularity; bounds and authentication only
contain what gets through. Everything below follows from this.

## Stage 0 — measure cohort skew, steer nothing

The chosen scope, and what is built. It adds no trust surface at all: nothing
writes a clock, nothing contacts chrony, no node's time depends on another's.

### The measurement

Four timestamps per exchange, and NTP's arithmetic (RFC 5905 §8):

```
offset = ((t2 - t1) + (t3 - t4)) / 2      # peer clock minus ours
delay  = (t4 - t1) - (t3 - t2)            # round trip, peer's own work removed
```

`t1`/`t4` are the puller's (request sent, response received) and `t2`/`t3` the
responder's (request received, response sent). **`t2` and `t3` must be separate
readings**: their difference is the responder's processing time, and subtracting
it is what keeps a slow peer from being reported as a skewed one. That is not a
micro-optimisation here — Python's responder cannot answer inline at all, since
its identity process must ask the main loop for the console session, so the gap
is routinely milliseconds.

A negative delay is arithmetically impossible, so such a sample is marked
**unusable** — reported and logged, never aggregated. It means a clock stepped
mid-exchange or a peer stamped dishonestly.

The cohort estimator is the **median**, not the mean: a minority of peers
reporting wild timestamps must not drag the estimate, and a mean lets any single
sample do exactly that. Dispersion (peak spread) still reports that something is
wrong. Both runtimes average the two middle values on even counts, matching
Python's `statistics.median`, so they agree to the bit.

### The surface

| | Python | C |
|---|---|---|
| sample + aggregation | `network/clock.py`: `sample_from_round_trip`, `ClockSample`, `cohort_offset` | `utilities/clock.{c,h}`: `at_clock_sample_from_round_trip`, `at_clock_sample_t`, `at_clock_cohort_offset` |
| bound resolution | `resolve_max_cohort_skew` (via the shared `resolve_env_int`) | `at_clock_max_cohort_skew_ms` |
| per-peer store | `IdentityProcess._peer_clock_samples` | `id_state.peer_clock_samples` |
| read back | `cohort_clock_state()` | `identity_get_peer_clock_sample` |

`ClockState.detail` carries `cohort_offset` / `cohort_dispersion` /
`cohort_samples`, so the cohort view rides the existing `describe()` log line
wherever samples are available. Cohort keys never change `synced`: a cohort
cannot vouch for a clock nothing is steering, and the startup gate ignores skew
entirely.

**The bound is `AT_MAX_COHORT_SKEW_MS`, default 2000, advisory everywhere.**
Milliseconds as an integer, matching `AT_NET_RECV_POLL_MS` and keeping both
runtimes off the float-parsing path; refused-not-clamped on a bad value, like
the other tunables (§2.4.4). 2 s is the pairwise implication of the existing 1 s
per-node bound. Unlike `AT_REQUIRE_SYNCED_CLOCK` there is no enforcing mode:
Stage 0 exists to find out what real skew looks like, and a bound enforced
before it was measured could partition a healthy fleet. A peer beyond it is
**flagged** — the same move `NtpTimeSource.trustworthy` already makes for badly
synced peers.

### The carrier: the attest round trip

`attest_request`/`attest_response` carries the readings, as `clock_recv_at` and
`clock_sent_at` on the answer. It was already a periodic challenge/response whose
purpose is asking a peer to prove something about itself, so a clock reading fits
its existing meaning, and it is twinned in `id_proc.c`. PingAT was disqualified:
it is Python-only, and C answers that selector `{"error": "unsupported"}`
(§2.4.1). `t1` deliberately never goes on the wire — it is ours, and a peer
echoing it back could lie about it.

A peer that omits the readings (an older build) simply yields no sample. Absence
is not an error, and the attestation completes untouched.

### What Stage 0 must not do

It must not apply the estimated offset to anything. An offset that reaches
`system.now()` is precisely the defect for which the old NTP module was retired:
the correction lived in a module global that only `system.now()` consulted, so
AT's notion of time diverged from its own host's, with no clock discipline behind
it. The offset here is *evidence about a peer*, never a correction to self.

### Scope of the surfacing

The samples live in the process where the attest round trips complete — the
identity subprocess — and a forked sibling holds its own copy. `cohort_clock_state()`
reports that process's view. The measurement also rides the existing local
attestation report to the main loop (`clock_offset` / `clock_delay` /
`clock_usable`), which is where a consumer reads it; nothing was added to
`NtpTimeSource`, because it runs elsewhere and cannot see this store.

### Pinning

Unit tests both sides (`TestClockSampleMath` / `TestCohortAggregation` /
`TestCohortStaysAdvisory` in `test_network_clock.py`; the `Clock` suite in
`clock_test.c`), the round trip in `test_operator_attestation.py`, and two
conformance scenarios — `cohort-clock-skew-peer-ahead` and `-peer-behind` — that
pin the derivation and the **sign convention** across languages, since a sign
error is the classic way two implementations of one formula diverge while each
looks right alone. Per-participant clocks come from a new `clocks` fixture;
`operator_session.clock` pins one clock for everyone and cannot express
disagreement.

Both scenarios read what the production handler recorded. This matters:
`attested_now` and `attest_accepted` are computed by the harness itself, and they
stayed green when a signature change left `handle_attest_response` raising
half-way through — the corpus could not see it. Assertions that read production
state do not have that blind spot.

## Stages 1–3 — recorded, not chosen

Kept here so the reasoning survives, and so the preconditions are explicit if
the question is reopened.

### Stage 1: a proposal file plus a host-side applier

AT would write `<var>/at/time/proposed.sources` into an AT-owned directory
(`AT_TIME_SOURCEDIR`). A separate host-side applier — a systemd path unit, or a
sidecar with chrony's `sourcedir` mounted — would validate it, copy it in, and
run `chronyc reload sources`.

The indirection is the design, not overhead. It preserves the boundary the clock
work already established: AT reads clock state and stock tooling does the
steering. AT still needs no `CAP_SYS_TIME` and no chrony socket; whether a
container may steer its host's clock stays the host operator's decision; and an
applier small enough to audit is what enforces the policy AT cannot be trusted
to enforce on itself.

### Stage 2: eligibility, authentication, bounds

- **Eligibility is provisioned, not earned.** Only a peer holding a
  `time_reference` capability and a named ZTA anchor may be proposed, optionally
  narrowed to operator-attended nodes. Reputation may **remove** a time source
  (tier-down revokes it) but never add one. This asymmetry is the invariant's
  second clause in practice.
- **Authentication.** NTS fits the existing credential chain (an AT anchor as
  `ntstrustedcerts`) and is the better long-term answer. Symmetric keys
  (`keyfile` plus `server … key <id>`) are easier to provision at runtime, but
  group-key rotation is deliberately deferred, so a static key is a long-lived
  cohort-wide shared secret — a fallback for constrained C nodes, not the
  default.
- **Bounded drag, two-sided.** chrony side: `maxchange … panic`, no `makestep`
  for cohort sources, `minsources ≥ 2`, and a worse stratum and poll than any
  external pool so a reachable pool always wins. AT side: a **cumulative** bound
  since boot, not only per-step — the per-step bound alone is what slow drag
  walks through.

### Stage 3: symmetric `peer` mode

The no-external-stratum case, and only after 0–2. Its failure mode must be
designed around rather than discovered: a cohort with no external reference can
agree *precisely* on a *wrong* absolute time. That is acceptable for ordering and
fatal for credential validity windows and external log correlation. Certificate
lifetime checks would need to keep reading a source the cohort cannot influence,
or enter an explicit "absolute time unverified" state — never validate silently
against consensus time.

## Anti-patterns

Three approaches that look simpler and give away the property the design exists
to keep:

1. **Calling `chronyc` from inside the container.** Requires the chrony socket
   mounted, which grants full control over the host's sources — far more than
   adding one peer.
2. **Writing directly into chrony's `sourcedir` from AT.** The same transfer of
   authority, and it makes AT the enforcer of its own bounds.
3. **An AT-internal offset applied in `system.now()`.** The retired NTP module's
   defect, restated. See [Clock discipline](node-lifecycle.md#clock-discipline).
