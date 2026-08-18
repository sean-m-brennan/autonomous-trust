# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************

"""Read the state of the system's clock discipline. Never implement it.

AT used to carry its own NTP client and apply the correction to a userspace
offset that only ``system.now()`` added -- so AT's notion of time diverged from
its own host's, with no clock discipline (one raw sample per poll, no filter,
dispersion check, step/slew policy or sanity bound) and no authentication. Time
discipline is a solved problem owned by chrony / ntpd / timesyncd; this module
only asks the kernel what those daemons have achieved, so AT can decline to run
on a clock it cannot trust.

The primary query is ``ntp_adjtime(modes=0)``, which is:

- **unprivileged** -- a read; setting the clock needs CAP_SYS_TIME
- **dependency-free** -- no chrony socket, no client binary, no network
- **honest inside a container** -- CLOCK_REALTIME is not namespaced (a time
  namespace can offset only CLOCK_MONOTONIC and CLOCK_BOOTTIME), so a container
  shares its host's wall clock and reads the host's discipline state. This is
  also why a per-container ``chronyd`` is the wrong shape: it could not
  discipline anything without CAP_SYS_TIME, and would fight the host if given it.

``chrony_tracking()`` adds richer detail when the chronyc client happens to be
reachable, and is never required -- an image without it still gates correctly.

The C side mirrors this in ``utilities/clock.{c,h}`` using the same syscall, so
both implementations agree on what "synced" means.
"""

import logging
import math
import os
import shutil
import statistics
import subprocess
from ctypes import (CDLL, Structure, byref, c_int, c_long, get_errno, util)
from dataclasses import dataclass, field
from datetime import timedelta

from .. import system

logger = logging.getLogger(__name__)

# From <sys/timex.h>. Values are ABI, not preference.
STA_UNSYNC = 0x0040      # clock unsynchronized: no daemon is disciplining it
STA_CLOCKERR = 0x1000    # clock hardware fault
TIME_ERROR = 5           # ntp_adjtime() return: the clock is not synchronized

#: Refuse a clock whose kernel-estimated maximum error exceeds this. NTP's own
#: notion of an unusable distance is 1 s (RFC 5905 MAXDIST is 1.5 s); an
#: undisciplined Linux kernel reports 16 s, so this cleanly separates "synced but
#: imprecise" from "nobody is steering this clock".
DEFAULT_MAX_ERROR = timedelta(seconds=1)

#: Operator switch. Unset/absent means advisory: warn once and proceed, which is
#: what a developer machine or a test run needs. AT container images set this to
#: 1 so a production node refuses to join a cohort on an undisciplined clock.
REQUIRE_ENV = 'AT_REQUIRE_SYNCED_CLOCK'


class _Timex(Structure):
    """Linux ``struct timex``. Field order and widths are the kernel ABI."""
    _fields_ = [
        ('modes', c_int), ('offset', c_long), ('freq', c_long),
        ('maxerror', c_long), ('esterror', c_long), ('status', c_int),
        ('constant', c_long), ('precision', c_long), ('tolerance', c_long),
        ('time_sec', c_long), ('time_usec', c_long), ('tick', c_long),
        ('ppsfreq', c_long), ('jitter', c_long), ('shift', c_int),
        ('stabil', c_long), ('jitcnt', c_long), ('calcnt', c_long),
        ('errcnt', c_long), ('stbcnt', c_long), ('tai', c_int),
        ('_pad', c_int * 11),
    ]


@dataclass(frozen=True)
class ClockState:
    """What the kernel says about its own time discipline."""
    synced: bool
    max_error: timedelta
    est_error: timedelta
    status: int
    source: str                      # which query produced this
    detail: dict = field(default_factory=dict)   # chrony extras, when available

    @property
    def hardware_fault(self) -> bool:
        return bool(self.status & STA_CLOCKERR)

    def describe(self) -> str:
        bits = ['synced' if self.synced else 'UNSYNCED',
                'max_error=%.3fs' % self.max_error.total_seconds(),
                'status=0x%04x' % self.status,
                'via %s' % self.source]
        if self.hardware_fault:
            bits.insert(1, 'CLOCK HARDWARE FAULT')
        for k, v in sorted(self.detail.items()):
            bits.append('%s=%s' % (k, v))
        return ', '.join(bits)


def _libc():
    return CDLL(util.find_library('c'), use_errno=True)


def kernel_clock_state() -> ClockState:
    """Query the kernel's clock discipline. Never raises.

    An unavailable syscall (a non-Linux host, a seccomp filter) reports
    ``synced=False`` with ``source='unavailable'`` rather than pretending the
    clock is fine -- a check that fails open would be worse than no check.
    """
    try:
        t = _Timex()
        t.modes = 0                       # read-only query
        rc = _libc().ntp_adjtime(byref(t))
    except (OSError, AttributeError) as err:
        logger.debug('ntp_adjtime unavailable: %s', err)
        return ClockState(synced=False, max_error=timedelta.max,
                          est_error=timedelta.max, status=0,
                          source='unavailable')
    if rc < 0:
        return ClockState(synced=False, max_error=timedelta.max,
                          est_error=timedelta.max, status=0,
                          source='ntp_adjtime(errno=%s)' % os.strerror(get_errno()))
    synced = rc != TIME_ERROR and not (t.status & STA_UNSYNC)
    return ClockState(synced=synced,
                      max_error=timedelta(microseconds=t.maxerror),
                      est_error=timedelta(microseconds=t.esterror),
                      status=t.status,
                      source='ntp_adjtime')


def chrony_tracking() -> dict:
    """Optional richer detail from the stock daemon. ``{}`` when unavailable.

    Deliberately best-effort: the gate must not depend on the chronyc binary
    being installed or the daemon's socket being reachable from a container.
    """
    exe = shutil.which('chronyc')
    if exe is None:
        return {}
    try:
        out = subprocess.run([exe, '-c', 'tracking'], capture_output=True,
                             text=True, timeout=2)
    except (OSError, subprocess.SubprocessError) as err:
        logger.debug('chronyc tracking failed: %s', err)
        return {}
    if out.returncode != 0 or not out.stdout.strip():
        return {}
    # `chronyc -c tracking` is comma-separated: refid,ip,stratum,ref_time,
    # system_time,last_offset,rms_offset,freq,resid_freq,skew,root_delay,
    # root_dispersion,update_interval,leap
    fields = out.stdout.strip().split(',')
    if len(fields) < 14:
        return {}
    detail = {'chrony_stratum': fields[2], 'chrony_leap': fields[13]}
    for key, idx in (('chrony_root_dispersion', 11), ('chrony_last_offset', 5)):
        try:
            detail[key] = float(fields[idx])
        except (TypeError, ValueError):
            pass
    return detail


def clock_state(with_chrony: bool = True, samples=None) -> ClockState:
    """``kernel_clock_state()`` plus chrony detail when it costs nothing.

    ``samples`` are :class:`ClockSample` values from peers, when the caller has
    any (see :func:`cohort_offset`). They add cohort keys to ``detail`` so the
    cohort view rides the existing ``describe()`` log line. Local discipline and
    cohort agreement stay separate facts: cohort keys never change ``synced``,
    because a cohort cannot vouch for a clock nothing is steering.
    """
    state = kernel_clock_state()
    detail = chrony_tracking() if with_chrony else {}
    cohort = cohort_offset(samples)
    if not detail and not cohort:
        return state
    merged = dict(detail)
    merged.update(cohort)
    source = state.source + ('+chronyc' if detail else '')
    return ClockState(synced=state.synced, max_error=state.max_error,
                      est_error=state.est_error, status=state.status,
                      source=source, detail=merged)


def required() -> bool:
    """Whether an unsynced clock is fatal here. See ``REQUIRE_ENV``."""
    return os.environ.get(REQUIRE_ENV, '').strip().lower() in ('1', 'true', 'yes', 'on')


class UnsyncedClockError(RuntimeError):
    """Raised when a node is required to have a disciplined clock and does not."""


def require_synced_clock(log: logging.Logger = None,
                         max_error: timedelta = DEFAULT_MAX_ERROR) -> ClockState:
    """Gate startup on the host's clock discipline.

    Enforcing when ``AT_REQUIRE_SYNCED_CLOCK`` is set (AT container images set
    it), advisory otherwise. Either way it logs which mode applied and what it
    saw, so a start that proceeded is never ambiguous about whether the clock was
    actually checked.

    :raises UnsyncedClockError: only when enforcing.
    """
    log = log or logger
    state = clock_state()
    enforcing = required()
    mode = 'enforcing' if enforcing else 'advisory'
    ok = state.synced and state.max_error <= max_error

    if ok:
        log.info('clock: %s [%s, requirement met]', state.describe(), mode)
        return state

    why = ('no NTP daemon is disciplining this clock'
           if not state.synced else
           'kernel max error %.3fs exceeds the %.3fs bound'
           % (state.max_error.total_seconds(), max_error.total_seconds()))
    msg = ('clock: %s -- %s. Run a stock NTP daemon (chrony, ntpd or '
           'systemd-timesyncd) on the HOST; a container cannot discipline '
           'CLOCK_REALTIME itself.' % (state.describe(), why))
    if enforcing:
        log.critical('%s [%s: refusing to start]', msg, mode)
        raise UnsyncedClockError(msg)
    log.warning('%s [%s: continuing; set %s=1 to make this fatal]',
                msg, mode, REQUIRE_ENV)
    return state


# ---------------------------------------------------------------------------
# Cohort skew: how far peers' clocks sit from ours.
#
# This measures and reports. It steers nothing. AT does not become a time
# source for its cohort, and an offset measured here is never applied to any
# clock and never reaches ``system.now()`` -- that last part is exactly the
# defect for which the old NTP module was retired, and re-creating it would
# make AT's notion of time diverge from its own host's again.
#
# What it is for: a peer whose clock disagrees with ours cannot have its
# timestamps compared against ours, so a node that can SEE the disagreement can
# decline to order events against that peer instead of trusting the stamp
# silently. See doc/architecture/cohort-clock-skew.md.
# ---------------------------------------------------------------------------

#: Bound past which a peer's timestamps stop being usable for ordering.
#:
#: 2 s is the pairwise implication of the existing per-node bound: if each of
#: two nodes is within ``DEFAULT_MAX_ERROR`` (1 s) of true time, the pair is
#: within 2 s of each other. So a peer beyond this is telling us something the
#: local gate would already have refused of itself.
DEFAULT_MAX_COHORT_SKEW_MS = 2000
MIN_COHORT_SKEW_MS = 1
MAX_COHORT_SKEW_MS = 86400000    # a day; past this the bound means nothing

#: Operator switch, in milliseconds to match ``AT_NET_RECV_POLL_MS`` and to keep
#: both runtimes off float parsing on the knob path.
SKEW_ENV = 'AT_MAX_COHORT_SKEW_MS'


def resolve_max_cohort_skew(log: logging.Logger = None) -> tuple[timedelta, str]:
    """Resolve the skew bound: env, then compile-time default.

    Same two layers, refusal rules and bounds as the network tunables (doc/architecture/networking.md),
    via the shared ``resolve_env_int``, so C's resolver can mirror it exactly.
    """
    ms, source = system.resolve_env_int(SKEW_ENV, DEFAULT_MAX_COHORT_SKEW_MS,
                                        MIN_COHORT_SKEW_MS, MAX_COHORT_SKEW_MS,
                                        logger=log or logger)
    return timedelta(milliseconds=ms), source


@dataclass(frozen=True)
class ClockSample:
    """One peer's clock, measured across one request/response round trip.

    ``offset`` is the peer's clock minus ours: positive means the peer is ahead.
    ``delay`` is the round trip with the peer's own processing time removed, so
    a peer that took a second to answer does not read as a second of skew.
    """
    peer: str
    offset: timedelta
    delay: timedelta

    @property
    def usable(self) -> bool:
        """A negative delay is arithmetically impossible, so the timestamps are
        wrong (a clock stepped mid-exchange, or a peer stamping dishonestly).
        Such a sample is reported, not silently dropped, but must not be
        aggregated."""
        return self.delay >= timedelta(0)

    def exceeds(self, bound: timedelta) -> bool:
        return abs(self.offset) > bound

    def describe(self) -> str:
        return ('peer=%s offset=%+.3fs delay=%.3fs%s'
                % (self.peer, self.offset.total_seconds(),
                   self.delay.total_seconds(),
                   '' if self.usable else ' UNUSABLE(negative delay)'))


def sample_from_round_trip(peer: str, t1: float, t2: float, t3: float,
                           t4: float) -> ClockSample:
    """Build a sample from the four timestamps of one round trip.

    ``t1``/``t4`` are ours (request sent, response received) and ``t2``/``t3``
    are the peer's (request received, response sent), all wall-clock epoch
    seconds. The arithmetic is NTP's (RFC 5905 §8), which is why ``t2`` and
    ``t3`` must be separate readings rather than one: their difference is the
    peer's processing time, and subtracting it is what keeps a slow responder
    from being reported as a skewed one. That matters here because the Python
    responder cannot answer inline at all -- it defers to its main loop -- so
    the gap is routinely milliseconds, not microseconds.

    Returns ``None`` if any timestamp is missing or not a finite number; a
    round trip we cannot measure yields no sample rather than a wrong one.
    """
    try:
        t1, t2, t3, t4 = (float(t1), float(t2), float(t3), float(t4))
    except (TypeError, ValueError):
        return None
    if not all(math.isfinite(t) for t in (t1, t2, t3, t4)):
        return None
    offset = ((t2 - t1) + (t3 - t4)) / 2.0
    delay = (t4 - t1) - (t3 - t2)
    return ClockSample(peer=str(peer), offset=timedelta(seconds=offset),
                       delay=timedelta(seconds=delay))


def cohort_offset(samples) -> dict:
    """Aggregate per-peer samples into the cohort view, as ``detail`` keys.

    The estimator is the **median**, not the mean: a minority of peers reporting
    wild timestamps -- broken, or lying -- must not be able to drag the cohort
    estimate, and a mean lets any single sample do exactly that. Dispersion is
    the peak spread across usable samples, which is the honest summary of "how
    much do the clocks here actually disagree".

    ``{}`` when there is nothing usable to report, so callers merge
    unconditionally and an idle node simply says nothing about the cohort.
    """
    usable = [s for s in (samples or []) if s is not None and s.usable]
    if not usable:
        return {}
    offsets = sorted(s.offset.total_seconds() for s in usable)
    return {'cohort_offset': statistics.median(offsets),
            'cohort_dispersion': offsets[-1] - offsets[0],
            'cohort_samples': len(offsets)}
