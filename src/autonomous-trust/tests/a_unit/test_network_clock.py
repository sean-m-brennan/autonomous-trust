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
"""Tests for reading stock NTP's state -- and for the startup gate over it."""

import logging
import os
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

from autonomous_trust.core._python.network import clock


def _timex(status=0, maxerror=0, esterror=0):
    """A real ``struct timex`` pre-filled as the kernel would leave it.

    It has to be the genuine ctypes instance -- ``byref()`` rejects a stand-in,
    which is exactly the kind of layout mistake these tests exist to catch.
    """
    t = clock._Timex()
    t.status, t.maxerror, t.esterror = status, maxerror, esterror
    return t


def _state(synced=True, max_error_sec=0.01, status=0, source='ntp_adjtime',
           detail=None):
    return clock.ClockState(synced=synced,
                            max_error=timedelta(seconds=max_error_sec),
                            est_error=timedelta(seconds=max_error_sec),
                            status=status, source=source,
                            detail=detail or {})


class TestKernelClockState:
    def test_reads_the_real_kernel(self):
        # No mocking: the syscall must actually answer on this host, because
        # that is the whole reason it was chosen over a chrony socket.
        state = clock.kernel_clock_state()
        assert state.source.startswith('ntp_adjtime') or state.source == 'unavailable'
        assert isinstance(state.synced, bool)
        assert isinstance(state.max_error, timedelta)

    def test_unsynced_status_bit_means_unsynced(self):
        t = _timex(status=clock.STA_UNSYNC, maxerror=16_000_000,
                   esterror=16_000_000)
        with patch.object(clock, '_Timex', return_value=t), \
                patch.object(clock, '_libc') as lib:
            lib.return_value.ntp_adjtime.return_value = 0   # TIME_OK return...
            state = clock.kernel_clock_state()
        # ...but STA_UNSYNC is set, so a return code alone must not clear it.
        assert state.synced is False
        assert state.max_error == timedelta(seconds=16)

    def test_time_error_return_means_unsynced(self):
        t = _timex(status=0, maxerror=500, esterror=500)   # no bits set...
        with patch.object(clock, '_Timex', return_value=t), \
                patch.object(clock, '_libc') as lib:
            lib.return_value.ntp_adjtime.return_value = clock.TIME_ERROR
            state = clock.kernel_clock_state()
        # ...and TIME_ERROR alone must still be read as unsynced.
        assert state.synced is False

    def test_synced_when_no_error_bit_and_ok_return(self):
        t = _timex(status=0, maxerror=12_000, esterror=8_000)
        with patch.object(clock, '_Timex', return_value=t), \
                patch.object(clock, '_libc') as lib:
            lib.return_value.ntp_adjtime.return_value = 0
            state = clock.kernel_clock_state()
        assert state.synced is True
        assert state.max_error == timedelta(microseconds=12_000)

    def test_missing_syscall_fails_closed(self):
        with patch.object(clock, '_libc', side_effect=OSError('no libc')):
            state = clock.kernel_clock_state()
        assert state.synced is False           # never fail open
        assert state.source == 'unavailable'

    def test_negative_return_fails_closed_with_errno(self):
        with patch.object(clock, '_Timex', return_value=_timex()), \
                patch.object(clock, '_libc') as lib:
            lib.return_value.ntp_adjtime.return_value = -1
            state = clock.kernel_clock_state()
        assert state.synced is False
        assert 'errno' in state.source

    def test_hardware_fault_is_reported(self):
        assert _state(status=clock.STA_CLOCKERR).hardware_fault is True
        assert 'CLOCK HARDWARE FAULT' in _state(status=clock.STA_CLOCKERR).describe()


class TestChronyTracking:
    def test_absent_client_is_empty_not_an_error(self):
        with patch.object(clock.shutil, 'which', return_value=None):
            assert clock.chrony_tracking() == {}

    def test_parses_csv_tracking(self):
        csv = ('C0A80001,192.168.0.1,3,1750000000.0,0.000001,-0.000002,'
               '0.000003,1.5,0.1,0.2,0.004,0.008,64,Normal\n')

        class _Out:
            returncode = 0
            stdout = csv

        with patch.object(clock.shutil, 'which', return_value='/usr/bin/chronyc'), \
                patch.object(clock.subprocess, 'run', return_value=_Out()):
            detail = clock.chrony_tracking()
        assert detail['chrony_stratum'] == '3'
        assert detail['chrony_leap'] == 'Normal'
        assert detail['chrony_root_dispersion'] == pytest.approx(0.008)

    def test_failed_client_is_empty(self):
        with patch.object(clock.shutil, 'which', return_value='/usr/bin/chronyc'), \
                patch.object(clock.subprocess, 'run', side_effect=OSError('boom')):
            assert clock.chrony_tracking() == {}

    def test_short_output_is_rejected_not_indexed(self):
        class _Out:
            returncode = 0
            stdout = 'a,b,c\n'

        with patch.object(clock.shutil, 'which', return_value='/usr/bin/chronyc'), \
                patch.object(clock.subprocess, 'run', return_value=_Out()):
            assert clock.chrony_tracking() == {}

    def test_clock_state_merges_detail_when_present(self):
        with patch.object(clock, 'kernel_clock_state', return_value=_state()), \
                patch.object(clock, 'chrony_tracking',
                             return_value={'chrony_stratum': '2'}):
            state = clock.clock_state()
        assert state.detail == {'chrony_stratum': '2'}
        assert state.source == 'ntp_adjtime+chronyc'

    def test_clock_state_survives_without_the_client(self):
        # Negative control 6, as a test: no chronyc, gate still works.
        with patch.object(clock, 'kernel_clock_state', return_value=_state()), \
                patch.object(clock.shutil, 'which', return_value=None):
            state = clock.clock_state()
        assert state.source == 'ntp_adjtime'
        assert state.synced is True


class TestRequireSyncedClock:
    def _log(self):
        return logging.getLogger('test.clock.gate')

    def test_synced_clock_passes_either_mode(self):
        with patch.object(clock, 'clock_state', return_value=_state()):
            for env in ('1', ''):
                with patch.dict(os.environ, {clock.REQUIRE_ENV: env}):
                    assert clock.require_synced_clock(self._log()).synced is True

    def test_enforcing_refuses_unsynced(self):
        with patch.object(clock, 'clock_state',
                          return_value=_state(synced=False, max_error_sec=16.0,
                                              status=clock.STA_UNSYNC)), \
                patch.dict(os.environ, {clock.REQUIRE_ENV: '1'}):
            with pytest.raises(clock.UnsyncedClockError) as exc:
                clock.require_synced_clock(self._log())
        assert 'UNSYNCED' in str(exc.value)
        assert 'HOST' in str(exc.value)     # says whose job the daemon is

    def test_advisory_proceeds_with_one_warning(self, caplog):
        with patch.object(clock, 'clock_state',
                          return_value=_state(synced=False, max_error_sec=16.0)), \
                patch.dict(os.environ, {clock.REQUIRE_ENV: '0'}), \
                caplog.at_level(logging.WARNING):
            state = clock.require_synced_clock(self._log())
        assert state.synced is False        # returned, not raised
        assert len([r for r in caplog.records if r.levelno == logging.WARNING]) == 1
        assert 'advisory' in caplog.text

    def test_unset_env_is_advisory(self, caplog):
        env = {k: v for k, v in os.environ.items() if k != clock.REQUIRE_ENV}
        with patch.object(clock, 'clock_state', return_value=_state(synced=False)), \
                patch.dict(os.environ, env, clear=True), \
                caplog.at_level(logging.WARNING):
            clock.require_synced_clock(self._log())     # must not raise
        assert 'advisory' in caplog.text

    def test_synced_but_imprecise_is_refused_when_enforcing(self):
        with patch.object(clock, 'clock_state',
                          return_value=_state(synced=True, max_error_sec=5.0)), \
                patch.dict(os.environ, {clock.REQUIRE_ENV: 'true'}):
            with pytest.raises(clock.UnsyncedClockError) as exc:
                clock.require_synced_clock(self._log(),
                                           max_error=timedelta(seconds=1))
        assert 'exceeds' in str(exc.value)

    def test_mode_is_always_logged_so_a_pass_is_never_ambiguous(self, caplog):
        with patch.object(clock, 'clock_state', return_value=_state()), \
                patch.dict(os.environ, {clock.REQUIRE_ENV: '1'}), \
                caplog.at_level(logging.INFO):
            clock.require_synced_clock(self._log())
        assert 'enforcing' in caplog.text
        assert 'requirement met' in caplog.text

    @pytest.mark.parametrize('value,expected',
                             [('1', True), ('true', True), ('YES', True),
                              ('on', True), ('0', False), ('', False),
                              ('no', False), ('maybe', False)])
    def test_required_parses_env(self, value, expected):
        with patch.dict(os.environ, {clock.REQUIRE_ENV: value}):
            assert clock.required() is expected


class TestNowEquivalence:
    """Negative control 2: deleting the NTP offset changed nothing for
    deployments that never configured it -- measured, not assumed."""

    def test_now_is_the_host_clock(self):
        from autonomous_trust.core._python.system import now
        before = datetime.now(UTC)
        got = now()
        after = datetime.now(UTC)
        assert before <= got <= after
        assert got.tzinfo is not None

    def test_now_carries_no_offset_module(self):
        with pytest.raises(ImportError):
            __import__('autonomous_trust.core._python.network.ntp')


class TestClockSampleMath:
    """Stage 0 of cohort-clock-skew.md: measure how far peers' clocks sit from
    ours. Nothing here steers a clock -- see TestCohortStaysAdvisory."""

    def test_offset_and_delay_from_a_round_trip(self):
        # Peer is 4 s ahead; 100 ms each way; peer took 500 ms to answer.
        t1 = 1000.0
        t2 = t1 + 4.0 + 0.1
        t3 = t2 + 0.5
        t4 = t1 + 0.1 + 0.5 + 0.1
        s = clock.sample_from_round_trip('peer-a', t1, t2, t3, t4)
        assert s.offset.total_seconds() == pytest.approx(4.0)
        # The peer's own 500 ms is subtracted: delay is network time only.
        assert s.delay.total_seconds() == pytest.approx(0.2)
        assert s.usable

    def test_a_slow_responder_is_not_reported_as_a_skewed_one(self):
        """The reason t2 and t3 must be separate readings. Same clocks on both
        sides, but the peer sits on the request for a full minute."""
        t1 = 1000.0
        t2, t3 = t1 + 0.05, t1 + 60.05
        t4 = t1 + 60.1
        s = clock.sample_from_round_trip('slow', t1, t2, t3, t4)
        assert s.offset.total_seconds() == pytest.approx(0.0, abs=1e-9)
        assert s.delay.total_seconds() == pytest.approx(0.1)

    def test_impossible_timings_are_unusable_not_silently_dropped(self):
        # Round trip of 1 s, but the peer claims 2 s of processing inside it.
        s = clock.sample_from_round_trip('liar', 0.0, 0.0, 2.0, 1.0)
        assert s.delay.total_seconds() < 0
        assert not s.usable
        assert 'UNUSABLE' in s.describe()
        assert clock.cohort_offset([s]) == {}

    @pytest.mark.parametrize('bad', [None, 'x', float('inf'), float('nan')])
    def test_unmeasurable_round_trip_yields_no_sample(self, bad):
        assert clock.sample_from_round_trip('p', bad, 1.0, 2.0, 3.0) is None

    def test_exceeds_is_symmetric_about_zero(self):
        bound = timedelta(seconds=2)
        behind = clock.ClockSample('b', timedelta(seconds=-5), timedelta(0))
        ahead = clock.ClockSample('a', timedelta(seconds=5), timedelta(0))
        assert behind.exceeds(bound) and ahead.exceeds(bound)
        assert not clock.ClockSample('ok', timedelta(seconds=1),
                                     timedelta(0)).exceeds(bound)


class TestCohortAggregation:
    def _sample(self, peer, offset_sec, delay_sec=0.01):
        return clock.ClockSample(peer, timedelta(seconds=offset_sec),
                                 timedelta(seconds=delay_sec))

    def test_median_resists_a_lying_minority(self):
        """The reason the estimator is a median. One peer reporting a wild
        offset must not move the cohort estimate -- with a mean, it would."""
        good = [self._sample('a', 0.01), self._sample('b', 0.02),
                self._sample('c', 0.03)]
        clean = clock.cohort_offset(good)
        poisoned = clock.cohort_offset(good + [self._sample('evil', 9999.0)])
        assert clean['cohort_offset'] == pytest.approx(0.02)
        assert poisoned['cohort_offset'] == pytest.approx(0.025, abs=0.01)
        # ...while dispersion still reports that something is very wrong.
        assert poisoned['cohort_dispersion'] > 9000

    def test_unusable_samples_are_excluded_from_the_estimate(self):
        bad = clock.ClockSample('bad', timedelta(seconds=50), timedelta(seconds=-1))
        got = clock.cohort_offset([self._sample('a', 0.01), bad])
        assert got['cohort_samples'] == 1
        assert got['cohort_offset'] == pytest.approx(0.01)

    @pytest.mark.parametrize('samples', [None, [], [None]])
    def test_nothing_to_report_is_an_empty_dict(self, samples):
        assert clock.cohort_offset(samples) == {}


class TestCohortStaysAdvisory:
    """The invariant: cohort time never influences the clock that orders trust
    decisions. Stage 0 observes only."""

    def test_cohort_keys_never_change_synced(self):
        wild = clock.ClockSample('p', timedelta(seconds=9999), timedelta(0))
        with patch.object(clock, 'kernel_clock_state',
                          return_value=_state(synced=True)):
            with patch.object(clock, 'chrony_tracking', return_value={}):
                state = clock.clock_state(samples=[wild])
        assert state.synced is True          # a cohort cannot unsync a clock...
        assert state.detail['cohort_offset'] == pytest.approx(9999)  # ...but it is reported

    def test_no_samples_adds_no_cohort_keys(self):
        with patch.object(clock, 'kernel_clock_state', return_value=_state()):
            with patch.object(clock, 'chrony_tracking', return_value={}):
                state = clock.clock_state()
        assert state.detail == {}

    def test_cohort_and_chrony_detail_coexist(self):
        s = clock.ClockSample('p', timedelta(seconds=0.5), timedelta(0))
        with patch.object(clock, 'kernel_clock_state', return_value=_state()):
            with patch.object(clock, 'chrony_tracking',
                              return_value={'chrony_stratum': '3'}):
                state = clock.clock_state(samples=[s])
        assert state.detail['chrony_stratum'] == '3'
        assert state.detail['cohort_offset'] == pytest.approx(0.5)
        assert 'chronyc' in state.source

    def test_the_gate_ignores_cohort_skew_entirely(self):
        """require_synced_clock is about local discipline. A wildly skewed
        cohort must not make a locally-synced node refuse to start."""
        log = logging.getLogger('test.gate')
        with patch.object(clock, 'clock_state', return_value=_state(
                synced=True, detail={'cohort_offset': 9999.0})):
            with patch.dict(os.environ, {clock.REQUIRE_ENV: '1'}):
                state = clock.require_synced_clock(log)   # must not raise
        assert state.synced


class TestSkewBoundResolution:
    def test_default_when_unset(self):
        with patch.dict(os.environ, {}, clear=True):
            bound, source = clock.resolve_max_cohort_skew()
        assert bound == timedelta(milliseconds=clock.DEFAULT_MAX_COHORT_SKEW_MS)
        assert source == 'default'

    def test_env_override(self):
        with patch.dict(os.environ, {clock.SKEW_ENV: '250'}):
            bound, source = clock.resolve_max_cohort_skew()
        assert bound == timedelta(milliseconds=250)
        assert source == 'env'

    @pytest.mark.parametrize('raw', ['0', '-1', 'abc', '999999999'])
    def test_out_of_range_is_refused_and_the_default_kept(self, raw):
        with patch.dict(os.environ, {clock.SKEW_ENV: raw}):
            bound, source = clock.resolve_max_cohort_skew(
                logging.getLogger('test.knob'))
        assert bound == timedelta(milliseconds=clock.DEFAULT_MAX_COHORT_SKEW_MS)
        assert source == 'default'
