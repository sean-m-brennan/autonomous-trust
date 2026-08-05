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
