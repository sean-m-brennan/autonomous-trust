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

"""Tests for DelayRouter tc netem delay injection (Phase 5)."""

from __future__ import annotations

from unittest.mock import patch, MagicMock
from datetime import datetime

import pytest

# Try to import DelayRouter; mark tests that need it as skipped if unavailable
_delay_router_error = None
try:
    from autonomous_trust.simulator.radio.delay import DelayRouter
except ImportError as _e:
    _delay_router_error = _e
    DelayRouter = None  # type: ignore[assignment,misc]

# DelayMatrix type alias (Task 4 will add this to sim_data; define locally for now)
DelayMatrix = dict[str, dict[str, float]]

# Skip marker for tests that need the full Router dependency chain
needs_router = pytest.mark.skipif(
    DelayRouter is None,
    reason=f"missing dependency: {_delay_router_error}",
)


def _format_netem_delay(delay_s: float) -> str:
    """Standalone implementation of the netem delay formatter (mirrors DelayRouter)."""
    delay_ms = int(delay_s * 1000)
    return '%dms' % delay_ms


class TestNetemDelayFormat:
    """Test netem delay format logic — pure arithmetic, no dependencies."""

    def test_netem_delay_format_seconds(self):
        """Delay of 1152.7 seconds -> '1152700ms' tc netem param."""
        assert _format_netem_delay(1152.7) == '1152700ms'

    def test_netem_delay_format_sub_second(self):
        """Delay of 0.5 seconds -> '500ms'."""
        assert _format_netem_delay(0.5) == '500ms'

    def test_netem_delay_format_zero(self):
        """Zero delay -> '0ms'."""
        assert _format_netem_delay(0.0) == '0ms'

    def test_netem_delay_format_large(self):
        """64-minute delay -> '3840000ms'."""
        assert _format_netem_delay(3840.0) == '3840000ms'

    @needs_router
    def test_static_method_matches(self):
        """DelayRouter.format_netem_delay must agree with local impl."""
        for val in [0.0, 0.5, 1152.7, 3840.0]:
            assert DelayRouter.format_netem_delay(val) == _format_netem_delay(val)


@needs_router
class TestDelayRouterUnit:
    """Test DelayRouter logic with mocked system calls."""

    @pytest.fixture
    def mock_router(self):
        """Create a DelayRouter with mocked root check and iptables."""
        with patch('os.geteuid', return_value=0), \
             patch.object(DelayRouter, 'chain_available', return_value=True), \
             patch.object(DelayRouter, 'iptables'), \
             patch.object(DelayRouter, 'traffic_ctl') as mock_tc:
            router = DelayRouter(containerized=False, rate_limit=False)
            router._mock_tc = mock_tc
            yield router

    def test_build_delay_commands(self, mock_router):
        """Verify correct tc netem commands are generated for peer pairs."""
        delays = {
            'peer_a': {'peer_b': 1152.7},
        }
        state = MagicMock()
        state.peers = {
            'peer_a': MagicMock(ip4_addr='10.0.0.1'),
            'peer_b': MagicMock(ip4_addr='10.0.0.2'),
        }
        state.delay = delays
        mock_router.apply_delays(state)
        # Should have called traffic_ctl for the delay
        assert mock_router._mock_tc.called

    def test_no_commands_when_no_delays(self, mock_router):
        """No tc commands when delay matrix is empty."""
        state = MagicMock()
        state.peers = {}
        state.delay = {}
        mock_router.apply_delays(state)
        assert not mock_router._mock_tc.called

    def test_delay_update_only_on_change(self, mock_router):
        """Same delay value should not re-issue tc commands."""
        delays = {
            'peer_a': {'peer_b': 500.0},
        }
        state = MagicMock()
        state.peers = {
            'peer_a': MagicMock(ip4_addr='10.0.0.1'),
            'peer_b': MagicMock(ip4_addr='10.0.0.2'),
        }
        state.delay = delays
        # First call: issues commands
        mock_router.apply_delays(state)
        call_count_1 = mock_router._mock_tc.call_count
        # Second call with same delays: no new commands
        mock_router.apply_delays(state)
        assert mock_router._mock_tc.call_count == call_count_1
