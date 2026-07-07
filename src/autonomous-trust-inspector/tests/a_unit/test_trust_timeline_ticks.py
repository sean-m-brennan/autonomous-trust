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

"""Regression tests for the Trust Dynamics timeline's m:ss x-axis ticks —
readable time labels + gridlines so a reader can locate a feature (e.g. a
sawtooth) in time."""
import pytest

try:
    import plotly  # noqa: F401
    from autonomous_trust.inspector.dashboard.trust_timeline import (
        TrustTimeline, ReputationSample, _time_ticks,
    )
    _has_deps = True
except (ImportError, ModuleNotFoundError):
    _has_deps = False

pytestmark = pytest.mark.skipif(not _has_deps, reason="plotly not installed")


def test_ticks_are_clean_mmss_at_zero_origin():
    vals, text = _time_ticks(480)
    assert vals[0] == 0 and text[0] == "0:00"
    # All labels are m:ss and correspond to their second value.
    for v, t in zip(vals, text):
        assert t == "%d:%02d" % (v // 60, v % 60)


def test_tick_interval_scales_to_stay_legible():
    # Short spans use fine intervals; long spans coarsen so labels stay <= ~11.
    for t_max in (5, 45, 90, 300, 480, 1500, 6000):
        vals, _ = _time_ticks(t_max)
        assert 1 <= len(vals) <= 11, (t_max, len(vals))
        assert all(b > a for a, b in zip(vals, vals[1:]))   # strictly increasing
        assert vals[-1] <= t_max


def test_minute_rollover_formats_correctly():
    labels_480 = dict(zip(*_time_ticks(480)))    # 60s step
    assert labels_480[60] == "1:00"
    assert labels_480[120] == "2:00"
    labels_1500 = dict(zip(*_time_ticks(1500)))  # 300s step
    assert labels_1500[600] == "10:00"
    assert labels_1500[900] == "15:00"


def test_figure_sets_mmss_axis_and_gridlines():
    tl = TrustTimeline(peer_colors={"squad-captain": "#22c55e"})
    for i in range(0, 310, 10):
        tl.add_sample(ReputationSample(t=float(i), peer_name="squad-captain",
                                       score=0.8))
    xaxis = tl.figure().layout.xaxis
    assert xaxis.title.text == "Time (m:ss)"
    assert xaxis.showgrid is True
    assert "0:00" in xaxis.ticktext and "5:00" in xaxis.ticktext
    assert tuple(xaxis.range) == (0, 300.0)


def test_legend_background_transparent_so_x_labels_show():
    # The h-legend is anchored below the plot, over the x-axis tick labels; a
    # solid background would hide them (plotly_dark's default is semi-opaque).
    legend = TrustTimeline(peer_colors={}).figure().layout.legend
    assert legend.bgcolor == "rgba(0, 0, 0, 0)"


def test_empty_timeline_still_builds_ticks():
    # No samples -> default 480s span, ticks still valid (no crash).
    xaxis = TrustTimeline(peer_colors={}).figure().layout.xaxis
    assert xaxis.title.text == "Time (m:ss)"
    assert xaxis.ticktext[0] == "0:00"
