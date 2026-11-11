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

"""Each browser page gets its own first draw of the map, trust graph and
Trust Dynamics figures.

The figures are skipped (no_update) while their inputs are unchanged. When
that "last drawn" signature lived on the server, the first page to poll took
the draw and every later page or reload kept an empty figure until the inputs
next changed; the map's inputs can sit unchanged for minutes. The signature
now lives in each page's own dcc.Store.
"""
import pytest

pytest.importorskip("dash")

from dash import no_update  # noqa: E402
from plotly.graph_objects import Figure  # noqa: E402

from autonomous_trust.evaluation.scenarios.disaster_response import (  # noqa: E402
    DisasterResponseScenario)
from autonomous_trust.evaluation.scenarios.playback_iface import (  # noqa: E402
    PlaybackInterface)
from examples.multi_agency import demo  # noqa: E402


@pytest.fixture
def dash_demo():
    return demo.MultiAgencyDemo(
        PlaybackInterface(DisasterResponseScenario()), port=0)


def _callback(d, output_key):
    for key, cb in d._dash.app.callback_map.items():
        if output_key in key:
            return cb["callback"].__wrapped__
    raise KeyError(output_key)


def _map_cb(d):
    return _callback(d, f"{demo._MAP_GRAPH}.figure")


def _tick_cb(d):
    return _callback(d, f"{demo._TIMELINE_GRAPH}.figure")


# Positions of the trust graph and timeline in _on_tick's outputs, and of its
# per-page signature store (the last output).
_TIMELINE, _GRAPH, _TICK_SIGS = 9, 11, -1


def test_a_second_page_gets_the_map(dash_demo):
    refresh = _map_cb(dash_demo)
    fig_a, sig_a = refresh(1, None)
    assert isinstance(fig_a, Figure)
    # The same page, nothing changed: skipped.
    assert refresh(2, sig_a)[0] is no_update
    # A second page (or a reload) has no signature yet: it draws.
    fig_b, _ = refresh(2, None)
    assert isinstance(fig_b, Figure)


def test_a_reset_redraws_the_map_on_every_page(dash_demo):
    refresh = _map_cb(dash_demo)
    _, sig = refresh(1, None)
    dash_demo._on_reset()
    assert isinstance(refresh(2, sig)[0], Figure)


def test_a_second_page_gets_the_trust_graph_and_timeline(dash_demo):
    tick = _tick_cb(dash_demo)
    first = tick(1, {"name": None}, None)
    assert isinstance(first[_TIMELINE], Figure)
    assert isinstance(first[_GRAPH], Figure)
    again = tick(2, {"name": None}, first[_TICK_SIGS])
    assert again[_TIMELINE] is no_update
    assert again[_GRAPH] is no_update
    other = tick(2, {"name": None}, None)
    assert isinstance(other[_TIMELINE], Figure)
    assert isinstance(other[_GRAPH], Figure)
