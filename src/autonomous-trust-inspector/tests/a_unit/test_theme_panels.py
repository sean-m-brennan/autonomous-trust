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
"""Shared inspector panels render with the current dashboard theme.

Light builds must carry no dark template or dark surface; dark builds
must look exactly as before the theme existed.
"""
import base64
import io
from datetime import timedelta

import pytest

pytest.importorskip("plotly")
import plotly.io as pio  # noqa: E402

from autonomous_trust.inspector.dashboard import theme as th  # noqa: E402
from autonomous_trust.inspector.dashboard.trust_timeline import (  # noqa: E402
    TrustTimeline, ReputationSample)
from autonomous_trust.inspector.dashboard.sensor_chart import (  # noqa: E402
    SensorComparisonChart)
from autonomous_trust.inspector.dashboard.disaster_response_graph import (  # noqa: E402
    TrustNetworkGraph)
from autonomous_trust.inspector.dashboard.peer_detail import (  # noqa: E402
    DetectionSummary, detection_figure)
from autonomous_trust.services.data import Reading  # noqa: E402

# Dark backgrounds. (#0f172a is left out: it is the light theme's text color.)
DARK_SURFACES = ("#121a2e", "#0b0f1a", "#0b1220")


@pytest.fixture
def light():
    th.set_theme(th.LIGHT)
    yield th.LIGHT
    th.set_theme(th.DARK)


def _no_dark_surface(fig):
    js = fig.to_json().lower()
    return not any(s in js for s in DARK_SURFACES)


def _timeline():
    tl = TrustTimeline(peer_colors={"rq86-1": "#D4AF37"})
    for i in range(0, 60, 10):
        tl.add_sample(ReputationSample(t=float(i), peer_name="rq86-1",
                                       score=0.8))
    return tl.figure()


def _sensor():
    ch = SensorComparisonChart("target_x", "m",
                               peer_colors={"a": "#D4AF37", "b": "#C68A3F",
                                            "c": "#1FB8CD"},
                               highlight_peer="c")
    for i in range(10):
        for name, v in (("a", 1.0), ("b", 1.1), ("c", 9.0)):
            ch.add_reading(Reading(peer_name=name, data_type="target_x",
                                   value=v + i * 0.01, unit="m",
                                   timestamp=timedelta(seconds=i)))
    ch.mark_anomalous("c", 5.0)
    return ch.figure()


def _graph():
    g = TrustNetworkGraph(peer_colors={"rq86-1": "#D4AF37"})
    g.add_peer("rq86-1", "Air-Support", kind="uav")
    g.add_peer("mq800", "Unknown-Air", kind="uav")
    g.set_trust("rq86-1", "mq800", 0.8)
    g.mark_compromised("mq800")
    return g.figure()


def _crop_b64():
    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", (32, 24), (90, 90, 90)).save(buf, format="JPEG")
    return base64.b64encode(buf.getvalue()).decode()


def _detection():
    return detection_figure(DetectionSummary(
        crop_b64=_crop_b64(), crop_size_px=(32, 24),
        bbox_in_crop_px=(4, 4, 20, 16), label="truck", confidence=0.9))


# --- trust timeline ----------------------------------------------------

def test_timeline_light(light):
    fig = _timeline()
    assert fig.layout.template == pio.templates["plotly_white"]
    assert _no_dark_surface(fig)
    peer = [t for t in fig.data if t.name == "rq86-1"][0]
    assert peer.line.color == light.data("#D4AF37")


def test_timeline_dark_unchanged():
    fig = _timeline()
    assert fig.layout.template == pio.templates["plotly_dark"]
    peer = [t for t in fig.data if t.name == "rq86-1"][0]
    assert peer.line.color == "#D4AF37"
    assert fig.layout.legend.bgcolor == "rgba(0, 0, 0, 0)"


# --- sensor chart --------------------------------------------------------

def test_sensor_light(light):
    fig = _sensor()
    assert fig.layout.template == pio.templates["plotly_white"]
    colors = {t.name: t.line.color for t in fig.data if t.name in ("a", "b", "c")}
    assert colors["a"] == light.data("#D4AF37")
    # highlight defaults to white on dark; it must not vanish on white
    assert colors["c"] == light.data("#ffffff") != "#ffffff"


def test_sensor_empty_light(light):
    ch = SensorComparisonChart("target_x", "m", peer_colors={})
    assert ch.figure().layout.template == pio.templates["plotly_white"]


def test_sensor_dark_unchanged():
    fig = _sensor()
    assert fig.layout.template == pio.templates["plotly_dark"]
    colors = {t.name: t.line.color for t in fig.data if t.name in ("a", "b", "c")}
    assert colors["a"] == "#D4AF37" and colors["c"] == "#ffffff"


# --- trust network graph -------------------------------------------------

def test_graph_light(light):
    fig = _graph()
    assert fig.layout.paper_bgcolor == light.surface
    assert _no_dark_surface(fig)
    nodes = [t for t in fig.data if t.mode == "markers+text"]
    drawn = {c for t in nodes for c in t.marker.color}
    assert light.data("#D4AF37") in drawn
    assert light.data("#ef4444") in drawn


def test_graph_dark_unchanged():
    fig = _graph()
    assert fig.layout.paper_bgcolor == "#121a2e"
    assert fig.layout.legend.bgcolor == "rgba(18, 26, 46, 0.4)"
    nodes = [t for t in fig.data if t.mode == "markers+text"]
    drawn = {c for t in nodes for c in t.marker.color}
    assert "#D4AF37" in drawn and "#ef4444" in drawn


# --- detection crop figure -----------------------------------------------

def test_detection_light(light):
    fig = _detection()
    assert fig.layout.paper_bgcolor == light.paper_bg
    assert fig.layout.plot_bgcolor == light.plot_bg
    assert _no_dark_surface(fig)


def test_detection_dark_unchanged():
    fig = _detection()
    assert fig.layout.paper_bgcolor == "#121a2e"
    assert fig.layout.plot_bgcolor == "#000"


# --- HTML panels -----------------------------------------------------------

from autonomous_trust.inspector.dashboard.peer_detail import (  # noqa: E402
    PeerDetailPanel, PeerDetailState, ReputationSnapshot)
from autonomous_trust.inspector.dashboard.narration import (  # noqa: E402
    NarrationBlock, NarrationOverlay, STYLE_COLORS, style_colors)
from autonomous_trust.inspector.dashboard.data_streams import (  # noqa: E402
    DataStreamsPanel)

DARK_HTML_BGS = ("background:#121a2e", "background:#0b1220",
                 "background:#0f172a", "background:#1e1e2e",
                 "background:#000")


def _drawer_html():
    st = PeerDetailState(name="mq800", agency="Unknown-Air", kind="uav",
                         status="compromised",
                         reputation=ReputationSnapshot())
    st.detection = DetectionSummary(
        crop_b64=_crop_b64(), crop_size_px=(32, 24),
        bbox_in_crop_px=(4, 4, 20, 16), label="truck", confidence=0.9)
    return PeerDetailPanel().to_html(st)


def _streams():
    p = DataStreamsPanel(peer_colors={"rq86-1": "#D4AF37"})
    p.update(Reading(peer_name="rq86-1", data_type="target_x", value=1.0,
                     unit="m", timestamp=timedelta(seconds=1)))
    return p


def test_drawer_light(light):
    out = _drawer_html().lower()
    assert not any(bg in out for bg in DARK_HTML_BGS)
    assert "#e2e8f0" not in out
    assert light.surface in out


def test_drawer_dark_unchanged():
    out = _drawer_html()
    assert "background:#121a2e" in out and "#e2e8f0" in out


def test_narration_style_colors_follow_theme(light):
    for style in STYLE_COLORS:
        assert style_colors(style) != STYLE_COLORS[style]
    assert style_colors("nonexistent") == style_colors("default")


def test_narration_style_colors_dark_unchanged():
    for style in STYLE_COLORS:
        assert style_colors(style) == STYLE_COLORS[style]


def test_narration_overlay_light(light):
    ov = NarrationOverlay([NarrationBlock(t_start=0, text="hi",
                                          style="alert")])
    ov.advance_to(1.0)
    out = ov.to_html()
    assert STYLE_COLORS["alert"]["bg"] not in out
    assert style_colors("alert")["bg"] in out


def test_streams_light(light):
    p = _streams()
    out = p.to_html().lower()
    # (#94a3b8 is also the light border color, so check text color only)
    assert "background:#1e1e2e" not in out and "color:#94a3b8" not in out
    assert light.data("#D4AF37").lower() in out
    dash_out = str(p.to_dash_children()).lower()
    assert "'color': '#94a3b8'" not in dash_out and "#334155" not in dash_out
    assert light.data("#D4AF37").lower() in dash_out


def test_streams_dark_unchanged():
    p = _streams()
    assert "background:#1E1E2E" in p.to_html()
    assert "#D4AF37" in str(p.to_dash_children())


# --- multi-agency map ------------------------------------------------------

from autonomous_trust.inspector.dashboard.disaster_response_map import (  # noqa: E402
    AgencyMap, MapPeer)


def _agency_map(monkeypatch, mapbox=None, mapbox_style=None):
    for var, val in (("MAPBOX", mapbox), ("MAPBOX_STYLE", mapbox_style)):
        if val is None:
            monkeypatch.delenv(var, raising=False)
        else:
            monkeypatch.setenv(var, val)
    m = AgencyMap()
    m.add_peer(MapPeer(name="noaa-1", agency="NOAA", kind="weather-sensor",
                       lat=46.7, lon=-122.5))
    m.add_peer(MapPeer(name="noaa-3", agency="NOAA", kind="weather-sensor",
                       lat=46.8, lon=-122.4, status="compromised"))
    return m.figure()


def test_agency_map_light_geo(light, monkeypatch):
    fig = _agency_map(monkeypatch)
    assert fig.layout.paper_bgcolor == light.surface
    assert fig.layout.geo.landcolor != "#1b263b"
    assert fig.layout.legend.font.color == light.text
    assert _no_dark_surface(fig)


def test_agency_map_light_tiles_default_light(light, monkeypatch):
    fig = _agency_map(monkeypatch, mapbox="1")
    assert fig.layout.map.style == "light"


def test_agency_map_explicit_mapbox_style_wins(light, monkeypatch):
    fig = _agency_map(monkeypatch, mapbox="1", mapbox_style="dark")
    assert fig.layout.map.style == "dark"


def test_agency_map_dark_unchanged(monkeypatch):
    fig = _agency_map(monkeypatch)
    assert fig.layout.paper_bgcolor == "#121a2e"
    assert fig.layout.geo.landcolor == "#1b263b"
    assert _agency_map(monkeypatch, mapbox="1").layout.map.style == "dark"
