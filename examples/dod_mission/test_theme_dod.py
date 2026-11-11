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

"""The DoD mission dashboard follows the launch-time theme.

Run from the repo root:
    pytest examples/dod_mission/test_theme_dod.py
"""

from __future__ import annotations

import plotly.io as pio
import pytest

from autonomous_trust.inspector.dashboard import theme as th
from examples.dod_mission.dashboard import live_server as ls
from examples.dod_mission.dashboard.target_position_map import (
    TargetPositionMapPanel, SQUAD_ORIGIN_LAT, SQUAD_ORIGIN_LON,
)

RQ86_GOLD = "#D4AF37"


@pytest.fixture
def light():
    th.set_theme(th.LIGHT)
    yield th.LIGHT
    th.set_theme(th.DARK)


@pytest.fixture(autouse=True)
def _dark_after():
    yield
    th.set_theme(th.DARK)


def _panel(view="2d") -> TargetPositionMapPanel:
    p = TargetPositionMapPanel(peer_colors={"rq86-1": RQ86_GOLD})
    p.set_platforms({
        "squad-1": {"lat": SQUAD_ORIGIN_LAT, "lon": SQUAD_ORIGIN_LON,
                    "alt": 197.0, "kind": "soldier", "color": "#5B6E1F"},
        "rq86-1": {"lat": 34.724, "lon": -86.640, "alt": 5000.0,
                   "kind": "recon-drone", "color": RQ86_GOLD},
    }, t_seconds=100.0)
    p.set_view_mode(view)
    return p


def _colors(fig):
    out = set()
    for tr in fig.data:
        m = getattr(tr, "marker", None)
        c = getattr(m, "color", None) if m is not None else None
        if isinstance(c, str):
            out.add(c)
        elif c is not None:
            out.update(x for x in c if isinstance(x, str))
    return out


def _state():
    return {"reputations": {"mq800": 0.1, "rq86-1": 0.8},
            "tiers": {"mq800": 0, "rq86-1": 2},
            "agencies": {"mq800": "Unknown-Air"},
            "kinds": {"mq800": "armed-drone"},
            "t_seconds": 164.0}


def test_target_map_light(light):
    fig = _panel().figure()
    assert fig.layout.map.style == "carto-positron"
    assert fig.layout.template == pio.templates["plotly_white"]
    assert light.data(RQ86_GOLD) in _colors(fig)


def test_target_map_dark_unchanged():
    fig = _panel().figure()
    assert fig.layout.map.style == "carto-darkmatter"
    assert fig.layout.template == pio.templates["plotly_dark"]
    assert RQ86_GOLD in _colors(fig)


def test_iso_map_light(light):
    fig = _panel("iso").figure()
    assert fig.layout.paper_bgcolor == light.bg
    assert fig.layout.scene.xaxis.backgroundcolor != "#0b0f1a"


def test_iso_map_dark_unchanged():
    fig = _panel("iso").figure()
    assert fig.layout.paper_bgcolor == "#0b0f1a"


def test_map_legend_light(light):
    # legend_groups() reports dark literals; the rendered legend is themed
    # once, by _themed (themed twice, light outputs would be remapped).
    out = str(ls._themed(ls._render_map_legend(_panel().legend_groups())))
    assert light.data(RQ86_GOLD) in out
    assert RQ86_GOLD not in out


def test_drawer_doc_light(light):
    doc = ls._render_peer_drawer(_state(), "mq800")
    assert f"background:{light.page_bg}" in doc
    assert "background:#0F172A" not in doc
    assert "#E2E8F0" not in doc


def test_drawer_doc_dark_unchanged():
    doc = ls._render_peer_drawer(_state(), "mq800")
    assert "body{margin:0;padding:8px;background:#0F172A;color:#E2E8F0;" in doc


def test_drawer_placeholder_light(light):
    assert "#0B1220" not in ls._drawer_placeholder()


def test_reputations_light(light):
    out = str(ls._themed(ls._render_reputations(_state())))
    for dark in ("#FACC15", "#FB923C", "#84CC16", "#E2E8F0"):
        assert dark not in out


def test_reputations_low_score_red_light(light):
    # mq800 at 0.10 draws its score in the low-score red, which must be
    # mapped to a shade that holds 3:1 on the light page.
    out = str(ls._themed(ls._render_reputations(_state())))
    assert "#F87171" not in out
    assert light.data("#F87171") in out


def test_reputations_dark_unchanged():
    out = str(ls._themed(ls._render_reputations(_state())))
    assert "#FACC15" in out or "#475569" in out


def test_narration_light(light):
    from autonomous_trust.inspector.dashboard.narration import (
        NarrationBlock, STYLE_COLORS, style_colors)
    div = ls._narration_div(NarrationBlock(t_start=0, text="x",
                                           style="alert"))
    assert div.style["background"] == style_colors("alert")["bg"]
    assert div.style["background"] != STYLE_COLORS["alert"]["bg"]


# --- theme selection on the launch paths -----------------------------------

import os  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402
from pathlib import Path  # noqa: E402

from examples.dod_mission import __main__ as dod_main  # noqa: E402

REPO = Path(__file__).resolve().parents[2]


def test_dod_parse_theme():
    assert dod_main._parse_args(
        ["--playback", "x.json", "--theme", "light"]).theme == "light"
    assert dod_main._parse_args(["--playback", "x.json"]).theme is None


def test_dod_parse_theme_rejects_unknown():
    with pytest.raises(SystemExit):
        dod_main._parse_args(["--playback", "x.json", "--theme", "bright"])


def test_compose_forwards_theme(monkeypatch):
    from examples.dod_mission.deploy import generate_compose as gc
    monkeypatch.setenv("AT_THEME", "light")
    env = gc.build_compose()["services"]["coordinator"]["environment"]
    assert env["AT_THEME"] == "light"


def test_compose_omits_theme_when_unset(monkeypatch):
    from examples.dod_mission.deploy import generate_compose as gc
    monkeypatch.delenv("AT_THEME", raising=False)
    env = gc.build_compose()["services"]["coordinator"]["environment"]
    assert "AT_THEME" not in env


def test_k8s_coordinator_forwards_theme(monkeypatch):
    # generate_k8s.py sits under a gitignored deploy/ path and may be absent
    # from a fresh checkout.
    gk = pytest.importorskip("examples.dod_mission.deploy.generate_k8s")
    monkeypatch.setenv("AT_THEME", "light")
    assert gk._coordinator_env(gk.K8sOptions(), {})["AT_THEME"] == "light"
    monkeypatch.delenv("AT_THEME")
    assert "AT_THEME" not in gk._coordinator_env(gk.K8sOptions(), {})


def _play_script_argv(tmp_path, *args):
    stub = tmp_path / "py"
    stub.write_text("#!/bin/sh\n"
                    "if [ \"$1\" = -c ]; then exit 0; fi\n"
                    "printf '%s\\n' \"$@\"\n")
    stub.chmod(0o755)
    rec = tmp_path / "rec.json"
    rec.write_text("{}")
    out = subprocess.run(
        ["bash", str(REPO / "scripts/play-dod-mission.sh"), str(rec), *args],
        env={**os.environ, "PYTHON": str(stub)},
        capture_output=True, text=True, check=True).stdout.splitlines()
    return out, str(rec)


def test_play_script_theme_space_form(tmp_path):
    argv, rec = _play_script_argv(tmp_path, "--theme", "light")
    assert argv[argv.index("--playback") + 1] == rec
    assert argv[argv.index("--theme") + 1] == "light"


def test_play_script_theme_equals_form(tmp_path):
    argv, rec = _play_script_argv(tmp_path, "--theme=light")
    assert argv[argv.index("--playback") + 1] == rec
    assert argv[argv.index("--theme") + 1] == "light"


def test_run_demo_accepts_theme_option():
    text = (REPO / "scripts/run-demo.sh").read_text()
    assert "--theme)" in text and "--theme=*)" in text
    assert "export AT_THEME" in text
