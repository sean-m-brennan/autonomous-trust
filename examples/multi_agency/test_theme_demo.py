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

"""The multi-agency dashboard follows the launch-time theme."""
from pathlib import Path

import pytest

pytest.importorskip("dash")

from autonomous_trust.inspector.dashboard import theme as th  # noqa: E402
from autonomous_trust.inspector.dashboard.disaster_response_layout import (  # noqa: E402
    build_dashboard)
from autonomous_trust.inspector.dashboard.narration import (  # noqa: E402
    NarrationBlock, STYLE_COLORS, style_colors)
from examples.multi_agency import demo  # noqa: E402

DEMO_CSS = (Path(th.__file__).resolve().parents[1]
            / "dash_components" / "assets" / "demo.css")


@pytest.fixture
def light():
    th.set_theme(th.LIGHT)
    yield th.LIGHT
    th.set_theme(th.DARK)


def _root_class(root):
    stack = [root]
    while stack:
        node = stack.pop()
        if getattr(node, "id", None) == "demo-root":
            return node.className
        kids = getattr(node, "children", None)
        if isinstance(kids, (list, tuple)):
            stack.extend(kids)
        elif kids is not None and not isinstance(kids, str):
            stack.append(kids)
    return None


def test_layout_gets_theme_class_in_light(light):
    root = demo._theme_layout(build_dashboard(scenario_title="t"))
    assert "theme-light" in _root_class(root).split()
    assert "demo-root" in _root_class(root).split()


def test_layout_has_no_theme_class_in_dark():
    root = demo._theme_layout(build_dashboard(scenario_title="t"))
    assert _root_class(root) == "demo-root"


def test_layout_inline_styles_recolored_in_light(light):
    from dash import html
    root = html.Div(id="demo-root", className="demo-root", children=[
        html.Div(style={"background": "#121a2e",
                        "border": "1px solid #1f2a44"})])
    demo._theme_layout(root)
    assert root.children[0].style["background"] == light.surface


def test_narration_uses_theme_colors(light):
    _, style = demo._build_narration(
        NarrationBlock(t_start=0, text="x", style="alert"))
    assert style["background"] == style_colors("alert")["bg"]
    assert style["background"] != STYLE_COLORS["alert"]["bg"]


def test_narration_dark_unchanged():
    _, style = demo._build_narration(
        NarrationBlock(t_start=0, text="x", style="alert"))
    assert style["background"] == STYLE_COLORS["alert"]["bg"]


def test_demo_css_has_light_block():
    css = DEMO_CSS.read_text()
    assert ".demo-root.theme-light" in css
    block = css.split(".demo-root.theme-light", 1)[1].split("}", 1)[0]
    assert "--demo-bg" in block and "--demo-text" in block


# --- theme selection on the launch paths -----------------------------------

from examples.multi_agency import __main__ as ma_main  # noqa: E402


def test_multi_agency_parse_theme():
    assert ma_main._parse_args(
        ["--playback", "x.json", "--theme", "light"]).theme == "light"
    assert ma_main._parse_args(["--playback", "x.json"]).theme is None
    with pytest.raises(SystemExit):
        ma_main._parse_args(["--playback", "x.json", "--theme", "bright"])


def test_disaster_compose_forwards_theme(monkeypatch):
    from autonomous_trust.evaluation.scenarios.disaster_response import (
        DisasterResponseScenario)
    from autonomous_trust.evaluation.scenarios.disaster_response_compose import (
        ComposeOptions, generate_compose)
    monkeypatch.setenv("AT_THEME", "light")
    assert 'AT_THEME: "light"' in generate_compose(DisasterResponseScenario(),
                                                    ComposeOptions())
    monkeypatch.delenv("AT_THEME")
    assert "AT_THEME" not in generate_compose(DisasterResponseScenario(),
                                              ComposeOptions())
