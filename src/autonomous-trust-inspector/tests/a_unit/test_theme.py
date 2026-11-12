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
"""Dashboard Theme: dark/light tokens, data-color mapping, selection."""
import logging

import pytest

from autonomous_trust.inspector.dashboard import theme as th

# Stops of disaster_response_graph._trust_color, low trust -> high trust:
# excluded crimson, red band, yellow band, green band.
TRUST_RAMP_STOPS = ("#881337", "#EF4444", "#FBBF24", "#4ADE80")


def _lin(c):
    c /= 255
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def _luminance(hex_color):
    h = hex_color.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    return 0.2126 * _lin(r) + 0.7152 * _lin(g) + 0.0722 * _lin(b)


def contrast(a, b):
    hi, lo = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def lab_l(hex_color):
    y = _luminance(hex_color)
    f = y ** (1 / 3) if y > 216 / 24389 else (24389 / 27 * y + 16) / 116
    return 116 * f - 16


def test_default_is_dark():
    assert th.current() is th.DARK


def test_dark_data_is_identity():
    for c in ("#D4AF37", "#ef4444", "#555", "rgba(1,2,3,0.5)", "red", ""):
        assert th.DARK.data(c) == c


def test_light_maps_known_colors_case_insensitively():
    assert th.LIGHT.data("#D4AF37") != "#D4AF37"
    assert th.LIGHT.data("#d4af37") == th.LIGHT.data("#D4AF37")


def test_light_expands_short_hex():
    assert th.LIGHT.data("#555") == th.LIGHT.data("#555555")
    assert th.LIGHT.data("#555") != "#555"


def test_light_maps_rgba_keeping_alpha():
    mapped = th.LIGHT.data("rgba(239, 68, 68, 0.35)")
    assert mapped != "rgba(239, 68, 68, 0.35)"
    assert mapped.startswith("rgba(") and mapped.endswith(", 0.35)")


def test_light_passes_unknown_colors_through():
    for c in ("#123456", "rgba(1,2,3,0.5)", "red", "", "#12345"):
        assert th.LIGHT.data(c) == c


def test_plotly_and_map_settings():
    assert th.LIGHT.plotly_template == "plotly_white"
    assert th.LIGHT.carto_style == "carto-positron"
    assert th.LIGHT.mapbox_style == "light"
    assert th.DARK.plotly_template == "plotly_dark"
    assert th.DARK.carto_style == "carto-darkmatter"
    assert th.DARK.mapbox_style == "dark"


def test_dark_chrome_matches_demo_css():
    assert th.DARK.bg == "#0b0f1a"
    assert th.DARK.surface == "#121a2e"
    assert th.DARK.border == "#1f2a44"
    assert th.DARK.text == "#e2e8f0"


def test_light_data_contrast_floor():
    for dark_c, light_c in th.LIGHT.data_colors.items():
        assert contrast(light_c, th.LIGHT.bg) >= 3.0, (dark_c, light_c)


def test_trust_ramp_monotonic_in_light():
    ls = [lab_l(th.LIGHT.data(c)) for c in TRUST_RAMP_STOPS]
    assert ls == sorted(ls) or ls == sorted(ls, reverse=True)


def test_get_theme_case_insensitive():
    assert th.get_theme("Light") is th.LIGHT
    assert th.get_theme("DARK") is th.DARK


def test_get_theme_unknown_raises():
    with pytest.raises(ValueError):
        th.get_theme("bright")


def test_resolve_cli_wins_over_env():
    assert th.resolve_theme("light", "dark") is th.LIGHT


def test_resolve_env_used_without_cli():
    assert th.resolve_theme(None, "LIGHT") is th.LIGHT


def test_resolve_defaults_to_dark():
    assert th.resolve_theme(None, None) is th.DARK
    assert th.resolve_theme(None, "") is th.DARK


def test_resolve_bad_env_warns_and_falls_back(caplog):
    with caplog.at_level(logging.WARNING):
        assert th.resolve_theme(None, "bright") is th.DARK
    assert "bright" in caplog.text


def test_resolve_bad_cli_raises():
    with pytest.raises(ValueError):
        th.resolve_theme("bright", None)


def test_set_theme_round_trip():
    th.set_theme(th.LIGHT)
    try:
        assert th.current() is th.LIGHT
    finally:
        th.set_theme(th.DARK)


# --- chrome colors in Dash styles and HTML strings ------------------------

def test_ui_maps_dark_chrome_to_light_tokens():
    assert th.LIGHT.ui("#e2e8f0") == th.LIGHT.text
    assert th.LIGHT.ui("#121A2E") == th.LIGHT.surface
    assert th.LIGHT.ui("#1f2a44") == th.LIGHT.border


def test_ui_falls_back_to_data_colors():
    assert th.LIGHT.ui("#ef4444") == th.LIGHT.data("#ef4444")


def test_ui_is_identity_in_dark():
    assert th.DARK.ui("#e2e8f0") == "#e2e8f0"


def test_recolor_html_swaps_every_known_color_once():
    src = ('<div style="background:#121a2e;color:#e2e8f0;'
           'border:1px solid #1f2a44"><span style="color:#ef4444">x</span>'
           '<i style="background:#000">y</i></div>')
    out = th.LIGHT.recolor_html(src)
    assert "#121a2e" not in out and "#e2e8f0" not in out
    assert f"background:{th.LIGHT.surface}" in out
    assert f"color:{th.LIGHT.text}" in out
    assert f"color:{th.LIGHT.data('#ef4444')}" in out
    assert f"background:{th.LIGHT.plot_bg}" in out


def test_recolor_html_leaves_entities_and_unknowns():
    src = 'a &#8212; b &#x2014; <b style="color:#123456">c</b>'
    assert th.LIGHT.recolor_html(src) == src


def test_recolor_html_is_identity_in_dark():
    src = '<div style="background:#121a2e;color:#e2e8f0">x</div>'
    assert th.DARK.recolor_html(src) == src


def test_ui_maps_rgba_chrome_keeping_alpha():
    out = th.LIGHT.ui("rgba(18, 26, 46, 0.7)")
    assert out == "rgba(255, 255, 255, 0.7)"


def test_recolor_figure_swaps_color_values_only():
    import plotly.graph_objects as go
    fig = go.Figure(go.Scatter(x=[0], y=[0], name="#e2e8f0",
                               marker=dict(color="#ef4444"),
                               textfont=dict(color="#e2e8f0")))
    fig.update_layout(paper_bgcolor="#121a2e")
    out = th.LIGHT.recolor_figure(fig)
    assert out.layout.paper_bgcolor == th.LIGHT.surface
    assert out.data[0].marker.color == th.LIGHT.data("#ef4444")
    assert out.data[0].textfont.color == th.LIGHT.text
    assert out.data[0].name == "#e2e8f0"      # not a color property


def test_recolor_figure_maps_color_lists():
    import plotly.graph_objects as go
    fig = go.Figure(go.Scatter(x=[0, 1], y=[0, 1],
                               marker=dict(color=["#ef4444", "#123456"])))
    out = th.LIGHT.recolor_figure(fig)
    assert list(out.data[0].marker.color) == [th.LIGHT.data("#ef4444"),
                                              "#123456"]


def test_recolor_figure_is_identity_in_dark():
    import plotly.graph_objects as go
    fig = go.Figure()
    assert th.DARK.recolor_figure(fig) is fig


def test_recolor_style_maps_bare_and_embedded_colors():
    out = th.LIGHT.recolor_style({"background": "#121a2e",
                                  "border": "1px solid #1f2a44",
                                  "boxShadow": "rgba(18, 26, 46, 0.7)",
                                  "padding": "8px", "zIndex": 3})
    assert out["background"] == th.LIGHT.surface
    assert out["border"] == f"1px solid {th.LIGHT.border}"
    assert out["boxShadow"] == "rgba(255, 255, 255, 0.7)"
    assert out["padding"] == "8px" and out["zIndex"] == 3


def test_recolor_style_identity_in_dark():
    st = {"background": "#121a2e"}
    assert th.DARK.recolor_style(st) is st


def test_recolor_layout_walks_dash_tree_in_place():
    from dash import html
    leaf = html.Span("x", style={"color": "#e2e8f0"})
    root = html.Div([html.Div([leaf], style={"background": "#121a2e"}),
                     "plain text"])
    assert th.LIGHT.recolor_layout(root) is root
    assert leaf.style["color"] == th.LIGHT.text
    assert root.children[0].style["background"] == th.LIGHT.surface


def test_recolor_figure_leaves_template_alone():
    import plotly.graph_objects as go
    import plotly.io as pio
    fig = go.Figure()
    fig.update_layout(template="plotly_white", paper_bgcolor="#121a2e")
    out = th.LIGHT.recolor_figure(fig)
    assert out.layout.template == pio.templates["plotly_white"]
    assert out.layout.paper_bgcolor == th.LIGHT.surface
