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

"""Dark and light color themes for the demo dashboards.

The theme is picked once at launch (``--theme`` or the ``AT_THEME`` env
var) and read at render time through ``current()``; it defaults to
``DARK``, so a panel built and rendered without any theme setup looks the
way it always has.

Chrome colors (backgrounds, text, borders) are theme fields. Data colors
(roles, agencies, tiers, statuses, the trust ramp) stay defined where the
panels define them, as dark-background values; panels draw them through
``Theme.data()``, which returns the input unchanged in dark and a darker
shade of the same hue in light. Every light data color holds at least 3:1
contrast against the light page background, and colors that share a panel
are spread in lightness so they separate in grayscale where the contrast
floor leaves room.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping, Optional

logger = logging.getLogger(__name__)

THEME_ENV = "AT_THEME"

# A #rgb / #rrggbb color in CSS text; the lookbehind skips HTML character
# references such as &#8212; and &#x2014;.
_HEX_IN_TEXT = re.compile(r"(?<![&\w])#(?:[0-9a-fA-F]{6}|[0-9a-fA-F]{3})(?![0-9a-zA-Z])")

_RGBA = re.compile(
    r"rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*(?:,\s*([\d.]+)\s*)?\)")


def _norm_hex(color: str) -> Optional[str]:
    """'#abc' / '#aabbcc' -> '#AABBCC'; anything else -> None."""
    h = color.strip().lstrip("#")
    if not color.strip().startswith("#") or len(h) not in (3, 6):
        return None
    try:
        int(h, 16)
    except ValueError:
        return None
    if len(h) == 3:
        h = "".join(ch * 2 for ch in h)
    return "#" + h.upper()


@dataclass(frozen=True)
class Theme:
    name: str
    light: bool
    # Page chrome
    bg: str              # page / figure background
    page_bg: str         # DoD outer page
    panel_bg: str        # DoD inset panels and drawer placeholder
    surface: str         # cards, multi-agency panels
    surface_2: str       # raised surfaces, data-stream cards
    control_bg: str      # buttons and inputs
    border: str
    border_muted: str
    text: str
    text_muted: str
    text_dim: str
    accent: str
    # Plotly
    plotly_template: str
    paper_bg: str
    plot_bg: str         # image plot area (detection crops)
    grid: str
    legend_bg: str
    # Maps
    carto_style: str     # DoD scattermap tiles
    mapbox_style: str    # multi-agency tile default when MAPBOX_STYLE is unset
    # Dark-background data color (#RRGGBB, uppercase) -> light counterpart.
    data_colors: Mapping[str, str] = field(
        default_factory=lambda: MappingProxyType({}))
    # Dark chrome literal (#RRGGBB, uppercase) as the panels write it ->
    # this theme's chrome value. Lets inline styles and HTML strings keep
    # their dark literals and still render light.
    chrome_colors: Mapping[str, str] = field(
        default_factory=lambda: MappingProxyType({}))

    def data(self, color: str) -> str:
        """The color to draw for a data color defined for a dark background."""
        return _lookup(color, (self.data_colors,))

    def ui(self, color: str) -> str:
        """The color to draw for a dark chrome literal (or a data color)."""
        return _lookup(color, (self.chrome_colors, self.data_colors))

    def recolor_html(self, text: str) -> str:
        """Swap every dark color literal in an HTML/CSS string in one pass."""
        if not self.chrome_colors and not self.data_colors:
            return text
        return _HEX_IN_TEXT.sub(lambda m: self.ui(m.group(0)), text)

    def recolor_figure(self, fig):
        """Swap dark color literals in every color property of a Plotly figure.

        Only values under keys naming a color (``color``, ``bgcolor``,
        ``fillcolor``, ...) are touched, and only when the whole value is a
        color this theme maps; colorscales, names and text stay as they are.
        """
        if not self.chrome_colors and not self.data_colors:
            return fig
        import plotly.graph_objects as go
        return go.Figure(self._recolor_props(fig.to_dict()))

    def recolor_style(self, style: dict) -> dict:
        """A copy of a Dash ``style`` dict with dark color literals swapped,
        bare (``"#121a2e"``, ``"rgba(...)"``) or inside a value
        (``"1px solid #1f2a44"``)."""
        if not self.chrome_colors and not self.data_colors:
            return style
        return {k: (self._recolor_value(v) if isinstance(v, str) else v)
                for k, v in style.items()}

    def _recolor_value(self, value: str) -> str:
        # Whole-value lookup first (covers rgba()); otherwise swap hex
        # literals inside it. Never both, or a mapped color could be
        # mapped again.
        mapped = self.ui(value)
        return mapped if mapped != value else self.recolor_html(value)

    def recolor_layout(self, root):
        """Recolor every ``style`` in a Dash component tree, in place."""
        if not self.chrome_colors and not self.data_colors:
            return root
        stack = [root]
        while stack:
            node = stack.pop()
            style = getattr(node, "style", None)
            if isinstance(style, dict):
                node.style = self.recolor_style(style)
            kids = getattr(node, "children", None)
            if isinstance(kids, (list, tuple)):
                stack.extend(kids)
            elif kids is not None and not isinstance(kids, (str, int, float)):
                stack.append(kids)
        return root

    def _recolor_props(self, node, in_color: bool = False):
        if isinstance(node, dict):
            return {k: self._recolor_props(
                        v, k.endswith("color") and k != "colorscale")
                    for k, v in node.items()}
        if isinstance(node, (list, tuple)):
            return [self._recolor_props(v, in_color) for v in node]
        if in_color and isinstance(node, str):
            return self.ui(node)
        return node


def _lookup(color: str, tables) -> str:
    """Map a #hex / rgb() / rgba() color through the first table that has
    its rgb value; alpha is kept. Anything unmapped comes back unchanged."""
    if not color or not any(tables):
        return color
    key = _norm_hex(color)
    alpha = None
    if key is None:
        m = _RGBA.fullmatch(color.strip())
        if m is None:
            return color
        r, g, b, alpha = m.groups()
        key = "#{:02X}{:02X}{:02X}".format(int(r), int(g), int(b))
        is_rgb = True
    else:
        is_rgb = False
    for table in tables:
        mapped = table.get(key)
        if mapped is not None:
            break
    else:
        return color
    if not is_rgb:
        return mapped
    mr, mg, mb = (int(mapped[i:i + 2], 16) for i in (1, 3, 5))
    if alpha is None:
        return f"rgb({mr}, {mg}, {mb})"
    return f"rgba({mr}, {mg}, {mb}, {alpha})"

DARK = Theme(
    name="dark", light=False,
    bg="#0b0f1a", page_bg="#0F172A", panel_bg="#0B1220",
    surface="#121a2e", surface_2="#1E1E2E", control_bg="#1E293B",
    border="#1f2a44", border_muted="#334155",
    text="#e2e8f0", text_muted="#94a3b8", text_dim="#64748b",
    accent="#60a5fa",
    plotly_template="plotly_dark", paper_bg="#121a2e", plot_bg="#000",
    grid="rgba(148, 163, 184, 0.18)", legend_bg="rgba(0, 0, 0, 0)",
    carto_style="carto-darkmatter", mapbox_style="dark",
)

LIGHT = Theme(
    name="light", light=True,
    bg="#f8fafc", page_bg="#f1f5f9", panel_bg="#ffffff",
    surface="#ffffff", surface_2="#f1f5f9", control_bg="#e2e8f0",
    border="#cbd5e1", border_muted="#94a3b8",
    text="#0f172a", text_muted="#475569", text_dim="#64748b",
    accent="#2563eb",
    plotly_template="plotly_white", paper_bg="#ffffff", plot_bg="#f1f5f9",
    grid="rgba(71, 85, 105, 0.18)", legend_bg="rgba(0, 0, 0, 0)",
    carto_style="carto-positron", mapbox_style="light",
    chrome_colors=MappingProxyType({
        "#0B0F1A": "#f8fafc",   # bg
        "#0F172A": "#f1f5f9",   # page_bg
        "#0B1220": "#ffffff",   # panel_bg
        "#121A2E": "#ffffff",   # surface
        "#1E2940": "#f1f5f9",   # surface-2 (demo.css)
        "#1E1E2E": "#f1f5f9",   # surface_2
        "#1E293B": "#e2e8f0",   # control_bg
        "#1F2A44": "#cbd5e1",   # border
        "#233554": "#cbd5e1",   # 3D scene grid, map subunit borders
        "#1B263B": "#e2e8f0",   # map land
        "#CBD5F5": "#334155",   # map range labels
        "#334155": "#94a3b8",   # border_muted
        "#E2E8F0": "#0f172a",   # text
        "#94A3B8": "#475569",   # text_muted
        "#64748B": "#64748b",   # text_dim
        "#FDE68A": "#92400e",   # status-bar highlight text
        "#000000": "#f1f5f9",   # image plot area
    }),
    data_colors=MappingProxyType({
        # DoD roles. RQ-86 gold and MQ-800 amber share a panel and differ
        # mostly in hue on dark, so gold goes darker and amber stays mid.
        "#5B6E1F": "#4D5E17",   # squad green
        "#1FB8CD": "#0E7490",   # microdrone cyan
        "#D4AF37": "#6B4F00",   # RQ-86 gold
        "#E6C656": "#9A7400",   # rq86-2 lighter gold
        "#C68A3F": "#C2410C",   # MQ-800 amber
        "#888888": "#5F6670",   # sensor grey / neutral fallback
        "#C0C0C0": "#8A8F98",   # jet silver
        # Trust tiers
        "#94A3B8": "#64748B",   # tier 1, edges, gridlines
        "#FACC15": "#A16207",   # tier 2
        "#FB923C": "#C2410C",   # tier 3
        "#84CC16": "#4D7C0F",   # tier 4
        # Status, score bands and the trust ramp (excluded crimson #881337
        # already reads on white). Ramp lightness rises with trust.
        "#4ADE80": "#16A34A",   # ok / high trust
        "#FBBF24": "#B45309",   # warn / mid trust
        "#EF4444": "#B91C1C",   # alert / low trust / anomaly
        "#FF4444": "#B91C1C",   # cut-off line
        "#F87171": "#B91C1C",   # low reputation score (DoD list)
        "#60A5FA": "#2563EB",   # info / onboarding
        "#555555": "#7C8696",   # excluded, dimmed
        "#64C864": "#16A34A",   # consensus band
        "#FFFFFF": "#0F172A",   # highlight trace
        "#22D3EE": "#0E7490",   # map detection markers
        "#38BDF8": "#0284C7",   # map movement paths
    }),
)

_THEMES = {"dark": DARK, "light": LIGHT}
_current: Theme = DARK


def get_theme(name: str) -> Theme:
    try:
        return _THEMES[name.strip().lower()]
    except KeyError:
        raise ValueError(
            f"unknown theme {name!r} (expected one of: "
            f"{', '.join(_THEMES)})") from None


def resolve_theme(cli: Optional[str], env: Optional[str]) -> Theme:
    """CLI choice, else the AT_THEME value, else dark.

    A bad CLI value is the operator's typo and raises; a bad env value
    (set in a compose file or pod spec) logs and falls back to dark so the
    coordinator still starts.
    """
    if cli:
        return get_theme(cli)
    if env:
        try:
            return get_theme(env)
        except ValueError:
            logger.warning("%s=%r is not a theme; using dark", THEME_ENV, env)
    return DARK


def set_theme(theme: Theme) -> None:
    global _current
    _current = theme


def current() -> Theme:
    return _current
