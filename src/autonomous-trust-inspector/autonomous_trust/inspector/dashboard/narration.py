"""
Narration overlay system for presentation mode — reusable across demos.

Displays phase-specific explanatory text overlaid on the dashboard.
In presentation mode, these appear as semi-transparent banners that
auto-advance with the scenario timeline or hold on pause.

The narration credits all trust decisions to the autonomous network,
never to a human operator — this is a core design principle.

Each demo provides its own narration script (list of timed text blocks).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class NarrationBlock:
    """A single narration overlay.

    Attributes:
        t_start:     Scenario time to show (seconds)
        t_end:       Scenario time to hide (seconds, None = show until next)
        text:        The narration text (supports simple HTML)
        subtext:     Smaller explanatory text below the main text
        style:       "default", "alert", "success", "info"
    """
    t_start: float
    t_end: Optional[float] = None
    text: str = ""
    subtext: str = ""
    style: str = "default"


STYLE_COLORS = {
    "default": {"bg": "rgba(15,23,42,0.85)", "border": "#3B82F6",
                "text": "#E2E8F0"},
    "alert":   {"bg": "rgba(127,29,29,0.85)", "border": "#EF4444",
                "text": "#FCA5A5"},
    "success": {"bg": "rgba(6,78,59,0.85)",   "border": "#10B981",
                "text": "#A7F3D0"},
    "info":    {"bg": "rgba(30,58,138,0.85)",  "border": "#60A5FA",
                "text": "#BFDBFE"},
}


class NarrationOverlay:
    """Manages timed narration blocks and renders the current overlay.

    Usage:
        narration = NarrationOverlay(script=[...])
        narration.advance_to(t_seconds=125.0)
        html = narration.to_html()
    """

    def __init__(self, script: list[NarrationBlock]):
        self._script = sorted(script, key=lambda b: b.t_start)
        self._current: Optional[NarrationBlock] = None
        self._visible = True

    def advance_to(self, t_seconds: float):
        """Update the current narration block based on scenario time."""
        self._current = None
        for block in reversed(self._script):
            if t_seconds >= block.t_start:
                if block.t_end is None or t_seconds < block.t_end:
                    self._current = block
                break

    @property
    def current_block(self) -> Optional[NarrationBlock]:
        return self._current

    def toggle_visibility(self):
        self._visible = not self._visible

    def to_html(self) -> str:
        """Render the current narration overlay."""
        if not self._visible or self._current is None:
            return ""

        block = self._current
        colors = STYLE_COLORS.get(block.style, STYLE_COLORS["default"])

        subtext_html = ""
        if block.subtext:
            subtext_html = (
                f'<div style="font-size:13px;color:{colors["text"]};'
                f'opacity:0.8;margin-top:6px">{block.subtext}</div>'
            )

        return (
            f'<div style="position:fixed;bottom:40px;left:50%;'
            f'transform:translateX(-50%);max-width:700px;width:90%;'
            f'background:{colors["bg"]};border:1px solid {colors["border"]};'
            f'border-radius:10px;padding:16px 24px;z-index:1000;'
            f'backdrop-filter:blur(8px);text-align:center">'
            f'<div style="font-size:16px;color:{colors["text"]};'
            f'font-weight:500;line-height:1.4">{block.text}</div>'
            f'{subtext_html}'
            f'</div>'
        )
