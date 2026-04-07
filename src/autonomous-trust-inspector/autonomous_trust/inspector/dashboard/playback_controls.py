"""
Playback controls panel — reusable across demos.

Provides play/pause, speed (1x-10x), phase jump buttons, and a
progress bar with phase markers.  Works in both live mode (controlling
scenario speed) and playback mode (controlling PlaybackEngine).

Renders as HTML + optional Dash callbacks.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class PlaybackState:
    """Current state of the playback controller."""
    playing: bool = False
    speed: float = 1.0
    current_t: float = 0.0
    duration: float = 480.0
    current_phase: str = ""
    mode: str = "live"  # "live" or "playback"

    @property
    def progress_pct(self) -> float:
        if self.duration <= 0:
            return 0.0
        return min(100.0, 100.0 * self.current_t / self.duration)

    @property
    def time_str(self) -> str:
        m = int(self.current_t) // 60
        s = int(self.current_t) % 60
        return f"T+{m}:{s:02d}"

    @property
    def duration_str(self) -> str:
        m = int(self.duration) // 60
        s = int(self.duration) % 60
        return f"{m}:{s:02d}"


@dataclass
class PhaseButton:
    """A clickable phase jump button."""
    label: str
    t_seconds: float
    is_current: bool = False


class PlaybackControls:
    """Builds playback control HTML with phase markers.

    Usage:
        ctl = PlaybackControls(phases=[("Formation", 0), ("Bootstrap", 60), ...])
        ctl.update(PlaybackState(playing=True, speed=2.0, current_t=45.0))
        html = ctl.to_html()
    """

    SPEEDS = [1.0, 2.0, 5.0, 10.0]

    def __init__(self, phases: list[tuple[str, float]], duration: float = 480.0):
        """
        Args:
            phases:   List of (phase_name, start_seconds)
            duration: Total scenario duration in seconds
        """
        self._phases = phases
        self._duration = duration
        self._state = PlaybackState(duration=duration)

    def update(self, state: PlaybackState):
        """Update the control state."""
        self._state = state
        self._state.duration = self._duration

    @property
    def state(self) -> PlaybackState:
        return self._state

    def to_html(self) -> str:
        """Render the full playback controls as HTML."""
        return (
            f'<div style="background:#1E1E2E;padding:10px 16px;border-radius:8px;'
            f'font-family:system-ui;font-size:12px">'
            f'{self._transport_row()}'
            f'{self._progress_bar()}'
            f'{self._phase_buttons()}'
            f'</div>'
        )

    def _transport_row(self) -> str:
        """Play/pause button, speed selector, time display."""
        s = self._state
        play_icon = "&#9646;&#9646;" if s.playing else "&#9654;"
        play_label = "Pause" if s.playing else "Play"
        mode_badge = (
            f'<span style="background:#334155;color:#94A3B8;padding:2px 6px;'
            f'border-radius:3px;font-size:10px;margin-left:8px">'
            f'{s.mode.upper()}</span>'
        )

        speed_buttons = ""
        for spd in self.SPEEDS:
            active = "background:#3B82F6;color:#FFF" if spd == s.speed else \
                     "background:#334155;color:#94A3B8"
            speed_buttons += (
                f'<button data-speed="{spd}" style="{active};border:none;'
                f'padding:4px 8px;border-radius:3px;margin:0 2px;'
                f'cursor:pointer;font-size:11px">{spd:.0f}x</button>'
            )

        return (
            f'<div style="display:flex;align-items:center;margin-bottom:8px">'
            f'<button data-action="playpause" style="background:#3B82F6;color:#FFF;'
            f'border:none;padding:6px 12px;border-radius:4px;cursor:pointer;'
            f'font-size:14px;margin-right:12px" title="{play_label}">'
            f'{play_icon}</button>'
            f'<div style="margin-right:12px">{speed_buttons}</div>'
            f'<div style="color:#E2E8F0;font-family:monospace;font-size:14px;'
            f'margin-right:8px">{s.time_str}</div>'
            f'<div style="color:#64748B;font-size:11px">/ {s.duration_str}</div>'
            f'{mode_badge}'
            f'<div style="flex:1"></div>'
            f'<div style="color:#94A3B8;font-size:11px">{s.current_phase}</div>'
            f'</div>'
        )

    def _progress_bar(self) -> str:
        """Progress bar with phase markers overlaid."""
        s = self._state
        pct = s.progress_pct

        # Phase markers as positioned dots
        markers = ""
        for name, t in self._phases:
            pos = 100.0 * t / self._duration if self._duration > 0 else 0
            markers += (
                f'<div style="position:absolute;left:{pos:.1f}%;top:-2px;'
                f'width:2px;height:10px;background:#64748B" '
                f'title="{name} (T+{int(t)//60}:{int(t)%60:02d})"></div>'
            )

        return (
            f'<div style="position:relative;height:6px;background:#334155;'
            f'border-radius:3px;margin-bottom:8px;cursor:pointer" '
            f'data-action="seek">'
            f'<div style="height:100%;width:{pct:.1f}%;background:#3B82F6;'
            f'border-radius:3px;transition:width 0.3s"></div>'
            f'{markers}'
            f'</div>'
        )

    def _phase_buttons(self) -> str:
        """Phase jump buttons."""
        buttons = ""
        for name, t in self._phases:
            is_current = (name == self._state.current_phase)
            bg = "#3B82F6" if is_current else "#1E293B"
            color = "#FFF" if is_current else "#94A3B8"
            border = "1px solid #3B82F6" if is_current else "1px solid #334155"
            buttons += (
                f'<button data-phase-t="{t}" style="background:{bg};color:{color};'
                f'border:{border};padding:3px 8px;border-radius:3px;margin:0 3px;'
                f'cursor:pointer;font-size:10px">{name}</button>'
            )

        return (
            f'<div style="display:flex;flex-wrap:wrap;gap:2px">'
            f'{buttons}'
            f'</div>'
        )
