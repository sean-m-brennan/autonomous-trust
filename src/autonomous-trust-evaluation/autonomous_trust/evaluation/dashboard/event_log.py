"""
Event log panel — reusable across demos.

Displays a scrolling, color-coded log of scenario events:
  - Phase transitions (blue)
  - Peer joins/departures (green)
  - Compromise events (red)
  - Detection events (orange)
  - Data stream events (gray)
  - Annotations / narration (white/italic)

Events are rendered as a simple HTML table that auto-scrolls to the
latest entry.  Works with both live scenarios and canned playback.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Optional

from autonomous_trust.evaluation.scenarios.scenario import PhaseEvent


# Color mapping for event types
EVENT_COLORS = {
    PhaseEvent.PEER_JOIN:         "#4ADE80",  # green
    PhaseEvent.PEER_DEPART:       "#94A3B8",  # slate
    PhaseEvent.COMPROMISE_START:  "#EF4444",  # red
    PhaseEvent.COMPROMISE_DETECT: "#F97316",  # orange
    PhaseEvent.PEER_EXCLUDE:      "#DC2626",  # dark red
    PhaseEvent.DATA_STREAM_START: "#64748B",  # gray
    PhaseEvent.DATA_STREAM_STOP:  "#64748B",  # gray
    PhaseEvent.ANNOTATION:        "#E2E8F0",  # light gray
    PhaseEvent.CUSTOM:            "#A78BFA",  # purple
}

EVENT_ICONS = {
    PhaseEvent.PEER_JOIN:         "+",
    PhaseEvent.PEER_DEPART:       "-",
    PhaseEvent.COMPROMISE_START:  "!",
    PhaseEvent.COMPROMISE_DETECT: "?",
    PhaseEvent.PEER_EXCLUDE:      "X",
    PhaseEvent.DATA_STREAM_START: ">",
    PhaseEvent.DATA_STREAM_STOP:  ".",
    PhaseEvent.ANNOTATION:        "#",
    PhaseEvent.CUSTOM:            "*",
}


@dataclass
class LogEntry:
    """A single event log entry."""
    t: float
    event_type: PhaseEvent
    description: str
    peer_name: Optional[str] = None

    @property
    def color(self) -> str:
        return EVENT_COLORS.get(self.event_type, "#E2E8F0")

    @property
    def icon(self) -> str:
        return EVENT_ICONS.get(self.event_type, " ")

    @property
    def time_str(self) -> str:
        minutes = int(self.t) // 60
        seconds = int(self.t) % 60
        return f"T+{minutes}:{seconds:02d}"

    def to_html_row(self) -> str:
        style = f'color: {self.color}'
        if self.event_type == PhaseEvent.ANNOTATION:
            style += '; font-style: italic'
        peer = f' [{self.peer_name}]' if self.peer_name else ''
        return (
            f'<tr style="{style}">'
            f'<td style="width:60px;font-family:monospace">{self.time_str}</td>'
            f'<td style="width:20px;text-align:center">{self.icon}</td>'
            f'<td>{self.description}{peer}</td>'
            f'</tr>'
        )


class EventLog:
    """Accumulates scenario events and renders as HTML.

    Usage:
        log = EventLog(max_entries=200)
        log.add(LogEntry(t=0, event_type=PhaseEvent.PEER_JOIN,
                         description="noaa-sensor-1 joins"))
        html = log.to_html()
    """

    def __init__(self, max_entries: int = 200):
        self._entries: list[LogEntry] = []
        self._max = max_entries

    def add(self, entry: LogEntry):
        self._entries.append(entry)
        if len(self._entries) > self._max:
            self._entries = self._entries[-self._max:]

    def clear(self):
        self._entries.clear()

    @property
    def entries(self) -> list[LogEntry]:
        return list(self._entries)

    @property
    def count(self) -> int:
        return len(self._entries)

    def to_html(self, height: str = "300px") -> str:
        """Render the log as a scrollable HTML table."""
        rows = "\n".join(e.to_html_row() for e in self._entries)
        return (
            f'<div style="height:{height};overflow-y:auto;'
            f'background:#1E1E2E;padding:8px;border-radius:6px;'
            f'font-size:12px;font-family:monospace">'
            f'<table style="width:100%;border-collapse:collapse">'
            f'{rows}'
            f'</table>'
            f'</div>'
        )

    def latest_html(self, n: int = 1) -> str:
        """Return HTML for just the last N entries (for incremental updates)."""
        recent = self._entries[-n:]
        return "\n".join(e.to_html_row() for e in recent)
