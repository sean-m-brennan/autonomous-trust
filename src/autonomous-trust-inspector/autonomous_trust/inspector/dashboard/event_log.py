# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ******************

"""Event log panel -- scrolling timestamped entries, color-coded by severity.

Consumes the scenario's event stream (PhaseEvent / ScenarioEvent from
scenarios/scenario.py) plus runtime events from the AT reputation /
negotiation subsystems. Renders as HTML that slots into the dashboard's
`panel_log` placeholder. CSS classes match demo.css:

    demo-event--info     neutral discovery / handshake
    demo-event--data     routine stream / subscription messages
    demo-event--warning  divergence detected, reputation dipping
    demo-event--threat   compromise detected, peer excluded
    demo-event--success  onboarded, trust threshold crossed
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from dash_extensions.enrich import html


# Severity -> CSS class suffix. Plain string to keep this file pure-Python.
SEVERITY_INFO    = "info"
SEVERITY_DATA    = "data"
SEVERITY_WARNING = "warning"
SEVERITY_THREAT  = "threat"
SEVERITY_SUCCESS = "success"

_SEVERITIES = {SEVERITY_INFO, SEVERITY_DATA,
               SEVERITY_WARNING, SEVERITY_THREAT, SEVERITY_SUCCESS}

# Scenario PhaseEvent name -> default severity. Keeps callers from
# having to pass a severity for every scenario-driven entry.
_SCENARIO_SEVERITY = {
    "PEER_JOIN":          SEVERITY_INFO,
    "PEER_DEPART":        SEVERITY_INFO,
    "DATA_STREAM_START":  SEVERITY_DATA,
    "DATA_STREAM_STOP":   SEVERITY_DATA,
    "COMPROMISE_START":   SEVERITY_WARNING,
    "COMPROMISE_DETECT":  SEVERITY_WARNING,
    "PEER_EXCLUDE":       SEVERITY_THREAT,
    "ANNOTATION":         SEVERITY_INFO,
    "CUSTOM":             SEVERITY_INFO,
}


@dataclass
class LogEntry:
    """A single entry in the event log.

    Attributes:
        t:          Scenario seconds.
        text:       Human-readable line.
        severity:   One of SEVERITY_*.
        peer_name:  Optional peer reference (makes click-to-highlight work).
        source:     "scenario" | "reputation" | "negotiation" | "network"
                    | caller-defined. Used for filtering in future views.
    """
    t: float
    text: str
    severity: str = SEVERITY_INFO
    peer_name: Optional[str] = None
    source: str = "scenario"

    def css_class(self) -> str:
        sev = self.severity if self.severity in _SEVERITIES else SEVERITY_INFO
        return f"demo-event demo-event--{sev}"

    def time_str(self) -> str:
        if self.t < 0:
            t = 0
        else:
            t = self.t
        m = int(t) // 60
        s = int(t) % 60
        return f"T+{m:02d}:{s:02d}"


class EventLogPanel:
    """Ring buffer of log entries with newest-first rendering.

    Usage:
        log = EventLogPanel(capacity=200)
        log.add_from_scenario_event(ev)           # PhaseEvent/ScenarioEvent
        log.add(LogEntry(t=42, text="...", severity=SEVERITY_WARNING))
        html = log.to_html()
    """

    def __init__(self, capacity: int = 200):
        self._capacity = max(1, int(capacity))
        self._entries: list[LogEntry] = []

    # --- population ---------------------------------------------------

    def add(self, entry: LogEntry):
        self._entries.append(entry)
        if len(self._entries) > self._capacity:
            # Drop oldest -- cheaper than deque for capacity~200 AND
            # keeps the list sortable by t for time-based slicing.
            del self._entries[0: len(self._entries) - self._capacity]

    def add_from_scenario_event(self, ev) -> None:
        """Ingest a ScenarioEvent (duck-typed: needs .timestamp,
        .event_type.name, .description, .peer_name, .data)."""
        name = getattr(ev.event_type, "name", str(ev.event_type))
        severity = _SCENARIO_SEVERITY.get(name, SEVERITY_INFO)
        # Narration overrides: the scenario flags detection/exclusion
        # annotations so they read as successes when the network worked
        # (excluded rogue) rather than as pure threats.
        data = getattr(ev, "data", {}) or {}
        if data.get("source") == "narration":
            severity = SEVERITY_INFO

        desc = getattr(ev, "description", "") or name
        t = getattr(ev.timestamp, "total_seconds",
                    lambda: float(ev.timestamp))()
        self.add(LogEntry(
            t=float(t),
            text=desc,
            severity=severity,
            peer_name=getattr(ev, "peer_name", None),
            source="scenario",
        ))

    def add_from_event_record(self, rec: dict) -> None:
        """Ingest a serialized event from `Scenario.event_log` (dict
        shape: t, type, peer, description, data). Used by the inspector
        runtime that drains scenario.event_log incrementally each tick;
        live ScenarioEvent objects go through add_from_scenario_event."""
        name = str(rec.get("type", ""))
        data = rec.get("data") or {}
        # Bridge-emitted ANNOTATION records carry a "data" severity by
        # default — they are stream/heartbeat chatter, not phase events.
        if name == "ANNOTATION" and data.get("source") == "bridge":
            severity = SEVERITY_DATA
        else:
            severity = _SCENARIO_SEVERITY.get(name, SEVERITY_INFO)
            if data.get("source") == "narration":
                severity = SEVERITY_INFO
        desc = rec.get("description") or name
        self.add(LogEntry(
            t=float(rec.get("t", 0.0)),
            text=desc,
            severity=severity,
            peer_name=rec.get("peer"),
            source="scenario",
        ))

    def add_success(self, t: float, text: str,
                    peer_name: Optional[str] = None,
                    source: str = "scenario"):
        """Shortcut for onboarding / threshold-crossed events."""
        self.add(LogEntry(t=t, text=text, severity=SEVERITY_SUCCESS,
                          peer_name=peer_name, source=source))

    def add_threat(self, t: float, text: str,
                   peer_name: Optional[str] = None,
                   source: str = "scenario"):
        self.add(LogEntry(t=t, text=text, severity=SEVERITY_THREAT,
                          peer_name=peer_name, source=source))

    def add_warning(self, t: float, text: str,
                    peer_name: Optional[str] = None,
                    source: str = "scenario"):
        self.add(LogEntry(t=t, text=text, severity=SEVERITY_WARNING,
                          peer_name=peer_name, source=source))

    # --- rendering ----------------------------------------------------

    @property
    def entries(self) -> list[LogEntry]:
        return list(self._entries)

    def to_dash_children(self,
                         empty_text: str = "No events yet") -> list:
        """Render entries as a list of Dash html.Div children for direct
        insertion into the layout's panel_log slot. Newest first.

        Returns a single-element placeholder list when empty so the slot
        always has a child."""
        if not self._entries:
            return [html.Div(empty_text, className="demo-placeholder")]
        items = []
        for e in reversed(self._entries):
            items.append(html.Div(
                className=e.css_class(),
                children=[
                    html.Span(e.time_str(),
                              className="demo-event__time"),
                    html.Span(e.text,
                              className="demo-event__text"),
                ],
            ))
        return items

    def to_html(self, height: str = "100%") -> str:
        # Newest first: reverse the stored order in the rendered output.
        rendered = []
        for e in reversed(self._entries):
            peer_span = ""
            if e.peer_name:
                # data-* attributes let a click-handler resolve the peer
                # selection without re-parsing the text. Inspector's
                # callback layer can listen on demo-event and read
                # data-peer to highlight the peer in the map + graph.
                peer_span = (
                    f' data-peer="{_esc(e.peer_name)}"'
                )
            else:
                peer_span = ''
            rendered.append(
                f'<div class="{e.css_class()}" data-t="{e.t:.2f}"'
                f'{peer_span}>'
                f'<span class="demo-event__time">{e.time_str()}</span>'
                f'<span>{_esc(e.text)}</span>'
                f'</div>'
            )

        return (
            f'<div style="height:{height};overflow-y:auto;padding-right:4px">'
            f'{"".join(rendered) if rendered else _empty_block()}'
            f'</div>'
        )

    def clear(self):
        self._entries.clear()


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def _esc(s: str) -> str:
    """Minimal HTML escape for log content (no markup expected)."""
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def _empty_block() -> str:
    return ('<div class="demo-placeholder" '
            'style="height:100%">No events yet</div>')
