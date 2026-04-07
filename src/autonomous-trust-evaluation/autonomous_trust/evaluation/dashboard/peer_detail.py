"""
Peer detail drawer — reusable across demos.

When a peer is selected (clicked in the trust graph or map), this panel
shows detailed information:
  - Identity: name, agency, kind, station ID
  - Reputation: current score, trend arrow, history sparkline
  - Network: latency, connected peers count
  - Data streams: active feeds with latest readings
  - State: current lifecycle state (active, compromised, excluded)

Renders as HTML for embedding in Dash layouts or overlaying as a drawer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from autonomous_trust.evaluation.scenarios.scenario import PeerRole, PeerState


# State display configuration
STATE_COLORS = {
    PeerState.PENDING:     ("#94A3B8", "Pending"),
    PeerState.JOINING:     ("#60A5FA", "Joining..."),
    PeerState.ACTIVE:      ("#4ADE80", "Active"),
    PeerState.COMPROMISED: ("#EF4444", "Compromised"),
    PeerState.DETECTED:    ("#F97316", "Anomaly Detected"),
    PeerState.EXCLUDED:    ("#DC2626", "Excluded"),
    PeerState.DEPARTED:    ("#64748B", "Departed"),
}


@dataclass
class PeerDetail:
    """Collected detail for a single peer."""
    role: PeerRole
    state: PeerState
    reputation: float = 0.0
    reputation_trend: float = 0.0  # positive = improving
    connected_peers: int = 0
    latency_ms: float = 0.0
    active_streams: list[str] = field(default_factory=list)
    latest_readings: dict[str, float] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)


class PeerDetailDrawer:
    """Renders a peer detail panel as HTML.

    Usage:
        drawer = PeerDetailDrawer()
        html = drawer.render(detail)
    """

    def render(self, detail: Optional[PeerDetail]) -> str:
        """Render the drawer HTML.  If detail is None, show placeholder."""
        if detail is None:
            return self._placeholder()

        role = detail.role
        state_color, state_text = STATE_COLORS.get(
            detail.state, ("#888", "Unknown"))
        trend = "+" if detail.reputation_trend > 0 else ""

        # Build sections
        identity = self._section("Identity", [
            ("Name", role.name),
            ("Agency", role.agency),
            ("Type", role.kind),
            *[(k, str(v)) for k, v in role.metadata.items()
              if k not in ("compromised",)],
        ])

        reputation = self._section("Reputation", [
            ("Score", f"{detail.reputation:.3f}"),
            ("Trend", f"{trend}{detail.reputation_trend:.3f}/min"),
            ("State", f'<span style="color:{state_color}">{state_text}</span>'),
        ])

        network = self._section("Network", [
            ("Connected Peers", str(detail.connected_peers)),
            ("Latency", f"{detail.latency_ms:.0f} ms"),
        ])

        streams = ""
        if detail.active_streams:
            stream_items = []
            for s in detail.active_streams:
                val = detail.latest_readings.get(s, None)
                val_str = f"{val:.2f}" if val is not None else "--"
                stream_items.append((s, val_str))
            streams = self._section("Data Streams", stream_items)

        return (
            f'<div style="background:#1E1E2E;padding:12px;border-radius:8px;'
            f'border-left:4px solid {role.color};font-size:12px;'
            f'font-family:system-ui">'
            f'<div style="font-size:16px;font-weight:bold;color:{role.color};'
            f'margin-bottom:8px">{role.name}</div>'
            f'{identity}{reputation}{network}{streams}'
            f'</div>'
        )

    def _section(self, title: str, items: list[tuple[str, str]]) -> str:
        rows = "".join(
            f'<tr><td style="color:#94A3B8;padding:2px 8px 2px 0">{k}</td>'
            f'<td style="color:#E2E8F0;padding:2px 0">{v}</td></tr>'
            for k, v in items
        )
        return (
            f'<div style="margin-bottom:8px">'
            f'<div style="color:#64748B;font-size:10px;text-transform:uppercase;'
            f'letter-spacing:1px;margin-bottom:2px">{title}</div>'
            f'<table style="width:100%">{rows}</table>'
            f'</div>'
        )

    def _placeholder(self) -> str:
        return (
            '<div style="background:#1E1E2E;padding:20px;border-radius:8px;'
            'text-align:center;color:#64748B;font-size:12px;'
            'font-family:system-ui">'
            'Click a peer in the trust graph or map to see details'
            '</div>'
        )
