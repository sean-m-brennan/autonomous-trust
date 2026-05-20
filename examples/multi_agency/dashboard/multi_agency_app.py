"""
Multi-agency demo dashboard configuration.

Instantiates the reusable dashboard components with multi-agency-specific
settings: agency colors, map center (coastal NC), data types, and
scenario phase markers.

This module is the glue between the generic dashboard components and
the multi-agency scenario.  A DoD demo would have a similar file with
military-specific colors, map styles, and data types.
"""

from __future__ import annotations

from autonomous_trust.inspector.dashboard.trust_timeline import TrustTimeline
from autonomous_trust.inspector.dashboard.event_log import EventLog
from autonomous_trust.inspector.dashboard.sensor_chart import SensorComparisonChart
from autonomous_trust.inspector.dashboard.data_streams import DataStreamsPanel
from autonomous_trust.inspector.dashboard.peer_detail import PeerDetailDrawer

from examples.multi_agency.scenario import (
    DisasterResponseScenario,
    NOAA_BLUE, USGS_GREEN, FEMA_ORANGE, EPA_PURPLE,
)


def build_peer_colors(scenario: DisasterResponseScenario) -> dict[str, str]:
    """Extract per-peer color map from scenario definition."""
    return {name: role.color for name, role in scenario.peers.items()}


def build_dashboard(scenario: DisasterResponseScenario) -> dict:
    """Create all dashboard components configured for the multi-agency demo.

    Returns a dict of component name -> component instance.
    """
    colors = build_peer_colors(scenario)

    # Trust dynamics timeline with phase markers
    timeline = TrustTimeline(
        peer_colors=colors,
        threshold=0.5,
        title="Trust Dynamics — Multi-Agency Disaster Response",
    )
    for phase in scenario.phases:
        timeline.add_phase_marker(
            t_seconds=phase.start.total_seconds(),
            label=phase.name,
        )

    # Sensor comparison chart (temperature — the money shot)
    temp_chart = SensorComparisonChart(
        data_type="temperature",
        unit="C",
        peer_colors={
            "noaa-sensor-1": NOAA_BLUE,
            "noaa-sensor-2": "#5BB5FF",   # lighter blue for differentiation
            "noaa-sensor-3": "#FF6B6B",   # red-ish to hint at compromise
        },
        window_sec=120.0,
        title="Temperature Comparison — NOAA Sensors",
    )

    # Wind speed comparison (secondary chart)
    wind_chart = SensorComparisonChart(
        data_type="wind_speed",
        unit="km/h",
        peer_colors={
            "noaa-sensor-1": NOAA_BLUE,
            "noaa-sensor-2": "#5BB5FF",
            "noaa-sensor-3": "#FF6B6B",
        },
        window_sec=120.0,
        title="Wind Speed — NOAA Sensors",
    )

    # Event log
    event_log = EventLog(max_entries=200)

    # Data streams panel
    streams = DataStreamsPanel(peer_colors=colors)

    # Peer detail drawer
    detail = PeerDetailDrawer()

    return {
        "trust_timeline": timeline,
        "temperature_chart": temp_chart,
        "wind_chart": wind_chart,
        "event_log": event_log,
        "data_streams": streams,
        "peer_detail": detail,
    }


# Map configuration for Mapbox
MAP_CONFIG = {
    "center": {"lat": 34.23, "lon": -77.88},  # Wilmington, NC area
    "zoom": 10,
    "style": "satellite-streets",  # Mapbox style
    "agency_layers": {
        "NOAA":  {"color": NOAA_BLUE,   "icon": "weather",   "label": "NOAA Weather"},
        "USGS":  {"color": USGS_GREEN,  "icon": "seismic",   "label": "USGS Seismic"},
        "FEMA":  {"color": FEMA_ORANGE, "icon": "emergency",  "label": "FEMA Emergency"},
        "EPA":   {"color": EPA_PURPLE,  "icon": "air",        "label": "EPA Air Quality"},
    },
}
