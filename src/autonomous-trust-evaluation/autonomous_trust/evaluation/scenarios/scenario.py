"""
Base scenario engine for AutonomousTrust demonstration examples.

A Scenario defines:
  - A set of peers with roles, positions, and capabilities
  - A sequence of timed phases with entry/exit events
  - Peer lifecycle events (join, compromise, exclude, onboard)
  - Data generators bound to peers
  - Playback-recordable event stream

The scenario engine is a higher-level orchestrator that drives the
simulator (for network topology), inspector (for dashboard), and
custom services (data generators, tasks) together.

Both the multi-agency and DoD demos inherit from this base.
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import Any, Callable, Optional

try:
    from autonomous_trust.services.peer.position import GeoPosition
except ImportError:
    # Lightweight fallback when AT packages are not installed.
    # Only lat/lon/alt are used by the scenario engine.
    class GeoPosition:  # type: ignore[no-redef]
        def __init__(self, lat: float = 0.0, lon: float = 0.0,
                     alt: float | None = None):
            self.lat = lat
            self.lon = lon
            self.alt = alt


logger = logging.getLogger(__name__)


class PeerState(Enum):
    """Lifecycle state of a peer in the scenario."""
    PENDING = auto()     # Not yet joined
    JOINING = auto()     # In the process of joining
    ACTIVE = auto()      # Fully admitted, normal operation
    COMPROMISED = auto() # Exhibiting malicious behavior (may not be detected yet)
    DETECTED = auto()    # Compromise detected by the network
    EXCLUDED = auto()    # Removed from the network
    DEPARTED = auto()    # Left voluntarily


@dataclass
class PeerRole:
    """Definition of a peer's role in the scenario.

    Attributes:
        name:        Unique peer identifier (e.g. "noaa-sensor-1")
        agency:      Organization the peer belongs to (e.g. "NOAA", "Squad-Alpha")
        kind:        Hardware/software type (e.g. "weather-sensor", "micro-drone")
        position:    Initial geographic position
        color:       Display color for dashboards (CSS color string)
        join_phase:  Phase index when this peer joins (0 = start)
        capabilities: List of capability strings this peer advertises
        metadata:    Arbitrary key-value pairs for demo-specific data
    """
    name: str
    agency: str
    kind: str
    position: GeoPosition
    color: str = "#4A90D9"
    join_phase: int = 0
    capabilities: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class PhaseEvent(Enum):
    """Types of events that occur at phase boundaries."""
    PEER_JOIN = auto()
    PEER_DEPART = auto()
    COMPROMISE_START = auto()
    COMPROMISE_DETECT = auto()
    PEER_EXCLUDE = auto()
    DATA_STREAM_START = auto()
    DATA_STREAM_STOP = auto()
    # Reputation-derived trust-tier demotion (peer's _tier dropped).
    # Recorded as a dict by the DoD coordinator; the playback engine
    # reconstructs it as a ScenarioEvent on this enum.
    TIER_LOST = auto()
    ANNOTATION = auto()       # Narration / explanatory text for presentation mode
    CUSTOM = auto()


@dataclass
class ScenarioEvent:
    """A single event in the scenario timeline.

    Attributes:
        timestamp:   Scenario-relative time (offset from T+0)
        event_type:  What kind of event
        peer_name:   Which peer is affected (None for global events)
        description: Human-readable description for event log / narration
        data:        Event-specific payload
    """
    timestamp: timedelta
    event_type: PhaseEvent
    peer_name: Optional[str] = None
    description: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "t": self.timestamp.total_seconds(),
            "type": self.event_type.name,
            "peer": self.peer_name,
            "description": self.description,
            "data": self.data,
        }


@dataclass
class Phase:
    """A named phase of the scenario with a time window.

    Attributes:
        name:        Human-readable phase name (e.g. "Formation", "Compromise")
        start:       Offset from scenario start
        description: Narration text for this phase
        events:      Events that fire during this phase
        gate:        Optional predicate. When set, ``advance_to`` will
                     refuse to step from the prior phase into this one
                     until ``gate(scenario)`` returns True. Lets a
                     scenario hold a transition on an external
                     readiness signal (e.g. ≥90% of peers reached a
                     trust-tier floor) without depending on a
                     specific clock value. A scenario whose gates
                     never clear effectively halts at the last
                     unblocked phase.
    """
    name: str
    start: timedelta
    description: str = ""
    events: list[ScenarioEvent] = field(default_factory=list)
    gate: Optional[Callable[["Scenario"], bool]] = None


class Scenario(ABC):
    """Abstract base class for demo scenarios.

    Subclasses define the peers, phases, and event timeline.
    The engine handles lifecycle, event dispatch, and playback recording.
    """

    def __init__(self):
        self._peers: dict[str, PeerRole] = {}
        self._phases: list[Phase] = []
        self._peer_states: dict[str, PeerState] = {}
        self._listeners: list[Callable[[ScenarioEvent], None]] = []
        self._event_log: list[dict] = []   # recorded events for playback
        self._start_time: Optional[datetime] = None
        self._current_phase_idx: int = 0
        self._running: bool = False
        # Phase names already logged as gate-blocked at least once.
        # Used to keep advance_to's blocked-by-gate log line one-shot
        # per phase even when called every tick by the live coordinator.
        self._gate_blocks_logged: set[str] = set()

        # Let the subclass define everything
        self.define()

    # ------------------------------------------------------------------
    # Subclass API: override these to define the scenario
    # ------------------------------------------------------------------

    @abstractmethod
    def define(self):
        """Called during __init__. Subclass must call add_peer() and
        add_phase() to build the scenario."""
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable scenario name."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """One-paragraph summary for README / dashboard header."""
        ...

    @property
    def duration(self) -> timedelta:
        """Total scenario duration (last phase start + 60s buffer)."""
        if not self._phases:
            return timedelta(minutes=10)
        last = self._phases[-1].start
        return last + timedelta(seconds=60)

    # ------------------------------------------------------------------
    # Builder API: used by subclass define()
    # ------------------------------------------------------------------

    def add_peer(self, role: PeerRole):
        """Register a peer in the scenario."""
        if role.name in self._peers:
            raise ValueError(f"Duplicate peer name: {role.name}")
        self._peers[role.name] = role
        self._peer_states[role.name] = PeerState.PENDING

    def add_phase(self, phase: Phase):
        """Append a phase to the timeline.  Phases must be added in order."""
        if self._phases and phase.start < self._phases[-1].start:
            raise ValueError(
                f"Phase '{phase.name}' starts at {phase.start} which is "
                f"before previous phase '{self._phases[-1].name}' at "
                f"{self._phases[-1].start}"
            )
        self._phases.append(phase)

    def add_event(self, phase_name: str, event: ScenarioEvent):
        """Add an event to a named phase."""
        for phase in self._phases:
            if phase.name == phase_name:
                phase.events.append(event)
                return
        raise ValueError(f"Unknown phase: {phase_name}")

    # ------------------------------------------------------------------
    # Runtime API
    # ------------------------------------------------------------------

    @property
    def peers(self) -> dict[str, PeerRole]:
        return dict(self._peers)

    @property
    def phases(self) -> list[Phase]:
        return list(self._phases)

    @property
    def peer_states(self) -> dict[str, PeerState]:
        return dict(self._peer_states)

    @property
    def current_phase(self) -> Optional[Phase]:
        if 0 <= self._current_phase_idx < len(self._phases):
            return self._phases[self._current_phase_idx]
        return None

    @property
    def event_log(self) -> list[dict]:
        """Recorded events for playback export."""
        return list(self._event_log)

    def on_event(self, callback: Callable[[ScenarioEvent], None]):
        """Register a listener for scenario events."""
        self._listeners.append(callback)

    def _emit(self, event: ScenarioEvent):
        """Dispatch an event to all listeners and record it."""
        record = event.to_dict()
        record["wall_time"] = datetime.utcnow().isoformat()
        self._event_log.append(record)

        for listener in self._listeners:
            try:
                listener(event)
            except Exception:
                logger.exception("Event listener error for %s", event.event_type)

    def _apply_event(self, event: ScenarioEvent):
        """Update internal state based on an event."""
        if event.event_type == PhaseEvent.PEER_JOIN and event.peer_name:
            self._peer_states[event.peer_name] = PeerState.ACTIVE
        elif event.event_type == PhaseEvent.COMPROMISE_START and event.peer_name:
            self._peer_states[event.peer_name] = PeerState.COMPROMISED
        elif event.event_type == PhaseEvent.COMPROMISE_DETECT and event.peer_name:
            self._peer_states[event.peer_name] = PeerState.DETECTED
        elif event.event_type == PhaseEvent.PEER_EXCLUDE and event.peer_name:
            self._peer_states[event.peer_name] = PeerState.EXCLUDED
        elif event.event_type == PhaseEvent.PEER_DEPART and event.peer_name:
            self._peer_states[event.peer_name] = PeerState.DEPARTED

        self._emit(event)

    def advance_to(self, scenario_time: timedelta):
        """Advance the scenario to the given time offset, firing any
        events whose timestamps have been reached.

        Handles peer auto-join (based on join_phase), phase transitions,
        and explicit scenario events.
        """
        # Auto-join peers whose join_phase has been reached
        for name, role in self._peers.items():
            if self._peer_states[name] != PeerState.PENDING:
                continue
            # Check if the phase index for this peer has been reached
            if role.join_phase <= self._current_phase_idx:
                phase_start = (self._phases[role.join_phase].start
                               if role.join_phase < len(self._phases)
                               else timedelta(0))
                if scenario_time >= phase_start:
                    self._apply_event(ScenarioEvent(
                        timestamp=phase_start,
                        event_type=PhaseEvent.PEER_JOIN,
                        peer_name=name,
                        description=f"{name} ({role.agency}) joins the network",
                    ))

        # Advance phase index. A Phase whose ``gate`` predicate is
        # set must consent before we step into it -- the scenario
        # holds at the prior phase index but scenario_time keeps
        # ticking, so the moment the gate clears the next advance_to
        # call steps in. The first refusal per (phase) is logged so
        # there's a visible record without spam; subsequent refusals
        # for the same phase are silent.
        while (self._current_phase_idx < len(self._phases) - 1 and
               self._phases[self._current_phase_idx + 1].start <= scenario_time):
            next_phase = self._phases[self._current_phase_idx + 1]
            if next_phase.gate is not None:
                try:
                    cleared = bool(next_phase.gate(self))
                except Exception:
                    logger.exception(
                        "Phase gate %r raised; treating as blocked",
                        next_phase.name)
                    cleared = False
                if not cleared:
                    if next_phase.name not in self._gate_blocks_logged:
                        self._gate_blocks_logged.add(next_phase.name)
                        logger.info(
                            "Phase '%s' blocked by gate at T+%s (holding "
                            "at '%s')",
                            next_phase.name, next_phase.start,
                            self._phases[self._current_phase_idx].name)
                    break
            self._current_phase_idx += 1
            phase = self._phases[self._current_phase_idx]
            logger.info("Phase: %s (T+%s)", phase.name, phase.start)
            self._emit(ScenarioEvent(
                timestamp=phase.start,
                event_type=PhaseEvent.ANNOTATION,
                description=f"Phase: {phase.name} — {phase.description}",
            ))

            # Auto-join peers for the new phase
            for name, role in self._peers.items():
                if (self._peer_states[name] == PeerState.PENDING and
                        role.join_phase == self._current_phase_idx):
                    self._apply_event(ScenarioEvent(
                        timestamp=phase.start,
                        event_type=PhaseEvent.PEER_JOIN,
                        peer_name=name,
                        description=f"{name} ({role.agency}) joins the network",
                    ))

        # Fire events up to current time
        for phase in self._phases[:self._current_phase_idx + 1]:
            for event in phase.events:
                if event.timestamp <= scenario_time:
                    # Only fire each event once (check via event log)
                    key = (event.timestamp.total_seconds(), event.event_type.name,
                           event.peer_name)
                    already_fired = any(
                        (r["t"], r["type"], r["peer"]) == key
                        for r in self._event_log
                    )
                    if not already_fired:
                        self._apply_event(event)

    def run(self, realtime_factor: float = 1.0, tick_callback: Optional[Callable] = None):
        """Run the scenario in real time (or accelerated).

        Args:
            realtime_factor: Speed multiplier (1.0 = real time, 10.0 = 10x)
            tick_callback:   Called each tick with (scenario, elapsed_timedelta)
        """
        self._start_time = datetime.utcnow()
        self._running = True
        self._current_phase_idx = 0

        # Fire phase 0 annotation and auto-join via advance_to
        if self._phases:
            phase = self._phases[0]
            self._emit(ScenarioEvent(
                timestamp=timedelta(0),
                event_type=PhaseEvent.ANNOTATION,
                description=f"Phase: {phase.name} — {phase.description}",
            ))

        tick_interval = 0.5  # seconds
        total_seconds = self.duration.total_seconds()

        while self._running:
            wall_elapsed = (datetime.utcnow() - self._start_time).total_seconds()
            scenario_elapsed = wall_elapsed * realtime_factor
            elapsed_td = timedelta(seconds=scenario_elapsed)

            if scenario_elapsed >= total_seconds:
                logger.info("Scenario complete (%.1fs)", scenario_elapsed)
                break

            self.advance_to(elapsed_td)

            if tick_callback:
                tick_callback(self, elapsed_td)

            time.sleep(tick_interval / realtime_factor)

        self._running = False

    def stop(self):
        """Stop a running scenario."""
        self._running = False

    # ------------------------------------------------------------------
    # Serialization for canned playback
    # ------------------------------------------------------------------

    def export_scenario_def(self) -> dict:
        """Export the scenario definition (peers, phases) as a dict."""
        return {
            "name": self.name,
            "description": self.description,
            "duration_sec": self.duration.total_seconds(),
            "peers": {
                name: {
                    "agency": role.agency,
                    "kind": role.kind,
                    "position": {"lat": role.position.lat, "lon": role.position.lon,
                                 "alt": role.position.alt},
                    "color": role.color,
                    "join_phase": role.join_phase,
                    "capabilities": role.capabilities,
                    "metadata": role.metadata,
                }
                for name, role in self._peers.items()
            },
            "phases": [
                {
                    "name": p.name,
                    "start_sec": p.start.total_seconds(),
                    "description": p.description,
                }
                for p in self._phases
            ],
        }
