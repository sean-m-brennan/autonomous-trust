"""
Data-sharing task definitions for the civilian disaster response demo.

These define the negotiable tasks that peers advertise and fulfill
through the AutonomousTrust negotiation protocol.  Each task maps to
a data stream type and the capabilities required to provide it.

Task types:
  - weather_stream:    NOAA peers provide weather data
  - seismic_stream:    USGS peers provide seismic data
  - airquality_stream: EPA peers provide air quality data
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TaskDefinition:
    """A negotiable data-sharing task.

    Attributes:
        task_type:           Unique task type identifier
        description:         Human-readable description
        required_capabilities: Provider must advertise these
        consumer_capabilities: Consumer must advertise these (empty = any)
        min_reputation:      Minimum reputation to accept as provider
        data_types:          What data types this task produces
        cadence_sec:         How often data is expected
        priority:            Scheduling priority (higher = more important)
    """
    task_type: str
    description: str
    required_capabilities: list[str] = field(default_factory=list)
    consumer_capabilities: list[str] = field(default_factory=list)
    min_reputation: float = 0.5
    data_types: list[str] = field(default_factory=list)
    cadence_sec: float = 5.0
    priority: int = 1
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "task_type": self.task_type,
            "description": self.description,
            "required_capabilities": self.required_capabilities,
            "consumer_capabilities": self.consumer_capabilities,
            "min_reputation": self.min_reputation,
            "data_types": self.data_types,
            "cadence_sec": self.cadence_sec,
            "priority": self.priority,
            "metadata": self.metadata,
        }


# --- Standard civilian demo tasks ---

WEATHER_STREAM = TaskDefinition(
    task_type="weather_stream",
    description="Real-time weather observations (temp, wind, pressure, precip)",
    required_capabilities=["weather_stream"],
    data_types=["temperature", "wind_speed", "pressure", "precipitation"],
    cadence_sec=5.0,
    priority=2,
)

SEISMIC_STREAM = TaskDefinition(
    task_type="seismic_stream",
    description="Seismic monitoring data (magnitude, ground velocity)",
    required_capabilities=["seismic_stream"],
    data_types=["magnitude", "ground_velocity"],
    cadence_sec=15.0,
    priority=1,
)

AIRQUALITY_STREAM = TaskDefinition(
    task_type="airquality_stream",
    description="Air quality observations (AQI, PM2.5, ozone)",
    required_capabilities=["airquality_stream"],
    data_types=["aqi", "pm25", "ozone"],
    cadence_sec=10.0,
    priority=1,
)

ALL_TASKS = [WEATHER_STREAM, SEISMIC_STREAM, AIRQUALITY_STREAM]
