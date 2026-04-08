# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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

"""A single sensor reading with metadata."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any


@dataclass
class Reading:
    """A single sensor reading with metadata.

    Attributes:
        timestamp:   Scenario-relative time
        peer_name:   Which peer produced this reading
        data_type:   What kind of data (e.g. "temperature", "magnitude")
        value:       The numeric value
        unit:        Unit string (e.g. "C", "m/s", "ug/m3")
        quality:     Data quality score (0.0-1.0); honest sensors ~ 0.95+
        metadata:    Additional fields (e.g. sensor_id, location)
    """
    timestamp: timedelta
    peer_name: str
    data_type: str
    value: float
    unit: str
    quality: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "t": self.timestamp.total_seconds(),
            "peer": self.peer_name,
            "type": self.data_type,
            "value": round(self.value, 4),
            "unit": self.unit,
            "quality": round(self.quality, 3),
            "metadata": self.metadata,
        }
