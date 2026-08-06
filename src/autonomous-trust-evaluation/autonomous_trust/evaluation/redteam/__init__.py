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
"""Red team attack scenarios for AutonomousTrust adversarial testing."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PartitionEvent:
    """A scheduled network partition between two groups of peers."""
    start_s: float
    end_s: float
    group_a: list[str]  # peer IDs isolated from group_b
    group_b: list[str]


class AttackScenario:
    """Base class for adversarial test scenarios.

    Subclasses modify simulation config at setup time, then collect
    attack-specific metrics after the simulation completes.
    """
    name: str = "unnamed"
    description: str = ""

    def setup(self, sim_config: dict, compose_config: dict) -> None:
        """Modify configs before launch (e.g., swap Router, inject processes)."""

    def teardown(self) -> None:
        """Cleanup after simulation ends or on failure."""

    def collect(self, metrics: dict) -> dict:
        """Add attack-specific metrics to the report. Returns augmented dict."""
        return metrics
