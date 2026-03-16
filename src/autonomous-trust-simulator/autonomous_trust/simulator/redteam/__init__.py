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
