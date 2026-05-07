#!/usr/bin/env python3
"""
Generate the simulator scenario.yaml for the multi-agency demo.

Translates the Python scenario definition into the YAML format that
the AT simulator expects (PeerInfo objects with positions, paths,
antennas, interfaces, data streams).

Usage:
    python generate_scenario.py [output_file]

Default output: examples/multi_agency/simulator/scenario.yaml
"""

from __future__ import annotations

import sys
import uuid
import json
from datetime import datetime, timedelta
from pathlib import Path

# Ensure repo root is on path
_repo = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(_repo))

from examples.multi_agency.scenario import DisasterResponseScenario


def generate_scenario_yaml(output_path: str | None = None) -> str:
    """Generate scenario YAML from the multi-agency scenario definition."""
    scenario = DisasterResponseScenario()

    # Build peer list in simulator format
    peers = []
    start = datetime(2025, 9, 15, 14, 0, 0)  # Hurricane season afternoon
    end = start + scenario.duration

    for name, role in scenario.peers.items():
        peer = {
            "uuid": str(uuid.uuid5(uuid.NAMESPACE_DNS, name)),
            "kind": role.kind,
            "nickname": name,
            "ip4_addr": "",  # assigned by docker network
            "position": {
                "lat": role.position.lat,
                "lon": role.position.lon,
                "alt": role.position.alt or 10.0,
            },
            "signal": 20.0,
            "antenna": "DIPOLE",
            "interface": "SMALL",
            "initial_time": start.isoformat(),
            "last_seen": end.isoformat(),
            "path_list": [
                {
                    "type": "point",
                    "position": {
                        "lat": role.position.lat,
                        "lon": role.position.lon,
                        "alt": role.position.alt or 10.0,
                    },
                }
            ],
            "data_streams": [],
            "agency": role.agency,
            "capabilities": role.capabilities,
        }
        peers.append(peer)

    config = {
        "start": start.isoformat(),
        "end": end.isoformat(),
        "peers": peers,
    }

    import yaml
    yaml_str = yaml.dump(config, default_flow_style=False, sort_keys=False)

    if output_path:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            f.write(f"# Auto-generated scenario for: {scenario.name}\n")
            f.write(f"# {scenario.description}\n\n")
            f.write(yaml_str)
        print(f"Wrote {output_path}")

    return yaml_str


if __name__ == "__main__":
    output = sys.argv[1] if len(sys.argv) > 1 else str(
        Path(__file__).parent / "scenario.yaml")
    generate_scenario_yaml(output)
