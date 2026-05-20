#!/usr/bin/env python3
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
"""Emit the simulator scenario.yaml from the DoD scenario definition.

This is the simulator-side counterpart to the Scenario subclass in
../scenario.py.  Each peer becomes a PeerInfo entry consumed by
`python -m autonomous_trust.simulator scenario.yaml`.

Movement: the first pass writes a stationary path_list (type: point) for
every peer, matching the multi-agency demo.  Realistic motion (squad
approach, microdrone sweep, RQ-86 orbit, jet ingress) belongs in a
follow-on that builds Bezier / Ellipse path lists per role; the
positions and altitudes here are already set up so paths can be slotted
in without re-deriving coordinates.  See examples/mission/simulator/
scenario.yaml for the path shapes that should eventually be emitted.

Loader gap (shared with multi-agency, surfaced 2026-05-18):
`autonomous_trust.simulator.sim_data.SimConfig.load` calls
`Configuration.from_json_string`, which routes through `json.loads`.
This dict-style YAML is not valid JSON, so it cannot be consumed by the
loader as-is.  The original `examples/mission/simulator/scenario.yaml`
used tagged-YAML (`!Cfg:autonomous_trust.simulator.sim_data.SimConfig`)
which a previous YAML loader presumably handled; that path appears to
be retired.  This generator's output matches the multi-agency format
exactly so any fix benefits both demos.  Likely resolutions: (a) add a
PyYAML loader path in `Configuration.from_string` that detects YAML and
deserializes via a `Loader` subclass that handles `!Cfg:` tags, or
(b) emit JSON here instead of YAML.  Defer until Phase 3 (deployment),
when the simulator container actually has to consume this file.
"""

from __future__ import annotations

import argparse
import sys
import uuid
from datetime import datetime
from pathlib import Path

# Make the sibling scenario.py importable without packaging the directory.
_THIS = Path(__file__).resolve().parent
_DOD_PKG = _THIS.parent
sys.path.insert(0, str(_DOD_PKG))

from scenario import DoDMissionScenario  # noqa: E402


# Per-role radio profile.  See src/autonomous-trust-simulator/.../radio/iface.py
# for the enum values.  Conservative defaults; refine after radio modeling.
ROLE_RADIO = {
    "soldier":      ("DIPOLE",    "SMALL", -200.0),
    "microdrone":   ("DIPOLE",    "SMALL", -200.0),
    "recon-drone":  ("PARABOLIC", "LARGE", -1200.0),
    "armed-drone":  ("PARABOLIC", "LARGE", -1200.0),
    "ground-sensor":("DIPOLE",    "SMALL", -200.0),
    "fighter-jet":  ("YAGI",      "LARGE", -1200.0),
    "command-node": ("PARABOLIC", "LARGE", -1200.0),
}


def _radio_for(kind: str):
    return ROLE_RADIO.get(kind, ROLE_RADIO["soldier"])


def generate(output_path: Path, *, scenario_kwargs: dict | None = None) -> dict:
    sc = DoDMissionScenario(**(scenario_kwargs or {}))

    # Wall-clock window: arbitrary but consistent with the original mission
    # YAML's time range (1 hour).  Simulator uses this for path interpolation.
    start = datetime(2025, 6, 1, 12, 0, 0)
    end = start + sc.duration

    peers = []
    for name, role in sc.peers.items():
        antenna, iface, signal = _radio_for(role.kind)
        pos = {
            "lat": role.position.lat,
            "lon": role.position.lon,
            "alt": role.position.alt if role.position.alt is not None else 0.0,
        }
        peers.append({
            "uuid": str(uuid.uuid5(uuid.NAMESPACE_DNS, f"dod-mission:{name}")),
            "kind": role.kind,
            "nickname": role.metadata.get("nickname", name),
            "ip4_addr": "",  # Docker network assigns
            "position": pos,
            "signal": signal,
            "antenna": antenna,
            "interface": iface,
            "initial_time": start.isoformat(),
            "last_seen": end.isoformat(),
            # Stationary first pass; replace with Bezier/Ellipse path_list
            # once role-based motion patterns are wired in.
            "path_list": [{"type": "point", "position": pos}],
            "data_streams": [],
            "agency": role.agency,
            "capabilities": role.capabilities,
            "join_phase": role.join_phase,
        })

    config = {
        "start": start.isoformat(),
        "end": end.isoformat(),
        "peers": peers,
    }

    import yaml
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w") as f:
        f.write(f"# Auto-generated scenario for: {sc.name}\n")
        f.write(f"# {len(peers)} peers across {len(sc.phases)} phases.\n")
        f.write("# Source: examples/dod_mission/scenario.py "
                "(via simulator/generate_scenario.py)\n\n")
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    return config


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("output", nargs="?",
                        default=str(_THIS / "scenario.yaml"),
                        help="Path to write the YAML to.")
    parser.add_argument("--squad-size", type=int, default=4)
    parser.add_argument("--swarm-size", type=int, default=4)
    parser.add_argument("--sensor-count", type=int, default=3)
    parser.add_argument("--hacked-sensors", type=int, default=2)
    parser.add_argument("--no-mq800", action="store_true")
    parser.add_argument("--no-jet", action="store_true")
    parser.add_argument("--no-command", action="store_true")
    args = parser.parse_args(argv)

    cfg = generate(Path(args.output), scenario_kwargs=dict(
        squad_size=args.squad_size,
        swarm_size=args.swarm_size,
        sensor_count=args.sensor_count,
        hacked_sensors=args.hacked_sensors,
        include_mq800=not args.no_mq800,
        include_jet=not args.no_jet,
        include_command=not args.no_command,
    ))
    print(f"Wrote {args.output}  ({len(cfg['peers'])} peers)")


if __name__ == "__main__":
    main()
