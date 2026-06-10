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

Loader format: writes JSON (with a `.yaml` extension for filename
continuity with the original mission demo and multi-agency).
`autonomous_trust.simulator.sim_data.SimConfig.load` routes the file
contents through `json.loads` via `Configuration.from_string`, so the
on-disk bytes must be JSON regardless of extension. An earlier
revision emitted PyYAML output and surfaced a `JSONDecodeError` in
the simulator pod; the docstring's prior speculation about a YAML
loader path in `Configuration` turned out not to exist, so resolution
(b) — emit JSON — is the active fix. Multi-agency carries the same
mismatch; treat this as the template if/when that side gets fixed.
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


from autonomous_trust.services.peer.position import GeoPosition, UTMPosition  # noqa: E402
from autonomous_trust.simulator.peer.peer import PeerInfo  # noqa: E402
from autonomous_trust.simulator.peer.path import (  # noqa: E402
    PathData, PointData, Variability,
)
from autonomous_trust.simulator.radio.iface import Antenna, NetInterface  # noqa: E402
from autonomous_trust.simulator.sim_data import SimConfig  # noqa: E402

# Per-role radio profile.  Conservative defaults; refine after radio
# modeling.
ROLE_RADIO = {
    "soldier":       (Antenna.DIPOLE,    NetInterface.SMALL, -200.0),
    "microdrone":    (Antenna.DIPOLE,    NetInterface.SMALL, -200.0),
    "recon-drone":   (Antenna.PARABOLIC, NetInterface.LARGE, -1200.0),
    "armed-drone":   (Antenna.PARABOLIC, NetInterface.LARGE, -1200.0),
    "ground-sensor": (Antenna.DIPOLE,    NetInterface.SMALL, -200.0),
    "fighter-jet":   (Antenna.YAGI,      NetInterface.LARGE, -1200.0),
    "command-node":  (Antenna.PARABOLIC, NetInterface.LARGE, -1200.0),
}


def _radio_for(kind: str):
    return ROLE_RADIO.get(kind, ROLE_RADIO["soldier"])


def generate(output_path: Path, *, scenario_kwargs: dict | None = None) -> SimConfig:
    sc = DoDMissionScenario(**(scenario_kwargs or {}))

    # Wall-clock window: arbitrary but consistent with the original mission
    # YAML's time range.  Simulator uses this for path interpolation.
    start = datetime(2025, 6, 1, 12, 0, 0)
    end = start + sc.duration

    peers = []
    for name, role in sc.peers.items():
        antenna, iface, signal = _radio_for(role.kind)
        # GeoPosition → UTMPosition: PathData/ShapeData want metric
        # coordinates so distance + bearing math stays linear; the
        # simulator internally converts on the boundary anyway.
        alt = role.position.alt if role.position.alt is not None else 0.0
        utm_pos = GeoPosition(role.position.lat,
                              role.position.lon,
                              alt).convert(UTMPosition)
        # Stationary first pass: a single PointData on the peer's home
        # location. Replace with BezierData / EllipseData when role-
        # based motion patterns are wired in (squad approach,
        # microdrone sweep, RQ-86 orbit, jet ingress).
        shape = PointData(utm_pos)
        path = PathData(start, end, shape, Variability.UNIFORM, 0.0,
                        Variability.UNIFORM)
        peers.append(PeerInfo(
            str(uuid.uuid5(uuid.NAMESPACE_DNS, f"dod-mission:{name}")),
            role.kind,
            role.metadata.get("nickname", name),
            "",                   # ip4_addr — docker network assigns
            utm_pos,
            signal,
            antenna,
            iface,
            start,
            end,
            [path],
            [],                   # data_streams
        ))

    config = SimConfig(start=start, end=end, peers=peers)

    # SimConfig.to_json_string() uses Configuration.ConfigJSONEncoder,
    # which tags datetime / UUID / Enum / Configuration subclasses with
    # `__type__` markers so SimConfig.load (which routes through
    # json.loads + config_json_decoder) can reconstruct them. Anything
    # else (e.g. PyYAML output, plain ISO strings) lands as opaque
    # dicts/strings and the loader produces a SimConfig with a string
    # in `.start`, killing the simulator on its first `self.end -
    # self.start` arithmetic. The `.yaml` filename extension is a
    # historical carryover from the original mission demo.
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w") as f:
        f.write(config.to_json_string())

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
    print(f"Wrote {args.output}  ({len(cfg.peers)} peers)")


if __name__ == "__main__":
    main()
