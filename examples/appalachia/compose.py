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

"""Docker-compose generator for Appalachian mesh scenario.

Wraps gen_compose.generate_compose() and patches the output YAML
with Appalachian scenario metadata (node names, coordinates, antenna
types, terrain config path).
"""

import os
import sys
from typing import Optional

import yaml

# gen_compose.py is at the autonomous_trust repo root
_AT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                         '..', '..', '..', '..', '..'))
if _AT_ROOT not in sys.path:
    sys.path.insert(0, _AT_ROOT)

from gen_compose import generate_compose  # noqa: E402
from .scenario import HILLTOP_NODES, VALLEY_NODES  # noqa: E402


def generate_appalachian_compose(
    hilltop_only: bool = False,
    terrain_config: Optional[str] = None,
    backend: str = "native",
    log_level: str = "info",
    exclude_logs: str = "network",
    metrics_dir: str = "",
) -> str:
    """Generate docker-compose YAML for Appalachian scenario.

    Wraps gen_compose.generate_compose() for the correct node count,
    then patches service names and adds scenario metadata as env vars.

    Args:
        hilltop_only: If True, only 8 hilltop relay nodes.
        terrain_config: Path to terrain path-loss CSV (mounted in container).
        backend: AT backend selection (native/python).
        log_level: Logging verbosity.
        exclude_logs: Log categories to exclude.
        metrics_dir: Host directory to mount for metrics output.

    Returns:
        YAML string for docker-compose.
    """
    nodes = list(HILLTOP_NODES)
    if not hilltop_only:
        nodes.extend(VALLEY_NODES)

    num_nodes = len(nodes)
    base_yaml = generate_compose(num_nodes, exclude_logs, log_level, backend,
                                 metrics_dir)
    data = yaml.safe_load(base_yaml)

    # Rebuild services with Appalachian node names and metadata
    old_services = data.get('services', {})
    new_services = {}
    for idx, (name, lat, lon, elev) in enumerate(nodes):
        old_key = 'at-%d' % (idx + 1)
        svc = old_services.get(old_key, {})
        if not svc:
            continue

        # Update container/hostname to match node name
        svc['container_name'] = name
        svc['hostname'] = name

        # Add scenario metadata as environment variables
        env = svc.get('environment', {})
        env['APPALACHIAN_NODE_NAME'] = name
        env['APPALACHIAN_LAT'] = str(lat)
        env['APPALACHIAN_LON'] = str(lon)
        env['APPALACHIAN_ELEV_M'] = str(elev)
        env['APPALACHIAN_TIER'] = (
            'hilltop' if idx < len(HILLTOP_NODES) else 'valley')
        if terrain_config:
            env['TERRAIN_CONFIG'] = terrain_config
        svc['environment'] = env

        new_services[name] = svc

    data['services'] = new_services
    return yaml.dump(data, default_flow_style=False, sort_keys=False)
