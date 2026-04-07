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

"""Docker-compose generator for asteroid belt scenario.

Wraps gen_compose.generate_compose() and patches the output YAML
with asteroid belt habitat metadata (orbital parameters, comm interfaces).
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
from .scenario import HABITATS  # noqa: E402


def generate_asteroid_belt_compose(
    backend: str = "native",
    log_level: str = "info",
    exclude_logs: str = "network",
    metrics_dir: str = "",
    habitats: Optional[list[dict]] = None,
) -> str:
    """Generate docker-compose YAML for asteroid belt scenario.

    Args:
        backend: AT backend selection (native/python).
        log_level: Logging verbosity.
        exclude_logs: Log categories to exclude.
        metrics_dir: Host directory to mount for metrics output.
        habitats: Optional override for HABITATS list.

    Returns:
        YAML string for docker-compose.
    """
    if habitats is None:
        habitats = HABITATS

    num_nodes = len(habitats)
    base_yaml = generate_compose(num_nodes, exclude_logs, log_level, backend,
                                 metrics_dir)
    data = yaml.safe_load(base_yaml)

    # Rebuild services with habitat names and metadata
    old_services = data.get('services', {})
    new_services = {}
    for idx, hab in enumerate(habitats):
        old_key = 'at-%d' % (idx + 1)
        svc = old_services.get(old_key, {})
        if not svc:
            continue

        name = hab['name']

        # Update container/hostname to match habitat name
        svc['container_name'] = name
        svc['hostname'] = name

        # Add scenario metadata as environment variables
        env = svc.get('environment', {})
        env['SPACE_HABITAT_NAME'] = name
        env['SPACE_SEMI_MAJOR_AU'] = str(hab['semi_major_au'])
        env['SPACE_ECCENTRICITY'] = str(hab['eccentricity'])
        env['SPACE_ANGLE_DEG'] = str(hab['angle_deg'])
        env['SPACE_IFACE'] = hab['iface'].value
        env['SPACE_MODE'] = 'true'
        svc['environment'] = env

        new_services[name] = svc

    data['services'] = new_services
    return yaml.dump(data, default_flow_style=False, sort_keys=False)
