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

import yaml
import pytest

try:
    from autonomous_trust.simulator.scenarios.appalachian_compose import (
        generate_appalachian_compose,
    )
except ImportError:
    pytest.skip("scenarios not available", allow_module_level=True)


class TestAppalachianCompose:
    def test_generates_valid_yaml(self, backend):
        """Output is parseable YAML with services and networks."""
        content = generate_appalachian_compose(hilltop_only=True, backend=backend)
        data = yaml.safe_load(content)
        assert 'services' in data
        assert 'networks' in data

    def test_hilltop_only_has_8_services(self, backend):
        """hilltop_only=True produces 8 AT node services."""
        content = generate_appalachian_compose(hilltop_only=True, backend=backend)
        data = yaml.safe_load(content)
        services = data['services']
        assert len(services) == 8

    def test_full_scenario_has_20_services(self, backend):
        """Full scenario produces 20 AT node services."""
        content = generate_appalachian_compose(hilltop_only=False, backend=backend)
        data = yaml.safe_load(content)
        services = data['services']
        assert len(services) == 20

    def test_services_have_scenario_metadata(self, backend):
        """Each service has APPALACHIAN_NODE_NAME env var."""
        content = generate_appalachian_compose(hilltop_only=True, backend=backend)
        data = yaml.safe_load(content)
        for svc_name, svc in data['services'].items():
            env = svc.get('environment', {})
            assert 'APPALACHIAN_NODE_NAME' in env

    def test_preserves_net_admin(self, backend):
        """Services retain NET_ADMIN capability from gen_compose."""
        content = generate_appalachian_compose(hilltop_only=True, backend=backend)
        data = yaml.safe_load(content)
        first_svc = list(data['services'].values())[0]
        assert 'NET_ADMIN' in first_svc.get('cap_add', [])

    def test_terrain_config_path_in_env(self, backend):
        """When terrain_config provided, it appears in env vars."""
        content = generate_appalachian_compose(
            hilltop_only=True, terrain_config='/data/terrain.csv', backend=backend)
        data = yaml.safe_load(content)
        first_svc = list(data['services'].values())[0]
        env = first_svc.get('environment', {})
        assert env.get('TERRAIN_CONFIG') == '/data/terrain.csv'

    def test_backend_in_env(self, backend):
        """Selected backend appears in container environment."""
        content = generate_appalachian_compose(hilltop_only=True, backend=backend)
        data = yaml.safe_load(content)
        first_svc = list(data['services'].values())[0]
        env = first_svc.get('environment', {})
        assert env.get('AUTONOMOUS_TRUST_BACKEND') == backend
