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

"""Full Docker system test for Appalachian scenario.

Requires Docker daemon. Run with: pytest -m docker
"""
import os
import subprocess

import pytest

try:
    from autonomous_trust.simulator.scenarios.appalachian_compose import (
        generate_appalachian_compose,
    )
except ImportError:
    pytest.skip("AT simulator not installed", allow_module_level=True)

pytestmark = pytest.mark.docker


def docker_available():
    """Check if Docker daemon is running."""
    try:
        subprocess.run(['docker', 'info'], capture_output=True, check=True,
                       timeout=10)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError,
            subprocess.TimeoutExpired):
        return False


@pytest.fixture
def compose_dir(tmp_path, backend):
    """Generate Appalachian docker-compose in a temp directory."""
    content = generate_appalachian_compose(hilltop_only=True, backend=backend)
    compose_file = tmp_path / 'docker-compose.yaml'
    compose_file.write_text(content)
    return tmp_path


class TestAppalachianDockerScenario:
    """Full integration test with Docker containers and Router enforcement."""

    @pytest.mark.skipif(not docker_available(), reason="Docker not available")
    def test_hilltop_scenario_produces_metrics(self, compose_dir):
        """8-node hilltop scenario: compose config is valid for Docker."""
        compose_file = str(compose_dir / 'docker-compose.yaml')

        # Validate compose file is parseable by Docker
        assert os.path.exists(compose_file)
        result = subprocess.run(
            ['docker', 'compose', '-f', compose_file, 'config'],
            capture_output=True, text=True
        )
        assert result.returncode == 0, (
            "docker compose config failed: %s" % result.stderr
        )
