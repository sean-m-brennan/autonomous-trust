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
"""The verification layers as the core finds them (FEATURE_SPLIT_PLAN Phase 3).

Pins: the core's discovery finds this distribution with nothing but the source
tree on the path (its ``_at_extension.py`` marker), the five layers are then
declared, their arms reproduce the scorer's fixed sequence, and a node
declaring every layer starts. The registry itself is tested in the core
(tests/a_unit/test_oracles.py).
"""
from autonomous_trust.core import oracles
from autonomous_trust.core.extensions import all_extensions


def setup_module():
    oracles.load()


def test_discovery_finds_this_distribution():
    from autonomous_trust.oracle._at_extension import EXTENSION
    exts = [e for e in all_extensions() if e.name == 'oracle']
    assert exts == [EXTENSION]     # found once, however many ways


class TestRegisteredLayers:
    """The real registry, as the layers left it at import."""

    def test_the_five_are_declared(self):
        for name in ('physics', 'calibration', 'certificates', 'prequential',
                     'replication'):
            assert oracles.present(name), name

    def test_arms_reproduce_the_scorer_sequence(self):
        assert [(a.name, a.order, a.observe is not None)
                for a in oracles.arms()] == [
            ('physics.check', 100, False),
            ('calibration.settle', 200, True),
            ('prequential.observe', 210, True),
            ('certificates.check', 300, False),
            ('calibration.assess', 400, False),
        ]

    def test_a_node_with_every_layer_starts(self, monkeypatch, tmp_path):
        from autonomous_trust.core.config import Configuration
        monkeypatch.setenv(Configuration.ROOT_VARIABLE_NAME, str(tmp_path))
        for env, _ in oracles.DECLARATIONS:
            monkeypatch.setenv(env, '/nonexistent/declaration.json')
        oracles.check_env()
        # The node itself, through its own load -> check_env.
        from autonomous_trust.core.automate import AutonomousTrust
        AutonomousTrust(multiproc=False, silent=True,
                        logfile=Configuration.log_stdout).cleanup()
