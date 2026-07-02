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
"""Extra tests for config/generate.py - covering interactive and worker paths."""
import os
from unittest.mock import patch, MagicMock

import pytest

from autonomous_trust.core.config import Configuration
from autonomous_trust.core.config.configuration import InitializableConfig
from autonomous_trust.core.config.generate import generate_identity, generate_worker_config, random_config
from autonomous_trust.core.processes import ProcessTracker

from .. import TEST_DIR


MOCK_ADDRS = {
    'ip4': '192.168.1.100/24',
    'ip6': '::1/128',
    'mac': '00:11:22:33:44:55',
    'ip4_subnet': '255.255.255.0',
    'ip6_subnet': 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
    'mac_bcast': 'ff:ff:ff:ff:ff:ff',
}


def test_generate_identity_preserve_existing(setup_teardown):
    """Test preserve=True skips existing files."""
    cfg_dir = os.path.join(TEST_DIR, 'gen_preserve')
    os.makedirs(cfg_dir, exist_ok=True)
    # First create files
    with patch('autonomous_trust.core.config.generate.Network.get_addresses', return_value=MOCK_ADDRS):
        net1, ident1, _ = generate_identity(cfg_dir, randomize=True, seed=42, silent=True)
    # Now call with preserve=True
    with patch('autonomous_trust.core.config.generate.Network.get_addresses', return_value=MOCK_ADDRS):
        with patch('builtins.input', side_effect=EOFError):
            net2, ident2, _ = generate_identity(cfg_dir, preserve=True)
    # Preserved files should be loaded from disk
    assert net2 is not None


def test_random_config_with_env_var(setup_teardown):
    """Test random_config when ROOT_VARIABLE_NAME is set."""
    base_dir = os.path.join(TEST_DIR, 'rand_env')
    cfg_dir = os.path.join(base_dir, Configuration.CFG_PATH)
    os.makedirs(cfg_dir, exist_ok=True)
    with patch('autonomous_trust.core.config.generate.Network.get_addresses', return_value=MOCK_ADDRS):
        random_config(base_dir)
    assert Configuration.ROOT_VARIABLE_NAME in os.environ


class SimpleInitCfg(InitializableConfig):
    def __init__(self, name='default', count=5):
        self.name = name
        self.count = count

    @classmethod
    def initialize(cls, name: str = 'init', count: int = 3):
        return cls(name=name, count=count)


def test_generate_worker_config_defaults(setup_teardown):
    """Test generate_worker_config with defaults=True."""
    cfg_dir = os.path.join(TEST_DIR, 'worker_defaults')
    os.makedirs(cfg_dir, exist_ok=True)
    generate_worker_config(cfg_dir, 'testproc', SimpleInitCfg, defaults=True)
    cfg_file = os.path.join(cfg_dir, 'testproc' + Configuration.file_ext)
    assert os.path.exists(cfg_file)


def test_generate_worker_config_custom_input(setup_teardown):
    """Test generate_worker_config with user input."""
    cfg_dir = os.path.join(TEST_DIR, 'worker_input')
    os.makedirs(cfg_dir, exist_ok=True)
    with patch('builtins.input', side_effect=['myname', '10']):
        generate_worker_config(cfg_dir, 'customproc', SimpleInitCfg, defaults=False)
    cfg_file = os.path.join(cfg_dir, 'customproc' + Configuration.file_ext)
    assert os.path.exists(cfg_file)
