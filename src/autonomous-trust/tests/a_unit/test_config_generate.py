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

import os
import re
from unittest.mock import patch, MagicMock

from autonomous_trust.core.config import Configuration
from autonomous_trust.core.config.generate import generate_identity, _subsystems, random_config, generate_worker_config
from autonomous_trust.core.processes import ProcessTracker
from autonomous_trust.core.system import core_system, agreement_impl, communications, CfgIds

from .. import INSIDE_DOCKER, TEST_DIR


cidr_regex = r'(?:/\d{1,3})'
ipv4_regex = r'(\d{1,3}\.){3}\d{1,3}'
ipv6_regex = r'([0-9a-fA-F]{1,4}:?|:)+'
mac_regex = r'([0-9A-Fa-f]{2}:){5}(?:[0-9A-Fa-f]{2})'
hex_seed_regex = r'([0-9A-Fa-f]{86}==)'


def test_generate_identity(setup_teardown):
    net, ident, subsys = generate_identity(os.environ[Configuration.ROOT_VARIABLE_NAME], True)

    # Verify serialized output is valid JSON with expected fields
    import json
    net_json = json.loads(net.to_json_string())
    assert '__type__' in net_json
    assert 'Network' in net_json['__type__']
    assert '_ip4_cidr' in net_json
    assert '_mac_address' in net_json

    ident_json = json.loads(ident.to_json_string())
    assert '__type__' in ident_json
    assert 'Identity' in ident_json['__type__']
    assert '_nickname' in ident_json
    assert '_signature' in ident_json
    assert '_encryptor' in ident_json

    subsys_str = subsys.to_json_string()
    assert CfgIds.network in subsys_str



def test_subsystems():
    pt = _subsystems(communications)
    assert isinstance(pt, ProcessTracker)


def test_generate_randomize_with_string_seed(setup_teardown):
    cfg_dir = os.path.join(TEST_DIR, 'gen_str_seed')
    os.makedirs(cfg_dir, exist_ok=True)
    mock_addrs = {
        'ip4': '192.168.1.100',
        'ip6': '::1',
        'mac': '00:11:22:33:44:55',
        'ip4_subnet': '255.255.255.0',
        'ip6_subnet': 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
        'mac_bcast': 'ff:ff:ff:ff:ff:ff',
    }
    with patch('autonomous_trust.core.config.generate.Network.get_addresses', return_value=mock_addrs):
        net, ident, subsys = generate_identity(cfg_dir, randomize=True, seed='hello', silent=True)
    assert net is not None
    assert ident is not None


def test_generate_randomize_honors_at_peer_name(setup_teardown):
    """When AT_PEER_NAME is set, the generated identity uses it as the
    nickname (so deployment-side container labels survive into the AT
    identity protocol)."""
    cfg_dir = os.path.join(TEST_DIR, 'gen_at_peer_name')
    os.makedirs(cfg_dir, exist_ok=True)
    mock_addrs = {
        'ip4': '192.168.1.100',
        'ip6': '::1',
        'mac': '00:11:22:33:44:55',
        'ip4_subnet': '255.255.255.0',
        'ip6_subnet': 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
        'mac_bcast': 'ff:ff:ff:ff:ff:ff',
    }
    with patch.dict(os.environ, {'AT_PEER_NAME': 'noaa-1'}):
        with patch('autonomous_trust.core.config.generate.Network.get_addresses',
                   return_value=mock_addrs):
            net, ident, subsys = generate_identity(
                cfg_dir, randomize=True, seed=1, silent=True)
    assert ident.petname == 'noaa-1'
    assert ident.nickname == 'noaa-1@tekfive.com'


def test_generate_randomize_no_at_peer_name_uses_random(setup_teardown):
    """Sanity: with AT_PEER_NAME unset, the random-pool nickname survives."""
    cfg_dir = os.path.join(TEST_DIR, 'gen_no_at_peer_name')
    os.makedirs(cfg_dir, exist_ok=True)
    mock_addrs = {
        'ip4': '192.168.1.100',
        'ip6': '::1',
        'mac': '00:11:22:33:44:55',
        'ip4_subnet': '255.255.255.0',
        'ip6_subnet': 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
        'mac_bcast': 'ff:ff:ff:ff:ff:ff',
    }
    env = {k: v for k, v in os.environ.items() if k != 'AT_PEER_NAME'}
    with patch.dict(os.environ, env, clear=True):
        with patch('autonomous_trust.core.config.generate.Network.get_addresses',
                   return_value=mock_addrs):
            net, ident, subsys = generate_identity(
                cfg_dir, randomize=True, seed=1, silent=True)
    # Random-pool surnames; never 'noaa-1'.
    assert ident.petname != 'noaa-1'
    assert '@tekfive.com' in ident.nickname


def test_generate_randomize_verbose(setup_teardown, caplog):
    import logging
    cfg_dir = os.path.join(TEST_DIR, 'gen_verbose')
    os.makedirs(cfg_dir, exist_ok=True)
    mock_addrs = {
        'ip4': '192.168.1.100',
        'ip6': '::1',
        'mac': '00:11:22:33:44:55',
        'ip4_subnet': '255.255.255.0',
        'ip6_subnet': 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
        'mac_bcast': 'ff:ff:ff:ff:ff:ff',
    }
    with caplog.at_level(logging.DEBUG, logger='autonomous_trust.core._python.config.generate'):
        with patch('autonomous_trust.core.config.generate.Network.get_addresses', return_value=mock_addrs):
            generate_identity(cfg_dir, randomize=True, seed=1, silent=False)
    assert 'Wrote configs' in caplog.text


def test_random_config(setup_teardown):
    mock_addrs = {
        'ip4': '192.168.1.100',
        'ip6': '::1',
        'mac': '00:11:22:33:44:55',
        'ip4_subnet': '255.255.255.0',
        'ip6_subnet': 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
        'mac_bcast': 'ff:ff:ff:ff:ff:ff',
    }
    base_dir = os.path.join(TEST_DIR, 'rand_cfg')
    os.makedirs(base_dir, exist_ok=True)
    with patch('autonomous_trust.core.config.generate.Network.get_addresses', return_value=mock_addrs):
        random_config(base_dir)


def test_random_config_with_ident(setup_teardown):
    mock_addrs = {
        'ip4': '192.168.1.100',
        'ip6': '::1',
        'mac': '00:11:22:33:44:55',
        'ip4_subnet': '255.255.255.0',
        'ip6_subnet': 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
        'mac_bcast': 'ff:ff:ff:ff:ff:ff',
    }
    base_dir = os.path.join(TEST_DIR, 'rand_cfg2')
    os.makedirs(base_dir, exist_ok=True)
    with patch('autonomous_trust.core.config.generate.Network.get_addresses', return_value=mock_addrs):
        random_config(base_dir, ident='node1')


def test_generate_worker_existing_file(setup_teardown):
    cfg_dir = os.path.join(TEST_DIR, 'worker_test')
    os.makedirs(cfg_dir, exist_ok=True)
    cfg_file = os.path.join(cfg_dir, 'testproc' + Configuration.file_ext)
    with open(cfg_file, 'w') as f:
        f.write('test')
    # Should do nothing since file already exists
    generate_worker_config(cfg_dir, 'testproc', MagicMock, defaults=True)


def test_generate_identity_interactive_eof(setup_teardown):
    """Test generate_identity interactive path with EOFError from input."""
    cfg_dir = os.path.join(TEST_DIR, 'gen_interactive_eof')
    os.makedirs(cfg_dir, exist_ok=True)
    mock_addrs = {
        'ip4': '192.168.1.100',
        'ip6': '::1',
        'mac': '00:11:22:33:44:55',
        'ip4_subnet': '255.255.255.0',
        'ip6_subnet': 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
        'mac_bcast': 'ff:ff:ff:ff:ff:ff',
    }
    with patch('autonomous_trust.core.config.generate.Network.get_addresses', return_value=mock_addrs):
        with patch('builtins.input', side_effect=EOFError):
            net, ident, subsys = generate_identity(cfg_dir, randomize=False, preserve=False, defaults=True, silent=True)
    assert net is not None
    assert ident is not None


def test_generate_identity_eof_honors_at_peer_name(setup_teardown):
    """Non-interactive container path (input → EOFError) must still
    honor AT_PEER_NAME, the same as the randomize=True branch already
    does. Without this, every participant pod gets a random-pool
    nickname like 'ClearDale' and the inspector reputations panel
    can't show scenario role names ('mq800', 'microdrone-1'). See
    dod-demo-implementation-plan.md Phase 6 #6.
    """
    cfg_dir = os.path.join(TEST_DIR, 'gen_eof_at_peer_name')
    os.makedirs(cfg_dir, exist_ok=True)
    mock_addrs = {
        'ip4': '192.168.1.100',
        'ip6': '::1',
        'mac': '00:11:22:33:44:55',
        'ip4_subnet': '255.255.255.0',
        'ip6_subnet': 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
        'mac_bcast': 'ff:ff:ff:ff:ff:ff',
    }
    with patch.dict(os.environ, {'AT_PEER_NAME': 'mq800'}):
        with patch('autonomous_trust.core.config.generate.Network.get_addresses',
                   return_value=mock_addrs):
            with patch('builtins.input', side_effect=EOFError):
                net, ident, subsys = generate_identity(
                    cfg_dir, randomize=False, preserve=False,
                    defaults=True, silent=True)
    assert ident.petname == 'mq800'
    assert ident.nickname == 'mq800@tekfive.com'


def test_generate_identity_with_defaults(setup_teardown):
    """Test non-randomize path with defaults=True (skips input for network)."""
    cfg_dir = os.path.join(TEST_DIR, 'gen_defaults')
    os.makedirs(cfg_dir, exist_ok=True)
    mock_addrs = {
        'ip4': '192.168.1.100',
        'ip6': '::1',
        'mac': '00:11:22:33:44:55',
        'ip4_subnet': '255.255.255.0',
        'ip6_subnet': 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
        'mac_bcast': 'ff:ff:ff:ff:ff:ff',
    }
    inputs = iter(['testname', 'nick', ''])  # FQDN name (->nickname), petname, net_impl (empty=default)
    with patch('autonomous_trust.core.config.generate.Network.get_addresses', return_value=mock_addrs):
        with patch('builtins.input', side_effect=inputs):
            net, ident, subsys = generate_identity(cfg_dir, randomize=False, preserve=False, defaults=True)
    assert net is not None


def test_generate_worker_config_no_existing(setup_teardown):
    """Test generate_worker_config when file doesn't exist."""
    from autonomous_trust.core.config.configuration import InitializableConfig
    cfg_dir = os.path.join(TEST_DIR, 'worker_new')
    os.makedirs(cfg_dir, exist_ok=True)

    class MockConfig(InitializableConfig):
        @staticmethod
        def initialize(name: str, count: int = 5):
            cfg = MockConfig()
            cfg.name = name
            cfg.count = count
            return cfg

    with patch('builtins.input', side_effect=['myname']):
        generate_worker_config(cfg_dir, 'mockproc', MockConfig, defaults=True)


def test_random_config_existing_configs(setup_teardown):
    """Test random_config when configs already exist."""
    base_dir = os.path.join(TEST_DIR, 'rand_existing')
    cfg_dir = os.path.join(base_dir, Configuration.CFG_PATH)
    os.makedirs(cfg_dir, exist_ok=True)
    # Create a dummy config file
    with open(os.path.join(cfg_dir, 'test' + Configuration.file_ext), 'w') as f:
        f.write('test')
    mock_addrs = {
        'ip4': '192.168.1.100',
        'ip6': '::1',
        'mac': '00:11:22:33:44:55',
        'ip4_subnet': '255.255.255.0',
        'ip6_subnet': 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
        'mac_bcast': 'ff:ff:ff:ff:ff:ff',
    }
    with patch('autonomous_trust.core.config.generate.Network.get_addresses', return_value=mock_addrs):
        random_config(base_dir)


def test_generate_identity_name_empty_uses_hostname(setup_teardown):
    """Test interactive path where the FQDN-name input is empty — falls back to hostname (line 108)."""
    cfg_dir = os.path.join(TEST_DIR, 'gen_hostname_fallback')
    os.makedirs(cfg_dir, exist_ok=True)
    mock_addrs = {
        'ip4': '192.168.1.100',
        'ip6': '::1',
        'mac': '00:11:22:33:44:55',
        'ip4_subnet': '255.255.255.0',
        'ip6_subnet': 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
        'mac_bcast': 'ff:ff:ff:ff:ff:ff',
    }
    # Empty string for the FQDN name triggers the hostname fallback (line 108).
    # Then: petname, net_impl (all default via empty string), and
    # three overwrite prompts for net/ident/subsys files (answer 'y').
    inputs = iter(['', 'testnick', '', 'y', 'y', 'y'])
    with patch('autonomous_trust.core.config.generate.Network.get_addresses', return_value=mock_addrs):
        with patch('builtins.input', side_effect=inputs):
            net, ident, subsys = generate_identity(cfg_dir, randomize=False, preserve=False, defaults=True)
    assert net is not None
    assert ident is not None


def test_generate_identity_non_default_addresses(setup_teardown):
    """Test non-defaults interactive path for IP4/IP6/MAC address input (lines 119-127)."""
    cfg_dir = os.path.join(TEST_DIR, 'gen_custom_addrs')
    os.makedirs(cfg_dir, exist_ok=True)
    mock_addrs = {
        'ip4': '192.168.1.100',
        'ip6': '::1',
        'mac': '00:11:22:33:44:55',
        'ip4_subnet': '255.255.255.0',
        'ip6_subnet': 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
        'mac_bcast': 'ff:ff:ff:ff:ff:ff',
    }
    # FQDN name (->nickname), petname (non-interactive ident), then custom IP4, custom IP6, custom MAC,
    # net_impl (empty = default), and three overwrite prompts for config files
    inputs = iter([
        'custom.user@example.com',  # FQDN name (->nickname)
        'customnick',               # petname
        '10.0.0.1',                 # IP4 (non-empty, non-default)
        '::2',                      # IP6 (non-empty, non-default)
        'AA:BB:CC:DD:EE:FF',        # MAC (non-empty, non-default)
        '',                         # net_impl (empty = default)
        'y', 'y', 'y',             # overwrite prompts
    ])
    with patch('autonomous_trust.core.config.generate.Network.get_addresses', return_value=mock_addrs):
        with patch('builtins.input', side_effect=inputs):
            net, ident, subsys = generate_identity(cfg_dir, randomize=False, preserve=False, defaults=False)
    assert net is not None
    assert ident is not None


def test_generate_identity_empty_address_inputs_use_defaults(setup_teardown):
    """Test non-defaults interactive path where IP inputs are empty — fall back to detected values (lines 120-127)."""
    cfg_dir = os.path.join(TEST_DIR, 'gen_empty_addrs')
    os.makedirs(cfg_dir, exist_ok=True)
    mock_addrs = {
        'ip4': '192.168.1.100',
        'ip6': '::1',
        'mac': '00:11:22:33:44:55',
        'ip4_subnet': '255.255.255.0',
        'ip6_subnet': 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
        'mac_bcast': 'ff:ff:ff:ff:ff:ff',
    }
    # Empty inputs for addresses exercise the "if addr == '': addr = detected" branches
    inputs = iter([
        'user@example.com',  # FQDN name (->nickname)
        'usernick',          # petname
        '',                  # IP4 empty -> use detected
        '',                  # IP6 empty -> use detected
        '',                  # MAC empty -> use detected
        '',                  # net_impl empty -> default
        'y', 'y', 'y',     # overwrite prompts
    ])
    with patch('autonomous_trust.core.config.generate.Network.get_addresses', return_value=mock_addrs):
        with patch('builtins.input', side_effect=inputs):
            net, ident, subsys = generate_identity(cfg_dir, randomize=False, preserve=False, defaults=False)
    assert net is not None


def test_generate_identity_overwrite_prompt_yes(setup_teardown):
    """Test overwrite confirmation prompt when config files already exist and user says 'y' (lines 154-156)."""
    cfg_dir = os.path.join(TEST_DIR, 'gen_overwrite_yes')
    os.makedirs(cfg_dir, exist_ok=True)
    mock_addrs = {
        'ip4': '192.168.1.100',
        'ip6': '::1',
        'mac': '00:11:22:33:44:55',
        'ip4_subnet': '255.255.255.0',
        'ip6_subnet': 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
        'mac_bcast': 'ff:ff:ff:ff:ff:ff',
    }
    # First pass: create all three config files via randomize
    with patch('autonomous_trust.core.config.generate.Network.get_addresses', return_value=mock_addrs):
        generate_identity(cfg_dir, randomize=True, seed=7, silent=True)

    # Second pass: non-randomize with preserve=False so existing files trigger overwrite prompt.
    # The prompt fires once per file (3 files).  Reply 'y' to each.
    inputs = iter([
        'user@example.com',  # FQDN name (->nickname)
        'usernick',          # petname
        '',                  # net_impl empty -> default
        'y',                 # overwrite network config
        'y',                 # overwrite identity config
        'y',                 # overwrite subsystem config
    ])
    with patch('autonomous_trust.core.config.generate.Network.get_addresses', return_value=mock_addrs):
        with patch('builtins.input', side_effect=inputs):
            net, ident, subsys = generate_identity(cfg_dir, randomize=False, preserve=False, defaults=True)
    assert net is not None


def test_generate_identity_overwrite_prompt_no(setup_teardown):
    """Test overwrite confirmation prompt where user declines ('N') — files kept (line 154)."""
    cfg_dir = os.path.join(TEST_DIR, 'gen_overwrite_no')
    os.makedirs(cfg_dir, exist_ok=True)
    mock_addrs = {
        'ip4': '192.168.1.100',
        'ip6': '::1',
        'mac': '00:11:22:33:44:55',
        'ip4_subnet': '255.255.255.0',
        'ip6_subnet': 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
        'mac_bcast': 'ff:ff:ff:ff:ff:ff',
    }
    # Create files first
    with patch('autonomous_trust.core.config.generate.Network.get_addresses', return_value=mock_addrs):
        generate_identity(cfg_dir, randomize=True, seed=8, silent=True)

    # Second pass: decline overwrite for all files
    inputs = iter([
        'user@example.com',  # FQDN name (->nickname)
        'usernick',          # petname
        '',                  # net_impl empty -> default
        'N',                 # decline overwrite network config
        'N',                 # decline overwrite identity config
        'N',                 # decline overwrite subsystem config
    ])
    with patch('autonomous_trust.core.config.generate.Network.get_addresses', return_value=mock_addrs):
        with patch('builtins.input', side_effect=inputs):
            net, ident, subsys = generate_identity(cfg_dir, randomize=False, preserve=False, defaults=True)
    # Function returns objects regardless of whether files were written
    assert net is not None


class _TypedWorkerConfig(MagicMock.__class__.__bases__[0]):
    """Module-level config class used by test_generate_worker_config_with_type_annotation.

    Must be at module level so the YAML constructor can import it by name.
    Inherits from InitializableConfig to satisfy the generate_worker_config type hint.
    """


# Re-import at module level for the typed annotation test
from autonomous_trust.core.config.configuration import InitializableConfig as _IC


class _TypedConfig(_IC):
    def __init__(self, count=0, label='default'):
        self.count = count
        self.label = label

    @classmethod
    def initialize(cls, count: int, label: str = 'init'):
        return cls(count=count, label=label)


def test_generate_worker_config_with_type_annotation(setup_teardown):
    """Test generate_worker_config applies type annotation to convert input (lines 201-202).

    'count' has no default — exercises line 200 (bare input prompt).
    Both 'count' and 'label' have annotations — exercises line 202 (ann[name](arg)).
    'label' has a default and defaults=False — exercises line 196 (input with default).
    """
    cfg_dir = os.path.join(TEST_DIR, 'worker_typed')
    os.makedirs(cfg_dir, exist_ok=True)

    # 'count' has no default -> line 200: arg = input('  count: ')
    #   annotation int -> line 202: arg = int('5') = 5
    # 'label' has default 'init', defaults=False -> line 196: arg = input(...)
    #   annotation str -> line 202: arg = str('custom_label') = 'custom_label'
    with patch('builtins.input', side_effect=['5', 'custom_label']):
        generate_worker_config(cfg_dir, 'typedproc', _TypedConfig, defaults=False)

    cfg_file = os.path.join(cfg_dir, 'typedproc' + Configuration.file_ext)
    assert os.path.exists(cfg_file)
