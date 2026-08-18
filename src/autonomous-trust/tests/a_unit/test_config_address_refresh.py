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
"""A config directory outlives the address it recorded, so
Automate re-derives the address at load when the stored one is no longer
present on this host -- and leaves it alone when it is."""
import json
import os
import socket
from unittest.mock import patch, MagicMock

import pytest

from autonomous_trust.core.automate import AutonomousTrust
from autonomous_trust.core.config import Configuration
from autonomous_trust.core.config.generate import generate_identity
from autonomous_trust.core.system import CfgIds

_LIVE = {
    'ip4': '10.4.0.9', 'ip6': None, 'mac': 'aa:bb:cc:dd:ee:ff',
    'ip4_subnet': '255.255.255.0', 'ip6_subnet': None,
    'mac_bcast': 'ff:ff:ff:ff:ff:ff', 'device': 'eth1',
}


def _live_interfaces():
    """psutil.net_if_addrs() shaped to agree with _LIVE."""
    entry = MagicMock()
    entry.family = socket.AF_INET
    entry.address = _LIVE['ip4']
    entry.netmask = _LIVE['ip4_subnet']
    loop = MagicMock()
    loop.family = socket.AF_INET
    loop.address = '127.0.0.1'
    loop.netmask = '255.0.0.0'
    return {'lo': [loop], 'eth1': [entry]}


@pytest.fixture
def cfg_dir(tmp_path):
    path = tmp_path / 'etc' / 'at'
    path.mkdir(parents=True)
    with patch('autonomous_trust.core.config.generate.Network.get_addresses',
               return_value=_LIVE):
        generate_identity(str(path), randomize=True, seed=1, silent=True)
    with patch.dict(os.environ, {Configuration.ROOT_VARIABLE_NAME: str(path)}):
        yield path


def _net_file(cfg_dir):
    return os.path.join(str(cfg_dir), CfgIds.network + Configuration.file_ext)


def _stored_ip4(cfg_dir):
    with open(_net_file(cfg_dir), 'r') as net:
        return json.load(net)['_ip4_cidr']


def _configure(cfg_dir):
    at = AutonomousTrust(logfile=Configuration.log_stdout)
    with patch('autonomous_trust.core.network.network.psutil.net_if_addrs',
               side_effect=_live_interfaces), \
         patch('autonomous_trust.core.network.network.Network.get_addresses',
               return_value=_LIVE):
        return at._configure(start=False)


def test_generated_config_records_the_discovered_cidr(cfg_dir):
    assert _stored_ip4(cfg_dir) == '10.4.0.9/24'


def test_valid_stored_address_is_left_alone(cfg_dir):
    configs = _configure(cfg_dir)
    assert configs[CfgIds.network].ip4 == '10.4.0.9'
    assert _stored_ip4(cfg_dir) == '10.4.0.9/24'


def test_stale_stored_address_is_rederived_and_persisted(cfg_dir):
    """The container-moved-subnet case: var/at survived, the IP did not."""
    with open(_net_file(cfg_dir), 'r') as net:
        data = json.load(net)
    data['_ip4_cidr'] = '192.168.99.7/24'
    with open(_net_file(cfg_dir), 'w') as net:
        json.dump(data, net, indent=2)

    configs = _configure(cfg_dir)
    assert configs[CfgIds.network].ip4 == '10.4.0.9'
    # the identity address follows the re-derived one, since that is what
    # peers will see us answer on
    assert configs[CfgIds.identity].address == '10.4.0.9'
    assert _stored_ip4(cfg_dir) == '10.4.0.9/24'
