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

import json
import os
import shutil
import time
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

from autonomous_trust.core import AutonomousTrust, Process, CfgIds
from autonomous_trust.core.config import Configuration
from autonomous_trust.core.config.generate import generate_identity

from . import PRESERVE_FILES, TEST_DIR

_MOCK_ADDRESSES = {
    'ip4': '192.168.1.100',
    'ip6': '::1',
    'mac': '00:11:22:33:44:55',
    'ip4_subnet': '255.255.255.0',
    'ip6_subnet': 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
    'mac_bcast': 'ff:ff:ff:ff:ff:ff',
}

base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def setup(local_net=False):
    test_dir = os.path.join(TEST_DIR, 'etc/at')
    os.makedirs(test_dir, exist_ok=True)
    os.environ[Configuration.ROOT_VARIABLE_NAME] = test_dir
    with patch('autonomous_trust.core.network.network.Network.get_addresses', return_value=_MOCK_ADDRESSES):
        generate_identity(test_dir, True)
    if local_net:
        net_cfg_file = os.path.join(test_dir, CfgIds.network + Configuration.file_ext)
        with open(net_cfg_file, 'r') as net:
            data = json.load(net)
        data['_ip4_cidr'] = '127.0.0.1/8'
        data['_port'] = None
        with open(net_cfg_file, 'w') as net:
            json.dump(data, net, indent=2)


def teardown():
    if not PRESERVE_FILES and os.path.isdir(TEST_DIR):
        shutil.rmtree(TEST_DIR)


@pytest.fixture(scope="session")
def setup_teardown():
    setup()
    yield
    teardown()


@pytest.fixture(scope="session")
def setup_local_net_teardown():
    setup(True)
    yield
    teardown()


class QuickTrust(AutonomousTrust):
    default_runtime = 20

    def __init__(self, runtime=None, **kwargs):
        super().__init__(**kwargs)
        self.exceptions = []
        self.runtime = runtime
        if runtime is None:
            self.runtime = self.default_runtime
        self.debug = False

    def autonomous_loop(self, results, queues, signals):
        start = datetime.now(UTC)
        end = start + timedelta(seconds=self.runtime)
        if self.debug:
            print()
        while datetime.now(UTC) < end:
            time.sleep(1)
            if self.debug:
                print('%d    ' % (end - datetime.now(UTC)).seconds, end='\r')
        for result in results.values():
            if result.ready():
                try:
                    result.get(0)
                except Exception as e:
                    self.exceptions.append(e)
        for sig in signals.values():
            sig.put_nowait(Process.sig_quit)
        if self.debug:
            print("test complete")
