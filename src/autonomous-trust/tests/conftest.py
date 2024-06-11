# ******************
#  Copyright 2024 TekFive, Inc. and contributors
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
import shutil
import re
import time
from datetime import datetime, timedelta

import pytest

from autonomous_trust.core import AutonomousTrust, Process, CfgIds
from autonomous_trust.core.config import Configuration
from autonomous_trust.core.config.generate import generate_identity

from . import PRESERVE_FILES, TEST_DIR

base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


def setup(local_net=False):
    test_dir = os.path.join(TEST_DIR, 'etc/at')
    os.makedirs(test_dir, exist_ok=True)
    os.environ[Configuration.ROOT_VARIABLE_NAME] = test_dir
    generate_identity(test_dir, True)
    if local_net:
        net_cfg_file = os.path.join(test_dir, CfgIds.network + Configuration.file_ext)
        contents = []
        with open(net_cfg_file, 'r') as net:
            for line in net.readlines():
                line = re.sub(r'_ip4_address: \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*', '_ip4_address: 127.0.0.1', line)
                line = re.sub(r'_port: .*', '_port: null', line)
                contents.append(line)
        with open(net_cfg_file, 'w') as net:
            net.writelines(contents)


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
        start = datetime.utcnow()
        end = start + timedelta(seconds=self.runtime)
        if self.debug:
            print()
        while datetime.utcnow() < end:
            time.sleep(1)
            if self.debug:
                print('%d    ' % (end - datetime.utcnow()).seconds, end='\r')
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
