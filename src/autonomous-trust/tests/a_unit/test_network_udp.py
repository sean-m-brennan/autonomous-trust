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

import pytest

from autonomous_trust.core.network.tcp import UDPNetworkProcess
from autonomous_trust.core.config import Configuration
from autonomous_trust.core.automate import AutonomousTrust
from autonomous_trust.core.system import CfgIds


@pytest.mark.skip
def test_reject(setup_teardown):
    at = AutonomousTrust(logfile=Configuration.log_stdout)
    cfgs = at._configure(start=False)
    net_addr = cfgs[CfgIds.network].ip4
    udp = UDPNetworkProcess(cfgs, dict({}), None)
    udp.send_peer('test1', net_addr)
    msg_tpl = udp.recv_peer()
    assert msg_tpl[0] is None
    assert net_addr == msg_tpl[1][0]


@pytest.mark.skip
def test_p2p(setup_teardown):
    at = AutonomousTrust(logfile=Configuration.log_stdout)
    cfgs = at._configure(start=False)
    net_addr = cfgs[CfgIds.network].ip4
    udp = UDPNetworkProcess(cfgs, dict({}), None, acceptance_func=lambda x: True)
    udp.send_peer('test1', net_addr)
    msg_tpl = udp.recv_peer()
    assert 'test1' == msg_tpl[0]
    assert net_addr == msg_tpl[1][0]


@pytest.mark.skip(reason="blocked by firewall")
def test_mcast(setup_teardown):
    at = AutonomousTrust(logfile=Configuration.log_stdout)
    cfgs = at._configure(start=False)
    udp = UDPNetworkProcess(cfgs, dict({}), None)
    udp.send_any('test2')
    assert 'test2' == udp.recv_any()
