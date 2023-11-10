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
