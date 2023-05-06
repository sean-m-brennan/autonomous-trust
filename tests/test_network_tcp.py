import os
import shutil
import pytest

from autonomous_trust.network.tcp import TCPNetworkProcess
from autonomous_trust.config import Configuration, CfgIds, generate_identity
from autonomous_trust.automate import AutonomousTrust
from . import PRESERVE_FILES, TEST_DIR


@pytest.fixture(scope="session", autouse=True)
def setup_teardown():
    test_dir = os.path.join(TEST_DIR, 'etc.at')
    os.makedirs(test_dir, exist_ok=True)
    os.environ[Configuration.VARIABLE_NAME] = test_dir
    generate_identity(test_dir, True)

    yield
    if not PRESERVE_FILES and os.path.isdir(test_dir):
        shutil.rmtree(test_dir)


def test_reject():
    at = AutonomousTrust(logfile=Configuration.log_stdout)
    cfgs = at._configure(start=False)
    net_addr = cfgs[CfgIds.network.value].ip4
    tcp = TCPNetworkProcess(cfgs, dict({}), None)
    tcp.send_peer('test1', net_addr)
    msg_tpl = tcp.recv_peer()
    assert msg_tpl[0] is None
    assert net_addr == msg_tpl[1][0]


def test_p2p():
    at = AutonomousTrust(logfile=Configuration.log_stdout)
    cfgs = at._configure(start=False)
    net_addr = cfgs[CfgIds.network.value].ip4
    tcp = TCPNetworkProcess(cfgs, dict({}), None, acceptance_func=lambda x: True)
    tcp.send_peer('test1', net_addr)
    msg_tpl = tcp.recv_peer()
    assert 'test1' == msg_tpl[0]
    assert net_addr == msg_tpl[1][0]


@pytest.mark.skip(reason="blocked by firewall")
def test_mcast():
    at = AutonomousTrust(logfile=Configuration.log_stdout)
    cfgs = at._configure(start=False)
    tcp = TCPNetworkProcess(cfgs, dict({}), None)
    tcp.send_any('test2')
    assert 'test2' == tcp.recv_any()
