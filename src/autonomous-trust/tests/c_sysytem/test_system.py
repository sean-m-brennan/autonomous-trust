from contextlib import ExitStack

from autonomous_trust.core import LogLevel
from ..autonomoustrustcontainer import AutonomousTrustContainer, docker_init
from ..conftest import *


def run_library(mp=True, runtime=None):
    at = QuickTrust(runtime=runtime, multiproc=mp, log_level=LogLevel.DEBUG, logfile=Configuration.log_stdout)
    # FIXME extra functionality
    # stats = asyncio.get_event_loop().run_until_complete(ping(self.ip_address, timeout=30))
    at.run_forever()  # blocks
    return at


def test_dockered_trust_nominal(setup_teardown):
    docker_init()
    containers = []
    num_peers = 4
    for _ in range(num_peers):
        containers.append(AutonomousTrustContainer())
    with ExitStack() as stack:
        for cont in containers:
            stack.enter_context(cont)
    #with AutonomousTrustContainer() as at1:
        at = run_library(True, 60)
        assert len(at.exceptions) == 0
        assert len(at.peers.all) == num_peers  # FIXME == 0, implies containers not running or unreachable


#def test_dockered_trust_troubled(setup_teardown):
#    containers = []
#    for _ in range(4):
#        containers.append(AutonomousTrustContainer())
#    with ExitStack() as stack:
#        for cont in containers:
#            stack.enter_context(cont)
#        at = run_library(True, 60)
#        # FIXME pathologies here
#        assert len(at.exceptions) == 0
