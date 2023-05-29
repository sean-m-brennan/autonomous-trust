from contextlib import ExitStack

from autonomous_trust.core import LogLevel
from ..autonomoustrustcontainer import AutonomousTrustContainer, docker_init
from ..conftest import *


def run_library(mp=True, runtime=None):
    at = QuickTrust(runtime=runtime, multiproc=mp, log_level=LogLevel.DEBUG, logfile=Configuration.log_stdout)
    # FIXME extra functionality
    at.run_forever()  # blocks until timeout
    return at


def test_nominal(setup_teardown):
    at = run_library(True, 60)
    assert len(at.exceptions) == 0
    assert len(at.peers.all) == 4


def test_troubled(setup_teardown):
    at = run_library(True, 60)
    # FIXME pathologies here
    assert len(at.exceptions) == 0
