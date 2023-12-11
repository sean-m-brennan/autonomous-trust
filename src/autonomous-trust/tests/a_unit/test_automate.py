import os

from autonomous_trust.core.config import Configuration
from autonomous_trust.core.config.generate import generate_identity
from autonomous_trust.core.automate import AutonomousTrust


def test_configure(setup_teardown):
    generate_identity(os.environ[Configuration.ROOT_VARIABLE_NAME], True)
    at = AutonomousTrust(logfile=Configuration.log_stdout)
    cfgs = at._configure(start=False)
    assert 'network' in cfgs.keys()
    assert 'identity' in cfgs.keys()
    assert 'peers' in cfgs.keys()
