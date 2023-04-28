import os
import shutil
import pytest

from autonomous_trust.config import Configuration, generate_identity
from autonomous_trust.automate import AutonomousTrust
from . import PRESERVE_FILES, TEST_DIR


@pytest.fixture(scope="session", autouse=True)
def setup_teardown():
    test_dir = os.path.join(TEST_DIR, 'etc.at')
    os.makedirs(test_dir, exist_ok=True)
    os.environ[Configuration.VARIABLE_NAME] = test_dir
    yield
    if not PRESERVE_FILES and os.path.isdir(test_dir):
        shutil.rmtree(test_dir)


def test_config():
    generate_identity(os.environ[Configuration.VARIABLE_NAME], True)
    at = AutonomousTrust(logfile=Configuration.log_stdout)
    cfgs = at.configure(start=False)
    assert 'network' in cfgs.keys()
    assert 'identity' in cfgs.keys()
    assert 'peers' in cfgs.keys()
