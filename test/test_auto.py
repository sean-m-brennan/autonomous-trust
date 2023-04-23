import os
import shutil
import pytest
from config.configuration import Configuration
from autonomous_trust.automate import configure
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
    cfgs = configure()
    assert 'identity' in cfgs.keys()
