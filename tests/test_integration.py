import os
import re
import shutil
import subprocess
import threading
import time
from datetime import datetime, timedelta

import pytest
from autonomous_trust.config import Configuration, CfgIds, generate_identity
from autonomous_trust.processes import Process
from autonomous_trust.automate import AutonomousTrust
from . import PRESERVE_FILES, TEST_DIR


class ShortTimer(AutonomousTrust):
    default_runtime = 20

    def __init__(self, runtime=None, debug=False, **kwargs):
        super().__init__(**kwargs)
        self.exceptions = []
        self.runtime = runtime
        if runtime is None:
            self.runtime = runtime
        self.debug = debug

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


def run_main(mp=True, debug=True, reconfig=True, runtime=None):
    cfg_dir = os.environ[Configuration.VARIABLE_NAME]
    generate_identity(cfg_dir, True)
    if reconfig:
        net_cfg_file = os.path.join(cfg_dir, CfgIds.network.value + Configuration.yaml_file_ext)
        contents = []
        with open(net_cfg_file, 'r') as net:
            for line in net.readlines():
                line = re.sub(r'_ip4_address: \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', '_ip4_address: 127.0.0.1', line)
                line = re.sub(r'_port: .*', '_port: 0', line)
                contents.append(line)
        with open(net_cfg_file, 'w') as net:
            net.writelines(contents)
    at = ShortTimer(runtime=runtime, debug=debug, multiproc=mp, logfile=Configuration.log_stdout)
    at.run_forever()
    assert len(at.exceptions) == 0


class DockerThread(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        self.script = os.path.join(base_dir, 'emulate.sh')

    def run(self):
        subprocess.run([self.script, 1], shell=True, check=True)


@pytest.fixture(scope="session", autouse=True)
def setup_teardown():
    test_dir = os.path.join(TEST_DIR, 'etc.at')
    os.makedirs(test_dir, exist_ok=True)
    os.environ[Configuration.VARIABLE_NAME] = test_dir
    yield
    if not PRESERVE_FILES and os.path.isdir(test_dir):
        shutil.rmtree(test_dir)


######################
# Tests:


# FIXME use asyncio?
@pytest.mark.skip(reason="broken")
def test_multiproc():
    run_main(True)


@pytest.mark.skip(reason="will not complete")
def test_threading():
    run_main(False, True)


@pytest.mark.skip(reason="not ready")
def test_two():
    DockerThread().start()
    time.sleep(5)
    run_main(True, False, False, 60)
