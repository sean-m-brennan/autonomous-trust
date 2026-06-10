# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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
import pytest
from autonomous_trust.core.config import Configuration

from .. import TEST_DIR


class ConfigTester(Configuration):
    def __init__(self, name, domain, process, comm_link):
        self.name = name
        self.domain = domain
        self.process = process
        self.comm_link = comm_link


class NestedTester(Configuration):
    def __init__(self, name, subclasses):
        self.name = name
        self.subclasses = subclasses


@pytest.fixture
def simple_cfg(setup_teardown):
    return ConfigTester('test1', 'TEST', 't1', 'c1')


@pytest.fixture
def simple_repr(setup_teardown):
    return 'ConfigTester(comm_link=c1, domain=TEST, name=test1, process=t1)'


@pytest.fixture
def nested_cfg(setup_teardown):
    return NestedTester('test2', [ConfigTester('test3', 'TEST', 't3', 'c2'),
                                  ConfigTester('test4', 'TEST', 't4', 'c3')])


@pytest.fixture
def nested_repr(setup_teardown):
    return 'NestedTester(name=test2, subclasses=[' \
           'ConfigTester(comm_link=c2, domain=TEST, name=test3, process=t3), ' \
           'ConfigTester(comm_link=c3, domain=TEST, name=test4, process=t4)])'


def test_cfg_repr(setup_teardown, simple_cfg, simple_repr):
    assert repr(simple_cfg) == simple_repr


def test_cfg_dict(setup_teardown, simple_cfg):
    t2 = simple_cfg
    d = t2.to_dict()
    assert d['name'] == 'test1'
    assert d['domain'] == 'TEST'
    assert d['process'] == 't1'
    assert d['comm_link'] == 'c1'


def test_cfg_file(setup_teardown, simple_cfg, simple_repr):
    t3 = simple_cfg
    file = os.path.join(TEST_DIR, 'test_cfg_file')
    t3.to_file(file)
    t4 = Configuration.from_file(file)
    assert repr(t4) == simple_repr


def test_nesting_cfg_repr(setup_teardown, nested_cfg, nested_repr):
    assert repr(nested_cfg) == nested_repr


def test_nesting_cfg_dict(setup_teardown, nested_cfg):
    t6 = nested_cfg
    d = t6.to_dict()
    assert d['name'] == 'test2'
    d1 = d['subclasses'][0].to_dict()
    assert d1['name'] == 'test3'
    assert d1['domain'] == 'TEST'
    assert d1['process'] == 't3'
    assert d1['comm_link'] == 'c2'
    d2 = d['subclasses'][1].to_dict()
    assert d2['name'] == 'test4'
    assert d2['domain'] == 'TEST'
    assert d2['process'] == 't4'
    assert d2['comm_link'] == 'c3'


def test_nesting_cfg_file(setup_teardown, nested_cfg, nested_repr):
    t7 = nested_cfg
    file = os.path.join(TEST_DIR, 'test_nesting_cfg_file')
    t7.to_file(file)
    t8 = Configuration.from_file(file)
    assert repr(t8) == nested_repr


def test_config_json_decoder_rejects_unknown_type():
    """P1: config_json_decoder must reject types not in the allowlist."""
    from autonomous_trust.core.config.configuration import config_json_decoder
    malicious = {"__type__": "os.system", "command": "echo pwned"}
    with pytest.raises(ValueError, match="not in allowed"):
        config_json_decoder(malicious)


def test_cfg_file_write_is_atomic_on_failure(setup_teardown, simple_cfg, simple_repr):
    """to_file must be atomic: a write that fails mid-serialize must leave the
    previous complete file intact (never an empty/partial file) and leave no
    leftover temp files. Guards the load_configs race that produced
    'JSONDecodeError: Expecting value: line 1 column 1'."""
    from unittest.mock import patch
    file = os.path.join(TEST_DIR, 'test_cfg_atomic.cfg.json')
    simple_cfg.to_file(file)  # establish a good prior version

    # Force the serialization step to blow up partway through. to_file lives in
    # the _python module (the native backend re-exports it), so patch there.
    with patch('autonomous_trust.core._python.config.configuration.json.dump',
               side_effect=RuntimeError('boom')):
        with pytest.raises(RuntimeError, match='boom'):
            simple_cfg.to_file(file)

    # Prior file is untouched and still parses to the same object.
    assert os.path.getsize(file) > 0
    assert repr(Configuration.from_file(file)) == simple_repr
    # No temp turds left behind in the directory.
    leftovers = [f for f in os.listdir(TEST_DIR) if f.endswith('.tmp')]
    assert leftovers == [], f'leftover temp files: {leftovers}'


def test_cfg_file_concurrent_reads_never_see_empty(setup_teardown, simple_cfg):
    """Stress the writer/reader race directly: repeated concurrent to_file /
    from_file on the same path must never surface a partial (empty) read."""
    import json
    import threading
    file = os.path.join(TEST_DIR, 'test_cfg_concurrent.cfg.json')
    simple_cfg.to_file(file)

    stop = threading.Event()
    errors = []

    def writer():
        while not stop.is_set():
            simple_cfg.to_file(file)

    def reader():
        while not stop.is_set():
            try:
                Configuration.from_file(file)
            except json.JSONDecodeError as exc:
                errors.append(str(exc))
                return
            except FileNotFoundError:
                pass  # tolerated transient; the bug under test is empty content

    threads = [threading.Thread(target=writer) for _ in range(2)] + \
              [threading.Thread(target=reader) for _ in range(4)]
    for t in threads:
        t.start()
    stop.wait(1.0)
    stop.set()
    for t in threads:
        t.join()
    assert not errors, f'partial reads observed: {errors[:3]}'
