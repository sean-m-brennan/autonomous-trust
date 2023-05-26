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
