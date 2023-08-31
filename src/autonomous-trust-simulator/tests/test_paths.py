import json

import pytest

from autonomous_trust.simulator.peer.position import GeoPosition
from autonomous_trust.simulator.peer.path import PathData, Path


steps = 10
cadence = 1


@pytest.fixture
def locations():
    t5 = GeoPosition(34.669650, -86.575907, 182)
    uah = GeoPosition(34.725279, -86.639962, 198)
    return [t5, uah]


@pytest.fixture
def line_cfg():
    return """

"""


@pytest.fixture
def bezier_cfg():
    return """

"""


@pytest.fixture
def beziergon_cfg():
    return """

"""


@pytest.fixture
def ellipse_cfg():
    return """

"""


def test_line_serialization(line_cfg):
    cfg = line_cfg()
    path_data = PathData(**(json.loads(cfg)))
    cfg2 = path_data.to_json()
    assert cfg == cfg2


def test_bezier_serialization(bezier_cfg):
    cfg = bezier_cfg()
    path_data = PathData(**(json.loads(cfg)))
    cfg2 = path_data.to_json()
    assert cfg == cfg2


def test_beziergon_serialization(beziergon_cfg):
    cfg = beziergon_cfg()
    path_data = PathData(**(json.loads(cfg)))
    cfg2 = path_data.to_json()
    assert cfg == cfg2


def test_ellipse_serialization(ellipse_cfg):
    cfg = ellipse_cfg()
    path_data = PathData(**(json.loads(cfg)))
    cfg2 = path_data.to_json()
    assert cfg == cfg2


def test_line_path(line_cfg):
    cfg = line_cfg()
    path_data = PathData(**(json.loads(cfg)))
    path = Path(steps, cadence, path_data)
    for step in range(1, steps+1):
        path.move_along(step)
        # FIXME verify correct movement??
