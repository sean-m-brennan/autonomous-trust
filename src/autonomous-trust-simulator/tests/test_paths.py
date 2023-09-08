import json
from datetime import datetime, timedelta

import pytest
import matplotlib.pyplot as plt

from autonomous_trust.simulator.peer.position import GeoPosition, UTMPosition
from autonomous_trust.simulator.peer.path import PathData, Path, Variability
from autonomous_trust.simulator.peer.path import LineData, BezierData, BeziergonData, EllipseData

steps = 10
cadence = 1
display_plot = True


def plot_shape(points: list[UTMPosition], start: UTMPosition, end: UTMPosition = None,
               extras: list[UTMPosition] = None):
    if not display_plot:
        return
    pts = [start]
    if end:
        pts.append(end)
    if extras:
        pts += extras
    pts_x = [pt.easting for pt in pts]
    pts_y = [pt.northing for pt in pts]
    plt.scatter(x=pts_x, y=pts_y, c='r', s=30)

    xes = [pt.easting for pt in points]
    yes = [pt.northing for pt in points]
    plt.plot(xes, yes)
    plt.gca().set_aspect('equal', adjustable='box')
    plt.show(block=False)
    plt.pause(3)
    plt.close()


@pytest.fixture
def locations():
    t5 = GeoPosition(34.669650, -86.575907, 182).convert(UTMPosition)
    uah = GeoPosition(34.725279, -86.639962, 198).convert(UTMPosition)
    return t5, uah


@pytest.fixture
def ctl_pts(locations):
    t5, uah = locations
    mid = t5.midpoint(uah)
    one = UTMPosition(t5.zone, t5.easting, uah.northing, mid.alt)
    two = UTMPosition(t5.zone, uah.easting, t5.northing, mid.alt)
    return [one, two]


@pytest.fixture
def times():
    start = datetime.now()
    end = datetime.now() + timedelta(minutes=30)
    return start, end


@pytest.fixture
def line_cfg(locations, times):
    t5, uah = locations
    start, end = times
    shape = LineData(t5, uah)
    path = PathData(start, end, shape, Variability.GAUSSIAN, 4.4, Variability.UNIFORM)
    return path.to_yaml_string()


@pytest.fixture
def bezier_cfg(locations, times, ctl_pts):
    t5, uah = locations
    start, end = times
    shape = BezierData(t5, uah, ctl_pts)
    path = PathData(start, end, shape, Variability.GAUSSIAN, 4.4, Variability.UNIFORM)
    return path.to_yaml_string()


@pytest.fixture
def beziergon_cfg(locations, times, ctl_pts):
    t5, uah = locations
    start, end = times
    shape = BeziergonData(t5, ctl_pts)
    path = PathData(start, end, shape, Variability.GAUSSIAN, 4.4, Variability.UNIFORM)
    return path.to_yaml_string()


@pytest.fixture
def ellipse_cfg(locations, times):
    t5, uah = locations
    start, end = times
    shape = EllipseData(uah, 1000, 600, -45.)
    path = PathData(start, end, shape, Variability.GAUSSIAN, 4.4, Variability.UNIFORM)
    return path.to_yaml_string()


@pytest.fixture
def configs(line_cfg, bezier_cfg, beziergon_cfg, ellipse_cfg):
    return line_cfg, bezier_cfg, beziergon_cfg, ellipse_cfg


def test_serialization(configs):
    for cfg in configs:
        path_data = PathData.from_yaml_string(cfg)
        cfg2 = path_data.to_yaml_string()
        assert cfg == cfg2


def path_tester(cfg, locs, confirm):
    prev, _ = locs
    path_data = PathData.from_yaml_string(cfg)
    assert cfg == path_data.to_yaml_string()
    path = Path(steps, cadence, path_data)
    pts = []
    for step in range(1, steps+1):
        pos = path.move_along(step)
        confirm(step, prev, pos)
        prev = pos
        pts.append(pos)
    return pts


def test_line_path(line_cfg, locations):
    def confirm(_, prev, pos):
        assert prev.easting > pos.easting
        assert prev.northing < pos.northing

    start, end = locations
    pts = [start]
    pts += path_tester(line_cfg, locations, confirm)
    pts.append(end)
    plot_shape(pts, start, end)


def test_bezier_path(bezier_cfg, locations):
    def confirm(_, prev, pos):
        assert prev.easting > pos.easting
        assert prev.northing < pos.northing

    start, end = locations
    pts = [start]
    pts += path_tester(bezier_cfg, locations, confirm)
    pts.append(end)
    path = PathData.from_yaml_string(bezier_cfg)
    plot_shape(pts, path.shape.start, path.shape.end, path.shape.ctl_pts)


def test_beziergon_path(beziergon_cfg, locations):
    def confirm(step, prev, pos):
        if step <= (steps // 3 * 2) + 1:
            assert prev.easting > pos.easting
        else:
            assert prev.easting < pos.easting
        if step <= steps // 3:
            assert prev.northing < pos.northing
        else:
            assert prev.northing > pos.northing

    start, _ = locations
    pts = [start]
    pts += path_tester(beziergon_cfg, locations, confirm)
    path = PathData.from_yaml_string(beziergon_cfg)
    plot_shape(pts, path.shape.start, extras=path.shape.ctl_pts)


def test_ellipse_path(ellipse_cfg, locations):
    def confirm(step, prev, pos):
        if step in [6, 7, 8]:
            assert prev.easting > pos.easting
            assert prev.northing > pos.northing
        elif step in [1, 4, 5]:
            assert prev.easting > pos.easting
            assert prev.northing < pos.northing
        elif step in [3]:
            assert prev.easting < pos.easting
            assert prev.northing < pos.northing
        elif step in [9, 10]:
            assert prev.easting < pos.easting
            assert prev.northing > pos.northing

    start, _ = locations
    pts = path_tester(ellipse_cfg, locations, confirm)
    path = PathData.from_yaml_string(ellipse_cfg)
    plot_shape(pts, path.shape.center, extras=[path.shape.start])
