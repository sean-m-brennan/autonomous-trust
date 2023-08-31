import math
from datetime import datetime
from enum import Enum
from typing import Optional

from ..util import Serializable, Variability
from .position import UTMPosition


class ShapeType(str, Enum):
    LINE = 'line'
    BEZIER = 'bezier'
    BEZIERGON = 'beziergon'
    ELLIPSE = 'ellipse'


# ######### Data objects

class ShapeData(Serializable):
    def __init__(self, start: UTMPosition):
        self.start = start
        self.type = None


class LineData(ShapeData):
    def __init__(self, start: UTMPosition, end: UTMPosition):
        super().__init__(start)
        self.end = end
        self.type = ShapeType.LINE


class BezierData(LineData):
    def __init__(self, start: UTMPosition, end: UTMPosition, ctl_pts: list[UTMPosition]):
        super().__init__(start, end)
        self.ctl_pts = ctl_pts
        self.type = ShapeType.BEZIER


class BeziergonData(ShapeData):
    def __init__(self, start: UTMPosition, ctl_pts: list[UTMPosition]):
        super().__init__(start)
        self.ctl_pts = ctl_pts
        self.type = ShapeType.BEZIERGON


class EllipseData(ShapeData):
    def __init__(self, center: UTMPosition, semi_major: float, semi_minor: float, angle: float):
        """Angle is in radians"""
        super().__init__(center)
        self.center = center
        self.semi_major = max(semi_major, semi_minor)
        self.semi_minor = min(semi_major, semi_minor)
        self.angle = angle
        self.type = ShapeType.ELLIPSE


# ######### Implementations

class PathShape(ShapeData):
    def __init__(self, num_steps: int, start: UTMPosition):
        super().__init__(start)
        self.num_steps = num_steps
        self.prev = self.start
        self.prev_prev = None
        self.points = [self.start]

    @classmethod
    def from_data(cls, num_steps: int, data: ShapeData):
        return cls(num_steps, **data.__dict__)

    @property
    def bearing(self) -> tuple[float, float, float]:
        """Normalized proportion for dimensions on path"""
        raise NotImplementedError

    def closest_point(self, step: int) -> UTMPosition:
        """Find position on the path at this step"""
        return self.points[step]

    def move_along(self, var: Variability, speed: float, step: int, cadence: float) -> UTMPosition:
        pos = self.closest_point(step)

        # add speed in proportion in each dimension
        pos.easting += self.bearing[0] * speed * cadence
        pos.northing += self.bearing[1] * speed * cadence
        pos.alt += self.bearing[2] * speed * cadence

        # add in variability
        pos.easting += var()
        pos.northing += var()
        pos.alt += var()
        self.prev = pos
        return pos

    def get_generic_bearing(self, second_pt: UTMPosition):
        first = self.prev_prev
        second = self.prev
        if self.prev_prev is None:
            first = self.start
            second = second_pt
        dist = first.distance(second)
        bearing_x = (first.easting - second.easting) / dist
        bearing_y = (first.northing - second.northing) / dist
        bearing_z = (first.alt - second.alt) / dist
        return bearing_x, bearing_y, bearing_z


class LinePath(LineData, PathShape):
    def __init__(self, num_steps: int, start: UTMPosition, end: UTMPosition):
        super().__init__(start, end)
        self.num_steps = num_steps
        self.prev = self.start
        self.points = [self.start]

        # bearing (direction) is constant
        self._bearing = self.get_generic_bearing(self.end)

        # split into points on the line
        dist = self.start.distance(self.end)
        pt_dist = dist / num_steps
        self.points = [self.start]
        prev = self.start
        for i in range(1, num_steps+1):
            prev = UTMPosition(prev.zone, prev.easting + pt_dist * self._bearing[0],
                               prev.northing + pt_dist * self._bearing[1], prev.alt)
            self.points.append(prev)

    @property
    def bearing(self) -> tuple[float, float, float]:
        return self._bearing


class BezierPath(BezierData, PathShape):
    def __init__(self, num_steps: int, start: UTMPosition, end: UTMPosition, ctl_pts: list[UTMPosition]):
        super().__init__(start, end, ctl_pts)
        self.num_steps = num_steps
        self.prev = self.start
        self.prev_prev = None

        self.points = [self.start]
        self.points += self.de_casteljau(num_steps, ctl_pts, self.start)
        self.points.append(self.end)

    @classmethod
    def de_casteljau(cls, num_steps: int, ctl_pts: list[UTMPosition], ref: UTMPosition) -> list[UTMPosition]:
        """de Casteljau's algorithm for Bezier curves"""
        points = []
        for step in range(1, num_steps):
            pts: list[tuple[float]] = [pt.to_tuple() for pt in ctl_pts]
            while len(pts) > 1:
                t = step / num_steps
                ctrls = zip(pts[:-1], pts[1:])
                pts = [(1 - t) * p1 + t * p2 for p1, p2 in ctrls]
            points.append(UTMPosition.from_tuple(pts[0], ref))
        return points

    @property
    def bearing(self) -> tuple[float, float, float]:
        return self.get_generic_bearing(self.ctl_pts[0])

    def move_along(self, var: Variability, speed: float, step: int, cadence: float) -> UTMPosition:
        self.prev_prev = self.prev
        return super().move_along(var, speed, step, cadence)


class BeziergonPath(BeziergonData, BezierPath):
    def __init__(self, num_steps: int, start: UTMPosition, ctl_pts: list[UTMPosition]):
        super().__init__(start, ctl_pts)
        self.num_steps = num_steps
        self.prev = self.start
        self.prev_prev = None

        self.points = [self.start]
        self.points += self.de_casteljau(num_steps // 2, ctl_pts, self.start)
        self.points += self.de_casteljau(num_steps - num_steps // 2, list(reversed(ctl_pts)), self.start)


class EllipsePath(EllipseData, PathShape):
    def __init__(self, num_steps: int, start: UTMPosition, center: UTMPosition,
                 semi_major: float, semi_minor: float, angle: float):
        super().__init__(center, semi_major, semi_minor, angle)
        self.num_steps = num_steps

        # de La Hire's construction
        start_dist = self.semi_major * 2 + 1
        t_step = 2 * math.pi / num_steps
        pt_idx = 0
        for idx, step in enumerate(range(1, num_steps)):
            t = t_step * step + self.angle
            pt = UTMPosition(self.center.zone, semi_major * math.cos(t), semi_minor * math.sin(t), self.center.alt)
            self.points.append(pt)
            dist = start.distance(pt)
            if dist < start_dist:
                start_dist = dist
                pt_idx = idx

        # rotate to point closest to given start
        self.points = self.points[pt_idx:] + self.points[:pt_idx]
        self.start = self.points[0]
        self.prev = self.start
        self.prev_prev = None

    @property
    def bearing(self) -> tuple[float, float, float]:
        return self.get_generic_bearing(self.points[1])


# ######### Shape factory

def implement_shape(num_steps: int, data: ShapeData) -> Optional[PathShape]:
    if data.type == ShapeType.LINE:
        return LinePath.from_data(num_steps, data)
    if data.type == ShapeType.BEZIER:
        return BezierPath.from_data(num_steps, data)
    if data.type == ShapeType.BEZIERGON:
        return BeziergonPath.from_data(num_steps, data)
    if data.type == ShapeType.ELLIPSE:
        return EllipsePath.from_data(num_steps, data)
    return None


# ######### Path

class PathData(Serializable):
    def __init__(self, begin: datetime, end: datetime, shape: ShapeData, variability: Variability,
                 speed: float, accel: Variability):
        self.begin = begin
        self.end = end
        self.shape = shape
        self.variability = variability
        self.speed = speed
        self.accel = accel


class Path(PathData):
    def __init__(self, steps: int, cadence: float, data: PathData):
        super().__init__(**data.__dict__)
        self.steps = steps
        self.cadence = cadence
        self.shape_impl = implement_shape(steps, self.shape)

    def move_along(self, step: int):
        cur_speed = self.speed + self.accel()
        return self.shape_impl.move_along(self.variability, cur_speed, step, self.cadence)
