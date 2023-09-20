import math
import random
from datetime import datetime
from typing import Optional

from autonomous_trust.core.config.configuration import Configuration
from autonomous_trust.inspector.peer.position import UTMPosition
from ..serialize import SerializableEnum


class Variability(SerializableEnum):
    """Random distributions centered about zero"""
    BROWNIAN = 'brownian'
    GAUSSIAN = 'gaussian'
    UNIFORM = 'uniform'

    def __call__(self, *args) -> float:
        if self.value == 'brownian':
            return random.normalvariate(mu=0.0, sigma=2.0)
        if self.value == 'gaussian':
            return random.gauss(0., 1.)
        if self.value == 'uniform':
            return random.uniform(-1.0, 1.0)


# ######### Data objects

class ShapeData(Configuration):
    def __init__(self, start: UTMPosition):
        super().__init__()
        self.start = start


class LineData(ShapeData):
    def __init__(self, start: UTMPosition, end: UTMPosition):
        super().__init__(start)
        self.end = end


class BezierData(LineData):
    def __init__(self, start: UTMPosition, end: UTMPosition, ctl_pts: list[UTMPosition]):
        super().__init__(start, end)
        self.ctl_pts = ctl_pts


class BeziergonData(ShapeData):
    def __init__(self, start: UTMPosition, ctl_pts: list[UTMPosition], loops: int):
        super().__init__(start)
        self.ctl_pts = ctl_pts
        self.loops = loops


class EllipseData(ShapeData):
    def __init__(self, center: UTMPosition, semi_major: float, semi_minor: float, angle: float, loops: int):
        """Angle is in decimal degrees"""
        super().__init__(center)
        self.center = center
        self.semi_major = max(semi_major, semi_minor)
        self.semi_minor = min(semi_major, semi_minor)
        self.angle = angle
        self.loops = loops

    def to_dict(self) -> dict:
        d = super().to_dict()
        for param in ['start']:
            del d[param]
        return d


# ######### Implementations

class PathShape(object):
    def __init__(self, num_steps: int, data: ShapeData):
        self.num_steps = num_steps
        self.data = data
        self.prev: UTMPosition = self.start
        self.prev_prev: Optional[UTMPosition] = None
        self.points: list[UTMPosition] = [self.start]
        self.closed = False

    @property
    def start(self) -> UTMPosition:
        return self.data.start

    @property
    def bearing(self) -> tuple[float, float, float]:
        """Normalized proportion for dimensions on path"""
        raise NotImplementedError

    def closest_point(self, step: int) -> UTMPosition:
        """Find position on the path at this step"""
        if self.closed:
            return self.points[step % len(self.points)]
        return self.points[step]

    def move_along(self, var: Variability, speed: float, step: int, cadence: float) -> UTMPosition:
        pos = self.closest_point(step)

        # add speed in proportion in each dimension
        pos.easting += self.bearing[0] * speed * cadence
        pos.northing += self.bearing[1] * speed * cadence
        if pos.alt is not None:
            pos.alt += self.bearing[2] * speed * cadence

        # add in variability
        pos.easting += var()
        pos.northing += var()
        if pos.alt is not None:
            pos.alt += var()
        self.prev = pos
        return pos

    def get_generic_bearing(self, second_pt: UTMPosition):
        first = self.prev_prev
        second = self.prev
        if self.prev_prev is None:
            first = self.start
            second = second_pt
        dist = first.distance(second) * 10.  # FIXME why?
        bearing_x = 0
        bearing_y = 0
        bearing_z = 0
        if dist > 0:
            bearing_x = (second.easting - first.easting) / dist
            bearing_y = (second.northing - first.northing) / dist
            if first.alt is not None and second.alt is not None:
                bearing_z = (second.alt - first.alt) / dist
        return bearing_x, bearing_y, bearing_z

    @classmethod
    def implement_shape(cls, num_steps: int, data: ShapeData) -> 'PathShape':
        if data.__class__ == LineData:
            return LinePath(num_steps, data)  # noqa
        if data.__class__ == BezierData:
            return BezierPath(num_steps, data)  # noqa
        if data.__class__ == BeziergonData:
            return BeziergonPath(num_steps, data)  # noqa
        if data.__class__ == EllipseData:
            return EllipsePath(num_steps, data)  # noqa
        raise RuntimeError('Invalid shape: %s' % data.__class__.__name__)


class LinePath(PathShape):
    def __init__(self, num_steps: int, data: LineData):
        super().__init__(num_steps, data)

        # bearing (direction) is constant
        self._bearing = self.get_generic_bearing(self.end)

        # split into points on the line
        dist = self.start.distance(self.end)
        self.points = [self.start]
        prev = self.start
        for i in range(1, num_steps+1):
            prev = UTMPosition(prev.zone, prev.easting + dist * self._bearing[0],
                               prev.northing + dist * self._bearing[1],
                               prev.alt + dist * self._bearing[2])
            self.points.append(prev)

    @property
    def end(self) -> UTMPosition:
        return self.data.end  # noqa

    @property
    def bearing(self) -> tuple[float, float, float]:
        return self._bearing


class BezierPath(PathShape):
    def __init__(self, num_steps: int, data: BezierData):
        super().__init__(num_steps, data)

        if self.start not in self.ctl_pts:
            self.ctl_pts.insert(0, self.start)
        if self.end not in self.ctl_pts:
            self.ctl_pts.append(self.end)
        self.points += self.de_casteljau(num_steps, self.ctl_pts, self.start)
        self.points.append(self.end)

    @property
    def end(self) -> UTMPosition:
        return self.data.end  # noqa

    @property
    def ctl_pts(self) -> list[UTMPosition]:
        return self.data.ctl_pts  # noqa

    @staticmethod
    def de_casteljau(num_steps: int, ctl_pts: list[UTMPosition], ref: UTMPosition) -> list[UTMPosition]:
        """de Casteljau's algorithm for Bezier curves"""
        def lerp(pt1: tuple[float, float], pt2: tuple[float, float], t: float) -> tuple[float, float]:
            x1, y1 = pt1
            x2, y2 = pt2
            s = 1. - t
            return x1 * s + x2 * t, y1 * s + y2 * t

        points = []
        for step in range(1, num_steps+1):
            pts: list[tuple[float, float]] = [pt.to_tuple() for pt in ctl_pts]
            t = step / float(num_steps)
            n = len(pts)
            for j in range(1, n):
                for k in range(n - j):
                    pts[k] = lerp(pts[k], pts[k + 1], t)
            points.append(UTMPosition.from_tuple(pts[0], ref))
        return points

    @property
    def bearing(self) -> tuple[float, float, float]:
        return self.get_generic_bearing(self.ctl_pts[0])

    def move_along(self, var: Variability, speed: float, step: int, cadence: float) -> UTMPosition:
        self.prev_prev = self.prev
        return super().move_along(var, speed, step, cadence)


class BeziergonPath(PathShape):
    def __init__(self, num_steps: int, data: BeziergonData):
        super().__init__(num_steps, data)
        if self.start not in self.ctl_pts:
            self.ctl_pts.insert(0, self.start)
            self.ctl_pts.append(self.start)  # closed, must start and end at same point
        for _ in range(data.loops):
            self.points += BezierPath.de_casteljau(num_steps//data.loops, self.ctl_pts, self.start)
        self.closed = True

    @property
    def ctl_pts(self) -> list[UTMPosition]:
        return self.data.ctl_pts  # noqa

    @property
    def bearing(self) -> tuple[float, float, float]:
        return self.get_generic_bearing(self.ctl_pts[0])

    def move_along(self, var: Variability, speed: float, step: int, cadence: float) -> UTMPosition:
        self.prev_prev = self.prev
        return super().move_along(var, speed, step, cadence)


class EllipsePath(PathShape):
    def __init__(self, num_steps: int, data: EllipseData):
        super().__init__(num_steps, data)

        # de La Hire's construction
        start_dist = self.semi_major * 2 + 1
        t_step = 2. * math.pi / ((num_steps // data.loops) - 1)
        pt_idx = 0

        points = []
        for idx, step in enumerate(range(1, (num_steps // data.loops)+1)):
            t = t_step * idx + math.radians(self.angle)
            if t < 0:
                t += 2. * math.pi
            if t > 2. * math.pi:
                t -= 2. * math.pi
            x = self.semi_major * math.cos(t)
            y = self.semi_minor * math.sin(t)
            pt = UTMPosition(self.center.zone, self.center.easting + x, self.center.northing + y, self.center.alt)
            points.append(pt)
            dist = self.start.distance(pt)
            if dist < start_dist:
                start_dist = dist
                pt_idx = idx

        # rotate to point closest to given start
        points = points[pt_idx:] + points[:pt_idx]
        self.points = []
        for _ in range(data.loops):
            self.points += points
        self.data.start = self.points[0]
        self.closed = True

    @property
    def center(self) -> UTMPosition:
        return self.data.center  # noqa

    @property
    def semi_major(self) -> float:
        return self.data.semi_major  # noqa

    @property
    def semi_minor(self) -> float:
        return self.data.semi_minor  # noqa

    @property
    def angle(self) -> float:
        return self.data.angle  # noqa

    @property
    def bearing(self) -> tuple[float, float, float]:
        return self.get_generic_bearing(self.points[1])


# ######### Path

class PathData(Configuration):
    def __init__(self, begin: datetime, end: datetime, shape: ShapeData,
                 variability: Variability, speed: float, accel: Variability):
        super().__init__()
        self.begin = begin
        self.end = end
        self.shape = shape
        self.variability = variability
        self.speed = speed
        self.accel = accel


class Path(object):
    def __init__(self, steps: int, cadence: float, data: PathData):
        self.steps = steps
        self.cadence = cadence
        self.data = data
        self.shape_impl = PathShape.implement_shape(steps, self.data.shape)

    def move_along(self, step: int):
        cur_speed = self.data.speed + self.data.accel()
        return self.shape_impl.move_along(self.data.variability, cur_speed, step, self.cadence)
