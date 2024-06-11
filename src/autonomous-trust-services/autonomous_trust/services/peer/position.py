# ******************
#  Copyright 2024 TekFive, Inc. and contributors
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

import math
from typing import Optional, Union

from geopy import distance
import utm

from autonomous_trust.core.config import Configuration


class Position(Configuration):
    def __init__(self, x: float, y: float, z: Optional[float] = None):
        super().__init__()
        self._x = x
        self._y = y
        self._z = z

    @property
    def x(self):
        return self._x

    @property
    def y(self):
        return self._y

    @property
    def z(self):
        return self._z

    def distance(self, other: 'Position'):
        raise NotImplementedError

    def convert(self, cls):
        raise NotImplementedError

    def to_dict(self) -> dict:
        """Remove private members"""
        d = super().to_dict()
        for param in ['_x', '_y', '_z']:
            del d[param]
        return d

    def midpoint(self, other: 'Position'):
        return self.middle([self, other])

    @classmethod
    def middle(cls, others: list['Position']):
        if len(others) < 1:
            return GeoPosition(0, 0, 0)
        if not all([isinstance(pos, type(others[0])) for pos in others]):
            raise RuntimeError('Cannot mix differing Position types')
        if isinstance(others[0], UTMPosition):
            zones = [others[i].zone == others[i - 1].zone for i in range(len(others)) if i > 0]  # noqa
            if not all(zones):
                raise RuntimeError('Incompatible UTMPositions (differing zones)')
        x = [pos._x for pos in others]
        mid_x = (max(x) + min(x)) / 2.
        y = [pos._y for pos in others]
        mid_y = (max(y) + min(y)) / 2.
        z = [pos._z for pos in others if pos is not None]
        mid_z = None
        if len(z) > 0:
            mid_z = (max(z) + min(z)) / 2.
        if cls == UTMPosition:  # FIXME
            return UTMPosition(others[0].zone, mid_x, mid_y, mid_z)  # noqa
        return GeoPosition(mid_x, mid_y, mid_z)

    def _additive_op(self, op, other) -> 'Position':
        if op not in ['plus', 'minus']:
            raise RuntimeError('Invalid operation %s' % op)
        if isinstance(other, Position):
            if not all([isinstance(pos, type(self)) for pos in [self, other]]):
                raise RuntimeError('Cannot mix differing Position types')
            if isinstance(other, UTMPosition) and self.zone_num != other.zone_num:  # noqa
                raise RuntimeError('Incompatible UTMPositions (differing zones)')
            if op == 'plus':
                x = self.x + other.x
                y = self.y + other.y
                z = None if self.z is None or other.z is None else self.z + other.z
            elif op == 'minus':
                x = self.x - other.x
                y = self.y - other.y
                z = None if self.z is None or other.z is None else self.z - other.z
        elif isinstance(other, int) or isinstance(other, float):
            if op == 'plus':
                x = self.x + other
                y = self.y + other
                z = self.z + other
            elif op == 'minus':
                x = self.x - other
                y = self.y - other
                z = self.z - other
        else:
            raise RuntimeError('Cannot add type %s to Position' % type(other).__name__)
        if isinstance(self, UTMPosition):
            return UTMPosition(self.zone, x, y, z)  # noqa
        return GeoPosition(x, y, z)  # noqa

    def __add__(self, other: Union['Position', int, float]) -> 'Position':
        return self._additive_op('plus', other)

    def __sub__(self, other: Union['Position', int, float]) -> 'Position':
        return self._additive_op('minus', other)

    def __mul__(self, other: Union[int, float]) -> 'Position':
        x = self.x * other
        y = self.y * other
        z = None if self.z is None else self.z * other
        if isinstance(self, UTMPosition):
            return UTMPosition(self.zone, x, y, z)
        return GeoPosition(x, y, z)

    def __truediv__(self, other: Union[int, float]) -> 'Position':
        x = self.x / other
        y = self.y / other
        z = None if self.z is None else self.z / other
        if isinstance(self, UTMPosition):
            return UTMPosition(self.zone, x, y, z)
        return GeoPosition(x, y, z)


class GeoPosition(Position):
    def __init__(self, lat: float, lon: float, alt: Optional[float] = None):
        """Specified in decimal degrees, plus meters for altitude"""
        super().__init__(lat, lon, alt)
        self.lat = float(lat)
        self.lon = float(lon)
        self.alt = alt
        if alt is not None:
            self.alt = float(alt)

    def convert(self, cls):
        """Convert to UTM"""
        if cls == self.__class__:
            return self
        easting, northing, zone_num, _ = utm.from_latlon(self.lat, self.lon)
        zone = '%d%s' % (zone_num, UTMPosition.hemisphere(self))
        return UTMPosition(zone, easting, northing, self.alt)

    def distance(self, other: 'GeoPosition'):
        d = distance.distance((self.lat, self.lon), (other.lat, other.lon)).m
        if self.alt is not None and other.alt is not None:
            delta_alt = self.alt - other.alt
            d = math.sqrt(delta_alt ** 2 + d ** 2)
        return d


class UTMPosition(Position):
    def __init__(self, zone: str, easting: float, northing: float, alt: Optional[float] = None):
        """
        Easting/northing/altitude specified in meters;
        reference geo point is the intersection of the UTM zone's central meridian and the equator;
        reference point is at 500000m east, at 0m for the Northern hemisphere, 10000000m for the South
        """
        super().__init__(easting, northing, alt)
        self.easting = float(easting)
        self.northing = float(northing)
        self.alt = float(alt)
        self.zone = zone
        self.north = zone.lower().endswith('n')
        self.zone_num = int(zone[:-1])

    def to_dict(self) -> dict:
        d = super().to_dict()
        for param in ['north', 'zone_num']:
            del d[param]
        return d

    def to_tuple(self):
        return tuple((self.easting, self.northing))

    @classmethod
    def from_tuple(cls, tpl: tuple[float, float], ref: 'UTMPosition') -> 'UTMPosition':
        return UTMPosition(ref.zone, tpl[0], tpl[1], ref.alt)

    def convert(self, cls):
        """Convert to Geo"""
        if cls == self.__class__:
            return self
        lat, lon = utm.to_latlon(self.easting, self.northing, self.zone_num, northern=self.north)
        return GeoPosition(lat, lon, self.alt)

    @classmethod
    def hemisphere(cls, ref: GeoPosition) -> str:
        if ref.lat < 0.:
            return 'S'
        return 'N'

    @classmethod
    def get_zone(cls, ref: GeoPosition) -> str:
        hemi = 'S' if ref.lat < 0 else 'N'
        _, _, zone_num, _ = utm.from_latlon(ref.lat, ref.lon)
        return '%d%s' % (zone_num, hemi)

    def distance(self, other: 'Position') -> float:
        if isinstance(other, GeoPosition):
            if self.get_zone(other) != self.zone:
                return self.convert(GeoPosition).distance(other)
            other = other.convert(UTMPosition)

        if self.zone_num != other.zone_num:
            geo1 = self.convert(GeoPosition)
            geo2 = other.convert(GeoPosition)
            return geo1.distance(geo2)

        sum_sq = ((self.easting - other.easting) ** 2) + ((self.northing - other.northing) ** 2)
        if self.alt is not None and other.alt is not None:
            sum_sq += (self.alt - other.alt) ** 2
        return math.sqrt(sum_sq) * 0.9996
