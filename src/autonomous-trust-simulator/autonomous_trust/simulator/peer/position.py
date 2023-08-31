import math
from typing import Optional, Any

from geopy import distance
import utm

from .. import Serializable


class Position(Serializable):
    def distance(self, other: 'Position'):
        raise NotImplementedError


class GeoPosition(Position):
    def __init__(self, lat: float, lon: float, alt: Optional[float] = None):
        """Specified in decimal degrees, plus meters for altitude"""
        super().__init__()
        self.lat = lat
        self.lon = lon
        self.alt = alt

    def convert(self):
        """Convert to UTM"""
        easting, northing, zone_num, _ = utm.from_latlon(self.lat, self.lon)
        zone = '%d%s' % (zone_num, UTMPosition.hemisphere(self))
        return UTMPosition(zone, easting, northing)

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
        super().__init__()
        self.easting = easting
        self.northing = northing
        self.alt = alt
        self.zone = zone
        self.north = zone.lower().endswith('n')
        self.zone_num = int(zone[:-1])

    def to_tuple(self):
        return tuple((self.easting, self.northing))

    @classmethod
    def from_tuple(cls, tpl: tuple[float], ref: 'UTMPosition') -> 'UTMPosition':
        return UTMPosition(ref.zone, tpl[0], tpl[1], ref.alt)

    def convert(self):
        """Convert to Geo"""
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
                return self.convert().distance(other)
            other = other.convert()

        if self.zone_num != other.zone_num:
            geo1 = self.convert()
            geo2 = other.convert()
            return geo1.distance(geo2)

        sum_sq = ((self.easting - other.easting) ** 2) + ((self.northing - other.northing) ** 2)
        if self.alt is not None and other.alt is not None:
            sum_sq += (self.alt - other.alt) ** 2
        return math.sqrt(sum_sq) * 0.9996

    def __add__(self, other: Any) -> Optional['UTMPosition']:
        if isinstance(other, UTMPosition):
            if self.zone_num != other.zone_num:
                return None
            return UTMPosition(self.zone, self.easting + other.easting,
                               self.northing + other.northing, self.alt + other.alt)
        elif isinstance(other, int) or isinstance(other, float):
            return UTMPosition(self.zone, self.easting + other, self.northing + other, self.alt + other)
        return None

    def __mul__(self, other: Any) -> Optional['UTMPosition']:
        if isinstance(other, int) or isinstance(other, float):
            return UTMPosition(self.zone, self.easting * other, self.northing * other, self.alt * other)
        return None


