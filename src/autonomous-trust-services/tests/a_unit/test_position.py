from __future__ import annotations

import math

import pytest

try:
    from autonomous_trust.services.peer.position import Position, GeoPosition, UTMPosition
except ImportError as _e:
    pytestmark = pytest.mark.skip(reason=f"missing dependency: {_e}")


# --- Fixtures ---

@pytest.fixture
def huntsville():
    return GeoPosition(34.669650, -86.575907, 182)

@pytest.fixture
def uah():
    return GeoPosition(34.725279, -86.639962, 198)

@pytest.fixture
def abq():
    return GeoPosition(35.106499574, -106.605997576, 1558)

@pytest.fixture
def southern():
    return GeoPosition(-33.8688, 151.2093, 58)

@pytest.fixture
def utm_huntsville(huntsville):
    return huntsville.convert(UTMPosition)

@pytest.fixture
def utm_uah(uah):
    return uah.convert(UTMPosition)


# --- GeoPosition basic ---

class TestGeoPosition:
    def test_creation(self, huntsville):
        assert huntsville.lat == pytest.approx(34.669650)
        assert huntsville.lon == pytest.approx(-86.575907)
        assert huntsville.alt == pytest.approx(182.0)

    def test_x_y_z_properties(self, huntsville):
        assert huntsville.x == huntsville.lat
        assert huntsville.y == huntsville.lon
        assert huntsville.z == huntsville.alt

    def test_no_altitude(self):
        g = GeoPosition(10.0, 20.0)
        assert g.alt is None
        assert g.z is None

    def test_convert_to_self(self, huntsville):
        same = huntsville.convert(GeoPosition)
        assert same is huntsville

    def test_convert_to_utm(self, huntsville):
        u = huntsville.convert(UTMPosition)
        assert isinstance(u, UTMPosition)
        assert u.zone.endswith('N')
        assert u.alt == pytest.approx(182.0)

    def test_distance_symmetric(self, huntsville, uah):
        d1 = huntsville.distance(uah)
        d2 = uah.distance(huntsville)
        assert d1 == pytest.approx(d2)

    def test_distance_positive(self, huntsville, uah):
        d = huntsville.distance(uah)
        assert d > 0

    def test_distance_with_altitude(self):
        # Use large altitude difference so it materially affects distance
        a = GeoPosition(0.0, 0.0, 0.0)
        b = GeoPosition(0.0, 0.001, 1000.0)
        d_with = a.distance(b)
        no_alt1 = GeoPosition(0.0, 0.0)
        no_alt2 = GeoPosition(0.0, 0.001)
        d_without = no_alt1.distance(no_alt2)
        assert d_with > d_without

    def test_distance_no_altitude(self):
        a = GeoPosition(0.0, 0.0)
        b = GeoPosition(0.0, 1.0)
        d = a.distance(b)
        assert d > 100000  # ~111km per degree at equator

    def test_distance_long(self, huntsville, abq):
        d = huntsville.distance(abq)
        assert d > 1_000_000  # >1000 km

    def test_hemisphere_north(self, huntsville):
        assert UTMPosition.hemisphere(huntsville) == 'N'

    def test_hemisphere_south(self, southern):
        assert UTMPosition.hemisphere(southern) == 'S'


# --- UTMPosition basic ---

class TestUTMPosition:
    def test_creation(self, utm_huntsville):
        assert isinstance(utm_huntsville.easting, float)
        assert isinstance(utm_huntsville.northing, float)
        assert utm_huntsville.north is True
        assert isinstance(utm_huntsville.zone_num, int)

    def test_zone_string(self, utm_huntsville):
        assert utm_huntsville.zone[-1] == 'N'
        assert utm_huntsville.zone[:-1].isdigit()

    def test_convert_to_self(self, utm_huntsville):
        same = utm_huntsville.convert(UTMPosition)
        assert same is utm_huntsville

    def test_convert_roundtrip(self, huntsville):
        u = huntsville.convert(UTMPosition)
        back = u.convert(GeoPosition)
        assert back.lat == pytest.approx(huntsville.lat, abs=1e-5)
        assert back.lon == pytest.approx(huntsville.lon, abs=1e-5)
        assert back.alt == pytest.approx(huntsville.alt)

    def test_to_tuple(self, utm_huntsville):
        t = utm_huntsville.to_tuple()
        assert len(t) == 2
        assert t[0] == utm_huntsville.easting
        assert t[1] == utm_huntsville.northing

    def test_from_tuple(self, utm_huntsville):
        t = utm_huntsville.to_tuple()
        rebuilt = UTMPosition.from_tuple(t, utm_huntsville)
        assert rebuilt.easting == utm_huntsville.easting
        assert rebuilt.northing == utm_huntsville.northing
        assert rebuilt.zone == utm_huntsville.zone

    def test_get_zone(self, huntsville):
        zone = UTMPosition.get_zone(huntsville)
        assert zone[-1] == 'N'
        assert zone[:-1].isdigit()

    def test_distance_same_zone(self, utm_huntsville, utm_uah):
        d = utm_huntsville.distance(utm_uah)
        assert d > 0

    def test_distance_symmetric(self, utm_huntsville, utm_uah):
        d1 = utm_huntsville.distance(utm_uah)
        d2 = utm_uah.distance(utm_huntsville)
        assert d1 == pytest.approx(d2)

    def test_distance_with_geo(self, utm_huntsville, uah):
        d = utm_huntsville.distance(uah)
        assert d > 0

    def test_distance_cross_zone(self, huntsville, abq):
        u1 = huntsville.convert(UTMPosition)
        u2 = abq.convert(UTMPosition)
        assert u1.zone_num != u2.zone_num
        d_utm = u1.distance(u2)
        d_geo = huntsville.distance(abq)
        assert d_utm == pytest.approx(d_geo, rel=0.01)

    def test_distance_geo_different_zone(self, utm_huntsville, abq):
        # UTM.distance(GeoPosition) where zones differ
        d = utm_huntsville.distance(abq)
        assert d > 1_000_000

    def test_to_dict_excludes_computed(self, utm_huntsville):
        d = utm_huntsville.to_dict()
        assert 'north' not in d
        assert 'zone_num' not in d
        assert '_x' not in d
        assert '_y' not in d
        assert 'zone' in d
        assert 'easting' in d
        assert 'northing' in d


# --- Position arithmetic ---

class TestPositionArithmetic:
    def test_add_geo_positions(self, huntsville, uah):
        result = huntsville + uah
        assert isinstance(result, GeoPosition)
        assert result.lat == pytest.approx(huntsville.lat + uah.lat)
        assert result.lon == pytest.approx(huntsville.lon + uah.lon)

    def test_sub_geo_positions(self, huntsville, uah):
        result = huntsville - uah
        assert isinstance(result, GeoPosition)
        assert result.lat == pytest.approx(huntsville.lat - uah.lat)

    def test_add_scalar(self, huntsville):
        result = huntsville + 1.0
        assert result.lat == pytest.approx(huntsville.lat + 1.0)
        assert result.lon == pytest.approx(huntsville.lon + 1.0)
        assert result.alt == pytest.approx(huntsville.alt + 1.0)

    def test_sub_scalar(self, huntsville):
        result = huntsville - 0.5
        assert result.lat == pytest.approx(huntsville.lat - 0.5)

    def test_mul_scalar(self, huntsville):
        result = huntsville * 2
        assert result.lat == pytest.approx(huntsville.lat * 2)
        assert result.lon == pytest.approx(huntsville.lon * 2)
        assert result.alt == pytest.approx(huntsville.alt * 2)

    def test_div_scalar(self, huntsville):
        result = huntsville / 2
        assert result.lat == pytest.approx(huntsville.lat / 2)

    def test_mul_no_altitude(self):
        g = GeoPosition(10.0, 20.0)
        result = g * 3
        assert result.z is None

    def test_div_no_altitude(self):
        g = GeoPosition(10.0, 20.0)
        result = g / 2
        assert result.z is None

    def test_add_utm_positions(self, utm_huntsville, utm_uah):
        result = utm_huntsville + utm_uah
        assert isinstance(result, UTMPosition)
        assert result.zone == utm_huntsville.zone

    def test_sub_utm_positions(self, utm_huntsville, utm_uah):
        result = utm_huntsville - utm_uah
        assert isinstance(result, UTMPosition)

    def test_mul_utm(self, utm_huntsville):
        result = utm_huntsville * 2
        assert isinstance(result, UTMPosition)
        assert result.zone == utm_huntsville.zone

    def test_div_utm(self, utm_huntsville):
        result = utm_huntsville / 2
        assert isinstance(result, UTMPosition)

    def test_add_mixed_types_raises(self, huntsville, utm_uah):
        with pytest.raises(RuntimeError, match='Cannot mix'):
            huntsville + utm_uah

    def test_add_invalid_type_raises(self, huntsville):
        with pytest.raises(RuntimeError, match='Cannot add type'):
            huntsville + "invalid"

    def test_add_position_none_z(self):
        a = GeoPosition(1.0, 2.0, 3.0)
        b = GeoPosition(4.0, 5.0)
        result = a + b
        assert result.z is None

    def test_sub_position_none_z(self):
        a = GeoPosition(1.0, 2.0, 3.0)
        b = GeoPosition(4.0, 5.0)
        result = a - b
        assert result.z is None

    def test_invalid_op_raises(self, huntsville):
        with pytest.raises(RuntimeError, match='Invalid operation'):
            huntsville._additive_op('multiply', huntsville)

    def test_add_utm_different_zones_raises(self, huntsville, abq):
        u1 = huntsville.convert(UTMPosition)
        u2 = abq.convert(UTMPosition)
        with pytest.raises(RuntimeError, match='Incompatible UTMPositions'):
            u1 + u2


# --- Midpoint / Middle ---

class TestMiddle:
    def test_midpoint_geo(self, huntsville, uah):
        mid = huntsville.midpoint(uah)
        assert isinstance(mid, GeoPosition)
        # midpoint lat should be between the two
        assert min(huntsville.lat, uah.lat) <= mid.lat <= max(huntsville.lat, uah.lat)
        assert min(huntsville.lon, uah.lon) <= mid.lon <= max(huntsville.lon, uah.lon)

    def test_midpoint_utm(self, utm_huntsville, utm_uah):
        mid = utm_huntsville.midpoint(utm_uah)
        assert isinstance(mid, UTMPosition)
        assert mid.zone == utm_huntsville.zone

    def test_middle_empty(self):
        result = GeoPosition.middle([])
        assert isinstance(result, GeoPosition)
        assert result.lat == 0
        assert result.lon == 0

    def test_middle_mixed_types_raises(self, huntsville, utm_uah):
        with pytest.raises(RuntimeError, match='Cannot mix'):
            Position.middle([huntsville, utm_uah])

    def test_middle_utm_different_zones_raises(self, huntsville, abq):
        u1 = huntsville.convert(UTMPosition)
        u2 = abq.convert(UTMPosition)
        with pytest.raises(RuntimeError, match='Incompatible UTMPositions'):
            UTMPosition.middle([u1, u2])

    def test_middle_single_point(self, huntsville):
        mid = GeoPosition.middle([huntsville])
        assert mid.lat == pytest.approx(huntsville.lat)
        assert mid.lon == pytest.approx(huntsville.lon)


# --- to_dict ---

class TestPositionBase:
    def test_distance_raises(self):
        p = Position(1.0, 2.0)
        with pytest.raises(NotImplementedError):
            p.distance(Position(3.0, 4.0))

    def test_convert_raises(self):
        p = Position(1.0, 2.0)
        with pytest.raises(NotImplementedError):
            p.convert(GeoPosition)


class TestToDict:
    def test_geo_to_dict(self, huntsville):
        d = huntsville.to_dict()
        assert '_x' not in d
        assert '_y' not in d
        assert '_z' not in d
        assert 'lat' in d
        assert 'lon' in d

    def test_utm_to_dict(self, utm_huntsville):
        d = utm_huntsville.to_dict()
        assert '_x' not in d
        assert 'north' not in d
        assert 'zone_num' not in d
