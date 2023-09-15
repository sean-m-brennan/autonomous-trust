from datetime import datetime, timedelta
from uuid import uuid4
import os

from .path import BezierData, PathData, Variability, EllipseData
from .peer import PeerData
from .position import GeoPosition, UTMPosition
from ..radio.iface import Antenna, NetInterface
from ..sim_data import SimConfig


def create_config(which):
    cfg = os.path.join(os.path.dirname(__file__), 'test.cfg')
    if not os.path.exists(cfg):
        try:
            if which == 'small':
                generate_small_config(cfg)
            elif which == 'full':
                generate_full_config(cfg)
        except:
            os.remove(cfg)
            raise
    return cfg


def generate_full_config(filepath: str):
    t5 = GeoPosition(34.669650, -86.575907, 182).convert(UTMPosition)
    uah = GeoPosition(34.725279, -86.639962, 198).convert(UTMPosition)
    mid = t5.midpoint(uah)
    one = UTMPosition(t5.zone, t5.easting, uah.northing, mid.alt)
    two = UTMPosition(t5.zone, uah.easting, t5.northing, mid.alt)
    start = datetime.now()
    end = datetime.now() + timedelta(minutes=30)
    shape1 = BezierData(t5, uah, [one, two])
    path1 = PathData(start, end, shape1, Variability.GAUSSIAN, 4.4, Variability.UNIFORM)
    peer1 = PeerData(str(uuid4()), '192.168.0.2', path1.shape.start+1, -200.,
                     Antenna.DIPOLE, NetInterface.SMALL, start, end, path1, [])
    path2 = PathData(start, end, shape1, Variability.GAUSSIAN, 4.3, Variability.UNIFORM)
    peer2 = PeerData(str(uuid4()), '192.168.0.3', path2.shape.start+2, -200.,
                     Antenna.DIPOLE, NetInterface.SMALL, start, end, path2, [])
    path3 = PathData(start, end, shape1, Variability.GAUSSIAN, 4.5, Variability.UNIFORM)
    peer3 = PeerData(str(uuid4()), '192.168.0.4', path3.shape.start+3, -200.,
                     Antenna.DIPOLE, NetInterface.SMALL, start, end, path3, [])
    path4 = PathData(start, end, shape1, Variability.GAUSSIAN, 4.1, Variability.UNIFORM)
    peer4 = PeerData(str(uuid4()), '192.168.0.5', path4.shape.start+4, -200.,
                     Antenna.DIPOLE, NetInterface.SMALL, start, end, path4, [])
    uah_alt = GeoPosition(34.725279, -86.639962, 5000).convert(UTMPosition)
    shape0 = EllipseData(uah_alt, 1800, 1200, -90., 3)
    path0 = PathData(start, end, shape0, Variability.GAUSSIAN, 40.2, Variability.UNIFORM)
    peer0 = PeerData(str(uuid4()), '192.168.0.1', path0.shape.start, -1200.,
                     Antenna.PARABOLIC, NetInterface.LARGE, start, end, path0, [])
    config = SimConfig(time=start, peers=[peer0, peer1, peer2, peer3, peer4])
    config.to_file(filepath)


def generate_small_config(filepath: str):
    t5 = GeoPosition(34.669650, -86.575907, 182).convert(UTMPosition)
    uah = GeoPosition(34.725279, -86.639962, 198).convert(UTMPosition)
    mid = t5.midpoint(uah)
    one = UTMPosition(t5.zone, t5.easting, uah.northing, mid.alt)
    two = UTMPosition(t5.zone, uah.easting, t5.northing, mid.alt)
    start = datetime.now()
    end = datetime.now() + timedelta(minutes=30)
    shape1 = BezierData(t5, uah, [one, two])
    path1 = PathData(start, end, shape1, Variability.GAUSSIAN, 4.4, Variability.UNIFORM)
    peer1 = PeerData(str(uuid4()), '192.168.0.2', path1.shape.start, -200.,
                     Antenna.DIPOLE, NetInterface.SMALL, start, end, path1, [])
    shape2 = EllipseData(uah, 1000, 600, -45., 1)
    path2 = PathData(start, end, shape2, Variability.GAUSSIAN, 4.4, Variability.UNIFORM)
    peer2 = PeerData(str(uuid4()), '192.168.0.1', path2.shape.start, -200.,
                     Antenna.DIPOLE, NetInterface.SMALL, start, end, path2, [])
    config = SimConfig(time=start, peers=[peer1, peer2])
    config.to_file(filepath)
