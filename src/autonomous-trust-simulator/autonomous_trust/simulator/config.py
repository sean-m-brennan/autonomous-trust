import sys
from datetime import datetime, timedelta
import os

from autonomous_trust.services.data.server import DataSrc
from autonomous_trust.services.peer.position import GeoPosition, UTMPosition
from autonomous_trust.core.identity import Identity

from .peer.path import PointData, BezierData, PathData, Variability, EllipseData
from .peer.peer import PeerInfo
from .peer.peer_metadata import SimMetadata
from .radio.iface import Antenna, NetInterface
from .sim_data import SimConfig

base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))


class MetaIdentity(object):
    def __init__(self, ident, meta, data):
        self.ident = ident
        self.meta = meta
        self.data = data

    @classmethod
    def from_directory(cls, path: str) -> 'MetaIdentity':
        ident = Identity.from_file(os.path.join(path, 'identity.cfg.yaml'))
        meta = SimMetadata.from_file(os.path.join(path, 'metadata-source.cfg.yaml'))
        if ident._uuid != meta.uuid:  # noqa
            raise RuntimeError('Identity and Metadata configs are inconsistent for %s (%s vs %s)' %
                               (path, ident._uuid, meta.uuid))  # noqa
        data = None
        data_cfg = os.path.join(path, 'data-source.cfg.yaml')
        if os.path.exists(data_cfg):
            data = DataSrc.from_file(data_cfg)
            #if data.channels != meta.data_meta:  # FIXME either eliminate DataSrc files or remove from Metadata
            #   raise RuntimeError('DataSource and Metadata configs are inconsistent for %s (%s vs %s)' %
            #                      (path, data.channels, meta.data_channels))
        return cls(ident, meta, data)

    @property
    def uuid(self):
        return self.ident._uuid  # noqa

    @property
    def kind(self):
        return self.meta.peer_kind

    @property
    def nickname(self):
        return self.ident.nickname

    @property
    def address(self):
        return self.ident.address

    @property
    def data_meta(self):
        return self.meta.data_meta


def create_config(path: str = None, output_file: str = None, duration: timedelta = None, start: datetime = None):
    if path is None:
        path = os.path.join(base_dir, 'examples', 'mission', 'participant')
    if not os.path.isabs(path):
        path = os.path.join(base_dir, path)
    if output_file is None:
        output_file = os.path.join(os.path.dirname(__file__), 'test.cfg')
    if not os.path.isabs(output_file):
        output_file = os.path.join(base_dir, output_file)
    if start is None:
        start = datetime.now().replace(microsecond=0, second=0, minute=0)
    if duration is None:
        duration = timedelta(minutes=60)
    end = start + duration

    bot = GeoPosition(34.706505, -86.633657, 197).convert(UTMPosition)
    uah_geo = GeoPosition(34.724448, -86.639802, 195)
    uah = uah_geo.convert(UTMPosition)
    uah_alt = GeoPosition(uah_geo.lat, uah_geo.lon, 5000).convert(UTMPosition)
    uah_alt2 = GeoPosition(uah_geo.lat, -86.45378852314055, 400).convert(UTMPosition)

    mid = bot.midpoint(uah)
    east1 = bot.easting
    east2 = uah.easting
    if abs(east1 - east2) < 1000:
        east1 += 500
        east2 -= 500
    north1 = uah.northing
    north2 = bot.northing
    if abs(north1 - north2) < 1000:
        north1 += 500
        north2 += 500
    one = UTMPosition(bot.zone, east1, north1, mid.alt)
    two = UTMPosition(bot.zone, east2, north2, mid.alt)

    one_third = start + timedelta(minutes=24)
    last_minute = start + timedelta(minutes=21)
    two_thirds = start + timedelta(minutes=36)

    recon_info = [(1800, 1200, -90.), (-1800, 1200, 90.)]
    recon_num = 0
    jet_info = 18000, 480, 135.
    grd_sig = -200.
    aer_sig = -1200.

    peers = []
    for number in [sub for sub in next(os.walk(path))[1] if sub.isdigit()]:
        meta_id = MetaIdentity.from_directory(os.path.join(path, number, 'etc', 'at'))
        data_streams = []
        if meta_id.data_meta is not None:
            for mode, channels in meta_id.data_meta.items():
                for channel in range(1, channels+1):
                    data_streams.append(mode + number + 'c' + str(channel).zfill(2))

        if meta_id.kind == 'microdrone':
            shape1 = BezierData(bot, uah, [one, two])
            shape2 = PointData(uah)
            shape3 = BezierData(uah, bot, [two, one])
            path_data1 = PathData(start, one_third, shape1, Variability.GAUSSIAN, 2.0, Variability.UNIFORM)
            path_data2 = PathData(one_third, two_thirds, shape2, Variability.GAUSSIAN, 2.0, Variability.UNIFORM)
            path_data3 = PathData(two_thirds, end, shape3, Variability.GAUSSIAN, 2.0, Variability.UNIFORM)
            path_data = [path_data1, path_data2, path_data3]
            peers.append(PeerInfo(meta_id.uuid, meta_id.kind, meta_id.nickname, meta_id.address, shape1.start, grd_sig,
                                  Antenna.DIPOLE, NetInterface.SMALL, start, end, path_data, data_streams))

        elif meta_id.kind == 'soldier':
            shape1 = BezierData(bot, uah, [one, two])
            shape2 = PointData(uah)
            shape3 = BezierData(uah, bot, [two, one])
            path_data1 = PathData(start, one_third, shape1, Variability.GAUSSIAN, 1.2, Variability.UNIFORM)
            path_data2 = PathData(one_third, two_thirds, shape2, Variability.GAUSSIAN, 0, Variability.UNIFORM)
            path_data3 = PathData(two_thirds, end, shape3, Variability.GAUSSIAN, 1.6, Variability.UNIFORM)
            path_data = [path_data1, path_data2, path_data3]
            peers.append(PeerInfo(meta_id.uuid, meta_id.kind, meta_id.nickname, meta_id.address, shape1.start, grd_sig,
                                  Antenna.DIPOLE, NetInterface.SMALL, start, end, path_data, data_streams))

        elif meta_id.kind == 'recon':
            shape = EllipseData(uah_alt, *recon_info[recon_num], 3)
            path_data = PathData(start, end, shape, Variability.GAUSSIAN, 90.2, Variability.UNIFORM)
            peers.append(PeerInfo(meta_id.uuid, meta_id.kind, meta_id.nickname, meta_id.address, path_data.shape.start,
                                  aer_sig, Antenna.PARABOLIC, NetInterface.LARGE, start, end, [path_data],
                                  data_streams))
            recon_num += 1

        elif meta_id.kind == 'jet':
            shape = EllipseData(uah_alt2,  *jet_info, 1)
            path_data = PathData(last_minute, end, shape, Variability.GAUSSIAN, 203.4, Variability.UNIFORM)
            peers.append(PeerInfo(meta_id.uuid, meta_id.kind, meta_id.nickname, meta_id.address, path_data.shape.start,
                                  aer_sig, Antenna.YAGI, NetInterface.LARGE, last_minute, end, [path_data],
                                  data_streams))
            # FIXME confirm start, end

    config = SimConfig(start=start, end=end, peers=peers)
    config.to_file(output_file)
    return output_file


if __name__ == '__main__':
    output = None
    if len(sys.argv) == 2:
        output = sys.argv[1]
    create_config(output_file=output)
