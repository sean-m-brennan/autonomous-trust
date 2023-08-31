from enum import Enum

from .. import Serializable


class NetInterface(Serializable):
    def __init__(self, rate: int, mark: int):
        self.rate = rate
        self.mark = mark


class InterfaceClasses(NetInterface, Enum):
    SMALL = NetInterface(10 * 1000, 11)  # 10Kbps
    MEDIUM = NetInterface(10 * 1000 * 1000, 22)  # 10Mbps
    LARGE = NetInterface(10 * 1000 * 1000 * 1000, 33)  # 10Gbps
    POINT_TO_POINT = LARGE  # eg. laser


class AntennaClasses(float, Enum):
    DIPOLE = 3.0
    YAGI = 12.0
    PARABOLIC = 25.0
