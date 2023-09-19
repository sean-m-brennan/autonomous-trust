from ..serial import SerializableEnum


class Antenna(SerializableEnum):
    DIPOLE = 'dipole'
    YAGI = 'yagi'
    PARABOLIC = 'parabolic'

    @property
    def gain(self):
        """Antenna gain in dBm"""
        if self.value == 'dipole':
            return 3.0
        if self.value == 'yagi':
            return 12.0
        if self.value == 'parabolic':
            return 25.0


class NetInterface(SerializableEnum):
    """Classes of network interfaces with transfer rate and identifier mark"""
    SMALL = 'small'
    MEDIUM = 'medium'
    LARGE = 'large'
    POINT_TO_POINT = LARGE  # eg. laser

    @property
    def rate(self):
        """Transfer rate in bps"""
        if self.value == 'small':
            return 10 * 1000  # 10Kbps
        if self.value == 'medium':
            return 10 * 1000 * 1000 # 10Mbps
        if self.value == 'large':
            return 10 * 1000 * 1000 * 1000 # 10Gbps

    @property
    def mark(self):
        """iptables mark"""
        if self.value == 'small':
            return 11
        if self.value == 'medium':
            return 22
        if self.value == 'large':
            return 33
