import ipaddress

from ..config import Configuration
from ..system import encoding


class Network(Configuration):
    encoding = encoding
    broadcast = 'anyone'
    multicast_v4_address = '239.0.0.65'
    multicast_v6_address = 'ff00::41e9:dddc:e4c7:e7e7'
    ping = 'ping'

    def __init__(self, _ip4_cidr, _ip6_cidr, _mac_address, _mcast4_addr, _mcast6_addr, _port=None):
        self._ip4_cidr = _ip4_cidr
        self._ip6_cidr = _ip6_cidr
        self._mac_address = _mac_address
        self._mcast4_addr = _mcast4_addr
        self._mcast6_addr = _mcast6_addr
        self._port = _port

    @property
    def ip4(self):
        return self._ip4_cidr.split('/')[0]

    @property
    def ip6(self):
        return self._ip6_cidr.split('/')[0]

    @property
    def mac(self):
        return self._mac_address

    @property
    def port(self):
        return self._port

    @property
    def ip4_broadcast(self):
        net4 = ipaddress.IPv4Network(self._ip4_cidr, False)
        return str(net4.broadcast_address)

    @property
    def ip4_multicast(self):
        return self._mcast4_addr

    @property
    def ip6_multicast(self):
        return self._mcast6_addr

    @classmethod
    def initialize(cls, my_ip4, my_ip6, my_mac):
        return Network(my_ip4, my_ip6, my_mac, cls.multicast_v4_address, cls.multicast_v6_address, None)
