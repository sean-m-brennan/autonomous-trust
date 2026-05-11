# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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

import re
import ipaddress
import psutil
import socket
import subprocess

from ..config import InitializableConfig
from ..system import encoding

#from ..protobuf import network_pb2

class Network(InitializableConfig):
    encoding = encoding
    broadcast = 'anyone'
    multicast_v4_address = '239.0.0.65'  # must be setup in OS
    multicast_v6_address = 'ff00::41e9:dddc:e4c7:e7e7'
    ping = 'ping'
    stats_req = 'stats_req'
    stats_resp = 'stats_resp'
    # Parser-level wire-bytes size cap. Matches the C transport's
    # NET_MSG_MAX_DATA (net_message.h:31). Enforced at envelope-parse
    # time as defense-in-depth: the TCP transport already caps inbound
    # bytes, but Message.parse may be called on in-process or
    # alternate-transport bytes, so the parser carries the same
    # guarantee. Used by Message.parse to reject oversized envelopes
    # before json.loads consumes them. Any change here must match
    # NET_MSG_MAX_DATA in src/c/autonomous_trust/network/net_message.h.
    max_wire_bytes = 1024 * 1024

    def __init__(self, _ip4_cidr, _ip6_cidr, _mac_address, _mcast4_addr, _mcast6_addr, _port=None):
        #super().__init__(network_pb2.Network)
        #self._ip4_cidr = _ip4_cidr
        #self._ip6_cidr = _ip6_cidr
        #self._mac_address = _mac_address
        addresses = self.get_addresses()
        self._ip4_cidr = self.cidr(addresses['ip4'], addresses['ip4_subnet'])
        self._ip6_cidr = self.cidr(addresses['ip6'], addresses['ip6_subnet'])
        self._mac_address = addresses['mac']
        self._mcast4_addr = _mcast4_addr
        self._mcast6_addr = _mcast6_addr
        self._port = _port

    @classmethod
    def _get_default_device(cls):
        route = subprocess.check_output(['/sbin/ip', 'route']).decode().split('\n')[0]
        if 'default' in route:
            return route.split()[4]
        return route.split()[2]

    @classmethod
    def get_addresses(cls):
        device = cls._get_default_device()
        if device == '':
            device = 'eth0'

        ip4_address = None
        ip6_address = None
        mac_address = None
        ip4_subnet = None
        ip6_subnet = None
        mac_bcast_address = None

        info = psutil.net_if_addrs()[device]
        for addr in info:
            if addr.family == socket.AF_INET:
                ip4_address = addr.address
                ip4_subnet = addr.netmask
            if addr.family == socket.AF_INET6:
                ip6_address = re.sub('%.*$', '', addr.address)
                ip6_subnet = addr.netmask
            if addr.family == socket.AF_PACKET:
                mac_address = addr.address
                mac_bcast_address = addr.broadcast

        return {'ip4': ip4_address, 'ip6': ip6_address, 'mac': mac_address,
                'ip4_subnet': ip4_subnet, 'ip6_subnet': ip6_subnet,
                'mac_bcast': mac_bcast_address}

    @staticmethod
    def cidr(address, subnet):
        if address is None:
            return None
        if address.startswith('fe80'):
            return 'fe80::/64'
        try:
            return str(ipaddress.ip_interface('%s/%s' % (address, subnet)))
        except ValueError:
            if ':' in str(subnet):
                try:
                    # Convert hex netmask to prefix length by counting set bits
                    addr_int = int(ipaddress.IPv6Address(subnet))
                    prefix_len = bin(addr_int).count('1')
                    return str(ipaddress.ip_interface('%s/%d' % (address, prefix_len)))
                except (ValueError, ipaddress.AddressValueError):
                    pass
            return None

    @property
    def ip4(self):
        if self._ip4_cidr is None:
            return None
        return self._ip4_cidr.split('/')[0]

    @property
    def ip6(self):
        if self._ip6_cidr is None:
            return None
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
