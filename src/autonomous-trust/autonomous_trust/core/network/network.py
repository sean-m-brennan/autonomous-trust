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

import ipaddress

from ..config import InitializableConfig
from ..system import encoding


class Network(InitializableConfig):
    encoding = encoding
    broadcast = 'anyone'
    multicast_v4_address = '239.0.0.65'
    multicast_v6_address = 'ff00::41e9:dddc:e4c7:e7e7'
    ping = 'ping'
    stats_req = 'stats_req'
    stats_resp = 'stats_resp'

    def __init__(self, _ip4_cidr, _ip6_cidr, _mac_address, _mcast4_addr, _mcast6_addr, _port=None):
        super().__init__(network_pb2.Network)
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
