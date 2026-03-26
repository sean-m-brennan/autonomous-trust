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
import pytest
import socket
import ipaddress
from unittest.mock import patch, MagicMock

from autonomous_trust.core.network.network import Network


class TestCidr:
    def test_none_address(self):
        assert Network.cidr(None, '255.255.255.0') is None

    def test_ipv4(self):
        result = Network.cidr('192.168.1.100', '255.255.255.0')
        assert result == '192.168.1.100/24'

    def test_link_local(self):
        result = Network.cidr('fe80::1', 'ffff:ffff:ffff:ffff::')
        assert result == 'fe80::/64'

    def test_ipv6_prefix(self):
        result = Network.cidr('2001:db8::1', '64')
        assert result == '2001:db8::1/64'

    def test_ipv6_hex_netmask(self):
        result = Network.cidr('2001:db8::1', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
        assert result == '2001:db8::1/128'

    def test_ipv6_hex_netmask_64(self):
        result = Network.cidr('2001:db8::1', 'ffff:ffff:ffff:ffff::')
        assert result == '2001:db8::1/64'

    def test_ipv6_prefix_numeric(self):
        result = Network.cidr('2001:db8::1', '64')
        assert result == '2001:db8::1/64'

    def test_invalid_returns_none(self):
        result = Network.cidr('192.168.1.1', 'garbage')
        assert result is None


class TestGetAddresses:
    @patch('autonomous_trust.core.network.network.Network._get_default_device')
    @patch('autonomous_trust.core.network.network.psutil.net_if_addrs')
    def test_basic(self, mock_addrs, mock_dev):
        mock_dev.return_value = 'eth0'
        mock_inet = MagicMock()
        mock_inet.family = socket.AF_INET
        mock_inet.address = '192.168.1.100'
        mock_inet.netmask = '255.255.255.0'

        mock_inet6 = MagicMock()
        mock_inet6.family = socket.AF_INET6
        mock_inet6.address = 'fe80::1%eth0'
        mock_inet6.netmask = 'ffff:ffff:ffff:ffff::'

        mock_packet = MagicMock()
        mock_packet.family = socket.AF_PACKET
        mock_packet.address = '00:11:22:33:44:55'
        mock_packet.broadcast = 'ff:ff:ff:ff:ff:ff'

        mock_addrs.return_value = {'eth0': [mock_inet, mock_inet6, mock_packet]}

        result = Network.get_addresses()
        assert result['ip4'] == '192.168.1.100'
        assert result['ip6'] == 'fe80::1'  # %eth0 stripped
        assert result['mac'] == '00:11:22:33:44:55'
        assert result['ip4_subnet'] == '255.255.255.0'

    @patch('autonomous_trust.core.network.network.Network._get_default_device')
    @patch('autonomous_trust.core.network.network.psutil.net_if_addrs')
    def test_empty_device(self, mock_addrs, mock_dev):
        mock_dev.return_value = ''
        mock_inet = MagicMock()
        mock_inet.family = socket.AF_INET
        mock_inet.address = '10.0.0.1'
        mock_inet.netmask = '255.0.0.0'
        mock_addrs.return_value = {'eth0': [mock_inet]}
        result = Network.get_addresses()
        assert result['ip4'] == '10.0.0.1'


class TestGetDefaultDevice:
    @patch('autonomous_trust.core.network.network.subprocess.check_output')
    def test_default_route(self, mock_output):
        mock_output.return_value = b'default via 192.168.1.1 dev eth0 proto dhcp\n'
        assert Network._get_default_device() == 'eth0'

    @patch('autonomous_trust.core.network.network.subprocess.check_output')
    def test_no_default(self, mock_output):
        mock_output.return_value = b'192.168.1.0/24 dev eth0 proto kernel\n'
        assert Network._get_default_device() == 'eth0'


class TestNetworkProperties:
    @patch('autonomous_trust.core.network.network.Network.get_addresses')
    def test_properties(self, mock_addrs):
        mock_addrs.return_value = {
            'ip4': '192.168.1.100', 'ip6': '::1',
            'mac': '00:11:22:33:44:55',
            'ip4_subnet': '255.255.255.0',
            'ip6_subnet': '128',
            'mac_bcast': 'ff:ff:ff:ff:ff:ff',
        }
        n = Network(None, None, None, '239.0.0.65', 'ff00::41e9', 8000)
        assert n.ip4 == '192.168.1.100'
        assert n.mac == '00:11:22:33:44:55'
        assert n.port == 8000
        assert n.ip4_multicast == '239.0.0.65'
        assert n.ip6_multicast == 'ff00::41e9'

    @patch('autonomous_trust.core.network.network.Network.get_addresses')
    def test_ip4_broadcast(self, mock_addrs):
        mock_addrs.return_value = {
            'ip4': '192.168.1.100', 'ip6': None,
            'mac': '00:11:22:33:44:55',
            'ip4_subnet': '255.255.255.0',
            'ip6_subnet': None,
            'mac_bcast': 'ff:ff:ff:ff:ff:ff',
        }
        n = Network(None, None, None, '239.0.0.65', 'ff00::41e9')
        assert n.ip4_broadcast == '192.168.1.255'

    @patch('autonomous_trust.core.network.network.Network.get_addresses')
    def test_ip6_none(self, mock_addrs):
        mock_addrs.return_value = {
            'ip4': '192.168.1.100', 'ip6': None,
            'mac': '00:11:22:33:44:55',
            'ip4_subnet': '255.255.255.0',
            'ip6_subnet': None,
            'mac_bcast': 'ff:ff:ff:ff:ff:ff',
        }
        n = Network(None, None, None, '239.0.0.65', 'ff00::41e9')
        assert n.ip6 is None


class TestNetworkInitialize:
    @patch('autonomous_trust.core.network.network.Network.get_addresses')
    def test_initialize(self, mock_addrs):
        mock_addrs.return_value = {
            'ip4': '10.0.0.1', 'ip6': '::1',
            'mac': 'aa:bb:cc:dd:ee:ff',
            'ip4_subnet': '255.255.255.0',
            'ip6_subnet': '128',
            'mac_bcast': 'ff:ff:ff:ff:ff:ff',
        }
        n = Network.initialize('10.0.0.1', '::1', 'aa:bb:cc:dd:ee:ff')
        assert n.ip4 == '10.0.0.1'
        assert n.port is None
