# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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
import json
import os
import pytest
import socket
import ipaddress
from unittest.mock import patch, MagicMock

from autonomous_trust.core.config import Configuration
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
    # _get_default_device() short-circuits to '' when the `ip` binary is absent
    # (e.g. a minimal CI container without iproute2). Patch shutil.which so the
    # parse logic is exercised regardless of what's installed on the host.
    @patch('autonomous_trust.core.network.network.shutil.which', return_value='/sbin/ip')
    @patch('autonomous_trust.core.network.network.subprocess.check_output')
    def test_default_route(self, mock_output, _mock_which):
        mock_output.return_value = b'default via 192.168.1.1 dev eth0 proto dhcp\n'
        assert Network._get_default_device() == 'eth0'

    @patch('autonomous_trust.core.network.network.shutil.which', return_value='/sbin/ip')
    @patch('autonomous_trust.core.network.network.subprocess.check_output')
    def test_no_default(self, mock_output, _mock_which):
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


def _addr(family, address, netmask=None, broadcast=None):
    """One psutil.net_if_addrs() entry."""
    entry = MagicMock()
    entry.family = family
    entry.address = address
    entry.netmask = netmask
    entry.broadcast = broadcast
    return entry


# A multi-homed host: the cohort is on eth1, but eth0 sorts first and is the
# one a name-ordered scan would pick.
_MULTI_HOMED = {
    'lo': [_addr(socket.AF_INET, '127.0.0.1', '255.0.0.0')],
    'eth0': [_addr(socket.AF_INET, '172.17.0.1', '255.255.0.0'),
             _addr(socket.AF_PACKET, '00:11:22:33:44:55', broadcast='ff:ff:ff:ff:ff:ff')],
    'eth1': [_addr(socket.AF_INET, '10.4.0.9', '255.255.255.0'),
             _addr(socket.AF_PACKET, 'aa:bb:cc:dd:ee:ff', broadcast='ff:ff:ff:ff:ff:ff')],
}


@patch('autonomous_trust.core.network.network.Network._outbound_address', return_value=None)
@patch('autonomous_trust.core.network.network.Network._get_default_device', return_value='')
@patch('autonomous_trust.core.network.network.psutil.net_if_addrs')
class TestSelectDevice:
    def test_env_override(self, mock_addrs, _mock_dev, _mock_out):
        mock_addrs.return_value = _MULTI_HOMED
        with patch.dict(os.environ, {Network.device_variable_name: 'eth1'}):
            assert Network._select_device() == ('eth1', False)

    def test_env_override_absent_device_falls_through(self, mock_addrs, _mock_dev, _mock_out):
        """A named interface this host doesn't have must not be fatal."""
        mock_addrs.return_value = _MULTI_HOMED
        with patch.dict(os.environ, {Network.device_variable_name: 'wlan9'}):
            device, matched = Network._select_device()
        assert device == 'eth0'  # first non-loopback with IPv4
        assert matched is False

    def test_preferred_ip_picks_its_subnet(self, mock_addrs, _mock_dev, _mock_out):
        """The provisioned address decides which NIC faces the cohort."""
        mock_addrs.return_value = _MULTI_HOMED
        assert Network._select_device('10.4.0.9') == ('eth1', True)

    def test_preferred_ip_off_subnet_falls_back(self, mock_addrs, _mock_dev, _mock_out):
        mock_addrs.return_value = _MULTI_HOMED
        assert Network._select_device('192.0.2.7') == ('eth0', False)

    def test_malformed_preferred_ip_is_ignored(self, mock_addrs, _mock_dev, _mock_out):
        mock_addrs.return_value = _MULTI_HOMED
        assert Network._select_device('not-an-address') == ('eth0', False)

    def test_default_route_device(self, mock_addrs, mock_dev, _mock_out):
        mock_addrs.return_value = _MULTI_HOMED
        mock_dev.return_value = 'eth1'
        assert Network._select_device() == ('eth1', False)

    def test_outbound_address_beats_name_order(self, mock_addrs, _mock_dev, mock_out):
        """With no route table to read, the kernel's own source address
        decides -- otherwise a docker0/bridge that sorts first wins."""
        mock_addrs.return_value = _MULTI_HOMED
        mock_out.return_value = '10.4.0.9'
        assert Network._select_device() == ('eth1', False)

    def test_no_eth0_no_route(self, mock_addrs, _mock_dev, _mock_out):
        """Thea bug: a host with neither a parseable default route nor
        an interface literally named eth0 used to raise KeyError."""
        mock_addrs.return_value = {
            'lo': [_addr(socket.AF_INET, '127.0.0.1', '255.0.0.0')],
            'enp3s0': [_addr(socket.AF_INET, '10.1.2.3', '255.255.255.0')],
        }
        assert Network._select_device() == ('enp3s0', False)

    def test_loopback_only_host(self, mock_addrs, _mock_dev, _mock_out):
        mock_addrs.return_value = {'lo': [_addr(socket.AF_INET, '127.0.0.1', '255.0.0.0')]}
        assert Network._select_device() == (None, False)


@patch('autonomous_trust.core.network.network.Network._bootstrap_address', return_value=None)
@patch('autonomous_trust.core.network.network.Network._outbound_address', return_value=None)
@patch('autonomous_trust.core.network.network.Network._get_default_device', return_value='')
@patch('autonomous_trust.core.network.network.psutil.net_if_addrs')
class TestGetAddressesSelection:
    def test_no_eth0_does_not_raise(self, mock_addrs, _mock_dev, _mock_out, _mock_boot):
        mock_addrs.return_value = {
            'lo': [_addr(socket.AF_INET, '127.0.0.1', '255.0.0.0')],
            'enp3s0': [_addr(socket.AF_INET, '10.1.2.3', '255.255.255.0')],
        }
        result = Network.get_addresses()
        assert result['ip4'] == '10.1.2.3'
        assert result['device'] == 'enp3s0'

    def test_loopback_only_reports_empty(self, mock_addrs, _mock_dev, _mock_out, _mock_boot):
        mock_addrs.return_value = {'lo': [_addr(socket.AF_INET, '127.0.0.1', '255.0.0.0')]}
        result = Network.get_addresses()
        assert result['device'] is None
        assert result['ip4'] is None
        assert result['mac'] is None

    def test_provisioned_address_wins_on_its_subnet(self, mock_addrs, _mock_dev,
                                                    _mock_out, _mock_boot):
        """C parity (fill_ipv4's override_ip): the provisioned address is the
        one we answer on, not whatever else the matched NIC carries."""
        mock_addrs.return_value = _MULTI_HOMED
        result = Network.get_addresses('10.4.0.55')
        assert result['device'] == 'eth1'
        assert result['ip4'] == '10.4.0.55'
        assert result['mac'] == 'aa:bb:cc:dd:ee:ff'

    def test_bootstrap_supplies_the_preference(self, mock_addrs, _mock_dev,
                                               _mock_out, mock_boot):
        mock_addrs.return_value = _MULTI_HOMED
        mock_boot.return_value = '10.4.0.9'
        assert Network.get_addresses()['device'] == 'eth1'


class TestBootstrapAddress:
    def test_reads_node_address(self, tmp_path):
        boot_dir = tmp_path / 'bootstrap'
        boot_dir.mkdir()
        (boot_dir / ('bootstrap' + Configuration.file_ext)).write_text(
            json.dumps({'node_address': '10.4.0.9', 'subnet': '255.255.255.0'}))
        assert Network._bootstrap_address(str(tmp_path)) == '10.4.0.9'

    def test_absent_file(self, tmp_path):
        assert Network._bootstrap_address(str(tmp_path)) is None

    def test_malformed_file(self, tmp_path):
        boot_dir = tmp_path / 'bootstrap'
        boot_dir.mkdir()
        (boot_dir / ('bootstrap' + Configuration.file_ext)).write_text('{not json')
        assert Network._bootstrap_address(str(tmp_path)) is None

    def test_empty_address(self, tmp_path):
        boot_dir = tmp_path / 'bootstrap'
        boot_dir.mkdir()
        (boot_dir / ('bootstrap' + Configuration.file_ext)).write_text(
            json.dumps({'node_address': ''}))
        assert Network._bootstrap_address(str(tmp_path)) is None


class TestGetDefaultDeviceParsing:
    @patch('autonomous_trust.core.network.network.shutil.which', return_value='/sbin/ip')
    @patch('autonomous_trust.core.network.network.subprocess.check_output')
    def test_default_not_on_first_line(self, mock_output, _mock_which):
        mock_output.return_value = (b'172.17.0.0/16 dev docker0 proto kernel scope link\n'
                                    b'default via 10.4.0.1 dev eth1 proto dhcp\n')
        assert Network._get_default_device() == 'eth1'

    @patch('autonomous_trust.core.network.network.shutil.which', return_value='/sbin/ip')
    @patch('autonomous_trust.core.network.network.subprocess.check_output')
    def test_line_without_dev_token(self, mock_output, _mock_which):
        mock_output.return_value = (b'blackhole 10.9.0.0/24\n'
                                    b'10.4.0.0/24 dev eth1 proto kernel\n')
        assert Network._get_default_device() == 'eth1'

    @patch('autonomous_trust.core.network.network.shutil.which', return_value='/sbin/ip')
    @patch('autonomous_trust.core.network.network.subprocess.check_output')
    def test_empty_route_table(self, mock_output, _mock_which):
        mock_output.return_value = b'\n'
        assert Network._get_default_device() == ''


class TestStaleness:
    """b: the stored address is authoritative while it is still valid on
    this host, and re-derived when it isn't."""

    @patch('autonomous_trust.core.network.network.psutil.net_if_addrs')
    def test_stored_address_is_kept_when_live(self, mock_addrs):
        mock_addrs.return_value = _MULTI_HOMED
        n = Network('10.4.0.9/24', None, 'aa:bb:cc:dd:ee:ff', '239.0.0.65', 'ff00::41e9')
        assert n.is_current()
        with patch.object(Network, 'get_addresses') as never:
            assert n.refresh() is False
            never.assert_not_called()
        assert n.ip4 == '10.4.0.9'

    @patch('autonomous_trust.core.network.network.psutil.net_if_addrs')
    def test_stale_address_is_rederived(self, mock_addrs):
        mock_addrs.return_value = _MULTI_HOMED
        n = Network('192.168.99.7/24', None, '00:00:00:00:00:00', '239.0.0.65', 'ff00::41e9')
        assert not n.is_current()
        with patch.object(Network, 'get_addresses', return_value={
                'ip4': '10.4.0.9', 'ip6': None, 'mac': 'aa:bb:cc:dd:ee:ff',
                'ip4_subnet': '255.255.255.0', 'ip6_subnet': None,
                'mac_bcast': None, 'device': 'eth1'}):
            assert n.refresh() is True
        assert n.ip4 == '10.4.0.9'
        assert n.mac == 'aa:bb:cc:dd:ee:ff'

    @patch('autonomous_trust.core.network.network.psutil.net_if_addrs')
    def test_stale_but_nothing_to_rederive_keeps_config(self, mock_addrs):
        """A node with no usable NIC keeps its (wrong) address: diagnosable
        beats empty."""
        mock_addrs.return_value = {'lo': [_addr(socket.AF_INET, '127.0.0.1', '255.0.0.0')]}
        n = Network('192.168.99.7/24', None, None, '239.0.0.65', 'ff00::41e9')
        with patch.object(Network, 'get_addresses', return_value={
                'ip4': None, 'ip6': None, 'mac': None, 'ip4_subnet': None,
                'ip6_subnet': None, 'mac_bcast': None, 'device': None}):
            assert n.refresh() is False
        assert n.ip4 == '192.168.99.7'

    @patch('autonomous_trust.core.network.network.psutil.net_if_addrs')
    def test_link_local_ip6_does_not_force_a_refresh(self, mock_addrs):
        """cidr() stores any link-local as the literal fe80::/64, which no
        host holds as an address; it must not read as stale."""
        mock_addrs.return_value = _MULTI_HOMED
        n = Network('10.4.0.9/24', 'fe80::/64', 'aa:bb:cc:dd:ee:ff',
                    '239.0.0.65', 'ff00::41e9')
        assert n.is_current()

    @patch('autonomous_trust.core.network.network.psutil.net_if_addrs')
    def test_force_rederives_a_current_config(self, mock_addrs):
        mock_addrs.return_value = _MULTI_HOMED
        n = Network('10.4.0.9/24', None, 'aa:bb:cc:dd:ee:ff', '239.0.0.65', 'ff00::41e9')
        with patch.object(Network, 'get_addresses', return_value={
                'ip4': '172.17.0.1', 'ip6': None, 'mac': '00:11:22:33:44:55',
                'ip4_subnet': '255.255.0.0', 'ip6_subnet': None,
                'mac_bcast': None, 'device': 'eth0'}) as forced:
            assert n.refresh(force=True) is True
            forced.assert_called_once()
        assert n.ip4 == '172.17.0.1'

    @patch('autonomous_trust.core.network.network.psutil.net_if_addrs')
    def test_empty_config_is_not_current(self, mock_addrs):
        mock_addrs.return_value = _MULTI_HOMED
        n = Network.__new__(Network)
        n._ip4_cidr = None
        n._ip6_cidr = None
        assert not n.is_current()
