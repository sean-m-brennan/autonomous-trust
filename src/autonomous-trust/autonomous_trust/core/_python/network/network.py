# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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
import logging
import os
import re
import ipaddress
import psutil
import socket
import shutil
import subprocess

from ..config import Configuration, InitializableConfig
from ..system import encoding

#from ..protobuf import network_pb2

_logger = logging.getLogger(__name__)


class Network(InitializableConfig):
    encoding = encoding
    broadcast = 'anyone'
    multicast_v4_address = '239.0.0.65'  # must be setup in OS
    multicast_v6_address = 'ff00::41e9:dddc:e4c7:e7e7'
    # Operator override naming the interface to take our addresses from.
    # Neither the default route nor the bootstrap subnet can be right on
    # every host (multi-homed nodes, VPNs, bridged test rigs), so the
    # deployment gets the last word. See _select_device.
    device_variable_name = 'AT_NETWORK_DEVICE'
    ping_at = 'ping_at'
    stats_req = 'stats_req'
    stats_resp = 'stats_resp'
    # Reputation communication cut-off control (local IPC, reputation ->
    # network). A peer whose reputation falls below the cut-off is
    # EXCLUDED: the network process ignores its inbound frames and does
    # not forward to/for it. `readmit` reverses it (explicit
    # rehabilitation only). Payload is the peer's address string.
    exclude = 'exclude'
    readmit = 'readmit'
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
        # The stored addresses are authoritative while they remain valid on
        # this host; `refresh` re-derives them when they don't (see below).
        # A config that carries no address at all (Network(None, None, None))
        # means "discover", which is what a fresh generation asks for.
        if _ip4_cidr is None and _ip6_cidr is None and _mac_address is None:
            addresses = self.get_addresses()
            _ip4_cidr = self.cidr(addresses['ip4'], addresses['ip4_subnet'])
            _ip6_cidr = self.cidr(addresses['ip6'], addresses['ip6_subnet'])
            _mac_address = addresses['mac']
        self._ip4_cidr = _ip4_cidr
        self._ip6_cidr = _ip6_cidr
        self._mac_address = _mac_address
        self._mcast4_addr = _mcast4_addr
        self._mcast6_addr = _mcast6_addr
        self._port = _port

    @classmethod
    def _get_default_device(cls):
        # Prefer the canonical /sbin (or /usr/sbin) ip; fall back to any `ip`
        # on PATH. If iproute2 isn't present at all (e.g. a minimal CI/build
        # container), return '' so _select_device moves on to its interface
        # scan instead of crashing with FileNotFoundError.
        ip_bin = shutil.which('ip', path='/sbin:/usr/sbin') or shutil.which('ip')
        if ip_bin is None:
            return ''
        try:
            routes = subprocess.check_output([ip_bin, 'route']).decode().split('\n')
        except (OSError, subprocess.CalledProcessError):
            return ''
        # The default route wins wherever it appears in the table; any other
        # route's device is the fallback. Read the name after the `dev` token
        # rather than a fixed column -- route lines vary by kernel and by
        # route type, and a fixed index reads the wrong token (or overruns).
        first = ''
        for route in routes:
            tokens = route.split()
            if 'dev' not in tokens:
                continue
            idx = tokens.index('dev') + 1
            if idx >= len(tokens):
                continue
            device = tokens[idx]
            if tokens[0] == 'default':
                return device
            if first == '':
                first = device
        return first

    @staticmethod
    def _outbound_address():
        """The address the kernel would source outbound traffic from.

        Connecting a UDP socket sends nothing; it just makes the kernel run
        its route lookup, which answers "which interface faces the world"
        without iproute2 and without parsing anything. (NetworkProcess.my_ip
        uses the same trick.) Returns None when there is no route at all.
        """
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(('8.8.8.8', 80))
            return sock.getsockname()[0]
        except OSError:
            return None
        finally:
            if sock is not None:
                sock.close()

    @classmethod
    def _bootstrap_address(cls, cfg_dir=None):
        """This node's provisioned address, if the deployment supplied one.

        Mirrors the C twin's `read_bootstrap` (config/generate.c): the
        bootstrap config names the address this node is expected to answer
        on, which is what tells us *which* interface faces the cohort.
        Returns None when there is no bootstrap config or no address in it.
        """
        if cfg_dir is None:
            try:
                cfg_dir = Configuration.get_cfg_dir()
            except (OSError, ValueError):
                return None
        path = os.path.join(cfg_dir, 'bootstrap', 'bootstrap' + Configuration.file_ext)
        try:
            with open(path, 'r') as bootstrap:
                data = json.load(bootstrap)
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict):
            return None
        address = data.get('node_address')
        if not isinstance(address, str) or address == '':
            return None
        return address

    @staticmethod
    def _is_loopback(device, addrs):
        if device == 'lo':
            return True
        for addr in addrs:
            if addr.family == socket.AF_INET:
                try:
                    return ipaddress.ip_address(addr.address).is_loopback
                except ValueError:
                    return False
        return False

    @classmethod
    def _select_device(cls, preferred_ip=None, interfaces=None):
        """Pick the interface this node takes its addresses from.

        Returns (device, matched_preferred). `device` is None when the host
        has no usable interface at all -- callers report empty addresses
        rather than raising, since a node with no NIC is a diagnosable
        condition and not a crash.

        The ladder, in order:
          1. `AT_NETWORK_DEVICE`, when the operator names an interface.
          2. The interface whose subnet contains `preferred_ip` (the
             bootstrap-provisioned address) -- "use the NIC that can
             actually reach the cohort". This is the C twin's rule
             (`discover_network_for`).
          3. The default-route device.
          4. The first non-loopback interface carrying an IPv4 address.
        """
        if interfaces is None:
            interfaces = psutil.net_if_addrs()

        forced = os.environ.get(cls.device_variable_name, '').strip()
        if forced != '':
            if forced in interfaces:
                return forced, False
            _logger.warning('%s names interface %s, which this host does not have '
                            '(have: %s); falling back to discovery',
                            cls.device_variable_name, forced, ', '.join(sorted(interfaces)))

        if preferred_ip:
            try:
                wanted = ipaddress.ip_address(preferred_ip)
            except ValueError:
                _logger.warning('provisioned address %s is not a valid IP address; '
                                'ignoring it for interface selection', preferred_ip)
                wanted = None
            if wanted is not None:
                for device in sorted(interfaces):
                    addrs = interfaces[device]
                    if cls._is_loopback(device, addrs):
                        continue
                    for addr in addrs:
                        if addr.family != socket.AF_INET or not addr.netmask:
                            continue
                        try:
                            subnet = ipaddress.ip_network('%s/%s' % (addr.address, addr.netmask),
                                                          strict=False)
                        except ValueError:
                            continue
                        if wanted.version == subnet.version and wanted in subnet:
                            return device, True

        device = cls._get_default_device()
        if device != '' and device in interfaces:
            return device, False

        # No route table to read (no iproute2, or it told us nothing useful):
        # ask the kernel which address it would send from, and find whose it
        # is. Without this the scan below falls through to whatever sorts
        # first, which on a host with docker0 or a bridge is the wrong NIC.
        outbound = cls._outbound_address()
        if outbound is not None:
            for device in sorted(interfaces):
                for addr in interfaces[device]:
                    if addr.family == socket.AF_INET and addr.address == outbound:
                        return device, False

        for device in sorted(interfaces):
            addrs = interfaces[device]
            if cls._is_loopback(device, addrs):
                continue
            if any(addr.family == socket.AF_INET for addr in addrs):
                return device, False

        return None, False

    @classmethod
    def get_addresses(cls, preferred_ip=None):
        interfaces = psutil.net_if_addrs()
        if preferred_ip is None:
            preferred_ip = cls._bootstrap_address()
        device, matched_preferred = cls._select_device(preferred_ip, interfaces)

        ip4_address = None
        ip6_address = None
        mac_address = None
        ip4_subnet = None
        ip6_subnet = None
        mac_bcast_address = None

        if device is None:
            _logger.warning('No usable network interface found (have: %s); '
                            'set %s to name the one to use',
                            ', '.join(sorted(interfaces)) or 'none',
                            cls.device_variable_name)
        for addr in interfaces.get(device, []):
            if addr.family == socket.AF_INET:
                ip4_address = addr.address
                ip4_subnet = addr.netmask
            if addr.family == socket.AF_INET6:
                ip6_address = re.sub('%.*$', '', addr.address)
                ip6_subnet = addr.netmask
            if addr.family == socket.AF_PACKET:
                mac_address = addr.address
                mac_bcast_address = addr.broadcast

        # A provisioned address is the one we answer on, even if the matched
        # interface also carries another (C: fill_ipv4's override_ip).
        if matched_preferred:
            ip4_address = preferred_ip

        return {'ip4': ip4_address, 'ip6': ip6_address, 'mac': mac_address,
                'ip4_subnet': ip4_subnet, 'ip6_subnet': ip6_subnet,
                'mac_bcast': mac_bcast_address, 'device': device}

    @classmethod
    def _live_addresses(cls):
        """Every IPv4/IPv6 address currently configured on this host."""
        live4 = set()
        live6 = set()
        for addrs in psutil.net_if_addrs().values():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    live4.add(addr.address)
                elif addr.family == socket.AF_INET6:
                    live6.add(re.sub('%.*$', '', addr.address))
        return live4, live6

    def is_current(self):
        """True when the configured addresses still exist on this host.

        A config directory outlives the addresses it recorded -- a container
        restarted onto a different subnet, a host that moved networks -- and
        an address we no longer hold is one we cannot bind.
        """
        if self._ip4_cidr is None and self._ip6_cidr is None:
            return False
        live4, live6 = self._live_addresses()
        if self._ip4_cidr is not None and self.ip4 not in live4:
            return False
        # cidr() collapses any link-local to the literal 'fe80::/64', which is
        # a subnet and never an address the host holds; it says nothing about
        # staleness either way.
        if (self._ip6_cidr is not None and not self._ip6_cidr.startswith('fe80')
                and self.ip6 not in live6):
            return False
        return True

    def refresh(self, preferred_ip=None, force=False):
        """Re-derive the addresses when the stored ones are no longer valid.

        Returns True if anything changed (so the caller can persist it).
        Keeps the stored config when discovery turns up nothing at all --
        a wrong address is more diagnosable than an empty one.
        """
        if not force and self.is_current():
            return False
        stale = self._ip4_cidr or self._ip6_cidr
        if preferred_ip is None:
            addresses = self.get_addresses()
        else:
            addresses = self.get_addresses(preferred_ip)
        ip4_cidr = self.cidr(addresses['ip4'], addresses['ip4_subnet'])
        ip6_cidr = self.cidr(addresses['ip6'], addresses['ip6_subnet'])
        if ip4_cidr is None and ip6_cidr is None:
            _logger.warning('Network address %s is not present on this host and no '
                            'live interface address was found; keeping the stored '
                            'configuration', stale)
            return False
        changed = (ip4_cidr != self._ip4_cidr or ip6_cidr != self._ip6_cidr
                   or addresses['mac'] != self._mac_address)
        self._ip4_cidr = ip4_cidr
        self._ip6_cidr = ip6_cidr
        self._mac_address = addresses['mac']
        if changed:
            _logger.warning('Network address %s is not present on this host; '
                            're-derived %s on %s', stale, ip4_cidr or ip6_cidr,
                            addresses.get('device'))
        return changed

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
    def initialize(cls, my_ip4_cidr, my_ip6_cidr, my_mac):
        return Network(my_ip4_cidr, my_ip6_cidr, my_mac,
                       cls.multicast_v4_address, cls.multicast_v6_address, None)
