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

import argparse
import math
import os
import subprocess
import shlex

from .iface import NetInterface
from .. import sim_net as net
from ..peer.peer import PeerConnection


class Router(net.Client):
    """
    Per the wireless simulation, adjust container connectivity and throughput
    Note: this implementation is for Linux only - either host based or per container
    """
    header_fmt = '!Q'
    max_rate = max_bw = '100Gbit'

    # Signal quality thresholds for bandwidth degradation (dB path loss)
    # Below min_loss: full rate. Above max_loss: minimum rate.
    # Between: linear interpolation.
    _min_loss_db = 80.0    # path loss below which full bandwidth is available
    _max_loss_db = 160.0   # path loss above which minimum bandwidth applies
    _min_rate_fraction = 0.01  # minimum rate as fraction of interface rate

    def __init__(self, containerized: bool = False, rate_limit: bool = False):
        super().__init__()
        self.all_peers: list[PeerConnection] = []
        self.containerized = containerized
        self.rate_limit = rate_limit
        self.orig_tc_qdisc = None
        self._mark_to_classid: dict[int, int] = {}

        if os.geteuid() != 0:
            raise RuntimeError('This user cannot modify iptables')

        if self.rate_limit:
            self.limiting()

    @property
    def iface(self):
        if self.containerized:
            return 'eth0'
        return 'docker0'

    def limiting(self):
        self.rate_limit = True

        self.orig_tc_qdisc = subprocess.check_output(shlex.split('sudo tc qdisc show %s' % self.iface))

        # clear & recreate:
        self.traffic_ctl('qdisc', 'del dev', self.iface, 'root')
        self.traffic_ctl('qdisc', 'add dev', self.iface,
                         'root handle 1: cbq bandwidth %s avpkt 1000' % self.max_bw)

        # base traffic class:
        self.traffic_ctl('class', 'add dev', self.iface,
                         'parent 1:0 classid 1:1 cbq bandwidth %s rate %s ' % (self.max_bw, self.max_rate) +
                         'allot 1514 weight %s prio 8 maxburst 1000 avpkt 1000' % self.max_rate)
        # full-speed traffic class:
        self.traffic_ctl('class', 'add dev', self.iface,
                         'parent 1:1 classid 1:100 cbq bandwidth %s rate %s ' % (self.max_bw, self.max_rate) +
                         'allot 1514 weight 1Mbit prio 5 maxburst 1000 avpkt 1000')
        self.traffic_ctl('qdisc', 'add dev', self.iface, 'parent 1:100 sfq quantum 1514b perturb 15')
        # throttled classes: one per NetInterface type, keyed by iptables mark
        self._mark_to_classid = {}
        for idx, net_iface in enumerate(NetInterface):
            classid = 200 + idx
            self._mark_to_classid[net_iface.mark] = classid
            rate_str = '%dbit' % net_iface.rate
            self.traffic_ctl('class', 'add dev', self.iface,
                             'parent 1:1 classid 1:%d cbq bandwidth %s rate %s ' % (classid, self.max_bw, rate_str) +
                             'allot 1514 weight %s prio 3 maxburst 50 avpkt 1000 bounded' % rate_str)
            self.traffic_ctl('qdisc', 'add dev', self.iface,
                             'parent 1:%d tbf rate %s latency 100ms burst 1540' % (classid, rate_str))
            self.traffic_ctl('filter', 'add dev', self.iface,
                             'protocol ip parent 1:0 prio 8 handle %d fw flowid 1:%d'
                             % (net_iface.mark, classid))

    def unlimiting(self):
        if self.rate_limit:
            self.rate_limit = False
            if self.orig_tc_qdisc is not None:
                self.traffic_ctl('qdisc', 'del dev', self.iface, 'root')
                self.traffic_ctl('qdisc', 'add dev', self.iface, self.orig_tc_qdisc.decode().strip())

    @staticmethod
    def iptables(args, output: bool = False):
        if output:
            return subprocess.check_output(shlex.split('sudo iptables ' + args)).decode().split('\n')
        subprocess.check_call(shlex.split('sudo iptables ' + args))

    @staticmethod
    def traffic_ctl(mode: str, cmd: str, iface: str, params: str):
        subprocess.check_call(shlex.split('sudo tc %s %s %s %s' % (mode, cmd, iface, params)))

    def chain_available(self, chain: str):
        try:
            self.iptables('-L %s' % chain)
            return True
        except subprocess.CalledProcessError:
            return False
        
    def parse_chain(self, chain: str, src: str = None, dst: str = None):
        if src is None and dst is None:
            return False
        if src is None:
            src = 'anywhere'
        if dst is None:
            dst = 'anywhere'
        result = self.iptables('-L %s' % chain, output=True)[2:]
        for line in result:
            fields = line.split()
            if len(fields) > 4 and fields[3] == src and fields[4] == dst:
                return True
        return False

    @classmethod
    def degraded_rate(cls, base_rate_bps: int, path_loss_db: float) -> str:
        """Compute a degraded bandwidth rate string based on signal quality.

        Linearly interpolates between full rate (at min_loss) and minimum rate
        (at max_loss). Returns a tc-compatible rate string (e.g., '5Mbit').
        """
        if path_loss_db <= cls._min_loss_db:
            fraction = 1.0
        elif path_loss_db >= cls._max_loss_db:
            fraction = cls._min_rate_fraction
        else:
            # Linear interpolation in dB domain
            t = (path_loss_db - cls._min_loss_db) / (cls._max_loss_db - cls._min_loss_db)
            fraction = 1.0 - t * (1.0 - cls._min_rate_fraction)

        rate_bps = max(1000, int(base_rate_bps * fraction))  # floor at 1 Kbps

        if rate_bps >= 1_000_000_000:
            return '%dGbit' % (rate_bps // 1_000_000_000)
        elif rate_bps >= 1_000_000:
            return '%dMbit' % (rate_bps // 1_000_000)
        elif rate_bps >= 1_000:
            return '%dKbit' % (rate_bps // 1_000)
        return '%dbit' % rate_bps

    def recv_data(self, **kwargs):
        state = super().recv_data(**kwargs)

        chain = 'DOCKER-USER'
        if self.containerized:
            chain = 'OUTPUT'
        if not self.chain_available(chain):
            raise RuntimeError('Docker not running (required)')

        for p_id in state.reachable:
            for o_id in state.reachable[p_id]:
                peer = state.peers[p_id]
                other = state.peers[o_id]
                rule_present = self.parse_chain(chain, peer.ip4_addr, other.ip4_addr)
                if state.reachable[p_id][o_id]:  # unblock
                    if rule_present:
                        self.iptables('-D %s -s %s -d %s -j DROP' % (chain, peer.ip4_addr, other.ip4_addr))
                else:
                    if not rule_present:  # cannot reach, block
                        self.iptables('-A %s -s %s -d %s -j DROP' % (chain, peer.ip4_addr, other.ip4_addr))

        if self.rate_limit:
            for peer in state.peers.values():
                if peer not in self.all_peers:
                    self.all_peers.append(peer)

                # OS-level deferred: consider also installing
                # rate-limit rules on the PREROUTING chain. Today we
                # only attach to POSTROUTING, so traffic is shaped on
                # egress; PREROUTING would let us shape ingress before
                # policy routing kicks in. Requires nontrivial
                # Netfilter ordering analysis — confirm the rule set
                # won't conflict with the existing OUTPUT/INPUT
                # branches below.
                for chain in ['POSTROUTING']:
                    if not self.chain_available(chain):
                        self.iptables('-N %s' % chain)
                        if chain.startswith('PRE'):
                            self.iptables('-A %s -j INPUT' % chain)
                        else:
                            self.iptables('-A OUTPUT -j %s' % chain)

                    if not self.parse_chain(chain, None, peer.ip4_addr):
                        self.iptables('-t mangle -A %s -j MARK --set-mark %d -d %s' %
                                      (chain, peer.iface.mark, peer.ip4_addr))

        # Apply signal-quality-based bandwidth degradation
        if self.rate_limit and hasattr(state, 'signal_quality') and state.signal_quality:
            for p_id in state.signal_quality:
                if p_id not in state.peers:
                    continue
                peer = state.peers[p_id]
                classid = self._mark_to_classid.get(peer.iface.mark)
                if classid is None:
                    continue
                # Find worst-case link quality for this peer to set its tc class rate
                worst_loss = max(state.signal_quality[p_id].values(), default=0.0)
                rate_str = self.degraded_rate(peer.iface.rate, worst_loss)
                try:
                    self.traffic_ctl('class', 'change dev', self.iface,
                                     'parent 1:1 classid 1:%d cbq bandwidth %s rate %s '
                                     % (classid, self.max_bw, rate_str) +
                                     'allot 1514 weight %s prio 3 maxburst 50 avpkt 1000 bounded'
                                     % rate_str)
                except subprocess.CalledProcessError:
                    pass  # tc class may not exist yet; limiting() must run first

    def finish(self):  # clear any rules created
        self.unlimiting()
        for chain in ['DOCKER-USER', 'POSTROUTING']:
            for peer in self.all_peers:
                if self.parse_chain(chain, None, peer.ip4_addr):
                    self.iptables('-D %s -d %s' % (chain, peer.ip4_addr))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('sim-host', nargs='?', default='localhost')
    parser.add_argument('sim-port', nargs='?', default=8778)
    args = parser.parse_args()

    Router().run(args.sim_host, args.sim_port)
