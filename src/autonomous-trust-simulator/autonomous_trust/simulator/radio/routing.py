import argparse
import json
import os
import subprocess
import shlex

from .iface import InterfaceClasses
from .. import net_util as net
from ..peer.peer import PeerConnection
from ..sim_data import SimState


class Router(net.Client):
    """
    Per the wireless simulation, adjust container connectivity and throughput
    Note: this implementation is for Linux only - either host based or per container
    """
    header_fmt = '!Q'
    max_rate = max_bw = '100Gbit'

    def __init__(self, containerized: bool = False, rate_limit: bool = False):
        super().__init__()
        self.all_peers: list[PeerConnection] = []
        self.containerized = containerized
        self.rate_limit = rate_limit
        self.orig_tc_qdisc = None

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
        # throttled classes:
        for net_class in [n.value for n in InterfaceClasses]:
            self.traffic_ctl('class', 'add dev', self.iface,
                             'parent 1:1 classid 1:200 cbq bandwidth %s rate %s ' % (self.max_bw, net_class.rate) +
                             'allot 1514 weight %s prio 3 maxburst 50 avpkt 1000 bounded' % net_class.rate)
            self.traffic_ctl('qdisc', 'add dev', self.iface,
                             'parent 1:200 tbf rate %s latency 100ms burst 1540' % net_class.rate)
            self.traffic_ctl('qdisc', 'add dev', self.iface,
                             'protocol ip parent 1:0 prio 8 handle %d fw flowid 1:200' % net_class.mark)

    def unlimiting(self):
        if self.rate_limit:
            self.rate_limit = False
            if self.orig_tc_qdisc is not None:
                self.traffic_ctl('qdisc', 'del dev', self.iface, 'root')
                self.traffic_ctl('qdisc', 'add dev', self.iface, self.orig_tc_qdisc)

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
            if line[3] == src and line[4] == dst:
                return True
        return False

    def recv_data(self, **kwargs):
        data = self.recv_all(self.header_fmt)
        state = SimState(**json.loads(data))

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
                        self.iptables('-D %s -s %s -d %s DROP' % (chain, peer.ip4_addr, other.ip4_addr))
                else:
                    if not rule_present:  # cannot reach, block
                        self.iptables('-A %s -s %s -d %s DROP' % (chain, peer.ip4_addr, other.ip4_addr))

        if self.rate_limit:
            for peer in state.peers.values():
                if peer not in self.all_peers:
                    self.all_peers.append(peer)

                for chain in ['POSTROUTING']:  # FIXME 'PREROUTING'??
                    if not self.chain_available(chain):
                        self.iptables('-N %s' % chain)
                        if chain.startswith('PRE'):
                            self.iptables('-A %s -j INPUT' % chain)
                        else:
                            self.iptables('A OUTPUT -j %s' % chain)

                    if not self.parse_chain(chain, None, peer.ip4_addr):
                        self.iptables('-A %s -t mangle -j MARK --set-mark %d -d %s' %
                                      (chain, peer.iface.mark, peer.ip4_addr))

    def finish(self):  # clear any rules created
        self.unlimiting()
        for chain in ['DOCKER-USER', 'POSTROUTING']:
            for peer in self.all_peers:
                if self.parse_chain(chain, None, peer.ip4_addr):
                    self.iptables('-D %s -d %s' % (chain, peer.ip4_addr))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('sim-host', nargs='?', default='localhost')
    parser.add_argument('sim-port', nargs='?', default=8888)
    args = parser.parse_args()

    Router().run(args.sim_host, args.sim_port)
