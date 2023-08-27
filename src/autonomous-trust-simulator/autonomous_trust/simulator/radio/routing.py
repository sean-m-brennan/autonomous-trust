import json
import os
import subprocess
import shlex

from .. import net_util as net
from ..simulator import SimState, InterfaceClasses


class Router(net.Client):
    header_fmt = '!Q'
    rate_limt = False

    def __init__(self):
        super().__init__()
        self.all_peers = []
        if os.geteuid() != 0:
            raise RuntimeError('This user cannot modify iptables')

        if self.rate_limt:
            iface = 'docker0'
            max_rate = max_bw = '100Gbit'  # FIXME measure

            # clear & recreate:
            self.traffic_ctl('qdisc', 'del dev', iface, 'root')
            self.traffic_ctl('qdisc', 'add dev', iface,
                             'root handle 1: cbq bandwidth %s avpkt 1000' % max_bw)

            # base traffic class:
            self.traffic_ctl('class', 'add dev', iface,
                             'parent 1:0 classid 1:1 cbq bandwidth %s rate %s allot 1514 weight %s prio 8 maxburst 1000 avpkt 1000' % (max_bw, max_rate, max_rate))
            # full-speed traffic class:
            self.traffic_ctl('class', 'add dev', iface,
                             'parent 1:1 classid 1:100 cbq bandwidth %s rate %s allot 1514 weight 1Mbit prio 5 maxburst 1000 avpkt 1000' % (max_bw, max_rate))
            self.traffic_ctl('qdisc', 'add dev', iface,
                             'parent 1:100 sfq quantum 1514b perturb 15')
            # throttled classes:
            for net_class in [n.value for n in InterfaceClasses]:
                self.traffic_ctl('class', 'add dev', iface,
                                 'parent 1:1 classid 1:200 cbq bandwidth %s rate %s allot 1514 weight %s prio 3 maxburst 5 avpkt 1000 bounded' % (max_bw, net_class.rate, net_class.rate))
                self.traffic_ctl('qdisc', 'add dev', iface,
                                 'parent 1:200 tbf rate %s latency 100ms burst 1540' % net_class.rate)
                self.traffic_ctl('qdisc', 'add dev', iface,
                                 'protocol ip parent 1:0 prio 8 handle %d fw flowid 1:200' % net_class.mark)

    @staticmethod
    def iptables(args, output=False):
        if output:
            return subprocess.check_output(shlex.split('sudo iptables ' + args)).decode().split('\n')
        subprocess.check_call(shlex.split('sudo iptables ' + args))

    @staticmethod
    def traffic_ctl(mode, cmd, iface, params):
        subprocess.check_call(shlex.split('sudo tc %s %s %s %s' % (mode, cmd, iface, params)))

    def chain_available(self, chain):
        try:
            self.iptables('-L %s' % chain)
            return True
        except subprocess.CalledProcessError:
            return False
        
    def parse_chain(self, chain, src=None, dst=None):
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
        if not self.chain_available(chain):
            raise RuntimeError('Docker not running (required)')

        for peer in state.reachable:
            for other in state.reachable[peer.uuid]:
                rule_present = self.parse_chain(chain, peer.ip, other.ip)
                # FIXME need IP addresses for all peers!!
                if state.reachable[peer][other]:  # unblock
                    if rule_present:
                        self.iptables('-D %s -s %s -d %s DROP' % (chain, peer.ip, other.ip))
                else:
                    if not rule_present:  # cannot reach, block
                        self.iptables('-A %s -s %s -d %s DROP' % (chain, peer.ip, other.ip))

        if self.rate_limt:
            for peer in state.peers:
                if peer not in self.all_peers:
                    self.all_peers.append(peer)

                for chain in ['POSTROUTING']:  # FIXME 'PREROUTING'??
                    #if not self.chain_available(chain):  # FIXME is this created by tc?
                    #    self.iptables('-N %s' % chain)
                    #   self.iptables('-A OUTPUT -j Services')

                    if not self.parse_chain(chain, None, peer.ip):
                        self.iptables('-A %s -t mangle -j MARK --set-mark %d -d %s' % (chain, peer.mark, peer.ip))

    def finish(self):  # clear any rules created
        for chain in ['DOCKER-USER', 'POSTROUTING']:
            for peer in self.all_peers:
                if self.parse_chain(chain, None, peer.ip):
                    self.iptables('-D %s -d %s' % (chain, peer.ip))


if __name__ == '__main__':
    Router().run('127.0.1.1', 8888)