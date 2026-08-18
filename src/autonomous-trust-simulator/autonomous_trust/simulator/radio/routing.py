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

    # Explicit HTB DRR quantum (bytes). Class rates span 10 Kbit..100 Gbit, so
    # no single `r2q` keeps the auto-computed quantum in range for every class
    # (hence the "quantum is big/small, consider r2q change" advisories). Since
    # the throttle classes are hard-capped (rate == ceil, no borrowing) the
    # quantum only affects sibling DRR fairness, not the rate cap, so we pin it
    # to one MTU on every class: this silences the advisory (only emitted on the
    # auto-compute path) without changing shaping behaviour.
    _htb_quantum = 1514

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
        # Ingress rate-limiting: tc only shapes egress, so
        # ingress is shaped by redirecting the iface's ingress to this IFB
        # device and applying the same class tree there. Set once ingress
        # shaping is successfully wired in _setup_ingress_ifb(); when False
        # (platform without IFB, or setup failed) the router falls back to
        # egress-only shaping and skips the PREROUTING mark rules.
        self.ifb_dev = 'ifb0'
        self._ingress_shaping = False
        self._ingress_classified: set = set()  # source IPs given an IFB u32 filter

        if os.geteuid() != 0:
            raise RuntimeError('This user cannot modify iptables')

        if self.rate_limit:
            self.limiting()

    @property
    def iface(self):
        if self.containerized:
            return 'eth0'
        return 'docker0'

    def _reset_root_qdisc(self, dev, spec):
        """Install a fresh root qdisc on `dev`, tolerating both a fresh device
        (whose default `noqueue` root has handle 0 and cannot be *deleted* --
        "Cannot delete qdisc with handle of zero") and a re-run (an existing
        qdisc that must be removed first). `tc qdisc replace` is unsuitable:
        against an existing same-handle qdisc it becomes an in-place *change*,
        which HTB rejects ("Change operation not supported"). So delete
        best-effort, then add; a real add failure still propagates to the
        caller.
        """
        try:
            self.traffic_ctl('qdisc', 'del dev', dev, 'root')
        except subprocess.CalledProcessError:
            pass  # fresh device: undeletable noqueue root -- fine, just add
        self.traffic_ctl('qdisc', 'add dev', dev, spec)

    def _build_shaping_tree(self, dev, fw_filters=True):
        """Build the HTB class tree + per-NetInterface throttle classes on `dev`
        and (idempotently) populate self._mark_to_classid (mark -> classid).
        Assumes the caller already added the `1:` root qdisc (htb default 100).

        HTB is used because CBQ was removed from the Linux kernel in 6.8. The
        root class 1:1 holds the full link rate; 1:100 is the full-speed default
        for unclassified traffic; 1:200+ are the per-interface throttle classes
        (rate == ceil, i.e. a hard cap).

        `fw_filters` controls classification: on the EGRESS device it is True --
        packets are matched by fw MARK, since POSTROUTING marks are applied
        before the egress qdisc. On the ingress IFB device it is False, because
        the tc ingress redirect runs BEFORE netfilter PREROUTING (so no mark is
        set yet); ingress packets are instead classified by SOURCE IP via u32
        filters added per-peer in _classify_ingress.
        """
        # root class holding the full link bandwidth:
        self.traffic_ctl('class', 'add dev', dev,
                         'parent 1: classid 1:1 htb rate %s ceil %s quantum %d'
                         % (self.max_rate, self.max_bw, self._htb_quantum))
        # full-speed (default) class for unclassified traffic:
        self.traffic_ctl('class', 'add dev', dev,
                         'parent 1:1 classid 1:100 htb rate %s ceil %s quantum %d'
                         % (self.max_rate, self.max_rate, self._htb_quantum))
        self.traffic_ctl('qdisc', 'add dev', dev, 'parent 1:100 sfq perturb 15')
        # throttled classes: one per NetInterface type, keyed by iptables mark
        for idx, net_iface in enumerate(NetInterface):
            classid = 200 + idx
            self._mark_to_classid[net_iface.mark] = classid
            rate_str = '%dbit' % net_iface.rate
            self.traffic_ctl('class', 'add dev', dev,
                             'parent 1:1 classid 1:%d htb rate %s ceil %s quantum %d'
                             % (classid, rate_str, rate_str, self._htb_quantum))
            self.traffic_ctl('qdisc', 'add dev', dev, 'parent 1:%d sfq perturb 15' % classid)
            if fw_filters:
                self.traffic_ctl('filter', 'add dev', dev,
                                 'protocol ip parent 1: prio 8 handle %d fw flowid 1:%d'
                                 % (net_iface.mark, classid))

    def _setup_ingress_ifb(self):
        """Wire ingress shaping via an IFB device.

        `tc` shapes egress only; to rate-limit INGRESS we attach an ingress
        qdisc to self.iface and redirect all arriving packets to the IFB
        device, where they appear as egress and are shaped by the same class
        tree. Ingress packets are classified on the IFB by SOURCE IP (u32
        filters added per-peer in _classify_ingress) rather than by fw mark:
        the tc ingress redirect runs before netfilter PREROUTING, so a mark is
        not yet set when the packet reaches the IFB. Best-effort: any failure
        (kernel without IFB, restricted container) leaves _ingress_shaping False
        and the router shapes egress only -- exactly the prior behaviour.
        """
        try:
            subprocess.call(shlex.split('sudo modprobe ifb'))
            # add ifb device (may already exist from a prior run)
            subprocess.call(shlex.split('sudo ip link add %s type ifb' % self.ifb_dev))
            subprocess.check_call(shlex.split('sudo ip link set dev %s up' % self.ifb_dev))
            # ingress qdisc on the real iface + redirect everything to the IFB
            self.traffic_ctl('qdisc', 'add dev', self.iface, 'handle ffff: ingress')
            self.traffic_ctl('filter', 'add dev', self.iface,
                             'parent ffff: protocol ip u32 match u32 0 0 '
                             'action mirred egress redirect dev %s' % self.ifb_dev)
            self._reset_root_qdisc(self.ifb_dev, 'root handle 1: htb default 100')
            self._build_shaping_tree(self.ifb_dev, fw_filters=False)
            self._ingress_classified = set()
            self._ingress_shaping = True
        except subprocess.CalledProcessError:
            self._ingress_shaping = False  # egress-only fallback

    def _classify_ingress(self, src_ip, classid):
        """Add a u32 filter on the IFB steering ingress traffic FROM src_ip into
        the given throttle class. Idempotent per source IP. Used instead of fw
        marks because the ingress redirect precedes PREROUTING (see
        _setup_ingress_ifb)."""
        if not self._ingress_shaping or classid is None or src_ip in self._ingress_classified:
            return
        self.traffic_ctl('filter', 'add dev', self.ifb_dev,
                         'protocol ip parent 1: prio 8 u32 match ip src %s/32 flowid 1:%d'
                         % (src_ip, classid))
        self._ingress_classified.add(src_ip)

    def limiting(self):
        self.rate_limit = True

        # Snapshot the current root qdisc so unlimiting() can note what was
        # there (best-effort; the `dev` keyword is required by modern iproute2).
        try:
            self.orig_tc_qdisc = subprocess.check_output(
                shlex.split('sudo tc qdisc show dev %s' % self.iface))
        except subprocess.CalledProcessError:
            self.orig_tc_qdisc = None

        # (Re)create the egress tree on the real interface.
        self._reset_root_qdisc(self.iface, 'root handle 1: htb default 100')
        self._mark_to_classid = {}
        self._build_shaping_tree(self.iface, fw_filters=True)
        # ingress shaping (best-effort; falls back to egress-only):
        self._setup_ingress_ifb()

    def unlimiting(self):
        if self.rate_limit:
            self.rate_limit = False
            if self._ingress_shaping:
                # tear down the ingress redirect + IFB shaping
                try:
                    self.traffic_ctl('qdisc', 'del dev', self.iface, 'ingress')
                    self.traffic_ctl('qdisc', 'del dev', self.ifb_dev, 'root')
                    subprocess.call(shlex.split('sudo ip link set dev %s down' % self.ifb_dev))
                    subprocess.call(shlex.split('sudo ip link del %s' % self.ifb_dev))
                except subprocess.CalledProcessError:
                    pass
                self._ingress_shaping = False
            # Drop our egress root qdisc; the kernel restores the device
            # default (pfifo_fast/noqueue). Best-effort so teardown never
            # raises mid-cleanup.
            try:
                self.traffic_ctl('qdisc', 'del dev', self.iface, 'root')
            except subprocess.CalledProcessError:
                pass

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

    def _apply_reachability(self, state, chain):
        """Default-deny reachability. The connectivity matrix is
        now SPARSE: ``state.reachable[p]`` lists only the peers p can reach, so
        an absent pair means "unreachable". Iterating only the present keys (the
        old behaviour) would therefore never install a block, so we enumerate
        every ordered pair of ACTIVE peers and default-deny: unblock the pair
        iff it is present-and-reachable, otherwise block it. ``reach_row.get``
        yields True for a reachable sparse entry, None for an absent
        (unreachable) pair, and True/False for a dense space-mode entry -- all
        handled uniformly by the truthiness test.
        """
        managed = [pid for pid in state.active if pid in state.peers]
        for p_id in managed:
            peer = state.peers[p_id]
            reach_row = state.reachable.get(p_id, {})
            for o_id in managed:
                if o_id == p_id:
                    continue
                other = state.peers[o_id]
                rule_present = self.parse_chain(chain, peer.ip4_addr, other.ip4_addr)
                if reach_row.get(o_id):  # reachable -> unblock
                    if rule_present:
                        self.iptables('-D %s -s %s -d %s -j DROP' % (chain, peer.ip4_addr, other.ip4_addr))
                else:  # unreachable / absent -> block (default-deny)
                    if not rule_present:
                        self.iptables('-A %s -s %s -d %s -j DROP' % (chain, peer.ip4_addr, other.ip4_addr))

    def _apply_rate_marks(self, state):
        """Per-peer traffic classification for rate-limiting.

        EGRESS: mark packets by DESTINATION on the mangle POSTROUTING chain with
        the peer's fw mark; the egress fw filter (self.iface tree) shapes them.
        POSTROUTING (mangle) runs before the egress qdisc, so the mark is set in
        time.

        INGRESS: classify by SOURCE IP with a u32 filter on the IFB device (see
        _classify_ingress) -- NOT by fw mark, because the tc ingress redirect to
        the IFB runs before netfilter PREROUTING, so no mark is set yet when the
        packet reaches the IFB.
        """
        for peer in state.peers.values():
            if peer not in self.all_peers:
                self.all_peers.append(peer)
            mark = peer.iface.mark
            # egress: mangle MARK by destination on POSTROUTING
            chain = 'POSTROUTING'
            if not self.chain_available(chain):
                self.iptables('-N %s' % chain)
                self.iptables('-A OUTPUT -j %s' % chain)
            if not self.parse_chain(chain, None, peer.ip4_addr):
                self.iptables('-t mangle -A %s -j MARK --set-mark %d -d %s'
                              % (chain, mark, peer.ip4_addr))
            # ingress: u32 source-IP classification on the IFB
            self._classify_ingress(peer.ip4_addr, self._mark_to_classid.get(mark))

    def recv_data(self, **kwargs):
        state = super().recv_data(**kwargs)

        chain = 'DOCKER-USER'
        if self.containerized:
            chain = 'OUTPUT'
        if not self.chain_available(chain):
            raise RuntimeError('Docker not running (required)')

        self._apply_reachability(state, chain)

        if self.rate_limit:
            self._apply_rate_marks(state)

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
                # Degrade the class on the egress device and, when active, the
                # IFB ingress device, so both directions track link quality.
                degrade_devs = [self.iface]
                if self._ingress_shaping:
                    degrade_devs.append(self.ifb_dev)
                for dev in degrade_devs:
                    try:
                        self.traffic_ctl('class', 'change dev', dev,
                                         'parent 1:1 classid 1:%d htb rate %s ceil %s quantum %d'
                                         % (classid, rate_str, rate_str, self._htb_quantum))
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
