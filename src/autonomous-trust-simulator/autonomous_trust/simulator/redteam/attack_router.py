"""AttackRouter: Router subclass that injects network partitions on schedule."""

from autonomous_trust.simulator.radio.routing import Router
from autonomous_trust.simulator.redteam import AttackScenario, PartitionEvent


class AttackRouter(Router):
    """Extends Router with scheduled network partition injection.

    After the parent Router applies connectivity-matrix-based iptables rules,
    AttackRouter re-injects DROP rules for any active partitions. This ordering
    ensures partitions override connectivity even if the parent just allowed a link.
    """

    def __init__(self, partitions: list[PartitionEvent],
                 containerized: bool = False, rate_limit: bool = False):
        super().__init__(containerized=containerized, rate_limit=rate_limit)
        self.partitions = partitions
        self._active_partitions: set[int] = set()
        self._start_time = None  # Set on first recv_data

    def recv_data(self, **kwargs):
        state = super().recv_data(**kwargs)
        self._apply_partitions(state)
        return state

    def _apply_partitions(self, state):
        """Check partition schedule against current sim time, activate/deactivate.

        Note: SimState has `time` (datetime) but no `elapsed_s`. We compute
        elapsed seconds from the first state timestamp.
        """
        if self._start_time is None:
            self._start_time = state.time
        elapsed = (state.time - self._start_time).total_seconds()
        for i, p in enumerate(self.partitions):
            if p.start_s <= elapsed < p.end_s:
                if i not in self._active_partitions:
                    self._activate_partition(p, state)
                    self._active_partitions.add(i)
            elif i in self._active_partitions:
                self._deactivate_partition(p, state)
                self._active_partitions.discard(i)

    def _activate_partition(self, partition: PartitionEvent, state):
        """Inject bidirectional DROP rules between partition groups."""
        chain = 'OUTPUT' if self.containerized else 'DOCKER-USER'
        for a_id in partition.group_a:
            for b_id in partition.group_b:
                a_ip = state.peers[a_id].ip4_addr
                b_ip = state.peers[b_id].ip4_addr
                self.iptables('-A %s -s %s -d %s -j DROP' % (chain, a_ip, b_ip))
                self.iptables('-A %s -s %s -d %s -j DROP' % (chain, b_ip, a_ip))

    def _deactivate_partition(self, partition: PartitionEvent, state):
        """Remove bidirectional DROP rules between partition groups."""
        if state is None:
            return  # Called from finish() with no state — rules cleared by parent
        chain = 'OUTPUT' if self.containerized else 'DOCKER-USER'
        for a_id in partition.group_a:
            for b_id in partition.group_b:
                a_ip = state.peers[a_id].ip4_addr
                b_ip = state.peers[b_id].ip4_addr
                try:
                    self.iptables('-D %s -s %s -d %s -j DROP' % (chain, a_ip, b_ip))
                    self.iptables('-D %s -s %s -d %s -j DROP' % (chain, b_ip, a_ip))
                except Exception:
                    pass  # Rule may already be gone

    def finish(self):
        """Clear all partition rules before parent cleanup."""
        for i in list(self._active_partitions):
            self._deactivate_partition(self.partitions[i], None)
        self._active_partitions.clear()
        super().finish()


class NetworkPartitionAttack(AttackScenario):
    """Attack scenario: scheduled network partition via iptables."""

    name = "network_partition"
    description = "iptables-based network split via AttackRouter"

    def __init__(self, partitions: list[PartitionEvent]):
        self.partitions = partitions

    def setup(self, sim_config: dict, compose_config: dict) -> None:
        """Replace Router with AttackRouter in the simulation config."""
        sim_config['router_class'] = AttackRouter
        sim_config['router_kwargs'] = {'partitions': self.partitions}

    def teardown(self) -> None:
        """No extra cleanup needed — AttackRouter.finish() handles iptables."""
        pass

    def collect(self, metrics: dict) -> dict:
        """Add partition-specific metrics."""
        metrics['attack_specific'] = {
            'partitions_scheduled': len(self.partitions),
            'partition_events': [
                {'start_s': p.start_s, 'end_s': p.end_s,
                 'group_a': p.group_a, 'group_b': p.group_b}
                for p in self.partitions
            ],
        }
        return metrics
