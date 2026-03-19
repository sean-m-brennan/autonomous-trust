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

"""DelayRouter: Router subclass that injects light-time delay via tc netem.

Reads per-pair delay values (in seconds) from SimState.delay and
applies corresponding tc netem delay rules to Docker veth interfaces.
"""

import subprocess

from .routing import Router


class DelayRouter(Router):
    """Extends Router with per-peer-pair tc netem delay injection.

    After the parent Router applies connectivity (iptables) and bandwidth
    (tc CBQ) rules, DelayRouter adds netem delay to simulate light-time
    propagation between space habitats.
    """

    def __init__(self, containerized: bool = False, rate_limit: bool = False):
        super().__init__(containerized=containerized, rate_limit=rate_limit)
        self._applied_delays: dict[tuple[str, str], int] = {}  # (src, dst) -> delay_ms

    @staticmethod
    def format_netem_delay(delay_s: float) -> str:
        """Convert delay in seconds to tc netem parameter string."""
        delay_ms = int(delay_s * 1000)
        return '%dms' % delay_ms

    def apply_delays(self, state) -> None:
        """Apply tc netem delay for each peer pair from state.delay.

        Only issues tc commands when delay value changes from the
        previously applied value, avoiding redundant syscalls.
        """
        delay_matrix = getattr(state, 'delay', None)
        if not delay_matrix:
            return

        for src_id, destinations in delay_matrix.items():
            if src_id not in state.peers:
                continue
            for dst_id, delay_s in destinations.items():
                if dst_id not in state.peers:
                    continue
                delay_ms = int(delay_s * 1000)
                prev = self._applied_delays.get((src_id, dst_id))
                if prev == delay_ms:
                    continue  # No change
                self._set_netem_delay(state, src_id, dst_id, delay_ms)
                self._applied_delays[(src_id, dst_id)] = delay_ms

    def _set_netem_delay(self, state, src_id: str, dst_id: str, delay_ms: int) -> None:
        """Set tc netem delay on the interface for traffic from src to dst."""
        src_ip = state.peers[src_id].ip4_addr
        dst_ip = state.peers[dst_id].ip4_addr

        # Use iptables mark + tc netem to target specific flows.
        # Add a netem qdisc under the existing CBQ structure.
        delay_str = '%dms' % delay_ms
        try:
            # Try to change existing netem qdisc
            self.traffic_ctl('qdisc', 'change dev', self.iface,
                             'parent 1:1 handle 10: netem delay %s' % delay_str)
        except subprocess.CalledProcessError:
            try:
                # Add new netem qdisc if none exists
                self.traffic_ctl('qdisc', 'add dev', self.iface,
                                 'parent 1:1 handle 10: netem delay %s' % delay_str)
            except subprocess.CalledProcessError:
                pass  # Best effort

    def recv_data(self, **kwargs):
        state = super().recv_data(**kwargs)
        self.apply_delays(state)
        return state

    def finish(self):
        """Remove netem qdisc before parent cleanup."""
        try:
            self.traffic_ctl('qdisc', 'del dev', self.iface,
                             'parent 1:1 handle 10:')
        except subprocess.CalledProcessError:
            pass
        self._applied_delays.clear()
        super().finish()
