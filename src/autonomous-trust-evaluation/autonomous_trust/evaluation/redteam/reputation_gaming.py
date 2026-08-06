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
"""Reputation gaming: cooperate then defect to exploit trust."""

import time

from autonomous_trust.core._python.reputation.repprocess import ReputationProcess
from autonomous_trust.core._python.reputation.protocol import ReputationProtocol
from autonomous_trust.core._python.processes import ProcMeta
from autonomous_trust.core._python.system import CfgIds
from autonomous_trust.evaluation.redteam import AttackScenario


class GamingReputationProcess(ReputationProcess, metaclass=ProcMeta,
                               proc_name='reputation-gaming',
                               description='Reputation gaming (cooperate then defect)',
                               cfg_name='reputation-gaming'):
    """Cooperates normally until defection_time_s, then defects.

    Defection means: reject all incoming transaction proposals and
    send negative reputation responses, exploiting the trust built
    during the cooperative phase.
    """

    defection_time_s: float = 60.0
    _start_time: float = 0.0

    def process(self, queues, signal):
        self._start_time = time.monotonic()
        super().process(queues, signal)

    @property
    def _is_defecting(self) -> bool:
        return (time.monotonic() - self._start_time) >= self.defection_time_s

    def handle_transaction(self, queues, message):
        if self._is_defecting and message.function == ReputationProtocol.transaction:
            self.logger.debug("Gaming: defecting — dropping transaction from %s" %
                            message.from_whom)
            return True
        return super().handle_transaction(queues, message)


class ReputationGamingAttack(AttackScenario):
    name = "reputation_gaming"
    description = "Build reputation through cooperation, then defect"

    def __init__(self, gaming_peer_ids: list[str], defection_time_s: float = 60.0):
        self.gaming_peer_ids = gaming_peer_ids
        self.defection_time_s = defection_time_s

    def setup(self, sim_config: dict, compose_config: dict) -> None:
        sim_config['gaming_peers'] = self.gaming_peer_ids
        sim_config['defection_time_s'] = self.defection_time_s
        sim_config['gaming_process_class'] = GamingReputationProcess

    def teardown(self) -> None:
        pass

    def collect(self, metrics: dict) -> dict:
        metrics['attack_specific'] = {
            'gaming_peer_ids': self.gaming_peer_ids,
            'defection_time_s': self.defection_time_s,
            'pre_defection_reputation': None,
            'post_defection_reputation': None,
            'penalty_exceeds_gain': None,
        }
        return metrics
