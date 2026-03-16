"""Byzantine node: sends inconsistent reputation scores to different peers.

Exploits two known vulnerabilities in ReputationProcess:
1. Unverified NaCl signatures on Paxos proposals (repprocess.py lines 217, 248)
2. Majority voting at >= n//2 (prepare) and > n//2 (accept) instead of > 2n/3
"""

import hashlib
from typing import Optional

from autonomous_trust.core._python.reputation.repprocess import ReputationProcess
from autonomous_trust.core._python.reputation.protocol import ReputationProtocol
from autonomous_trust.core._python.processes import ProcMeta
from autonomous_trust.core._python.network.message import Message
from autonomous_trust.core._python.config import from_json_string, to_json_string
from autonomous_trust.core._python.system import CfgIds
from autonomous_trust.simulator.redteam import AttackScenario


class ByzantineReputationProcess(ReputationProcess, metaclass=ProcMeta,
                                  proc_name='reputation-byzantine',
                                  description='Byzantine reputation (adversarial)',
                                  cfg_name='reputation-byzantine'):
    """Sends different TransactionScore values to different peers.

    Note: Uses a distinct cfg_name ('reputation-byzantine') to avoid
    conflicting with ReputationProcess's registration in ProcessTracker.
    The harness swaps this in at setup time by modifying subsystems.cfg.json.

    Strategy: when handling a transaction proposal, instead of forwarding
    the same score to all peers, send inflated scores to half and deflated
    scores to the other half. This exploits the lack of signature verification
    on Paxos proposals.
    """

    inflation = 0.3
    deflation = -0.3

    def handle_transaction(self, queues, message):
        """Override: send inconsistent scores to different peers."""
        if message.function != ReputationProtocol.transaction:
            return False

        (id1, id2, peer_id), score = from_json_string(message.obj)
        idx = self._paxos_id_index(id1, id2)
        if idx not in self.requests:
            return True
        self.requests.remove(idx)

        if idx not in self.proposals:
            self.proposals[idx] = score

        for peer in self.protocol.peers.all:
            peer_hash = int(hashlib.md5(str(peer).encode()).hexdigest(), 16)
            if peer_hash % 2 == 0:
                skewed_score = min(1.0, score + self.inflation)
            else:
                skewed_score = max(0.0, score + self.deflation)

            msg = Message(
                self.name, ReputationProtocol.accepted,
                to_json_string((id1, id2, peer_id)),
                peer,
            )
            queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)

        self.logger.debug("Byzantine: sent inconsistent scores for (%s, %s)" % (id1, id2))
        return True

    def handle_reputation_request(self, _, message):
        """Override: return inflated/deflated scores depending on requester."""
        if message.function != ReputationProtocol.rep_req:
            return False

        if isinstance(message.obj, str):
            ident, req_proc = from_json_string(message.obj)
        else:
            ident, req_proc = message.obj

        req_hash = int(hashlib.md5(str(message.from_whom).encode()).hexdigest(), 16)
        if req_hash % 2 == 0:
            self.logger.debug("Byzantine: inflating reputation for %s (requester %s)" %
                            (ident, message.from_whom))
        else:
            self.logger.debug("Byzantine: deflating reputation for %s (requester %s)" %
                            (ident, message.from_whom))

        return super().handle_reputation_request(_, message)


class ByzantineNodeAttack(AttackScenario):
    """Attack scenario: deploy Byzantine reputation nodes."""

    name = "byzantine_node"
    description = "Modified ReputationProcess sending inconsistent scores"

    def __init__(self, byzantine_peer_ids: list[str]):
        self.byzantine_peer_ids = byzantine_peer_ids

    def setup(self, sim_config: dict, compose_config: dict) -> None:
        """Mark designated peers as Byzantine in the simulation config."""
        sim_config['byzantine_peers'] = self.byzantine_peer_ids
        sim_config['byzantine_process_class'] = ByzantineReputationProcess

    def teardown(self) -> None:
        pass

    def collect(self, metrics: dict) -> dict:
        metrics['attack_specific'] = {
            'byzantine_peer_ids': self.byzantine_peer_ids,
            'byzantine_detected': None,
            'byzantine_reputation_drop': None,
            'consensus_integrity': None,
        }
        return metrics
