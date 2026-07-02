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

import os
from queue import Empty

from autonomous_trust.core import AutonomousTrust, Process, ProcMeta, LogLevel, CfgIds
from autonomous_trust.core.config import Configuration, to_json_string
from autonomous_trust.core.config.generate import random_config
from autonomous_trust.core.system import queue_cadence
from autonomous_trust.core.network import Network, Message
from autonomous_trust.core.reputation.protocol import ReputationProtocol

from .viz.server import VizServer, default_port as _viz_default_port
from .viz.live_graph import LiveData
from .transitive_trust import TransitiveTrustMixin, PEER_PAIR_QUERY_SEC


class InspectorProcess(Process, metaclass=ProcMeta,
                       proc_name='monitor', description='Silent system activity monitor'):
    command_deck = list(CfgIds) + ['package_hash', 'log-level', 'processes']

    def __init__(self, configurations, subsystems, log_q, dependencies):
        super().__init__(configurations, subsystems, log_q, dependencies=dependencies)

    def process(self, queues, signal):
        while self.keep_running(signal):
            try:
                cmd = queues[self.name].get(block=True, timeout=self.q_cadence)
                if isinstance(cmd, str):
                    if cmd in self.command_deck:
                        obj = self.configs[cmd]
                        msg_str = to_json_string(obj)
                        # send straight to viz server
                        queues['main'].put(msg_str, block=True, timeout=self.q_cadence)
            except Empty:
                pass


class Inspector(TransitiveTrustMixin, AutonomousTrust):
    def __init__(self, port=None, **kwargs):
        super().__init__(**kwargs)
        self.add_worker(InspectorProcess, self.system_dependencies)
        self.viz = None
        self.data_queue = self.queue_type()
        self._viz_port = port if port is not None else _viz_default_port

    def init_tasking(self, queues):
        viz_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'viz'))
        self.viz = VizServer(viz_dir, self._viz_port,
                             data_q=self.data_queue, finished=self.cleanup)
        self.viz.run()

    def autonomous_tasking(self, queues):
        if self.tasking_tick(1):  # every 30 sec
            for peer in self.peers.all:
                query = Message(CfgIds.reputation, ReputationProtocol.rep_req,
                                to_json_string((peer, self.proc_name)), self.identity)
                queues[CfgIds.reputation].put(query, block=True, timeout=queue_cadence)
                ping = Message(CfgIds.network, Network.ping, 5, peer, return_to=self.proc_name)
                queues[CfgIds.network].put(ping, block=True, timeout=queue_cadence)
        if self.tasking_tick(3, PEER_PAIR_QUERY_SEC):
            # Transitive trust (resolves the former open design question):
            # ask each observer for its view of every other subject. Responses
            # land in self.latest_reputation_pairs (automate.py), which we
            # forward to the live graph below as (observer, subject, score)
            # triples — run_data_handlers folds those into per-observer edge
            # trust. One-hop for now; deeper walking would need peers to share
            # their own rosters.
            self.query_peer_pairs(queues, logger=self.logger)
        if self.tasking_tick(2, 5.0):  # every 5 sec
            # Direct trust: our own view of each peer -> node reputation.
            for peer_id in self.latest_reputation:
                self.data_queue.put((LiveData.reputation, self.latest_reputation[peer_id]),
                                    block=True, timeout=queue_cadence)
            # Transitive trust: each observer's view of each subject -> edge.
            for (obs_uuid, sub_uuid), rep in list(self.latest_reputation_pairs.items()):
                score = getattr(rep, 'score', rep)
                self.data_queue.put(
                    (LiveData.reputation, (str(obs_uuid), str(sub_uuid), score)),
                    block=True, timeout=queue_cadence)
            for message in list(self.unhandled_messages):
                # unhandled_messages may contain non-Message objects
                # (e.g. IdentityByAuthority); skip anything without .function.
                if getattr(message, "function", None) == Network.ping:
                    self.unhandled_messages.remove(message)
                    self.data_queue.put((LiveData.latencies, message.obj),
                                        block=True, timeout=queue_cadence)
            self._report_unhandled()

    def cleanup(self):
        self.viz.stop()


if __name__ == '__main__':
    random_config(os.path.join(os.path.dirname(__file__)), 'monitor')
    Inspector(log_level=LogLevel.INFO, logfile=Configuration.log_stdout).run_forever()
