# ******************
#  Copyright 2024 TekFive, Inc. and contributors
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

import struct
from queue import Empty, Full

from autonomous_trust.core import Process, ProcMeta, CfgIds, from_yaml_string
from autonomous_trust.core.network import Message
from .server import DataProcess, DataProtocol


class DataRcvr(Process, metaclass=ProcMeta,
               proc_name='data-sink', description='Data stream consumer'):
    header_fmt = DataProcess.header_fmt

    def __init__(self, configurations, subsystems, log_queue, dependencies, **kwargs):
        super().__init__(configurations, subsystems, log_queue, dependencies=dependencies)
        self.cohort = kwargs['cohort']
        self.servicers = []
        self.hdr_size = struct.calcsize(self.header_fmt)
        self.protocol = DataProtocol(self.name, self.logger, configurations)
        self.protocol.register_handler(DataProtocol.data, self.handle_data)

    def handle_data(self, _, message):
        if message.function == DataProtocol.data:
            try:
                uuid = message.from_whom.uuid
                data = from_yaml_string(message.obj)
                if uuid in self.cohort.peers:
                    self.cohort.peers[uuid].data_stream.put(data, block=True, timeout=self.q_cadence)
            except (Full, Empty):
                pass

    def process(self, queues, signal):
        while self.keep_running(signal):
            if DataProcess.capability_name in self.protocol.peer_capabilities:
                for peer in self.protocol.peer_capabilities[DataProcess.capability_name]:
                    if peer not in self.servicers:
                        self.servicers.append(peer)
                        msg_obj = self.name
                        msg = Message(DataProcess.name, DataProtocol.request, msg_obj, peer)
                        queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)

            try:
                message = queues[self.name].get(block=True, timeout=self.q_cadence)
            except Empty:
                message = None
            if message:
                if not self.protocol.run_message_handlers(queues, message):
                    if isinstance(message, Message):
                        self.logger.error('Unhandled message %s' % message.function)
                    else:
                        self.logger.error('Unhandled message of type %s' % message.__class__.__name__)  # noqa
