import struct
from queue import Empty, Full

from autonomous_trust.core import Process, ProcMeta, CfgIds, from_yaml_string
from autonomous_trust.core.network import Message
from .server import DataSource, DataProtocol


class DataRcvr(Process, metaclass=ProcMeta,
               proc_name='data-sink', description='Data stream consumer'):
    header_fmt = DataSource.header_fmt

    def __init__(self, configurations, subsystems, log_queue, dependencies, **kwargs):
        super().__init__(configurations, subsystems, log_queue, dependencies=dependencies)
        self.cohort = kwargs['cohort']
        self.servicers = []
        self.hdr_size = struct.calcsize(self.header_fmt)
        self.protocol = DataProtocol(self.name, self.logger, configurations[CfgIds.peers])
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
            if DataSource.capability_name in self.protocol.peer_capabilities:
                for peer in self.protocol.peer_capabilities[DataSource.capability_name]:
                    if peer not in self.servicers:
                        self.servicers.append(peer)
                        msg_obj = self.name
                        msg = Message(DataSource.name, DataProtocol.request, msg_obj, peer)
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
