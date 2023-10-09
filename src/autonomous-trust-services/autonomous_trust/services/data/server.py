from queue import Empty

from autonomous_trust.core import Process, ProcMeta, CfgIds
from autonomous_trust.core.identity import Identity
from autonomous_trust.core.network import Message
from autonomous_trust.core.protocol import Protocol


class DataProtocol(Protocol):
    request = 'request'
    data = 'data'


class DataSource(Process, metaclass=ProcMeta,
                 proc_name='data-source', description='Data stream service'):
    header_fmt = "!Q?Q"
    capability_name = 'data'

    def __init__(self, configurations, subsystems, log_queue, dependencies, **kwargs):
        super().__init__(configurations, subsystems, log_queue, dependencies=dependencies)
        self.protocol = DataProtocol(self.name, self.logger, configurations[CfgIds.peers])
        self.protocol.register_handler(DataProtocol.request, self.handle_requests)
        self.clients: dict[str, tuple[bool, str, Identity]] = {}

    def handle_requests(self, _, message):
        if message.function == DataProtocol.request:
            fast_encoding, proc_name = message.obj
            uuid = message.from_whom.uuid
            if uuid not in self.clients:
                self.clients[uuid] = fast_encoding, proc_name, message.from_whom
            return True
        return False

    def process_messages(self, queues):
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
