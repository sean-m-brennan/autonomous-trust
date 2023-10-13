import warnings
from queue import Empty, Full

from autonomous_trust.core import Process, ProcMeta, CfgIds, Configuration, to_yaml_string
from autonomous_trust.core.identity import Identity
from autonomous_trust.core.network import Message
from autonomous_trust.core.protocol import Protocol


class DataProtocol(Protocol):
    request = 'request'
    data = 'data'


class DataSrc(Configuration):
    def __init__(self, channels: int = 3):
        self.channels = channels

    @classmethod
    def initialize(cls, channels: int):
        return DataSrc(channels)


class DataSource(Process, metaclass=ProcMeta,
                 proc_name='data-source', description='Data stream service'):
    header_fmt = "!Q?Q"
    capability_name = 'data'

    def __init__(self, configurations, subsystems, log_queue, dependencies):
        super().__init__(configurations, subsystems, log_queue, dependencies=dependencies)
        self.active = self.name in configurations
        if self.active:
            self.cfg = configurations[self.name]
        self.protocol = DataProtocol(self.name, self.logger, configurations[CfgIds.peers])
        self.protocol.register_handler(DataProtocol.request, self.handle_requests)
        self.clients: dict[str, tuple[str, Identity]] = {}

    def acquire(self):
        warnings.warn('NotImplementedError: DataSource.acquire() is not implemented - override.')
        return [None, None, None]

    def handle_requests(self, _, message):
        if message.function == DataProtocol.request and self.active:
            proc_name = message.obj
            uuid = message.from_whom.uuid
            if uuid not in self.clients:
                self.clients[uuid] = proc_name, message.from_whom
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

    def process(self, queues, signal):
        while self.keep_running(signal):
            self.process_messages(queues)

            if self.active:
                data = self.acquire()
                for client_id in self.clients:
                    proc_name, peer = self.clients[client_id]
                    msg_obj = to_yaml_string(data)
                    msg = Message(proc_name, DataProtocol.data, msg_obj, peer)
                    try:
                        queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
                    except Full:
                        pass

            self.sleep_until(self.cadence)
