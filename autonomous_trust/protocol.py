from .util import ClassEnumMeta
from .identity import Group, Peers
from .network import Message
from .capabilities import Capabilities


class Protocol(object, metaclass=ClassEnumMeta):
    def __init__(self, proc_name, logger, peers, group=None):
        self.proc_name = proc_name
        self.logger = logger
        self.peers = peers
        self.group = group
        self.capabilities = []
        self.handlers = {}

    def register_handler(self, func_name, handler):
        self.handlers[func_name] = handler

    def run_message_handlers(self, queues, message):
        if isinstance(message, Group):
            self.group = message
            self.logger.debug('Updated group')
            return True
        if isinstance(message, Peers):
            self.peers = message
            self.logger.debug('Updated peers')
            return True
        if isinstance(message, Capabilities):
            self.capabilities = message
            self.logger.debug('Updated my own capabilities')
            return True
        if isinstance(message, Message):
            if message.process == self.proc_name:
                for name, handler in self.handlers.items():
                    if name in self.handlers and name == message.function:
                        return self.handlers[name](queues, message)
            return False
