import logging

import icontract

from .system import QueueType
from .util import ClassEnumMeta
from .identity import Group, Peers
from .network import Message
from .capabilities import Capabilities, PeerCapabilities

PeerHistory = tuple[Peers, PeerCapabilities]


class Protocol(object, metaclass=ClassEnumMeta):
    def __init__(self, proc_name: str, logger: logging.Logger, peer_info: PeerHistory, group: Group = None):
        self.proc_name = proc_name
        self.logger = logger
        if peer_info is not None:
            self.peers = peer_info[0]
            self.peer_capabilities = peer_info[1]
        else:
            self.peers = Peers()
            self.peer_capabilities = PeerCapabilities()
        self.group: Group = group
        self.capabilities = Capabilities()
        self.handlers = {}

    def register_handler(self, func_name: str, handler):
        self.handlers[func_name] = handler

    @icontract.require(lambda queues: len(queues) > 0)
    @icontract.require(lambda message: message is not None)
    def run_message_handlers(self, queues: dict[str, QueueType], message: Message):
        if isinstance(message, Group):
            self.group = message
            return True
        if isinstance(message, Peers):
            self.peers = message
            return True
        if isinstance(message, Capabilities):
            self.capabilities = message
            return True
        if isinstance(message, PeerCapabilities):
            self.peer_capabilities = message
            return True
        if isinstance(message, Message):
            if message.process == self.proc_name:
                for name, handler in self.handlers.items():
                    if name == message.function:
                        return self.handlers[name](queues, message)
        return False
