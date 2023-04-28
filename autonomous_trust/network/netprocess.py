import threading
from queue import Empty, Full
from enum import Enum

from ..processes import Process, ProcMeta
from ..config.configuration import CfgIds
from .network import Network
from .message import Message


class NetworkProtocol(Enum):
    IPV4 = 4
    IPV6 = 6
    MAC = 2
    NONE = 0


class TransmissionError(RuntimeError):
    pass


class _NetProcMeta(ProcMeta):  # so that subclasses inherit meta args
    def __init__(cls, name, bases, namespace, cadence=0.0001, port=27787):
        super().__init__(name, bases, namespace,
                         proc_name=CfgIds.network.value, description='Network I/O')
        cls.cadence = cadence
        cls.default_port = port


class NetworkProcess(Process, metaclass=_NetProcMeta):
    """
    Handle requests to send Messages over the network and route incoming Messages to the right process
    Abstract class - subclasses must implement send_* and recv_* methods
    """
    rcv_backlog = 5
    annoy_limit = 5
    net_proto = NetworkProtocol.NONE

    def __init__(self, configurations, subsystems, log_q, acceptance_func=None):
        super().__init__(configurations, subsystems, log_q)
        self.net_cfg = configurations[CfgIds.network.value]
        port = self.net_cfg.port
        self.port = port
        if port is None:
            self.port = self.default_port
        self.myself = configurations[CfgIds.identity.value]
        self.peers = configurations[CfgIds.peers.value]
        self.peer_messages = []
        self.unknown_messages = []
        self.acceptance = acceptance_func
        self.pests = {}

    def send_peer(self, msg, whom_list):
        raise NotImplementedError

    def send_all(self, msg):
        raise NotImplementedError

    def recv_peer(self):
        raise NotImplementedError

    def recv_any(self):
        raise NotImplementedError

    def accept_peer_message(self, address):
        """
        Accept/reject messages based on sender's address
        :param address: Incoming sender
        :return: bool
        """
        if self.acceptance is not None:
            return self.acceptance(address)
        if self.peers.find_by_address(address) is None:
            return False
        return True

    def reject_message(self, address):  # FIXME
        return False

    def peer_receiver(self):
        """
        Receive thread for point-to-point
        Track peers not on whitelist (accept_peer_message), demote if they persist
        :return: None
        """
        while True:
            try:
                raw_msg, from_addr = self.recv_peer()
            except TransmissionError as err:
                self.logger.error('Network: %s' % err)
                continue
            if raw_msg is not None:
                self.peer_messages.append((raw_msg, from_addr))
            else:
                who = self.peers.find_by_address(from_addr)
                if who is not None:
                    if who not in self.pests.keys():
                        self.pests[who] = 0
                    self.pests[who] += 1
                    if self.pests[who] > self.annoy_limit:
                        self.peers.demote(who)
                        del self.pests[who]

    def unknown_receiver(self):
        """
        Receive thread for one-to_many
        :return: None
        """
        while True:
            try:
                raw_msg, from_addr = self.recv_any()
            except TransmissionError as err:
                self.logger.error('Network: %s' % err)
                continue
            if raw_msg is not None:
                self.unknown_messages.append((raw_msg, from_addr))

    def process(self, queues, signal):
        """
        Network processing main loop
        Two channels:
            open, one-to-any - requires enhanced security
            encrypted, one-to-n, 1 <= n <= all peers
        :param queues: Interprocess communication queues
        :param signal: IPC queue for signalling halt
        :return:
        """
        threading.Thread(target=self.peer_receiver, daemon=True).start()
        threading.Thread(target=self.unknown_receiver, daemon=True).start()
        while self.keep_running(signal):
            try:
                message = queues[self.name].get(block=True, timeout=self.q_cadence)
            except Empty:
                message = None
            if message:
                if isinstance(message, Message):
                    self.logger.debug('Send network message: %s' % message.process)
                    try:
                        if message.to_whom == Network.broadcast:
                            try:
                                self.send_all(bytes(message))
                            except TransmissionError as err:
                                self.logger.error('Network: %s' % err)
                        else:  # defaults to pseudo-multicast
                            for who in message.to_whom:  # Message ensures this is list
                                encrypt_msg = self.myself.encrypt(bytes(message), who)
                                try:
                                    self.send_peer(encrypt_msg, who.address)
                                except TransmissionError as err:
                                    self.logger.error('Network: %s' % err)
                    except BrokenPipeError as err:
                        self.logger.error('Network: %s' % err)
                else:
                    self.logger.error('Net process recvd message of type %s - Message required. Ignoring.' %
                                      type(message))
                    self.logger.debug('Message: %s' % str(message))

            # async recv peer messages
            if len(self.peer_messages) > 0:
                raw_msg, from_addr = self.peer_messages.pop(0)
                from_whom = self.configs[CfgIds.peers.value].find_by_address(from_addr)
                if from_whom is not None:
                    decrypt_msg = self.myself.decrypt(raw_msg, from_whom)
                    message = Message.parse(decrypt_msg, from_whom)
                    for sub_sys_proc in self.subsystems.keys():
                        if message.process == sub_sys_proc:
                            try:
                                queues[sub_sys_proc].put(message, block=True, timeout=self.q_cadence)
                                self.logger.debug('Recvd network message for %s:%s' % (sub_sys_proc, message.function))
                            except Full:
                                self.logger.error('Network: %s queue is full' % sub_sys_proc)
                else:
                    self.logger.error('Recvd transmission from %s - not recognized as a peer. Ignoring.' % from_addr)
                    self.logger.debug('Message: %s' % str(message))

            # async recv stranger messages (separate channel)
            if len(self.unknown_messages) > 0:
                raw_msg, from_addr = self.unknown_messages.pop(0)
                message = Message.parse(raw_msg, from_addr, validate=False)
                for sub_sys_proc in self.subsystems.keys():
                    if message.process == sub_sys_proc:
                        try:
                            queues[sub_sys_proc].put(message, block=True, timeout=self.q_cadence)
                            self.logger.debug('Recvd multicast message for %s:%s' % (sub_sys_proc, message.function))
                        except Full:
                            self.logger.error('Network: %s queue is full' % sub_sys_proc)
