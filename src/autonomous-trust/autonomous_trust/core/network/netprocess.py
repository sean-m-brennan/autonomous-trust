import asyncio
import threading
import time
from queue import Empty, Full
from enum import Enum

import nacl

from ..protocol import Protocol
from ..identity import Identity
from ..processes import Process, ProcMeta
from ..config.configuration import CfgIds
from ..identity import Group
from ..system import comm_port, net_cadence
from .network import Network
from .message import Message
from .ping import PingServer, ping


class NetworkProtocol(Enum):
    IPV4 = 4
    IPV6 = 6
    MAC = 2
    NONE = 0


class TransmissionError(RuntimeError):
    pass


class _NetProcMeta(ProcMeta):  # so that subclasses inherit meta args
    def __init__(cls, name, bases, namespace, cadence=net_cadence, port=comm_port):
        super().__init__(name, bases, namespace,
                         proc_name=CfgIds.network, description='Network I/O')
        cls.cadence = cadence
        cls.default_port = port


class NetworkProcess(Process, metaclass=_NetProcMeta):
    """
    Handle requests to send Messages over the network and route incoming Messages to the right process
    Abstract class - subclasses must implement send_* and recv_* methods
    """
    enc = Network.encoding
    annoy_limit = 5
    net_proto = NetworkProtocol.NONE
    mystery_max_retries = 60  # 30 seconds
    socket_timeout = 0.1

    def __init__(self, configurations, subsystems, log_q, acceptance_func=None, **kwargs):
        super().__init__(configurations, subsystems, log_q, **kwargs)
        self.net_cfg = configurations[CfgIds.network]
        port = self.net_cfg.port
        self.port = port
        if port is None:
            self.port = self.default_port
        self.diplomat = True
        self.ping = None
        self.myself = configurations[CfgIds.identity]
        self.peer_messages = []
        self.encrypted_messages = []
        self.group_messages = []
        self.unknown_messages = []
        self.acceptance = acceptance_func
        self.pests = {}
        self.protocol = Protocol(self.name, self.logger, configurations[CfgIds.peers])  # noqa
        self.stop = False

    @property
    def peers(self):
        return self.protocol.peers

    @property
    def group(self):
        return self.protocol.group

    def send_peer(self, msg, whom):
        raise NotImplementedError

    def send_group(self, msg, whom):
        raise NotImplementedError

    def send_any(self, msg):
        raise NotImplementedError

    def recv_peer(self):
        raise NotImplementedError

    def recv_group(self):
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

    def accept_group_message(self, address):
        """
        Accept/reject group messages based on sender's address
        :param address: Incoming sender
        :return: bool
        """
        if address not in self.group.addresses:
            return False
        return self.accept_peer_message(address)

    def reject_message(self, address):  # FIXME
        return False

    def _encr_recv(self, method, msg_queue):
        while not self.stop:
            try:
                raw_msg, from_addr, from_port = method()
            except TransmissionError as err:
                self.logger.error('Network: %s' % err)
                continue
            except TimeoutError:
                continue
            if raw_msg is not None:
                msg_queue.append((raw_msg, from_addr))
            elif from_addr is not None:
                who = self.peers.find_by_address(from_addr)
                if who is not None:
                    if who not in self.pests:
                        self.pests[who] = 0
                    self.pests[who] += 1
                    if self.pests[who] > self.annoy_limit:
                        self.peers.demote(who)
                        del self.pests[who]

    def peer_receiver(self):
        """
        Receive thread for point-to-point
        Track peers not on whitelist (accept_peer_message), demote if they persist
        :return: None
        """
        self._encr_recv(self.recv_peer, self.peer_messages)

    def group_receiver(self):
        """
        Receive thread for pseudo-multicast with a single encryption key
        Track peers not on whitelist (accept_peer_message), demote if they persist
        :return: None
        """
        self._encr_recv(self.recv_group, self.group_messages)

    def unknown_receiver(self):
        """
        Receive thread for one-to_many
        :return: None
        """
        while not self.stop:
            try:
                raw_msg, from_addr, from_port = self.recv_any()
            except TransmissionError as err:
                self.logger.error('Network: %s' % err)
                continue
            except TimeoutError:
                continue
            if raw_msg is not None:
                self.unknown_messages.append((raw_msg, from_addr))

    def mystery_handler(self, queues):
        """
        Handle encrypted messages sent before the peer is known
        :return: None
        """
        try_count = {}
        while not self.stop:
            for raw_msg, from_addr in self.encrypted_messages:
                peer = self.peers.find_by_address(from_addr)
                if peer is not None:
                    decrypt_msg = self.myself.decrypt(raw_msg, peer)
                    self._msg_to_queue(decrypt_msg, peer, queues, 'point-to-point')
                    self.logger.debug('Out-of-order message from %s handled' % peer.nickname)
                    self.encrypted_messages.remove((raw_msg, from_addr))
                else:
                    if from_addr not in try_count:
                        try_count[from_addr] = 0
                    try_count[from_addr] += 1
                    if try_count[from_addr] > self.mystery_max_retries:
                        self.encrypted_messages.remove((raw_msg, from_addr))
                        self.logger.debug('Spurious encrypted message from %s dropped' % from_addr)
            time.sleep(self.cadence + self.q_cadence)  # curiously, does not sleep if exactly cadence

    def _msg_to_queue(self, msg, from_whom, queues, rcvd_by, validate=True):
        try:
            message = Message.parse(msg, from_whom, validate=validate)
        except TypeError:
            print('Error parsing: %s' % msg)  #FIXME
            return
        from_addr = from_whom
        if isinstance(from_whom, Identity):
            from_addr = from_whom.address
        processed = False
        for sub_sys_proc in self.subsystems:
            if message.process == sub_sys_proc:
                try:
                    processed = True
                    queues[sub_sys_proc].put(message, block=True, timeout=self.q_cadence)
                    self.logger.debug('Recvd %s message for %s:%s from %s' %
                                      (rcvd_by, sub_sys_proc, message.function, from_addr))
                except Full:
                    self.logger.error('Network: %s queue is full' % sub_sys_proc)
        if not processed:
            self.logger.error('Recvd message for unknown %s process from %s. Ignoring.' %
                              (message.process, from_addr))
            self.logger.debug('Message: %s' % str(message))

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
        threading.Thread(target=self.group_receiver, daemon=True).start()
        threading.Thread(target=self.unknown_receiver, daemon=True).start()
        threading.Thread(target=self.mystery_handler, args=(queues,), daemon=True).start()
        while self.keep_running(signal):
            if self.diplomat:
                if self.ping is None:
                    self.ping = PingServer(self.net_cfg.ip4, self.logger)
                    self.ping.start()
            elif self.ping is not None:
                self.ping.stop()
                self.ping = None
            try:
                message = queues[self.name].get(block=True, timeout=self.q_cadence)  # noqa
            except Empty:
                message = None
            if message and not self.protocol.run_message_handlers(queues, message):
                if isinstance(message, Message):
                    self.logger.debug('Send network message: %s:%s' % (message.process, message.function))
                    try:
                        if message.function == Network.ping:
                            try:
                                stats = ping(message.to_whom.address, count=message.obj)  # noqa
                                msg = Message(self.name, Network.ping, stats)  # noqa
                                queues[message.return_to].put(msg, block=True, timeout=self.q_cadence)
                            except TransmissionError as err:
                                self.logger.error('Network: %s' % err)
                        elif message.to_whom == Network.broadcast:
                            msg = bytes(message)
                            try:
                                self.send_any(msg)
                            except TransmissionError as err:
                                self.logger.error('Network: %s' % err)
                        elif isinstance(message.to_whom, Group):
                            if message.encrypt:
                                msg = self.group.encrypt(bytes(message), self.group)
                            else:
                                msg = bytes(message)
                            for addr in message.to_whom.addresses:
                                if addr == self.myself.address:
                                    continue
                                try:
                                    self.send_group(msg, addr)
                                except TransmissionError as err:
                                    self.logger.error('Network: %s' % err)
                        else:  # defaults to pseudo-multicast
                            for who in message.to_whom:  # Message ensures this is list  # noqa
                                address = who.address
                                if '/' in address:
                                    address = address.split('/')[0]
                                if message.encrypt:
                                    msg = self.myself.encrypt(bytes(message), who)
                                else:
                                    msg = bytes(message)
                                try:
                                    self.send_peer(msg, address)
                                except TransmissionError as err:
                                    self.logger.error('Network: %s' % err)
                    except BrokenPipeError as err:
                        self.logger.error('Network: %s' % err)
                else:
                    self.logger.error('Net process recvd message of type %s - Message required. Ignoring.' %
                                      type(message))
                    self.logger.debug('Ignored message: %s' % str(message))

            # async recv point-to-point messages
            if len(self.peer_messages) > 0:
                raw_msg, from_addr = self.peer_messages.pop(0)
                peers = self.configs[CfgIds.peers]
                from_whom = peers.find_by_address(from_addr)
                if len(peers.all) < 1:
                    # bootstrapping will not (cannot) be encrypted
                    try:
                        self._msg_to_queue(raw_msg, from_addr, queues, 'point-to-point', validate=False)
                    except UnicodeDecodeError:
                        self.logger.debug('Out-of-order message detected, retry later')
                        self.encrypted_messages.append((raw_msg, from_addr))
                elif from_whom is not None:
                    decrypt_msg = self.myself.decrypt(raw_msg, from_whom)
                    self._msg_to_queue(decrypt_msg, from_whom, queues, 'point-to-point')
                else:
                    self.logger.error('Recvd transmission from %s - not recognized as a peer. Ignoring.' % from_addr)
                    self.logger.debug('Ignored message: %s' % str(message))

            # async recv group messages
            if len(self.group_messages) > 0:
                if self.group is not None:  # otherwise, skip for now
                    raw_msg, from_addr = self.group_messages.pop(0)
                    if from_addr in self.group.addresses:
                        from_whom = self.peers.find_by_address(from_addr)
                        try:
                            decrypt_msg = self.group.decrypt(raw_msg, self.group)
                            if from_whom is not None:
                                self._msg_to_queue(decrypt_msg, from_whom, queues, 'group')
                            else:
                                self.logger.error('Recvd transmission from %s - not in peers. Ignoring.' % from_addr)
                                self.logger.debug('Ignored message: %s' % str(message))
                        except nacl.exceptions.CryptoError:
                            self.logger.error('CryptoError decrypting message from %s' % from_whom.nickname)
                    else:
                        self.logger.error('Recvd transmission from %s - not in group. Ignoring.' % from_addr)
                        self.logger.debug('Ignored message: %s' % str(message))

            # async recv stranger messages (separate channel)
            if len(self.unknown_messages) > 0:
                raw_msg, from_addr = self.unknown_messages.pop(0)
                self._msg_to_queue(raw_msg, from_addr, queues, 'multicast', validate=False)

        self.stop = True
