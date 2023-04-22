from ..processes import Process, Empty, ProcMeta, SUBSYSTEMS
from ..configuration import CfgIds
from .network import Message, Network


class NetProcMeta(ProcMeta):  # so that subclasses inherit meta args
    def __init__(cls, name, bases, namespace, cadence=0.0001, port=7787):
        super().__init__(name, bases, namespace,
                         proc_name=CfgIds.network.value, description='Network I/O')
        cls.cadence = cadence
        cls.port = port


class NetworkProcess(Process, metaclass=NetProcMeta):
    rcv_backlog = 5

    def send(self, msg, whom_list):
        raise NotImplementedError

    def bcast(self, msg):
        raise NotImplementedError

    def recv(self):
        raise NotImplementedError

    def listen(self, queues, output, signal):
        while self.keep_running(signal):
            try:
                message = queues[self.name].get(block=True, timeout=self.cadence)
            except Empty:
                message = None
            if message is not None:
                if not isinstance(message, Message):
                    self.error('Net process recvd message of type %s - Message required. Ignoring.' % type(message))
                    continue
                self.debug('Send network message %s' % message)
                if message.to_whom == Network.broadcast:
                    self.bcast(bytes(message))
                else:  # defaults to pseudo-multicast
                    addr_list = [who.address for who in message.to_whom]  # Message ensures this is list
                    self.send(bytes(message), addr_list)

    def speak(self, queues, output, signal):
        while self.keep_running(signal):
            raw_msg, from_addr = self.recv()
            from_whom = self.configs[CfgIds.peers.value].find_by_address(from_addr)
            if from_whom is None:
                self.error('Recvd transmission from %s - not recognized as a peer. Ignoring.' % from_addr)
                continue
            message = Message.parse(raw_msg, from_whom)
            for sub_sys_proc in SUBSYSTEMS.keys():
                if message.msg_type == sub_sys_proc:
                    queues[sub_sys_proc].put(message)
                    self.debug('Recvd network message for %s' % sub_sys_proc)
