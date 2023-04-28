import time
from queue import Empty, Full
import threading

from ..config.configuration import CfgIds
from ..processes import Process, ProcMeta
from ..network import Message, Network
from .blocks import IdentityChain, IdentityBlock, IdentityProof, ChainImpl
from .blocks import BlockMessage, BlockSignedMessage, BlockChainMessage
from .blocks import IdentityProofOfWork, IdentityProofOfStake, IdentityProofOfAuthority


class IdentityProcess(Process, metaclass=ProcMeta,
                      proc_name=CfgIds.identity.value, description='Identity registration'):
    """
    Handle Identity and Peer tracking
    """
    init_timeout = 10

    def __init__(self, configurations, subsystems, log_q):
        super().__init__(configurations, subsystems, log_q, dependencies=[CfgIds.network.value])
        self.ident = configurations[self.cfg_name]
        self.peers = configurations[CfgIds.peers.value]
        self.phase = 0
        self.confirmed_block = []
        impl = self.ident.block_impl
        if impl == ChainImpl.POW.value:
            self._chain = IdentityProofOfWork(self.ident, self.peers, log_q, 0)
        elif impl == ChainImpl.POS.value:
            self._chain = IdentityProofOfStake(self.ident, self.peers, log_q, 5)
        elif impl == ChainImpl.POA.value:
            self._chain = IdentityProofOfAuthority(self.ident, self.peers, log_q, 5)
        else:
            raise RuntimeError('Invalid blockchain implementation: %s' % impl)
        self.messages = []

    def _process_block(self, block):
        digest = self._chain.confirm(block)
        if digest is not None:
            proof = IdentityProof(block.identity.uuid, digest, True)
            self.confirmed_block.append((block, proof, self.ident.sign(proof)))

    def request_chain(self, queues):
        """
        Enqueue a request for an existing list of Identities for transmission
        Non-blocking
        Phase 0 of protocol
        :param queues: Interprocess communication queues
        :return: None
        """
        if self.phase != 0:
            return
        if len(self._chain) > 1:
            self.phase = 1
            return
        try:
            self.logger.debug('Request existing chain')
            message = Message(self.name, IdentityChain.request_chain, '', to_whom=Network.broadcast)
            queues[CfgIds.network.value].put(message, block=True, timeout=self.q_cadence)
        except Full:
            self.logger.error('IdProc(1): Network queue full')
        self.phase = 1

    def receive_chain(self, queues):
        """
        Receive an external list of Identities or timeout
        Blocking! - Must precede the process loop or be enclosed in a Thread
        Phase 1 of protocol
        :param queues: Interprocess communication queues
        :return: None
        """
        if self.phase != 1:
            return
        try:
            # FIXME possible fraud here, compare multiples, but what if < 3 respond?
            # need provers
            message = queues[self.name].get(block=True, timeout=self.init_timeout)
            if message.function == IdentityChain.provide_chain:
                self.logger.debug('Received existing chain')
                existing = BlockChainMessage.from_yaml_string(message.obj)
                if existing.impl == self.ident.block_impl:
                    self._chain.catch_up(existing.chain)
            else:
                self.messages.append(message)
        except Empty:
            self.logger.debug('No chain: generate my own.')
        self.phase = 2

    def propose_my_block(self, queues):  # propose my own identity to (only) peers on the chain; blocking!
        """
        Sign and package my own Identity as a Block, enqueue for transmission
        Blocking! - must be in a Thread
        Phase 2 of protocol
        :param queues: Interprocess communication queues
        :return: None
        """
        while self.phase < 2:
            time.sleep(self.cadence)
        try:
            self.logger.debug('Create my identity')
            last = self._chain.last_block
            block = IdentityBlock(last.index + 1, self.ident.publish(), self._chain.now, last.hash, '0')
            digest = self._chain.confirm(block)  # confirm my own identity for bootstrapping
            if digest:
                proof = IdentityProof(block.identity.uuid, digest, True)
                sig_msg = self.ident.sign(proof.to_yaml_string().encode())
                sig_hash = BlockSignedMessage(sig_msg.message, sig_msg.signature)
                if not self._chain.verify(block, proof, sig_hash):  # may run long
                    self.logger.error('Invalid identity block for myself')
                else:
                    msg_str = BlockMessage(block, proof, sig_hash).to_yaml_string()
                    peers = self.configs[CfgIds.peers.value].all
                    if len(peers) > 0:
                        message = Message(self.name, IdentityChain.propose, msg_str, to_whom=peers)
                    else:
                        message = Message(self.name, IdentityChain.propose, msg_str, to_whom=Network.broadcast)
                    self.logger.debug('Send block proposal')
                    queues[CfgIds.network.value].put(message, block=True, timeout=self.q_cadence)
                    if not block.checker(self._chain, proof, sig_hash):  # will run long
                        self.logger.error('Not accepted by peers')
                        # FIXME what if I'm refused?
        except Full:
            self.logger.error('IdProc(3): Network queue full')
        self.phase = 3

    def process_blocks(self, _, message):
        """
        Process received block proposals (if the given message matches)
        Non-blocking - spins up autonomous thread for processing
        Phase 3 of protocol
        :param _: Unused Interprocess communication queues
        :param message: The request Message
        :return: 
        """
        if self.phase != 3:
            return
        try:
            if message.function == IdentityChain.propose:
                self.logger.debug('Received block proposal')
                block = BlockMessage.from_yaml_string(message.obj)  # FIXME verify
                threading.Thread(target=self._process_block, args=(block,), daemon=True).start()
        except Empty:
            pass
        except Full:
            self.logger.error('IdProc(4): Network queue full')

    def block_processing_response(self, queues):
        """
        Enqueue previously processed blocks for transmission
        Non-blocking
        Phase 3 of protocol
        :param queues: Interprocess communication queues
        :return: None
        """
        try:
            if self.phase != 3:
                return
            if len(self.confirmed_block) < 1:
                return
            block = self.confirmed_block.pop(0)
            msg_str = BlockMessage(*block).signed().to_yaml_string()
            message = Message(self.name, IdentityChain.vote, msg_str, to_whom=self.peers)
            self.logger.debug("Send confirmed block")
            queues[CfgIds.network.value].put(message, block=True, timeout=self.q_cadence)
        except Full:
            self.logger.error('IdProc(5): Network queue full')

    def chain_response(self, queues, message):
        """
        Sign the current requested blockchain and enqueue for transmission (if the given message matches)
        Non_blocking
        Phase 3 of protocol
        :param queues: Interprocess communication queues
        :param message: The request Message
        :return: None
        """
        if self.phase != 3:
            return
        try:
            if message.function == IdentityChain.request_chain:
                to_whom = message.from_whom
                msg = BlockChainMessage(self.ident.block_impl, self._chain).signed().to_yaml_string()
                message = Message(self.name, IdentityChain.provide_chain, msg, to_whom=to_whom)
                self.logger.debug('Send requested chain')
                queues[CfgIds.network.value].put(message, block=True, timeout=self.q_cadence)
        except Empty:
            pass
        except Full:
            self.logger.error('IdProc(6): Network queue full')

    def process(self, queues, signal):
        """
        Identity/Peer processing main loop
        :param queues: Interprocess communication queues
        :param signal: IPC queue for signalling halt
        :return: None
        """
        self.phase = 0
        self.request_chain(queues)
        self.receive_chain(queues)  # blocks on purpose
        threading.Thread(target=self.propose_my_block, args=(queues,), daemon=True).start()
        while self.keep_running(signal):
            if self.phase > 1:
                self.block_processing_response(queues)
                while len(self.messages) > 0:
                    message = self.messages.pop(0)
                    self.process_blocks(queues, message)
                    self.chain_response(queues, message)
                try:
                    message = queues[self.name].get(block=True, timeout=self.q_cadence)
                    self.process_blocks(queues, message)
                    self.chain_response(queues, message)
                except Empty:
                    pass
            time.sleep(self.cadence)
