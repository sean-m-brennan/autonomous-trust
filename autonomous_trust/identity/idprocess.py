import time
from queue import Empty, Full

from ..config.configuration import CfgIds
from ..processes import Process, ProcMeta
from ..network import Message, Network
from .blocks import IdentityChain, IdentityBlock, IdentityProof
from .blocks import BlockMessage, BlockChainMessage, ChainImpl
from .pow import IdentityProofOfWork
from .pos import IdentityProofOfStake
from .poa import IdentityProofOfAuthority


class IdentityProcess(Process, metaclass=ProcMeta,
                      proc_name=CfgIds.identity.value, description='Identity registration'):
    init_timeout = 5

    def __init__(self, configurations):
        super().__init__(configurations, dependencies=[CfgIds.network.value])
        self._ident = configurations[self.cfg_name]
        self.peers = configurations[CfgIds.peers.value]
        impl = self._ident.block_impl
        if impl == ChainImpl.POW.value:
            self._chain = IdentityProofOfWork(self._ident, self.peers, 0)
        elif impl == ChainImpl.POS.value:
            self._chain = IdentityProofOfStake(self._ident, self.peers, 5)
        elif impl == ChainImpl.POA.value:
            self._chain = IdentityProofOfAuthority(self._ident, self.peers, 5)
        else:
            raise RuntimeError('Invalid blockchain implementation: %s' % impl)
        self.phase = 0
        self.confirmed_block = None

    def listen(self, queues, output, signal):
        queue = queues[self.name]
        try:
            msg = queue.get(block=True, timeout=self.init_timeout)
            if msg.startswith(IdentityChain.provide_chain):
                self.debug('Received existing chain')
                existing = BlockChainMessage.from_yaml_string(msg[len(IdentityChain.provide_chain):])
                if existing.impl == self._ident.block_impl:
                    self._chain.catch_up(existing.chain)
        except Empty:
            self.phase += 1
            self.debug('No chain: generate my own.')
        while self.keep_running(signal):
            try:
                message = queue.get(block=True)  # FIXME need IPC obj to know whether from network or reputation
                msg = message.obj
                if msg.startswith(IdentityChain.propose):
                    self.debug('Received block proposal')
                    block = BlockMessage.from_yaml_string(msg[len(IdentityChain.propose):])
                    digest = self._chain.confirm(block)
                    if digest is not None:
                        proof = IdentityProof(block.identity.uuid, digest, True)
                        self.confirmed_block = (block, proof, self._ident.sign(proof))
                elif msg.startswith(IdentityChain.request_chain):
                    to_whom = message.from_whom
                    msg = BlockChainMessage(self._ident.block_impl, self._chain).to_yaml_string()
                    message = Message(self.name, IdentityChain.provide_chain + msg, to_whom)
                    queues[CfgIds.network.value].put(message, block=True)
            except Empty:
                pass
            except Full:
                self.error('Network queue full')
            time.sleep(self.cadence)

    def speak(self, queues, output, signal):
        try:
            if self.phase == 0:
                self.debug('Request existing chain')
                message = Message(self.name, IdentityChain.request_chain, to_whom=Network.broadcast)
                queues[CfgIds.network.value].put(message, block=True, timeout=self.cadence)
        except Full:
            self.error('Network queue full')
        while self.keep_running(signal):
            try:
                if self.phase == 1:
                    block = IdentityBlock(self._chain.last_block.index + 1, self._ident, self._chain.now, None, '0')
                    digest = self._chain.confirm(block)  # confirm my own identity for bootstrapping
                    if digest:
                        proof = IdentityProof(block.identity.uuid, digest, True)
                        sig_hash = self._ident.sign(proof)
                        if not self._chain.add_block(block, proof, sig_hash):
                            self.error('Invalid identity block for myself')
                        else:
                            # FIXME protocol
                            msg_str = IdentityChain.propose + BlockMessage(block, proof, sig_hash).to_yaml_string()
                            message = Message(self.name, msg_str, to_whom=Network.broadcast)  # FIXME bcast?
                            self.debug('Send propose block')
                            queues[CfgIds.network.value].put(message, block=True, timeout=self.cadence)
                    self.phase += 1
                elif self.phase == 2:
                    if self.confirmed_block is not None:
                        # FIXME protocol
                        msg_str = IdentityChain.vote + BlockMessage(*self.confirmed_block).to_yaml_string()
                        message = Message(self.name, msg_str, to_whom=self.peers)
                        self.debug("Send confirmed block")
                        queues[CfgIds.network.value].put(message, block=True, timeout=self.cadence)
                        self.confirmed_block = None
            except Full:
                self.error('Queues at capacity')
            time.sleep(self.cadence)
