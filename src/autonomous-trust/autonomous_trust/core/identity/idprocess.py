import os
import time
from queue import Empty, Full
import threading

from nacl.exceptions import BadSignatureError

from .group import Group
from ..algorithms.impl import AgreementImpl
from ..config import Configuration, CfgIds, to_yaml_string, from_yaml_string
from ..processes import Process, ProcMeta
from ..network import Message, Network
from ..capabilities import PeerCapabilities
from .history import IdentityByWork, IdentityByStake, IdentityByAuthority
from .history import IdentityObj
from .protocol import IdentityProtocol
from ..system import encoding, PackageHash, now


class IdentityProcess(Process, metaclass=ProcMeta,
                      proc_name=CfgIds.identity, description='Identity registration'):
    """
    Handle Identity and Peer tracking
    Zero trust in this stage
    """
    init_timeout = 10
    init_extra = 2
    enc = encoding

    def __init__(self, configurations, subsystems, log_q, **kwargs):
        super().__init__(configurations, subsystems, log_q, dependencies=[CfgIds.network], **kwargs)
        self.identity = configurations[self.cfg_name]
        self.protocol = IdentityProtocol(self.name, self.logger, configurations[CfgIds.peers])
        self.peers = self.protocol.peers
        self.group = self.protocol.group
        self.phase = 0
        self.confirmed_block = []
        self.peer_capabilities = PeerCapabilities()
        impl = self.identity.block_impl
        if impl == AgreementImpl.POW.value:
            self._history = IdentityByWork(self.identity, self.peers, log_q, 0)
        elif impl == AgreementImpl.POS.value:
            self._history = IdentityByStake(self.identity, self.peers, log_q, 5)
        elif impl == AgreementImpl.POA.value:
            self._history = IdentityByAuthority(self.identity, self.peers, log_q, 5)
        else:
            raise RuntimeError('Invalid identity history implementation: %s' % impl)
        self.messages = []
        self.border_guard_mode = True
        self.histories = []
        self.package_hash = self.configs[PackageHash.key]
        self.choosing = False
        self.peer_potentials = {}
        self.protocol.register_handler(IdentityProtocol.announce, self.welcoming_committee)
        self.protocol.register_handler(IdentityProtocol.accept, self.handle_acceptance)
        self.protocol.register_handler(IdentityProtocol.history, self.receive_history)
        self.protocol.register_handler(IdentityProtocol.diff, self.handle_history_diff)
        self.protocol.register_handler(IdentityProtocol.propose, self.handle_vote_on_peer)
        self.protocol.register_handler(IdentityProtocol.vote, self.count_vote)
        self.protocol.register_handler(IdentityProtocol.confirm, self.handle_confirm_peer)
        self.protocol.register_handler(IdentityProtocol.update, self.handle_group_update)

    @property
    def capabilities(self):
        return self.protocol.capabilities

    def _remember_activity(self, queues, name, obj):
        self.configs[name] = obj
        obj.to_file(os.path.join(Configuration.get_cfg_dir(), name + Configuration.yaml_file_ext))
        self.update(obj, queues)

    def _record_group(self, queues):
        self._remember_activity(queues, CfgIds.group, self.group)

    def _record_peers(self, queues):
        self._remember_activity(queues, CfgIds.peers, self.peers)

    def acquire_capabilities(self, queues):
        start = now()
        while (now() - start).seconds <= self.init_timeout:
            try:
                message = queues[self.name].get(block=True, timeout=self.q_cadence)
            except Empty:
                message = None
            if message is not None and not self.protocol.run_message_handlers(queues, message):
                self.messages.append(message)
            if self.capabilities is not None:
                break
            time.sleep(self.cadence)
        self.phase = 1

    def announce_identity(self, queues):
        """
        Request access for my identity
        Open broadcast channel
        Non-blocking
        Phase 1 of protocol
        :param queues: Interprocess communication queues
        :return: None
        """
        if self.phase != 1:
            return
        try:
            self.logger.debug('Announce myself')
            msg_str = to_yaml_string((self.identity.publish(), self.package_hash, self.capabilities.to_list()))
            message = Message(self.name, IdentityProtocol.announce,
                              msg_str, to_whom=Network.broadcast, encrypt=False)
            queues[CfgIds.network].put(message, block=True, timeout=self.q_cadence)
        except Full:
            self.logger.error('announce_identity: Network queue full')
        self.phase = 2

    def choose_group(self, queues):
        """
        Await incoming histories, choose from among them
        :param queues:
        :return: None
        """
        start = now()
        self.choosing = True
        while (now() - start).seconds <= self.init_timeout:
            time.sleep(self.cadence)
        accepted = None, None

        for steps, group in self.histories:
            # FIXME validate steps
            if CfgIds.group in self.configs and self.configs[CfgIds.group] == group:
                # FIXME verify history goes with group
                accepted = group, steps
                break
            else:
                if accepted == (None, None):
                    accepted = group, steps
                elif len(steps) > len(accepted[1]):  # noqa
                    accepted = group, steps
        try:
            if accepted != (None, None):
                self.group = accepted[0]
                self.logger.debug('Updated group key')
                self._record_group(queues)
                existing = accepted[1]  # FIXME
                #existing = self._history.hear(*accepted[1])  # noqa
                diff = self._history.catch_up(existing)

                msg_str = to_yaml_string(diff)
                message = Message(self.name, IdentityProtocol.diff, msg_str, to_whom=self.group)
                self.logger.debug('Send history diff')
                queues[CfgIds.network].put(message, block=True, timeout=self.q_cadence)
            else:
                self.logger.debug('No history/group key: generate my own.')
                self.group = Group.initialize([self.identity.address], 'nick')  # FIXME name generation
                self._record_group(queues)
        except Full:
            self.logger.error('receive_history: Network queue full')
        self.choosing = False
        self.phase = 3

    def receive_history(self, queues, message):
        """
        Receive a full history plus group key or timeout
        Phase 2 of protocol
        :param queues: Interprocess communication queues (unused)
        :param message: identity, history, tuple of history steps, group
        :return: bool (message handled)
        """
        if message.function == IdentityProtocol.history:
            self.logger.debug('Received existing history')
            self.histories.append(from_yaml_string(message.obj))
            if not self.choosing:
                threading.Thread(target=self.choose_group, args=(queues,), daemon=True).start()
            return True
        return False

    def count_vote(self, _, message):
        """
        Receive/record a vote
        :param _:
        :param message: tuple of blob, proof, sig
        :return: bool (message handled)
        """
        if self.phase != 3:
            return False
        if message.function == IdentityProtocol.vote:
            blob, proof, sig = message.obj
            try:
                message.from_whom.identity.verify(sig)
                self._history.verify(blob, proof, sig)
            except BadSignatureError:
                self.logger.error('Vote had a bad signature')
            return True
        return False

    def _vote_collection(self, queues, new_guy, blob):
        try:
            start = now()
            voted = False
            while (now() - start).seconds <= self._history.timeout:
                if not voted:
                    vote = self._process_id(blob)
                    self._history.verify(*vote)
                    if vote in self.confirmed_block:
                        self.confirmed_block.remove(vote)
                    self.logger.debug('I voted')
                    voted = True
                else:
                    time.sleep(self.cadence)
            if not voted:
                self.logger.debug('I did not vote')
            if self._history.finalize(blob):
                message = Message(self.name, IdentityProtocol.confirm, blob, to_whom=self.group)
                queues[CfgIds.network].put(message, block=True, timeout=self.q_cadence)

                self.group.addresses.append(blob.identity.address)
                self._record_group(queues)

                self._add_peer(queues, blob.identity, self.peer_potentials[blob.identity.uuid])
                del self.peer_potentials[blob.identity.uuid]

                # send my identity in the open to enable encryption
                msg_str = to_yaml_string((self.identity.publish(), self.package_hash, self.capabilities.to_list()))
                message = Message(self.name, IdentityProtocol.accept, msg_str, to_whom=new_guy, encrypt=False)
                queues[CfgIds.network].put(message, block=True, timeout=self.q_cadence)

                # now send encrypted history
                msg_str = to_yaml_string((self._history.recite(), self.group))
                message = Message(self.name, IdentityProtocol.history, msg_str, to_whom=new_guy)
                self.logger.debug('Send full history')
                queues[CfgIds.network].put(message, block=True, timeout=self.q_cadence)
        except Full:
            self.logger.error('vote_collection: Network queue full')

    def welcoming_committee(self, queues, message):
        """
        Handle incoming newbies
        :param queues: Interprocess communication queues
        :param message: The new Identity
        :return: bool (message handled)
        """
        if self.phase != 3 or not self.border_guard_mode:
            return False
        if message.function == IdentityProtocol.announce:
            try:
                new_id, ph, caps = from_yaml_string(message.obj)
                if new_id == self.identity:
                    self.logger.debug('Should not have received my own announcement')
                    return
                if ph != self.package_hash:
                    self.logger.error("Newbie is running a counterfeit; Ignore")
                    return True
                self.logger.debug('Received new identity: %s' % new_id.nickname)
                self.peer_potentials[new_id.uuid] = caps
                id_obj = IdentityObj(new_id, new_id.uuid)
                #threading.Thread(target=self._process_id, args=(id_obj,), daemon=True).start()
                #time.sleep(self.cadence) # FIXME invalid
                threading.Thread(target=self._vote_collection,
                                 args=(queues, new_id, id_obj), daemon=True).start()
                msg_str = id_obj.to_yaml_string()  # FIXME validate
                message = Message(self.name, IdentityProtocol.propose, msg_str, to_whom=self.group)
                queues[CfgIds.network].put(message, block=True, timeout=self.q_cadence)
            except Full:
                self.logger.error('welcoming_committee: Network queue full')
            return True
        return False

    def _add_peer(self, queues, identity, capabilities):
        self._history.upgrade_peer(identity)
        self.peers.promote(identity)
        self._record_peers(queues)
        self.peer_capabilities.register(identity.uuid, capabilities)
        queues[CfgIds.main].put(self.peer_capabilities, block=True, timeout=self.q_cadence)
        queues[CfgIds.negotiation].put(self.peer_capabilities, block=True, timeout=self.q_cadence)

    def _process_id(self, blob):
        proof = self._history.prove(blob)
        vote = blob, proof, self.identity.sign(proof)
        self.confirmed_block.append(vote)
        return vote

    def handle_vote_on_peer(self, _, message):
        """
        Process received proposals
        Non-blocking - spins up autonomous thread for processing
        Phase 4 of protocol
        :param _: Unused Interprocess communication queues
        :param message: The request Message
        :return: bool (message handled)
        """
        if self.phase != 3:
            return False
        if message.function == IdentityProtocol.propose:
            self.logger.debug('Received peer proposal')
            # FIXME should I be in border_guard_mode?
            blob = IdentityObj.from_yaml_string(message.obj)
            # FIXME verify
            threading.Thread(target=self._process_id, args=(blob,), daemon=True).start()
            return True
        return False

    def vote_response(self, queues):
        """
        Enqueue previously processed blocks for transmission
        Non-blocking
        Phase 4 of protocol
        :param queues: Interprocess communication queues
        :return: None
        """
        if self.phase != 3:
            return
        if len(self.confirmed_block) < 1:
            return
        try:
            vote = self.confirmed_block.pop(0)
            if vote[0].uuid == vote[1].uuid:
                return  # no voting for yourself
            # FIXME handle if I proposed the vote
            msg_str = to_yaml_string(vote)
            message = Message(self.name, IdentityProtocol.vote, msg_str, to_whom=self.group)
            self.logger.debug("Send vote")
            queues[CfgIds.network].put(message, block=True, timeout=self.q_cadence)
        except Full:
            self.logger.error('vote_response: Network queue full')

    def handle_acceptance(self, queues, message):
        if self.phase < 2:
            return False
        if message.function == IdentityProtocol.accept:
            self.logger.debug('Received peer acceptance')
            ident, ph, caps = from_yaml_string(message.obj)
            if ph != self.package_hash:
                self.logger.error("Counterfeit 'peer'")
                return True
            self._add_peer(queues, ident, caps)
            return True
        return False

    def handle_confirm_peer(self, queues, message):
        """
        Receive peer confirmation, add new peer to list
        :param queues:
        :param message:
        :return: bool (message handled)
        """
        if self.phase != 3:
            return False
        if message.function == IdentityProtocol.confirm:
            self.logger.debug('Received peer confirmation')
            peer = message.obj.identity
            # FIXME validate blob
            self._add_peer(queues, peer, self.peer_potentials[peer.uuid])
            del self.peer_potentials[peer.uuid]
            return True
        return False

    def handle_history_diff(self, _, message):
        """
        Receive a history diff, possibly merge
        :param _:
        :param message:
        :return: bool (message handled)
        """
        if self.phase != 3:
            return False
        if message.function == IdentityProtocol.diff:
            self.logger.debug('Received history diff')
            steps = from_yaml_string(message.obj)
            self._history.ingest_branch(steps, message.from_whom.nickname)
            # FIXME validate and merge
            return True
        return False

    def handle_group_update(self, queues, message):
        """
        Receive a group update (addresses list only)
        :param queues:
        :param message:
        :return: bool (message handled)
        """
        if self.phase != 3:
            return False
        if message.function == IdentityProtocol.update:
            self.logger.debug('Received group update')
            group = Group.from_yaml_string(message.obj)
            if self.group == group:
                self.group = group
                self._record_group(queues)
            return True
        return False

    def process(self, queues, signal):
        """
        Identity/Peer processing main loop
        :param queues: Interprocess communication queues
        :param signal: IPC queue for signalling halt
        :return: None
        """
        phase = self.phase
        self.logger.debug('Phase %s' % self.phase)
        self.acquire_capabilities(queues)
        self.announce_identity(queues)
        if not self.choosing:
            # initial run, may be called again
            threading.Thread(target=self.choose_group, args=(queues,), daemon=True).start()
        while self.keep_running(signal):
            if self.phase != phase:
                self.logger.debug('Phase %s' % self.phase)
                phase = self.phase
            self.vote_response(queues)

            untouched = []
            while len(self.messages) > 0:
                message = self.messages.pop(0)
                if not self.protocol.run_message_handlers(queues, message):
                    untouched.append(message)
            try:
                message = queues[self.name].get(block=True, timeout=self.q_cadence)
                if message and not self.protocol.run_message_handlers(queues, message):
                    untouched.append(message)
            except Empty:
                pass
            self.messages += untouched
            self.sleep_until(self.cadence)
