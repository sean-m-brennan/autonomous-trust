import os
import time
from queue import Empty, Full
import threading
from datetime import datetime

from .group import Group
from ..algorithms import AgreementImpl
from ..config import Configuration, CfgIds, to_yaml_string, from_yaml_string
from ..processes import Process, ProcMeta
from ..network import Message, Network
from .history import IdentityByWork, IdentityByStake, IdentityByAuthority
from .history import IdentityProtocol, IdentityObj
from ..system import encoding, PackageHash


class IdentityProcess(Process, metaclass=ProcMeta,
                      proc_name=CfgIds.identity.value, description='Identity registration'):
    """
    Handle Identity and Peer tracking
    Zero trust in this stage
    """
    init_timeout = 10
    init_extra = 2
    enc = encoding

    def __init__(self, configurations, subsystems, log_q):
        super().__init__(configurations, subsystems, log_q, dependencies=[CfgIds.network.value])
        self.identity = configurations[self.cfg_name]
        self.peers = configurations[CfgIds.peers.value]
        self.phase = 1
        self.confirmed_block = []
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
        self.group = None
        self.border_guard_mode = True
        self.histories = []
        self.package_hash = self.configs[PackageHash.key]
        self.choosing = False

    def _remember_activity(self, queues, name, obj):
        self.configs[name] = obj
        obj.to_file(os.path.join(Configuration.get_cfg_dir(), name + Configuration.yaml_file_ext))
        self.update(obj, queues)

    def _record_group(self, queues):
        self._remember_activity(queues, CfgIds.group.value, self.group)

    def _record_peers(self, queues):
        self._remember_activity(queues, CfgIds.peers.value, self.peers)

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
            msg_str = to_yaml_string((self.identity.publish(), self.package_hash))
            message = Message(self.name, IdentityProtocol.announce.value,
                              msg_str, to_whom=Network.broadcast, encrypt=False)
            queues[CfgIds.network.value].put(message, block=True, timeout=self.q_cadence)
        except Full:
            self.logger.error('announce_identity: Network queue full')
        self.phase = 2

    def choose_group(self, queues):
        """
        Await incoming histories, choose from among them
        :param queues:
        :return: None
        """
        start = datetime.utcnow()
        self.choosing = True
        while (datetime.utcnow() - start).seconds <= self.init_timeout:
            time.sleep(self.cadence)
        accepted = None, None

        for steps, group in self.histories:
            # FIXME validate steps
            if CfgIds.group.value in self.configs and self.configs[CfgIds.group.value] == group:
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
                message = Message(self.name, IdentityProtocol.diff.value, msg_str, to_whom=self.group)
                self.logger.debug('Send history diff')
                queues[CfgIds.network.value].put(message, block=True, timeout=self.q_cadence)
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
        if message.function == IdentityProtocol.history.value:
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
        if message.function == IdentityProtocol.vote.value:
            # FIXME check signature -> message.from_whom.identity.verify
            self._history.verify(*message.obj)
            return True
        return False

    def _vote_collection(self, queues, new_guy, blob):
        try:
            start = datetime.utcnow()
            voted = False
            while (datetime.utcnow() - start).seconds <= self._history.timeout:
                if not voted:
                    for vote in self.confirmed_block:
                        if vote[0] == blob:
                            # FIXME check signature (my own!)
                            if self._history.verify(*vote):
                                self.confirmed_block.remove(vote)
                                self.logger.debug('I voted')
                                voted = True
                time.sleep(self.cadence)
            if not voted:
                self.logger.debug('I did not vote')
            if self._history.finalize(blob):
                message = Message(self.name, IdentityProtocol.confirm.value, blob, to_whom=self.group)
                queues[CfgIds.network.value].put(message, block=True, timeout=self.q_cadence)

                self.group.addresses.append(blob.identity.address)
                self._record_group(queues)
                self._add_peer(queues, blob.identity)
                print('Peers: %s' % self.peers.all)  # FIXME

                # send my identity in the open to enable encryption
                msg_str = to_yaml_string((self.identity.publish(), self.package_hash))
                message = Message(self.name, IdentityProtocol.accept.value, msg_str, to_whom=new_guy, encrypt=False)
                queues[CfgIds.network.value].put(message, block=True, timeout=self.q_cadence)

                # now send encrypted history
                msg_str = to_yaml_string((self._history.recite(), self.group))
                message = Message(self.name, IdentityProtocol.history.value, msg_str, to_whom=new_guy)
                self.logger.debug('Send full history')
                queues[CfgIds.network.value].put(message, block=True, timeout=self.q_cadence)
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
        if message.function == IdentityProtocol.announce.value:
            try:
                new_id, ph = from_yaml_string(message.obj)
                if new_id == self.identity:
                    self.logger.debug('Should not have received my own announcement')
                    return
                if ph != self.package_hash:
                    self.logger.error("Newbie is running a counterfeit; Ignore")
                    return True
                self.logger.debug('Received new identity: %s' % new_id.nickname)
                id_obj = IdentityObj(new_id, new_id.uuid)
                threading.Thread(target=self._process_id, args=(id_obj,), daemon=True).start()
                threading.Thread(target=self._vote_collection,  # FIXME I need to vote too
                                 args=(queues, new_id, id_obj), daemon=True).start()
                msg_str = id_obj.to_yaml_string()  # FIXME validate
                message = Message(self.name, IdentityProtocol.propose.value, msg_str, to_whom=self.group)
                queues[CfgIds.network.value].put(message, block=True, timeout=self.q_cadence)
            except Full:
                self.logger.error('welcoming_committee: Network queue full')
            return True
        return False

    def _add_peer(self, queues, identity):
        self._history.upgrade_peer(identity)
        self.peers.promote(identity)
        self._record_peers(queues)

    def _process_id(self, blob):
        proof = self._history.prove(blob)
        self.confirmed_block.append((blob, proof,
                                     self.identity.sign(proof.to_yaml_string().encode(self.enc))))

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
        if message.function == IdentityProtocol.propose.value:
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
            # FIXME handle if I proposed the vote
            msg_str = to_yaml_string(vote)
            message = Message(self.name, IdentityProtocol.vote.value, msg_str, to_whom=self.group)
            self.logger.debug("Send vote")
            queues[CfgIds.network.value].put(message, block=True, timeout=self.q_cadence)
        except Full:
            self.logger.error('vote_response: Network queue full')

    def handle_acceptance(self, queues, message):
        if self.phase < 2:
            return False
        if message.function == IdentityProtocol.accept.value:
            self.logger.debug('Received peer acceptance')
            ident, ph = from_yaml_string(message.obj)
            if ph != self.package_hash:
                self.logger.error("Counterfeit 'peer'")
                return True
            self._add_peer(queues, ident)
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
        if message.function == IdentityProtocol.confirm.value:
            self.logger.debug('Received peer confirmation')
            # FIXME validate blob
            self._add_peer(queues, message.obj.identity)
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
        if message.function == IdentityProtocol.diff.value:
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
        if message.function == IdentityProtocol.update.value:
            self.logger.debug('Received group update')
            group = Group.from_yaml_string(message.obj)
            if self.group == group:
                self.group = group
                self._record_group(queues)
            return True
        return False

    def _run_handlers(self, queues, message):
        self.vote_response(queues)
        if self.handle_acceptance(queues, message):
            return True
        if self.receive_history(queues, message):
            return True
        if self.welcoming_committee(queues, message):
            return True
        if self.handle_vote_on_peer(queues, message):
            return True
        if self.count_vote(queues, message):
            return True
        if self.handle_history_diff(queues, message):
            return True
        if self.handle_group_update(queues, message):
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
        self.announce_identity(queues)
        if not self.choosing:
            # initial run, may be called again
            threading.Thread(target=self.choose_group, args=(queues,), daemon=True).start()
        while self.keep_running(signal):
            if self.phase != phase:
                self.logger.debug('Phase %s' % self.phase)
                phase = self.phase
            untouched = []
            while len(self.messages) > 0:
                message = self.messages.pop(0)
                if not self._run_handlers(queues, message):
                    untouched.append(message)
            try:
                message = queues[self.name].get(block=True, timeout=self.q_cadence)
                if not self._run_handlers(queues, message):
                    untouched.append(message)
            except Empty:
                pass
            self.messages += untouched
            time.sleep(self.cadence)
