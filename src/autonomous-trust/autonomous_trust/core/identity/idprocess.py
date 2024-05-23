import os
import sys
import time
from queue import Empty, Full
import threading
from typing import Optional, Union

from nacl.exceptions import BadSignatureError
from nacl.signing import SignedMessage

from . import Peers
from .group import Group
from .history.history import IdentityHistory
from ..algorithms.agreement import AgreementProof
from ..algorithms.impl import AgreementImpl
from ..capabilities import PeerCapabilities
from ..config import Configuration, to_yaml_string, from_yaml_string, names
from ..processes import Process, ProcMeta
from ..network import Message, Network
from .history import IdentityByWork, IdentityByStake, IdentityByAuthority
from .history import IdentityObj
from .protocol import IdentityProtocol
from ..structures.dag import LinkedStep
from ..system import CfgIds, encoding, PackageHash, now


VoteData = tuple[IdentityObj, AgreementProof, tuple[bytes, bytes]]

GroupHistory = tuple[Group, IdentityHistory]

GroupTree = tuple[Group, list[LinkedStep]]


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
        self.protocol = IdentityProtocol(self.name, self.logger, configurations)
        self.peers = self.protocol.peers
        self.group = self.protocol.group
        self.peer_capabilities = self.protocol.peer_capabilities
        self.phase = 0
        self.confirmed_block: list[VoteData] = []
        impl = self.identity.block_impl
        if impl == AgreementImpl.POW.value:
            self._history = IdentityByWork(self.identity, self.peers, log_q, 0)
        elif impl == AgreementImpl.POS.value:
            self._history = IdentityByStake(self.identity, self.peers, log_q, 5)
        elif impl == AgreementImpl.POA.value:
            self._history = IdentityByAuthority(self.identity, self.peers, log_q, 5)
        else:
            raise RuntimeError('Invalid identity history implementation: %s' % impl)
        self.messages: list[Message] = []
        self.border_guard_mode = True
        self.histories: list[tuple[Group, list[LinkedStep]]] = []
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
        self.lock = None

    @property
    def capabilities(self):
        return self.protocol.capabilities

    def _remember_activity(self, queues, name: str, obj: Union[Peers, PeerCapabilities, GroupHistory]):
        filename = os.path.join(Configuration.get_cfg_dir(), name + Configuration.file_ext)
        try:
            with self.lock:  # multiple *threads* may try to save data
                if isinstance(obj, Peers) or isinstance(obj, PeerCapabilities):
                    self.configs[name] = obj
                    obj.to_file(filename)
                    if isinstance(obj, Peers):
                        self.update(obj, queues)
                else:
                    self.configs[name] = obj[0]
                    with open(filename, 'w') as cfg:
                        if isinstance(obj[0], Group):
                            cfg.write(to_yaml_string((obj[0], obj[1].to_dict())))
                        else:
                            cfg.write(to_yaml_string((obj[0], obj[1])))
                    self.update(obj[0], queues)
                    #self.update(obj[1], queues)  # FIXME ??
        except Exception as err:
            self.logger.error('Error saving %s for %s: %s' % (name, obj, err))
            try:
                if os.path.exists(filename) and os.stat(filename).st_size == 0:
                    os.remove(filename)
            except FileNotFoundError:
                pass

    def _record_group(self, queues):
        if self.group is None:
            return
        self.logger.debug('Add group')
        self._remember_activity(queues, CfgIds.group, (self.group, self._history))

    def _record_peers(self, queues):
        self.logger.debug('Add peers')
        self._remember_activity(queues, CfgIds.peers, self.peers)
        self._remember_activity(queues, CfgIds.capabilities, self.peer_capabilities)

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
            # to self.welcoming_committee()
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
        try:
            start = now()
            self.choosing = True
            while (now() - start).seconds <= self.init_timeout:
                time.sleep(self.cadence)
            accepted: tuple[Optional[Group], Optional[list[LinkedStep]]] = None, None

            self.logger.debug('%d histories' % len(self.histories))
            for group, steps in self.histories:
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
                    self.group, hist = accepted
                    self.logger.debug('Updated group key')
                    self._record_group(queues)  # FIXME what about peers? *****************************
                    existing = hist  # FIXME
                    # existing = self._history.hear(*accepted[1])  # noqa
                    diff: list[LinkedStep] = self._history.catch_up(existing)
                    # FIXME dag has digests, not peer data, need peers - use history to verify

                    self.logger.debug('Diff %s' % diff)  # FIXME remove
                    msg_str = to_yaml_string(diff)  # to self.handle_history_diff()
                    message = Message(self.name, IdentityProtocol.diff, msg_str, to_whom=self.group)
                    self.logger.debug('Send history diff')
                    queues[CfgIds.network].put(message, block=True, timeout=self.q_cadence)
                else:
                    from_scratch = True
                    try:
                        filename = os.path.join(Configuration.get_cfg_dir(), 'group' + Configuration.file_ext)
                        if os.path.exists(filename):
                            with open(filename, 'r') as cfg:
                                self.group, hist_dict = from_yaml_string(cfg.read())
                                self._history.populate(hist_dict)
                                from_scratch = False
                    except Exception as err:
                        self.report_exception(err, 'choose_group')
                    if from_scratch:
                        self.logger.debug('No history/group key: generate my own.')
                        self.group = Group.initialize({self.identity.uuid: self.identity.address},
                                                      names.random_name())
                    self.logger.debug(self.group)  # FIXME remove
                    self._record_group(queues)
            except Full:
                self.logger.error('choose_group: Network queue full')
            self.choosing = False
            self.phase = 3
        except Exception as err:
            self.report_exception(err, 'choose_group')

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
            hist_tpl = from_yaml_string(message.obj)  # from self._peer_accepted()
            self.histories.append(hist_tpl)  # see choose_group
            if not self.choosing:
                threading.Thread(target=self.choose_group, args=(queues,), daemon=True).start()
            return True
        return False

    def count_vote(self, _, message):
        """
        Receive/record a vote
        :param _: unused queues
        :param message: tuple of blob, proof, sig
        :return: bool (message handled)
        """
        if self.phase != 3:
            return False
        if message.function == IdentityProtocol.vote:
            obj = message.obj
            if isinstance(obj, str):
                obj = from_yaml_string(obj)  # from self.vote_response()
            blob, proof, (msg, sig) = obj
            sig_msg = SignedMessage(sig + msg)
            try:
                message.from_whom.verify(sig_msg)
                self._history.verify(blob, proof, sig_msg)
            except BadSignatureError:
                self.logger.error('Vote had a bad signature')
            return True
        return False

    def _vote_collection(self, queues, blob: IdentityObj):
        try:
            start = now()
            voted = False
            while (now() - start).seconds <= self._history.timeout:
                if not voted:
                    vote = self._process_id(blob)
                    if vote is not None:
                        self._history.verify(*vote)
                        if vote in self.confirmed_block:
                            self.confirmed_block.remove(vote)
                        self.logger.debug('I voted for %s' % blob.identity.nickname)
                    voted = True
                else:
                    time.sleep(self.cadence)
            if not voted:
                self.logger.debug('I did not vote')
            if self._history.finalize(blob):
                self._peer_accepted(queues, blob)
        except Full:
            self.logger.error('vote_collection: Network queue full')
        except Exception as err:
            self.report_exception(err, 'vote_collection')

    def _peer_accepted(self, queues, blob: IdentityObj, amnesia=False):
        if self.group is None:  # too early
            return
        self.logger.debug('Process accepted peer: %s (%s)' % (blob.identity.nickname, amnesia))

        # inform other peers;  to self.handle_confirm_peer()
        message = Message(self.name, IdentityProtocol.confirm, blob, to_whom=self.group)
        queues[CfgIds.network].put(message, block=True, timeout=self.q_cadence)

        if not amnesia:  # otherwise, already in listings
            # add to group and peer list
            self._add_peer(queues, blob.identity, amnesia)

        # send my identity in the open to enable encryption;  to self.handle_acceptance()
        msg_str = to_yaml_string((self.identity.publish(), self.package_hash, self.capabilities.to_list()))
        message = Message(self.name, IdentityProtocol.accept, msg_str, to_whom=blob.identity, encrypt=False)
        queues[CfgIds.network].put(message, block=True, timeout=self.q_cadence)

        # now send encrypted history (peer identities);  to self.receive_history()  # FIXME this should contain all peer identities
        msg_str = to_yaml_string((self.group, self._history.recite()))
        message = Message(self.name, IdentityProtocol.history, msg_str, to_whom=blob.identity)
        self.logger.debug('Send full history')
        queues[CfgIds.network].put(message, block=True, timeout=self.q_cadence)

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
                new_id, ph, caps = from_yaml_string(message.obj)  # from self.announce_identity()
                if new_id == self.identity:
                    self.logger.debug('Should not have received my own announcement')
                    return
                if ph != self.package_hash:
                    self.logger.error("Newbie is running a counterfeit; Ignore")
                    return True
                id_obj = IdentityObj(new_id, new_id.uuid)
                existing = self.peers.find_by_uuid(new_id.uuid)
                if new_id == existing:  # don't care if it's a different address
                    self.logger.debug('Amnesiac peer: %s' % new_id.nickname)
                    self._peer_accepted(queues, id_obj, amnesia=True)
                    return True

                self.logger.debug('Received new identity: %s - %s - %s' % (new_id.nickname, new_id.address, new_id.uuid))
                self.peer_potentials[new_id.uuid] = caps

                # threading.Thread(target=self._process_id, args=(id_obj,), daemon=True).start()
                # time.sleep(self.cadence) # FIXME invalid
                threading.Thread(target=self._vote_collection,
                                 args=(queues, id_obj), daemon=True).start()
                msg_str = id_obj.to_yaml_string()  # to self.handle_vote_on_peer()
                # FIXME validate
                message = Message(self.name, IdentityProtocol.propose, msg_str, to_whom=self.group)
                queues[CfgIds.network].put(message, block=True, timeout=self.q_cadence)
            except Full:
                self.logger.error('welcoming_committee: Network queue full')
            return True
        return False

    def _update_group(self, queues, group, level):
        grp_msg = group.to_yaml_string()  # to self.handle_group_update()
        for to_peer in list(self.peers.hierarchy[level].values()):
            message = Message(self.name, IdentityProtocol.update, grp_msg, to_whom=to_peer)
            queues[CfgIds.network].put(message, block=True, timeout=self.q_cadence)
            self.logger.debug('Sent group %s to %s (%s)' % (group.nickname, to_peer.nickname, to_peer.address))

    def _add_peer(self, queues, identity, amnesia=False):  # FIXME use amnesia
        level = self.peers.mid_level
        if self.group is not None:  # FIXME delay?
            self.group.add_address(identity.uuid, identity.address)
            self._record_group(queues)
            self._update_group(queues, self.group, level)  # FIXME use group from new peer instead?
        self._history.insert_peer(identity, level)
        if identity.uuid in self.peer_potentials:
            capabilities = self.peer_potentials[identity.uuid]
            self.peer_capabilities.register(identity.uuid, capabilities)
            self._record_peers(queues)
            try:
                del self.peer_potentials[identity.uuid]
            except KeyError:
                pass  # FIXME but, why? This should have thrown above instead
        # FIXME these may not be necessary: (see self.update())
        queues[CfgIds.main].put(self.peer_capabilities, block=True, timeout=self.q_cadence)
        queues[CfgIds.negotiation].put(self.peer_capabilities, block=True, timeout=self.q_cadence)

    def _process_id(self, blob):
        try:
            for peer in self.peers.all:
                if blob.identity.uuid == peer.uuid or \
                        blob.identity.signature == peer.signature or \
                        blob.identity.encryptor == peer.signature:
                    self.logger.warning('New identity (%s) using peer id (%s)' % (blob.identity.nickname, peer.nickname))
                    return None
            proof: AgreementProof = self._history.prove(blob)
            sigmsg = self.identity.sign(proof)
            vote = blob, proof, (sigmsg.message, sigmsg.signature)
            # FIXME any failures should *not* load confirmed_block
            self.confirmed_block.append(vote)
            return vote
        except Exception as err:
            self.report_exception(err, 'process_id')

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
            blob = message.obj  # from self.welcoming_committee()
            # FIXME verify
            threading.Thread(target=self._process_id, args=(message.obj,), daemon=True).start()
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
            vote: VoteData = self.confirmed_block.pop(0)
            if vote[0].uuid == vote[1].uuid:
                return  # no voting for yourself
            # FIXME handle if I proposed the vote
            msg_str = to_yaml_string(vote)  # to self.count_vote()
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
            ident, pkh, caps = from_yaml_string(message.obj)  # from self._peer_accepted()
            if pkh != self.package_hash:
                self.logger.error("Counterfeit 'peer'")
                return True
            self.peer_potentials[ident.uuid] = caps
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
        if message.function == IdentityProtocol.confirm:
            self.logger.debug('Received peer confirmation')
            peer = message.obj.identity  # from self._peer_accepted()
            if peer.uuid not in self.peer_potentials:
                return True
            # FIXME validate blob
            self._add_peer(queues, peer)
            return True
        return False

    def handle_history_diff(self, queues, message):
        """
        Receive a history diff, possibly merge
        :param queues:
        :param message:
        :return: bool (message handled)
        """
        if self.phase != 3:
            return False
        if message.function == IdentityProtocol.diff:
            self.logger.debug('Received history diff')
            steps = from_yaml_string(message.obj)  # from self.choose_group()
            self._record_group(queues)
            branch = self._history.ingest_branch(steps, message.from_whom.nickname)
            # FIXME validate
            #self._history.merge(branch)
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
            group = message.obj  # from self._update_group()
            if (self.group.uuid != group.uuid and len(group.addresses) >= len(self.group.addresses)) or \
                    (self.group.uuid == group.uuid and len(group.addresses) > len(self.group.addresses)):
                self.logger.debug('Replace %s group with %s group' % (self.group.nickname, group.nickname))
                self.group = group
                self._record_group(queues)
            else:
                self._update_group(queues, self.group, self.peers.mid_level)  # counter with my superior group
            return True
        return False

    def process(self, queues, signal):
        """
        Identity/Peer processing main loop
        :param queues: Interprocess communication queues
        :param signal: IPC queue for signalling halt
        :return: None
        """
        self.lock = threading.Lock()  # initialize here to get past pickling
        phase = self.phase
        self.logger.debug('Phase %s' % self.phase)
        self.acquire_capabilities(queues)
        self.announce_identity(queues)
        if not self.choosing:
            # initial run, may be called again
            threading.Thread(target=self.choose_group, args=(queues,), daemon=True).start()
        while self.keep_running(signal):
            try:
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
            except Exception as err:
                self.report_exception(err, 'process')
