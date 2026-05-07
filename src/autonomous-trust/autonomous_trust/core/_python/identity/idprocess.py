# ******************
#  Copyright 2025 Sean M. Brennan and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************

import hmac
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
import json
from ..config import Configuration, to_json_string, from_json_string, names
from ..config.configuration import ConfigJSONEncoder
from ..processes import Process, ProcMeta
from ..network import Message, Network
from .history import IdentityByWork, IdentityByStake, IdentityByAuthority
from .history import IdentityObj
from .protocol import IdentityProtocol
from ..structures.dag import LinkedStep
from ..system import CfgIds, encoding, PackageHash, now
from .. import _probes


VoteData = tuple[IdentityObj, AgreementProof, tuple[bytes, bytes]]

GroupHistory = tuple[Group, IdentityHistory]

GroupTree = tuple[Group, list[LinkedStep]]


class IdentityProcess(Process, metaclass=ProcMeta,
                      proc_name=CfgIds.identity, description='Identity registration'):
    """
    Handle Identity and Peer tracking
    Zero trust in this stage
    """
    init_timeout = 5
    init_extra = 2
    vote_timeout = 0.5  # seconds to wait for additional votes after own vote cast
    enc = encoding

    def __init__(self, configurations, subsystems, log_q, **kwargs):
        super().__init__(configurations, subsystems, log_q, dependencies=[CfgIds.network], **kwargs)
        # Optional override of the choose_group bootstrap window. The
        # default 5s is fine for the bootstrap node of a fresh group, but
        # late joiners that need an existing group's history to arrive
        # over UDP broadcast (e.g. an observer container coming up beside
        # an already-running peer mesh) routinely lose the race and end
        # up self-grouping. Set AT_INIT_TIMEOUT_SEC on those containers.
        try:
            override = float(os.environ.get('AT_INIT_TIMEOUT_SEC', '0'))
            if override > 0:
                self.init_timeout = override
        except (TypeError, ValueError):
            pass
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
            self._reputations = {}  # populated by reputation process messages
            self._history = IdentityByStake(self.identity, self.peers, log_q, 2,
                                            reputation_fn=lambda uid: self._reputations.get(uid, 1.0))
        elif impl == AgreementImpl.POA.value:
            self._history = IdentityByAuthority(self.identity, self.peers, log_q, 2)
        else:
            raise RuntimeError('Invalid identity history implementation: %s' % impl)
        self.messages: list[Message] = []
        self.border_guard_mode = True
        # 3-tuple: (group, history-steps, peer-identities). The peer
        # list rides along to seed self.peers with welcomer-known peers
        # whose admission confirm broadcasts predated our join. Older
        # sender versions send a 2-tuple; choose_group() tolerates both.
        self.histories: list[tuple] = []
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
        self.protocol.register_handler(IdentityProtocol.caps_query, self.handle_caps_query)
        self.protocol.register_handler(IdentityProtocol.caps_response, self.handle_caps_response)
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
                    # Fan-put BOTH Peers and PeerCapabilities. Previously
                    # only Peers was broadcast here; PeerCapabilities was
                    # saved to file but never propagated, so any cap
                    # registered outside the _add_peer-with-explicit-put
                    # path (e.g. recovery via handle_caps_response or
                    # welcoming_committee amnesia branch) would land in
                    # idprocess's view but never reach the main proc /
                    # bridge.rcvr — manifesting as the EPA airquality_stream
                    # gap in the multi-agency demo (idproc had 9 keys, main
                    # proc stayed at 8). The _add_peer path's explicit
                    # put to main+negotiation queues becomes redundant
                    # but harmless after this change.
                    self.update(obj, queues)
                else:
                    self.configs[name] = obj[0]
                    with open(filename, 'w') as cfg:
                        if isinstance(obj[0], Group):
                            json.dump((obj[0], obj[1].to_dict()), cfg, cls=ConfigJSONEncoder, indent=2)
                        else:
                            json.dump((obj[0], obj[1]), cfg, cls=ConfigJSONEncoder, indent=2)
                    self.update(obj[0], queues)
                    # The history (obj[1]) is intentionally NOT broadcast.
                    # protocol.run_message_handlers has no isinstance branch
                    # for IdentityHistory / IdentityByAuthority, so every
                    # consumer logs "Unhandled message of type
                    # IdentityByAuthority" and discards it. The history is
                    # already persisted to disk above for any process that
                    # needs to reload it.
        except Exception as err:
            self.logger.error('Error saving %s for %s: %s' % (name, obj.__class__.__name__, err))
            try:
                if os.path.exists(filename) and os.stat(filename).st_size == 0:
                    os.remove(filename)
            except FileNotFoundError:
                pass

    def _record_group(self, queues):
        if self.group is None:
            return
        # Demoted to verbose: every peer-acceptance triggers _add_peer →
        # _record_group, which cascades log lines O(N²) across the mesh.
        # The meaningful event ("Process accepted peer:") is logged by
        # _peer_accepted at debug level, which is enough.
        self.logger.verbose('Add group')
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
        with self.lock:
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
            msg_str = to_json_string((self.identity.publish(), self.package_hash, self.capabilities.to_list()))
            message = Message(self.name, IdentityProtocol.announce,
                              msg_str, to_whom=Network.broadcast, encrypt=False)
            queues[CfgIds.network].put(message, block=True, timeout=self.q_cadence)
        except Full:
            self.logger.error('announce_identity: Network queue full')
        with self.lock:
            self.phase = 2

    def choose_group(self, queues):
        """
        Await incoming histories, choose from among them
        :param queues:
        :return: None
        """
        try:
            start = now()
            with self.lock:
                self.choosing = True
            # Wait adaptively: exit early once histories arrive, with a short
            # grace period for additional histories; fall back to init_timeout.
            grace = 1  # seconds to wait after first history arrives
            history_seen_at = None
            while (now() - start).seconds <= self.init_timeout:
                with self.lock:
                    has_histories = len(self.histories) > 0
                if has_histories:
                    if history_seen_at is None:
                        history_seen_at = now()
                    elif (now() - history_seen_at).total_seconds() >= grace:
                        break
                time.sleep(self.cadence)
            # accepted is (group, steps) — group/steps come from the
            # one chosen welcomer (longest history wins). Peer
            # identities, however, are unioned across ALL received
            # histories so we don't miss peers any one welcomer
            # happens to be unaware of (each welcomer's peer view can
            # be partial due to admit-time confirm propagation gaps).
            accepted: tuple[Optional[Group], Optional[list[LinkedStep]]] = None, None
            unioned_peers: dict = {}  # uuid_str -> Identity

            self.logger.debug('%d histories' % len(self.histories))
            for hist_tpl in self.histories:
                # Tolerate 2-tuple (legacy) and 3-tuple (group, steps,
                # peer_idents) wire shapes.
                if len(hist_tpl) >= 3:
                    group, steps, peer_idents = hist_tpl[0], hist_tpl[1], hist_tpl[2]
                else:
                    group, steps = hist_tpl[0], hist_tpl[1]
                    peer_idents = None
                # Merge peer identities from every history that arrived
                # — even ones we won't pick for our group/DAG — so the
                # peer set is the union of what all welcomers saw.
                if peer_idents:
                    for ident in peer_idents:
                        uuid = getattr(ident, 'uuid', None)
                        if uuid is not None:
                            unioned_peers.setdefault(str(uuid), ident)
                if not steps:
                    continue
                if CfgIds.group in self.configs and self.configs[CfgIds.group] == group:
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
                    self._record_group(queues)
                    self._populate_peers_from_history(
                        queues, list(unioned_peers.values()))
                    existing = hist
                    diff: list[LinkedStep] = self._history.catch_up(existing)
                    msg_str = to_json_string(diff)  # to self.handle_history_diff()
                    message = Message(self.name, IdentityProtocol.diff, msg_str, to_whom=self.group)
                    self.logger.debug('Send history diff')
                    queues[CfgIds.network].put(message, block=True, timeout=self.q_cadence)
                else:
                    from_scratch = True
                    try:
                        filename = os.path.join(Configuration.get_cfg_dir(), 'group' + Configuration.file_ext)
                        if os.path.exists(filename):
                            with open(filename, 'r') as cfg:
                                from ..config.configuration import config_json_decoder
                                self.group, hist_dict = json.load(cfg, object_hook=config_json_decoder)
                                self._history.populate(hist_dict)
                                from_scratch = False
                    except Exception as err:
                        self.report_exception(err, 'choose_group')
                    if from_scratch:
                        self.logger.debug('No history/group key: generate my own.')
                        self.group = Group.initialize({self.identity.uuid: self.identity.address},
                                                      names.random_name())
                    self.logger.debug('Generated group: %s' % self.group.nickname)
                    self._record_group(queues)
            except Full:
                self.logger.error('choose_group: Network queue full')
            with self.lock:
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
            hist_tpl = from_json_string(message.obj)  # from self._peer_accepted()
            shape = ('3tuple' if isinstance(hist_tpl, (list, tuple))
                     and len(hist_tpl) >= 3 else '2tuple')
            _probes.counter('id.receive_history', 'arrived', shape)
            with self.lock:
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
                obj = from_json_string(obj)  # from self.vote_response()
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
            vote = self._process_id(blob)
            if vote is not None:
                self._history.verify(*vote)
                with self.lock:
                    if vote in self.confirmed_block:
                        self.confirmed_block.remove(vote)
                self.logger.debug('I voted for %s' % blob.identity.nickname)
            else:
                self.logger.debug('I did not vote for %s' % blob.identity.nickname)
            # Short wait for other votes to arrive before finalizing
            start = now()
            while (now() - start).total_seconds() <= self.vote_timeout:
                time.sleep(self.cadence)
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

        # inform existing group members about the new peer;  to self.handle_confirm_peer()
        message = Message(self.name, IdentityProtocol.confirm, blob, to_whom=self.group)
        queues[CfgIds.network].put(message, block=True, timeout=self.q_cadence)

        # send my identity in the open to enable encryption;  to self.handle_acceptance()
        msg_str = to_json_string((self.identity.publish(), self.package_hash, self.capabilities.to_list()))
        message = Message(self.name, IdentityProtocol.accept, msg_str, to_whom=blob.identity, encrypt=False)
        queues[CfgIds.network].put(message, block=True, timeout=self.q_cadence)

        # send group key + history + my peer set so the new peer can
        # decrypt future group messages AND populate identities for the
        # peers I already admitted (otherwise it never receives confirm
        # broadcasts for those peers — see project_inspector_peer_set_gap).
        # Peer identities are stripped of private keys via publish().
        peers_payload = [p.publish() for p in self.peers.all]
        msg_str = to_json_string((self.group, self._history.recite(),
                                  peers_payload))
        message = Message(self.name, IdentityProtocol.history, msg_str, to_whom=blob.identity)
        self.logger.debug('Send full history (+%d peer identities)' %
                          len(peers_payload))
        queues[CfgIds.network].put(message, block=True, timeout=self.q_cadence)

        if not amnesia:  # otherwise, already in listings
            # add to group and peer list (after history is queued, so peer
            # receives the group key before any group-encrypted messages)
            _probes.emit('peer.set', 'add_request',
                         peer_uuid=str(blob.identity.uuid),
                         peer_addr=getattr(blob.identity, 'address', None),
                         source='peer_accepted')
            self._add_peer(queues, blob.identity, amnesia)

    def welcoming_committee(self, queues, message):
        """
        Handle incoming newbies. Every peer in phase 3 caches the
        announcement (so handle_confirm_peer can later add the peer
        when the admission broadcast arrives). Only border-guards
        drive the vote/broadcast/welcome cycle.
        """
        if self.phase != 3:
            return False
        if message.function == IdentityProtocol.announce:
            try:
                new_id, ph, caps = from_json_string(message.obj)  # from self.announce_identity()
                if new_id == self.identity:
                    self.logger.debug('Should not have received my own announcement')
                    return
                if not hmac.compare_digest(str(ph), str(self.package_hash)):
                    self.logger.error("Newbie is running a counterfeit; Ignore")
                    return True
                id_obj = IdentityObj(new_id, new_id.uuid)
                existing = self.peers.find_by_uuid(new_id.uuid)
                if new_id == existing:  # don't care if it's a different address
                    self.logger.debug('Amnesiac peer: %s' % new_id.nickname)
                    # Late-arrival cap recovery: if this peer was added
                    # to self.peers via a confirm broadcast that arrived
                    # before its announce (no_prior_potential path), its
                    # capabilities never registered — _add_peer needs the
                    # announce-time peer_potentials cache. The announce
                    # we just got carries those caps; register them now
                    # if they aren't already in peer_capabilities.
                    # Without this, late-joiner peers (e.g. EPA in the
                    # disaster demo) end up in peers but invisible to
                    # any cap-driven discovery (DataRcvr subscribes,
                    # task negotiation participant lookup, etc.).
                    with self.lock:
                        # Per-cap dedup: register only the caps for
                        # which this peer's uuid isn't already recorded.
                        # A coarse "uuid anywhere?" check would skip
                        # missing caps when the peer is already in the
                        # mapping under any other cap.
                        missing = [
                            c for c in (caps or [])
                            if new_id.uuid not in self.peer_capabilities.get(c, [])
                        ]
                    if missing:
                        self.peer_capabilities.register(new_id.uuid, missing)
                        self._record_peers(queues)
                        _probes.counter('peer.set', 'amnesia_caps_registered',
                                        str(len(missing)))
                    if self.border_guard_mode:
                        self._peer_accepted(queues, id_obj, amnesia=True)
                    return True

                self.logger.debug('Received new identity: %s - %s - %s' % (new_id.nickname, new_id.address, new_id.uuid))
                if not id_obj.validate():
                    self.logger.warning('Invalid identity object from %s' % new_id.nickname)
                    return True
                # Cache the announcement on every peer (regardless of
                # border_guard_mode). Without this, non-welcomers later
                # silent-drop the peer_accepted broadcast in
                # handle_confirm_peer because peer.uuid is not in
                # peer_potentials.
                with self.lock:
                    self.peer_potentials[new_id.uuid] = caps
                if not self.border_guard_mode:
                    return True  # cache-only path; voting is welcomers' job
                threading.Thread(target=self._vote_collection,
                                 args=(queues, id_obj), daemon=True).start()
                msg_str = id_obj.to_string()  # to self.handle_vote_on_peer()
                message = Message(self.name, IdentityProtocol.propose, msg_str, to_whom=self.group)
                queues[CfgIds.network].put(message, block=True, timeout=self.q_cadence)
            except Full:
                self.logger.error('welcoming_committee: Network queue full')
            return True
        return False

    def _update_group(self, queues, group, level):
        grp_msg = group.to_string()  # to self.handle_group_update()
        for to_peer in list(self.peers.hierarchy[level].values()):
            message = Message(self.name, IdentityProtocol.update, grp_msg, to_whom=to_peer)
            queues[CfgIds.network].put(message, block=True, timeout=self.q_cadence)
            self.logger.debug('Sent group %s to %s (%s)' % (group.nickname, to_peer.nickname, to_peer.address))

    def _populate_peers_from_history(self, queues, peer_idents):
        """Seed self.peers from a welcomer's bundled peer list.

        Late joiners never receive the confirm broadcasts for peers
        admitted before they joined — admit-time `_peer_accepted`
        targets the welcomer's group at that moment. _peer_accepted
        therefore now includes a peer-identity payload alongside the
        history; this helper merges those into self.peers.

        We deliberately do NOT call `_add_peer` here because:
          * `self._history.catch_up` (the caller) already adopted the
            welcomer's history DAG, which contains an admission step
            for each of these peers. `_history.insert_peer` would
            double-write.
          * `self.group` was just replaced with the welcomer's group,
            which already lists these peers; `_add_peer` would re-emit
            address-add side effects.

        Capabilities are not part of the history bundle (would balloon
        wire size); peer_capabilities entries for these peers stay
        absent until the normal `peer-capabilities` broadcasts catch
        up. Reputation/messaging works without them.

        After populating, calls `_announce_self_to_bundled_peers` so
        the bundled peers learn about us — without this, the symmetry
        breaks: we know them but they don't know us, and our encrypted
        messages to them can't be decrypted (find_by_address fails →
        unknown-sender path → defer → mystery-handler timeout → drop).
        """
        if not peer_idents:
            return
        newly_added = []
        for ident in peer_idents:
            if ident is None:
                continue
            uuid = getattr(ident, 'uuid', None)
            if uuid is None:
                continue
            if str(uuid) == str(self.identity.uuid):
                continue
            if self.peers.find_by_uuid(uuid) is not None:
                continue
            self.peers.add(ident)
            _probes.emit('peer.set', 'add_request',
                         peer_uuid=str(uuid),
                         peer_addr=getattr(ident, 'address', None),
                         source='history_bundle')
            newly_added.append(ident)
        if newly_added:
            self._record_peers(queues)
            self.logger.debug('History bundle: added %d previously '
                              'unknown peer identities' % len(newly_added))
            self._announce_self_to_bundled_peers(queues, newly_added)

    def _announce_self_to_bundled_peers(self, queues, peer_idents):
        """Send `identity:accept` (containing self) to each peer
        learned via the history bundle.

        Mirrors the welcomer's accept payload format
        (`(self.identity.publish(), self.package_hash,
        self.capabilities.to_list())`) so the receivers' existing
        `handle_acceptance` adds us to their peer list. The package
        hash check on their side is the security gate.

        Without this, only welcomers (the few peers that voted on us
        at announce time) ever add us; everyone else stays in the
        unknown-sender path for our encrypted traffic and silently
        defers/drops it via the mystery-handler.
        """
        if self.identity is None or self.package_hash is None:
            return
        try:
            payload = to_json_string((self.identity.publish(),
                                      self.package_hash,
                                      self.capabilities.to_list()))
        except Exception as err:
            self.logger.error(
                '_announce_self_to_bundled_peers: payload build failed: %s' % err)
            return
        sent = 0
        for peer in peer_idents:
            try:
                message = Message(self.name, IdentityProtocol.accept,
                                  payload, to_whom=peer, encrypt=False)
                queues[CfgIds.network].put(
                    message, block=True, timeout=self.q_cadence)
                _probes.counter('peer.set', 'self_announce', 'sent')
                sent += 1
            except Full:
                _probes.counter('peer.set', 'self_announce', 'queue_full')
                self.logger.error(
                    '_announce_self_to_bundled_peers: Network queue full')
        if sent:
            self.logger.debug(
                'Announced self to %d bundled peers' % sent)

    def _add_peer(self, queues, identity, amnesia=False):
        # TODO: Use 'amnesia' parameter — when True, treat this peer as if
        # we have no prior history with them (e.g. after a partition heal).
        level = self.peers.mid_level
        if self.group is not None:
            # TODO: Consider delaying group update until after peer is fully
            # validated, to avoid exposing group key to unconfirmed peers.
            self.group.add_address(identity.uuid, identity.address)
            self._record_group(queues)
            # TODO: Consider using the new peer's group key instead of ours
            # when the new peer comes from a larger/older group.
            self._update_group(queues, self.group, level)
        self._history.insert_peer(identity, level)
        with self.lock:
            has_potential = identity.uuid in self.peer_potentials
            capabilities = self.peer_potentials.get(identity.uuid) if has_potential else None
        if has_potential:
            self.peer_capabilities.register(identity.uuid, capabilities)
            self._record_peers(queues)
            with self.lock:
                try:
                    del self.peer_potentials[identity.uuid]
                except KeyError:
                    pass  # race condition: another thread may have deleted it
        # TODO: Review whether these capability broadcasts are redundant
        # with self.update() — they may cause duplicate processing downstream.
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
            # Resolved: If prove() or sign() raises, the exception is caught below
            # and vote is never appended to confirmed_block (append is unreachable).
            with self.lock:
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
            # TODO: Check border_guard_mode — when True, this node acts as a
            # gatekeeper and should apply stricter validation before processing
            # proposals. When False, defer to other peers' judgment.
            blob = message.obj  # from self.welcoming_committee()
            if isinstance(blob, str):
                blob = Configuration.from_string(blob)
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
        with self.lock:
            if len(self.confirmed_block) < 1:
                return
            vote: VoteData = self.confirmed_block.pop(0)
        try:
            if vote[0].uuid == vote[1].uuid:
                return  # no voting for yourself
            # If we proposed this peer (present in our peer_potentials),
            # abstain from voting to avoid self-endorsement bias.
            if vote[0].identity.uuid in self.peer_potentials:
                self.logger.debug('Abstaining from vote on self-proposed peer %s' %
                                  vote[0].identity.nickname)
                return
            msg_str = to_json_string(vote)  # to self.count_vote()
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
            ident, pkh, caps = from_json_string(message.obj)  # from self._peer_accepted()
            if not hmac.compare_digest(str(pkh), str(self.package_hash)):
                self.logger.error("Counterfeit 'peer'")
                return True
            with self.lock:
                self.peer_potentials[ident.uuid] = caps
            _probes.emit('peer.set', 'add_request',
                         peer_uuid=str(ident.uuid),
                         peer_addr=getattr(ident, 'address', None),
                         source='handle_acceptance')
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
            blob = message.obj
            if isinstance(blob, str):
                blob = Configuration.from_string(blob)
            if hasattr(blob, 'validate') and not blob.validate():
                _probes.counter('peer.set', 'silent_drop', 'invalid_blob')
                self.logger.warning('Invalid peer confirmation blob')
                return True
            peer = blob.identity if hasattr(blob, 'identity') else blob
            # Note: peer_potentials membership was previously a hard gate here.
            # It was redundant — blob.validate() already checked authenticity,
            # the confirm broadcast comes from a trusted group member, and the
            # gate fought UDP loss of the prior announcement multicast.
            # We now proceed unconditionally and emit a probe when the prior
            # potential is missing, so the announcement-loss rate is still
            # observable.
            if peer.uuid not in self.peer_potentials:
                _probes.counter('peer.set', 'no_prior_potential')
                _probes.emit('peer.set', 'no_prior_potential',
                             peer_uuid=str(peer.uuid),
                             peer_addr=getattr(peer, 'address', None))
                # Recovery for UDP-loss of the new peer's announce. The
                # confirm broadcast (group/TCP) is reliable; the
                # announce (broadcast/UDP) isn't. Send a directed
                # caps_query — peer responds via group/TCP with its
                # capability list, which we register on receipt. Without
                # this, late joiners (e.g. EPA in the disaster demo)
                # stay invisible to cap-driven discovery: in self.peers
                # but missing from peer_capabilities, so DataRcvr never
                # subscribes to their streams.
                self._send_caps_query(queues, peer)
            _probes.emit('peer.set', 'add_request',
                         peer_uuid=str(peer.uuid),
                         peer_addr=getattr(peer, 'address', None),
                         source='handle_confirm_peer')
            self._add_peer(queues, peer)
            return True
        return False

    def _send_caps_query(self, queues, peer):
        """Ask `peer` directly for its capability list.

        Used as the recovery path when this node's `peer_potentials`
        cache is empty for a peer that's being admitted via confirm
        broadcast — i.e. the peer's UDP announce was lost. Unlike the
        announce path, this query goes to `peer` (group/TCP), so it's
        reliable.
        """
        try:
            message = Message(self.name, IdentityProtocol.caps_query,
                              '', to_whom=peer)
            queues[CfgIds.network].put(message, block=True,
                                       timeout=self.q_cadence)
            _probes.counter('peer.set', 'caps_query_sent')
        except Full:
            _probes.counter('peer.set', 'caps_query_q_full')
            self.logger.error('_send_caps_query: Network queue full')

    def handle_caps_query(self, queues, message):
        """Respond to a peer's caps_query with our own capability list."""
        if message.function != IdentityProtocol.caps_query:
            return False
        try:
            caps_list = self.capabilities.to_list() \
                if self.capabilities is not None else []
            # Diagnostic: emit the actual caps we're about to send so we
            # can verify that the responder's idprocess capabilities have
            # been populated by the autonomous_ability fan-put. If
            # caps_list is missing the role-specific cap (e.g. EPA's
            # airquality_stream), the fan-put hasn't propagated to
            # idprocess in time.
            _probes.emit('peer.set', 'caps_query_responding',
                         caps_count=len(caps_list),
                         caps=','.join(sorted(caps_list)) if caps_list else '')
            payload = to_json_string(caps_list)
            sender = getattr(message, 'from_whom', None)
            if sender is None:
                _probes.counter('peer.set', 'caps_query_no_sender')
                return True
            reply = Message(self.name, IdentityProtocol.caps_response,
                            payload, to_whom=sender)
            queues[CfgIds.network].put(reply, block=True,
                                       timeout=self.q_cadence)
            _probes.counter('peer.set', 'caps_response_sent')
        except Full:
            _probes.counter('peer.set', 'caps_response_q_full')
            self.logger.error('handle_caps_query: Network queue full')
        except Exception as err:
            _probes.counter('peer.set', 'caps_query_exc')
            self.report_exception(err, 'handle_caps_query')
        return True

    def handle_caps_response(self, queues, message):
        """Receive caps from a peer we previously queried; register any
        caps that aren't already recorded for this peer.

        Per-cap dedup is important: a peer may already be registered
        under SOME of its caps (e.g. `sensor_validation`) but missing
        from OTHERS (e.g. `airquality_stream`). A coarse "is the uuid
        anywhere?" check would silently skip registering the missing
        ones — exactly the EPA late-joiner bug we're recovering from."""
        if message.function != IdentityProtocol.caps_response:
            return False
        sender = getattr(message, 'from_whom', None)
        if sender is None:
            _probes.counter('peer.set', 'caps_response_no_sender')
            return True
        try:
            caps_list = from_json_string(message.obj)
            if not isinstance(caps_list, list) or not caps_list:
                _probes.counter('peer.set', 'caps_response_bad_shape')
                return True
            # Compute the set of caps this peer is missing from.
            # Snapshot under lock; emit diagnostics OUTSIDE the lock to
            # avoid contention with the identity proc's fan-put path.
            with self.lock:
                missing = [
                    c for c in caps_list
                    if sender.uuid not in self.peer_capabilities.get(c, [])
                ]
                pc_size_idproc = len(self.peer_capabilities)
                # Has airquality_stream as a key in idprocess's view?
                ids_has_aqs = 'airquality_stream' in self.peer_capabilities
            _probes.counter('peer.set', 'caps_response_idproc_pc_size',
                            str(pc_size_idproc))
            _probes.counter('peer.set', 'caps_response_aqs_in_idproc',
                            str(int(ids_has_aqs)))
            if missing:
                self.peer_capabilities.register(sender.uuid, missing)
                self._record_peers(queues)
                _probes.counter('peer.set', 'caps_response_registered',
                                str(len(missing)))
            else:
                _probes.counter('peer.set', 'caps_response_redundant')
            # Always re-broadcast peer_capabilities to main + negotiation,
            # mirroring _add_peer's explicit puts. _record_peers's
            # update() fan-put has been observed to silently drop under
            # main proc queue contention — q_cadence=10ms is too short
            # when main proc is processing thousands of rep_resp msgs.
            # Use a 1s timeout here so the put rides through bursty
            # contention; it's still bounded, so it won't deadlock.
            try:
                queues[CfgIds.main].put(
                    self.peer_capabilities, block=True, timeout=1.0)
                _probes.counter('peer.set', 'caps_explicit_main_put')
            except Full:
                _probes.counter('peer.set', 'caps_explicit_main_full')
            try:
                queues[CfgIds.negotiation].put(
                    self.peer_capabilities, block=True, timeout=1.0)
                _probes.counter('peer.set', 'caps_explicit_neg_put')
            except Full:
                _probes.counter('peer.set', 'caps_explicit_neg_full')
        except Exception as err:
            _probes.counter('peer.set', 'caps_response_exc')
            self.report_exception(err, 'handle_caps_response')
        return True

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
            steps = from_json_string(message.obj)  # from self.choose_group()
            self._record_group(queues)
            name = message.from_whom.nickname
            if name in self._history.heads:
                del self._history.heads[name]
            branch = self._history.ingest_branch(steps, name)
            if self._history._validate(branch):
                self._history.merge(branch)
            else:
                self.logger.warning('Invalid history diff from %s' % name)
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
            mine, theirs = self.group, group
            if mine.uuid == theirs.uuid:
                # Same group: adopt strictly larger membership, otherwise no-op.
                if len(theirs.addresses) > len(mine.addresses):
                    adopt = True
                else:
                    return True   # quiet no-op; never echo on equal/smaller
            else:
                # Different groups: adopt strictly larger membership; on a tie,
                # break it deterministically by uuid (smaller wins). Without
                # the tiebreaker, two peers with same-size groups each fall
                # through to _update_group, generating a network-wide
                # group_key_update ping-pong (~10k msgs/sec under load).
                if len(theirs.addresses) > len(mine.addresses):
                    adopt = True
                elif len(theirs.addresses) < len(mine.addresses):
                    adopt = False
                else:
                    adopt = str(theirs.uuid) < str(mine.uuid)
            if adopt:
                self.logger.debug('Replace %s group with %s group' % (mine.nickname, theirs.nickname))
                self.group = theirs
                self._record_group(queues)
                return True
            # We are the canonical winner — push our group to peers below us
            # in the hierarchy so they converge on it. Don't echo on every
            # equal-size update we receive; that's the flood.
            self._update_group(queues, self.group, self.peers.mid_level)
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
        # Drain budget per iter — same shape as repprocess.py /
        # negprocess.py. The 0.5 s cadence-pacing sleep used to cap
        # each subsystem at ~2 msgs/s; welcoming-committee + confirm
        # broadcast volume during convergence routinely exceeds that,
        # leaving messages in the deferred backlog for whole rounds.
        # vote_response and the deferred `self.messages` drain run
        # once per iter — both are non-blocking and don't need the
        # outer cadence to pace them.
        DRAIN_BUDGET = 64
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

                drained = 0
                first = True
                while drained < DRAIN_BUDGET:
                    try:
                        if first:
                            message = queues[self.name].get(
                                block=True, timeout=self.q_cadence)
                            first = False
                        else:
                            message = queues[self.name].get_nowait()
                    except Empty:
                        break
                    drained += 1
                    if message and not self.protocol.run_message_handlers(queues, message):
                        untouched.append(message)
                _probes.counter('proc.identity', 'iter_drained', str(drained))
                self.messages += untouched
            except Exception as err:
                self.report_exception(err, 'process')
