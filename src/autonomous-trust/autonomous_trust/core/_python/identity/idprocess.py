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
from datetime import datetime
from queue import Empty, Full
import threading
from typing import Optional, Union

from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
from nacl.signing import SignedMessage

from . import Peers
from .group import Group, ChildGroupSet
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
from .zta import ZtaPolicy, ZtaStatus
from ..structures.dag import LinkedStep
from ..system import CfgIds, encoding, PackageHash, now
from .. import _probes


VoteData = tuple[IdentityObj, AgreementProof, tuple[bytes, bytes]]

GroupHistory = tuple[Group, IdentityHistory]

GroupTree = tuple[Group, list[LinkedStep]]


# Persistent-cohort gate: peers below this trust tier are excluded from
# the peers.cfg.json / peer-capabilities.cfg.json snapshots. Mirrors
# REPUTATION_PERSIST_THRESHOLD (rep > 0.5) via TIER_FLOORS: tier 1 floor
# is 0.50, so any peer that's been scored above 0.5 has _tier >= 1.
PERSIST_TIER_FLOOR = 1


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

    # When True, _spawn replaces threading.Thread().start() with a direct,
    # synchronous call. The conformance harness sets this so scenario steps
    # are deterministic; production paths should leave it False.
    synchronous_dispatch = False

    def _spawn(self, target, args=(), kwargs=None, daemon=True):
        kwargs = kwargs or {}
        if self.synchronous_dispatch:
            target(*args, **kwargs)
            return None
        thread = threading.Thread(target=target, args=args, kwargs=kwargs, daemon=daemon)
        thread.start()
        return thread

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
        # ZTA admission gate (parity with the C handle_welcoming_committee
        # block, id_proc.c:777-821). Lazily built on first announce; the
        # default policy is disabled so non-ZTA deployments are unaffected.
        # See doc/architecture/zta-python-parity.md and zta-integration.md §11.
        self._zta_policy_cache: Optional[ZtaPolicy] = None
        self._zta_verifier_cache = None
        self._zta_capped: set = set()  # uuids admitted via DDIL fallback (rep-capped)
        self.choosing = False
        # P1 group-merge tracking: set when choose_group falls through to
        # self-bootstrap (mesh didn't answer in init_timeout). A late
        # `full_history` arriving after this point triggers a merge path
        # that adopts the mesh's group AND re-broadcasts request_access so
        # the mesh's BG admits us through the normal welcoming-committee
        # flow. Cleared once the merge is in flight to prevent loops.
        self.self_bootstrapped = False
        self.merging = False
        self.peer_potentials = {}
        # Gateway multi-group state — see
        # doc/architecture/gateway-reputation-tree.md.
        #   child_groups:   group-uuid-str -> Group (with key) we gateway
        #   parent_gateway: uuid-str of the higher-rank node we federate
        #                   through, or None
        # Both empty/None on rank-1 leaf nodes, which keeps every
        # multi-group path inert and behaviour identical to today.
        self.child_groups: dict[str, Group] = {}
        self.parent_gateway: Optional[str] = None
        # Partition-recovery state — see doc/architecture/partition-recovery.md.
        # All three maps are pure local memory; no wire egress, no
        # configuration import.  They get reset when _merge_to_mesh adopts
        # a remote group (the partition is resolved at that point).
        #   _partition_probe_cooldown:   from_addr  -> last probe sent
        #   _partition_response_cooldown: peer_uuid -> last response sent
        #   _partition_recovery_in_progress: (their_group_uuid, started_at)
        #     while non-None, suppress new probes until the timeout (15s)
        #     elapses or `_merge_to_mesh` clears it.
        self._partition_probe_cooldown: dict[str, datetime] = {}
        self._partition_response_cooldown: dict[str, datetime] = {}
        self._partition_recovery_in_progress: Optional[tuple[str, datetime]] = None
        # Late-joiner capability-loss backstop (see feedback_late_joiner_caps):
        # the confirm-time directed caps_query is a one-shot; if it OR its
        # response is lost in UDP, a peer stays in self.peers but invisible to
        # cap-driven discovery. This timestamp paces a periodic re-query sweep
        # over cap-less peers. Set on first process() iteration (post-fork).
        self._last_caps_resync: Optional[datetime] = None
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
        self.protocol.register_handler(IdentityProtocol.tier_update, self.handle_tier_update)
        self.protocol.register_handler(IdentityProtocol.partition_signal, self.handle_partition_signal)
        self.protocol.register_handler(IdentityProtocol.partition_probe, self.handle_partition_probe)
        self.protocol.register_handler(IdentityProtocol.partition_response, self.handle_partition_response)
        self.lock = None

    @property
    def capabilities(self):
        return self.protocol.capabilities

    def _trusted_uuids_for_persist(self):
        """Return uuids that should survive the persistent-cohort filter.

        Self is always included. A peer survives iff its `_tier` attr
        (populated by handle_tier_update from ReputationProcess) is at
        or above PERSIST_TIER_FLOOR — i.e. rep > REPUTATION_PERSIST_THRESHOLD
        per repprocess.TIER_FLOORS.
        """
        kept = {self.identity.uuid}
        for peer in self.peers.all:
            tier = getattr(peer, '_tier', 0) or 0
            if tier >= PERSIST_TIER_FLOOR:
                puuid = getattr(peer, 'uuid', None)
                if puuid is not None:
                    kept.add(puuid)
        return kept

    def _remember_activity(self, queues, name: str, obj: Union[Peers, PeerCapabilities, GroupHistory]):
        filename = os.path.join(Configuration.get_cfg_dir(), name + Configuration.file_ext)
        try:
            with self.lock:  # multiple *threads* may try to save data
                if isinstance(obj, Peers) or isinstance(obj, PeerCapabilities):
                    self.configs[name] = obj
                    # The in-memory object keeps untrusted peers (so we
                    # can still detect/handle them during this session);
                    # only the on-disk snapshot is filtered.
                    keep_uuids = self._trusted_uuids_for_persist()
                    snapshot = obj.filtered_for_persist(keep_uuids)
                    snapshot.to_file(filename)
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

    def _record_child_groups(self, queues):
        """Fan the current child-group set out to the other processes.

        Sibling of _record_group, but for the gateway's child groups
        rather than its primary. Sends a ChildGroupSet so the
        reputation / network processes can hold the child keys and
        chains without clobbering Protocol.group. No-op (and no IPC) on
        a leaf node — child_groups is empty. See
        doc/architecture/gateway-reputation-tree.md.
        """
        if not self.child_groups:
            return
        self.protocol.child_groups = dict(self.child_groups)
        try:
            self.update(ChildGroupSet(self.child_groups), queues)
        except Exception as err:
            self.logger.warning('Could not propagate child groups: %s' % err)

    def _adopt_child_group(self, queues, group, peer_idents=None):
        """Adopt a foreign cohort as one of our child groups (gateway).

        Stores the group (with its key) under child_groups keyed by
        uuid, seeds its member identities into our peer view, and
        propagates the updated child-group set. Idempotent — re-adopting
        a known child group just refreshes it. Does NOT touch self.group
        (the primary/parent cohort). See
        doc/architecture/gateway-reputation-tree.md.
        """
        if group is None:
            return
        key = str(group.uuid)
        if self.group is not None and key == str(self.group.uuid):
            return  # never demote our own primary group to a child
        self.child_groups[key] = group
        self.logger.info('Gateway adopted child group %s (%s)' %
                         (getattr(group, 'nickname', '?'), key[:8]))
        if peer_idents:
            self._populate_peers_from_history(queues, list(peer_idents))
        self._record_child_groups(queues)

    def _load_child_groups(self, queues):
        """Seed-assisted dual membership: adopt any child-group config
        files present in the config dir.

        A gateway is seeded with group.cfg.json for its primary/parent
        cohort plus one ``group_child_*.cfg.json`` per cohort it
        gateways (each holding that group's shared key). Runtime rank
        still governs the reputation roster and commit routing; this
        only hands the gateway the child keys at t=0 so the demo's
        warm-started, pre-partitioned cohorts work without a runtime
        cross-group join handshake. Leaf nodes have no such files, so
        this is a no-op. See doc/architecture/gateway-reputation-tree.md.
        """
        try:
            cfg_dir = Configuration.get_cfg_dir()
            prefix = 'group_child'
            ext = Configuration.file_ext
            try:
                names = sorted(os.listdir(cfg_dir))
            except FileNotFoundError:
                return
            from ..config.configuration import config_json_decoder
            for fname in names:
                if not (fname.startswith(prefix) and fname.endswith(ext)):
                    continue
                path = os.path.join(cfg_dir, fname)
                try:
                    with open(path, 'r') as cfg:
                        payload = json.load(cfg, object_hook=config_json_decoder)
                    # Tolerate (Group, hist_dict) — mirroring the primary
                    # group.cfg.json layout — or a bare Group.
                    group = payload[0] if isinstance(payload, (list, tuple)) else payload
                    self._adopt_child_group(queues, group)
                except Exception as err:
                    self.logger.warning(
                        'Could not load child group %s: %s' % (fname, err))
        except Exception as err:
            self.logger.warning('_load_child_groups failed: %s' % err)

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

    def _broadcast_request_access(self, queues):
        """Build and broadcast the `request_access` envelope on the open
        channel. Factored out of announce_identity so the group-merge
        path (see _merge_to_mesh) can re-broadcast without a phase change.
        Quiet on Full — caller logs."""
        msg_str = to_json_string((self.identity.publish(), self.package_hash, self.capabilities.to_list()))
        message = Message(self.name, IdentityProtocol.announce,
                          msg_str, to_whom=Network.broadcast, encrypt=False)
        queues[CfgIds.network].put(message, block=True, timeout=self.q_cadence)

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
            self._broadcast_request_access(queues)
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
                    # Mark self-bootstrap so a late-arriving `full_history`
                    # from a real mesh triggers the merge path in
                    # receive_history → _merge_to_mesh (BUGS.md §P1).
                    with self.lock:
                        self.self_bootstrapped = True
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
                should_merge = (self.self_bootstrapped
                                and not self.merging
                                and not self.choosing)
                if should_merge:
                    self.merging = True
            if should_merge:
                # Late history arrived after we already self-bootstrapped:
                # adopt the mesh's group and re-announce so the mesh's BG
                # admits us through the normal welcoming-committee path
                # (BUGS.md §P1).
                self._spawn(self._merge_to_mesh, args=(queues,))
            elif not self.choosing:
                self._spawn(self.choose_group, args=(queues,))
            return True
        return False

    def _merge_to_mesh(self, queues):
        """Merge from a self-bootstrap group of one into a real mesh.

        Called when receive_history arrives AFTER choose_group fell through
        to self-bootstrap. Discards our self-generated group and adopts the
        mesh's group key + history, then re-broadcasts `request_access` on
        the open channel so a BG admits us via welcoming_committee. The
        eventual `access_granted` + `full_history` round-trip routes back
        through the normal receive_history path with self_bootstrapped now
        clear — no merge re-entry. See BUGS.md §P1.
        """
        try:
            with self.lock:
                snapshot = list(self.histories)
            accepted: tuple[Optional[Group], Optional[list[LinkedStep]]] = None, None
            unioned_peers: dict = {}
            for hist_tpl in snapshot:
                if len(hist_tpl) >= 3:
                    group, steps, peer_idents = hist_tpl[0], hist_tpl[1], hist_tpl[2]
                else:
                    group, steps = hist_tpl[0], hist_tpl[1]
                    peer_idents = None
                if peer_idents:
                    for ident in peer_idents:
                        uuid = getattr(ident, 'uuid', None)
                        if uuid is not None:
                            unioned_peers.setdefault(str(uuid), ident)
                if not steps:
                    continue
                if accepted == (None, None) or len(steps) > len(accepted[1]):  # noqa
                    accepted = group, steps
            if accepted == (None, None):
                # All received histories were empty — nothing to merge to;
                # leave self-bootstrap state alone and clear merging flag.
                with self.lock:
                    self.merging = False
                return
            self.group, hist = accepted
            self.logger.info('Merging self-bootstrap into mesh group %s' %
                             getattr(self.group, 'nickname', '?'))
            self._record_group(queues)
            # Partition-recovery cleanup: this is the typical exit path
            # for a successful partition-recovery probe → request_access
            # → full_history round-trip (see
            # doc/architecture/partition-recovery.md §5.5).
            self._partition_recovery_in_progress = None
            self._partition_probe_cooldown.clear()
            self._populate_peers_from_history(queues, list(unioned_peers.values()))
            # We were not a member of the new group; do NOT send a
            # history_diff here. Re-announce on the open channel so a BG
            # admits us through welcoming_committee. The subsequent
            # `full_history` reply will re-enter receive_history with
            # self_bootstrapped = False, and choose_group's normal path
            # will catch_up + send a diff if needed.
            with self.lock:
                self.self_bootstrapped = False
            try:
                self._broadcast_request_access(queues)
            except Full:
                self.logger.error('_merge_to_mesh: Network queue full')
        except Exception as err:
            self.report_exception(err, '_merge_to_mesh')
        finally:
            with self.lock:
                self.merging = False

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

    def _zta_policy(self) -> ZtaPolicy:
        """Resolve the ZTA policy once (configs['zta_policy'] or the on-disk
        zta_policy.cfg.json, else a disabled default). Cached for the process."""
        if self._zta_policy_cache is None:
            cfg = self.configs.get(ZtaPolicy.CONFIG_KEY) if hasattr(self.configs, 'get') else None
            if isinstance(cfg, ZtaPolicy):
                self._zta_policy_cache = cfg
            else:
                try:
                    self._zta_policy_cache = ZtaPolicy.load()
                except Exception:
                    self._zta_policy_cache = ZtaPolicy.defaults()
        return self._zta_policy_cache

    def _zta_verifier(self):
        """Build the configured verifier once (cached)."""
        if self._zta_verifier_cache is None:
            self._zta_verifier_cache = self._zta_policy().create_verifier()
        return self._zta_verifier_cache

    def _zta_admit(self, new_id) -> str:
        """ZTA admission decision for a newly-announced peer.

        Mirrors zta-integration.md §11 / the C gate: returns 'admit' (proceed,
        no cap), 'admit_capped' (DDIL fallback, reputation-capped), or 'reject'
        (do not propose). A no-op ('admit') when the policy is disabled or does
        not require verification at admission.
        """
        policy = self._zta_policy()
        if not (policy.enabled and policy.require_at_admission):
            return 'admit'
        nick = getattr(new_id, 'nickname', '?')
        try:
            cred = new_id.zta_credential or None
        except AttributeError:
            cred = None  # peer from an older/non-ZTA build carries no field
        result = self._zta_verifier().verify_credential(cred)
        status = result.status
        if status is ZtaStatus.VERIFIED:
            return 'admit'
        if status in (ZtaStatus.REJECTED, ZtaStatus.EXPIRED, ZtaStatus.REVOKED):
            self.logger.warning('ZTA: rejecting %s at admission: %s (%s)',
                                 nick, status.value, result.reason)
            _probes.emit('id.welcome', 'zta_rejected', peer_nick=str(nick),
                         zta_status=status.value, reason=result.reason)
            _probes.counter('id.welcome', 'zta_rejected')
            return 'reject'
        # DEFERRED / UNAVAILABLE -> DDIL handling
        if policy.allow_ddil_fallback:
            self.logger.info('ZTA: verification deferred for %s (%s); admitting '
                             'with reputation cap %.2f', nick, status.value,
                             policy.ddil_fallback_reputation_cap)
            _probes.emit('id.welcome', 'zta_deferred', peer_nick=str(nick),
                         zta_status=status.value, reason=result.reason)
            _probes.counter('id.welcome', 'zta_deferred')
            try:
                self._zta_capped.add(new_id.uuid)
            except Exception:
                pass
            return 'admit_capped'
        self.logger.warning('ZTA: verification unavailable for %s (%s) and DDIL '
                            'fallback disabled; rejecting', nick, status.value)
        _probes.emit('id.welcome', 'zta_rejected', peer_nick=str(nick),
                     zta_status=status.value, reason=result.reason)
        _probes.counter('id.welcome', 'zta_rejected')
        return 'reject'

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
                # ZTA credential check at admission (parity with the C gate in
                # handle_welcoming_committee). A forged/unsigned/expired/
                # untrusted-issuer credential is rejected here, before the peer
                # is cached or proposed for the welcoming-committee vote — the
                # peer never enters the trust graph. No-op when the zta_policy
                # is disabled. See doc/architecture/zta-python-parity.md.
                zta_decision = self._zta_admit(new_id)
                if zta_decision == 'reject':
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
                self._spawn(self._vote_collection, args=(queues, id_obj))
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
        # The `amnesia` parameter is currently a structural placeholder.
        # All callers either pass the default (`False`) or are guarded
        # by `if not amnesia` above. The actual amnesia recovery flow
        # — registering caps for late-arriving announces and querying
        # peers directly when announces are lost — lives in
        # `welcoming_committee` (amnesia branch, line ~566) and
        # `handle_confirm_peer` (caps_query path, line ~860). See the
        # late-joiner-caps four-layer defense pattern for context.
        # The parameter is retained so future per-callsite recovery
        # policy can plug in here without changing the signature.
        level = self.peers.mid_level
        if self.group is not None:
            # DEFERRED DESIGN: delaying group-update vs. exposing group
            # key. Current behavior adds the new peer's address and
            # publishes the group BEFORE the peer is fully validated by
            # the welcoming-committee vote. This trades a brief window
            # of premature group-key visibility for simpler ordering —
            # if the peer is later rejected, group_remove cleans up.
            # Tightening this requires a multi-phase admission protocol
            # (provisional vs. confirmed group membership) that both
            # the Python and C implementations would need to agree on.
            self.group.add_address(identity.uuid, identity.address)
            self._record_group(queues)
            # DEFERRED DESIGN: adopting the new peer's group key when
            # they come from an older/larger group (group-merge
            # protocol). Today we always retain our own group identity
            # and add the joiner's address to it. Inverting this would
            # require: (a) a comparable size/age signal on Group, (b)
            # a peer-key handover handshake, (c) C-side parity. Tracked
            # alongside the broader group-merge discussion in
            # divergence.md context (see also the M2 / late-history
            # paths that already merge histories without merging keys).
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
        # Intentional redundancy: these explicit puts back up the fan-put
        # that `_record_peers` performs via `update()`, which has been
        # observed to silently drop entries under main-proc queue
        # contention. The same pattern + a longer 1s timeout appears in
        # `handle_caps_response` (~line 970), with the full rationale.
        # Removing either side risks dropped capability updates downstream.
        queues[CfgIds.main].put(self.peer_capabilities, block=True, timeout=self.q_cadence)
        queues[CfgIds.negotiation].put(self.peer_capabilities, block=True, timeout=self.q_cadence)

    def _process_id(self, blob):
        try:
            for peer in self.peers.all:
                if blob.identity.uuid == peer.uuid or \
                        blob.identity.signature == peer.signature or \
                        blob.identity.encryptor == peer.encryptor:
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
            # DEFERRED DESIGN: should non-border-guards vote on
            # proposals? `welcoming_committee` only emits `propose`
            # when `self.border_guard_mode` is True (line ~587), but
            # any peer in phase 3 that receives the broadcast
            # currently votes. Two viable policies:
            #   A. Current: everyone in phase 3 votes — wider quorum,
            #      but a non-border-guard's view of the candidate is
            #      necessarily shallower (no welcoming-committee
            #      validation context).
            #   B. Border-guards-only: gate this branch on
            #      `if self.border_guard_mode:` to mirror the emit
            #      side. Tighter security model, smaller quorum.
            # Policy B requires C-side parity — the C implementation
            # has no `border_guard_mode` concept yet (greppable: no
            # matches in src/c/autonomous_trust/identity/). Land
            # cross-impl before changing the Python behavior.
            blob = message.obj  # from self.welcoming_committee()
            if isinstance(blob, str):
                blob = Configuration.from_string(blob)
            self._spawn(self._process_id, args=(blob,))
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

    # How often the cap-resync sweep runs, and the max queries it emits per
    # sweep (so a large degraded group can't burst the network queue). The
    # interval is long relative to the q_cadence loop so steady-state cost is
    # negligible; a converged group emits zero queries (every peer has caps).
    _CAPS_RESYNC_INTERVAL_SEC = 20.0
    _CAPS_RESYNC_MAX_PER_SWEEP = 16

    def _periodic_caps_resync(self, queues):
        """Periodic backstop for the late-joiner UDP-loss case.

        The confirm-time directed ``caps_query`` (``handle_confirm_peer``)
        recovers a peer whose ``announce`` was lost — but it is a one-shot.
        If that query or its ``caps_response`` is also dropped (UDP across
        the docker bridge), the peer stays in ``self.peers`` yet absent from
        ``peer_capabilities``, so cap-driven discovery (DataRcvr's stream
        subscription, negotiation participant lookup) never sees it. This
        sweep re-sends ``caps_query`` to every admitted peer that has NO
        capabilities registered, every ``_CAPS_RESYNC_INTERVAL_SEC``, until
        the caps arrive.

        Self-limiting: a peer with any registered cap is skipped, so a
        converged group emits nothing. Idempotent: ``handle_caps_response``
        already per-cap-dedups, so a redundant re-query is harmless. Reuses
        the existing reliable directed query/response — no new wire message,
        so Python/C wire parity is unaffected.
        """
        if self.phase != 3 or self.group is None or self.choosing:
            return
        try:
            with self.lock:
                if self.peers is None:
                    return
                # uuids that already have at least one cap registered
                known = set()
                for _cap, uuids in self.peer_capabilities.items():
                    known.update(str(u) for u in uuids)
                self_uuid = str(self.identity.uuid)
                capless = [
                    peer for peer in self.peers.all
                    if str(peer.uuid) != self_uuid
                    and str(peer.uuid) not in known
                ]
            if not capless:
                return
            sent = 0
            for peer in capless:
                if sent >= self._CAPS_RESYNC_MAX_PER_SWEEP:
                    _probes.counter('peer.set', 'caps_resync_truncated',
                                    str(len(capless) - sent))
                    break
                self._send_caps_query(queues, peer)
                sent += 1
            _probes.counter('peer.set', 'caps_resync_query', str(sent))
            self.logger.debug(
                'Caps resync: re-queried %d cap-less peer(s)' % sent)
        except Exception as err:
            _probes.counter('peer.set', 'caps_resync_exc')
            self.report_exception(err, '_periodic_caps_resync')

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
            # Empty-diff guard: `_history.ingest_branch` does `steps[-1]`
            # without a length check (BUGS.md §P10). Production code path
            # is from `choose_group()` which never sends empty diffs, but
            # an empty payload on the wire reaches here too. Treat empty
            # as a no-op rather than crashing.
            if not steps:
                return True
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

    def handle_tier_update(self, _, message):
        """Apply a reputation-derived trust tier to a peer (or self).

        Local-only IPC from ReputationProcess. Mutates `peer._tier`
        (the runtime, local-view trust attribute) — distinct from
        `peer._rank` (topology, populated from identity.json). The
        next negotiation tier-gate sees the elevated `_tier` via the
        local peer mirror.
        """
        if message.function != IdentityProtocol.tier_update:
            return False
        try:
            payload = from_json_string(message.obj) if isinstance(
                message.obj, (str, bytes)) else message.obj
            if not (isinstance(payload, (list, tuple)) and len(payload) >= 2):
                self.logger.warning('handle_tier_update: bad payload %r' % payload)
                return True
            peer_uuid_str, new_tier = str(payload[0]), int(payload[1])
            target = None
            if str(self.identity.uuid) == peer_uuid_str:
                target = self.identity
            else:
                for peer in self.peers.all:
                    if str(getattr(peer, 'uuid', '')) == peer_uuid_str:
                        target = peer
                        break
            if target is None:
                # Tier update arrived before we have the peer's identity.
                # Drop quietly — the next reputation cycle will retry.
                return True
            old = getattr(target, '_tier', 0)
            if old != new_tier:
                target._tier = new_tier
                self.logger.debug('Tier update for %s: %d -> %d' %
                                  (getattr(target, 'nickname', peer_uuid_str),
                                   old, new_tier))
        except Exception as err:
            self.report_exception(err, 'handle_tier_update')
        return True

    # ------------------------------------------------------------------
    # Partition recovery (doc/architecture/partition-recovery.md).
    # ------------------------------------------------------------------

    _PARTITION_PROBE_COOLDOWN_SEC = 10.0   # per from_addr (§5.2)
    _PARTITION_RESPONSE_COOLDOWN_SEC = 30.0  # per probe-sender uuid (§5.3)
    _PARTITION_RECOVERY_TIMEOUT_SEC = 15.0  # in-progress lockout (§5.4)

    @staticmethod
    def _partition_probe_canonical(group_uuid, group_size):
        """Canonical byte form for probe signature input."""
        return ('%s|%s' % (group_uuid, int(group_size))).encode('utf-8')

    @staticmethod
    def _partition_response_canonical(group_uuid, group_size, in_response_to):
        """Canonical byte form for response signature input."""
        return ('%s|%s|%s' % (group_uuid, int(group_size),
                              in_response_to)).encode('utf-8')

    def _partition_recovery_active(self):
        """True iff a recovery is currently in flight and not yet timed out."""
        if self._partition_recovery_in_progress is None:
            return False
        _, started_at = self._partition_recovery_in_progress
        elapsed = (now() - started_at).total_seconds()
        if elapsed >= self._PARTITION_RECOVERY_TIMEOUT_SEC:
            self._partition_recovery_in_progress = None
            return False
        return True

    def _select_partition_leader(self):
        """Return one of our group members the probe sender can address
        their request_access to.

        Picks the most recently-admitted peer with peer_rank >= ours
        (so newcomers don't get pinned as welcomer for the merging
        peer; the welcoming-committee at the target still runs through
        the normal voting flow). Falls back to self.identity when our
        group is size-1 — the dod_mission coordinator case.
        """
        candidates = []
        our_rank = getattr(self.identity, '_rank', 0)
        for peer in self.peers.all:
            if str(getattr(peer, 'uuid', '')) == str(self.identity.uuid):
                continue
            if getattr(peer, '_rank', 0) < our_rank:
                continue
            candidates.append(peer)
        if not candidates:
            return self.identity
        # newest first — fall back to UUID order for determinism
        candidates.sort(key=lambda p: (getattr(p, '_admitted_at', 0),
                                       str(p.uuid)),
                        reverse=True)
        return candidates[0]

    def handle_partition_signal(self, queues, message):
        """Local-only IPC from NetProcess: a group message arrived from
        ``from_addr`` whose address is not in our group. Emit a
        ``partition_probe`` on unsecured multicast so any responder in
        any group can identify itself, then decide whether to merge.

        Rate-limited at one probe per ``from_addr`` per 10 s.
        Suppressed while bootstrapping (``self.group is None`` or
        ``self.choosing``) and while a recovery is already in flight.
        See doc/architecture/partition-recovery.md §5.2.
        """
        if message.function != IdentityProtocol.partition_signal:
            return False
        if self.group is None or self.choosing:
            return True
        if self._partition_recovery_active():
            return True
        from_addr = message.obj
        if not isinstance(from_addr, str) or not from_addr:
            return True
        cutoff = now()
        last = self._partition_probe_cooldown.get(from_addr)
        if (last is not None
                and (cutoff - last).total_seconds()
                < self._PARTITION_PROBE_COOLDOWN_SEC):
            return True
        self._partition_probe_cooldown[from_addr] = cutoff
        try:
            group_uuid = str(self.group.uuid)
            group_size = len(list(self.group.addresses))
            sig_bytes = self._partition_probe_canonical(group_uuid, group_size)
            signed = self.identity.sign(sig_bytes)
            payload = to_json_string({
                'from_identity': self.identity.publish(),
                'from_address': self.identity.address,
                'my_group_uuid': group_uuid,
                'my_group_size': group_size,
                'signature': signed.signature.decode('ascii'),
            })
            probe = Message(self.name, IdentityProtocol.partition_probe,
                            payload, to_whom=Network.broadcast,
                            encrypt=False)
            queues[CfgIds.network].put(probe, block=True,
                                       timeout=self.q_cadence)
            _probes.counter('peer.set', 'partition_probe_sent')
            self.logger.debug(
                'Partition probe broadcast (group=%s size=%d trigger=%s)' %
                (self.group.nickname, group_size, from_addr))
        except Full:
            _probes.counter('peer.set', 'partition_probe_q_full')
            self.logger.error('handle_partition_signal: Network queue full')
        except Exception as err:
            self.report_exception(err, 'handle_partition_signal')
        return True

    def handle_partition_probe(self, queues, message):
        """Receive an unsecured-multicast probe from a peer that sees us
        as cross-group. Verify the probe signature against the embedded
        sender identity, then reply with a ``partition_response`` so the
        sender can compare group sizes and decide whether to merge.

        Rate-limited at one response per probing peer uuid per 30 s.
        Skipped if we are still bootstrapping (no group yet). See
        doc/architecture/partition-recovery.md §5.3.
        """
        if message.function != IdentityProtocol.partition_probe:
            return False
        if self.group is None:
            return True
        try:
            payload = from_json_string(message.obj) if isinstance(
                message.obj, (str, bytes)) else message.obj
            if not isinstance(payload, dict):
                _probes.counter('peer.set', 'partition_probe_bad_payload')
                return True
            sender_id = payload.get('from_identity')
            group_uuid = payload.get('my_group_uuid')
            group_size = payload.get('my_group_size')
            sig_hex = payload.get('signature')
            if (sender_id is None or group_uuid is None
                    or group_size is None or sig_hex is None):
                _probes.counter('peer.set', 'partition_probe_missing_fields')
                return True
            # sender_id arrived deserialized as an Identity (Configuration
            # auto-deserialization in Message.__init__). Verify signature
            # using the raw-bytes path that message.py:228-243 documents
            # — Identity.verify's two-arg form double-encodes under nacl.
            try:
                sig_raw = HexEncoder.decode(sig_hex.encode('ascii'))
                sender_id.signature.public.verify(
                    self._partition_probe_canonical(group_uuid, group_size),
                    sig_raw)
            except (BadSignatureError, ValueError):
                _probes.counter('peer.set', 'partition_probe_bad_sig')
                return True
            sender_uuid = str(sender_id.uuid)
            # If the sender is already in our group, this is the
            # graceful no-op case (their local view is stale); send a
            # normal group_key_update and bail.
            if any(str(getattr(p, 'uuid', '')) == sender_uuid
                   for p in self.peers.all
                   if str(getattr(p, 'address', '')) in
                   list(self.group.addresses)):
                # Existing code already handles group_key_update; just
                # don't respond with a partition_response.
                _probes.counter('peer.set', 'partition_probe_known_peer')
                return True
            cutoff = now()
            last = self._partition_response_cooldown.get(sender_uuid)
            if (last is not None
                    and (cutoff - last).total_seconds()
                    < self._PARTITION_RESPONSE_COOLDOWN_SEC):
                return True
            self._partition_response_cooldown[sender_uuid] = cutoff
            # Build the response.
            our_group_uuid = str(self.group.uuid)
            our_group_size = len(list(self.group.addresses))
            leader = self._select_partition_leader()
            resp_sig_bytes = self._partition_response_canonical(
                our_group_uuid, our_group_size, sender_uuid)
            resp_signed = self.identity.sign(resp_sig_bytes)
            resp_payload = to_json_string({
                'from_identity': self.identity.publish(),
                'from_address': self.identity.address,
                'in_response_to': sender_uuid,
                'my_group_uuid': our_group_uuid,
                'my_group_size': our_group_size,
                'my_group_leader': str(leader.uuid),
                'my_group_leader_address': leader.address,
                'signature': resp_signed.signature.decode('ascii'),
            })
            reply = Message(self.name, IdentityProtocol.partition_response,
                            resp_payload, to_whom=Network.broadcast,
                            encrypt=False)
            queues[CfgIds.network].put(reply, block=True,
                                       timeout=self.q_cadence)
            _probes.counter('peer.set', 'partition_response_sent')
            self.logger.debug(
                'Partition response broadcast (to=%s our_group=%s/%d)' %
                (sender_uuid, self.group.nickname, our_group_size))
        except Full:
            _probes.counter('peer.set', 'partition_response_q_full')
            self.logger.error('handle_partition_probe: Network queue full')
        except Exception as err:
            self.report_exception(err, 'handle_partition_probe')
        return True

    def handle_partition_response(self, queues, message):
        """Receive a probe response. If the responder's group is larger
        (or equal-size with smaller uuid), initiate a normal
        ``request_access`` toward their group leader's address — the
        existing welcoming-committee flow then drives a ``full_history``
        exchange, which feeds ``_merge_to_mesh`` and adopts the larger
        group. See doc/architecture/partition-recovery.md §5.4.
        """
        if message.function != IdentityProtocol.partition_response:
            return False
        if self.group is None or self._partition_recovery_active():
            return True
        try:
            payload = from_json_string(message.obj) if isinstance(
                message.obj, (str, bytes)) else message.obj
            if not isinstance(payload, dict):
                return True
            sender_id = payload.get('from_identity')
            in_response_to = payload.get('in_response_to')
            their_group_uuid = payload.get('my_group_uuid')
            their_group_size = payload.get('my_group_size')
            leader_uuid = payload.get('my_group_leader')
            leader_address = payload.get('my_group_leader_address')
            sig_hex = payload.get('signature')
            if (sender_id is None or in_response_to is None
                    or their_group_uuid is None or their_group_size is None
                    or leader_address is None or sig_hex is None):
                _probes.counter('peer.set', 'partition_response_missing_fields')
                return True
            if in_response_to != str(self.identity.uuid):
                # Response to someone else's probe — multicast bleed-through.
                return True
            try:
                sig_raw = HexEncoder.decode(sig_hex.encode('ascii'))
                sender_id.signature.public.verify(
                    self._partition_response_canonical(
                        their_group_uuid, their_group_size, in_response_to),
                    sig_raw)
            except (BadSignatureError, ValueError):
                _probes.counter('peer.set', 'partition_response_bad_sig')
                return True
            our_size = len(list(self.group.addresses))
            theirs = int(their_group_size)
            adopt = (theirs > our_size
                     or (theirs == our_size
                         and str(their_group_uuid) < str(self.group.uuid)))
            if not adopt:
                # They will reach the symmetric conclusion when they
                # receive our probe — initiate from their side. No-op.
                _probes.counter('peer.set', 'partition_response_we_win')
                return True
            self._partition_recovery_in_progress = (str(their_group_uuid),
                                                    now())
            # Re-broadcast request_access on the open channel. This is the
            # same call announce_identity uses; the welcoming committee at
            # the responder's group will admit us through the standard
            # POA-voting flow, and the resulting full_history will drive
            # _merge_to_mesh to adopt their group.
            self._broadcast_request_access(queues)
            _probes.counter('peer.set', 'partition_recovery_initiated')
            self.logger.info(
                'Partition recovery: adopting group %s (size=%d > our %d), '
                'sent request_access toward leader %s@%s' %
                (their_group_uuid, theirs, our_size,
                 leader_uuid, leader_address))
        except Full:
            _probes.counter('peer.set', 'partition_request_access_q_full')
            self.logger.error('handle_partition_response: Network queue full')
        except Exception as err:
            self.report_exception(err, 'handle_partition_response')
        return True

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
            # Wire form arrives as a serialized string; parse it back to a
            # Group object. handle_confirm_peer (idprocess.py:742-743) does
            # the same — handle_group_update was missing it (BUGS.md §P11).
            # Without this guard, accessing `theirs.uuid` below raises
            # AttributeError on any over-the-wire delivery.
            if isinstance(group, str):
                if not group:
                    return True  # empty payload — no-op
                group = Configuration.from_string(group)
            mine, theirs = self.group, group
            if mine is None or theirs is None:
                return True
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
                # Partition recovery completes here whenever the adopted
                # group matches an in-flight recovery, OR opportunistically
                # whenever any merge lands (we don't insist on UUID match —
                # an unrelated merge that absorbs the same addresses is
                # also a resolution).
                self._partition_recovery_in_progress = None
                self._partition_probe_cooldown.clear()
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
        # Seed-assisted dual membership: a gateway adopts its child
        # cohort(s) from group_child_*.cfg.json before grouping. No-op
        # on leaf nodes. See doc/architecture/gateway-reputation-tree.md.
        self._load_child_groups(queues)
        if not self.choosing:
            # initial run, may be called again
            self._spawn(self.choose_group, args=(queues,))
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

                # Periodic late-joiner cap-loss backstop. Interval-gated so
                # the fast drain loop doesn't run it every iteration; a
                # converged group emits no queries. See
                # _periodic_caps_resync / feedback_late_joiner_caps.
                tick = now()
                if (self._last_caps_resync is None
                        or (tick - self._last_caps_resync).total_seconds()
                        >= self._CAPS_RESYNC_INTERVAL_SEC):
                    self._last_caps_resync = tick
                    self._periodic_caps_resync(queues)

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
        # Final flush on graceful shutdown — ensures the most-recent
        # peers + capabilities + group snapshots survive a SIGTERM/quit.
        # Belt-and-suspenders on top of the per-mutation saves in
        # _record_peers / _record_group.
        try:
            self._record_group(queues)
            self._record_peers(queues)
            self.logger.debug('Final identity-state flush on shutdown')
        except Exception as err:
            self.logger.warning('Final identity-state flush failed: %s' % err)
