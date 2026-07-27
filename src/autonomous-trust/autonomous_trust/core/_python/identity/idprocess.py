# ******************
#  Copyright 2023 TekFive, Inc., Sean M. Brennan, and contributors
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

import base64
import hashlib
import hmac
import os
import sys
import time
import uuid
from datetime import datetime
from queue import Empty, Full
import threading
from types import SimpleNamespace
from typing import Optional, Union

from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
from nacl.signing import SignedMessage

from . import Peers
from .identity import Identity, public_identity_to_canonical, public_identity_from_canonical
from .group import Group, ChildGroupSet
from .history.history import IdentityHistory
from ..algorithms.agreement import AgreementProof
from ..algorithms.impl import AgreementImpl
from ..capabilities import PeerCapabilities
import json
from ..config import Configuration, to_json_string, from_json_string, names
from ..config.configuration import ConfigJSONEncoder, atomic_write
from ..processes import Process, ProcMeta
from ..network import Message, Network
from .history import IdentityByWork, IdentityByStake, IdentityByAuthority
from .history import IdentityObj
from .protocol import IdentityProtocol
from .zta import ZtaPolicy, ZtaStatus, ZTA_CRED_MAX
from ..structures.dag import LinkedStep
from ..system import CfgIds, encoding, PackageHash, now, _env_bool
from .. import _probes


VoteData = tuple[IdentityObj, AgreementProof, tuple[bytes, bytes]]

GroupHistory = tuple[Group, IdentityHistory]

GroupTree = tuple[Group, list[LinkedStep]]


# Persistent-cohort gate: peers below this trust tier are excluded from
# the peers.cfg.json / peer-capabilities.cfg.json snapshots. Mirrors
# REPUTATION_PERSIST_THRESHOLD (rep > 0.5) via TIER_FLOORS: tier 1 floor
# is 0.50, so any peer that's been scored above 0.5 has _tier >= 1.
PERSIST_TIER_FLOOR = 1


# Fan-out / cycle backstop for the recursive subtree-roster aggregation. Far
# above any real cohort tree; bounds a malformed or looping topology so the
# query returns a partial result rather than hanging.
SUBTREE_ROSTER_MAX_NODES = 4096


def aggregate_subtree_roster(top_gateway_uuid, fetch, max_nodes=SUBTREE_ROSTER_MAX_NODES):
    """Breadth-first flatten of a gateway's subtree into a deduped, sorted
    member roster — the requestor side of the recursive enumeration.

    ``fetch(gateway_uuid) -> {'members': [...], 'child_gateways': [uuid_str],
    'private': bool}`` is the per-gateway query: a network round-trip
    (roster_req / roster_resp) in production, an injected stub in tests. Each
    visited gateway contributes its local members and names the child gateways
    to recurse into; this walks the tree, dedups members by uuid, and sorts by
    uuid so the result is canonical across implementations.

    A gateway that has opted out of disclosure (AT_ROSTER_PRIVATE) replies
    with ``private: True`` and no members/children: it is recorded as an
    intentional, opaque boundary, NOT as a failure — the enumeration simply
    does not see behind it. A private TOP gateway therefore yields an empty
    roster that is nonetheless ``complete`` (the network chose not to be
    mapped), which the caller distinguishes from an unreachable node via the
    boundary list.

    Cycle- and fan-out-guarded. Returns ``(members, complete,
    private_boundaries)`` where ``complete`` is False only if a fetch
    failed/returned nothing or the node cap tripped (unreachability, NOT
    privacy), and ``private_boundaries`` lists the gateway uuids that opted
    out. A partial roster is returned rather than hanging or raising."""
    by_uuid: dict[str, dict] = {}
    private_boundaries: list[str] = []
    complete = True
    queued = [str(top_gateway_uuid)]
    visited: set[str] = set()
    while queued:
        if len(visited) >= max_nodes:
            complete = False
            break
        gateway = queued.pop(0)
        if gateway in visited:
            continue
        visited.add(gateway)
        try:
            resp = fetch(gateway)
        except Exception:
            complete = False
            continue
        if not resp:
            complete = False
            continue
        if resp.get('private'):
            # Intentional opaque boundary — succeeded, but discloses nothing.
            private_boundaries.append(gateway)
            continue
        for member in resp.get('members') or []:
            key = str(member.get('uuid')) if isinstance(member, dict) else None
            if key and key not in by_uuid:
                by_uuid[key] = member
        for child in resp.get('child_gateways') or []:
            child = str(child)
            if child not in visited and child not in queued:
                queued.append(child)
    members = [by_uuid[k] for k in sorted(by_uuid)]
    return members, complete, private_boundaries


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
        # Two-phase admission (ISSUES.md §3.1-a). A member receiving a
        # `confirm` broadcast holds the peer PROVISIONAL — known in
        # self.peers/history for reputation/routing, but the group key is NOT
        # propagated to it (no group.add_address + _update_group) — until
        # `_admission_quorum` DISTINCT border-guards have independently
        # confirmed the admission, at which point it is promoted to CONFIRMED.
        # The default quorum of 1 promotes on the first confirm, reproducing
        # the historical single-welcomer behavior exactly (no regression); a
        # deployment sets it higher for corroborated key handover. Local policy
        # only — no wire field. `_provisional_confirmations` maps a peer uuid
        # (str) to the set of confirmer uuids (str) seen so far.
        self._admission_quorum = 1
        self._provisional_confirmations: dict[str, set] = {}
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
        self._zta_operator_verifier_cache = None  # operator-anchor verifier (D8/Q9)
        self._zta_capped: set = set()  # uuids admitted via DDIL fallback (rep-capped)
        self._operator_verified: set = set()  # uuids whose operator credential verified
        self._operator_session = None  # live OperatorSession, attached in P-L3
        # Attended-now pulls awaiting the main loop's session answer:
        # nonce -> (requestor Identity, req_proc, deadline). This process runs
        # in its own subprocess and cannot see the console's OperatorSession, so
        # each pull costs one local round trip to the main loop (which shares
        # the console's address space). Nothing is cached, so nothing goes
        # stale; a pull the main loop never answers ages out and is answered
        # honestly as not-attended. See doc/architecture/operator-attended.md.
        self._attest_pending: dict[str, tuple] = {}
        # Pulls we SENT and have not yet resolved: nonce -> (peer_uuid,
        # deadline). Keyed by nonce because the nonce is the only thing that
        # makes a returned stamp attributable to a request we actually made.
        self._attest_sent: dict[str, tuple] = {}
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
        # Subtree member-roster recursion targets: child-group-uuid-str ->
        # child-gateway-node-uuid-str. The values are the gateways a full
        # subtree-roster query recurses into (see handle_roster_request /
        # aggregate_subtree_roster). Empty on a leaf or a gateway with no
        # deeper gateways, in which case a roster query is purely local and
        # behaviour is identical to today. Seeded (group_child_*.cfg.json may
        # name a gateway) or supplied by a test/adapter fixture.
        self.child_gateways: dict[str, str] = {}
        # Roster-privacy opt-out (AT config option AT_ROSTER_PRIVATE). When
        # set, this node refuses to disclose its subtree to a roster query:
        # handle_roster_request replies with a `private` marker carrying no
        # members and no child gateways, so the enumeration stops at this
        # node as an intentional, opaque boundary (distinct from an
        # unreachable/timed-out node). Applies uniformly to every requestor,
        # including the node's own app-issued enumeration — so a private
        # TOP gateway yields an empty roster, which is how a fully private
        # network/subtree opts out of being mapped at all. Enforced at the
        # DISCLOSURE boundary only; enumerate_local_members stays pure (a
        # node always knows its own members locally). Per-node granularity
        # (one node = one process); C reads the same env var for parity.
        # See doc/architecture/gateway-reputation-tree.md.
        self.roster_private: bool = _env_bool('AT_ROSTER_PRIVATE')
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
        self.protocol.register_handler(IdentityProtocol.id_query, self.handle_identity_query)
        self.protocol.register_handler(IdentityProtocol.id_response, self.handle_identity_response)
        self.protocol.register_handler(IdentityProtocol.roster_req, self.handle_roster_request)
        self.protocol.register_handler(IdentityProtocol.attest_req, self.handle_attest_request)
        self.protocol.register_handler(IdentityProtocol.attest_resp, self.handle_attest_response)
        self.protocol.register_handler(IdentityProtocol.attest_trigger, self.handle_attest_trigger)
        self.protocol.register_handler(IdentityProtocol.operator_state_resp,
                                       self.handle_operator_state_response)
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
                    # Atomic write: load_configs may read this snapshot
                    # concurrently; a raw open(...,'w') exposes an empty window.
                    with atomic_write(filename) as cfg:
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

    # --- Subtree member-roster enumeration -----------------------------------

    def enumerate_local_members(self):
        """The member identities this node holds directly: itself, its primary
        group, and every child group it gateways (from each group's address
        map). Returns a list of ``{'uuid', 'nickname', 'address'}`` dicts,
        deduped by uuid and sorted by uuid. Pure and local — no network, no
        reputation. A leaf node returns itself plus its primary-group members;
        a gateway additionally includes each child group's members. This is the
        per-node contribution the recursive aggregation composes across the
        cohort tree. See doc/architecture/gateway-reputation-tree.md."""
        by_uuid: dict[str, dict] = {}

        def add(uuid, address=None, nickname=None):
            key = str(uuid)
            if not key:
                return
            entry = by_uuid.get(key)
            if entry is None:
                by_uuid[key] = {'uuid': key, 'nickname': nickname, 'address': address}
                return
            if nickname and not entry.get('nickname'):
                entry['nickname'] = nickname
            if address and not entry.get('address'):
                entry['address'] = address

        if self.identity is not None:
            add(self.identity.uuid, getattr(self.identity, 'address', None),
                getattr(self.identity, 'nickname', None))
        groups = [self.group] + list(self.child_groups.values())
        for grp in groups:
            if grp is None:
                continue
            amap = getattr(grp, '_address_map', None) or {}
            try:
                items = list(amap.items())
            except AttributeError:
                items = []
            for uuid, address in items:
                nick = None
                try:
                    ident = self.peers.find_by_uuid(uuid) if self.peers else None
                    nick = getattr(ident, 'nickname', None) if ident else None
                except Exception:
                    nick = None
                add(uuid, address, nick)
        return [by_uuid[k] for k in sorted(by_uuid)]

    def _member_rank(self, uuid):
        """A peer's rank for child-gateway discovery: operational
        ``effective_rank`` if present, else the static ``_rank``, else 0
        (unknown). Mirrors the welcomer-selection rank read (idprocess ~2082)."""
        try:
            peer = self.peers.find_by_uuid(uuid) if self.peers else None
        except Exception:
            peer = None
        if peer is None:
            return 0
        r = getattr(peer, 'effective_rank', None)
        if r is None:
            r = getattr(peer, '_rank', 0)
        return r or 0

    def _discover_child_gateway(self, group, self_uuid):
        """The recursion target for one child group = its highest-rank member
        (excluding self), ties broken by the lexicographically greater uuid so
        the choice is deterministic and identical in C. Returns a uuid string
        or None (empty group / self only)."""
        amap = getattr(group, '_address_map', None) or {}
        best, best_key = None, None
        for uuid in amap:
            u = str(uuid)
            if self_uuid is not None and u == self_uuid:
                continue
            key = (self._member_rank(u), u)
            if best_key is None or key > best_key:
                best, best_key = u, key
        return best

    def _child_gateway_uuids(self):
        """Node uuids of the child gateways a full-subtree roster recurses into
        — one per gatewayed child group, **discovered by rank** (the highest-rank
        member of the group, excluding self; see :meth:`_discover_child_gateway`).
        An explicit ``self.child_gateways[cg]`` entry overrides discovery (tests /
        pinned topologies). Deduped, order-stable. Empty when this node gateways
        no deeper gateways — a roster query is then purely local. See
        doc/architecture/gateway-reputation-tree.md."""
        self_uuid = str(self.identity.uuid) if self.identity is not None else None
        out = []
        for cg_uuid, group in self.child_groups.items():
            explicit = self.child_gateways.get(cg_uuid)
            gw = str(explicit) if explicit else self._discover_child_gateway(group, self_uuid)
            if gw and gw not in out:
                out.append(gw)
        return out

    def _roster_response(self):
        """This node's roster-query answer as a plain dict: ``{'members',
        'child_gateways', 'private'}``. A node that opted out
        (``self.roster_private``, AT config ``AT_ROSTER_PRIVATE``) discloses
        nothing. Shared by :meth:`handle_roster_request` (the wire path) and
        the requestor-side aggregation's fetch (tests / conformance), so both
        see byte-identical content. See gateway-reputation-tree.md."""
        if self.roster_private:
            return {'members': [], 'child_gateways': [], 'private': True}
        return {'members': self.enumerate_local_members(),
                'child_gateways': self._child_gateway_uuids(),
                'private': False}

    def handle_roster_request(self, queues, message):
        """Answer a subtree-roster query with this node's LOCAL members and the
        child gateways to recurse into. The requestor performs the breadth-first
        aggregation across the tree (see :func:`aggregate_subtree_roster`), so
        this handler never blocks awaiting child responses — matching the async,
        no-blocking-handler model of the rest of the protocol.

        A node that has opted out of disclosure (``self.roster_private``,
        AT config option ``AT_ROSTER_PRIVATE``) replies with a ``private``
        marker carrying NO members and NO child gateways: the enumeration
        stops here as an intentional, opaque boundary. The requestor
        records the boundary (see :func:`aggregate_subtree_roster`) rather
        than treating it as an unreachable/incomplete node.

        The reply is addressed to the process the requestor named in
        ``requesting_process`` (rep_req's convention), defaulting to the main
        loop. That default is the answer's real home: inbound messages route by
        ``Message.process`` alone, and the breadth-first aggregation that
        consumes a roster_resp lives in the main loop
        (AutonomousTrust._consume_roster_resp), not in this process. Replying
        to our own process name would deliver every answer to the requestor's
        identity process, which has no handler for it — the walk would then
        never complete on a real multiprocess node while still looking correct
        in a single-process test."""
        if message.function != IdentityProtocol.roster_req:
            return False
        try:
            requestor = message.from_whom
            payload = message.obj
            if isinstance(payload, str) and payload:
                try:
                    payload = from_json_string(payload)
                except Exception:
                    payload = {}
            req_proc = (payload.get('requesting_process')
                        if isinstance(payload, dict) else None) or CfgIds.main
            out = to_json_string(self._roster_response())
            reply = Message(req_proc, IdentityProtocol.roster_resp, out,
                            to_whom=requestor if requestor is not None
                            else Network.broadcast,
                            from_whom=self.identity, encrypt=False)
            queues[CfgIds.network].put(reply, block=True, timeout=self.q_cadence)
        except Full:
            self.logger.error('handle_roster_request: Network queue full')
        except Exception as err:
            self.report_exception(err, 'handle_roster_request')
        return True

    # --- Operator-attended pull, responder side (ethne D8/Q9) ----------------

    #: how long a pull waits for the main loop's session answer before it is
    #: answered honestly as not-attended. Short: the round trip is two local
    #: queue hops, and a puller waiting on attendance wants a prompt "no" far
    #: more than a slow "yes".
    _ATTEST_ROUND_TRIP_SEC = 2.0

    def handle_attest_request(self, queues, message):
        """Take in an attended-now pull and start the local session round trip.

        Cannot answer inline: the live OperatorSession belongs to the console
        app's address space, which the node's MAIN LOOP shares but this
        subprocess does not. So record the pull and ask the main loop
        (operator_state_query); handle_operator_state_response finishes it.
        Returns without blocking, matching handle_roster_request's contract —
        no handler in this protocol may wait on another process.

        Where an in-process session HAS been attached (tests, single-process
        embeds) the answer still goes through the same path, so both
        deployments exercise one code path."""
        if message.function != IdentityProtocol.attest_req:
            return False
        try:
            payload = message.obj
            if isinstance(payload, str):
                payload = from_json_string(payload)
            if not isinstance(payload, dict):
                payload = {}
            nonce = payload.get('nonce')
            if not nonce:
                # Unnonced pulls are refused, not answered: an attestation with
                # nothing binding it to a request is replayable forever, which
                # is precisely what attended-NOW must not permit.
                self.logger.warning('handle_attest_request: missing nonce')
                return True
            deadline = self._now_epoch() + self._ATTEST_ROUND_TRIP_SEC
            self._attest_pending[str(nonce)] = (message.from_whom, deadline)
            query = Message(CfgIds.main, IdentityProtocol.operator_state_req,
                            '', from_whom=self.identity)
            queues[CfgIds.main].put(query, block=True, timeout=self.q_cadence)
        except Full:
            # The main loop is backlogged; the pull ages out on the next tick
            # and gets answered as not-attended rather than left hanging.
            self.logger.error('handle_attest_request: main queue full')
        except Exception as err:
            self.report_exception(err, 'handle_attest_request')
        return True

    def _attest_payload(self, nonce, attested_at):
        """The attestation to return for one pull: the same shape the admission
        path carries (so the receiver can re-verify the real operator
        credential), with attended-now overridden by what the session just said
        and the requestor's nonce echoed back to bind it to this request."""
        payload = dict(self._operator_attestation())
        payload['nonce'] = str(nonce)
        if attested_at:
            payload['operator_attested_at'] = float(attested_at)
        else:
            # Explicit 0 rather than an omitted key: "asked, and no human is
            # attending" is a real answer and must not read as "didn't say".
            payload['operator_attested_at'] = 0.0
        return payload

    def _answer_attest_pull(self, queues, nonce, requestor, attested_at):
        """Send one attest_resp back to the puller.

        Addressed to the puller's IDENTITY process (self.name, as
        handle_roster_request does), because that is the only process holding
        the operator trust anchor the answer has to be checked against — an
        unverified attestation is not evidence of anything."""
        try:
            reply = Message(self.name, IdentityProtocol.attest_resp,
                            to_json_string(self._attest_payload(nonce,
                                                                attested_at)),
                            to_whom=requestor if requestor is not None
                            else Network.broadcast,
                            from_whom=self.identity, encrypt=False)
            queues[CfgIds.network].put(reply, block=True, timeout=self.q_cadence)
        except Full:
            self.logger.error('_answer_attest_pull: Network queue full')
        except Exception as err:
            self.report_exception(err, '_answer_attest_pull')

    def handle_operator_state_response(self, queues, message):
        """The main loop reported the console session state — answer every pull
        waiting on it.

        One answer serves all pulls in flight: they all asked the same question
        of the same session at effectively the same instant. `have_session`
        False (a drone, or no console attached) is a legitimate answer meaning
        not-attended, not an error."""
        if message.function != IdentityProtocol.operator_state_resp:
            return False
        try:
            payload = message.obj
            if isinstance(payload, str):
                payload = from_json_string(payload)
            if not isinstance(payload, dict):
                payload = {}
            attended = bool(payload.get('attended'))
            epoch = float(payload.get('epoch') or 0.0) if attended else 0.0
            pending, self._attest_pending = self._attest_pending, {}
            for nonce, (requestor, _deadline) in pending.items():
                self._answer_attest_pull(queues, nonce, requestor, epoch)
        except Exception as err:
            self.report_exception(err, 'handle_operator_state_response')
        return True

    def _expire_attest_pending(self, queues):
        """Answer pulls the main loop never got to, as not-attended.

        The roster convention applied to attendance: report a bounded, honest
        partial rather than hang. Silence is what a puller cannot act on — a
        node whose console never answers is, for the purpose of the guardian
        edge, unattended."""
        if not self._attest_pending:
            return
        tick = self._now_epoch()
        expired = [nonce for nonce, (_r, deadline)
                   in self._attest_pending.items() if deadline <= tick]
        for nonce in expired:
            requestor, _deadline = self._attest_pending.pop(nonce)
            self.logger.debug('attest pull %s timed out; answering unattended'
                              % nonce)
            self._answer_attest_pull(queues, nonce, requestor, 0.0)

    # --- Operator-attended pull, requestor side (ethne D8/Q9) ----------------

    #: how long a pull we SENT stays open before the consumer is told
    #: not-attended. Generous next to the responder's own round trip: this
    #: spans the network. An unreachable node is unattended for the guardian
    #: edge's purposes, so silence still resolves to an answer.
    _ATTEST_REPLY_WAIT_SEC = 10.0

    #: how far a peer's claimed stamp may sit from our clock and still be
    #: believed. The nonce already stops replay of an old attestation; this
    #: catches a peer asserting attendance at an implausible time (a
    #: far-future stamp meant to stay "fresh", or an ancient one).
    _ATTEST_WINDOW_SEC = 120.0

    def handle_attest_trigger(self, queues, message):
        """A consumer asked us to pull one peer's attended-now state.

        The pull lives here rather than in the main loop because the answer is
        only worth having once the operator credential inside it has been
        re-verified against the operator trust anchor — and this process owns
        that anchor (see _is_operator_credential, shared with admission).

        Local-only verb: never leaves this node. Mints the nonce that binds
        the peer's answer to this request."""
        if message.function != IdentityProtocol.attest_trigger:
            return False
        try:
            payload = message.obj
            if isinstance(payload, str):
                payload = from_json_string(payload)
            if not isinstance(payload, dict):
                payload = {}
            target_uuid = payload.get('target')
            if not target_uuid:
                return True
            target = None
            try:
                target = self.peers.find_by_uuid(str(target_uuid)) if self.peers else None
            except Exception:
                target = None
            if target is None:
                # Unroutable peer: answer the consumer now rather than let it
                # wait on a pull that can never be sent.
                self._report_attestation(queues, str(target_uuid), 0.0, False)
                return True
            nonce = uuid.uuid4().hex
            req = Message(self.name, IdentityProtocol.attest_req,
                          to_json_string({'nonce': nonce}),
                          to_whom=target, from_whom=self.identity,
                          encrypt=False)
            queues[CfgIds.network].put(req, block=True, timeout=self.q_cadence)
            self._attest_sent[nonce] = (
                str(target.uuid),
                self._now_epoch() + self._ATTEST_REPLY_WAIT_SEC)
        except Full:
            self.logger.error('handle_attest_trigger: Network queue full')
        except Exception as err:
            self.report_exception(err, 'handle_attest_trigger')
        return True

    def _report_attestation(self, queues, peer_uuid, attested_at, verified):
        """Hand a finished pull back to the main loop for consumers to read
        (AutonomousTrust.peer_attestations, which is what ethne's guardian
        edge reads). Local-only; carries the VERIFIED verdict, never the
        peer's assertion."""
        try:
            out = Message(CfgIds.main, IdentityProtocol.attest_resp,
                          to_json_string({'peer': str(peer_uuid),
                                          'operator_attested_at': float(attested_at or 0.0),
                                          'operator_verified': bool(verified)}),
                          from_whom=self.identity)
            queues[CfgIds.main].put(out, block=True, timeout=self.q_cadence)
        except Full:
            self.logger.error('_report_attestation: main queue full')
        except Exception as err:
            self.report_exception(err, '_report_attestation')

    def handle_attest_response(self, queues, message):
        """Verify one peer's attended-now answer and record it.

        Nothing the peer asserts is taken at face value. Three independent
        checks must pass before a stamp counts:

        1. the nonce must be one WE minted and have not yet retired — this is
           what makes the signal attended-*now* instead of a recording that
           can be replayed indefinitely;
        2. the operator credential in the payload must chain-verify against the
           distinct operator anchor, with its hash recomputed from the actual
           bytes (:meth:`_is_operator_credential`, the same gate admission
           uses) — a node cannot talk its way into operator class;
        3. the stamp must fall inside a bounded window around our clock.

        A failure of any check records not-attended rather than raising: the
        guardian edge needs a decision, and "unverified" and "unattended" are
        the same answer to it."""
        if message.function != IdentityProtocol.attest_resp:
            return False
        try:
            payload = message.obj
            if isinstance(payload, str):
                payload = from_json_string(payload)
            if not isinstance(payload, dict):
                payload = {}
            nonce = payload.get('nonce')
            sent = self._attest_sent.pop(str(nonce), None) if nonce else None
            if sent is None:
                # Unsolicited, replayed, or an answer to a pull already retired.
                self.logger.warning('handle_attest_response: unknown nonce %r'
                                    % nonce)
                return True
            peer_uuid, _deadline = sent
            responder_uuid = str(getattr(message.from_whom, 'uuid', '') or '')
            if responder_uuid and responder_uuid != peer_uuid:
                # Right nonce, wrong node — someone else answering for the
                # peer we asked.
                self.logger.warning('handle_attest_response: nonce %s answered '
                                    'by %s, expected %s'
                                    % (nonce, responder_uuid, peer_uuid))
                self._report_attestation(queues, peer_uuid, 0.0, False)
                return True
            claimed = 0.0
            try:
                claimed = float(payload.get('operator_attested_at') or 0.0)
            except (TypeError, ValueError):
                claimed = 0.0
            # Re-verify the credential against the operator anchor. Decode the
            # attestation onto a scratch identity so the existing gate sees the
            # same shape it sees at admission.
            scratch = SimpleNamespace(zta_issuer='', zta_credential=b'',
                                      zta_credential_hash=b'',
                                      operator_bound=False,
                                      operator_attested_at=0.0)
            self._apply_operator_attestation(scratch, payload)
            cred = getattr(scratch, 'zta_credential', b'') or b''
            verified = self._is_operator_credential(scratch, cred)
            tick = self._now_epoch()
            in_window = bool(claimed) and abs(tick - claimed) <= self._ATTEST_WINDOW_SEC
            if claimed and not in_window:
                self.logger.warning('handle_attest_response: stamp %r outside '
                                    'acceptance window (now %r)' % (claimed, tick))
            attested = claimed if (verified and in_window) else 0.0
            self._store_peer_attestation(peer_uuid, attested, verified)
            self._report_attestation(queues, peer_uuid, attested, verified)
        except Exception as err:
            self.report_exception(err, 'handle_attest_response')
        return True

    def _store_peer_attestation(self, peer_uuid, attested_at, verified):
        """Write the verified result onto our stored peer identity, so a
        consumer reading the local peer mirror sees a live value instead of
        the stamp captured once at admission (the gap this closes)."""
        try:
            peer = self.peers.find_by_uuid(str(peer_uuid)) if self.peers else None
        except Exception:
            peer = None
        if peer is None:
            return
        try:
            peer.operator_attested_at = float(attested_at or 0.0)
        except Exception:
            pass
        if verified:
            # Durable half: a peer that just proved an operator credential IS
            # operator-bound, even if nobody is at the console right now.
            self._mark_operator_bound(peer, True)

    def _expire_attest_sent(self, queues):
        """Resolve pulls the peer never answered as not-attended, so a
        consumer is never left waiting on a node that has gone quiet."""
        if not self._attest_sent:
            return
        tick = self._now_epoch()
        expired = [nonce for nonce, (_u, deadline)
                   in self._attest_sent.items() if deadline <= tick]
        for nonce in expired:
            peer_uuid, _deadline = self._attest_sent.pop(nonce)
            self.logger.debug('attest pull to %s unanswered; reporting '
                              'unattended' % peer_uuid)
            self._report_attestation(queues, peer_uuid, 0.0, False)

    def _record_peers(self, queues):
        self.logger.debug('Add peers')
        self._remember_activity(queues, CfgIds.peers, self.peers)
        self._remember_activity(queues, CfgIds.capabilities, self.peer_capabilities)
        # Reliable re-put of self.peers to the main proc. _remember_activity's
        # update() fan-put uses the q_cadence (10 ms) timeout, which silently
        # DROPS under main-proc queue contention — e.g. the dod_mission
        # coordinator, whose main loop is processing thousands of rep_resp
        # messages, so the Peers broadcast never lands and self.peers stays
        # stale (peers.all=1 while group.addresses grows). handle_caps_response
        # already does exactly this for peer_capabilities (see ~line 1336, the
        # same drop); self.peers had no equivalent. 1 s timeout rides through
        # bursty contention; bounded, so it can't deadlock. Without this the
        # coordinator can never name consensus reputations -> dashboard stuck
        # "forming…". See dod-coordinator-partition-nonconvergence.md (layer 3).
        if CfgIds.main in queues:
            try:
                queues[CfgIds.main].put(self.peers, block=True, timeout=1.0)
                _probes.counter('peer.set', 'peers_explicit_main_put')
            except Full:
                _probes.counter('peer.set', 'peers_explicit_main_full')

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

    def set_operator_session(self, session):
        """Attach a live OperatorSession so (re)announces can stamp attended-now
        (ethne D8/Q9). In-process seam: usable when the session and the identity
        process share an address space (tests, single-process embeds).

        The multiprocess node runs this process in its own subprocess where the
        console's session object is not reachable. That case is served the other
        way round: an inbound attest_req triggers a local round trip to the main
        loop, which DOES share the console's address space (see
        handle_attest_request / AutonomousTrust.set_operator_session). The
        DURABLE operator_bound signal crosses the boundary on its own, via the
        persisted identity."""
        self._operator_session = session

    def _refresh_operator_attestation(self):
        """Re-stamp self.identity.operator_attested_at from the live operator
        session state just before a (re)announce (ethne D8/Q9 attended-now).

        No-op unless an OperatorSession has been attached (set_operator_session).
        When one is present and attended the node stamps the current epoch time;
        otherwise it clears the stamp to 0 so a locked/absent session reads as
        not-attended. operator_bound (durable) is set once at operator activation
        (operator/activate.bind_piv_credential) and is not touched here."""
        session = getattr(self, '_operator_session', None)
        if session is None:
            return
        try:
            from ..operator.session import is_attended  # operator pkg is optional
            fresh = is_attended(session)
            self.identity.operator_attested_at = self._now_epoch() if fresh else 0.0
        except Exception:  # never let attestation refresh break an announce
            self.logger.debug('operator attestation refresh skipped', exc_info=True)

    def _now_epoch(self):
        """Wall-clock epoch seconds; a seam so P-L3 unit tests can inject a
        deterministic clock."""
        return time.time()

    def _operator_attestation(self):
        """Build the operator-attended attestation carried in the signed
        request_access DATA payload (ethne guardian edge, D8/Q9). It reuses
        the node's own ZTA binding so the welcoming committee can verify the
        operator credential and confirm the claim (see welcoming_committee /
        _zta_admit). Emitted as a dict of only the non-default fields so a node
        with no operator binding contributes an empty dict (backward-compatible
        with the 2-element payload). Bytes are base64 (standard, no newline),
        matching public_identity_to_canonical and the C payload encoder.

        NOTE: this reads self.identity's CURRENT fields. operator_attested_at
        freshness is (re)stamped by _refresh_operator_attestation (P-L3) before
        this is called; here in P-L1 it reflects whatever activation set."""
        me = self.identity
        att = {}
        if getattr(me, 'operator_bound', False):
            att['operator_bound'] = True
        attested = float(getattr(me, 'operator_attested_at', 0.0) or 0.0)
        if attested:
            att['operator_attested_at'] = attested
        issuer = getattr(me, 'zta_issuer', '') or ''
        if issuer:
            att['zta_issuer'] = issuer
        cred_hash = getattr(me, 'zta_credential_hash', b'') or b''
        if cred_hash:
            att['zta_credential_hash'] = base64.b64encode(bytes(cred_hash)).decode('ascii')
        cred = getattr(me, 'zta_credential', b'') or b''
        if cred:
            att['zta_credential'] = base64.b64encode(bytes(cred)).decode('ascii')
        return att

    @staticmethod
    def _apply_operator_attestation(new_id, att):
        """Decode the request_access attestation dict onto a newly-announced
        peer identity (inverse of _operator_attestation). Copies the ZTA
        binding (so _zta_admit can verify a wire-delivered credential) and the
        advertised operator claim. The advertised operator_bound is NOT trusted
        here — _zta_admit overwrites it with the verified result (P-L2).
        Tolerant of missing/malformed keys (defaults false/0/empty)."""
        if not isinstance(att, dict):
            return
        try:
            issuer = att.get('zta_issuer', '') or ''
            if issuer:
                new_id.zta_issuer = issuer
            cred_hash_b64 = att.get('zta_credential_hash', '') or ''
            if cred_hash_b64:
                new_id.zta_credential_hash = base64.b64decode(cred_hash_b64)
            cred_b64 = att.get('zta_credential', '') or ''
            if cred_b64:
                new_id.zta_credential = base64.b64decode(cred_b64)
            new_id.operator_bound = bool(att.get('operator_bound', False))
            new_id.operator_attested_at = float(att.get('operator_attested_at', 0.0) or 0.0)
        except (ValueError, TypeError):
            # A malformed attestation is treated as absent; identity/keys still
            # stand on their own and normal admission proceeds.
            pass

    def _broadcast_request_access(self, queues):
        """Build and broadcast the `request_access` envelope on the open
        channel. Factored out of announce_identity so the group-merge
        path (see _merge_to_mesh) can re-broadcast without a phase change.
        Quiet on Full — caller logs."""
        # DRY request_access wire contract (cross-runtime canonical): the
        # requester identity travels in the envelope from_* fields (set via
        # from_whom below — the single representation C and Python both
        # emit/parse, pinned by the message-envelope conformance vectors),
        # NOT in the payload. The payload carries only the request-specific
        # extras [package_hash, capabilities]. This is what lets a C at_demo
        # node (whose net_proc stamps identity into from_* on every outbound
        # and leaves request-payload identity absent) be admitted by a Python
        # welcoming committee, and vice-versa. See welcoming_committee and
        # message._identity_from_wire.
        #
        # The operator-attended attestation (ethne D8/Q9) rides as an OPTIONAL
        # 3rd payload element. It carries the node's ZTA operator binding
        # (credential + hash + issuer) which — unlike identity in from_* — is
        # NOT on the envelope, so this payload is also what finally delivers a
        # verifiable credential to the welcoming committee. Because it is in the
        # signed DATA payload (process|function|base64(data)), it is
        # tamper-evident under the existing message signature with no change to
        # the signing formula and no envelope/wire-vector change. Old peers emit
        # a 2-element payload; welcoming_committee tolerates both arities.
        self._refresh_operator_attestation()
        msg_str = to_json_string((self.package_hash, self.capabilities.to_list(),
                                  self._operator_attestation()))
        message = Message(self.name, IdentityProtocol.announce,
                          msg_str, to_whom=Network.broadcast,
                          from_whom=self.identity, encrypt=False)
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
                # Group rides the wire as the DRY canonical flat dict (shared
                # byte-shape with C's group_to_json); reconstruct it. Tolerate
                # a legacy Group object (in-process / pre-canonical path).
                if isinstance(group, dict):
                    group = Group.from_canonical(group)
                # Merge peer identities from every history that arrived
                # — even ones we won't pick for our group/DAG — so the
                # peer set is the union of what all welcomers saw.
                if peer_idents:
                    for ident in peer_idents:
                        # Slot-2 peers ride as DRY canonical public-identity
                        # dicts (shared with C); reconstruct, tolerating a
                        # legacy Identity object.
                        if isinstance(ident, dict):
                            ident = public_identity_from_canonical(ident)
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
                # Group rides the wire as the DRY canonical flat dict (see
                # _merge_to_mesh); reconstruct it, tolerating a legacy object.
                if isinstance(group, dict):
                    group = Group.from_canonical(group)
                if peer_idents:
                    for ident in peer_idents:
                        # Slot-2 peers ride as DRY canonical public-identity
                        # dicts (shared with C); reconstruct, tolerating a
                        # legacy Identity object.
                        if isinstance(ident, dict):
                            ident = public_identity_from_canonical(ident)
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
        # New-peer identity rides as the DRY canonical public-identity payload
        # (shared byte-shape with C public_identity_to_json) so a C member can
        # parse it — the new peer is a third party, so it can't use from_*.
        # from_whom carries the CONFIRMER (us) so a member can count distinct
        # confirmers for the two-phase admission quorum (§3.1-a). The new-peer
        # identity is the payload; the confirmer rides the envelope (idiomatic,
        # mirrors `accept`). Harmless at the default quorum of 1.
        msg_str = to_json_string(public_identity_to_canonical(blob.identity))
        message = Message(self.name, IdentityProtocol.confirm, msg_str, to_whom=self.group,
                          from_whom=self.identity)
        queues[CfgIds.network].put(message, block=True, timeout=self.q_cadence)

        # send my identity in the open to enable encryption — the new peer needs
        # my enc pubkey to decrypt the box-encrypted full_history that follows.
        # DRY canonical (mirrors request_access): identity travels in the
        # envelope from_* (from_whom), payload is [package_hash, capabilities],
        # so a C peer reads the granter identity where C always stamps it.
        # to self.handle_acceptance()
        msg_str = to_json_string((self.package_hash, self.capabilities.to_list()))
        message = Message(self.name, IdentityProtocol.accept, msg_str, to_whom=blob.identity,
                          from_whom=self.identity, encrypt=False)
        queues[CfgIds.network].put(message, block=True, timeout=self.q_cadence)

        # send group key + history + my peer set so the new peer can
        # decrypt future group messages AND populate identities for the
        # peers I already admitted (otherwise it never receives confirm
        # broadcasts for those peers — see project_inspector_peer_set_gap).
        # Peer identities are stripped of private keys via publish().
        # Peer bundle (slot 2) rides as DRY canonical public-identity dicts
        # (shared byte-shape with C public_identity_to_json) so the joining
        # peer — including a C node — can parse the existing roster. (Was
        # p.publish(), the ConfigJSONEncoder form C cannot read.)
        peers_payload = [public_identity_to_canonical(p) for p in self.peers.all]
        # Group slot travels as the DRY canonical flat dict (shared byte-shape
        # with C's group_to_json) so a C peer can parse it and recover the
        # shared private key; Python peers reconstruct via Group.from_canonical
        # in receive_history/_merge_to_mesh/choose_group. See
        # [[project_group_key_sync]].
        msg_str = to_json_string((self.group.to_canonical(), self._history.recite(),
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

    def _zta_operator_verifier(self):
        """Build the OPERATOR-anchor verifier once (cached); None when no
        operator CA bundle is configured (ethne D8/Q9). Sentinel False marks
        "already tried, none configured" so we don't rebuild every admission."""
        if self._zta_operator_verifier_cache is None:
            self._zta_operator_verifier_cache = \
                self._zta_policy().create_operator_verifier() or False
        return self._zta_operator_verifier_cache or None

    @staticmethod
    def _mark_operator_bound(new_id, value):
        """Set the AUTHORITATIVE operator_bound on a peer identity (defensive:
        test stand-ins may lack the attribute)."""
        try:
            new_id.operator_bound = bool(value)
        except Exception:
            pass

    def _is_operator_credential(self, new_id, cred) -> bool:
        """True iff ``cred`` is an operator (human-attended) credential — i.e.
        it chain-verifies against the distinct operator trust anchor (D8/Q9).

        Non-forgeable: the decision comes from verifying the actual credential
        against the operator anchor, never from the peer-advertised
        operator_bound / zta_issuer. Fail-safe: no credential, an advertised
        hash that does not match the actual bytes, no operator anchor
        configured, or a non-VERIFIED operator-chain result all yield False."""
        if not cred:
            return False
        advertised = getattr(new_id, 'zta_credential_hash', b'') or b''
        if advertised and hashlib.sha256(cred).digest() != bytes(advertised):
            # The node's advertised hash disagrees with the credential it sent —
            # do not treat as operator-class (a claim/credential mismatch).
            return False
        op_verifier = self._zta_operator_verifier()
        if op_verifier is None:
            return False
        return op_verifier.verify_credential(cred).status is ZtaStatus.VERIFIED

    def _zta_credential_replayed(self, new_id, cred) -> bool:
        """True if this exact credential is already bound to a DIFFERENT network
        identity — a harvested/replayed credential (closes ISSUES §1.5).

        The chain-only verifier accepts a chain-valid certificate regardless of
        WHO presents it, so a credential lifted from one peer's (clear-text)
        announce could be re-announced under a different uuid/signing key and
        still pass. Here we enforce a credential↔identity uniqueness invariant: a
        credential is a one-per-identity binding. "Previously seen" = present in
        this node's peer roster (or our own identity); since rosters are built
        from announces propagated across the mesh, this is the "seen by other
        nodes" check. It is first-use-wins (TOFU): the first identity to bind a
        credential keeps it, and a later, different identity presenting the same
        credential is treated as a replay/clone and refused.

        Fingerprints are recomputed from the actual credential bytes, never the
        peer-advertised ``zta_credential_hash`` (which the announcer controls).
        Defensive about missing ``peers``/``identity`` so the gate works when
        invoked on a lightweight stand-in (no roster → no prior binding).
        """
        if not cred:
            return False
        fp = hashlib.sha256(cred).digest()
        new_uuid = getattr(new_id, 'uuid', None)
        # Our own credential must not be worn by anyone else.
        own_id = getattr(self, 'identity', None)
        if own_id is not None:
            own = getattr(own_id, 'zta_credential', b'') or b''
            if (own and getattr(own_id, 'uuid', None) != new_uuid
                    and hashlib.sha256(own).digest() == fp):
                return True
        peers = getattr(self, 'peers', None)
        roster = list(getattr(peers, 'all', []) or []) if peers is not None else []
        for peer in roster:
            if getattr(peer, 'uuid', None) == new_uuid:
                continue  # same identity re-announcing its own credential: fine
            pc = getattr(peer, 'zta_credential', b'') or b''
            if pc and hashlib.sha256(pc).digest() == fp:
                return True
        return False

    def _zta_admit(self, new_id) -> str:
        """ZTA admission decision for a newly-announced peer.

        Mirrors zta-integration.md §11 / the C gate: returns 'admit' (proceed,
        no cap), 'admit_capped' (DDIL fallback, reputation-capped), or 'reject'
        (do not propose). A no-op ('admit') when the policy is disabled or does
        not require verification at admission.

        Also sets the AUTHORITATIVE operator_bound (ethne D8/Q9): the advertised
        claim is neutralized to False on entry and set True only when the
        credential verifies against the distinct operator trust anchor (see
        _is_operator_credential). So a disabled policy, an unverified peer, or a
        lying node (advertising operator_bound with a non-operator credential)
        all end up operator_bound=False.
        """
        # Never trust the peer-advertised operator_bound: start False and earn
        # True only via operator-anchor verification below.
        self._mark_operator_bound(new_id, False)
        policy = self._zta_policy()
        if not (policy.enabled and policy.require_at_admission):
            return 'admit'
        nick = getattr(new_id, 'nickname', '?')
        try:
            cred = new_id.zta_credential or None
        except AttributeError:
            cred = None  # peer from an older/non-ZTA build carries no field
        # Size guard BEFORE handing the blob to the verifier: an oversized
        # credential is almost certainly hostile/corrupt and would let a remote
        # cause an OOM / parse-time DoS. Mirrors C `ZTA_CRED_MAX` (identity.h);
        # the C twin enforces the same cap at this admission gate (id_proc.c)
        # AND at protobuf deserialization (identity.c). Keep the bound in
        # lockstep -- pinned by conformance zta-x509-reject-oversized-credential.
        if cred is not None and len(cred) > ZTA_CRED_MAX:
            self.logger.warning('ZTA: rejecting %s at admission: credential too '
                                'large (%d > %d)', nick, len(cred), ZTA_CRED_MAX)
            _probes.emit('id.welcome', 'zta_rejected', peer_nick=str(nick),
                         zta_status=ZtaStatus.REJECTED.value,
                         reason='credential too large')
            _probes.counter('id.welcome', 'zta_rejected')
            return 'reject'
        # Credential↔identity uniqueness (ISSUES §1.5 replay mitigation): a
        # chain-valid credential harvested from another peer's announce and
        # re-presented under a different identity is a replay/clone. Reject it
        # before chain verification — the cert may verify fine; the point is it
        # is already bound elsewhere. C parity (handle_welcoming_committee) is a
        # tracked follow-up; the deeper fix (binding the cert to the identity via
        # SAN/challenge-response) remains open in ISSUES §1.5.
        if cred is not None and self._zta_credential_replayed(new_id, cred):
            self.logger.warning('ZTA: rejecting %s at admission: credential '
                                'already bound to a different identity (replay)',
                                nick)
            _probes.emit('id.welcome', 'zta_rejected', peer_nick=str(nick),
                         zta_status=ZtaStatus.REJECTED.value,
                         reason='credential bound to a different identity (replay)')
            _probes.counter('id.welcome', 'zta_rejected')
            return 'reject'
        result = self._zta_verifier().verify_credential(cred)
        status = result.status
        if status is ZtaStatus.VERIFIED:
            # A chain-valid certificate may nonetheless have been revoked.
            # verify_credential does NOT consult the CRL/OCSP source (it mirrors
            # C x509_verify_credential, which only walks the chain + expiry), so
            # the admission gate must explicitly check revocation before
            # admitting. Only an affirmative REVOKED blocks: UNAVAILABLE — the
            # default when no crl_path/ocsp_url is configured — keeps the peer
            # admitted, so deployments without a revocation source see no change
            # in behavior. Mirrors the C welcoming_committee revocation gate;
            # pinned by conformance zta-x509-reject-revoked-credential.
            rev = self._zta_verifier().check_revocation(result.credential_hash)
            if rev.status is ZtaStatus.REVOKED:
                self.logger.warning('ZTA: rejecting %s at admission: %s (%s)',
                                    nick, rev.status.value, rev.reason)
                _probes.emit('id.welcome', 'zta_rejected', peer_nick=str(nick),
                             zta_status=rev.status.value, reason=rev.reason)
                _probes.counter('id.welcome', 'zta_rejected')
                return 'reject'
            # Peer credential verified against the mission anchor. Now classify
            # operator-class against the DISTINCT operator anchor (D8/Q9): only
            # a credential that also chain-verifies there marks a human guardian.
            if self._is_operator_credential(new_id, cred):
                self._mark_operator_bound(new_id, True)
                try:
                    self._operator_verified.add(new_id.uuid)
                except Exception:
                    pass
                self.logger.debug('ZTA: %s is operator-attended (human guardian)', nick)
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
                # DRY request_access contract: requester identity comes from
                # the envelope (Message.parse reconstructs from_whom from the
                # canonical from_* fields for an as-yet-unknown peer); the
                # payload carries only [package_hash, capabilities]. See
                # _broadcast_request_access and message._identity_from_wire.
                new_id = message.from_whom
                if not isinstance(new_id, Identity):
                    self.logger.warning('request_access with no sender identity; ignoring')
                    return True
                # [package_hash, capabilities, (optional) operator attestation].
                # Arity-tolerant: an old peer sends a 2-element payload → no
                # attestation. The attestation's ZTA binding (credential/hash/
                # issuer) is NOT on the envelope, so copy it onto new_id here
                # BEFORE _zta_admit — this is the wire delivery of the
                # verifiable credential (see _operator_attestation). The
                # advertised operator_bound is copied only as a claim; _zta_admit
                # overwrites it with the verified truth (P-L2).
                parts = from_json_string(message.obj)
                ph, caps = parts[0], parts[1]
                attestation = parts[2] if len(parts) > 2 and isinstance(parts[2], dict) else {}
                if attestation:
                    self._apply_operator_attestation(new_id, attestation)
                if new_id == self.identity:
                    self.logger.debug('Should not have received my own announcement')
                    return
                # Counterfeit check: a peer advertising a DIFFERENT non-empty
                # package hash is running tampered software → reject. An EMPTY
                # advertised hash means the peer doesn't compute one (e.g. a C
                # at_demo node, which has no package-hash concept) — treat as
                # "unknown", skip the check, and admit on identity/keys alone.
                # This is the heterogeneous-fleet allowance that lets a C node
                # join a Python welcoming committee; a same-runtime counterfeit
                # still advertises its (mismatched) hash and is caught.
                if str(ph) and not hmac.compare_digest(str(ph), str(self.package_hash)):
                    self.logger.error("Newbie is running a counterfeit; Ignore")
                    return True
                if not str(ph):
                    self.logger.debug("Peer advertised no package hash (heterogeneous "
                                      "runtime, e.g. C node); skipping counterfeit check")
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
        # DRY canonical flat wire form (shared byte-shape with C's
        # group_to_json) so a C co-member can parse the group_key_update —
        # Python's default ConfigJSONEncoder group is unparseable by C, which
        # left cross-runtime membership updates silently dropped. Mirrors the
        # full_history group delivery in _peer_accepted. The group key itself
        # is not rotated here (membership-only; key handover is a deferred
        # design — see idprocess.py:1042 / [[project_group_key_sync]]).
        grp_msg = to_json_string(group.to_canonical())  # to self.handle_group_update()
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

    def _confirm_group_membership(self, queues, identity, level=None):
        """Propagate group membership + key to a CONFIRMED peer (§3.1-a).

        Adds the peer's address to our group and re-publishes the group —
        which carries the shared private key (Group.to_canonical) — to the
        mid-level hierarchy. Split out of _add_peer so a PROVISIONAL member
        can be tracked (known in self.peers/history) without the group key
        ever leaving this node until the admission quorum is met. Only reached
        for confirmed peers; see handle_confirm_peer for the state machine."""
        if self.group is None:
            return
        if level is None:
            level = self.peers.mid_level
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

    def _add_peer(self, queues, identity, amnesia=False, confirmed=True):
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
        #
        # `confirmed` (§3.1-a two-phase admission): when False, the peer is
        # recorded in history/peers/caps but the group key is NOT propagated
        # (the group-address add + _update_group are withheld) — the
        # PROVISIONAL state. handle_confirm_peer promotes to confirmed once
        # the admission quorum of distinct confirmers is met. The welcomer
        # (post-finalize) and single-confirm default (quorum 1) pass True, so
        # existing behavior is unchanged.
        level = self.peers.mid_level
        if confirmed:
            self._confirm_group_membership(queues, identity, level)
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
            # Policy B — border-guards-only voting (ISSUES.md §3.1-c).
            # `welcoming_committee` only *emits* a proposal when this peer is a
            # border guard; the vote side now mirrors that: only border guards
            # vote on a received proposal. A non-border-guard has no
            # welcoming-committee validation context for the candidate, so its
            # vote would carry the same weight on a shallower view — Policy B is
            # the tighter security model. border_guard_mode defaults True (every
            # peer is a guard) so this is a no-op unless a deployment designates
            # non-guards; the C `handle_vote_on_peer` mirrors this gate. The
            # message is still consumed (returns True) — a non-guard simply
            # abstains rather than leaving it unhandled.
            if not self.border_guard_mode:
                self.logger.debug('Not a border guard; abstaining from vote')
                return True
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
            # DRY accept contract (mirrors request_access): granter identity
            # comes from the envelope (from_whom, reconstructed from the
            # canonical from_* fields); payload is [package_hash, capabilities].
            ident = message.from_whom
            if not isinstance(ident, Identity):
                self.logger.warning('access_granted with no sender identity; ignoring')
                return True
            payload = from_json_string(message.obj) if message.obj else None
            if payload and len(payload) >= 2:
                pkh, caps = payload[0], payload[1]
            else:
                pkh, caps = '', []  # C granter sends an empty payload
            # Counterfeit check: skip when the granter advertises an empty
            # package hash (heterogeneous runtime, e.g. a C node) — same
            # allowance as the request_access welcoming committee.
            if str(pkh) and not hmac.compare_digest(str(pkh), str(self.package_hash)):
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
            # DRY canonical confirm contract: the new-peer identity rides as a
            # flat public-identity dict (shared byte-shape with C
            # public_identity_to_json). Tolerate a legacy Configuration/
            # IdentityObj blob (in-process / pre-canonical path).
            blob = message.obj
            if isinstance(blob, str):
                blob = from_json_string(blob)
            if isinstance(blob, dict):
                peer = public_identity_from_canonical(blob)
            else:
                if hasattr(blob, 'validate') and not blob.validate():
                    _probes.counter('peer.set', 'silent_drop', 'invalid_blob')
                    self.logger.warning('Invalid peer confirmation blob')
                    return True
                peer = blob.identity if hasattr(blob, 'identity') else blob
            if peer is None or not hasattr(peer, 'uuid'):
                _probes.counter('peer.set', 'silent_drop', 'invalid_blob')
                self.logger.warning('Invalid peer confirmation blob')
                return True
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
            # Two-phase admission (§3.1-a). Count DISTINCT confirmers for this
            # peer; propagate the group key only once the quorum is met.
            #   - quorum 1 (default): first confirm promotes immediately —
            #     identical to the historical single-welcomer behavior.
            #   - quorum >1: hold PROVISIONAL (peer known, key withheld) until
            #     that many distinct border-guards have independently
            #     confirmed, then CONFIRM (propagate the group key).
            peer_key = str(peer.uuid)
            confirmer = message.from_whom
            confirmer_uuid = str(confirmer.uuid) if isinstance(confirmer, Identity) else None
            with self.lock:
                confirmers = self._provisional_confirmations.setdefault(peer_key, set())
                # No confirmer identity on the envelope (e.g. quorum 1, or a
                # sender that didn't stamp from_whom): treat this confirm as a
                # distinct anonymous corroboration so single-confirm admission
                # still promotes.
                confirmers.add(confirmer_uuid if confirmer_uuid is not None
                               else '<anon:%d>' % len(confirmers))
                reached = len(confirmers) >= max(1, self._admission_quorum)
            first_add = self.peers.find_by_uuid(peer.uuid) is None
            _probes.emit('peer.set', 'add_request',
                         peer_uuid=str(peer.uuid),
                         peer_addr=getattr(peer, 'address', None),
                         source='handle_confirm_peer')
            if first_add:
                # Record the peer (history/peers/caps); propagate the group
                # key only if the quorum is already satisfied.
                self._add_peer(queues, peer, confirmed=reached)
            elif reached:
                # Already provisionally known; the quorum is now met —
                # propagate the group key (promotion).
                self._confirm_group_membership(queues, peer)
            if reached:
                with self.lock:
                    self._provisional_confirmations.pop(peer_key, None)
            else:
                self.logger.debug(
                    'Peer %s provisional: %d/%d confirms' %
                    (peer.nickname, len(confirmers), max(1, self._admission_quorum)))
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

    def _capability_descriptor(self, name: str) -> dict:
        """Build the JSON descriptor for one capability for caps_response.

        Always carries ``name``; adds required_tier/description/kind/arg_schema
        when this node's `Capabilities` registry knows them (operator-console
        directory metadata, PIV_MFA_OPERATOR_ACCESS_PLAN.md §3.5). Receivers are
        tolerant of both this object form and a legacy bare name string.
        """
        from ..capabilities import sanitize_descriptor
        desc = {'name': name}
        cap = None
        if self.capabilities is not None:
            try:
                cap = self.capabilities[name]
            except KeyError:
                cap = None
        if cap is not None:
            raw = {'required_tier': int(getattr(cap, 'required_tier', 0) or 0),
                   'description': getattr(cap, 'description', '') or '',
                   'kind': getattr(cap, 'kind', '') or ''}
            schema = getattr(cap, 'arg_schema', None)
            if not schema:
                arg_names = getattr(cap, 'arg_names', None)
                if arg_names:
                    schema = {a: 'any' for a in arg_names}
            if schema:
                raw['arg_schema'] = schema
            # Clamp to the same bounds the receiver enforces, so we never emit
            # an oversized descriptor (defensive symmetry).
            desc.update(sanitize_descriptor(raw))
        return desc

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
            # Carry per-capability descriptors (name + optional required_tier/
            # description/kind/arg_schema). Receivers are tolerant of both this
            # object form and a legacy bare-name string.
            payload = to_json_string(
                [self._capability_descriptor(n) for n in caps_list])
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
            items = from_json_string(message.obj)
            if not isinstance(items, list) or not items:
                _probes.counter('peer.set', 'caps_response_bad_shape')
                return True
            # Tolerant parse: each item is either a legacy bare capability
            # name (str) or a descriptor object {name, required_tier,
            # description, kind, arg_schema}. Descriptors are untrusted and
            # size-bounded by PeerCapabilities.register_descriptor.
            caps_list = []
            parsed_descriptors = {}
            for item in items:
                if isinstance(item, str):
                    caps_list.append(item)
                elif isinstance(item, dict) and isinstance(item.get('name'), str):
                    nm = item['name']
                    caps_list.append(nm)
                    parsed_descriptors[nm] = {k: v for k, v in item.items()
                                              if k != 'name'}
                # else: malformed item, skip
            if not caps_list:
                _probes.counter('peer.set', 'caps_response_bad_shape')
                return True
            # Compute the set of caps this peer is missing from.
            # Snapshot under lock; emit diagnostics OUTSIDE the lock to
            # avoid contention with the identity proc's fan-put path.
            with self.lock:
                for nm, desc in parsed_descriptors.items():
                    self.peer_capabilities.register_descriptor(nm, desc)
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

    # --- Identity backfill for cold/late joiners ---------------------------
    # group.addresses can list members whose full Identity never reached us:
    # the merge/partition path adopts the group (addresses grow) but
    # _populate_peers_from_history only adds the identities a welcomer bundled,
    # so self.peers stays sparse. Without the Identity (nickname) we can't name
    # those peers, so consensus reputations stay unattributed and the
    # dod_mission dashboard shows everyone "forming…". This sweep asks the
    # group for the identities we lack; matching members reply with their
    # published identity, which we add to self.peers (and _record_peers then
    # reliably reaches the main proc via the explicit-put fix above).
    # Self-limiting: a node that already holds an identity per group member
    # emits nothing. Shares the caps-resync cadence (driven from the loop).
    def _periodic_identity_resync(self, queues):
        if self.phase != 3 or self.group is None or self.choosing:
            return
        try:
            group_size = len(list(self.group.addresses))
            have = {str(p.uuid) for p in self.peers.all}
            have.add(str(self.identity.uuid))
            # We have an Identity for (at least) every group member -> nothing
            # to do. uuid-count vs address-count is 1:1 per member; an
            # occasional over-query is harmless (responders skip via `have`).
            if len(have) >= group_size:
                return
            payload = to_json_string({'group_uuid': str(self.group.uuid),
                                      'have': sorted(have)})
            query = Message(self.name, IdentityProtocol.id_query, payload,
                            to_whom=Network.broadcast, encrypt=False)
            queues[CfgIds.network].put(query, block=True, timeout=self.q_cadence)
            _probes.counter('peer.set', 'identity_resync_query',
                            str(group_size - len(have)))
            self.logger.debug(
                'Identity resync: querying group for %d missing member '
                'identity/ies' % (group_size - len(have)))
        except Full:
            _probes.counter('peer.set', 'identity_resync_q_full')
            self.logger.error('_periodic_identity_resync: Network queue full')
        except Exception as err:
            _probes.counter('peer.set', 'identity_resync_exc')
            self.report_exception(err, '_periodic_identity_resync')

    def handle_identity_query(self, queues, message):
        """A same-group peer that holds our address but not our Identity asks
        for it (payload: our group uuid + the uuids it already has). If we're
        in that group and not in its have-list, reply with our published
        identity so it can populate self.peers."""
        if message.function != IdentityProtocol.id_query:
            return False
        try:
            payload = from_json_string(message.obj) \
                if isinstance(message.obj, (str, bytes)) else message.obj
            if not isinstance(payload, dict) or self.group is None:
                return True
            if str(payload.get('group_uuid')) != str(self.group.uuid):
                return True  # different group — not our concern
            have = {str(x) for x in (payload.get('have') or [])}
            if str(self.identity.uuid) in have:
                return True  # asker already has us
            out = to_json_string({'from_identity': self.identity.publish(),
                                  'from_address': self.identity.address})
            reply = Message(self.name, IdentityProtocol.id_response, out,
                            to_whom=Network.broadcast, encrypt=False)
            queues[CfgIds.network].put(reply, block=True, timeout=self.q_cadence)
            _probes.counter('peer.set', 'identity_response_sent')
        except Full:
            _probes.counter('peer.set', 'identity_response_q_full')
            self.logger.error('handle_identity_query: Network queue full')
        except Exception as err:
            _probes.counter('peer.set', 'identity_query_exc')
            self.report_exception(err, 'handle_identity_query')
        return True

    def handle_identity_response(self, queues, message):
        """Receive a group member's published identity (reply to our
        id_query) and add it to self.peers. Gated to peers whose advertised
        address is actually in our group's address map, so a stray
        broadcaster can't inject itself into our peer set."""
        if message.function != IdentityProtocol.id_response:
            return False
        try:
            payload = from_json_string(message.obj) \
                if isinstance(message.obj, (str, bytes)) else message.obj
            if not isinstance(payload, dict) or self.group is None:
                return True
            ident = self._as_identity(payload.get('from_identity'))
            if ident is None or getattr(ident, 'uuid', None) is None:
                _probes.counter('peer.set', 'identity_response_no_identity')
                return True
            addr = (getattr(ident, 'address', None)
                    or payload.get('from_address'))
            if addr is None or addr not in list(self.group.addresses):
                # Only backfill identities for actual group members.
                _probes.counter('peer.set', 'identity_response_not_in_group')
                return True
            if str(ident.uuid) == str(self.identity.uuid):
                return True
            with self.lock:
                already = self.peers.find_by_uuid(ident.uuid) is not None
                if not already:
                    self.peers.add(ident)
            if not already:
                self._record_peers(queues)
                _probes.counter('peer.set', 'identity_response_added')
                self.logger.debug(
                    'Identity resync: backfilled identity for group member '
                    '%s' % getattr(ident, 'nickname', str(ident.uuid)))
            else:
                _probes.counter('peer.set', 'identity_response_redundant')
        except Exception as err:
            _probes.counter('peer.set', 'identity_response_exc')
            self.report_exception(err, 'handle_identity_response')
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
    def _as_identity(obj):
        """Normalize a payload's ``from_identity`` to an Identity (or None).

        A Python sender's identity round-trips through ``from_json_string``
        back into an Identity (its publish() form carries ``__type__``), but a
        C / cross-runtime sender serializes it as the flat *canonical* form
        (no ``__type__``), so ``from_json_string`` leaves it a plain dict.
        Reconstruct that via ``public_identity_from_canonical`` so the
        signature/uuid checks downstream work for both. Without this a
        C-originated partition_probe/response crashes the handler
        (``'dict' object has no attribute 'signature'``) and an id_response is
        silently dropped, stranding cross-runtime group merges."""
        if isinstance(obj, dict):
            return public_identity_from_canonical(obj)
        if getattr(obj, 'uuid', None) is not None:
            return obj
        return None

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
        # Use operational (effective) rank so a peer that has dropped off the
        # one-hop mesh isn't picked as welcomer; falls back to the static
        # rank when no reachability adjustment is in play (deferred.md §2.2).
        our_rank = getattr(self.identity, 'effective_rank',
                           getattr(self.identity, '_rank', 0))
        for peer in self.peers.all:
            if str(getattr(peer, 'uuid', '')) == str(self.identity.uuid):
                continue
            peer_rank = getattr(peer, 'effective_rank',
                                getattr(peer, '_rank', 0))
            if peer_rank < our_rank:
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
            sender_id = self._as_identity(payload.get('from_identity'))
            group_uuid = payload.get('my_group_uuid')
            group_size = payload.get('my_group_size')
            sig_hex = payload.get('signature')
            if (sender_id is None or group_uuid is None
                    or group_size is None or sig_hex is None):
                _probes.counter('peer.set', 'partition_probe_missing_fields')
                return True
            # sender_id normalized to an Identity by _as_identity (a Python
            # sender round-trips to Identity; a C sender's flat canonical
            # dict is rebuilt). Verify signature using the raw-bytes path
            # that message.py:228-243 documents
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
            our_group_uuid = str(self.group.uuid)
            our_group_size = len(list(self.group.addresses))
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
            # Symmetric adoption: the probe already advertises the prober's
            # group size, so decide adoption HERE too — not only in
            # handle_partition_response. Without this, a node that never
            # receives a foreign GROUP-channel message — e.g. the
            # dod_mission coordinator, which sits in no other group's
            # address map — only ever RESPONDS to probes (its
            # ``sender_group is None`` trigger in netprocess never fires)
            # and can never initiate a merge into a larger group, leaving a
            # size-1/2 group wedged on the losing side of every comparison
            # (partition-recovery.md §1's size-1-coordinator case). Same
            # decision as handle_partition_response (strictly larger, or
            # equal size with smaller uuid), guarded by the in-flight lock
            # so we neither double-initiate nor ping-pong with the
            # symmetric peer (exactly one side's adopt test is True).
            if not self._partition_recovery_active():
                their_size = int(group_size)
                if (their_size > our_group_size
                        or (their_size == our_group_size
                            and str(group_uuid) < our_group_uuid)):
                    self._partition_recovery_in_progress = (
                        str(group_uuid), now())
                    self._broadcast_request_access(queues)
                    _probes.counter('peer.set', 'partition_recovery_initiated')
                    self.logger.info(
                        'Partition recovery (from probe): adopting group %s '
                        '(size=%d vs our %d), sent request_access '
                        '(probe from %s@%s)' %
                        (group_uuid, their_size, our_group_size,
                         sender_uuid, payload.get('from_address')))
            cutoff = now()
            last = self._partition_response_cooldown.get(sender_uuid)
            if (last is not None
                    and (cutoff - last).total_seconds()
                    < self._PARTITION_RESPONSE_COOLDOWN_SEC):
                return True
            self._partition_response_cooldown[sender_uuid] = cutoff
            # Build the response.
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
            sender_id = self._as_identity(payload.get('from_identity'))
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
                # The group rides as the DRY canonical flat dict (shared
                # byte-shape with C's group_to_json) so a C co-member's
                # group_key_update parses; tolerate a legacy ConfigJSONEncoder
                # Group object (same-runtime / pre-canonical senders, which
                # from_json_string reconstructs directly via __type__). Mirrors
                # the full_history reconstruction. See [[project_group_key_sync]].
                decoded = from_json_string(group)
                group = (Group.from_canonical(decoded)
                         if isinstance(decoded, dict) else decoded)
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
                    # Size tie (ISSUES.md §3.1-b): the OLDER group wins — the
                    # more-established group absorbs the younger one — so we
                    # adopt theirs iff it is older. Only when both carry a known
                    # age (created > 0) that differs; otherwise fall back to the
                    # deterministic uuid tiebreaker (historical behavior, which
                    # prevents the equal-size group_key_update flood). "Adopt
                    # the older/larger group": larger is primary above, older
                    # breaks the tie here.
                    if theirs.created and mine.created and theirs.created != mine.created:
                        adopt = theirs.created < mine.created
                    else:
                        adopt = str(theirs.uuid) < str(mine.uuid)
            if adopt:
                if theirs.owns_private_key or not mine.owns_private_key:
                    # Normal adopt: `theirs` carries the shared private key, or
                    # we hold no key to lose — take it wholesale.
                    self.logger.debug('Replace %s group with %s group' % (mine.nickname, theirs.nickname))
                    self.group = theirs
                elif mine.uuid == theirs.uuid:
                    # `theirs` is PUBLIC-ONLY but has a larger membership for OUR
                    # group. Adopt the membership but KEEP our private encryptor:
                    # group_key_update is membership-only (the key is not rotated,
                    # idprocess.py:1042). Wholesale replacement here would drop the
                    # shared private key and break group decrypt — the Py<->C
                    # divergence that left cold-joining C nodes keyless (right
                    # uuid, wrong key bytes). C's handle_group_update already
                    # keeps its encryptor. See [[dod-microdrone-targets-live-vs-playback]].
                    self.logger.debug('Adopt %s membership; keep our group key' % theirs.nickname)
                    self.group.adopt_membership(theirs)
                else:
                    # `theirs` is a DIFFERENT, public-only group. Adopting it would
                    # abandon our key-bearing group for one we cannot decrypt;
                    # refuse and wait for a private-bearing full_history / update
                    # to converge. (Quiet no-op — don't echo, that's the flood.)
                    self.logger.debug('Refuse public-only group %s over our keyed group' % theirs.nickname)
                    return True
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
                    # Same cadence: backfill identities for group members we
                    # hold an address for but no Identity (cold/late joiner;
                    # see _periodic_identity_resync + layer 3 memory).
                    self._periodic_identity_resync(queues)

                # Every iteration, not interval-gated: an attended-now pull
                # must not outlive its deadline, in either direction — a pull
                # we owe an answer to, or one we are waiting on. Cheap — both
                # are no-ops unless a pull is in flight.
                self._expire_attest_pending(queues)
                self._expire_attest_sent(queues)

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
