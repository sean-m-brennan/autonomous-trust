# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
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
"""The anchored cohort (RD_14.4_HOSTILE_JOIN_PLAN.md Phase 6, D8 (b)).

A joiner that counts some of its cohort's members as anchors (verified
contacts, its operator's other nodes) forms a second group with them, beside
the cohort: its own key, its own reputation chain and quorum, no gateway and
no rank gate. The cohort stays their transport and roster; the reputation
evidence among the anchored members moves to the anchored cohort's chain,
which the rest of the cohort neither receives nor co-signs.

The user's calls (2026-10-27):

- **Forming.** Under the join policy, a node holding a primary group and no
  anchored cohort counts the primary group's members it counts as anchors.
  With at least ``anchored_cohort_min`` of them and its own uuid the lowest
  among itself and them, it mints the group and invites them; otherwise it
  waits for the lowest to.
- **Consent is automatic, gated on anchors.** A node accepts an invitation
  only under the policy, when it is listed, when the sender and every other
  listed member are anchors it counts, and when it holds no other anchored
  cohort. An invitation for the cohort it holds is an update, taken only at a
  higher key epoch; refusing one is leaving.
- **The coordinator** is the lowest-uuid member. It adds a cohort member that
  is an anchor and not yet in, removes a member that refused or did not answer
  within REPLY_TIMEOUT, and on either rotates the key and re-invites everyone.
  It never offers a peer the membership that peer refused: a peer that left
  because the coordinator added a stranger to it would otherwise be re-added,
  refuse again, and the two would trade places forever.

Two verbs, point-to-point and so pairwise-encrypted:
``anchored_cohort_invite`` (the group's canonical form, private key included)
and ``anchored_cohort_reply`` (``[group uuid, key epoch, accepted]``; the epoch
lets the coordinator ignore an answer to an invitation it has since
replaced). The C twin is
``src/c/autonomous_trust/identity/anchored_cohort.c``.
"""

from __future__ import annotations

import json
import os
import time
import uuid as uuid_mod
from queue import Full

from ..config import Configuration
from ..config.configuration import atomic_write
from ..system import CfgIds, now
from .encrypt import Encryptor
from .group import Group
from .join_policy import AnchoredCohort  # noqa: F401  (the IPC carrier)

#: The two verbs, as IdentityProtocol names them (cohort_invite,
#: cohort_reply); spelled here because identity.protocol imports this module's
#: importers.
INVITE = 'anchored_cohort_invite'
REPLY = 'anchored_cohort_reply'
#: Seconds the coordinator waits for a member's reply before removing it.
REPLY_TIMEOUT = 60.0
#: Where the held anchored cohort is persisted (the canonical group form).
COHORT_FILE = 'anchored_cohort' + Configuration.file_ext


def member_uuids(group) -> set:
    """The member uuids (lower-case strings) of ``group``'s address map."""
    members = getattr(group, '_address_map', None)
    return {str(k).lower() for k in members} if isinstance(members, dict) else set()


def holds_member(group, peer_uuid) -> bool:
    """Whether ``peer_uuid`` is a member of ``group`` (None: no group)."""
    return group is not None and str(peer_uuid).lower() in member_uuids(group)


class AnchoredCohortMixin(object):
    """IdentityProcess's half of the anchored cohort. Expects ``self.group``,
    ``self.peers``, ``self.identity``, ``self.join_policy``,
    ``self.is_anchored`` and ``self.update``."""

    def _cohort_init(self):
        self.anchored_cohort = None
        # Coordinator's bookkeeping: member uuid -> when it was invited, for
        # members that have not answered the current invitation.
        self._cohort_pending: dict[str, float] = {}
        # Coordinator's memory: member uuid -> the member set it refused.
        self._cohort_refused: dict[str, frozenset] = {}

    # --- state -------------------------------------------------------------

    def _cohort_path(self):
        return os.path.join(Configuration.get_cfg_dir(), COHORT_FILE)

    def _cohort_set(self, queues, group, reason):
        """Hold ``group`` as the anchored cohort (None: none), persist it and
        tell the sibling processes."""
        self.anchored_cohort = group
        path = self._cohort_path()
        try:
            if group is None:
                if os.path.exists(path):
                    os.remove(path)
            else:
                with atomic_write(path) as out:
                    json.dump(group.to_canonical(), out, indent=2)
        except OSError as err:
            self.logger.warning('Could not persist the anchored cohort: %s', err)
        self.protocol.anchored_cohort = group
        try:
            self.update(AnchoredCohort(group), queues)
        except Exception as err:
            self.logger.warning('Could not propagate the anchored cohort: %s', err)
        self.logger.info('Anchored cohort %s: %s (%d member(s))',
                         str(group.uuid)[:8] if group is not None else '-',
                         reason, len(member_uuids(group)))

    def _cohort_load(self, queues):
        """Restore the anchored cohort persisted before a restart."""
        path = self._cohort_path()
        if not os.path.exists(path):
            return
        try:
            with open(path, 'r', encoding='utf-8') as cfg:
                group = Group.from_canonical(json.load(cfg))
        except (OSError, ValueError, TypeError) as err:
            self.logger.warning('Could not load the anchored cohort: %s', err)
            return
        self._cohort_set(queues, group, 'restored')

    # --- who counts --------------------------------------------------------

    def _policy_cohorts(self) -> bool:
        return bool(getattr(getattr(self, 'join_policy', None), 'enabled', False))

    def _anchor_uuid(self, peer_uuid) -> bool:
        """Whether ``peer_uuid`` is a peer this node holds and counts as an
        anchor."""
        peer = self.peers.find_by_uuid(peer_uuid)
        return peer is not None and self.is_anchored(peer)

    def _cohort_anchors(self) -> list:
        """The primary group's members this node counts as anchors, as held
        Identities, by uuid."""
        primary = member_uuids(self.group)
        me = str(self.identity.uuid).lower()
        out = []
        for peer in list(self.peers.all):
            key = str(peer.uuid).lower()
            if key != me and key in primary and self.is_anchored(peer):
                out.append(peer)
        return sorted(out, key=lambda p: str(p.uuid).lower())

    def _is_coordinator(self) -> bool:
        """Whether this node is the lowest-uuid member of its cohort."""
        members = member_uuids(self.anchored_cohort)
        return bool(members) and min(members) == str(self.identity.uuid).lower()

    # --- forming and coordinating -----------------------------------------

    def _maybe_form_anchored_cohort(self, queues):
        """Form the anchored cohort, or coordinate the one held. Run on every
        peer-list change and on the resync cadence. Mirrors C
        identity_anchored_cohort_tick."""
        if not self._policy_cohorts() or self.group is None:
            return
        if self.anchored_cohort is not None:
            if self._is_coordinator():
                self._coordinate_cohort(queues)
            return
        anchors = self._cohort_anchors()
        if len(anchors) < self.join_policy.anchored_cohort_min:
            return
        me = str(self.identity.uuid).lower()
        if min([me] + [str(p.uuid).lower() for p in anchors]) != me:
            return                          # the lowest uuid forms it
        members = {me: self.identity.address}
        for peer in anchors:
            members[str(peer.uuid).lower()] = peer.address
        group = Group(uuid_mod.uuid4(), members,
                      (self.identity.nickname or 'anchored') + '-anchored',
                      Encryptor.generate(), False, _created=now().timestamp(),
                      _wire_format=getattr(self.group, 'wire_format', None))
        self._cohort_set(queues, group, 'formed')
        self._cohort_invite_all(queues)

    def _coordinate_cohort(self, queues):
        """The coordinator's duties: add a cohort anchor not yet a member, drop
        a member that refused or did not answer, and on either rotate and
        re-invite."""
        group = self.anchored_cohort
        changed = False
        members = member_uuids(group)
        new = {str(p.uuid).lower(): p for p in self._cohort_anchors()
               if str(p.uuid).lower() not in members}
        offer = frozenset(members | set(new))
        new = {k: p for k, p in new.items() if self._cohort_refused.get(k) != offer}
        offer = frozenset(members | set(new))
        for key, peer in sorted(new.items()):
            if self._cohort_refused.get(key) != offer:
                group.add_address(key, peer.address)
                changed = True
        present = time.time()
        for key, since in list(self._cohort_pending.items()):
            if present - since >= REPLY_TIMEOUT:
                self._cohort_drop(group, key)
                changed = True
        if changed:
            self._cohort_rotate(queues, 'membership changed')

    def _cohort_drop(self, group, key):
        self._cohort_pending.pop(key, None)
        members = getattr(group, '_address_map', {})
        for k in list(members):
            if str(k).lower() == key:
                del members[k]

    def _cohort_rotate(self, queues, reason):
        group = self.anchored_cohort
        try:
            group.rotate_key()
        except Exception as err:
            self.logger.warning('Could not rotate the anchored cohort key: %s', err)
            return
        self._cohort_set(queues, group, reason)
        self._cohort_invite_all(queues)

    def _cohort_invite_all(self, queues):
        """Send every other member the cohort's canonical form."""
        group = self.anchored_cohort
        me = str(self.identity.uuid).lower()
        payload = json.dumps(group.to_canonical())
        present = time.time()
        self._cohort_pending = {}
        for key in sorted(member_uuids(group) - {me}):
            peer = self.peers.find_by_uuid(key)
            if peer is None:
                continue
            self._cohort_pending[key] = present
            self._cohort_send(queues, INVITE, payload, peer)

    def _cohort_send(self, queues, function, payload, peer):
        from ..network import Message   # network imports protocol imports us
        msg = Message(self.name, function, payload, to_whom=peer,
                      from_whom=self.identity)
        try:
            queues[CfgIds.network].put(msg, block=True, timeout=self.q_cadence)
        except Full:
            self.logger.warning('Anchored cohort: network queue full (%s to %s)',
                                function, getattr(peer, 'nickname', '?'))

    # --- the verbs ---------------------------------------------------------

    @staticmethod
    def _payload(message):
        obj = message.obj
        if isinstance(obj, (bytes, bytearray)):
            obj = obj.decode('utf-8')
        return json.loads(obj) if isinstance(obj, str) else obj

    def handle_anchored_cohort_invite(self, queues, message):
        """An invitation to, or an update of, an anchored cohort. Accepted only
        under the policy, when this node is listed, when the sender and every
        other listed member are anchors it counts, and when it holds no other
        cohort; an update of the one held only at a higher key epoch. Refusing
        an update of the one held is leaving it."""
        if message.function != INVITE:
            return False
        sender = getattr(message.from_whom, 'uuid', None)
        if sender is None:
            return True
        try:
            group = Group.from_canonical(self._payload(message))
        except (ValueError, TypeError, AttributeError) as err:
            self.logger.warning('Anchored cohort: unreadable invite from %s: %s',
                                getattr(message.from_whom, 'nickname', '?'), err)
            return True
        if not self._policy_cohorts():
            return True                     # no policy: not ours to answer
        held = self.anchored_cohort
        same = held is not None and str(held.uuid) == str(group.uuid)
        if same and group.key_epoch <= held.key_epoch:
            return True                     # a replay or a stale update
        me = str(self.identity.uuid).lower()
        members = member_uuids(group)
        why = None
        if held is not None and not same:
            why = 'holds another anchored cohort'
        elif me not in members or str(sender).lower() not in members:
            why = 'not listed with its sender'
        elif not group.owns_private_key:
            why = 'carries no key'
        else:
            strangers = [k for k in members - {me} if not self._anchor_uuid(k)]
            if strangers:
                why = 'lists %d member(s) not anchors here' % len(strangers)
        accepted = why is None
        if accepted:
            self._cohort_pending = {}
            self._cohort_set(queues, group, 'joined' if not same else
                             'updated to epoch %d' % group.key_epoch)
        else:
            self.logger.info('Anchored cohort %s from %s refused: %s',
                             str(group.uuid)[:8],
                             getattr(message.from_whom, 'nickname', '?'), why)
            if same:
                self._cohort_set(queues, None, 'left (%s)' % why)
        self._cohort_send(queues, REPLY,
                          json.dumps([str(group.uuid), group.key_epoch, accepted]),
                          message.from_whom)
        return True

    def handle_anchored_cohort_reply(self, queues, message):
        """A member's answer to the coordinator's invitation. A refusal removes
        it; the coordinator then rotates and re-invites the rest."""
        if message.function != REPLY:
            return False
        try:
            group_uuid, epoch, accepted = self._payload(message)
        except (ValueError, TypeError):
            return True
        held = self.anchored_cohort
        sender = str(getattr(message.from_whom, 'uuid', '')).lower()
        if held is None or str(held.uuid) != str(group_uuid) \
                or sender not in member_uuids(held) \
                or int(epoch) != held.key_epoch:
            return True                     # not ours, or a superseded answer
        self._cohort_pending.pop(sender, None)
        if not accepted and self._is_coordinator():
            self._cohort_refused[sender] = frozenset(member_uuids(held))
            self._cohort_drop(held, sender)
            self._cohort_rotate(queues, 'a member refused')
        return True
