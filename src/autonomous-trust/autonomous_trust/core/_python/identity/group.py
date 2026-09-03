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

import random
import time
import uuid as uuid_mod

from nacl.exceptions import CryptoError
from nacl.public import Box

from ..config import InitializableConfig, NetWireFormat
from .encrypt import Encryptor
from autonomous_trust.core.protobuf.identity import identity_pb2


class Group(InitializableConfig):
    """
    Group identity details that can be saved to file or transmitted
    """
    _msg_class = identity_pb2.Group

    def __init__(self, _uuid, _address_map, _nickname, _encryptor, _public_only=True,
                 _created=0.0, _key_epoch=0, _previous_keys=None, _wire_format=None):
        super().__init__(identity_pb2.Group)
        self._uuid = str(_uuid)
        self._address_map = _address_map
        self._nickname = _nickname
        self._encryptor = _encryptor  # group-shared key
        self._public_only = _public_only
        # Group age (doc/architecture/identity-protocol.md): a comparable creation epoch
        # (seconds). Used only as the group-merge tiebreaker on a MEMBERSHIP-SIZE TIE —
        # the OLDER (smaller `created`) group wins, so the more-established group
        # absorbs the younger one. 0.0 = "unknown age" (the default for
        # wire/test-constructed groups), in which case the merge falls back to
        # the historical uuid tiebreaker so behavior is unchanged. Only groups
        # minted via `initialize` carry a real age. Local/merge signal only.
        self._created = float(_created) if _created else 0.0
        # Key rotation (doc/architecture/gateway-reputation-tree.md). The shared key
        # used to be permanent, which meant admitting a member handed it the ability to
        # decrypt any cohort traffic it had recorded BEFORE it joined. Admission now
        # rotates, and `key_epoch` is what makes a rotation safe to accept: a receiver
        # adopts a new key only when it comes with a HIGHER epoch, so a captured older
        # key cannot be replayed back over a newer one.
        # 0 = never rotated, which is every group minted before this existed.
        self._key_epoch = int(_key_epoch or 0)
        # Superseded keys, newest first, as (Encryptor, retired_at). Kept only
        # so traffic already in flight when the key changed still decrypts --
        # a rotation is not synchronous across a cohort, and dropping every
        # frame from a member that has not yet processed the update would make
        # rotation cost more than it buys. Bounded by count and by age; see
        # `decrypt`.
        #
        # PROCESS-LOCAL, and never serialized: `to_dict` drops it and
        # `to_canonical` never emitted it, matching C, which holds
        # previous_keys/previous_retired_at in the group struct and writes
        # neither. The `_previous_keys` parameter therefore exists only to
        # ACCEPT AND DISCARD the key that configs written before that fix
        # carry -- `config_json_decoder` rebuilds via `cls(**kwargs)`, so
        # without it every such file fails to load with "unexpected keyword
        # argument". Discarded rather than restored on purpose: the grace
        # window covers frames in flight across a rotation, and a process that
        # is only now reading its config off disk has none. Restoring would
        # just hold retired private keys open past any use for them.
        self._previous_keys = []
        # Envelope encoding every member of this group speaks
        # (doc/architecture/network-wire-format.md), as a NetWireFormat string. The
        # GROUP owns this, not the node: a cohort in which two members disagree cannot
        # talk, and there is deliberately no per-peer negotiation and no format
        # detection to reconcile a disagreement after the fact (§2.5). A joining node
        # therefore adopts its group's value at admission (from_canonical /
        # adopt_membership) instead of applying its own AT_NET_WIRE_MODE, which only
        # stamps a group this node MINTS (see `initialize`).
        #
        # None/absent -> json, which is what every group minted before this
        # existed is, and what every group config written before this field
        # decodes as.
        self._wire_format = str(_wire_format) if _wire_format else NetWireFormat.json
        if self._wire_format not in (NetWireFormat.json, NetWireFormat.proto):
            # An unrecognized value tightens to the format every node can read
            # rather than failing the load: a group config is provisioned data,
            # and refusing to start over a typo in a field that has a safe
            # reading would cost more than it protects. Same discipline as
            # zta_policy.binding_mode falling back to `require`.
            self._wire_format = NetWireFormat.json

    def to_dict(self):
        # `_previous_keys` is process-local grace-window state, not part of the
        # config or wire identity of a group -- the same reason `identity.py`
        # drops `_rank_adjustment` and `zta_anchors`. Two things go wrong if it
        # round-trips: `config_json_decoder` rebuilds via `cls(**kwargs)`, and
        # (worse) a `.cfg.json` on disk would carry SUPERSEDED PRIVATE KEYS,
        # keeping retired key material readable long after the grace window it
        # exists for has closed. C holds the same state in the group struct and
        # serializes it nowhere, so dropping it here is also what keeps the two
        # runtimes' persisted groups the same shape.
        d = super().to_dict()
        d.pop('_previous_keys', None)
        return d

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        return self.uuid == other.uuid and self.encryptor.publish() == other.encryptor.publish()

    @property
    def uuid(self):
        return self._uuid

    @property
    def created(self):
        """Comparable creation epoch (seconds); 0.0 if unknown. See doc/architecture/identity-protocol.md."""
        return getattr(self, '_created', 0.0)

    @property
    def key_epoch(self) -> int:
        """How many times this group's shared key has been rotated. Only ever
        compared, never trusted as an identity: see :meth:`accept_rotation`."""
        return getattr(self, '_key_epoch', 0)

    @property
    def wire_format(self) -> str:
        """The envelope encoding this group's members speak
        (doc/architecture/network-wire-format.md).

        A :class:`NetWireFormat` value. ``getattr`` with a default because a
        Group unpickled or decoded from a config written before this field
        existed has no attribute at all, and every such group is JSON."""
        return getattr(self, '_wire_format', NetWireFormat.json)

    #: How long a superseded key still decrypts, and how many are kept. A
    #: rotation propagates as fast as one message to each member, so this is
    #: generous; it bounds the window in which a key that was deliberately
    #: retired still opens traffic, which is the whole thing rotation exists
    #: to shorten.
    PREVIOUS_KEY_GRACE = 60.0
    PREVIOUS_KEY_MAX = 2

    def rotate_key(self, now_ts=None):
        """Mint a fresh shared key, retiring the current one into the grace
        window, and return the new epoch.

        Called when a cohort admits a member (doc/architecture/gateway-reputation-tree.md,
        user's call
        2026-08-13): the joiner receives only the NEW key, so ciphertext it
        recorded before being admitted stays closed to it.

        Requires ownership of the current private key -- a public-only view of
        somebody else's group has no standing to rotate it, and silently
        minting a key here would fork the cohort into two that cannot hear
        each other."""
        if not self.owns_private_key:
            raise RuntimeError(
                'Cannot rotate the key of a group whose private key we do not '
                'hold (%s)' % self.nickname)
        stamp = time.time() if now_ts is None else float(now_ts)
        prev = getattr(self, '_previous_keys', None)
        if prev is None:
            prev = self._previous_keys = []
        prev.insert(0, (self._encryptor, stamp))
        del prev[self.PREVIOUS_KEY_MAX:]
        self._encryptor = Encryptor.generate()
        self._public_only = False
        self._key_epoch = self.key_epoch + 1
        return self._key_epoch

    def accept_rotation(self, other, now_ts=None) -> bool:
        """Adopt ``other``'s shared key if it supersedes ours.

        Three conditions, and each is load-bearing:

        * **same group** -- a key for another cohort is not a rotation of this
          one;
        * **a strictly higher epoch** -- equal or lower is a replay, and
          accepting one would let a captured old key be reinstated over a
          newer one, which is precisely the attack rotation is meant to
          foreclose;
        * **the sender actually holds the private key** -- a public-only view
          carries nothing to adopt, and taking it would leave us unable to
          decrypt our own cohort.

        Authenticating WHO may rotate is the caller's job (a verified message
        from a member); this only decides whether the key on offer is newer."""
        if other is None or str(other.uuid) != str(self.uuid):
            return False
        if other.key_epoch <= self.key_epoch:
            return False
        if not other.owns_private_key:
            return False
        stamp = time.time() if now_ts is None else float(now_ts)
        prev = getattr(self, '_previous_keys', None)
        if prev is None:
            prev = self._previous_keys = []
        if self.owns_private_key:
            prev.insert(0, (self._encryptor, stamp))
            del prev[self.PREVIOUS_KEY_MAX:]
        self._encryptor = other.encryptor
        self._public_only = False
        self._key_epoch = other.key_epoch
        return True

    @property
    def nickname(self):
        return self._nickname

    @property
    def addresses(self):
        return self._address_map.values()

    def add_address(self, uuid, address):
        inv = {v: k for k, v in self._address_map.items()}
        if address in inv and inv[address] != uuid:
            del self._address_map[inv[address]]  # address collision
        self._address_map[uuid] = address

    @property
    def encryptor(self):
        return self._encryptor

    @property
    def owns_private_key(self):
        """True iff this Group holds the shared *private* box key (and can
        therefore decrypt group traffic). Mirrors the ``owns_private``
        predicate in :meth:`to_canonical` and the :meth:`encrypt` guard. A
        public-only group — e.g. one reconstructed from a protobuf round-trip
        (``sync_from_message`` forces ``_public_only=True``) or handed to us on
        the wire with ``public_only`` set — returns False."""
        return (not self._public_only) and self.encryptor.private is not None

    def wire_format_for_address(self, address) -> str:
        """This group's envelope format for traffic with *address*
        (doc/architecture/network-wire-format.md).

        A membership question, because the format belongs to the GROUP: a
        member speaks this group's format, and an address this group cannot
        place -- a stranger, a pre-admission newcomer, a member of a DIFFERENT
        group -- gets JSON, which every AT node can read and is therefore the
        only safe answer when there is no group to consult.

        That last case is what lets two groups with DIFFERENT formats complete a
        merge handshake without negotiating one: when a ``group_key_update``
        crosses from one cohort to another, neither side can place the other's
        members, so both fall to JSON independently and the exchange succeeds.
        Pinned by conformance ``network/cross-group-format-fallback``; the C
        twin is ``group_wire_format_for_address``.
        """
        try:
            member = address in self.addresses
        except Exception:
            member = False
        return self.wire_format if member else NetWireFormat.json

    def adopt_membership(self, other):
        """Adopt *other*'s group identity (uuid) and membership (address map)
        while KEEPING our own private encryptor. Used by ``handle_group_update``
        when a group_key_update carries a larger membership but only the public
        key: adopting *other* wholesale would drop our shared private key and
        break group decrypt. ``group_key_update`` is membership-only (the key is
        not rotated — see idprocess.py:1042), so retaining our encryptor is
        correct, and it mirrors C's ``handle_group_update`` which copies only
        uuid/address/address_map and keeps its own encryptor
        (id_proc.c:2113-2134). See [[dod-microdrone-targets-live-vs-playback]]."""
        self._uuid = str(other.uuid)
        self._address_map = (dict(other._address_map)
                             if isinstance(other._address_map, dict)
                             else {a: a for a in other.addresses})
        if other.nickname:
            self._nickname = other.nickname
        # Inherit the adopted group's age (doc/architecture/identity-protocol.md) so subsequent merges compare
        # against the established group's creation epoch, not ours.
        if other.created:
            self._created = other.created
        # Adopt the surviving group's envelope format too (doc/architecture/network-wire-format.md, user's call
        # 2026-08-18: "surviving group's format"). The merge winner is already
        # decided by size -> created -> uuid, so the format needs no tiebreaker
        # of its own -- it travels with the uuid and the address map, and this
        # node speaks the absorbing cohort's format from here on. Without this
        # line an absorbed node would keep talking in its old format inside its
        # new group, which is precisely the split a group-carried format exists
        # to prevent.
        self._wire_format = other.wire_format

    def encrypt(self, msg, whom, nonce=None):
        """
        Encrypt my own message
        :param msg: bytes
        :param whom: destination Identity
        :param nonce: bytes
        :return: EncryptedMessage (nonce, ciphertext)
        """
        if self._public_only or self.encryptor.private is None:
            raise RuntimeError('Cannot encrypt a message for another group (you are not part of %s)' % self.nickname)
        if isinstance(msg, str):
            msg = msg.encode()
        return Box(self.encryptor.private, whom.encryptor.public).encrypt(msg, nonce)

    def decrypt(self, msg, whom, nonce=None):
        """
        Decrypt someone else's message
        :param msg: EncryptedMessage (nonce, ciphertext)
        :param whom: sender Identity
        :param nonce: bytes
        :return: bytes
        """
        # Always return bytes — see identity.py:135 for the parity
        # rationale; group.decrypt mirrors identity.decrypt to keep
        # the two encrypt/decrypt entry points symmetric.
        try:
            return Box(self.encryptor.private, whom.encryptor.public).decrypt(msg, nonce)
        except CryptoError:
            # A rotation is not synchronous across a cohort: a member that has
            # not yet processed the key update is still sending under the old
            # one. Retry the recently retired keys rather than drop those
            # frames. Bounded by age so a retired key stops working soon after
            # it is retired -- an unbounded fallback would make rotation
            # decorative.
            stamp = time.time()
            for old_key, retired_at in list(getattr(self, '_previous_keys', [])):
                if stamp - retired_at > self.PREVIOUS_KEY_GRACE:
                    continue
                try:
                    return Box(old_key.private,
                               whom.encryptor.public).decrypt(msg, nonce)
                except CryptoError:
                    continue
            raise

    def publish(self):
        # wire_format travels with the published view: it is a property of the
        # GROUP, not of holding its private key, and a member handed a
        # public-only view still has to know which envelope the cohort speaks.
        return Group(self.uuid, self.addresses, self.nickname, Encryptor(self.encryptor.publish(), True), True,
                     _wire_format=self.wire_format)

    def sync_to_message(self):
        self.message.uuid = str(self._uuid).encode('utf-8')
        addr_map = dict(self._address_map) if isinstance(self._address_map, dict) \
            else {a: a for a in (self._address_map or [])}
        # Full UUID->address map (doc/architecture/identity-protocol.md).
        self.message.address_map.clear()
        for uuid, addr in addr_map.items():
            self.message.address_map[str(uuid)] = str(addr)
        # Legacy single address = first value, for older peers that only read it.
        self.message.address = next(iter(addr_map.values()), '')
        self.message.created = float(self.created)  # doc/architecture/identity-protocol.md group age
        # Envelope format (doc/architecture/network-wire-format.md). json is the proto3 default, so a JSON group
        # still encodes to the bytes it did before this field existed.
        self.message.wire_format = (identity_pb2.NET_WIRE_PROTO
                                    if self.wire_format == NetWireFormat.proto
                                    else identity_pb2.NET_WIRE_JSON)
        self._encryptor.sync_to_message()
        self.message.encryptor.CopyFrom(self._encryptor.message)

    def sync_from_message(self):
        self._uuid = self.message.uuid.decode('utf-8')
        # Prefer the full map (doc/architecture/identity-protocol.md); fall back to the legacy single `address`
        # from an older peer (keyed by the group uuid, the best we can do
        # without the original key).
        self._address_map = dict(self.message.address_map)
        if not self._address_map and self.message.address:
            self._address_map = {self._uuid: self.message.address}
        self._created = float(self.message.created) if self.message.created else 0.0
        # Absent/0 reads as json, which is what a group from a peer predating
        # this field is (doc/architecture/network-wire-format.md).
        self._wire_format = (NetWireFormat.proto
                             if self.message.wire_format == identity_pb2.NET_WIRE_PROTO
                             else NetWireFormat.json)
        self._nickname = ''
        self._public_only = True
        # Reconstruct nested Encryptor
        self._encryptor = object.__new__(Encryptor)
        self._encryptor.message = identity_pb2.Encryptor()
        self._encryptor.message.CopyFrom(self.message.encryptor)
        self._encryptor.sync_from_message()

    def to_canonical(self):
        """Flat, cross-runtime ("DRY canonical") group wire form, byte-shape
        identical to C's ``group_to_json`` (identity/group.c). Used for the
        ID_HISTORY group-key delivery so a C peer can parse it (Python's
        default ConfigJSONEncoder form, with ``__type__``/``_uuid`` and a
        base64-wrapped hex_seed, is unparseable by C). When we own the shared
        private key, ``hex_seed`` is the RAW 32-byte box private key (so the
        peer can decrypt group traffic); otherwise the public key, with
        ``public_only`` disambiguating on read. See [[project_group_key_sync]]."""
        addr_map = dict(self._address_map) if isinstance(self._address_map, dict) \
            else {}
        owns_private = (not self._public_only) and self.encryptor.private is not None
        seed = self.encryptor.serialize() if owns_private else self.encryptor.publish()
        if isinstance(seed, bytes):
            seed = seed.decode('ascii')
        return {
            'typename': 'group',
            'uuid': str(self._uuid),
            'address': next(iter(addr_map.values()), ''),
            'nickname': self._nickname or '',
            'address_map': addr_map,
            'encryptor': {'hex_seed': seed, 'public_only': not owns_private},
            # Group age (doc/architecture/identity-protocol.md) for the merge size-tie tiebreaker. Omitted-on-
            # read defaults to 0.0 (unknown → uuid tiebreak), so a peer on an
            # older build that doesn't send it stays compatible.
            'created': self.created,
            # Key rotation epoch (doc/architecture/gateway-reputation-tree.md). Additive and defaulted on read, so a
            # peer that predates rotation sends nothing and reads as epoch 0 --
            # which is exactly "never rotated" and needs no special case.
            'key_epoch': self.key_epoch,
            # Envelope encoding for this group's traffic (doc/architecture/network-wire-format.md). This is the
            # field a joining node adopts, which is what keeps a cohort from
            # ending up half in one format: it arrives with the group key, in
            # the same message, from the member that admitted us.
            'wire_format': self.wire_format,
        }

    @staticmethod
    def from_canonical(d):
        """Inverse of :meth:`to_canonical`; reconstruct a Group from the flat
        cross-runtime form (also what C emits). Tolerates a missing
        ``public_only`` (defaults to public-only, matching C)."""
        encr = d.get('encryptor', {}) or {}
        seed = encr.get('hex_seed', '')
        if isinstance(seed, str):
            seed = seed.encode('ascii')
        public_only = bool(encr.get('public_only', True))
        return Group(d.get('uuid'), dict(d.get('address_map', {}) or {}),
                     d.get('nickname', ''),
                     Encryptor(seed, public_only=public_only), public_only,
                     _created=d.get('created', 0.0) or 0.0,
                     _key_epoch=int(d.get('key_epoch', 0) or 0),
                     # Absent -> json (the constructor's default), which is both
                     # what an older peer means and the safe reading (doc/architecture/network-wire-format.md).
                     _wire_format=d.get('wire_format'))

    @staticmethod
    def initialize(address_map, our_nickname):
        time.sleep(random.random())  # reduce chance of collision
        # Stamp a real creation epoch (doc/architecture/identity-protocol.md) so a group minted here carries a
        # comparable age for the merge tiebreaker. now() is the NTP-adjusted
        # clock (autonomous_trust.core.system.now).
        from ..system import now, resolve_net_wire_mode
        created = now().timestamp()
        # AT_NET_WIRE_MODE applies HERE and only here: this is the one moment a
        # node decides a format rather than adopting one. Every other group this
        # node ever holds arrived from a peer with its format already set
        # (doc/architecture/network-wire-format.md), so an operator stands up a proto cohort by setting the knob on
        # whichever node forms the group.
        wire_format, _src = resolve_net_wire_mode()
        return Group(uuid_mod.uuid4(), address_map, our_nickname,
                     Encryptor.generate(), False, _created=created,
                     _wire_format=wire_format)


class ChildGroupSet(object):
    """IPC carrier for the set of child groups a gateway participates in.

    A gateway (rank > 1) belongs to its primary/parent group plus one or
    more child groups it bridges. The primary group is propagated to the
    other processes by fanning out a bare ``Group`` (which sets
    ``Protocol.group``). Child groups need the same cross-process
    propagation but must NOT clobber that single primary slot, so they
    ride in this distinct wrapper instead. Fanned out exactly like a
    ``Group`` via ``ProcessTracker.update``; handled in
    ``Protocol.run_message_handlers`` by setting ``Protocol.child_groups``.

    Plain picklable object (no protobuf) — it only ever travels the local
    inter-process queues, never the network. See
    doc/architecture/gateway-reputation-tree.md.
    """

    def __init__(self, groups=None):
        # dict[group-uuid-str -> Group]
        self.groups = dict(groups) if groups else {}
