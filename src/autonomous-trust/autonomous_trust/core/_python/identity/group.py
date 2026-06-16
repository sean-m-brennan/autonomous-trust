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

import random
import time
import uuid as uuid_mod

from nacl.public import Box

from ..config import InitializableConfig
from .encrypt import Encryptor
from autonomous_trust.core.protobuf.identity import identity_pb2


class Group(InitializableConfig):
    """
    Group identity details that can be saved to file or transmitted
    """
    _msg_class = identity_pb2.Group

    def __init__(self, _uuid, _address_map, _nickname, _encryptor, _public_only=True):
        super().__init__(identity_pb2.Group)
        self._uuid = str(_uuid)
        self._address_map = _address_map
        self._nickname = _nickname
        self._encryptor = _encryptor  # group-shared key
        self._public_only = _public_only

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        return self.uuid == other.uuid and self.encryptor.publish() == other.encryptor.publish()

    @property
    def uuid(self):
        return self._uuid

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
        return Box(self.encryptor.private, whom.encryptor.public).decrypt(msg, nonce)

    def publish(self):
        return Group(self.uuid, self.addresses, self.nickname, Encryptor(self.encryptor.publish(), True), True)

    def sync_to_message(self):
        self.message.uuid = str(self._uuid).encode('utf-8')
        # Proto has a single address string; take first value from map or empty
        if self._address_map:
            if isinstance(self._address_map, dict):
                self.message.address = next(iter(self._address_map.values()), '')
            else:
                self.message.address = next(iter(self._address_map), '')
        else:
            self.message.address = ''
        self._encryptor.sync_to_message()
        self.message.encryptor.CopyFrom(self._encryptor.message)

    def sync_from_message(self):
        self._uuid = self.message.uuid.decode('utf-8')
        self._address_map = {}
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
                     Encryptor(seed, public_only=public_only), public_only)

    @staticmethod
    def initialize(address_map, our_nickname):
        time.sleep(random.random())  # reduce chance of collision
        return Group(uuid_mod.uuid4(), address_map, our_nickname, Encryptor.generate(), False)


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
