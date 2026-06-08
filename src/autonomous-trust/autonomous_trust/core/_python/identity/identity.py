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

import secrets
import time
import uuid as uuid_mod

from nacl.public import Box
from nacl.encoding import HexEncoder

from ..config import Configuration, InitializableConfig
from ..system import encoding, agreement_impl
from ..algorithms.agreement import AgreementVoter
from .sign import Signature
from .encrypt import Encryptor
from autonomous_trust.core.protobuf.identity import identity_pb2

class Identity(InitializableConfig, AgreementVoter):
    """
    Identity details that can be saved to file or transmitted
    """
    _msg_class = identity_pb2.Identity
    enc = encoding

    def __init__(self, _uuid, address, _fullname, _nickname, _signature, _encryptor, petname='',
                 _public_only=True, _rank=0, _block_impl=agreement_impl, _tier=0,
                 zta_credential=b'', zta_issuer='', zta_credential_hash=b''):
        Configuration.__init__(self, identity_pb2.Identity)
        AgreementVoter.__init__(self, str(_uuid), _rank, _tier=_tier)
        self.address = address  # corresponds to one address in Network config
        self._fullname = _fullname
        self._nickname = _nickname
        self._signature = _signature  # signatures are for one-to-many verification
        self._encryptor = _encryptor  # one-to-one encryption
        self.petname = petname
        self._public_only = _public_only
        self._block_impl = _block_impl
        # ZTA credential binding (identity.proto fields 6-8; parity with C
        # public_identity_t, identity.c:349-398). The credential is an X.509
        # cert (DER) issued by the mission CA; it rides the announce/propose/
        # confirm payloads so the welcoming committee can verify it at
        # admission (see idprocess.welcoming_committee + identity/zta/). These
        # are deliberately NOT part of __eq__: credential rotation updates the
        # binding but must not change identity (zta-integration.md §6). Param
        # names mirror the stored attributes so config_json_decoder round-trips.
        self.zta_credential = zta_credential or b''
        self.zta_issuer = zta_issuer or ''
        self.zta_credential_hash = zta_credential_hash or b''
        # Reputation-derived trust tier (0..4) is stored on the base
        # AgreementVoter via the __init__ call above (so PoT can read
        # voter.tier directly). The protobuf wire form
        # (identity_pb2.Identity) does NOT encode `_tier` — trust is
        # others' opinion of a peer, not the peer's own claim — so over
        # the network this attribute is always 0 on receive and
        # populated locally via IdentityProcess.handle_tier_update.
        # The constructor accepts `_tier` so JSON roundtrips used for
        # IPC (Message.obj auto-deserialize) don't trip on the
        # serialized attribute. Distinct from `_rank` (network
        # topology); see doc/architecture/trust-tiers.md §1.

    def __eq__(self, other):
        return self.__class__.__name__ == other.__class__.__name__ and self.uuid == other.uuid and \
            self.address == other.address and \
            self.fullname == other.fullname and self.nickname == other.nickname and \
            self.signature == other.signature and self.encryptor == other.encryptor

    @property
    def uuid(self):
        return self._uuid

    @property
    def fullname(self):
        return self._fullname

    @property
    def nickname(self):
        return self._nickname

    @property
    def signature(self):
        return self._signature

    @property
    def encryptor(self):
        return self._encryptor

    @property
    def block_impl(self):
        return self._block_impl

    def sign(self, msg):
        """
        Sign my own message
        :param msg: bytes
        :return: SignedMessage (msg, sig)
        """
        if isinstance(msg, str):
            msg = msg.encode(self.enc)
        elif isinstance(msg, Configuration):
            msg = msg.to_string().encode(self.enc)
        if self._public_only or self.signature.private is None:
            raise RuntimeError('Cannot sign a message with another identity (%s is not you)' % self.nickname)
        return self.signature.private.sign(msg, encoder=HexEncoder)

    def verify(self, msg, signature=None):
        """
        Verify someone else's signature
        :param msg: SignedMessage (msg, sig) or bytes
        :param signature: sig, if msg was bytes
        :return: bytes
        """
        if isinstance(msg, str):
            msg = msg.encode(self.enc)
        elif isinstance(msg, Configuration):
            msg = msg.to_string().encode(self.enc)
        if signature is None:  # msg is a tuple
            return self.signature.public.verify(msg, encoder=HexEncoder)
        return self.signature.public.verify(msg, signature, encoder=HexEncoder)

    def encrypt(self, msg, whom, nonce=None):
        """
        Encrypt my own message
        :param msg: bytes
        :param whom: destination Identity
        :param nonce: bytes
        :return: EncryptedMessage (nonce, ciphertext)
        """
        if self._public_only or self.encryptor.private is None:
            raise RuntimeError('Cannot encrypt a message with another identity (%s is not you)' % self.nickname)
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
        # Return raw bytes unconditionally — matches the docstring,
        # the C twin (identity_decrypt in src/c/autonomous_trust/
        # identity/identity.c returns the buffer as-is), and the
        # native_encrypt_decrypt_roundtrip conformance test. The
        # previous try/except utf-8-decode silently produced a str
        # for ASCII payloads, which broke the docstring contract
        # and made cross-runtime parity tests fail.
        # Message.parse (network/message.py:197) accepts either
        # bytes or str so downstream callers (netprocess.py:417 and
        # neighbours) are unaffected.
        return Box(self.encryptor.private, whom.encryptor.public).decrypt(msg, nonce)

    def publish(self):
        return Identity(self.uuid, self.address, self.fullname, self.nickname,
                        Signature(self.signature.publish(), True), Encryptor(self.encryptor.publish(), True),
                        self.petname, True, _rank=self._rank,
                        _block_impl=self._block_impl,
                        zta_credential=self.zta_credential, zta_issuer=self.zta_issuer,
                        zta_credential_hash=self.zta_credential_hash)

    def sync_to_message(self):
        self.message.uuid = str(self.uuid).encode('utf-8')
        self.message.address = self.address
        self.message.fullname = self._fullname
        self.message.rank = self._rank
        self._signature.message = self.message.signature
        self._signature.sync_to_message()
        self._encryptor.message = self.message.encryptor
        self._encryptor.sync_to_message()
        # ZTA binding (proto fields 6-8). Only set when populated, matching the
        # C side (identity.c:349-354) which omits empty fields from the proto.
        if self.zta_credential:
            self.message.zta_credential = self.zta_credential
        if self.zta_issuer:
            self.message.zta_issuer = self.zta_issuer
        if self.zta_credential_hash:
            self.message.zta_credential_hash = self.zta_credential_hash

    def sync_from_message(self):
        self._uuid = self.message.uuid.decode('utf-8')
        self.address = self.message.address
        self._fullname = self.message.fullname
        self._nickname = ''
        self.petname = ''
        self._public_only = True
        self._rank = self.message.rank
        self._block_impl = agreement_impl
        self._signature = Signature.__new__(Signature)
        self._signature.message = identity_pb2.Signature()
        self._signature.message.CopyFrom(self.message.signature)
        self._signature.sync_from_message()
        self._encryptor = Encryptor.__new__(Encryptor)
        self._encryptor.message = identity_pb2.Encryptor()
        self._encryptor.message.CopyFrom(self.message.encryptor)
        self._encryptor.sync_from_message()
        # ZTA binding (proto fields 6-8); parity with C identity.c:384-398.
        self.zta_credential = bytes(self.message.zta_credential)
        self.zta_issuer = self.message.zta_issuer
        self.zta_credential_hash = bytes(self.message.zta_credential_hash)

    @staticmethod
    def initialize(my_name, my_nickname, my_address):
        if '/' in my_address:
            my_address = my_address.split('/')[0]
        time.sleep(secrets.randbelow(1000) / 1000.0)  # reduce chance of collision
        return Identity(uuid_mod.uuid4(), my_address, my_name, my_nickname,
                        Signature.generate(), Encryptor.generate(), 'me', False)


def public_identity_to_canonical(identity):
    """Flat, cross-runtime ("DRY canonical") PUBLIC-identity payload form,
    byte-shape identical to C's ``public_identity_to_json`` (identity.c). Used
    where a peer identity rides the wire in the *payload* rather than the
    envelope from_* fields — the ``peer_accepted`` (confirm) announcement and
    the ``full_history`` peer bundle — so a C peer can parse it (Python's
    default ConfigJSONEncoder ``publish()`` form, with ``__type__`` and a
    base64-wrapped hex_seed, is unparseable by C). The ``hex_seed`` values are
    the 64-char hex public keys (what ``signature_publish``/``encryptor_publish``
    emit and what ``Signature``/``Encryptor(public_only=True)`` accept). No
    private material. See [[project_group_key_sync]]."""
    if identity is None:
        return None
    return {
        'typename': 'identity',
        'uuid': str(identity.uuid),
        'address': getattr(identity, 'address', '') or '',
        'fullname': getattr(identity, 'fullname', '') or '',
        'nickname': getattr(identity, 'nickname', '') or '',
        'petname': getattr(identity, 'petname', '') or '',
        'signature': {'hex_seed': identity.signature.publish().decode('ascii')},
        'encryptor': {'hex_seed': identity.encryptor.publish().decode('ascii')},
    }


def public_identity_from_canonical(d):
    """Inverse of :func:`public_identity_to_canonical`; reconstruct a public
    Identity from the flat cross-runtime form (also what C emits). Returns
    None on a malformed dict (missing uuid or public keys)."""
    if not isinstance(d, dict):
        return None
    try:
        sig_hex = (d.get('signature') or {}).get('hex_seed', '')
        enc_hex = (d.get('encryptor') or {}).get('hex_seed', '')
        if not d.get('uuid') or not sig_hex or not enc_hex:
            return None
        sig = Signature(sig_hex.encode('ascii'), public_only=True)
        enc = Encryptor(enc_hex.encode('ascii'), public_only=True)
        return Identity(d['uuid'], d.get('address', '') or '',
                        d.get('fullname', '') or '', d.get('nickname', '') or '',
                        sig, enc, d.get('petname', '') or '')
    except (ValueError, TypeError, RuntimeError, KeyError):
        return None
