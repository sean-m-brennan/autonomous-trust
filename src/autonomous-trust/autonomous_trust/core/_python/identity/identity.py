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
from .operator_binding import OPERATOR_BINDING_MAX, OPERATOR_PUBKEY_LEN
from .zta_binding import ZTA_BINDING_MAX

from autonomous_trust.core.protobuf.identity import identity_pb2

#: Whether the generated protobuf module carries `Identity.zta_credentials`
#: (field 16, the multi-credential set). Regenerating the pb2 happens on the
#: toolchain host, so source can be newer than the generated module for a window;
#: without this the sync paths would raise on every identity. Remove the guard once
#: no deployed pb2 predates field 16.
_HAS_ZTA_CREDENTIALS = ('zta_credentials'
                        in identity_pb2.Identity.DESCRIPTOR.fields_by_name)


def derive_local_petname(nickname):
    """Mint a LOCAL, arbitrary Zooko petname for a *received* identity.

    The petname is a local-only name: it is never carried on the wire (see
    ``sync_from_message`` / ``public_identity_from_canonical``), so a receiver
    must assign its own when it learns a peer. We seed it from the online
    nickname's local-part for human readability, then append a random suffix so
    the result is locally-unique and -- deliberately -- NOT equal to any global
    identifier. Nothing in the system may depend on a peer's petname matching
    its roster/online name; peer-to-role matching keys off the ONLINE nickname
    (the only globally-consistent, wire-carried name). The petname is purely a
    display label. The random suffix is what enforces that contract: code that
    accidentally matches on petname will simply fail to match, surfacing the
    bug instead of silently relying on a globalized petname."""
    local = ''
    if nickname:
        local = str(nickname).split('@', 1)[0].strip()
    if not local:
        local = 'peer'
    return '%s-%04d' % (local, secrets.randbelow(10000))


class Identity(InitializableConfig, AgreementVoter):
    """
    Identity details that can be saved to file or transmitted
    """
    _msg_class = identity_pb2.Identity
    enc = encoding

    def __init__(self, _uuid, address, _nickname, _signature, _encryptor, petname='',
                 _public_only=True, _rank=0, _block_impl=agreement_impl, _tier=0,
                 zta_credential=b'', zta_issuer='', zta_credential_hash=b'',
                 operator_bound=False, operator_attested_at=0.0,
                 operator_pubkey=b'', operator_key_binding=b'',
                 zta_credential_binding=b'', zta_credentials=None):
        Configuration.__init__(self, identity_pb2.Identity)
        AgreementVoter.__init__(self, str(_uuid), _rank, _tier=_tier)
        self.address = address  # corresponds to one address in Network config
        # Zooko ONLINE name (global, human-meaningful, not unique) -- the only
        # name carried on the wire. (Formerly `fullname`; the old local
        # `nickname` has been removed -- `petname` is the local name.)
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
        # Proof that THIS node may present the primary credential above: a signature
        # by the credential's own private key over bytes naming this node (see
        # identity/zta_binding.py). Empty is legitimate -- a certificate whose SAN
        # names the node is bound by its issuer instead. Fields 6-8 have nowhere to
        # carry this, so on the wire it travels inside zta_credentials (field 16).
        self.zta_credential_binding = zta_credential_binding or b''
        # The full credential set as [{'der', 'binding', 'issuer'}], including the
        # primary. ONE entry for an ordinary node; several only at a network gateway
        # bridging agencies, which must hold one per agency it bridges. Each verified
        # credential earns authority for its anchor at admission (Identity.zta_anchors,
        # written by idprocess._zta_admit) and that -- not any declared role -- is what
        # permits gateway function across an agency boundary.
        self.zta_credentials = [dict(c) for c in zta_credentials] if zta_credentials else []
        # Anchors this peer PROVED at admission, written by idprocess._zta_admit.
        # Local and derived, never advertised: a peer stating which anchors it holds
        # would be a claim, and the entire point of deriving authority is that this is
        # not one. Excluded from to_dict (below) so it cannot ride the JSON identity
        # payloads out and back in -- if it round-tripped, a peer could assert gateway
        # authority for an agency whose credential it never presented. Deliberately
        # NOT an __init__ kwarg for the same reason.
        self.zta_anchors: list = []
        # Operator-attended signal (identity.proto fields 12-13; parity with C
        # public_identity_t). operator_bound is the durable "node has a human
        # guardian" flag — advertised by the node but authoritative only after
        # the receiver verifies the operator credential at admission (see
        # idprocess._zta_admit); operator_attested_at is the live freshness
        # stamp (epoch secs of the last verified operator session, 0 = none)
        # the node self-stamps on (re)announce. Like the zta_* fields, these
        # are deliberately NOT part of __eq__ (attestation must not change
        # identity). Feeds the ethne guardian edge (ethne design D8/Q9).
        self.operator_bound = bool(operator_bound)
        self.operator_attested_at = float(operator_attested_at or 0.0)
        # WHICH human (identity.proto fields 14-15; parity with C
        # public_identity_t), and STRICTLY OPT-IN. The two fields above say a
        # human exists and when one was last present; neither names them, because
        # the operator credential is an X.509 with no ed25519 key. ethne's
        # chartered node->guardian edge (D15) needs a guardian that can co-sign,
        # so a node MAY carry `operator_pubkey` (one key per OPERATOR, stable
        # across the nodes that human guards — per-node keys would let one person
        # present as N guardians, ethne D24) together with the PIV signature over
        # operator_binding_preimage() that earns it.
        #
        # ABSENT BY DEFAULT, AND ABSENCE COSTS NOTHING. AT never requires a
        # guardian identity: a node that declines is admitted identically, keeps
        # its anonymity, and serializes byte-for-byte as before (both fields are
        # emitted only when non-default, in the canonical form and by proto3).
        # Requiring a guardian is a consumer's rule, not AT's.
        #
        # Excluded from __eq__ with the rest: re-binding must not change identity.
        self.operator_pubkey = operator_pubkey or b''
        self.operator_key_binding = operator_key_binding or b''
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

    def to_dict(self):
        # `_rank_adjustment` (AgreementVoter) is ephemeral, locally-observed
        # operational state — the dynamic one-hop-reachability delta on top of
        # the signed `_rank` (deferred.md §2.2). It is NOT part of the wire/
        # config identity: the protobuf form has no such field, and a peer's
        # reachability is the observer's view, not the subject's claim. Drop it
        # so the serialized key-set is unchanged (config_json_decoder rebuilds
        # via cls(**kwargs), so a stray key would also break the round-trip).
        # Each node re-derives the adjustment from its own observations.
        #
        # `zta_anchors` is dropped for exactly the same reason: it records the trust
        # anchors a peer PROVED to us at admission, so it is the observer's finding
        # and not the subject's claim. If it round-tripped, a peer could simply state
        # gateway authority for an agency whose credential it never presented --
        # which is the whole thing deriving authority from credentials is meant to
        # prevent. It is deliberately not an __init__ kwarg either.
        d = super().to_dict()
        d.pop('_rank_adjustment', None)
        d.pop('zta_anchors', None)
        return d

    def __eq__(self, other):
        # NB: the zta_* binding and the operator_bound/operator_attested_at
        # attestation are intentionally excluded — credential rotation and
        # operator (re)attestation update those fields but must never change
        # identity (zta-integration.md §6; ethne design D8/Q9).
        return self.__class__.__name__ == other.__class__.__name__ and self.uuid == other.uuid and \
            self.address == other.address and \
            self.nickname == other.nickname and \
            self.signature == other.signature and self.encryptor == other.encryptor

    @property
    def uuid(self):
        return self._uuid

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
        return Identity(self.uuid, self.address, self.nickname,
                        Signature(self.signature.publish(), True), Encryptor(self.encryptor.publish(), True),
                        self.petname, True, _rank=self._rank,
                        _block_impl=self._block_impl,
                        zta_credential=self.zta_credential, zta_issuer=self.zta_issuer,
                        zta_credential_hash=self.zta_credential_hash,
                        operator_bound=self.operator_bound,
                        operator_attested_at=self.operator_attested_at,
                        operator_pubkey=self.operator_pubkey,
                        operator_key_binding=self.operator_key_binding,
                        zta_credential_binding=self.zta_credential_binding,
                        zta_credentials=self.zta_credentials)

    def sync_to_message(self):
        self.message.uuid = str(self.uuid).encode('utf-8')
        self.message.address = self.address
        self.message.nickname = self._nickname
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
        # Operator-attended signal (proto fields 12-13). Proto3 scalars are
        # always present, so — unlike the optional zta_* bytes/string above —
        # these are set unconditionally (default false/0 round-trips cleanly
        # and matches the C sync_out).
        self.message.operator_bound = self.operator_bound
        self.message.operator_attested_at = self.operator_attested_at
        # The opt-in guardian identity (proto fields 14-15). Bytes, so proto3
        # omits them when empty: a node that declines puts nothing on the wire,
        # which is the wire form of the anonymity guarantee. Both travel or
        # neither does — a key with no binding is unverifiable, and a binding with
        # no key names nothing. Mirrors the C sync_out.
        if self.operator_pubkey and self.operator_key_binding:
            self.message.operator_pubkey = self.operator_pubkey
            self.message.operator_key_binding = self.operator_key_binding
        else:
            # Cleared, not merely left unset: `self.message` is reused across
            # calls, so a node that UN-binds (the operator revokes the key, or
            # rotation invalidates the binding) would otherwise keep advertising a
            # guardian it no longer has. C sync_out builds a fresh proto each call
            # and has no such state; this is what keeps the two the same. (The
            # zta_* fields above carry the same latent staleness, harmless today
            # because their rotation path always writes a new value.)
            self.message.ClearField('operator_pubkey')
            self.message.ClearField('operator_key_binding')
        # The full credential set (proto field 16), primary first. The primary is
        # emitted here as well as in fields 6-8 -- redundant by design, because those
        # fields cannot carry a binding and a peer predating this field still needs
        # them. The receiver deduplicates by fingerprint (idprocess._zta_credentials).
        # Cleared first for the same reason as the operator fields: `self.message` is
        # reused, so a node whose credential set SHRANK would otherwise keep
        # advertising the credential it dropped.
        if _HAS_ZTA_CREDENTIALS:
            self.message.ClearField('zta_credentials')
            for der, binding, issuer in self._zta_credential_tuples():
                entry = self.message.zta_credentials.add()
                entry.der = der
                if binding:
                    entry.binding = binding
                if issuer:
                    entry.issuer = issuer

    def _zta_credential_tuples(self):
        """``[(der, binding, issuer)]`` for the wire, primary first, deduplicated by
        fingerprint over the actual bytes so listing the primary in
        ``zta_credentials`` too does not emit it twice."""
        out, seen = [], set()

        def _add(der, binding, issuer):
            der = bytes(der or b'')
            if not der:
                return
            fp = hashlib.sha256(der).digest()
            if fp in seen:
                return
            seen.add(fp)
            out.append((der, bytes(binding or b''), issuer or ''))

        _add(self.zta_credential, self.zta_credential_binding, self.zta_issuer)
        for cred in self.zta_credentials:
            _add(cred.get('der') or cred.get('credential'),
                 cred.get('binding'), cred.get('issuer'))
        return out

    def sync_from_message(self):
        self._uuid = self.message.uuid.decode('utf-8')
        self.address = self.message.address
        self._nickname = self.message.nickname
        # petname is local-only and never on the wire -- assign our own.
        self.petname = derive_local_petname(self._nickname)
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
        # Operator-attended signal (proto fields 12-13); parity with C sync_in.
        self.operator_bound = bool(self.message.operator_bound)
        self.operator_attested_at = float(self.message.operator_attested_at)
        # The guardian CLAIM (proto fields 14-15); parity with C sync_in. A key of
        # the wrong length is dropped whole rather than kept as a truncated (i.e.
        # different) key, and nothing here is verified: that happens in
        # _zta_admit, against the operator anchor.
        key = bytes(self.message.operator_pubkey)
        self.operator_pubkey = key if len(key) == OPERATOR_PUBKEY_LEN else b''
        binding = bytes(self.message.operator_key_binding)
        self.operator_key_binding = (
            binding if 0 < len(binding) <= OPERATOR_BINDING_MAX else b'')
        # The full credential set (proto field 16). Nothing is verified here --
        # _zta_admit walks the chains, checks each binding, and decides. An
        # oversized binding is dropped now, on the same reasoning as the operator
        # one above: it can only be corrupt or hostile, and carrying it forward
        # would just hand a bigger blob to the verifier.
        self.zta_credentials = []
        if _HAS_ZTA_CREDENTIALS:
            for entry in self.message.zta_credentials:
                der = bytes(entry.der)
                if not der:
                    continue
                cred_binding = bytes(entry.binding)
                if len(cred_binding) > ZTA_BINDING_MAX:
                    cred_binding = b''
                self.zta_credentials.append({'der': der, 'binding': cred_binding,
                                             'issuer': entry.issuer})
        # Recover the PRIMARY's binding: fields 6-8 cannot carry one, so it arrives
        # in the matching field-16 entry. Also promote the first entry to primary for
        # a peer that sent only field 16 (nothing does today, but reading the wire
        # form that way costs nothing and means the two can never disagree).
        self.zta_credential_binding = b''
        primary_fp = (hashlib.sha256(self.zta_credential).digest()
                      if self.zta_credential else None)
        for cred in self.zta_credentials:
            if primary_fp is None:
                self.zta_credential = cred['der']
                self.zta_credential_binding = cred['binding']
                self.zta_issuer = self.zta_issuer or cred['issuer']
                break
            if hashlib.sha256(cred['der']).digest() == primary_fp:
                self.zta_credential_binding = cred['binding']
                break

    @staticmethod
    def initialize(my_name, my_nickname, my_address):
        # my_name -> online nickname; my_nickname -> local petname.
        if '/' in my_address:
            my_address = my_address.split('/')[0]
        time.sleep(secrets.randbelow(1000) / 1000.0)  # reduce chance of collision
        return Identity(uuid_mod.uuid4(), my_address, my_name,
                        Signature.generate(), Encryptor.generate(), my_nickname, False)


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
    d = {
        'typename': 'identity',
        'uuid': str(identity.uuid),
        'address': getattr(identity, 'address', '') or '',
        'nickname': getattr(identity, 'nickname', '') or '',
        # petname is a Zooko local name -- never serialized (omitted here to
        # match C public_identity_to_json so the canonical form stays
        # byte-identical cross-runtime).
        'signature': {'hex_seed': identity.signature.publish().decode('ascii')},
        'encryptor': {'hex_seed': identity.encryptor.publish().decode('ascii')},
    }
    # Operator-attended signal + the ZTA binding that backs it. Emitted ONLY
    # when non-default so a plain (non-operator) peer's canonical form is
    # byte-identical to before (backward-compat for existing peer bundles). C
    # public_identity_to_json omits the same keys under the same condition, so
    # the cross-runtime form stays symmetric. Bytes are base64 (standard, no
    # newline); operator_attested_at is a JSON number. Keys are inserted in a
    # fixed order; the conformance diff compares JCS-canonical (key-sorted) so
    # order is not load-bearing, but we keep it stable for readability.
    if getattr(identity, 'operator_bound', False):
        d['operator_bound'] = True
    attested = float(getattr(identity, 'operator_attested_at', 0.0) or 0.0)
    if attested:
        d['operator_attested_at'] = attested
    issuer = getattr(identity, 'zta_issuer', '') or ''
    if issuer:
        d['zta_issuer'] = issuer
    cred_hash = getattr(identity, 'zta_credential_hash', b'') or b''
    if cred_hash:
        d['zta_credential_hash'] = base64.b64encode(bytes(cred_hash)).decode('ascii')
    cred = getattr(identity, 'zta_credential', b'') or b''
    if cred:
        d['zta_credential'] = base64.b64encode(bytes(cred)).decode('ascii')
    # The opt-in guardian identity, emitted only when a key is actually bound —
    # so a node that declines produces exactly the bytes it produced before these
    # fields existed. That is AT's side of the anonymity guarantee, at the byte
    # level, and it is pinned by a test rather than asserted here. Both keys
    # appear together or not at all (see sync_to_message).
    op_key = getattr(identity, 'operator_pubkey', b'') or b''
    op_binding = getattr(identity, 'operator_key_binding', b'') or b''
    if op_key and op_binding:
        d['operator_pubkey'] = base64.b64encode(bytes(op_key)).decode('ascii')
        d['operator_key_binding'] = base64.b64encode(bytes(op_binding)).decode('ascii')
    return d


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
        # petname intentionally NOT read from the wire form: it is a local-only
        # Zooko name. A receiver assigns its own petname locally (see
        # derive_local_petname).
        nickname = d.get('nickname', '') or ''
        # Operator-attended signal + ZTA binding (all optional; absent =>
        # default false/0/empty, so an old peer or a plain non-operator peer
        # reconstructs unchanged). Bytes are base64 (mirror of to_canonical).
        operator_bound = bool(d.get('operator_bound', False))
        operator_attested_at = float(d.get('operator_attested_at', 0.0) or 0.0)
        zta_issuer = d.get('zta_issuer', '') or ''
        cred_hash_b64 = d.get('zta_credential_hash', '') or ''
        cred_b64 = d.get('zta_credential', '') or ''
        zta_credential_hash = base64.b64decode(cred_hash_b64) if cred_hash_b64 else b''
        zta_credential = base64.b64decode(cred_b64) if cred_b64 else b''
        # The guardian claim, imported as a claim. A key of the wrong length is
        # dropped whole (a truncated ed25519 key is a different key) and an
        # oversized binding is refused; nothing here is verified — that happens at
        # admission, against the operator anchor.
        op_key_b64 = d.get('operator_pubkey', '') or ''
        op_binding_b64 = d.get('operator_key_binding', '') or ''
        operator_pubkey = base64.b64decode(op_key_b64) if op_key_b64 else b''
        operator_key_binding = base64.b64decode(op_binding_b64) if op_binding_b64 else b''
        if len(operator_pubkey) != OPERATOR_PUBKEY_LEN:
            operator_pubkey = b''
        if not 0 < len(operator_key_binding) <= OPERATOR_BINDING_MAX:
            operator_key_binding = b''
        return Identity(d['uuid'], d.get('address', '') or '',
                        nickname,
                        sig, enc, derive_local_petname(nickname),
                        zta_credential=zta_credential, zta_issuer=zta_issuer,
                        zta_credential_hash=zta_credential_hash,
                        operator_bound=operator_bound,
                        operator_attested_at=operator_attested_at,
                        operator_pubkey=operator_pubkey,
                        operator_key_binding=operator_key_binding)
    except (ValueError, TypeError, RuntimeError, KeyError):
        return None
