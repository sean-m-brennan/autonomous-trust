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
"""One human, several devices (FIRST_CONTACT_PLAN Phase 4).

Every device is its own node, with its own uuid and keys that never leave it.
What says two devices belong to one person is that person's **operator key**
(the ed25519 key in their operator keystore, operator/activate.py), which signs
a certificate for each device:

    DeviceCert := sign_Operator("at-device-v1|" + body)
    body       := {v, typename: "at-device-cert", operator, uuid, key, issued_at}

``key`` is the device node's ed25519 signing key and ``uuid`` its uuid, so the
cert cannot be lifted onto another node. No PIV, X.509 or CA is involved in
checking it: the operator key is only trusted because a device the user
already VERIFIED presented a cert under it (:func:`adopt_operator`). From
then on a new device with a cert under the same key joins that contact
(:func:`link_device`), verified, because the safety number Bob compared vouched
for the human, and the human vouches for the device. Earned reputation does not
move with it; only the contact's trust seed does.

Signatures cover the EXACT transmitted body string behind a domain prefix, as
invitations, reach records and directory entries do. Same format and rules as
C's ``contacts/device.{h,c}``.
"""
import time

from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

from .directory import (InvalidEntry, _split, _check_sig, _sign, _is_hex_key,
                        _is_int)

DEVICE_DOMAIN = 'at-device-v1|'
DEVICE_TYPENAME = 'at-device-cert'
VERSION = 1

#: Most devices one contact lists besides its first. Same as C's AT_CONTACT_DEVICES_MAX.
DEVICES_MAX = 8

#: Why a cert, an adoption or a link was refused. Index = C's -at_device_status_t.
REASONS = ('', 'malformed', 'bad_signature', 'mismatch', 'unknown_operator',
           'unverified', 'known', 'full')


class InvalidDevice(ValueError):
    """A device cert that is malformed or forged, or a link the rules refuse.
    ``reason`` is one of :data:`REASONS`."""

    def __init__(self, message, reason='malformed'):
        super().__init__(message)
        self.reason = reason


def signing_key_hex(identity) -> str:
    """``identity``'s ed25519 public signing key, lowercase hex."""
    return bytes(identity.signature.public).hex()


class DeviceCert:
    """An operator's word that the node ``uuid`` with signing ``key`` is theirs."""

    def __init__(self, body, body_str, sig_hex):
        self.body, self.body_str, self.sig_hex = body, body_str, sig_hex

    operator = property(lambda self: self.body.get('operator'))
    uuid = property(lambda self: self.body.get('uuid'))
    key = property(lambda self: self.body.get('key'))
    issued_at = property(lambda self: self.body.get('issued_at'))

    @classmethod
    def from_wire(cls, obj):
        try:
            body, body_str, sig_hex = _split(obj)
        except InvalidEntry as err:
            raise InvalidDevice(str(err)) from err
        return cls(body, body_str, sig_hex)

    def to_wire(self):
        return {'body': self.body_str, 'sig': self.sig_hex}

    def verify(self):
        """Raise :class:`InvalidDevice` unless well formed and signed by its
        operator. Returns self. A cert does not expire: it is withdrawn, not
        outlived."""
        b = self.body
        if b.get('typename') != DEVICE_TYPENAME or not _is_int(b.get('v')) \
                or b['v'] != VERSION:
            raise InvalidDevice('not a version-%d AT device cert' % VERSION)
        if not _is_hex_key(b.get('operator')) or not _is_hex_key(b.get('key')):
            raise InvalidDevice('device cert operator or key is not a hex key')
        if not isinstance(b.get('uuid'), str) or b['uuid'] != b['uuid'].lower() \
                or len(b['uuid']) != 36:
            raise InvalidDevice('device cert uuid is not a lowercase uuid')
        if not _is_int(b.get('issued_at')) or b['issued_at'] < 0:
            raise InvalidDevice('device cert has no issue time')
        try:
            _check_sig(b['operator'], DEVICE_DOMAIN, self.body_str, self.sig_hex)
        except InvalidEntry as err:
            raise InvalidDevice(str(err), 'bad_signature') from err
        return self

    def names(self, identity) -> bool:
        """Whether this cert is for ``identity`` (its uuid and signing key)."""
        return self.uuid == str(identity.uuid).lower() \
            and self.key == signing_key_hex(identity)


def create_device_cert(operator_key, identity, issued_at=None) -> DeviceCert:
    """The cert ``operator_key`` (a nacl SigningKey, or its hex seed) gives the
    node ``identity``. For the operator's own tooling: the key never enters a
    node's config."""
    if not isinstance(operator_key, SigningKey):
        seed = operator_key.encode('ascii') if isinstance(operator_key, str) else operator_key
        operator_key = SigningKey(seed, encoder=HexEncoder)
    body = {'v': VERSION, 'typename': DEVICE_TYPENAME,
            'operator': operator_key.verify_key.encode(HexEncoder).decode('ascii'),
            'uuid': str(identity.uuid).lower(), 'key': signing_key_hex(identity),
            'issued_at': int(issued_at if issued_at is not None else time.time())}
    signed = _sign(operator_key, DEVICE_DOMAIN, body)
    return DeviceCert.from_wire(signed)


class Device:
    """One more device of a contact: its public identity, the cert that
    links it, and when it was linked."""

    def __init__(self, identity, cert, added_at=0.0):
        if not getattr(identity, '_public_only', True):
            identity = identity.publish()
        self.identity = identity
        self.cert = cert
        self.added_at = float(added_at) or time.time()

    @property
    def uuid(self):
        return str(self.identity.uuid)

    def to_canonical(self):
        from ..identity.identity import public_identity_to_canonical
        return {'identity': public_identity_to_canonical(self.identity),
                'cert': self.cert.to_wire(), 'added_at': float(self.added_at)}

    @classmethod
    def from_canonical(cls, d):
        """None unless the record is well formed AND its cert still verifies
        for its identity: a hand-edited store must not smuggle a device in."""
        from ..identity.identity import public_identity_from_canonical
        if not isinstance(d, dict):
            return None
        identity = public_identity_from_canonical(d.get('identity'))
        if identity is None:
            return None
        try:
            cert = DeviceCert.from_wire(d.get('cert')).verify()
        except InvalidDevice:
            return None
        if not cert.names(identity):
            return None
        return cls(identity, cert, float(d.get('added_at', 0.0) or 0.0))


def adopt_operator(contact, cert, store=None) -> str:
    """Learn ``contact``'s operator key from a cert its own (first) device
    presented. Returns '' on success, else a reason from :data:`REASONS`.

    Only the contact's own node can introduce its operator: the cert must name
    that exact identity. An operator key, once learned, does not change, and
    belongs to one contact in ``store`` (``known`` otherwise), so a link always
    has exactly one place to go.
    """
    try:
        cert = cert if isinstance(cert, DeviceCert) else DeviceCert.from_wire(cert)
        cert.verify()
    except InvalidDevice as err:
        return err.reason
    if not cert.names(contact.identity):
        return 'mismatch'
    if contact.operator_key and contact.operator_key != cert.operator:
        return 'mismatch'
    if store is not None:
        holder = store.by_operator(cert.operator)
        if holder is not None and holder.uuid != contact.uuid:
            return 'known'
    if contact.operator_key != cert.operator:
        contact.operator_key = cert.operator
        contact.touch()
    return ''


def link_device(store, identity, cert):
    """File ``identity`` as another device of the contact whose operator
    signed ``cert``. Returns ``(contact, '')``, or ``(None, reason)``.

    The rules, each closing a hole:
      - the cert verifies and names ``identity`` (uuid + key): else anyone's
        cert would admit anyone (``bad_signature`` / ``mismatch``);
      - some contact already holds that operator key (``unknown_operator``);
      - that contact is VERIFIED (``unverified``): the link carries
        verification over, so there must be verification to carry;
      - the device is not already some other contact (``known``): merging
        two records is the user's call, not the node's;
      - at most :data:`DEVICES_MAX` extra devices (``full``).
    Linking a device the contact already lists is a no-op success.
    """
    try:
        cert = cert if isinstance(cert, DeviceCert) else DeviceCert.from_wire(cert)
        cert.verify()
    except InvalidDevice as err:
        return None, err.reason
    if not cert.names(identity):
        return None, 'mismatch'
    contact = store.by_operator(cert.operator)
    if contact is None:
        return None, 'unknown_operator'
    uuid = str(identity.uuid)
    if uuid == contact.uuid or uuid in contact.device_uuids():
        return contact, ''
    if uuid in store:
        return None, 'known'
    if not contact.verified:
        return None, 'unverified'
    if len(contact.devices) >= DEVICES_MAX:
        return None, 'full'
    contact.devices.append(Device(identity, cert))
    contact.touch()
    store.reindex()
    return contact, ''
