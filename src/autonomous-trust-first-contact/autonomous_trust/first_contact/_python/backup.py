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
"""An encrypted backup of the address book, for a lost device
(FIRST_CONTACT_PLAN Phase 4, recovery).

A backup is a small JSON file, safe to keep anywhere (a cloud drive, a USB
stick, an email to yourself):

    {typename: "at-backup", v: 1,
     kdf: "argon2id13", ops: 3, mem: 268435456, salt: <32 hex>,
     aead: "xchacha20poly1305-ietf", nonce: <48 hex>,
     ct: <base64>}

The key is Argon2id (libsodium ``crypto_pwhash``) over the passphrase and
``salt``; ``ct`` is XChaCha20-Poly1305 of the contents under that key and
``nonce``, with :func:`header_ad` -- every header field, in a fixed order --
as the associated data, so no parameter can be changed without the open
failing. ``ops`` and ``mem`` are stored so later backups can be made harder
without breaking older ones; an open refuses values outside
:data:`OPS_RANGE` / :data:`MEM_RANGE` rather than spend a gigabyte on a
crafted file.

The contents, once opened:

    {typename: "at-backup-contents", v: 1, created_at: <epoch>,
     contacts: <contacts/sync payload: every contact and tombstone>,
     siblings: <siblings.cfg.json canonical form>,
     operator_key: <hex seed>}        # only from tools/backup.py, on request

A node never puts the operator key in a backup and never reads one out
(``operator/activate.py``: a node that can read the key can impersonate its
human on every device). Only the operator-side tool ``tools/backup.py`` does.

A restore is a merge, never a replace (:func:`restore`): the address book
goes through :func:`.sync.merge`, so an edit made on the new device before
the restore survives, a verified contact stays verified (provenance
``backup``, its original ``verified_at``) and a tombstone keeps a removal
removed. The siblings are added to this node's own list when its device cert
names the same operator; they do not know the new device yet, so the user
pairs again to resume syncing.

The passphrase is the user's (at least :data:`PASSPHRASE_MIN` characters),
or one :func:`generate_passphrase` makes: 24 base32 characters (120 bits) in
groups of four. A passphrase in that shape is upper-cased and its separators
set to ``-`` before the key is derived, so the code can be typed in lower case
or with single spaces. Same format and rules as C's ``contacts/backup.{h,c}``.
"""
import base64
import binascii
import json
import os
import re
import secrets
import time

import nacl.bindings as _sodium
import nacl.exceptions
import nacl.pwhash

from .contact import Provenance
from .siblings import Siblings
from . import sync as _sync

BACKUP_TYPENAME = 'at-backup'
CONTENTS_TYPENAME = 'at-backup-contents'
VERSION = 1
KDF = 'argon2id13'
AEAD = 'xchacha20poly1305-ietf'

#: What a backup is made with: libsodium's MODERATE (3 passes, 256 MiB).
OPS_DEFAULT = nacl.pwhash.argon2id.OPSLIMIT_MODERATE
MEM_DEFAULT = nacl.pwhash.argon2id.MEMLIMIT_MODERATE
#: What an open accepts, inclusive. The floor is libsodium's own; the ceiling
#: is libsodium's SENSITIVE memory (1 GiB) and 10 passes.
OPS_RANGE = (1, 10)
MEM_RANGE = (8192, 1 << 30)

SALT_BYTES = 16
NONCE_BYTES = 24
KEY_BYTES = 32
TAG_BYTES = 16
#: The largest ciphertext an open reads: far above any address book (eight
#: devices a contact, every contact at most a few KB).
CT_MAX = 16 << 20

#: Shortest passphrase a backup is made with, in characters.
PASSPHRASE_MIN = 12

#: Why a seal or an open did not happen. Index = C's at_backup_reason_t.
REASONS = ('', 'malformed', 'unsupported', 'bad_passphrase', 'weak_passphrase')

_B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
_HEX = set('0123456789abcdef')
_CODE = re.compile(r'^[A-Za-z2-7]{4}([- ][A-Za-z2-7]{4}){5}$')


class BackupError(ValueError):
    """A backup that could not be made or opened; ``reason`` is one of
    :data:`REASONS`."""

    def __init__(self, reason, msg=''):
        super().__init__(msg or reason)
        self.reason = reason


def generate_passphrase() -> str:
    """A fresh 120-bit code for the user to write down:
    ``XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`` in base32 (A-Z, 2-7)."""
    bits = int.from_bytes(secrets.token_bytes(15), 'big')
    chars = [_B32[(bits >> (5 * i)) & 31] for i in range(23, -1, -1)]
    return '-'.join(''.join(chars[i:i + 4]) for i in range(0, 24, 4))


def normalize_passphrase(passphrase: str) -> str:
    """What the key is derived from: a generated code's shape is upper-cased
    with ``-`` separators; anything else is taken as typed."""
    if _CODE.fullmatch(passphrase):
        return '-'.join(re.split(r'[- ]', passphrase.upper()))
    return passphrase


def check_passphrase(passphrase) -> None:
    """Raise ``weak_passphrase`` unless ``passphrase`` may make a backup."""
    if not isinstance(passphrase, str) or len(passphrase) < PASSPHRASE_MIN:
        raise BackupError('weak_passphrase',
                          'a backup passphrase has at least %d characters' % PASSPHRASE_MIN)


def header_ad(ops, mem, salt_hex, nonce_hex) -> bytes:
    """The associated data: every header field, in a fixed order."""
    return ('at-backup-v%d|%s|%d|%d|%s|%s|%s' % (
        VERSION, KDF, ops, mem, salt_hex, AEAD, nonce_hex)).encode('ascii')


def _derive(passphrase, salt, ops, mem) -> bytes:
    return nacl.pwhash.argon2id.kdf(
        KEY_BYTES, normalize_passphrase(passphrase).encode('utf-8'), salt,
        opslimit=ops, memlimit=mem)


def seal_bytes(plaintext: bytes, passphrase: str, ops=None, mem=None,
               salt=None, nonce=None) -> dict:
    """Encrypt ``plaintext`` into a backup header + ``ct``. ``ops`` / ``mem``
    default to :data:`OPS_DEFAULT` / :data:`MEM_DEFAULT` as they are at the
    call; ``salt`` and ``nonce`` are random unless given (fixed only for test
    vectors)."""
    check_passphrase(passphrase)
    ops = OPS_DEFAULT if ops is None else ops
    mem = MEM_DEFAULT if mem is None else mem
    if not (OPS_RANGE[0] <= ops <= OPS_RANGE[1] and MEM_RANGE[0] <= mem <= MEM_RANGE[1]):
        raise BackupError('unsupported', 'KDF parameters out of range')
    salt = os.urandom(SALT_BYTES) if salt is None else bytes(salt)
    nonce = os.urandom(NONCE_BYTES) if nonce is None else bytes(nonce)
    if len(salt) != SALT_BYTES or len(nonce) != NONCE_BYTES:
        raise BackupError('malformed', 'salt or nonce of the wrong length')
    salt_hex, nonce_hex = salt.hex(), nonce.hex()
    key = _derive(passphrase, salt, ops, mem)
    ct = _sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, header_ad(ops, mem, salt_hex, nonce_hex), nonce, key)
    return {'typename': BACKUP_TYPENAME, 'v': VERSION,
            'kdf': KDF, 'ops': int(ops), 'mem': int(mem), 'salt': salt_hex,
            'aead': AEAD, 'nonce': nonce_hex,
            'ct': base64.b64encode(ct).decode('ascii')}


def _int(v):
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _hex(v, n):
    if not isinstance(v, str) or len(v) != 2 * n or not set(v) <= _HEX:
        return None
    return bytes.fromhex(v)


def open_bytes(blob, passphrase: str) -> bytes:
    """The plaintext of the backup ``blob`` (its JSON text, or the parsed
    object). Raises :class:`BackupError`: ``malformed`` (not a backup),
    ``unsupported`` (another version, algorithm, or parameters out of range),
    ``bad_passphrase`` (the open failed: a wrong passphrase, or a file
    changed since it was made -- the two cannot be told apart)."""
    if isinstance(blob, (str, bytes)):
        try:
            blob = json.loads(blob)
        except ValueError:
            raise BackupError('malformed', 'not JSON') from None
    if not isinstance(blob, dict) or blob.get('typename') != BACKUP_TYPENAME:
        raise BackupError('malformed', 'not an AT backup')
    if _int(blob.get('v')) != VERSION or blob.get('kdf') != KDF \
            or blob.get('aead') != AEAD:
        raise BackupError('unsupported', 'another backup version or algorithm')
    ops, mem = _int(blob.get('ops')), _int(blob.get('mem'))
    if ops is None or mem is None:
        raise BackupError('malformed', 'KDF parameters are not integers')
    if not (OPS_RANGE[0] <= ops <= OPS_RANGE[1] and MEM_RANGE[0] <= mem <= MEM_RANGE[1]):
        raise BackupError('unsupported', 'KDF parameters out of range')
    salt, nonce = _hex(blob.get('salt'), SALT_BYTES), _hex(blob.get('nonce'), NONCE_BYTES)
    ct_b64 = blob.get('ct')
    if salt is None or nonce is None or not isinstance(ct_b64, str) \
            or len(ct_b64) > (CT_MAX // 3 + 1) * 4:
        raise BackupError('malformed', 'bad salt, nonce or ciphertext')
    try:
        ct = base64.b64decode(ct_b64, validate=True)
    except (binascii.Error, ValueError):
        raise BackupError('malformed', 'ciphertext is not base64') from None
    if len(ct) < TAG_BYTES:
        raise BackupError('malformed', 'ciphertext too short')
    if not isinstance(passphrase, str) or not passphrase:
        raise BackupError('bad_passphrase')
    key = _derive(passphrase, salt, ops, mem)
    try:
        return _sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            ct, header_ad(ops, mem, blob['salt'], blob['nonce']), nonce, key)
    except nacl.exceptions.CryptoError:
        raise BackupError('bad_passphrase', 'wrong passphrase, or the file was changed') from None


# -- the contents ----------------------------------------------------------------

def build_contents(store, siblings=None, operator_key='', now=None) -> dict:
    """What a backup holds: the whole address book (tombstones included), the
    sibling list, and -- only when the operator-side tool passes it -- the
    operator key's hex seed."""
    out = {'typename': CONTENTS_TYPENAME, 'v': VERSION,
           'created_at': float(now if now is not None else time.time()),
           'contacts': _sync.build(store)}
    if siblings is not None and len(siblings):
        out['siblings'] = siblings.to_canonical()
    if operator_key:
        out['operator_key'] = str(operator_key)
    return out


def seal(contents: dict, passphrase: str, **kw) -> str:
    """The backup file's text for ``contents``."""
    plaintext = json.dumps(contents, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return json.dumps(seal_bytes(plaintext, passphrase, **kw), indent=2, sort_keys=True)


def open_contents(blob, passphrase: str) -> dict:
    """The contents of ``blob``; raises :class:`BackupError` as
    :func:`open_bytes` does, and ``malformed`` when what decrypts is not a
    backup's contents."""
    plaintext = open_bytes(blob, passphrase)
    try:
        contents = json.loads(plaintext.decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        raise BackupError('malformed', 'the contents are not JSON') from None
    if not isinstance(contents, dict) or contents.get('typename') != CONTENTS_TYPENAME \
            or _int(contents.get('v')) != VERSION \
            or not isinstance(contents.get('contacts'), dict):
        raise BackupError('malformed', 'not a backup\'s contents')
    return contents


def restore(store, siblings, contents, own_cert=None, own_uuid='', now=None):
    """Fold opened ``contents`` into ``store`` and ``siblings``. Returns
    ``(changes, paired)``: :func:`.sync.merge`'s change list (new contacts as
    provenance ``backup``), and the uuids added to ``siblings``.

    The backed-up siblings are this user's devices, never contacts, whatever
    ``siblings`` makes of them; each is added only if ``own_cert`` names the
    same operator (:meth:`.Siblings.add`), with its hints. ``siblings`` is
    left alone without a cert of our own. Raises :class:`BackupError`
    (``malformed``) when the address book in it is not a sync payload."""
    backed = Siblings.from_canonical(contents.get('siblings'))
    exclude = [str(own_uuid)] if own_uuid else []
    exclude += siblings.uuids() if siblings is not None else []
    exclude += backed.uuids()
    try:
        changes = _sync.merge(store, contents['contacts'], now=now, exclude=exclude,
                              provenance=Provenance.backup)
    except _sync.InvalidSync as err:
        raise BackupError('malformed', str(err)) from None
    paired = []
    if siblings is not None and own_cert is not None:
        for dev in backed.devices:
            if dev.uuid in siblings:
                continue
            if siblings.add(dev.identity, dev.cert, own_cert) == '' \
                    and dev.uuid in siblings:
                if backed.hints.get(dev.uuid):
                    siblings.set_hints(dev.uuid, backed.hints[dev.uuid])
                if backed.reach_seq.get(dev.uuid):
                    siblings.reach_seq[dev.uuid] = backed.reach_seq[dev.uuid]
                paired.append(dev.uuid)
    return changes, paired
