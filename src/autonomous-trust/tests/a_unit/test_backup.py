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
"""Phase 4, recovery: the encrypted backup (contacts/backup.py) and its app
verbs (identity/backup_contact.py). The node tests reuse test_sibling_sync's
per-node roots and router; Argon2id runs at libsodium's minimum except where
the default parameters themselves are under test."""
import base64
import importlib.util
import json
import os
import stat

import pytest
from nacl.signing import SigningKey

from autonomous_trust.core.system import CfgIds
from autonomous_trust.core.config import Configuration
from autonomous_trust.core.network.message import Message
from autonomous_trust.core.identity.protocol import IdentityProtocol
from autonomous_trust.core.contacts import Contact, Contacts, Siblings, backup as bk
from autonomous_trust.core.contacts.contact import Provenance
from autonomous_trust.core.identity import first_contact as fc
from autonomous_trust.core._python.identity import backup_contact as bc
from autonomous_trust.core._python.identity import device_contact as dc
from autonomous_trust.core._python.identity import sibling_sync as ss

_spec = importlib.util.spec_from_file_location(
    '_sibling_helpers', os.path.join(os.path.dirname(__file__), 'test_sibling_sync.py'))
_h = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_h)

PASS = 'correct horse battery staple'
FAST = dict(ops=1, mem=8192)


class Node(_h.Node):
    def app(self, verb, payload):
        handler = {bc.APP_BACKUP_EXPORT: bc.handle_app_backup_export,
                   bc.APP_BACKUP_IMPORT: bc.handle_app_backup_import}.get(verb)
        if handler is None:
            return super().app(verb, payload)
        msg = Message(CfgIds.identity, verb, json.dumps(payload),
                      to_whom=None, from_whom=None, encrypt=False)
        return self.call(handler, msg)

    def last(self, kind=None):
        evs = [e for e in self.drain_events() if kind is None or e.kind == kind]
        return evs[-1] if evs else None


@pytest.fixture(autouse=True)
def _restore_root():
    before = os.environ.get(Configuration.ROOT_VARIABLE_NAME)
    yield
    if before is None:
        os.environ.pop(Configuration.ROOT_VARIABLE_NAME, None)
    else:
        os.environ[Configuration.ROOT_VARIABLE_NAME] = before


@pytest.fixture
def fast_kdf(monkeypatch):
    monkeypatch.setattr(bk, 'OPS_DEFAULT', FAST['ops'])
    monkeypatch.setattr(bk, 'MEM_DEFAULT', FAST['mem'])


@pytest.fixture
def operator():
    return SigningKey.generate()


@pytest.fixture
def phone(tmp_path):
    return Node(tmp_path, 'alice-phone', '10.0.0.1')


@pytest.fixture
def laptop(tmp_path):
    return Node(tmp_path, 'alice-laptop', '10.0.0.3')


@pytest.fixture
def new_phone(tmp_path):
    return Node(tmp_path, 'alice-new-phone', '10.0.0.4')


@pytest.fixture
def bob(tmp_path):
    return Node(tmp_path, 'bob', '10.0.0.2')


# -- the format -------------------------------------------------------------------

def test_seal_and_open():
    blob = bk.seal_bytes(b'the book', PASS, **FAST)
    assert blob['typename'] == 'at-backup' and blob['v'] == 1
    assert blob['kdf'] == 'argon2id13' and blob['aead'] == 'xchacha20poly1305-ietf'
    assert len(bytes.fromhex(blob['salt'])) == 16 and len(bytes.fromhex(blob['nonce'])) == 24
    assert bk.open_bytes(blob, PASS) == b'the book'
    assert bk.open_bytes(json.dumps(blob), PASS) == b'the book'
    # Fresh salt and nonce each time.
    again = bk.seal_bytes(b'the book', PASS, **FAST)
    assert again['salt'] != blob['salt'] and again['nonce'] != blob['nonce']


def test_the_default_is_moderate_argon2id():
    assert (bk.OPS_DEFAULT, bk.MEM_DEFAULT) == (3, 256 << 20)
    blob = bk.seal_bytes(b'x', PASS)
    assert (blob['ops'], blob['mem']) == (3, 256 << 20)
    assert bk.open_bytes(blob, PASS) == b'x'


#: Fixed salt (00..0f), nonce (10..27), ops 1, mem 8192, passphrase PASS,
#: plaintext b'at backup vector'. C's contacts/backup test pins the same.
VECTOR_CT_B64 = '4l6LixkmgAPxRgX5dYgekx/XCaGKa/K6vivH8Albd3g='


def _vector():
    return bk.seal_bytes(b'at backup vector', PASS, **FAST, salt=bytes(range(16)),
                         nonce=bytes(range(16, 40)))


def test_a_fixed_vector_is_stable():
    blob = _vector()
    assert blob['ct'] == VECTOR_CT_B64
    assert bk.header_ad(1, 8192, blob['salt'], blob['nonce']) == (
        b'at-backup-v1|argon2id13|1|8192|000102030405060708090a0b0c0d0e0f|'
        b'xchacha20poly1305-ietf|'
        b'101112131415161718191a1b1c1d1e1f2021222324252627')


def test_a_wrong_passphrase_or_any_change_fails_alike():
    blob = bk.seal_bytes(b'the book', PASS, **FAST)
    with pytest.raises(bk.BackupError) as err:
        bk.open_bytes(blob, PASS + '!')
    assert err.value.reason == 'bad_passphrase'
    # Every header field is in the associated data.
    for field, value in (('ops', 2), ('mem', 16384),
                         ('salt', '00' * 16), ('nonce', '00' * 24)):
        changed = dict(blob, **{field: value})
        with pytest.raises(bk.BackupError) as err:
            bk.open_bytes(changed, PASS)
        assert err.value.reason == 'bad_passphrase', field
    ct = bytearray(base64.b64decode(blob['ct']))
    ct[0] ^= 1
    with pytest.raises(bk.BackupError) as err:
        bk.open_bytes(dict(blob, ct=base64.b64encode(bytes(ct)).decode()), PASS)
    assert err.value.reason == 'bad_passphrase'
    with pytest.raises(bk.BackupError) as err:
        bk.open_bytes(blob, '')
    assert err.value.reason == 'bad_passphrase'


@pytest.mark.parametrize('change, reason', [
    ({'typename': 'at-contacts-sync'}, 'malformed'),
    ({'v': 2}, 'unsupported'),
    ({'v': True}, 'unsupported'),
    ({'kdf': 'scrypt'}, 'unsupported'),
    ({'aead': 'aes256gcm'}, 'unsupported'),
    ({'ops': 0}, 'unsupported'),
    ({'ops': 11}, 'unsupported'),
    ({'mem': 4096}, 'unsupported'),
    ({'mem': (1 << 30) + 1}, 'unsupported'),
    ({'ops': True}, 'malformed'),
    ({'mem': 8192.0}, 'malformed'),
    ({'salt': '00' * 15}, 'malformed'),
    ({'salt': 'AB' * 16}, 'malformed'),
    ({'nonce': 'zz' * 24}, 'malformed'),
    ({'ct': 'not base64!'}, 'malformed'),
    ({'ct': base64.b64encode(b'short').decode()}, 'malformed'),
    ({'ct': 7}, 'malformed'),
])
def test_what_an_open_refuses(change, reason):
    blob = dict(bk.seal_bytes(b'the book', PASS, **FAST), **change)
    with pytest.raises(bk.BackupError) as err:
        bk.open_bytes(blob, PASS)
    assert err.value.reason == reason


def test_not_json_is_malformed():
    for text in ('', 'nope', '[]', '{"typename": "at-backup"'):
        with pytest.raises(bk.BackupError) as err:
            bk.open_bytes(text, PASS)
        assert err.value.reason in ('malformed', 'unsupported')


def test_the_passphrase_floor_counts_characters():
    with pytest.raises(bk.BackupError) as err:
        bk.seal_bytes(b'x', 'a' * 11, **FAST)
    assert err.value.reason == 'weak_passphrase'
    # Twelve characters, 24 bytes of UTF-8.
    assert bk.open_bytes(bk.seal_bytes(b'x', 'é' * 12, **FAST), 'é' * 12) == b'x'
    with pytest.raises(bk.BackupError) as err:
        bk.seal_bytes(b'x', b'bytes are not a passphrase', **FAST)
    assert err.value.reason == 'weak_passphrase'


def test_out_of_range_parameters_are_not_sealed():
    with pytest.raises(bk.BackupError) as err:
        bk.seal_bytes(b'x', PASS, ops=11, mem=8192)
    assert err.value.reason == 'unsupported'


def test_a_generated_code_and_its_typing():
    code = bk.generate_passphrase()
    groups = code.split('-')
    assert len(groups) == 6 and all(len(g) == 4 for g in groups)
    assert set(code.replace('-', '')) <= set('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')
    assert bk.generate_passphrase() != code
    blob = bk.seal_bytes(b'x', code, **FAST)
    for typed in (code.lower(), code.replace('-', ' '), code.lower().replace('-', ' ')):
        assert bk.open_bytes(blob, typed) == b'x'
    # Only that exact shape is folded; anything else is taken as typed.
    assert bk.normalize_passphrase('abcd-efgh') == 'abcd-efgh'
    assert bk.normalize_passphrase('abcd  efgh-ijkl-mnop-qrst-uvwx') == \
        'abcd  efgh-ijkl-mnop-qrst-uvwx'
    assert bk.normalize_passphrase('abc1-efgh-ijkl-mnop-qrst-uvwx') == \
        'abc1-efgh-ijkl-mnop-qrst-uvwx'
    with pytest.raises(bk.BackupError):
        bk.open_bytes(bk.seal_bytes(b'x', PASS, **FAST), PASS.upper())


# -- the contents -------------------------------------------------------------------

def _contact(nickname, verified=False):
    from autonomous_trust.core.identity import Identity
    c = Contact(Identity.initialize(nickname, nickname, '10.0.9.9').publish())
    if verified:
        c.mark_verified()
    return c


def test_contents_round_trip():
    store = Contacts()
    carol = store.add(_contact('carol', verified=True))
    dave = store.add(_contact('dave'))
    at = dave.version() + 1000.0
    store.remove(dave.uuid, at=at)
    text = bk.seal(bk.build_contents(store, now=5.0), PASS, **FAST)
    contents = bk.open_contents(text, PASS)
    assert contents['typename'] == 'at-backup-contents' and contents['created_at'] == 5.0
    assert set(contents['contacts']['contacts']) == {carol.uuid}
    assert contents['contacts']['tombstones'] == {dave.uuid: at}
    assert 'siblings' not in contents and 'operator_key' not in contents


#: Made by C's at_backup_seal (ops 1, mem 8192, PASS): c-dana verified with
#: petname Dana, created_at 1800000000. C's contacts_backup_test pins a
#: Python-made one the same way.
C_BACKUP = (
    '{"aead":"xchacha20poly1305-ietf","ct":"aaA9woaHzf3l73YRdcRoSpUlDp0CJRnk1FOTV'
    'v2SBWST8n7BiZkDj3vgKcT9+q4lC1C+Ohsj4wqy23oZFNZ2X33L0iKCBBCYRwVXHO6e18ezkbNEK'
    'uGgKR0JLMQxwiMtYDUg8nvkOoEg4U9sD0rlz4EDRUAHqeVVA4k8tQPQ0/ZIUEI54Af054IfuNUhj'
    '5qMIfkAWCRK2HaRYGCdSnzHXa0yCInkBGo3GijCoCvhSRK1RxGdPMhyzLleSUkIYHySGB53xKhF0'
    'WtC1LqhGQn50M9WqhF1OiN5Mpr5yGJC6qhSoYw3MDOhQugKw9LEnzHe6bxCZivkQvQDuH2yHDMBR'
    'xaQ9hPBXV4dyrWE+pe7gRev0jf/K0ExOuGI8LG2vJtVWvVncc6g/5cSEAsdxn0GfM0bRGCQI7BJ6'
    '+Q+wBMYemEMMRC6LUR7bxcV/THNL28hjGEUHhrRzH/EwsAWngnrjmeEqD+ADiOpQwN8GfmsjmHkl'
    'Y78FwowZ+/8x1xVglkTI0yt+dziEn2Z5oVeWibLzG/q7BVDXoxKAu5WimF+0yYeeUxPX6nuFybaV'
    '7TKmi7Xxq7QCav4tI7gS1Wqvrr+eiECiEySIzejQcEqsKFDo2xAOKK7rby+EglEX9YkWWMEl3dso'
    'A09e2YtwZsYF7ufbpTnUD95fnP2c+cGkWcmURDEjQ/vPCfOhZ5eUynP1nBmbdjT0wi//+zW3GiUb'
    'deC5f17BrAfmkHuENwlgVBm3mF13TDNgY9N/U/MDQ2anhrGVzfSLEPU5Z4/Wzfb01LxBPFJ3jzuV'
    '7423f8fVZfGuCugzXazK7QtYjxVdJU9lNxi+3r32BwMTnLQeXWQcKabeEx6GQSBbF0IBY/7Vpo5h'
    'lM7e9n9kGvzS5H4j65sdhCgl4km","kdf":"argon2id13","mem":8192,"nonce":"dd50292c'
    'eae31e4598d8709e709d2efb73709644356c62e2","ops":1,"salt":"afcd84a1cd212332fc'
    '5c55dea6a96dd4","typename":"at-backup","v":1}')
C_DANA = '81d2d34a-8c48-44c3-9deb-bcc12240d360'


def test_a_c_backup_opens_and_restores_here():
    contents = bk.open_contents(C_BACKUP, PASS)
    assert contents['created_at'] == 1800000000.0
    store = Contacts()
    changes, paired = bk.restore(store, None, contents, now=1800000100.0)
    assert changes == [(C_DANA, 'added')] and paired == []
    dana = store.get(C_DANA)
    assert dana.verified and dana.petname == 'Dana'
    assert dana.provenance is Provenance.backup
    with pytest.raises(bk.BackupError) as err:
        bk.open_contents(C_BACKUP, PASS + 'x')
    assert err.value.reason == 'bad_passphrase'


def test_contents_that_are_not_contents_are_malformed():
    for plaintext in (b'\xff', b'[]', b'{"typename":"at-backup-contents","v":1}',
                      b'{"typename":"x","v":1,"contacts":{}}'):
        with pytest.raises(bk.BackupError) as err:
            bk.open_contents(bk.seal_bytes(plaintext, PASS, **FAST), PASS)
        assert err.value.reason == 'malformed'


def test_a_restore_merges_and_keeps_verification():
    old = Contacts()
    carol = old.add(_contact('carol', verified=True))
    erin = old.add(_contact('erin'))
    gone = old.add(_contact('gone'))
    old.remove(gone.uuid, at=gone.version() + 10)
    contents = bk.build_contents(old)

    here = Contacts()
    mine = here.add(Contact.from_canonical(erin.to_canonical()))
    mine.petname = 'Erin (new)'
    mine.touch(now=erin.version() + 50)
    here.add(Contact.from_canonical(gone.to_canonical()))
    changes, paired = bk.restore(here, None, contents)
    assert dict(changes) == {carol.uuid: 'added', gone.uuid: 'removed'}
    assert paired == []
    got = here.get(carol.uuid)
    assert got.verified and got.verified_at == carol.verified_at
    assert got.provenance is Provenance.backup
    # The edit made here after the backup was taken survives.
    assert here.get(erin.uuid).petname == 'Erin (new)'
    assert gone.uuid not in here and gone.uuid in here.tombstones
    # Restoring the same backup twice changes nothing.
    assert bk.restore(here, None, contents) == ([], [])


def test_a_restore_of_a_bad_book_is_malformed():
    with pytest.raises(bk.BackupError) as err:
        bk.restore(Contacts(), None, {'contacts': {'typename': 'x'}})
    assert err.value.reason == 'malformed'


# -- the app verbs ---------------------------------------------------------------------

def _book(node, *others, verified=True, operator=None):
    for other in others:
        _h.befriend(node, other, verified=verified, operator=operator)


def test_export_writes_a_private_file(fast_kdf, phone, bob, tmp_path):
    _book(phone, bob)
    path = str(tmp_path / 'alice.atbackup')
    phone.app(bc.APP_BACKUP_EXPORT, {'ref': 'b', 'path': path, 'passphrase': PASS})
    ev = phone.last()
    assert (ev.kind, ev.ref, ev.path, ev.contacts, ev.siblings, ev.passphrase) == \
        (bc.EVENT_WRITTEN, 'b', path, 1, 0, '')
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    contents = bk.open_contents(open(path).read(), PASS)
    assert str(bob.identity.uuid) in contents['contacts']['contacts']
    assert PASS not in open(path).read()


def test_export_can_generate_the_passphrase(fast_kdf, phone, bob, tmp_path):
    _book(phone, bob)
    path = str(tmp_path / 'b')
    phone.app(bc.APP_BACKUP_EXPORT, {'ref': 'g', 'path': path, 'generate': True})
    ev = phone.last()
    assert ev.kind == bc.EVENT_WRITTEN and len(ev.passphrase) == 29
    assert bk.open_contents(open(path).read(), ev.passphrase)
    # A null passphrase is no passphrase (both runtimes).
    phone.app(bc.APP_BACKUP_EXPORT, {'ref': 'n', 'path': path, 'generate': True,
                                     'passphrase': None})
    assert phone.last().kind == bc.EVENT_WRITTEN


@pytest.mark.parametrize('payload, reason', [
    ({'ref': 'x', 'passphrase': PASS}, 'bad_request'),
    ({'ref': 'x', 'path': 'relative/file', 'passphrase': PASS}, 'bad_request'),
    ({'ref': 'x', 'path': '/' + 'a' * 4096, 'passphrase': PASS}, 'bad_request'),
    ({'ref': 'x', 'path': '@'}, 'bad_request'),
    ({'ref': 'x', 'path': '@', 'passphrase': PASS, 'generate': True}, 'bad_request'),
    ({'ref': 'x', 'path': '@', 'generate': 'yes'}, 'bad_request'),
    ({'ref': 'x', 'path': '@', 'passphrase': 12345678901234}, 'bad_request'),
    ({'ref': 'x', 'path': '@', 'passphrase': 'short'}, 'weak_passphrase'),
    ({'ref': 'x', 'path': '/nonexistent-dir/f', 'passphrase': PASS}, 'io'),
    ({'ref': 'r' * 64, 'path': '@', 'passphrase': PASS}, 'bad_request'),
])
def test_what_export_refuses(fast_kdf, phone, tmp_path, payload, reason):
    payload = {k: (str(tmp_path / 'f') if v == '@' else v) for k, v in payload.items()}
    phone.app(bc.APP_BACKUP_EXPORT, payload)
    ev = phone.last()
    assert ev.kind == bc.EVENT_REFUSED and ev.reason == reason
    assert ev.ref == ('' if len(payload['ref']) > fc.REF_MAX else 'x')
    assert not os.path.exists(str(tmp_path / 'f'))


def test_a_new_phone_keeps_contacts_and_verified_edges(fast_kdf, operator, phone,
                                                       laptop, new_phone, bob, tmp_path):
    """The exit criterion, end to end: Alice's phone is lost; her new phone
    restores the backup, keeps Bob verified, announces itself, and Bob files
    it under Alice -- with no old device in the room."""
    _h.install_cert(phone, operator)
    _h.install_cert(laptop, operator)
    _book(phone, bob)
    _h.befriend(bob, phone, verified=True, operator=operator)
    _h.pair(phone, laptop)
    path = str(tmp_path / 'alice.atbackup')
    phone.app(bc.APP_BACKUP_EXPORT, {'ref': 'b', 'path': path, 'passphrase': PASS})
    assert phone.last(bc.EVENT_WRITTEN).siblings == 1

    _h.install_cert(new_phone, operator)
    new_phone.app(bc.APP_BACKUP_IMPORT, {'ref': 'r', 'path': path, 'passphrase': PASS})
    evs = new_phone.drain_events()
    done = [e for e in evs if e.kind == bc.EVENT_RESTORED][-1]
    assert (done.ref, done.added, done.updated, done.removed, done.siblings,
            done.contacts) == ('r', 1, 0, 0, 1, 1)
    added = [e for e in evs if e.kind == fc.EVENT_CONTACT]
    assert added and added[0].origin == bc.ORIGIN_BACKUP and added[0].verified
    got = new_phone.store().get(str(bob.identity.uuid))
    assert got.verified and got.provenance is Provenance.backup
    # Saved, so it is there after a restart.
    with new_phone:
        assert Contacts.load().get(str(bob.identity.uuid)).verified
        assert Siblings.load().uuids() == [str(laptop.identity.uuid)]
    assert new_phone.siblings().uuids() == [str(laptop.identity.uuid)]
    # The new phone told Bob it is one of Alice's devices, and Bob agreed.
    sent = _h.route(new_phone, bob)
    assert ('alice-new-phone', 'bob', IdentityProtocol.device_announce) in sent
    alice = bob.store().get(str(phone.identity.uuid))
    assert str(new_phone.identity.uuid) in alice.device_uuids()


def test_no_cert_restores_the_book_but_no_siblings(fast_kdf, operator, phone, laptop,
                                                   new_phone, bob, tmp_path):
    _h.install_cert(phone, operator)
    _h.install_cert(laptop, operator)
    _book(phone, bob)
    _h.pair(phone, laptop)
    path = str(tmp_path / 'b')
    phone.app(bc.APP_BACKUP_EXPORT, {'ref': 'b', 'path': path, 'passphrase': PASS})
    new_phone.app(bc.APP_BACKUP_IMPORT, {'ref': 'r', 'path': path, 'passphrase': PASS})
    done = new_phone.last(bc.EVENT_RESTORED)
    assert (done.added, done.siblings) == (1, 0)
    assert len(new_phone.siblings()) == 0
    # A sibling is never taken as a contact, cert or not.
    assert str(laptop.identity.uuid) not in new_phone.store()


def test_another_operators_device_gets_no_siblings(fast_kdf, operator, phone, laptop,
                                                   new_phone, tmp_path):
    _h.install_cert(phone, operator)
    _h.install_cert(laptop, operator)
    _h.pair(phone, laptop)
    path = str(tmp_path / 'b')
    phone.app(bc.APP_BACKUP_EXPORT, {'ref': 'b', 'path': path, 'passphrase': PASS})
    _h.install_cert(new_phone, SigningKey.generate())
    new_phone.app(bc.APP_BACKUP_IMPORT, {'ref': 'r', 'path': path, 'passphrase': PASS})
    assert new_phone.last(bc.EVENT_RESTORED).siblings == 0
    assert len(new_phone.siblings()) == 0


def test_a_restore_reaches_the_current_sibling(fast_kdf, operator, phone, laptop,
                                               new_phone, bob, tmp_path):
    """A restore is a local edit to the book: pushed to the siblings this
    device already has."""
    _book(phone, bob)
    path = str(tmp_path / 'b')
    phone.app(bc.APP_BACKUP_EXPORT, {'ref': 'b', 'path': path, 'passphrase': PASS})
    _h.install_cert(new_phone, operator)
    _h.install_cert(laptop, operator)
    _h.pair(new_phone, laptop)
    new_phone.app(bc.APP_BACKUP_IMPORT, {'ref': 'r', 'path': path, 'passphrase': PASS})
    sent = _h.route(new_phone, laptop)
    assert ('alice-new-phone', 'alice-laptop', IdentityProtocol.contacts_sync) in sent
    assert str(bob.identity.uuid) in laptop.store()


def test_import_refusals_leave_the_book_alone(fast_kdf, phone, new_phone, bob, tmp_path):
    _book(phone, bob)
    path = str(tmp_path / 'b')
    phone.app(bc.APP_BACKUP_EXPORT, {'ref': 'b', 'path': path, 'passphrase': PASS})
    with open(str(tmp_path / 'junk'), 'w') as fh:
        fh.write('{"typename": "at-backup", "v": 9}')
    for payload, reason in (
            ({'path': path, 'passphrase': 'not the passphrase'}, 'bad_passphrase'),
            ({'path': path}, 'bad_request'),
            ({'path': 'b', 'passphrase': PASS}, 'bad_request'),
            ({'path': str(tmp_path / 'missing'), 'passphrase': PASS}, 'io'),
            ({'path': str(tmp_path / 'junk'), 'passphrase': PASS}, 'unsupported')):
        new_phone.app(bc.APP_BACKUP_IMPORT, dict(payload, ref='r'))
        ev = new_phone.last()
        assert (ev.kind, ev.reason, ev.ref) == (bc.EVENT_REFUSED, reason, 'r')
    assert len(new_phone.store()) == 0


def test_the_node_ignores_an_operator_key_in_a_backup(fast_kdf, phone, bob, new_phone,
                                                     tmp_path, monkeypatch):
    keystore = str(tmp_path / 'keystore')
    monkeypatch.setenv('AT_OPERATOR_KEYSTORE', keystore)
    _book(phone, bob)
    with phone:
        contents = bk.build_contents(fc._contacts_store(phone),
                                     operator_key='ab' * 32)
    path = str(tmp_path / 'b')
    with open(path, 'w') as fh:
        fh.write(bk.seal(contents, PASS))
    new_phone.app(bc.APP_BACKUP_IMPORT, {'ref': 'r', 'path': path, 'passphrase': PASS})
    assert new_phone.last(bc.EVENT_RESTORED).added == 1
    assert not os.path.exists(keystore)


def test_the_verbs_are_local_only_and_declared(fast_kdf, phone, bob, tmp_path,
                                               monkeypatch):
    from autonomous_trust.core._python import app_verbs
    monkeypatch.setenv('AT_FIRST_CONTACT', '1')
    path = str(tmp_path / 'b')
    for verb in bc.APP_VERBS:
        assert app_verbs.app_verb_target(verb) == CfgIds.identity
        handler = {bc.APP_BACKUP_EXPORT: bc.handle_app_backup_export,
                   bc.APP_BACKUP_IMPORT: bc.handle_app_backup_import}[verb]
        msg = Message(CfgIds.identity, verb,
                      json.dumps({'ref': 'x', 'path': path, 'passphrase': PASS}),
                      to_whom=phone.identity, from_whom=bob.identity.publish())
        phone.call(handler, msg)
    assert not os.path.exists(path)
    assert not [e for e in phone.drain_events() if e.kind == bc.EVENT_WRITTEN]
