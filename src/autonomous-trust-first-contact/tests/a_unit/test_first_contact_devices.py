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
"""Phase 4, one human with several devices: operator-signed device certs,
learning a contact's operator key, and linking a further device to a VERIFIED
contact (first_contact/device.py)."""
import json

import pytest
from nacl.signing import SigningKey

from autonomous_trust.core.identity import Identity
from autonomous_trust.first_contact import (
    Contact, Contacts, DeviceCert, InvalidDevice, create_device_cert,
    adopt_operator, link_device, FIRST_CONTACT_VERIFIED_SEED)
from autonomous_trust.first_contact.device import DEVICES_MAX


def make_identity(name):
    return Identity.initialize(name, name, '10.0.0.1')


@pytest.fixture
def operator():
    return SigningKey.generate()


@pytest.fixture
def phone():
    return make_identity('alice-phone')


@pytest.fixture
def laptop():
    return make_identity('alice-laptop')


def _verified_alice(store, operator, phone):
    """Bob's record of Alice's first device, verified, operator learned."""
    contact = Contact(phone.publish()).mark_verified()
    assert adopt_operator(contact, create_device_cert(operator, phone), store) == ''
    store.add(contact)
    return contact


def test_cert_roundtrip_verifies(operator, phone):
    cert = create_device_cert(operator, phone, issued_at=1000)
    again = DeviceCert.from_wire(json.dumps(cert.to_wire())).verify()
    assert again.uuid == str(phone.uuid).lower()
    assert again.operator == operator.verify_key.encode().hex()
    assert again.names(phone.publish())
    assert again.issued_at == 1000


def test_hex_seed_operator_key(operator, phone):
    cert = create_device_cert(operator.encode().hex(), phone)
    assert cert.verify().operator == operator.verify_key.encode().hex()


def test_tampered_cert_is_refused(operator, phone, laptop):
    wire = create_device_cert(operator, phone).to_wire()
    body = json.loads(wire['body'])
    body['uuid'] = str(laptop.uuid)
    forged = {'body': json.dumps(body, separators=(',', ':')), 'sig': wire['sig']}
    with pytest.raises(InvalidDevice) as err:
        DeviceCert.from_wire(forged).verify()
    assert err.value.reason == 'bad_signature'


def test_malformed_cert_is_refused():
    for bad in ('not json', {'body': '{}', 'sig': ''}, {'body': 1, 'sig': 'x'}):
        with pytest.raises(InvalidDevice) as err:
            DeviceCert.from_wire(bad).verify()
        assert err.value.reason == 'malformed'


def test_cert_names_only_its_device(operator, phone, laptop):
    assert not create_device_cert(operator, phone).names(laptop.publish())


def test_adopt_operator_needs_the_contacts_own_cert(operator, phone, laptop):
    contact = Contact(phone.publish())
    assert adopt_operator(contact, create_device_cert(operator, laptop)) == 'mismatch'
    assert contact.operator_key == ''
    assert adopt_operator(contact, create_device_cert(operator, phone)) == ''
    assert contact.operator_key == operator.verify_key.encode().hex()


def test_operator_key_does_not_change(operator, phone):
    contact = Contact(phone.publish())
    assert adopt_operator(contact, create_device_cert(operator, phone)) == ''
    other = SigningKey.generate()
    assert adopt_operator(contact, create_device_cert(other, phone)) == 'mismatch'
    assert contact.operator_key == operator.verify_key.encode().hex()


def test_operator_key_belongs_to_one_contact(operator, phone, laptop):
    store = Contacts()
    _verified_alice(store, operator, phone)
    second = Contact(laptop.publish())
    store.add(second)
    assert adopt_operator(second, create_device_cert(operator, laptop), store) == 'known'


def test_link_adds_a_verified_device(operator, phone, laptop):
    store = Contacts()
    alice = _verified_alice(store, operator, phone)
    contact, reason = link_device(store, laptop.publish(), create_device_cert(operator, laptop))
    assert reason == '' and contact is alice
    assert alice.device_uuids() == [str(laptop.uuid)]
    assert store.get(laptop.uuid) is alice and laptop.uuid in store
    assert contact.verified and contact.trust_seed == FIRST_CONTACT_VERIFIED_SEED
    # Idempotent.
    assert link_device(store, laptop.publish(), create_device_cert(operator, laptop)) == (alice, '')
    assert len(alice.devices) == 1


def test_link_refuses_an_unverified_contact(operator, phone, laptop):
    store = Contacts()
    contact = Contact(phone.publish())
    adopt_operator(contact, create_device_cert(operator, phone))
    store.add(contact)
    assert link_device(store, laptop.publish(),
                       create_device_cert(operator, laptop)) == (None, 'unverified')
    assert contact.devices == []


def test_link_refuses_an_unknown_operator(operator, phone, laptop):
    store = Contacts()
    _verified_alice(store, operator, phone)
    stranger = SigningKey.generate()
    assert link_device(store, laptop.publish(),
                       create_device_cert(stranger, laptop)) == (None, 'unknown_operator')


def test_link_refuses_a_lifted_cert(operator, phone, laptop):
    """Mallory presents Alice's laptop cert on her own node."""
    store = Contacts()
    _verified_alice(store, operator, phone)
    mallory = make_identity('mallory')
    assert link_device(store, mallory.publish(),
                       create_device_cert(operator, laptop)) == (None, 'mismatch')


def test_link_refuses_a_device_already_filed_elsewhere(operator, phone, laptop):
    store = Contacts()
    _verified_alice(store, operator, phone)
    store.add(Contact(laptop.publish()))
    assert link_device(store, laptop.publish(),
                       create_device_cert(operator, laptop)) == (None, 'known')


def test_link_is_capped(operator, phone):
    store = Contacts()
    alice = _verified_alice(store, operator, phone)
    for i in range(DEVICES_MAX):
        dev = make_identity('d%d' % i)
        assert link_device(store, dev.publish(), create_device_cert(operator, dev))[1] == ''
    extra = make_identity('extra')
    assert link_device(store, extra.publish(),
                       create_device_cert(operator, extra)) == (None, 'full')
    assert len(alice.devices) == DEVICES_MAX


def test_store_roundtrip_keeps_devices(tmp_path, operator, phone, laptop):
    store = Contacts()
    alice = _verified_alice(store, operator, phone)
    link_device(store, laptop.publish(), create_device_cert(operator, laptop))
    store.save(str(tmp_path))
    again = Contacts.load(str(tmp_path))
    back = again.get(laptop.uuid)
    assert back is not None and back.uuid == alice.uuid
    assert back.operator_key == alice.operator_key
    assert back.device_uuids() == [str(laptop.uuid)]
    assert [str(i.uuid) for i in back.identities()] == [str(phone.uuid), str(laptop.uuid)]


def test_store_without_devices_is_unchanged(phone):
    d = Contact(phone.publish()).to_canonical()
    assert 'operator_key' not in d and 'devices' not in d


def test_hand_added_device_does_not_load(tmp_path, operator, phone, laptop):
    """contacts.cfg.json is plain JSON in the user's data dir: a device whose
    cert is under another operator key, or does not name it, is dropped."""
    store = Contacts()
    _verified_alice(store, operator, phone)
    link_device(store, laptop.publish(), create_device_cert(operator, laptop))
    path = store.save(str(tmp_path))
    with open(path) as fh:
        doc = json.load(fh)
    rec = doc['contacts'][str(phone.uuid)]
    mallory = make_identity('mallory')
    stranger = SigningKey.generate()
    rec['devices'].append(dict(rec['devices'][0],
                               cert=create_device_cert(stranger, mallory).to_wire(),
                               identity=Contact(mallory.publish()).to_canonical()['identity']))
    rec['devices'].append(dict(rec['devices'][0],
                               identity=Contact(mallory.publish()).to_canonical()['identity']))
    with open(path, 'w') as fh:
        json.dump(doc, fh)
    back = Contacts.load(str(tmp_path)).get(phone.uuid)
    assert back.device_uuids() == [str(laptop.uuid)]


def test_devices_seed_and_cap_like_the_first(tmp_path, monkeypatch, operator, phone, laptop):
    """Every device of a verified contact reads as a verified contact to the
    tier cap (first_contact._contact_records)."""
    from autonomous_trust.first_contact._python import first_contact as fc
    from autonomous_trust.first_contact._python import store as store_mod
    store = Contacts()
    _verified_alice(store, operator, phone)
    link_device(store, laptop.publish(), create_device_cert(operator, laptop))
    store.save(str(tmp_path))
    monkeypatch.setattr(store_mod.Contacts, 'default_path',
                        classmethod(lambda cls, data_dir=None: str(tmp_path / 'contacts.cfg.json')))
    fc._verified_cache.clear()
    records = fc._contact_records()
    assert records == {str(phone.uuid): True, str(laptop.uuid): True}
