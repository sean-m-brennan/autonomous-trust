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
"""First contact's answer to the join policy's "is this identity anchored"
(RD_14.4_HOSTILE_JOIN_PLAN.md Phase 2).

A recorded contact anchors as ``verified_contact`` or ``unverified_contact``
by its state, a device its operator vouched for as the contact does, and a
sibling (a device under this node's own operator key) as ``operator``. Every
match is on uuid AND keys: a uuid is public, so a cohort could list a
contact's uuid with keys of its own.
"""
import pytest
from nacl.signing import SigningKey

from autonomous_trust.core.config import Configuration
from autonomous_trust.core.identity import Identity
from autonomous_trust.core._python.identity.idprocess import IdentityProcess
from autonomous_trust.first_contact import (Contact, Contacts, Siblings,
                                           adopt_operator, create_device_cert)
from autonomous_trust.first_contact import first_contact as fc
from autonomous_trust.first_contact._python.device import Device, link_device


class _Proc:
    _same_keys = staticmethod(IdentityProcess._same_keys)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv(Configuration.ROOT_VARIABLE_NAME, str(tmp_path))
    monkeypatch.setenv('AT_FIRST_CONTACT', '1')
    fc._verified_cache.clear()


def _node(name, addr='10.0.0.2'):
    return Identity.initialize(name, name, addr)


def _record(who, verified, operator=None, device=None):
    store = Contacts.load()
    c = Contact(who.publish())
    if verified:
        c.mark_verified()
    if operator is not None:
        assert adopt_operator(c, create_device_cert(operator, who), store) == ''
    store.add(c)
    if device is not None:
        c, why = link_device(store, device.publish(), create_device_cert(operator, device))
        assert why == ''
    store.save()
    return c


def _anchors(ident):
    return fc._anchor_classes(_Proc(), ident)


def test_a_verified_contact_anchors_as_verified():
    bob = _node('bob')
    _record(bob, verified=True)
    assert _anchors(bob.publish()) == {'verified_contact'}


def test_an_unverified_contact_anchors_as_unverified():
    bob = _node('bob')
    _record(bob, verified=False)
    assert _anchors(bob.publish()) == {'unverified_contact'}


def test_a_contacts_uuid_with_other_keys_anchors_nobody():
    bob, impostor = _node('bob'), _node('impostor')
    _record(bob, verified=True)
    impostor._uuid = bob.uuid
    assert str(impostor.uuid) == str(bob.uuid)
    assert _anchors(impostor.publish()) == frozenset()


def test_a_stranger_anchors_nobody():
    _record(_node('bob'), verified=True)
    assert _anchors(_node('carol').publish()) == frozenset()


def test_off_without_first_contact(monkeypatch):
    bob = _node('bob')
    _record(bob, verified=True)
    monkeypatch.delenv('AT_FIRST_CONTACT')
    assert _anchors(bob.publish()) == frozenset()


def test_a_device_the_contacts_operator_vouched_for_anchors_as_the_contact():
    bob, bobs_laptop, operator = _node('bob'), _node('bob-laptop', '10.0.0.4'), SigningKey.generate()
    contact = _record(bob, verified=True, operator=operator, device=bobs_laptop)
    assert str(bobs_laptop.uuid) in contact.device_uuids()
    assert _anchors(bobs_laptop.publish()) == {'verified_contact'}


def test_a_sibling_anchors_as_operator():
    laptop, operator = _node('my-laptop', '10.0.0.3'), SigningKey.generate()
    cert = create_device_cert(operator, laptop)
    sibs = Siblings(operator=cert.operator, devices=[Device(laptop.publish(), cert)])
    sibs.save()
    assert _anchors(laptop.publish()) == {'operator'}
    impostor = _node('impostor')
    impostor._uuid = laptop.uuid
    assert _anchors(impostor.publish()) == frozenset()
