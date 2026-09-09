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
"""First-contact offline slice: contact record, durable store, signed
invitations, and safety-number verification (FIRST_CONTACT_PLAN.md §4.0/§4.1/§4.4)."""
import json
import time

import pytest

from autonomous_trust.core.identity import Identity
from autonomous_trust.core.contacts import (
    Contact, Contacts, Provenance, FIRST_CONTACT_VERIFIED_SEED,
    Invitation, create_invitation, redeem_invitation,
    safety_number, verify_contact, InvalidInvitation, SafetyNumberMismatch)


def make_identity(name):
    # initialize(online_nickname, local_petname, address) -> signable identity
    return Identity.initialize(name, name, '10.0.0.1')


@pytest.fixture
def alice():
    return make_identity('alice@example')


@pytest.fixture
def bob():
    return make_identity('bob@example')


# -- invitation mint/redeem -------------------------------------------------
def test_invitation_roundtrip_and_signature(alice):
    inv = create_invitation(alice, rendezvous=['relay-1'], ttl_seconds=3600)
    blob = inv.encode()
    assert isinstance(blob, str) and '=' not in blob   # padding stripped
    decoded = Invitation.decode(blob)
    ident = decoded.verify_signature()                 # does not raise
    assert str(ident.uuid) == str(alice.uuid)
    assert ident.nickname == alice.nickname
    assert decoded.rendezvous == ['relay-1']


def test_invitation_uri_form(alice):
    inv = create_invitation(alice, ttl_seconds=0)
    uri = inv.to_uri()
    assert uri.startswith('at+contact:')
    assert Invitation.decode(uri).verify_signature() is not None


def test_invitation_carries_no_private_material(alice):
    inv = create_invitation(alice, ttl_seconds=0)
    # The published identity in the body must be public-only: no private seed.
    assert inv.body['identity'].get('signature', {}).get('hex_seed')
    raw = json.dumps(inv.body)
    assert 'private' not in raw.lower()
    assert '__type__' not in raw            # canonical form, not the config form


def test_tampered_invitation_rejected(alice, bob):
    inv = create_invitation(alice, ttl_seconds=3600)
    # Swap in Bob's identity but keep Alice's signature: must fail to verify.
    from autonomous_trust.core.identity.identity import public_identity_to_canonical
    forged = dict(inv.body)
    forged['identity'] = public_identity_to_canonical(bob.publish())
    forged_str = json.dumps(forged, sort_keys=True, separators=(',', ':'))
    tampered = Invitation(forged, forged_str, inv.sig_hex)
    with pytest.raises(InvalidInvitation):
        tampered.verify_signature()


def test_expired_invitation_rejected(alice):
    inv = create_invitation(alice, expiry=int(time.time()) - 1)
    assert inv.is_expired()
    with pytest.raises(InvalidInvitation):
        redeem_invitation(inv)


def test_malformed_blob_rejected():
    with pytest.raises(InvalidInvitation):
        Invitation.decode('not-a-real-blob!!!')


# -- verification posture per channel (§4.4) --------------------------------
def test_remote_redeem_is_unverified(alice):
    contact = redeem_invitation(create_invitation(alice, ttl_seconds=3600))
    assert isinstance(contact, Contact)
    assert contact.provenance == Provenance.token
    assert contact.verified is False
    assert contact.trust_seed == 0.0        # no edge seeded until verified
    assert str(contact.uuid) == str(alice.uuid)


def test_in_person_redeem_is_verified(alice):
    contact = redeem_invitation(create_invitation(alice, ttl_seconds=0),
                               in_person=True)
    assert contact.provenance == Provenance.in_person
    assert contact.verified is True
    assert contact.trust_seed == FIRST_CONTACT_VERIFIED_SEED
    assert contact.verified_at > 0


# -- safety number ----------------------------------------------------------
def test_safety_number_symmetric(alice, bob):
    # Both parties compute the SAME number regardless of argument order.
    assert safety_number(alice, bob) == safety_number(bob, alice)
    sn = safety_number(alice, bob)
    groups = sn.split()
    assert len(groups) == 12 and all(len(g) == 5 and g.isdigit() for g in groups)


def test_safety_number_differs_per_pair(alice, bob):
    carol = make_identity('carol@example')
    assert safety_number(alice, bob) != safety_number(alice, carol)


def test_verify_contact_promotes_on_match(alice, bob):
    # Bob redeems Alice's remote invitation (unverified), then confirms the
    # safety number Alice read to him.
    contact = redeem_invitation(create_invitation(alice, ttl_seconds=3600))
    presented = safety_number(alice, bob)          # what Alice reads to Bob
    verify_contact(contact, presented, bob)        # bob's own identity
    assert contact.verified is True
    assert contact.trust_seed == FIRST_CONTACT_VERIFIED_SEED


def test_verify_contact_rejects_mismatch(alice, bob):
    contact = redeem_invitation(create_invitation(alice, ttl_seconds=3600))
    with pytest.raises(SafetyNumberMismatch):
        verify_contact(contact, '00000 00000 00000 00000 00000 00000 '
                                '00000 00000 00000 00000 00000 00000', bob)
    assert contact.verified is False               # left unverified on mismatch


def test_verify_contact_tolerates_whitespace(alice, bob):
    contact = redeem_invitation(create_invitation(alice, ttl_seconds=3600))
    presented = safety_number(alice, bob).replace(' ', '  ')   # odd spacing
    verify_contact(contact, presented, bob)
    assert contact.verified is True


# -- durable store round-trip ----------------------------------------------
def test_contacts_store_roundtrip(tmp_path, alice, bob):
    data_dir = str(tmp_path)
    store = Contacts()
    a = redeem_invitation(create_invitation(alice, ttl_seconds=0), in_person=True)
    b = redeem_invitation(create_invitation(bob, ttl_seconds=0))
    store.add(a)
    store.add(b)
    assert len(store) == 2
    path = store.save(data_dir)
    assert path.endswith('contacts.cfg.json')

    reloaded = Contacts.load(data_dir)
    assert len(reloaded) == 2
    ra = reloaded.get(alice.uuid)
    assert ra is not None
    assert ra.verified is True
    assert ra.provenance == Provenance.in_person
    assert ra.trust_seed == FIRST_CONTACT_VERIFIED_SEED
    assert ra.petname == a.petname                 # petname preserved, not re-derived
    # identity survived as a public-only trust root
    assert str(ra.identity.uuid) == str(alice.uuid)
    assert ra.identity._public_only is True
    rb = reloaded.get(bob.uuid)
    assert rb.verified is False


def test_contacts_store_load_missing_is_empty(tmp_path):
    store = Contacts.load(str(tmp_path))
    assert len(store) == 0
    assert store.all() == []


def test_contacts_keyed_by_uuid_not_nickname(tmp_path, alice):
    store = Contacts()
    c1 = redeem_invitation(create_invitation(alice, ttl_seconds=0))
    store.add(c1)
    # same UUID re-added (e.g. a fresh invitation) replaces, not duplicates
    c2 = redeem_invitation(create_invitation(alice, ttl_seconds=0), in_person=True)
    store.add(c2)
    assert len(store) == 1
    assert store.get(alice.uuid).verified is True

    store.remove(alice.uuid)
    assert len(store) == 0
