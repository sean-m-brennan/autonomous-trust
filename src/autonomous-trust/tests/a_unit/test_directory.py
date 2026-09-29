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
"""Directory entries and attestations (contacts/directory.py), FIRST_CONTACT_PLAN Phase 3."""
import json
import time

import pytest
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

from autonomous_trust.core.identity import Identity
from autonomous_trust.core._python.contacts import directory as d

ISSUER = SigningKey(b'\x44' * 32)
ISSUER_KEY = ISSUER.verify_key.encode(HexEncoder).decode()


def _key(ident):
    return ident.signature.private.verify_key.encode(HexEncoder).decode()


@pytest.fixture
def alice():
    return Identity.initialize('alice', 'alice', '10.0.0.1')


def _entry(ident, handle='alice@example.org', seq=1, visibility='anyone', expiry=None,
           issuer=ISSUER):
    att = d.attest(issuer, handle, _key(ident), int(time.time()) + 3600)
    return d.create_entry(ident, att, seq, visibility, expiry)


@pytest.mark.parametrize('raw,folded', [
    ('Alice@Example.ORG', 'alice@example.org'), ('+15551234567', '+15551234567'),
    ('xn--bcher-kva.example', 'xn--bcher-kva.example'), ('a', 'a')])
def test_handles_fold_to_lower_case(raw, folded):
    assert d.normalize_handle(raw) == folded


@pytest.mark.parametrize('raw', ['', 'bücher', 'a b', 'a/b', 'x' * 129, None, 7])
def test_non_handles_are_refused(raw):
    assert d.normalize_handle(raw) is None


def test_an_entry_round_trips_and_verifies(alice):
    e = _entry(alice, 'Alice@Example.org')
    back = d.DirectoryEntry.from_wire(e.to_json()).verify({ISSUER_KEY})
    assert back.handle == 'alice@example.org'
    assert back.uuid == str(alice.uuid).lower()
    assert back.key == _key(alice)
    assert back.attestation.issuer == ISSUER_KEY


def test_an_untrusted_issuer_is_refused(alice):
    e = _entry(alice)
    with pytest.raises(d.InvalidEntry):
        e.verify({'00' * 32})
    e.verify()  # with no trust set, the client checks only the signatures


def test_an_attestation_for_another_key_cannot_be_used(alice):
    bob = Identity.initialize('bob', 'bob', '10.0.0.2')
    att = d.attest(ISSUER, 'alice@example.org', _key(bob), int(time.time()) + 60)
    with pytest.raises(d.InvalidEntry):
        d.create_entry(alice, att, 1)


def test_a_lifted_attestation_is_refused_even_if_signed_in(alice):
    """Mallory signs an entry for her own key around Alice's attestation."""
    mallory = Identity.initialize('m', 'm', '10.0.0.3')
    att = d.attest(ISSUER, 'alice@example.org', _key(alice), int(time.time()) + 60)
    body = dict(_entry(mallory, 'm@example.org').body, attestation=att.to_wire(),
                handle='alice@example.org')
    wire = d._sign(mallory.signature.private, d.ENTRY_DOMAIN, body)
    with pytest.raises(d.InvalidEntry, match='another handle or key'):
        d.DirectoryEntry.from_wire(wire).verify({ISSUER_KEY})


def test_the_entry_signature_covers_the_exact_body(alice):
    wire = _entry(alice).to_wire()
    wire['body'] = wire['body'].replace('"seq":1', '"seq":2')
    with pytest.raises(d.InvalidEntry):
        d.DirectoryEntry.from_wire(wire).verify()


def test_an_attestation_signature_does_not_verify_as_an_entry(alice):
    att = d.attest(alice.signature.private, 'alice@example.org', _key(alice),
                   int(time.time()) + 60)
    with pytest.raises(d.InvalidEntry):
        d.DirectoryEntry.from_wire(att.to_wire()).verify()


def test_expiry_is_capped_by_the_attestation_and_enforced(alice):
    att = d.attest(ISSUER, 'alice@example.org', _key(alice), int(time.time()) + 10)
    e = d.create_entry(alice, att, 1, expiry=int(time.time()) + 10 ** 6)
    assert e.expiry == att.expiry
    with pytest.raises(d.InvalidEntry, match='expired'):
        e.verify(now=att.expiry)


def test_a_bad_visibility_or_version_is_refused(alice):
    with pytest.raises(d.InvalidEntry):
        _entry(alice, visibility='friends')
    for patch in ({'v': 1.0}, {'v': True}, {'seq': 0}, {'seq': True},
                  {'visibility': 'friends'}, {'handle': 'Alice@example.org'}):
        e = _entry(alice)
        body = dict(e.body, **patch)
        wire = d._sign(alice.signature.private, d.ENTRY_DOMAIN, body)
        with pytest.raises(d.InvalidEntry):
            d.DirectoryEntry.from_wire(wire).verify()


def test_the_entry_carries_the_holder_without_an_address(alice):
    e = _entry(alice)
    assert e.identity_json['uuid'] == str(alice.uuid)
    assert e.identity_json['address'] == ''
    other = Identity.initialize('o', 'o', '10.0.0.9')
    from autonomous_trust.core._python.identity.identity import public_identity_to_canonical
    wire = d._sign(alice.signature.private, d.ENTRY_DOMAIN,
                   dict(e.body, identity=public_identity_to_canonical(other)))
    with pytest.raises(d.InvalidEntry, match='not the holder'):
        d.DirectoryEntry.from_wire(wire).verify()


def test_a_public_identity_cannot_sign_an_entry(alice):
    att = d.attest(ISSUER, 'alice@example.org', _key(alice), int(time.time()) + 60)
    with pytest.raises(d.InvalidEntry):
        d.create_entry(alice.publish(), att, 1)
