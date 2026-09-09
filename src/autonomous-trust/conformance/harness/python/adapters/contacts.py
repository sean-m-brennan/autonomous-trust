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
"""Contacts / first-contact adapter (kind: scenario, protocol: contacts).

Trigger-style, like the bootstrap adapter: each scenario names an `op` under
`fixtures.contacts`, the adapter runs the production first-contact call, and
asserts the pinned observables in `expected_state.host`. The pins are chosen so
a wrong value flips the case to fail (never a vacuous "no crash"): a redeemed
contact's verified/provenance/seed/uuid/nickname, the exact 60-digit safety
number, and the specific rejection reason for a tampered/expired invitation.

Mirrors the C adapter (src/c/conformance/adapters/contacts.c); the two are
diffed by case_id status, so both must assert the same values.
"""
from pathlib import Path

from ...common.scenario_loader import Case

from autonomous_trust.core.identity.identity import public_identity_from_canonical
from autonomous_trust.core.contacts import (redeem_invitation, safety_number,
                                            verify_contact, InvalidInvitation,
                                            SafetyNumberMismatch, Contacts)

_TOL = 1e-9


def _classify_invalid(exc: Exception) -> str:
    msg = str(exc).lower()
    if 'expire' in msg:
        return 'expired'
    if 'signature' in msg or 'identity' in msg:
        return 'bad_sig'
    return 'malformed'


class ContactsAdapter:
    def __init__(self, corpus_root: Path) -> None:
        self.corpus_root = corpus_root

    # -- kinds this adapter does not handle ---------------------------------
    def run_wire_vector(self, case: Case) -> None:  # noqa: ARG002
        raise NotImplementedError('contacts adapter handles kind:scenario only')

    def run_crypto_vector(self, case: Case) -> None:  # noqa: ARG002
        raise NotImplementedError('contacts adapter handles kind:scenario only')

    def run_agreement_vector(self, case: Case) -> None:  # noqa: ARG002
        raise NotImplementedError('contacts adapter handles kind:scenario only')

    def run_negative(self, case: Case) -> None:  # noqa: ARG002
        raise NotImplementedError('contacts adapter handles kind:scenario only')

    # -- the contacts scenario ----------------------------------------------
    def run_scenario(self, case: Case) -> None:
        spec = case.data
        fx = (spec.get('fixtures') or {}).get('contacts') or {}
        expected = (spec.get('expected_state') or {}).get('host', {})
        op = fx.get('op')
        if op == 'redeem':
            self._redeem(fx, expected)
        elif op == 'safety_number':
            self._safety_number(fx, expected)
        elif op == 'verify_contact':
            self._verify_contact(fx, expected)
        elif op == 'store_roundtrip':
            self._store_roundtrip(fx, expected)
        else:
            raise AssertionError('unknown contacts op %r' % op)

    # -- ops ----------------------------------------------------------------
    def _redeem(self, fx, expected):
        blob = fx['blob']
        in_person = bool(fx.get('in_person', False))
        if 'redeem_status' in expected:
            try:
                redeem_invitation(blob, in_person=in_person)
            except InvalidInvitation as exc:
                got = _classify_invalid(exc)
            else:
                raise AssertionError('expected redeem to be rejected (%s)'
                                     % expected['redeem_status'])
            assert got == expected['redeem_status'], (got, expected['redeem_status'])
            return
        contact = redeem_invitation(blob, in_person=in_person)
        assert contact.verified is bool(expected['verified']), contact.verified
        assert contact.provenance.value == expected['provenance'], contact.provenance
        assert abs(contact.trust_seed - float(expected['trust_seed'])) < _TOL, contact.trust_seed
        assert str(contact.uuid) == expected['uuid'], contact.uuid
        assert contact.nickname == expected['nickname'], contact.nickname

    def _safety_number(self, fx, expected):
        a = public_identity_from_canonical(fx['identity_a'])
        b = public_identity_from_canonical(fx['identity_b'])
        assert a is not None and b is not None, 'canonical identity did not parse'
        sn = safety_number(a, b)
        assert sn == expected['safety_number'], sn

    def _verify_contact(self, fx, expected):
        contact = redeem_invitation(fx['blob'])          # remote -> unverified
        me = public_identity_from_canonical(fx['identity_b'])
        assert me is not None, 'my identity did not parse'
        status = 'ok'
        try:
            verify_contact(contact, fx['presented'], me)
        except SafetyNumberMismatch:
            status = 'mismatch'
        assert status == expected['verify_status'], status
        assert contact.verified is bool(expected['verified']), contact.verified
        assert abs(contact.trust_seed - float(expected['trust_seed'])) < _TOL, contact.trust_seed

    def _store_roundtrip(self, fx, expected):
        store = Contacts.from_canonical(fx['store'])
        assert len(store) == int(expected['count']), len(store)
        a = store.get(expected['a_uuid'])
        assert a is not None, 'contact a missing'
        assert a.petname == expected['a_petname'], a.petname
        assert a.verified is bool(expected['a_verified']), a.verified
        assert a.provenance.value == expected['a_provenance'], a.provenance
        assert abs(a.trust_seed - float(expected['a_trust_seed'])) < _TOL, a.trust_seed
        b = store.get(expected['b_uuid'])
        assert b is not None, 'contact b missing'
        assert b.verified is bool(expected['b_verified']), b.verified
        assert abs(b.trust_seed - float(expected['b_trust_seed'])) < _TOL, b.trust_seed
        # internal round-trip stability: to_canonical -> from_canonical preserves count
        store2 = Contacts.from_canonical(store.to_canonical())
        assert len(store2) == len(store), len(store2)
