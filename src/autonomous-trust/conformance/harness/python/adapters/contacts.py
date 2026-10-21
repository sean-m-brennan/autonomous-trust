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
import json
from pathlib import Path

from ...common.scenario_loader import Case

from autonomous_trust.core.identity.identity import public_identity_from_canonical
from autonomous_trust.first_contact import (redeem_invitation, safety_number,
                                            verify_contact, InvalidInvitation,
                                            SafetyNumberMismatch, Contacts, Contact)
from autonomous_trust.first_contact._python import directory as _dir
from autonomous_trust.first_contact._python import registry as _registry

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
        elif op == 'dir_verify':
            self._dir_verify(fx, expected)
        elif op == 'dir_normalize':
            self._dir_normalize(fx, expected)
        elif op == 'registry':
            self._registry(fx, expected)
        elif op == 'hub':
            self._hub(fx, expected)
        elif op == 'device':
            self._device(fx, expected)
        elif op == 'sync':
            self._sync(fx, expected)
        elif op == 'siblings':
            self._siblings(fx, expected)
        elif op == 'backup':
            self._backup(fx, expected)
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

    # -- several devices, one human (FIRST_CONTACT_PLAN Phase 4) ---------------
    def _device(self, fx, expected):
        """``mode``: verify a cert (and whether it names ``identity``), adopt
        a contact's operator key from ``cert``, link ``identity`` into
        ``store``, or just load ``store``. Pins the status ('ok' or the
        refusal reason), then ``devices_of`` {contact uuid: [device uuids]}
        and ``resolves`` {uuid: contact uuid | None} against the store."""
        from autonomous_trust.first_contact._python import device as _dev
        mode, status, store = fx['mode'], 'ok', None
        if mode == 'verify':
            try:
                cert = _dev.DeviceCert.from_wire(fx['cert']).verify()
            except _dev.InvalidDevice as exc:
                cert, status = None, exc.reason
            if cert is not None and 'operator' in expected:
                assert cert.operator == expected['operator'], cert.operator
            if cert is not None and 'names' in expected:
                ident = public_identity_from_canonical(fx['identity'])
                assert cert.names(ident) is bool(expected['names']), 'names'
        elif mode == 'adopt':
            contact = Contact.from_canonical(fx['contact'])
            assert contact is not None, 'contact did not parse'
            store = Contacts.from_canonical(fx['store']) if 'store' in fx else None
            status = _dev.adopt_operator(contact, fx['cert'], store) or 'ok'
            if 'operator_key' in expected:
                assert contact.operator_key == expected['operator_key'], contact.operator_key
        elif mode == 'link':
            store = Contacts.from_canonical(fx['store'])
            ident = public_identity_from_canonical(fx['identity'])
            assert ident is not None, 'identity did not parse'
            _contact, reason = _dev.link_device(store, ident, fx['cert'])
            status = reason or 'ok'
        elif mode == 'load':
            store = Contacts.from_canonical(fx['store'])
        else:
            raise AssertionError('unknown device mode %r' % mode)
        if 'device_status' in expected:
            assert status == expected['device_status'], (status, expected['device_status'])
        for uuid, want in (expected.get('devices_of') or {}).items():
            c = store.get(uuid)
            assert c is not None, 'no contact %s' % uuid
            assert c.device_uuids() == list(want), c.device_uuids()
        for uuid, want in (expected.get('resolves') or {}).items():
            c = store.get(uuid)
            got = None if c is None else c.uuid
            assert got == want, (uuid, got, want)
        if store is not None and mode in ('link', 'load'):
            # The file form survives a round trip unchanged.
            again = Contacts.from_canonical(store.to_canonical())
            assert again.to_canonical() == store.to_canonical(), 'store round trip'

    # -- live pairing: one address book across devices (Phase 4) ---------------
    #: The contact fields a sync scenario may pin.
    _SYNC_FIELDS = ('petname', 'verified', 'verified_at', 'provenance',
                    'trust_seed', 'reach_seq', 'rendezvous', 'updated_at',
                    'operator_key')

    def _sync(self, fx, expected):
        """Fold ``payloads`` (or the one ``payload``) into ``store`` at
        ``now``, never taking ``exclude`` as contacts. Pins ``sync_status``
        ('ok' / 'invalid', the first refusal stopping the run), ``changes``
        (every merge's, in order, as [uuid, action]), ``contacts`` {uuid:
        {field: value} | None}, ``devices_of`` and ``tombstones`` (the whole
        map)."""
        from autonomous_trust.first_contact._python import sync as _sync
        store = Contacts.from_canonical(fx.get('store') or {})
        payloads = fx['payloads'] if 'payloads' in fx else [fx['payload']]
        status, changes = 'ok', []
        for payload in payloads:
            try:
                changes += [[u, a] for u, a in _sync.merge(
                    store, payload, now=float(fx['now']),
                    exclude=fx.get('exclude') or ())]
            except _sync.InvalidSync:
                status = 'invalid'
                break
        if 'sync_status' in expected:
            assert status == expected['sync_status'], status
        self._check_book(store, changes, expected)

    def _check_book(self, store, changes, expected):
        """The book pins a sync or a restore shares: ``changes``,
        ``contacts``, ``devices_of``, ``tombstones``, and a clean round trip."""
        if 'changes' in expected:
            assert changes == expected['changes'], changes
        for uuid, want in (expected.get('contacts') or {}).items():
            c = store.contacts.get(uuid)
            if want is None:
                assert c is None, 'contact %s still here' % uuid
                continue
            assert c is not None, 'no contact %s' % uuid
            got = c.to_canonical()
            got.setdefault('updated_at', 0.0)
            got.setdefault('reach_seq', 0)
            got.setdefault('operator_key', '')
            for k, v in want.items():
                assert k in self._SYNC_FIELDS, 'unknown field %s' % k
                assert got[k] == v, (uuid, k, got[k], v)
        for uuid, want in (expected.get('devices_of') or {}).items():
            c = store.get(uuid)
            assert c is not None, 'no contact %s' % uuid
            assert c.device_uuids() == list(want), c.device_uuids()
        if 'tombstones' in expected:
            assert store.tombstones == expected['tombstones'], store.tombstones
        again = Contacts.from_canonical(store.to_canonical())
        assert again.to_canonical() == store.to_canonical(), 'store round trip'

    # -- recovery: the encrypted backup (Phase 4) -------------------------------
    def _backup(self, fx, expected):
        """``mode`` seal (``plaintext`` under ``passphrase``, ``ops``, ``mem``,
        hex ``salt`` / ``nonce``: pins ``ct`` and ``ad``), open (``blob``
        object or ``text``: pins ``plaintext``), passphrase (pins
        ``normalized`` and ``passphrase_status``) or restore (``contents``
        into ``store`` at ``now``, never taking ``own_uuid``: the book pins
        as sync's). ``backup_status`` is 'ok' or the reason."""
        from autonomous_trust.first_contact._python import backup as _bk
        mode = fx['mode']
        status = 'ok'
        if mode == 'seal':
            try:
                blob = _bk.seal_bytes(fx['plaintext'].encode('utf-8'), fx['passphrase'],
                                      ops=int(fx['ops']), mem=int(fx['mem']),
                                      salt=bytes.fromhex(fx['salt']),
                                      nonce=bytes.fromhex(fx['nonce']))
            except _bk.BackupError as err:
                status, blob = err.reason, None
            assert status == expected.get('backup_status', 'ok'), status
            if 'ct' in expected:
                assert blob['ct'] == expected['ct'], blob['ct']
            if 'ad' in expected:
                assert _bk.header_ad(blob['ops'], blob['mem'], blob['salt'],
                                     blob['nonce']).decode() == expected['ad']
        elif mode == 'open':
            src = fx['text'] if 'text' in fx else fx['blob']
            try:
                pt = _bk.open_bytes(src, fx.get('passphrase', ''))
            except _bk.BackupError as err:
                status, pt = err.reason, None
            assert status == expected.get('backup_status', 'ok'), status
            if 'plaintext' in expected:
                assert pt.decode('utf-8') == expected['plaintext'], pt
        elif mode == 'passphrase':
            try:
                _bk.check_passphrase(fx['passphrase'])
            except _bk.BackupError as err:
                status = err.reason
            assert status == expected.get('passphrase_status', 'ok'), status
            if 'normalized' in expected:
                got = _bk.normalize_passphrase(fx['passphrase'])
                assert got == expected['normalized'], got
        elif mode == 'restore':
            store = Contacts.from_canonical(fx.get('store') or {})
            changes = []
            try:
                changes = [[u, a] for u, a in _bk.restore(
                    store, None, fx['contents'], own_uuid=fx.get('own_uuid', ''),
                    now=float(fx['now']))[0]]
            except _bk.BackupError as err:
                status = err.reason
            assert status == expected.get('backup_status', 'ok'), status
            self._check_book(store, changes, expected)
        else:
            raise AssertionError('unknown backup mode %r' % mode)

    def _siblings(self, fx, expected):
        """``mode`` add: pair ``identity`` (cert ``cert``) given this node's
        ``own_cert`` (absent = none) into ``siblings``; load: just load
        ``siblings``. Pins ``sibling_status``, ``siblings`` (uuids in order)
        and ``operator``."""
        from autonomous_trust.first_contact._python.siblings import Siblings
        sib = Siblings.from_canonical(fx.get('siblings') or {})
        status = 'ok'
        if fx['mode'] == 'add':
            ident = public_identity_from_canonical(fx['identity'])
            assert ident is not None, 'identity did not parse'
            status = sib.add(ident, fx['cert'], fx.get('own_cert')) or 'ok'
        elif fx['mode'] != 'load':
            raise AssertionError('unknown siblings mode %r' % fx['mode'])
        if 'sibling_status' in expected:
            assert status == expected['sibling_status'], status
        if 'siblings' in expected:
            assert sib.uuids() == list(expected['siblings']), sib.uuids()
        if 'operator' in expected:
            assert sib.operator == expected['operator'], sib.operator
        again = Siblings.from_canonical(sib.to_canonical())
        assert again.to_canonical() == sib.to_canonical(), 'siblings round trip'

    # -- the directory (FIRST_CONTACT_PLAN Phase 3) ----------------------------
    def _dir_verify(self, fx, expected):
        """Verify one signed object (``what``: entry | attestation | request)
        at a fixed ``now``, optionally against ``trusted`` issuers. Pins the
        exact status ('ok' or the refusal reason) and, when ok, its fields."""
        from autonomous_trust.first_contact._python import area_card as _card
        what, now = fx['what'], float(fx['now'])
        trusted = set(fx['trusted']) if 'trusted' in fx else None
        cls = {'entry': _dir.DirectoryEntry, 'attestation': _dir.Attestation,
               'request': _dir.ContactRequest, 'area_card': _card.AreaCard}[what]
        status, obj = 'ok', None
        try:
            obj = cls.from_wire(fx['wire'])
            if what in ('request', 'area_card'):
                obj.verify(now)
            else:
                obj.verify(trusted, now)
        except _dir.InvalidEntry as exc:
            status = exc.reason
        assert status == expected['dir_status'], (status, expected['dir_status'])
        if status == 'ok':
            for field in ('handle', 'seq', 'uuid', 'key', 'area', 'bucket'):
                if field in expected:
                    got = getattr(obj, 'sender' if (what == 'request' and field == 'uuid')
                                  else field)
                    assert got == expected[field], (field, got, expected[field])

    def _dir_normalize(self, fx, expected):
        got = [_dir.normalize_handle(h) for h in fx['handles']]
        assert got == expected['folded'], (got, expected['folded'])

    def _hub(self, fx, expected):
        """Run ``calls`` against one area hub on a fixed clock and pin each
        reply's op, area, reason / seq, and for a lookup the uuids of the
        cards it answered with, in order."""
        from autonomous_trust.first_contact._python import hub as _hub
        clock = {'mono': 0.0}
        bad = set(fx.get('distrusted', []))
        hub = _hub.Hub(list(fx['areas']), rate=int(fx.get('rate', 10)),
                       distrusted=lambda uuid, key: uuid in bad,
                       clock=lambda: clock['mono'],
                       wallclock=lambda: float(fx['now']))
        replies = []
        for call in fx['calls']:
            clock['mono'] += float(call.get('advance', 0.0))
            who = fx['clients'][call['as']]
            if call['call'] == 'publish':
                r = hub.publish(who['uuid'], who['key'], call['card'])
            elif call['call'] == 'withdraw':
                r = hub.withdraw(who['uuid'], who['key'], call['area'])
            else:
                r = hub.lookup(who['uuid'], call['area'])
            got = {'op': r['op'], 'area': r.get('area', '')}
            if 'reason' in r:
                got['reason'] = r['reason']
            if 'seq' in r:
                got['seq'] = r['seq']
            if r['op'] == 'hub_cards':
                got['cards'] = [str(json.loads(c['body'])['uuid']).lower() for c in r['cards']]
            replies.append(got)
        assert replies == expected['replies'], (replies, expected['replies'])

    def _registry(self, fx, expected):
        """Run ``calls`` against one registry on a fixed clock and pin each
        reply's op (plus reason / seq / whether an entry came back)."""
        clock = {'mono': 0.0}
        bad = set(fx.get('distrusted', []))
        reg = _registry.Registry(set(fx['issuers']), rate=int(fx.get('rate', 10)),
                                 distrusted=lambda uuid, key: uuid in bad,
                                 clock=lambda: clock['mono'],
                                 wallclock=lambda: float(fx['now']))
        replies = []
        for call in fx['calls']:
            clock['mono'] += float(call.get('advance', 0.0))
            who = fx['clients'][call['as']]
            if call['call'] == 'publish':
                r = reg.publish(who['uuid'], who['key'], call['entry'])
            elif call['call'] == 'withdraw':
                r = reg.withdraw(who['uuid'], who['key'], call['handle'])
            else:
                r = reg.lookup(who['uuid'], call['handle'])
            got = {'op': r['op'], 'handle': r.get('handle', '')}
            if 'reason' in r:
                got['reason'] = r['reason']
            if 'seq' in r:
                got['seq'] = r['seq']
            if r['op'] == 'dir_entry':
                got['found'] = r['entry'] is not None
            replies.append(got)
        assert replies == expected['replies'], (replies, expected['replies'])
