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
"""How an application adds a friend: the app-verb dispatch (app_verbs.py), the
two first-contact app verbs, and the FirstContactEvent answers.

Same stub-process approach as test_first_contact_handshake.py: no sockets. The
main loop's two hops (request in, event out) are driven through the real
AutonomousTrust methods against a stub ``self``.
"""
import json
import logging
import queue
import types

import pytest

from autonomous_trust.core.identity import Identity, Peers
from autonomous_trust.core.identity.protocol import IdentityProtocol
from autonomous_trust.core.system import CfgIds
from autonomous_trust.core.config import Configuration
from autonomous_trust.core.contacts import (create_invitation, Contacts,
                                           Invitation, Provenance)
from autonomous_trust.core.network import Message
from autonomous_trust.core.identity import first_contact as fc
from autonomous_trust.core._python import app_verbs
from autonomous_trust.core._python.app_verbs import AppRequest, AppEvent


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv(Configuration.ROOT_VARIABLE_NAME, str(tmp_path))
    monkeypatch.setenv('AT_FIRST_CONTACT', '1')


class StubProc:
    """What the handlers touch on an IdentityProcess."""
    def __init__(self, identity):
        self.name = CfgIds.identity
        self.identity = identity
        self.peers = Peers()
        self.logger = logging.getLogger('test-first-contact-app')
        self.q_cadence = 1.0
        self._first_contact_nonces = fc.SpentNonces()

    def _record_peers(self, queues):
        pass


def _queues():
    return {CfgIds.network: queue.Queue(), CfgIds.main: queue.Queue()}


def _events(q):
    out = []
    while not q[CfgIds.main].empty():
        out.append(q[CfgIds.main].get_nowait())
    return out


def _local(function, payload):
    """A request as the main loop forwards it: no sender at all."""
    return Message(CfgIds.identity, function, json.dumps(payload),
                   to_whom=None, from_whom=None, encrypt=False)


def _wire(sender, function, payload):
    """The same verb arriving from a peer."""
    return types.SimpleNamespace(from_whom=sender.publish(), function=function,
                                 obj=json.dumps(payload))


def _inbound(sender, obj):
    return types.SimpleNamespace(from_whom=sender.publish(), obj=obj)


def _stored(uuid):
    return Contacts.load().get(str(uuid))


@pytest.fixture
def alice():
    return Identity.initialize('alice@ex', 'alice@ex', '10.0.0.1')


@pytest.fixture
def bob():
    return Identity.initialize('bob@ex', 'bob@ex', '10.0.0.2')


# -- dispatch ---------------------------------------------------------------
def test_first_contact_verbs_route_to_identity_when_enabled():
    assert app_verbs.app_verb_target(fc.APP_INVITE) == CfgIds.identity
    assert app_verbs.app_verb_target(fc.APP_INITIATE) == CfgIds.identity


def test_no_verb_is_routed_while_the_feature_is_off(monkeypatch):
    monkeypatch.delenv('AT_FIRST_CONTACT')
    assert app_verbs.app_verb_target(fc.APP_INVITE) is None


def test_an_undeclared_verb_is_not_routed():
    # A real internal verb: an app must not be able to reach it.
    assert app_verbs.app_verb_target(IdentityProtocol.hello) is None
    assert app_verbs.app_verb_target('') is None


def test_local_origin_guard(alice, bob):
    proc = StubProc(alice)
    assert app_verbs.is_local_app_verb(proc, types.SimpleNamespace(from_whom=None))
    assert app_verbs.is_local_app_verb(proc, types.SimpleNamespace(
        from_whom=alice.publish()))
    assert not app_verbs.is_local_app_verb(proc, types.SimpleNamespace(
        from_whom=bob.publish()))


def _main_stub():
    return types.SimpleNamespace(name='main', proc_name=CfgIds.main,
                                 logger=logging.getLogger('test-main'),
                                 external_feedback='extern_in')


def test_the_main_loop_forwards_a_declared_request_with_no_sender():
    from autonomous_trust.core._python.automate import AutonomousTrust
    q = {CfgIds.identity: queue.Queue()}
    AutonomousTrust._route_app_request(
        _main_stub(), q, AppRequest(fc.APP_INVITE, '{"ref": "r1"}'))
    fwd = q[CfgIds.identity].get_nowait()
    assert fwd.function == fc.APP_INVITE
    assert fwd.obj == '{"ref": "r1"}'
    assert fwd.from_whom is None          # what makes the handler read it as local


def test_the_main_loop_refuses_an_undeclared_request():
    from autonomous_trust.core._python.automate import AutonomousTrust
    q = {CfgIds.identity: queue.Queue(), CfgIds.network: queue.Queue()}
    AutonomousTrust._route_app_request(
        _main_stub(), q, AppRequest(IdentityProtocol.hello, 'x'))
    assert all(v.empty() for v in q.values())


def test_the_main_loop_forwards_an_app_event_to_the_app():
    from autonomous_trust.core._python.automate import AutonomousTrust
    main = _main_stub()
    ev = fc.FirstContactEvent(fc.EVENT_INVITATION, ref='r1', blob='b')
    q = {CfgIds.main: queue.Queue(), 'extern_in': queue.Queue()}
    q[CfgIds.main].put(ev)
    main._mq_get = lambda qq, block=False, timeout=None: qq.get_nowait()
    main.run_message_handlers = lambda queues, message: False
    main.external_control = 'extern_out'          # absent from q: no request
    AutonomousTrust._handle_messages(main, q, None, {})
    assert q['extern_in'].get_nowait() is ev


# -- APP_INVITE -------------------------------------------------------------
def test_invite_mints_a_link_signed_by_this_node(alice):
    proc, q = StubProc(alice), _queues()
    fc.handle_app_invite(proc, q, _local(fc.APP_INVITE,
                                         {'ref': 'r1', 'ttl_seconds': 600,
                                          'rendezvous': ['10.0.0.1']}))
    [ev] = _events(q)
    assert isinstance(ev, AppEvent)
    assert (ev.kind, ev.ref) == (fc.EVENT_INVITATION, 'r1')
    inv = Invitation.decode(ev.blob)
    assert str(inv.verify_signature().uuid) == str(alice.uuid)
    assert inv.rendezvous == ['10.0.0.1']
    assert ev.expiry == inv.expiry and ev.expiry > 0


def test_invite_from_the_wire_is_refused(alice, bob):
    proc, q = StubProc(alice), _queues()
    fc.handle_app_invite(proc, q, _wire(bob, fc.APP_INVITE, {'ref': 'r1'}))
    assert _events(q) == []


def test_invite_with_an_unusable_payload_says_so(alice):
    proc, q = StubProc(alice), _queues()
    fc.handle_app_invite(proc, q, _local(fc.APP_INVITE,
                                         {'ref': 'r1', 'ttl_seconds': 'soon'}))
    [ev] = _events(q)
    assert (ev.kind, ev.reason, ev.ref) == (fc.EVENT_REFUSED, 'bad_request', 'r1')


@pytest.mark.parametrize('payload', [
    {'ref': 'r1', 'rendezvous': '10.0.0.1'},          # a string, not a list
    {'ref': 'r1', 'rendezvous': ['10.0.0.1', 7]},     # not all strings
])
def test_invite_wants_a_list_of_hint_strings(alice, payload):
    proc, q = StubProc(alice), _queues()
    fc.handle_app_invite(proc, q, _local(fc.APP_INVITE, payload))
    [ev] = _events(q)
    assert (ev.kind, ev.reason) == (fc.EVENT_REFUSED, 'bad_request')


@pytest.mark.parametrize('verb', [fc.APP_INVITE, fc.APP_INITIATE])
def test_a_ref_too_long_to_echo_is_refused(alice, verb):
    """C echoes the ref in a fixed-width field; a cut ref would answer
    nobody, so both runtimes refuse it rather than shorten it."""
    proc, q = StubProc(alice), _queues()
    handler = fc.handle_app_invite if verb == fc.APP_INVITE else fc.handle_app_initiate
    handler(proc, q, _local(verb, {'ref': 'x' * (fc.REF_MAX + 1),
                                   'invitation': 'at+contact:x'}))
    [ev] = _events(q)
    assert (ev.kind, ev.reason, ev.ref) == (fc.EVENT_REFUSED, 'bad_request', '')


def test_the_link_is_a_shareable_uri(alice):
    proc, q = StubProc(alice), _queues()
    fc.handle_app_invite(proc, q, _local(fc.APP_INVITE, {}))
    [ev] = _events(q)
    assert ev.blob.startswith('at+contact:')
    assert len(ev.blob) <= fc.BLOB_MAX


# -- APP_INITIATE -----------------------------------------------------------
def test_initiate_sends_the_hello_and_records_the_contact(alice, bob):
    proc, q = StubProc(bob), _queues()
    link = create_invitation(alice, rendezvous=['10.0.0.1'], ttl_seconds=600).to_uri()
    fc.handle_app_initiate(proc, q, _local(fc.APP_INITIATE,
                                           {'ref': 'r2', 'invitation': link}))
    hello = q[CfgIds.network].get_nowait()
    assert hello.function == IdentityProtocol.hello
    [ev] = _events(q)
    assert (ev.kind, ev.ref, ev.peer_uuid) == (fc.EVENT_HELLO_SENT, 'r2',
                                               str(alice.uuid))
    contact = _stored(alice.uuid)
    assert contact is not None and contact.verified is False


def test_initiate_in_person_is_verified_at_once(alice, bob):
    proc, q = StubProc(bob), _queues()
    link = create_invitation(alice, ttl_seconds=600).encode()
    fc.handle_app_initiate(proc, q, _local(fc.APP_INITIATE,
                                           {'invitation': link, 'in_person': True,
                                            'petname': 'Al'}))
    contact = _stored(alice.uuid)
    assert contact.verified is True
    assert contact.provenance is Provenance.in_person
    assert contact.petname == 'Al'
    assert contact.trust_seed > 0


def test_initiate_from_the_wire_is_refused(alice, bob):
    mallory = Identity.initialize('mallory@ex', 'mallory@ex', '10.0.0.66')
    proc, q = StubProc(bob), _queues()
    link = create_invitation(alice, ttl_seconds=600).encode()
    fc.handle_app_initiate(proc, q, _wire(mallory, fc.APP_INITIATE,
                                          {'invitation': link}))
    assert q[CfgIds.network].empty()
    assert _events(q) == []


def _tampered(blob):
    """Flip one signature hex digit inside a valid blob."""
    inv = Invitation.decode(blob)
    bad = ('0' if inv.sig_hex[0] != '0' else '1') + inv.sig_hex[1:]
    return Invitation(inv.body, inv.body_str, bad).encode()


@pytest.mark.parametrize('case,reason', [
    ('missing', 'bad_request'),
    ('garbage', 'malformed'),
    ('tampered', 'bad_signature'),
    ('expired', 'expired'),
    ('own', 'bad_request'),
])
def test_initiate_names_what_was_wrong(alice, bob, case, reason):
    proc, q = StubProc(bob), _queues()
    good = create_invitation(alice, ttl_seconds=600).encode()
    payload = {'ref': 'r3', 'invitation': {
        'missing': None,
        'garbage': 'at+contact:not-base64!!',
        'tampered': _tampered(good),
        'expired': create_invitation(alice, expiry=100).encode(),
        'own': create_invitation(bob, ttl_seconds=600).encode(),
    }[case]}
    fc.handle_app_initiate(proc, q, _local(fc.APP_INITIATE, payload))
    assert q[CfgIds.network].empty()
    [ev] = _events(q)
    assert (ev.kind, ev.reason, ev.ref) == (fc.EVENT_REFUSED, reason, 'r3')


# -- the whole flow, as two apps see it -------------------------------------
def test_two_apps_add_each_other(alice, bob):
    a_proc, b_proc = StubProc(alice), StubProc(bob)
    aq, bq = _queues(), _queues()

    fc.handle_app_invite(a_proc, aq, _local(fc.APP_INVITE,
                                            {'ref': 'alice-link',
                                             'rendezvous': ['10.0.0.1']}))
    [minted] = _events(aq)
    fc.handle_app_initiate(b_proc, bq, _local(fc.APP_INITIATE,
                                              {'ref': 'bob-add',
                                               'invitation': minted.blob}))
    hello = bq[CfgIds.network].get_nowait()
    [sent] = _events(bq)
    assert sent.kind == fc.EVENT_HELLO_SENT

    fc.handle_hello(a_proc, aq, _inbound(bob, hello.obj))
    [a_done] = _events(aq)
    assert (a_done.kind, a_done.role, a_done.ref, a_done.peer_uuid) == (
        fc.EVENT_ESTABLISHED, 'inviter', 'alice-link', str(bob.uuid))

    ack = aq[CfgIds.network].get_nowait()
    fc.handle_hello_ack(b_proc, bq, _inbound(alice, ack.obj))
    [b_done] = _events(bq)
    assert (b_done.kind, b_done.role, b_done.ref, b_done.peer_uuid) == (
        fc.EVENT_ESTABLISHED, 'initiator', 'bob-add', str(alice.uuid))
    assert b_proc.peers.find_by_uuid(alice.uuid) is not None


def test_the_inviter_hears_about_its_own_expired_or_spent_link(alice, bob):
    proc, q = StubProc(alice), _queues()
    expired = create_invitation(alice, expiry=100)
    fc.handle_hello(proc, q, _inbound(bob, expired.encode()))
    [ev] = _events(q)
    assert (ev.kind, ev.reason, ev.role) == (fc.EVENT_REFUSED, 'expired', 'inviter')

    fresh = create_invitation(alice, ttl_seconds=600)
    fc.handle_hello(proc, q, _inbound(bob, fresh.encode()))
    _events(q)                                   # established
    fc.handle_hello(proc, q, _inbound(bob, fresh.encode()))
    [ev] = _events(q)
    assert (ev.kind, ev.reason) == (fc.EVENT_REFUSED, 'spent')


def test_a_strangers_ticket_reaches_the_app_as_nothing(alice, bob):
    """Not ours, so not the app's business -- and reporting it would let anyone
    on the LAN flood the app with events."""
    carol = Identity.initialize('carol@ex', 'carol@ex', '10.0.0.3')
    proc, q = StubProc(alice), _queues()
    fc.handle_hello(proc, q, _inbound(bob, create_invitation(
        carol, ttl_seconds=600).encode()))
    fc.handle_hello(proc, q, _inbound(bob, 'at+contact:garbage'))
    assert _events(q) == []


# -- the address book, through the node --------------------------------------
from autonomous_trust.core.contacts import Contact, safety_number   # noqa: E402

BOOK_VERBS = [fc.APP_SAFETY_NUMBER, fc.APP_VERIFY, fc.APP_RENAME, fc.APP_REMOVE]
_BOOK_HANDLERS = {fc.APP_SAFETY_NUMBER: fc.handle_app_safety_number,
                  fc.APP_VERIFY: fc.handle_app_verify,
                  fc.APP_LIST: fc.handle_app_list,
                  fc.APP_RENAME: fc.handle_app_rename,
                  fc.APP_REMOVE: fc.handle_app_remove}


def _know(proc, who, added_at=100.0, as_peer=False):
    """Put ``who`` in proc's address book (and optionally its Peers)."""
    store = fc._contacts_store(proc)
    store.add(Contact(who.publish(), petname=who.nickname + '-pet',
                      added_at=added_at))
    store.save()
    if as_peer:
        proc.peers.add(who.publish(), proc.peers.mid_level)
    return str(who.uuid)


def _book(proc, verb, payload):
    q = _queues()
    _BOOK_HANDLERS[verb](proc, q, _local(verb, payload))
    return q, _events(q)


@pytest.mark.parametrize('verb', list(_BOOK_HANDLERS))
def test_every_book_verb_is_routed_and_local_only(alice, bob, verb):
    assert app_verbs.app_verb_target(verb) == CfgIds.identity
    proc, q = StubProc(alice), _queues()
    peer = _know(proc, bob)
    _BOOK_HANDLERS[verb](proc, q, _wire(bob, verb, {'ref': 'r', 'peer': peer,
                                                    'confirmed': True,
                                                    'petname': 'x'}))
    assert _events(q) == []
    assert _stored(bob.uuid).petname == bob.nickname + '-pet'   # untouched


@pytest.mark.parametrize('verb', BOOK_VERBS)
def test_a_book_verb_on_a_stranger_says_so(alice, bob, verb):
    proc = StubProc(alice)
    _q, [ev] = _book(proc, verb, {'ref': 'r', 'peer': str(bob.uuid),
                                  'confirmed': True, 'petname': 'x'})
    assert (ev.kind, ev.reason, ev.ref) == (fc.EVENT_REFUSED, 'unknown_contact', 'r')


def test_safety_number_is_the_one_both_screens_show(alice, bob):
    proc = StubProc(alice)
    peer = _know(proc, bob)
    _q, [ev] = _book(proc, fc.APP_SAFETY_NUMBER, {'ref': 's', 'peer': peer})
    assert ev.kind == fc.EVENT_SAFETY_NUMBER
    assert ev.safety_number == safety_number(bob.publish(), alice.publish())
    assert len(ev.safety_number.split()) == 12


def test_verify_by_typed_digits(alice, bob):
    proc = StubProc(alice)
    peer = _know(proc, bob)
    typed = safety_number(alice.publish(), bob.publish()).replace(' ', '')
    _q, [ev] = _book(proc, fc.APP_VERIFY, {'ref': 'v', 'peer': peer,
                                           'presented': typed})
    assert (ev.kind, ev.method, ev.verified) == (fc.EVENT_VERIFIED, 'presented', True)
    contact = _stored(bob.uuid)
    assert contact.verified is True and contact.trust_seed > 0


def test_verify_refuses_digits_that_do_not_match(alice, bob):
    proc = StubProc(alice)
    peer = _know(proc, bob)
    good = safety_number(alice.publish(), bob.publish())
    wrong = ('1' if good[0] != '1' else '2') + good[1:]
    _q, [ev] = _book(proc, fc.APP_VERIFY, {'ref': 'v', 'peer': peer,
                                           'presented': wrong})
    assert (ev.kind, ev.reason) == (fc.EVENT_REFUSED, 'mismatch')
    assert _stored(bob.uuid).verified is False


def test_verify_by_confirmation(alice, bob):
    proc = StubProc(alice)
    peer = _know(proc, bob)
    _q, [ev] = _book(proc, fc.APP_VERIFY, {'ref': 'v', 'peer': peer,
                                           'confirmed': True})
    assert (ev.kind, ev.method) == (fc.EVENT_VERIFIED, 'confirmed')
    assert _stored(bob.uuid).verified is True


@pytest.mark.parametrize('payload', [{}, {'confirmed': False},
                                     {'confirmed': 'yes'}, {'presented': '  '}])
def test_verify_needs_digits_or_a_confirmation(alice, bob, payload):
    proc = StubProc(alice)
    peer = _know(proc, bob)
    _q, [ev] = _book(proc, fc.APP_VERIFY, dict(payload, ref='v', peer=peer))
    assert (ev.kind, ev.reason) == (fc.EVENT_REFUSED, 'bad_request')
    assert _stored(bob.uuid).verified is False


def test_an_empty_book_still_answers(alice):
    _q, [done] = _book(StubProc(alice), fc.APP_LIST, {'ref': 'l'})
    assert (done.kind, done.count, done.ref) == (fc.EVENT_CONTACTS_DONE, 0, 'l')


def test_list_sends_every_record_oldest_first_then_the_count(alice, bob):
    carol = Identity.initialize('carol@ex', 'carol@ex', '10.0.0.3')
    proc = StubProc(alice)
    _know(proc, carol, added_at=200.0)
    _know(proc, bob, added_at=100.0)
    _q, events = _book(proc, fc.APP_LIST, {'ref': 'l'})
    assert [e.kind for e in events] == [fc.EVENT_CONTACT, fc.EVENT_CONTACT,
                                        fc.EVENT_CONTACTS_DONE]
    assert [e.peer_uuid for e in events[:2]] == [str(bob.uuid), str(carol.uuid)]
    assert events[0].provenance == 'token' and events[0].verified is False
    assert events[2].count == 2


def test_rename(alice, bob):
    proc = StubProc(alice)
    peer = _know(proc, bob)
    _q, [ev] = _book(proc, fc.APP_RENAME, {'ref': 'n', 'peer': peer,
                                           'petname': 'Bobby'})
    assert (ev.kind, ev.petname) == (fc.EVENT_CONTACT, 'Bobby')
    assert _stored(bob.uuid).petname == 'Bobby'


@pytest.mark.parametrize('petname', ['', '   ', 'x' * (fc.PETNAME_MAX + 1), 7])
def test_rename_refuses_an_unusable_name(alice, bob, petname):
    proc = StubProc(alice)
    peer = _know(proc, bob)
    _q, [ev] = _book(proc, fc.APP_RENAME, {'ref': 'n', 'peer': peer,
                                           'petname': petname})
    assert (ev.kind, ev.reason) == (fc.EVENT_REFUSED, 'bad_request')


def test_remove_drops_the_record_and_the_direct_peer(alice, bob):
    proc = StubProc(alice)
    peer = _know(proc, bob, as_peer=True)
    calls = []
    proc._record_peers = lambda queues: calls.append(queues)
    _q, [ev] = _book(proc, fc.APP_REMOVE, {'ref': 'x', 'peer': peer})
    assert (ev.kind, ev.peer_dropped) == (fc.EVENT_REMOVED, True)
    assert _stored(bob.uuid) is None
    assert proc.peers.find_by_uuid(bob.uuid) is None
    assert len(calls) == 1                 # the siblings are told


def test_remove_keeps_a_cohort_members_peer_entry(alice, bob):
    """Their place in Peers belongs to the group the vote admitted them to."""
    proc = StubProc(alice)
    peer = _know(proc, bob, as_peer=True)
    proc.group = types.SimpleNamespace(_address_map={peer: '10.0.0.2'})
    _q, [ev] = _book(proc, fc.APP_REMOVE, {'ref': 'x', 'peer': peer})
    assert (ev.kind, ev.peer_dropped) == (fc.EVENT_REMOVED, False)
    assert _stored(bob.uuid) is None
    assert proc.peers.find_by_uuid(bob.uuid) is not None


def test_remove_of_a_contact_that_is_not_a_peer(alice, bob):
    proc = StubProc(alice)
    peer = _know(proc, bob)
    _q, [ev] = _book(proc, fc.APP_REMOVE, {'ref': 'x', 'peer': peer})
    assert (ev.kind, ev.peer_dropped) == (fc.EVENT_REMOVED, False)
    assert _stored(bob.uuid) is None


def test_peers_remove_clears_every_lookup(bob):
    """``delete`` clears only the nickname slots; the network attributes frames
    through ``listing`` (by address), so a removed peer must leave it too."""
    peers = Peers()
    pub = bob.publish()
    peers.add(pub, peers.mid_level)
    assert peers.remove(pub) is True
    assert peers.find_by_uuid(bob.uuid) is None
    assert peers.find_by_address(pub.address) is None
    assert pub not in peers.all
    assert peers.find_by_index(pub.nickname) is None
    assert peers.remove(pub) is False
