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
"""The optional live 1:1 first-contact handshake (identity/first_contact.py).

Exercises the handler logic against a lightweight process stub: no sockets, no
subprocess. The wire delivery (a hello reaching a not-yet-known peer over the
open channel) is the network process's job and is covered by its own paths;
here we pin the identity-process behavior: ticket validation, single-use nonce,
no-vote/no-group-key admission, and the acknowledge/initiate messages.
"""
import logging
import os
import queue
import types

import pytest

from autonomous_trust.core.identity import Identity, Peers
from autonomous_trust.core.identity.protocol import IdentityProtocol, UNENCRYPTED_VERBS
from autonomous_trust.core.system import CfgIds
from autonomous_trust.core.config import Configuration
from autonomous_trust.core.contacts import (create_invitation, Contact,
                                           Contacts, Provenance)
from autonomous_trust.core.config.configuration import to_json_string
from autonomous_trust.core.identity import first_contact as fc


@pytest.fixture(autouse=True)
def _isolate_data_dir(monkeypatch, tmp_path):
    """Point the durable nonce store at a per-test temp dir, not the real one."""
    monkeypatch.setenv(Configuration.ROOT_VARIABLE_NAME, str(tmp_path))


def _identity(name, addr):
    return Identity.initialize(name, name, addr)


class StubProc:
    """Minimal stand-in for IdentityProcess: just what the handlers touch."""
    def __init__(self, identity):
        self.name = CfgIds.identity
        self.identity = identity
        self.peers = Peers()
        self.logger = logging.getLogger('test-first-contact')
        self.q_cadence = 1.0
        self.record_peers_calls = 0
        self._first_contact_nonces = fc.SpentNonces()

    def _record_peers(self, queues):
        self.record_peers_calls += 1


def _inbound(from_identity, obj):
    """A parsed inbound message: the handlers read only .from_whom and .obj."""
    return types.SimpleNamespace(from_whom=from_identity.publish(), obj=obj)


@pytest.fixture
def alice():
    return _identity('alice@ex', '10.0.0.1')


@pytest.fixture
def bob():
    return _identity('bob@ex', '10.0.0.2')


# -- gating -----------------------------------------------------------------
def test_disabled_by_default(monkeypatch):
    monkeypatch.delenv('AT_FIRST_CONTACT', raising=False)
    assert fc.enabled() is False


@pytest.mark.parametrize('val,expect', [('1', True), ('true', True), ('on', True),
                                        ('yes', True), ('0', False), ('', False),
                                        ('off', False)])
def test_enable_flag(monkeypatch, val, expect):
    monkeypatch.setenv('AT_FIRST_CONTACT', val)
    assert fc.enabled() is expect


def test_verbs_are_unencrypted():
    # The first hello arrives before the peer is known, so both must be plaintext.
    assert IdentityProtocol.hello in UNENCRYPTED_VERBS
    assert IdentityProtocol.hello_ack in UNENCRYPTED_VERBS


# -- handle_hello (inviter side) --------------------------------------------
def test_hello_admits_direct_peer_and_acks(alice, bob):
    proc = StubProc(alice)
    invite = create_invitation(alice, rendezvous=['10.0.0.1'], ttl_seconds=3600)
    q = {CfgIds.network: queue.Queue()}

    assert fc.handle_hello(proc, q, _inbound(bob, invite.encode())) is True
    # Bob is now a direct peer...
    assert proc.peers.find_by_uuid(bob.uuid) is not None
    assert proc.record_peers_calls == 1
    # ...but NOT a group member: no group key propagation happened (StubProc has
    # no group; _admit_direct_peer never touches group state).
    # An ack went back to Bob, plaintext, correct verb.
    ack = q[CfgIds.network].get_nowait()
    assert ack.function == IdentityProtocol.hello_ack
    assert ack.encrypt is False
    assert ack.to_whom[0].uuid == bob.uuid


def test_hello_is_single_use(alice, bob):
    proc = StubProc(alice)
    invite = create_invitation(alice, ttl_seconds=3600)
    q = {CfgIds.network: queue.Queue()}
    fc.handle_hello(proc, q, _inbound(bob, invite.encode()))
    q[CfgIds.network].get_nowait()          # drain first ack
    before = len(proc.peers.all)
    # Replay the SAME invitation: nonce already spent -> ignored, no second ack.
    fc.handle_hello(proc, q, _inbound(bob, invite.encode()))
    assert q[CfgIds.network].empty()
    assert len(proc.peers.all) == before


def test_hello_rejects_expired(alice, bob):
    proc = StubProc(alice)
    invite = create_invitation(alice, expiry=100)   # far past
    q = {CfgIds.network: queue.Queue()}
    fc.handle_hello(proc, q, _inbound(bob, invite.encode()))
    assert proc.peers.find_by_uuid(bob.uuid) is None
    assert q[CfgIds.network].empty()


def test_hello_rejects_foreign_invitation(alice, bob):
    # An invitation minted by a THIRD party, not by us, must not be honored.
    mallory = _identity('mallory@ex', '10.0.0.9')
    proc = StubProc(alice)
    foreign = create_invitation(mallory, ttl_seconds=3600)
    q = {CfgIds.network: queue.Queue()}
    fc.handle_hello(proc, q, _inbound(bob, foreign.encode()))
    assert proc.peers.find_by_uuid(bob.uuid) is None
    assert q[CfgIds.network].empty()


def test_hello_rejects_malformed(alice, bob):
    proc = StubProc(alice)
    q = {CfgIds.network: queue.Queue()}
    assert fc.handle_hello(proc, q, _inbound(bob, 'not-a-real-blob!!!')) is True
    assert proc.peers.find_by_uuid(bob.uuid) is None
    assert q[CfgIds.network].empty()


# -- handle_hello_ack (initiator side) --------------------------------------
def test_ack_admits_direct_peer(alice, bob):
    proc = StubProc(bob)   # Bob's node
    q = {CfgIds.network: queue.Queue()}
    from autonomous_trust.core.config.configuration import to_json_string
    assert fc.handle_hello_ack(proc, q, _inbound(alice, to_json_string({'nonce': 'x'}))) is True
    assert proc.peers.find_by_uuid(alice.uuid) is not None
    assert proc.record_peers_calls == 1


# -- endpoint resolution ----------------------------------------------------
@pytest.mark.parametrize('raw,expect', [
    # IPv4 and hostnames: a single colon is a port.
    ('10.0.0.1', '10.0.0.1'),
    ('10.0.0.1:9000', '10.0.0.1'),
    ('relay.example', 'relay.example'),
    ('relay.example:9000', 'relay.example'),
    # Bracketless IPv6: the colons are the ADDRESS. No port is expressible, so
    # nothing may be stripped. This is the case the old rsplit(':', 1) mangled
    # into 'fe80:' — a well-formed address turned unroutable, silently.
    ('fe80::1', 'fe80::1'),
    ('::1', '::1'),
    ('2001:db8:85a3::8a2e:370:7334', '2001:db8:85a3::8a2e:370:7334'),
    ('2001:db8::1%eth0', '2001:db8::1%eth0'),
    ('::ffff:10.0.0.1', '::ffff:10.0.0.1'),
    # Bracketed IPv6: the brackets delimit the host, so a port IS expressible.
    ('[fe80::1]', 'fe80::1'),
    ('[fe80::1]:9000', 'fe80::1'),
    ('[::1]:80', '::1'),
    # A path tail is dropped before any port search.
    ('relay.example:9000/introduce', 'relay.example'),
    ('[fe80::1]:9000/introduce', 'fe80::1'),
    ('fe80::1/introduce', 'fe80::1'),
    # Degenerate inputs: defined so the C twin can agree on them.
    ('', ''),
    (None, ''),
    ('[fe80::1', 'fe80::1'),      # unterminated bracket: best effort
])
def test_endpoint_host(raw, expect):
    assert fc.endpoint_host(raw) == expect


def test_initiate_carries_a_full_length_ipv6_literal(alice, bob):
    # A full uncompressed literal (39 chars) and the longest form there is
    # (45, IPv4-mapped). Nothing is bounded on this side, but the C twin keeps
    # the address in a fixed char[ADDR_LEN + 1] and ADDR_LEN was 32 until it was
    # widened to 45 — so these are the values that used to diverge, and the
    # conformance case first-contact-initiate-endpoint-forms compares them.
    for hint in ('2001:0db8:85a3:0000:0000:8a2e:0370:7334',
                 '0000:0000:0000:0000:0000:ffff:255.255.255.255'):
        proc = StubProc(bob)
        invite = create_invitation(alice, rendezvous=[hint], ttl_seconds=3600)
        q = {CfgIds.network: queue.Queue()}
        assert fc.initiate(proc, q, invite.encode()).address == hint
        assert q[CfgIds.network].get_nowait().to_whom[0].address == hint


def test_initiate_keeps_ipv6_intact(alice, bob):
    # End to end through the production call: the hello must be addressed to
    # the literal, not to a prefix of it.
    proc = StubProc(bob)
    invite = create_invitation(alice, rendezvous=['[2001:db8::1]:9000'],
                               ttl_seconds=3600)
    q = {CfgIds.network: queue.Queue()}
    inviter = fc.initiate(proc, q, invite.encode())
    assert inviter.address == '2001:db8::1'
    hello = q[CfgIds.network].get_nowait()
    assert hello.to_whom[0].address == '2001:db8::1'


# -- initiate (initiator side) ----------------------------------------------
def test_initiate_sends_hello_to_endpoint(alice, bob):
    proc = StubProc(bob)
    invite = create_invitation(alice, rendezvous=['10.5.5.5'], ttl_seconds=3600)
    q = {CfgIds.network: queue.Queue()}
    inviter = fc.initiate(proc, q, invite.encode())
    assert str(inviter.uuid) == str(alice.uuid)
    hello = q[CfgIds.network].get_nowait()
    assert hello.function == IdentityProtocol.hello
    assert hello.encrypt is False
    assert hello.to_whom[0].address == '10.5.5.5'    # from the rendezvous hint
    assert hello.obj == invite.encode()              # carries the ticket


def test_initiate_endpoint_override(alice, bob):
    proc = StubProc(bob)
    invite = create_invitation(alice, rendezvous=['10.5.5.5'], ttl_seconds=3600)
    q = {CfgIds.network: queue.Queue()}
    fc.initiate(proc, q, invite.encode(), endpoint='192.168.1.50')
    hello = q[CfgIds.network].get_nowait()
    assert hello.to_whom[0].address == '192.168.1.50'


# -- end-to-end (both handlers, in-process) ---------------------------------
def test_full_handshake_mutual_direct_peers(alice, bob):
    # Alice mints; Bob initiates; Alice handles hello -> admits Bob + acks;
    # Bob handles the ack -> admits Alice. Both end as direct peers.
    alice_proc, bob_proc = StubProc(alice), StubProc(bob)
    aq = {CfgIds.network: queue.Queue()}
    bq = {CfgIds.network: queue.Queue()}
    invite = create_invitation(alice, rendezvous=['10.0.0.1'], ttl_seconds=3600)

    fc.initiate(bob_proc, bq, invite.encode())
    hello = bq[CfgIds.network].get_nowait()
    # deliver hello to Alice (simulate the wire: from_whom is Bob's public id)
    fc.handle_hello(alice_proc, aq, _inbound(bob, hello.obj))
    assert alice_proc.peers.find_by_uuid(bob.uuid) is not None
    ack = aq[CfgIds.network].get_nowait()
    # deliver ack to Bob
    fc.handle_hello_ack(bob_proc, bq, _inbound(alice, ack.obj))
    assert bob_proc.peers.find_by_uuid(alice.uuid) is not None


# -- durable single-use (nonce persistence) ---------------------------------
def test_nonce_persists_across_restart(alice, bob):
    invite = create_invitation(alice, ttl_seconds=3600)
    q = {CfgIds.network: queue.Queue()}
    # First run: admit Bob; the nonce is recorded and persisted to disk.
    proc1 = StubProc(alice)
    fc.handle_hello(proc1, q, _inbound(bob, invite.encode()))
    assert proc1.peers.find_by_uuid(bob.uuid) is not None
    q[CfgIds.network].get_nowait()
    # "Restart": a fresh process loads the persisted spent-nonce set (same
    # data dir, via the autouse fixture), so the replay is still refused.
    proc2 = StubProc(alice)
    assert invite.nonce in proc2._first_contact_nonces
    fc.handle_hello(proc2, q, _inbound(bob, invite.encode()))
    assert q[CfgIds.network].empty()
    assert proc2.peers.find_by_uuid(bob.uuid) is None


def test_spent_nonces_survive_reload(tmp_path):
    s = fc.SpentNonces(data_dir=str(tmp_path))
    s.add('n1', 0)
    assert 'n1' in fc.SpentNonces(data_dir=str(tmp_path))   # reloaded from disk


def test_spent_nonces_prune_keeps_unexpired_and_forever(tmp_path):
    s = fc.SpentNonces(data_dir=str(tmp_path))
    s._by_nonce = {'expired': 500, 'future': 5000, 'forever': 0}
    s.prune(now=1000.0)
    assert 'expired' not in s
    assert 'future' in s and 'forever' in s


def test_corrupt_nonce_store_fails_safe(tmp_path):
    path = os.path.join(str(tmp_path),
                        fc.SpentNonces.FILENAME + Configuration.file_ext)
    with open(path, 'w') as fh:
        fh.write('{ not valid json')
    s = fc.SpentNonces(data_dir=str(tmp_path))   # must not raise
    assert 'anything' not in s                    # empty (fail-safe) guard


# -- the durable contact the handshake leaves behind -------------------------
# The handshake admits a direct PEER (cohort-adjacent, rebuilt every session);
# the address book is the part that has to survive a restart. Loaded from disk
# in each assertion rather than read off the process, so these also pin that the
# record was actually persisted.
def _stored(uuid):
    return Contacts.load().get(str(uuid))


def test_hello_records_an_unverified_contact(alice, bob):
    proc = StubProc(alice)
    invite = create_invitation(alice, rendezvous=['10.0.0.1'], ttl_seconds=3600)
    q = {CfgIds.network: queue.Queue()}

    fc.handle_hello(proc, q, _inbound(bob, invite.encode()))

    contact = _stored(bob.uuid)
    assert contact is not None
    # UNVERIFIED is the whole point: the accepter cannot know how its ticket
    # travelled, so a key that arrived over the wire has had no out-of-band
    # confirmation and earns no seed until a safety-number compare.
    assert contact.verified is False
    assert contact.trust_seed == 0.0
    assert contact.provenance is Provenance.token
    assert contact.nonce == invite.nonce
    assert contact.rendezvous == ['10.0.0.2']      # where Bob reached us from


def test_ack_records_the_inviter(alice, bob):
    proc = StubProc(bob)
    q = {CfgIds.network: queue.Queue()}

    fc.handle_hello_ack(proc, q, _inbound(alice, to_json_string({'nonce': 'n1'})))

    contact = _stored(alice.uuid)
    assert contact is not None
    assert contact.verified is False
    assert contact.nonce == 'n1'


def test_a_re_handshake_never_downgrades_a_verified_contact(alice, bob):
    """A re-presented ticket must not strip the verified flag or rename the
    contact -- that would hand an attacker a downgrade they could drive."""
    store = Contacts()
    known = Contact(bob.publish(), petname='old-friend',
                    rendezvous=['192.168.1.9'], provenance=Provenance.in_person)
    known.mark_verified()
    store.add(known)
    store.save()
    seed, added_at = known.trust_seed, known.added_at

    proc = StubProc(alice)
    invite = create_invitation(alice, ttl_seconds=3600)
    q = {CfgIds.network: queue.Queue()}
    fc.handle_hello(proc, q, _inbound(bob, invite.encode()))

    contact = _stored(bob.uuid)
    assert contact.verified is True                 # preserved
    assert contact.petname == 'old-friend'          # never re-derived
    assert contact.provenance is Provenance.in_person
    assert contact.trust_seed == seed
    assert contact.added_at == added_at
    # ...only reachability moved, newest first, with the old hint kept behind it
    assert contact.rendezvous == ['10.0.0.2', '192.168.1.9']


def test_rendezvous_hints_stay_bounded(alice, bob):
    """A peer that re-handshakes from a new network every join must not grow
    the record without bound -- the file is never pruned."""
    proc = StubProc(alice)
    q = {CfgIds.network: queue.Queue()}
    seen = []
    for i in range(fc.MAX_RENDEZVOUS_HINTS + 3):
        addr = '10.0.%d.2' % i
        seen.append(addr)
        peer = bob.publish()
        peer.address = addr
        invite = create_invitation(alice, ttl_seconds=3600)
        fc.handle_hello(proc, q, types.SimpleNamespace(from_whom=peer,
                                                       obj=invite.encode()))

    contact = _stored(bob.uuid)
    assert len(contact.rendezvous) == fc.MAX_RENDEZVOUS_HINTS
    assert contact.rendezvous == list(reversed(seen))[:fc.MAX_RENDEZVOUS_HINTS]


def test_an_unwritable_store_does_not_break_the_handshake(alice, bob, monkeypatch):
    """The peer is admitted either way; a lost record costs a re-add, not a
    security property."""
    def boom(self, data_dir=None):
        raise OSError('read-only file system')
    monkeypatch.setattr(Contacts, 'save', boom)

    proc = StubProc(alice)
    invite = create_invitation(alice, ttl_seconds=3600)
    q = {CfgIds.network: queue.Queue()}

    assert fc.handle_hello(proc, q, _inbound(bob, invite.encode())) is True
    assert proc.peers.find_by_uuid(bob.uuid) is not None
    assert q[CfgIds.network].get_nowait().function == IdentityProtocol.hello_ack
