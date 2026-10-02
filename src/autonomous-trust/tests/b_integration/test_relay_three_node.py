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
"""First contact through a rendezvous relay, three real nodes (Phase 0 spike).

Alice and Bob have NO direct path: different loopback addresses AND different
comm ports, so a hello sent straight to Alice lands on a port nobody listens on
(and neither discovers the other). Carol is an ordinary AT node that opted in
as a relay (AT_RELAY=1). Alice registers with her (AT_USE_RELAY), so the link
Alice's node mints names the relay; Bob learns it from the link alone.

This is the in-sandbox stand-in for NAT, which the sandbox cannot build (no
CAP_NET_ADMIN): it proves the relay path end to end -- registration, sealed
forwarding, relay-stamped senders, the reply routed back the way the hello
came -- over real sockets. tools/relay_nat_test.sh is the real-NAT check, run
on a host with sudo.

The control, test_without_the_relay_they_never_meet, is what makes "no direct
path" a fact rather than a claim: the same two nodes, Alice not behind the
relay, and the handshake never completes.
"""
import json
import logging
import os
import shutil
import time
from unittest.mock import patch

import pytest

from autonomous_trust.core import AutonomousTrust, Process
from autonomous_trust.core.config import Configuration
from autonomous_trust.core.config.generate import generate_identity
from autonomous_trust.core import plaintext_verbs
from autonomous_trust.first_contact import first_contact
from .test_two_node import MP_CTX, _make_node_dir, _mock_addresses, _patch_loopback
from .test_first_contact_two_node import _await, STARTUP
from .. import TEST_DIR

ALICE = ('alice', '127.0.0.1', 31101)
BOB = ('bob', '127.0.0.2', 31102)
CAROL = ('carol', '127.0.0.3', 31103)
DAVE = ('dave', '127.0.0.4', 31104)      # a second relay
RELAY_PORT = 31190
DAVE_RELAY_PORT = 31191
DEAD_RELAY = '127.0.0.5:31199'          # nothing listens here


def _run_node(cfg_dir, ip_addr, port, env, q_in, q_out, log_file):
    # `kill -USR1 <pid>` dumps every thread's stack beside the log: how a node
    # that will not exit is diagnosed.
    import faulthandler
    import signal
    faulthandler.register(signal.SIGUSR1, all_threads=True,
                          file=open(log_file + '.stacks', 'w'))
    # Exit without flushing app events nobody will read: a node restarted by
    # a test emits more than the pipe holds, and the queue's feeder thread
    # would otherwise hold the process open forever at exit.
    q_out.cancel_join_thread()
    os.environ[Configuration.ROOT_VARIABLE_NAME] = cfg_dir
    os.environ['AT_FIRST_CONTACT'] = '1'
    os.environ['AT_COMM_PORT'] = str(port)
    os.environ.update(env)
    _patch_loopback([ip_addr], ip_addr, port)
    with patch('autonomous_trust.core.network.network.Network.get_addresses',
               return_value=_mock_addresses(ip_addr)):
        at = AutonomousTrust(multiproc=False, log_level=logging.DEBUG,
                             logfile=log_file, testing=True, silent=True)
        at.run_forever(q_in=q_in, q_out=q_out)


@pytest.fixture
def cohort():
    base = os.path.join(TEST_DIR, 'relay_three_node')
    if os.path.exists(base):
        shutil.rmtree(base)
    nodes = {}
    for name, ip, port in (ALICE, BOB, CAROL, DAVE):
        cfg_dir = _make_node_dir(base, name)
        with patch('autonomous_trust.core.network.network.Network.get_addresses',
                   return_value=_mock_addresses(ip)):
            generate_identity(cfg_dir, randomize=True, seed=port)
        # First contact's plaintext verbs: granted, as a deployment must.
        plaintext_verbs.write(cfg_dir, first_contact.EXTENSION.plaintext_verbs)
        log_dir = os.path.join(base, name, 'var', 'at')
        os.makedirs(log_dir, exist_ok=True)
        nodes[name] = {'cfg_dir': cfg_dir, 'ip': ip, 'port': port,
                       'log': os.path.join(log_dir, 'autonomous_trust.log'),
                       'q_in': MP_CTX.Queue(), 'q_out': MP_CTX.Queue()}
    yield nodes
    if not os.environ.get('AT_KEEP_TEST_LOGS'):
        shutil.rmtree(base, ignore_errors=True)


def _start(nodes, envs):
    procs = []
    for name, env in envs.items():
        n = nodes[name]
        p = MP_CTX.Process(target=_run_node, daemon=True,
                           args=(n['cfg_dir'], n['ip'], n['port'], env,
                                 n['q_in'], n['q_out'], n['log']))
        p.start()
        procs.append(p)
    return procs


def _stop(nodes, procs):
    for n in nodes.values():
        n['q_in'].put(Process.sig_quit)
    for p in procs:
        p.join(timeout=30)
        if p.is_alive():
            p.terminate()
            p.join(timeout=5)


def _add_friend(alice, bob, seen_a, seen_b, rendezvous=None):
    from autonomous_trust.core.app_verbs import AppRequest
    from autonomous_trust.first_contact import first_contact as fc
    req = {'ref': 'r'}
    if rendezvous is not None:
        req['rendezvous'] = rendezvous
    alice['q_in'].put(AppRequest(fc.APP_INVITE, json.dumps(req)))
    minted = _await(alice['q_out'], lambda e: e.kind == fc.EVENT_INVITATION, seen_a)
    bob['q_in'].put(AppRequest(fc.APP_INITIATE, json.dumps(
        {'ref': 'add', 'invitation': minted.blob})))
    _await(bob['q_out'], lambda e: e.kind == fc.EVENT_HELLO_SENT, seen_b)
    return minted


def test_two_nodes_with_no_direct_path_meet_through_a_relay(cohort):
    from autonomous_trust.first_contact import Invitation
    from autonomous_trust.first_contact import first_contact as fc
    # AT_TEST_EXTERNAL_RELAY=host:port uses a relay someone else runs -- the
    # C one, for the cross-runtime check -- instead of Carol.
    external = os.environ.get('AT_TEST_EXTERNAL_RELAY', '')
    relay_ep = external or '%s:%d' % (CAROL[1], RELAY_PORT)
    nodes = {'alice': {'AT_USE_RELAY': relay_ep}, 'bob': {}}
    if not external:
        nodes['carol'] = {'AT_RELAY': '1', 'AT_RELAY_PORT': str(RELAY_PORT)}
    procs = _start(cohort, nodes)
    seen_a, seen_b = [], []
    try:
        time.sleep(STARTUP)
        minted = _add_friend(cohort['alice'], cohort['bob'], seen_a, seen_b)
        # The link names the relay: that is how Bob learns it.
        from autonomous_trust.rendezvous._python import relay as _relay
        hints = Invitation.decode(minted.blob).rendezvous
        assert relay_ep in ['%s:%d' % _relay.parse_endpoint(h) for h in hints
                            if h.startswith(_relay.SCHEME)]
        # Once Alice's relay proved itself, her link pins it (uuid + key).
        pinned = [_relay.parse_hint(h)[1] for h in hints
                  if h.startswith(_relay.SCHEME)]
        assert any(p is not None for p in pinned), hints
        a_done = _await(cohort['alice']['q_out'],
                        lambda e: e.kind == fc.EVENT_ESTABLISHED, seen_a)
        b_done = _await(cohort['bob']['q_out'],
                        lambda e: e.kind == fc.EVENT_ESTABLISHED, seen_b)
    finally:
        _stop(cohort, procs)
    assert (a_done.role, b_done.role) == ('inviter', 'initiator')
    if external:
        return

    with open(cohort['carol']['log']) as fh:
        carol = fh.read()
    # Both registered with the relay, which proved each one's key.
    assert carol.count('registered') >= 2, carol[-2000:]
    for name in ('alice', 'bob'):
        with open(cohort[name]['log']) as fh:
            log = fh.read()
        assert 'Relay: registered with %s' % relay_ep in log, name
        assert 'Received new identity:' not in log, name


def test_without_the_relay_they_never_meet(cohort):
    """The control: same nodes, same link path, Alice NOT behind the relay.
    Bob's hello goes straight to Alice's address on Bob's port, where nobody
    listens -- so nothing establishes. This is what makes the other test's
    success the relay's doing."""
    from autonomous_trust.first_contact import first_contact as fc
    procs = _start(cohort, {'alice': {}, 'bob': {}})
    seen_a, seen_b = [], []
    try:
        time.sleep(STARTUP)
        _add_friend(cohort['alice'], cohort['bob'], seen_a, seen_b)
        with pytest.raises(AssertionError):
            _await(cohort['bob']['q_out'],
                   lambda e: e.kind == fc.EVENT_ESTABLISHED, seen_b, timeout=20)
    finally:
        _stop(cohort, procs)


def _established(cohort, seen_a, seen_b):
    from autonomous_trust.first_contact import first_contact as fc
    a = _await(cohort['alice']['q_out'], lambda e: e.kind == fc.EVENT_ESTABLISHED, seen_a)
    b = _await(cohort['bob']['q_out'], lambda e: e.kind == fc.EVENT_ESTABLISHED, seen_b)
    return a.role, b.role


def _log(node):
    with open(node['log']) as fh:
        return fh.read()


def _await_log(node, text, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(node['log']) and text in _log(node):
            return True
        time.sleep(1)
    return False


CAROL_EP = '%s:%d' % (CAROL[1], RELAY_PORT)
DAVE_EP = '%s:%d' % (DAVE[1], DAVE_RELAY_PORT)
CAROL_RELAY = {'AT_RELAY': '1', 'AT_RELAY_PORT': str(RELAY_PORT)}
DAVE_RELAY = {'AT_RELAY': '1', 'AT_RELAY_PORT': str(DAVE_RELAY_PORT)}


def test_a_dead_first_relay_fails_over_to_the_next(cohort):
    """Alice names two relays and the first is down: she registers with the
    second, the link names both in order, and Bob's hello fails over."""
    from autonomous_trust.first_contact import Invitation
    procs = _start(cohort, {'alice': {'AT_USE_RELAY': DEAD_RELAY + ',' + CAROL_EP},
                            'bob': {}, 'carol': CAROL_RELAY})
    seen_a, seen_b = [], []
    try:
        time.sleep(STARTUP)
        minted = _add_friend(cohort['alice'], cohort['bob'], seen_a, seen_b)
        from autonomous_trust.rendezvous._python import relay as _relay
        hints = Invitation.decode(minted.blob).rendezvous
        assert ['%s:%d' % _relay.parse_endpoint(h) for h in hints] == [
            DEAD_RELAY, CAROL_EP]
        # The live relay is pinned; the dead one never proved anything.
        assert _relay.parse_hint(hints[0])[1] is None
        assert _relay.parse_hint(hints[1])[1] is not None
        assert _established(cohort, seen_a, seen_b) == ('inviter', 'initiator')
    finally:
        _stop(cohort, procs)
    assert 'Relay: %s unusable for' % DEAD_RELAY in _log(cohort['bob'])


def test_a_relay_that_cannot_reach_the_peer_hands_over_to_the_next(cohort):
    """The link's first relay is UP but Alice never registered there, so it
    answers "unreachable" -- the only signal a relay gives. Bob resends the
    hello through the link's second relay, where Alice is."""
    procs = _start(cohort, {'alice': {'AT_USE_RELAY': CAROL_EP}, 'bob': {},
                            'carol': CAROL_RELAY, 'dave': DAVE_RELAY})
    seen_a, seen_b = [], []
    try:
        time.sleep(STARTUP)
        _add_friend(cohort['alice'], cohort['bob'], seen_a, seen_b,
                    rendezvous=['relay://' + DAVE_EP, 'relay://' + CAROL_EP])
        assert _established(cohort, seen_a, seen_b) == ('inviter', 'initiator')
    finally:
        _stop(cohort, procs)
    bob = _log(cohort['bob'])
    assert 'cannot reach' in bob and 'now reached through ' + CAROL_EP in bob, bob[-3000:]


def test_saved_contacts_reconnect_after_a_restart(cohort):
    """Meet through the relay, stop everyone, start them again with no new
    link: each re-admits the other from its address book and their traffic
    flows through the relay again."""
    envs = {'alice': {'AT_USE_RELAY': CAROL_EP}, 'bob': {}, 'carol': CAROL_RELAY}
    procs = _start(cohort, envs)
    seen_a, seen_b = [], []
    try:
        time.sleep(STARTUP)
        _add_friend(cohort['alice'], cohort['bob'], seen_a, seen_b)
        assert _established(cohort, seen_a, seen_b) == ('inviter', 'initiator')
    finally:
        _stop(cohort, procs)
    for name in ('alice', 'bob'):
        os.remove(cohort[name]['log'])
    procs = _start(cohort, envs)
    try:
        uuids = {}
        for name in ('alice', 'bob'):
            with open(os.path.join(cohort[name]['cfg_dir'], 'identity.cfg.json')) as fh:
                uuids[name] = json.load(fh)['_uuid'][:8]
        for name, other in (('alice', 'bob'), ('bob', 'alice')):
            assert _await_log(cohort[name], 'reconnecting 1 saved contact'), name
            assert _await_log(cohort[name], 'Relay: %s is talking to us through %s'
                              % (uuids[other], CAROL_EP)), _log(cohort[name])[-3000:]
    finally:
        _stop(cohort, procs)


def test_without_the_address_book_a_restart_does_not_reconnect(cohort):
    """The control for the restart test: same meeting, but Bob's address book
    is deleted before the restart, so neither side reaches the other."""
    envs = {'alice': {'AT_USE_RELAY': CAROL_EP}, 'bob': {}, 'carol': CAROL_RELAY}
    procs = _start(cohort, envs)
    seen_a, seen_b = [], []
    try:
        time.sleep(STARTUP)
        _add_friend(cohort['alice'], cohort['bob'], seen_a, seen_b)
        assert _established(cohort, seen_a, seen_b) == ('inviter', 'initiator')
    finally:
        _stop(cohort, procs)
    bob_root = os.path.dirname(os.path.dirname(cohort['bob']['cfg_dir']))
    os.remove(os.path.join(bob_root, 'var', 'at', 'contacts.cfg.json'))
    for name in ('alice', 'bob'):
        os.remove(cohort[name]['log'])
    procs = _start(cohort, envs)
    try:
        assert not _await_log(cohort['bob'], 'is talking to us through', timeout=40)
    finally:
        _stop(cohort, procs)


def _contacts(node):
    root = os.path.dirname(os.path.dirname(node['cfg_dir']))
    path = os.path.join(root, 'var', 'at', 'contacts.cfg.json')
    with open(path) as fh:
        return json.load(fh).get('contacts', {})


def test_a_contacts_new_relays_arrive_in_its_reachability_record(cohort):
    """Alice moves to another relay while Bob is away from her old one: her
    signed record reaches Bob, and his address book names where she is now.

    Bob's own relay is Dave, Alice's is Carol; they meet through Carol, and
    Bob's record (naming Dave) reaches Alice at the handshake. Alice then
    restarts on Dave alone, and Carol goes away: Alice reaches Bob through
    Dave (from his record) and pushes her new record, so Bob's saved contact
    for her names Dave, at a higher sequence."""
    envs = {'alice': {'AT_USE_RELAY': CAROL_EP}, 'bob': {'AT_USE_RELAY': DAVE_EP},
            'carol': CAROL_RELAY, 'dave': DAVE_RELAY}
    procs = _start(cohort, envs)
    seen_a, seen_b = [], []
    try:
        time.sleep(STARTUP)
        _add_friend(cohort['alice'], cohort['bob'], seen_a, seen_b)
        assert _established(cohort, seen_a, seen_b) == ('inviter', 'initiator')
        assert _await_log(cohort['alice'], 'is reachable via'), _log(cohort['alice'])[-3000:]
    finally:
        _stop(cohort, procs)
    (alice_c,) = _contacts(cohort['alice']).values()
    assert any(DAVE_EP in h for h in alice_c['rendezvous']), alice_c   # Bob's record
    (bob_c,) = _contacts(cohort['bob']).values()
    first_seq = bob_c.get('reach_seq', 0)
    assert not any(DAVE_EP in h for h in bob_c['rendezvous'])

    for name in ('alice', 'bob'):
        os.remove(cohort[name]['log'])
    procs = _start(cohort, {'alice': {'AT_USE_RELAY': DAVE_EP},
                            'bob': {'AT_USE_RELAY': DAVE_EP}, 'dave': DAVE_RELAY})
    try:
        assert _await_log(cohort['bob'], 'is reachable via', timeout=60), \
            _log(cohort['bob'])[-3000:]
    finally:
        _stop(cohort, procs)
    (bob_c,) = _contacts(cohort['bob']).values()
    assert bob_c.get('reach_seq', 0) > first_seq, bob_c
    assert DAVE_EP in bob_c['rendezvous'][0], bob_c
