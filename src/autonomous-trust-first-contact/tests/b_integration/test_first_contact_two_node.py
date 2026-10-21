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
"""First contact between two real nodes, as their apps drive it.

Two AutonomousTrust nodes on separate loopback IPs, each in its own
subprocess, that can NOT discover each other: each node's "broadcast" reaches
only itself, so they form separate cohorts and stay strangers -- the actual
first-contact precondition. The only way they meet is the invitation:

  1. Alice's app asks her node for a link (app_first_contact_invite).
  2. The link is carried to Bob's app by this test, standing in for the
     out-of-band channel.
  3. Bob's app hands it to his node (app_first_contact_initiate).
  4. The hello and the ack cross real UDP sockets.

What this covers that the unit tests and the conformance corpus cannot: the
app request crossing the main loop to identity, the hello and ack arriving on
the network process's UNKNOWN-SENDER plaintext path, and the events coming
back out through the main loop to each app's feedback queue.

Loopback caveats are the ones the core's test_two_node.py handles; its patch is
reused (copied into _loopback.py), with a peer list of just the node itself.
"""
import json
import logging
import os
import queue
import shutil
import time
from unittest.mock import patch

import pytest

from autonomous_trust.core import AutonomousTrust, Process
from autonomous_trust.core.config import Configuration
from autonomous_trust.core.config.generate import generate_identity
from autonomous_trust.core.system import comm_port
from autonomous_trust.core import plaintext_verbs
from autonomous_trust.first_contact import first_contact
from ._loopback import MP_CTX, _make_node_dir, _mock_addresses, _patch_loopback
from .. import TEST_DIR

ALICE_IP = '127.0.0.1'
BOB_IP = '127.0.0.2'
STARTUP = 12        # seconds for both nodes to reach "Ready."
STEP_TIMEOUT = 45   # seconds to wait for any one event
RUNTIME = 180       # hard ceiling on a node's life; normally sig_quit ends it first


def _run_node(cfg_dir, ip_addr, q_in, q_out, log_file):
    """Subprocess entry point: one node that hears nobody but itself."""
    os.environ[Configuration.ROOT_VARIABLE_NAME] = cfg_dir
    os.environ['AT_FIRST_CONTACT'] = '1'
    _patch_loopback([ip_addr], ip_addr, comm_port)
    with patch('autonomous_trust.core.network.network.Network.get_addresses',
               return_value=_mock_addresses(ip_addr)):
        at = AutonomousTrust(multiproc=False, log_level=logging.DEBUG,
                             logfile=log_file, testing=True, silent=True)
        at.run_forever(q_in=q_in, q_out=q_out)


def _await(q_out, want, seen, timeout=STEP_TIMEOUT):
    """The first FirstContactEvent on ``q_out`` matching ``want``; every event
    read is appended to ``seen`` for the failure message."""
    from autonomous_trust.first_contact.first_contact import FirstContactEvent
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            item = q_out.get(timeout=1)
        except queue.Empty:
            continue
        if not isinstance(item, FirstContactEvent):
            continue            # the peer carrier's traffic, not ours
        seen.append(item)
        if want(item):
            return item
    raise AssertionError('no matching event within %ds; saw %r' % (timeout, seen))


@pytest.fixture
def strangers():
    base = os.path.join(TEST_DIR, 'first_contact_two_node')
    if os.path.exists(base):
        shutil.rmtree(base)
    nodes = {}
    for name, ip in (('alice', ALICE_IP), ('bob', BOB_IP)):
        cfg_dir = _make_node_dir(base, name)
        with patch('autonomous_trust.core.network.network.Network.get_addresses',
                   return_value=_mock_addresses(ip)):
            generate_identity(cfg_dir, randomize=True, seed=int(ip.split('.')[-1]))
        # First contact's plaintext verbs: granted, as a deployment must.
        plaintext_verbs.write(cfg_dir, first_contact.EXTENSION.plaintext_verbs)
        log_dir = os.path.join(base, name, 'var', 'at')
        os.makedirs(log_dir, exist_ok=True)
        nodes[name] = {'cfg_dir': cfg_dir, 'ip': ip, 'data_dir': log_dir,
                       'log': os.path.join(log_dir, 'autonomous_trust.log'),
                       'q_in': MP_CTX.Queue(), 'q_out': MP_CTX.Queue()}
    yield nodes
    shutil.rmtree(base, ignore_errors=True)


def _contacts(node):
    from autonomous_trust.first_contact import Contacts
    return Contacts.load(node['data_dir'])


def test_two_strangers_add_each_other_over_real_sockets(strangers):
    from autonomous_trust.core.app_verbs import AppRequest
    from autonomous_trust.first_contact import first_contact as fc

    alice, bob = strangers['alice'], strangers['bob']
    procs = []
    for node in (alice, bob):
        p = MP_CTX.Process(target=_run_node, daemon=True,
                           args=(node['cfg_dir'], node['ip'], node['q_in'],
                                 node['q_out'], node['log']))
        p.start()
        procs.append(p)
    seen_a, seen_b = [], []
    try:
        time.sleep(STARTUP)

        # 1. Alice's app asks for a link, reachable at her own address.
        alice['q_in'].put(AppRequest(fc.APP_INVITE, json.dumps(
            {'ref': 'for-bob', 'ttl_seconds': 600, 'rendezvous': [ALICE_IP]})))
        minted = _await(alice['q_out'], lambda e: e.kind in (
            fc.EVENT_INVITATION, fc.EVENT_REFUSED), seen_a)
        assert minted.kind == fc.EVENT_INVITATION, minted
        assert minted.ref == 'for-bob'
        assert minted.blob.startswith('at+contact:')

        # 2-3. The link reaches Bob's app out of band; he hands it to his node.
        bob['q_in'].put(AppRequest(fc.APP_INITIATE, json.dumps(
            {'ref': 'add-alice', 'invitation': minted.blob,
             'petname': 'Alice'})))
        sent = _await(bob['q_out'], lambda e: e.kind in (
            fc.EVENT_HELLO_SENT, fc.EVENT_REFUSED), seen_b)
        assert sent.kind == fc.EVENT_HELLO_SENT, sent

        # 4. Over the wire: Alice honors the ticket, Bob honors her ack.
        a_done = _await(alice['q_out'],
                        lambda e: e.kind == fc.EVENT_ESTABLISHED, seen_a)
        b_done = _await(bob['q_out'],
                        lambda e: e.kind == fc.EVENT_ESTABLISHED, seen_b)
    finally:
        for node in (alice, bob):
            node['q_in'].put(Process.sig_quit)
        for p in procs:
            p.join(timeout=30)
            if p.is_alive():
                p.terminate()
                p.join(timeout=5)

    assert (a_done.role, a_done.ref) == ('inviter', 'for-bob')
    assert (b_done.role, b_done.ref) == ('initiator', 'add-alice')
    assert a_done.peer_uuid == sent.peer_uuid or b_done.peer_uuid == sent.peer_uuid
    assert b_done.peer_uuid == sent.peer_uuid          # Bob reached who he meant to

    # Both address books hold the other, unverified (no in-person exchange,
    # no safety-number compare yet). Bob kept the petname his app chose.
    a_book, b_book = _contacts(alice), _contacts(bob)
    assert b_done.peer_uuid in b_book
    assert b_book.get(b_done.peer_uuid).petname == 'Alice'
    assert b_book.get(b_done.peer_uuid).verified is False
    assert a_done.peer_uuid in a_book
    assert a_book.get(a_done.peer_uuid).verified is False

    # They met ONLY through the invitation: neither discovered the other as a
    # cohort member, so no group membership was ever proposed between them.
    for node in (alice, bob):
        with open(node['log']) as fh:
            log = fh.read()
        assert 'direct peer' in log, node['log']
        assert 'Received new identity:' not in log, (
            '%s discovered its peer over the LAN; the test no longer isolates '
            'first contact' % node['log'])
