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
"""Find a friend by handle, three real nodes (FIRST_CONTACT_PLAN Phase 3).

Carol is a relay that also serves the directory (AT_RELAY + AT_REGISTRY),
trusting one issuer. Alice and Bob have no direct path (the setup of
test_relay_three_node) and are both registered with Carol. Alice publishes
her handle with that issuer's attestation; Bob looks it up, asks, Alice's app
accepts, and both end up holding an unverified directory contact -- with no
invitation link ever passing between the two people.

The control, test_a_request_waits_for_the_app, is what shows the accept is the
app's: without it the two never become peers.
"""
import json
import os
import queue
import time

import pytest
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

from .test_relay_three_node import (ALICE, BOB, CAROL, CAROL_EP, CAROL_RELAY, cohort,  # noqa: F401
                                    _start, _stop)
from .test_first_contact_two_node import STARTUP

ISSUER = SigningKey(b'\x44' * 32)
STEP = 30


def _await(q_out, want, seen, timeout=STEP):
    from autonomous_trust.core.identity.first_contact import FirstContactEvent
    from autonomous_trust.core._python.identity.directory_contact import DirectoryEvent
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            item = q_out.get(timeout=1)
        except queue.Empty:
            continue
        if not isinstance(item, (FirstContactEvent, DirectoryEvent)):
            continue
        seen.append(item)
        if want(item):
            return item
    raise AssertionError('no matching event within %ds; saw %r' % (timeout, seen))


def _signing_key(cfg_dir):
    from autonomous_trust.core.config import Configuration
    from autonomous_trust.core._python.network import relay
    return relay._signing_hex(Configuration.from_file(
        os.path.join(cfg_dir, 'identity.cfg.json'))).lower()


def _setup(cohort):
    with open(os.path.join(cohort['carol']['cfg_dir'], 'registry_issuers.cfg.json'), 'w') as f:
        json.dump({'issuers': [ISSUER.verify_key.encode(HexEncoder).decode()]}, f)
    envs = {'alice': {'AT_USE_RELAY': CAROL_EP}, 'bob': {'AT_USE_RELAY': CAROL_EP},
            'carol': dict(CAROL_RELAY, AT_REGISTRY='1')}
    return _start(cohort, envs)


def _publish_and_find(cohort, seen_a, seen_b):
    from autonomous_trust.core.app_verbs import AppRequest
    from autonomous_trust.core._python.contacts import directory as d
    from autonomous_trust.core._python.identity import directory_contact as dc
    alice, bob = cohort['alice'], cohort['bob']
    att = d.attest(ISSUER, 'alice@example.org', _signing_key(alice['cfg_dir']),
                   int(time.time()) + 3600)
    # Registration with Carol runs in the background: publish until filed.
    deadline = time.monotonic() + STEP
    while True:
        alice['q_in'].put(AppRequest(dc.APP_DIR_PUBLISH, json.dumps(
            {'ref': 'pub', 'attestation': att.to_wire()})))
        try:
            _await(alice['q_out'], lambda e: e.kind == dc.EVENT_PUBLISHED, seen_a, timeout=5)
            break
        except AssertionError:
            if time.monotonic() > deadline:
                raise
    deadline = time.monotonic() + STEP
    while True:
        bob['q_in'].put(AppRequest(dc.APP_DIR_LOOKUP, json.dumps(
            {'ref': 'look', 'handle': 'Alice@Example.org'})))
        ev = _await(bob['q_out'], lambda e: e.kind in (dc.EVENT_FOUND, dc.EVENT_NOT_FOUND),
                    seen_b, timeout=15)
        if ev.kind == dc.EVENT_FOUND or time.monotonic() > deadline:
            break
        time.sleep(1)
    assert ev.kind == dc.EVENT_FOUND, seen_b
    return ev


def test_find_a_friend_by_handle(cohort):
    from autonomous_trust.core.app_verbs import AppRequest
    from autonomous_trust.core.contacts import Contacts, Provenance
    from autonomous_trust.core.config import Configuration
    from autonomous_trust.core.identity import first_contact as fc
    from autonomous_trust.core._python.identity import directory_contact as dc
    procs = _setup(cohort)
    seen_a, seen_b = [], []
    try:
        time.sleep(STARTUP)
        alice, bob = cohort['alice'], cohort['bob']
        found = _publish_and_find(cohort, seen_a, seen_b)
        bob['q_in'].put(AppRequest(dc.APP_REQUEST, json.dumps(
            {'ref': 'ask', 'handle': 'alice@example.org'})))
        _await(bob['q_out'], lambda e: e.kind == dc.EVENT_REQUEST_SENT, seen_b)
        asked = _await(alice['q_out'], lambda e: e.kind == dc.EVENT_CONTACT_REQUEST, seen_a)
        assert asked.handle == 'alice@example.org'
        alice['q_in'].put(AppRequest(dc.APP_ACCEPT, json.dumps({'ref': asked.ref})))
        est_b = _await(bob['q_out'], lambda e: e.kind == fc.EVENT_ESTABLISHED, seen_b)
        est_a = _await(alice['q_out'], lambda e: e.kind == fc.EVENT_ESTABLISHED, seen_a)
        assert est_b.peer_uuid == found.peer_uuid and est_b.ref == 'ask'
        assert est_a.peer_uuid == asked.peer_uuid and est_a.ref == asked.ref
    finally:
        _stop(cohort, procs)
    for me, them in (('alice', asked.peer_uuid), ('bob', found.peer_uuid)):
        os.environ[Configuration.ROOT_VARIABLE_NAME] = cohort[me]['cfg_dir']
        c = Contacts.load().get(them)
        assert c is not None and not c.verified and c.provenance == Provenance.directory


def test_a_request_waits_for_the_app(cohort):
    from autonomous_trust.core.app_verbs import AppRequest
    from autonomous_trust.core.identity import first_contact as fc
    from autonomous_trust.core._python.identity import directory_contact as dc
    procs = _setup(cohort)
    seen_a, seen_b = [], []
    try:
        time.sleep(STARTUP)
        alice, bob = cohort['alice'], cohort['bob']
        _publish_and_find(cohort, seen_a, seen_b)
        bob['q_in'].put(AppRequest(dc.APP_REQUEST, json.dumps(
            {'ref': 'ask', 'handle': 'alice@example.org'})))
        _await(alice['q_out'], lambda e: e.kind == dc.EVENT_CONTACT_REQUEST, seen_a)
        with pytest.raises(AssertionError):
            _await(bob['q_out'], lambda e: e.kind == fc.EVENT_ESTABLISHED, seen_b, timeout=15)
    finally:
        _stop(cohort, procs)
