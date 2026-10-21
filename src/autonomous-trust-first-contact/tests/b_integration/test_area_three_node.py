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
"""Find people nearby at an area hub, three real nodes.

Carol is a relay that also serves as the hub for area u4pr (AT_RELAY + AT_HUB).
Alice and Bob have no direct path (the setup of test_relay_three_node) and are
both registered with Carol. Both list themselves in u4pr; Bob's lookup finds
Alice's card, he asks, Alice's app accepts, and both end up holding an
unverified contact of area provenance -- having never met, and with nothing
passed between them but what the hub was told.

The control, test_a_lookup_from_outside_the_area_finds_nobody, is what shows a
hub cannot be read from outside the area it serves: Alice is listed, Bob is
not, and Bob's lookup comes back empty.
"""
import json
import os
import queue
import time

from .test_relay_three_node import (ALICE, BOB, CAROL, CAROL_EP, CAROL_RELAY, cohort,  # noqa: F401
                                    _start, _stop)
from .test_first_contact_two_node import STARTUP

STEP = 30


def _await(q_out, want, seen, timeout=STEP):
    from autonomous_trust.first_contact.first_contact import FirstContactEvent
    from autonomous_trust.first_contact._python.area_contact import AreaEvent
    from autonomous_trust.first_contact._python.directory_contact import DirectoryEvent
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            item = q_out.get(timeout=1)
        except queue.Empty:
            continue
        if not isinstance(item, (FirstContactEvent, DirectoryEvent, AreaEvent)):
            continue
        seen.append(item)
        if want(item):
            return item
    raise AssertionError('no matching event within %ds; saw %r' % (timeout, seen))


def _setup(cohort):
    envs = {'alice': {'AT_USE_RELAY': CAROL_EP}, 'bob': {'AT_USE_RELAY': CAROL_EP},
            'carol': dict(CAROL_RELAY, AT_HUB='1', AT_HUB_AREAS='u4pr')}
    return _start(cohort, envs)


def _list(node, seen, bucket):
    """List ``node`` in u4pr, until the hub says it holds the card (registration
    with Carol runs in the background)."""
    from autonomous_trust.core.app_verbs import AppRequest
    from autonomous_trust.first_contact._python import area_contact as ac
    deadline = time.monotonic() + STEP
    while True:
        node['q_in'].put(AppRequest(ac.APP_AREA_PUBLISH, json.dumps(
            {'ref': 'pub', 'area': 'u4pr', 'bucket': bucket, 'name': 'someone'})))
        try:
            return _await(node['q_out'], lambda e: e.kind == ac.EVENT_PUBLISHED, seen, timeout=5)
        except AssertionError:
            if time.monotonic() > deadline:
                raise


def _lookup(node, seen):
    """Every card one lookup found, once its DONE arrives."""
    from autonomous_trust.core.app_verbs import AppRequest
    from autonomous_trust.first_contact._python import area_contact as ac
    node['q_in'].put(AppRequest(ac.APP_AREA_LOOKUP, json.dumps({'ref': 'look', 'area': 'u4pr'})))
    start = len(seen)
    _await(node['q_out'], lambda e: e.kind == ac.EVENT_DONE, seen)
    return [e for e in seen[start:] if e.kind == ac.EVENT_CARD]


def test_find_someone_nearby_and_become_contacts(cohort):
    from autonomous_trust.core.app_verbs import AppRequest
    from autonomous_trust.first_contact import Contacts, Provenance
    from autonomous_trust.core.config import Configuration
    from autonomous_trust.first_contact import first_contact as fc
    from autonomous_trust.first_contact._python import directory_contact as dc
    procs = _setup(cohort)
    seen_a, seen_b = [], []
    try:
        time.sleep(STARTUP)
        alice, bob = cohort['alice'], cohort['bob']
        _list(alice, seen_a, 'u4pru')
        _list(bob, seen_b, 'u4prv')
        [card] = _lookup(bob, seen_b)
        assert card.bucket == 'u4pru' and card.name == 'someone'
        bob['q_in'].put(AppRequest(dc.APP_REQUEST, json.dumps(
            {'ref': 'ask', 'area': 'u4pr', 'peer_uuid': card.peer_uuid})))
        _await(bob['q_out'], lambda e: e.kind == dc.EVENT_REQUEST_SENT, seen_b)
        asked = _await(alice['q_out'], lambda e: e.kind == dc.EVENT_CONTACT_REQUEST, seen_a)
        assert asked.handle == 'area:u4pr'
        alice['q_in'].put(AppRequest(dc.APP_ACCEPT, json.dumps({'ref': asked.ref})))
        est_b = _await(bob['q_out'], lambda e: e.kind == fc.EVENT_ESTABLISHED, seen_b)
        est_a = _await(alice['q_out'], lambda e: e.kind == fc.EVENT_ESTABLISHED, seen_a)
        assert est_b.peer_uuid == card.peer_uuid and est_b.ref == 'ask'
        assert est_a.peer_uuid == asked.peer_uuid and est_a.ref == asked.ref
    finally:
        _stop(cohort, procs)
    for me, them in (('alice', asked.peer_uuid), ('bob', card.peer_uuid)):
        os.environ[Configuration.ROOT_VARIABLE_NAME] = cohort[me]['cfg_dir']
        c = Contacts.load().get(them)
        assert c is not None and not c.verified and c.provenance == Provenance.area


def test_a_lookup_from_outside_the_area_finds_nobody(cohort):
    procs = _setup(cohort)
    seen_a, seen_b = [], []
    try:
        time.sleep(STARTUP)
        _list(cohort['alice'], seen_a, 'u4pru')
        assert _lookup(cohort['bob'], seen_b) == []
    finally:
        _stop(cohort, procs)
