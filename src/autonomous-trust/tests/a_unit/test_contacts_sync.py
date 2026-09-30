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
"""Phase 4, live pairing, offline half: one user's address book kept the same
on all their devices (contacts/sync.py), and the file of those devices
(contacts/siblings.py)."""
import json
import random

import pytest
from nacl.signing import SigningKey

from autonomous_trust.core.identity import Identity
from autonomous_trust.core.contacts import (
    Contact, Contacts, Provenance, Siblings, sync, create_device_cert,
    adopt_operator, link_device)
from autonomous_trust.core.contacts.device import DEVICES_MAX

NOW = 1_800_000_000.0


def make_identity(name):
    return Identity.initialize(name, name, '10.0.0.1')


@pytest.fixture(scope='module')
def people():
    return {n: make_identity(n) for n in ('bob', 'carol', 'dave', 'erin')}


def _contact(ident, at=NOW - 1000, **kw):
    return Contact(ident.publish(), petname=ident.nickname + '-pet',
                   added_at=at, **kw)


def _store(*contacts):
    s = Contacts()
    for c in contacts:
        s.add(c)
    return s


def _copy(store):
    return Contacts.from_canonical(json.loads(json.dumps(store.to_canonical())))


def _book(store):
    """What should agree between siblings: everything but provenance and
    reachability."""
    out = {}
    for u, c in store.to_canonical()['contacts'].items():
        c = dict(c)
        for k in ('provenance', 'reach_seq', 'rendezvous'):
            c.pop(k, None)
        out[u] = c
    return out, store.to_canonical().get('tombstones', {})


# -- the stored form ----------------------------------------------------------

def test_a_store_never_edited_is_byte_identical(people):
    """No updated_at and no tombstones until the user edits or removes."""
    c = _contact(people['bob']).mark_verified()
    d = _store(c).to_canonical()
    assert 'tombstones' not in d
    assert 'updated_at' not in d['contacts'][c.uuid]


def test_rename_dates_the_record(people):
    c = _contact(people['bob'])
    c.touch(NOW)
    assert c.to_canonical()['updated_at'] == NOW
    assert Contact.from_canonical(c.to_canonical()).updated_at == NOW
    assert c.version() == NOW


def test_touch_never_goes_back(people):
    c = _contact(people['bob'], at=NOW)
    c.touch(NOW - 50)
    assert c.version() == NOW


def test_remove_leaves_a_tombstone_and_readding_lifts_it(people):
    c = _contact(people['bob'])
    s = _store(c)
    assert s.remove(c.uuid, at=NOW)
    assert s.tombstones == {c.uuid: NOW}
    again = _copy(s)
    assert again.tombstones == {c.uuid: NOW}
    s.add(_contact(people['bob'], at=NOW + 1))
    assert s.tombstones == {}


def test_a_tombstone_is_never_older_than_what_it_removed(people):
    c = _contact(people['bob'], at=NOW)
    s = _store(c)
    s.remove(c.uuid, at=NOW - 500)
    assert s.tombstones[c.uuid] == NOW


@pytest.mark.parametrize('bad', [-1, 'x', True, None, float('inf')])
def test_a_malformed_tombstone_is_dropped_on_load(people, bad):
    d = Contacts().to_canonical()
    d['tombstones'] = {str(people['bob'].uuid): bad}
    assert Contacts.from_canonical(d).tombstones == {}


def test_a_tombstone_for_a_live_contact_is_dropped_on_load(people):
    c = _contact(people['bob'])
    d = _store(c).to_canonical()
    d['tombstones'] = {c.uuid: NOW}
    assert Contacts.from_canonical(d).tombstones == {}


# -- merge --------------------------------------------------------------------

def test_a_new_contact_arrives_as_a_sibling_one_verification_and_all(people):
    c = _contact(people['bob']).mark_verified()
    c.verified_at = NOW - 10
    here = Contacts()
    assert sync.merge(here, sync.build(_store(c)), now=NOW) == [(c.uuid, 'added')]
    got = here.get(c.uuid)
    assert got.provenance == Provenance.sibling
    assert got.verified and got.verified_at == NOW - 10
    assert got.trust_seed == c.trust_seed
    assert got.petname == c.petname


def test_the_newer_edit_wins_and_keeps_our_provenance(people):
    mine = _contact(people['bob'], provenance=Provenance.in_person)
    theirs = _contact(people['bob'])
    theirs.petname = 'Bobby'
    theirs.touch(NOW)
    here = _store(mine)
    assert sync.merge(here, sync.build(_store(theirs)), now=NOW) == \
        [(mine.uuid, 'updated')]
    assert here.get(mine.uuid).petname == 'Bobby'
    assert here.get(mine.uuid).provenance == Provenance.in_person


def test_an_older_edit_loses(people):
    mine = _contact(people['bob'])
    mine.petname = 'Bobby'
    mine.touch(NOW)
    theirs = _contact(people['bob'])
    theirs.petname = 'Robert'
    theirs.touch(NOW - 5)
    here = _store(mine)
    assert sync.merge(here, sync.build(_store(theirs)), now=NOW) == []
    assert here.get(mine.uuid).petname == 'Bobby'


def test_a_tie_goes_the_same_way_on_both_sides(people):
    a = _contact(people['bob'])
    a.petname = 'Aaa'
    a.touch(NOW)
    b = _contact(people['bob'])
    b.petname = 'Zzz'
    b.touch(NOW)
    sa, sb = _store(a), _store(b)
    pa, pb = sync.build(sa), sync.build(sb)
    sync.merge(sa, pb, now=NOW)
    sync.merge(sb, pa, now=NOW)
    assert sa.get(a.uuid).petname == sb.get(a.uuid).petname == 'Zzz'


def test_reachability_is_merged_not_replaced(people):
    mine = _contact(people['bob'], rendezvous=['relay:a'], reach_seq=9)
    theirs = _contact(people['bob'], rendezvous=['relay:b'], reach_seq=3)
    theirs.touch(NOW)
    here = _store(mine)
    sync.merge(here, sync.build(_store(theirs)), now=NOW)
    got = here.get(mine.uuid)
    assert got.reach_seq == 9
    assert got.rendezvous == ['relay:a', 'relay:b']


def test_a_rename_elsewhere_does_not_undo_our_verification(people):
    """The older copy verified; the newer one only renamed."""
    mine = _contact(people['bob']).mark_verified()
    mine.verified_at = NOW - 20
    theirs = _contact(people['bob'])
    theirs.petname = 'Bobby'
    theirs.touch(NOW - 10)
    here, there = _store(mine), _store(theirs)
    ph, pt = sync.build(here), sync.build(there)
    sync.merge(here, pt, now=NOW)
    sync.merge(there, ph, now=NOW)
    for s in (here, there):
        got = s.get(mine.uuid)
        assert got.verified and got.verified_at == NOW - 20
        assert got.petname == 'Bobby'
    assert _book(here) == _book(there)


def test_an_older_copy_still_gives_us_its_verification(people):
    mine = _contact(people['bob'])
    mine.petname = 'Bobby'
    mine.touch(NOW)
    theirs = _contact(people['bob']).mark_verified()
    theirs.verified_at = NOW - 30
    here = _store(mine)
    assert sync.merge(here, sync.build(_store(theirs)), now=NOW) == \
        [(mine.uuid, 'updated')]
    got = here.get(mine.uuid)
    assert got.verified and got.petname == 'Bobby'


def test_devices_linked_on_either_side_both_survive(people):
    op = SigningKey.generate()
    carol, dave, erin = people['carol'], people['dave'], people['erin']
    base = _contact(carol).mark_verified()
    assert adopt_operator(base, create_device_cert(op, carol)) == ''
    here, there = _store(base), _copy(_store(base))
    assert link_device(here, dave.publish(), create_device_cert(op, dave))[1] == ''
    assert link_device(there, erin.publish(), create_device_cert(op, erin))[1] == ''
    ph, pt = sync.build(here), sync.build(there)
    sync.merge(here, pt, now=NOW + 10_000)
    sync.merge(there, ph, now=NOW + 10_000)
    for s in (here, there):
        assert sorted(s.get(base.uuid).device_uuids()) == \
            sorted([str(dave.uuid), str(erin.uuid)])
        assert s.get(str(erin.uuid)) is s.get(base.uuid)


def test_a_removal_wins_over_an_equal_or_older_record(people):
    c = _contact(people['bob'], at=NOW - 100)
    here = _store(c)
    there = _copy(here)
    there.remove(c.uuid, at=NOW - 100)
    assert sync.merge(here, sync.build(there), now=NOW) == [(c.uuid, 'removed')]
    assert c.uuid not in here
    assert here.tombstones[c.uuid] == NOW - 100


def test_a_later_readd_beats_the_removal(people):
    c = _contact(people['bob'], at=NOW - 100)
    there = _store(c)
    there.remove(c.uuid, at=NOW - 50)
    here = _store(_contact(people['bob'], at=NOW - 10))
    assert sync.merge(here, sync.build(there), now=NOW) == []
    assert c.uuid in here
    # ...and the re-add then removes the tombstone over there.
    assert sync.merge(there, sync.build(here), now=NOW) == [(c.uuid, 'added')]
    assert there.tombstones == {}


def test_a_removed_contact_does_not_come_back(people):
    c = _contact(people['bob'], at=NOW - 100)
    here = _store(c)
    stale = sync.build(here)
    here.remove(c.uuid, at=NOW - 50)
    assert sync.merge(here, stale, now=NOW) == []
    assert c.uuid not in here


def test_a_tombstone_is_kept_to_pass_on(people):
    c = _contact(people['bob'])
    there = _store(c)
    there.remove(c.uuid, at=NOW)
    here = Contacts()
    assert sync.merge(here, sync.build(there), now=NOW) == [(c.uuid, 'tombstone')]
    third = _store(_contact(people['bob']))
    assert sync.merge(third, sync.build(here), now=NOW) == [(c.uuid, 'removed')]


def test_a_time_from_the_future_is_taken_as_now(people):
    theirs = _contact(people['bob'])
    theirs.petname = 'Bobby'
    theirs.touch(NOW + 86400)
    here = _store(_contact(people['bob']))
    sync.merge(here, sync.build(_store(theirs)), now=NOW)
    got = here.get(theirs.uuid)
    assert got.petname == 'Bobby' and got.version() == NOW
    # A local edit a minute later still wins.
    got.petname = 'Robert'
    got.touch(NOW + 60)
    assert got.version() == NOW + 60


def test_a_time_within_the_skew_is_kept(people):
    theirs = _contact(people['bob'])
    theirs.touch(NOW + sync.CLOCK_SKEW)
    here = Contacts()
    sync.merge(here, sync.build(_store(theirs)), now=NOW)
    assert here.get(theirs.uuid).updated_at == NOW + sync.CLOCK_SKEW


def test_a_future_tombstone_is_taken_as_now(people):
    c = _contact(people['bob'])
    there = _store(c)
    there.remove(c.uuid, at=NOW + 86400)
    here = Contacts()
    sync.merge(here, sync.build(there), now=NOW)
    assert here.tombstones[c.uuid] == NOW


def test_our_own_devices_are_never_contacts(people):
    c = _contact(people['bob'])
    here = Contacts()
    assert sync.merge(here, sync.build(_store(c)), now=NOW, exclude=[c.uuid]) == []
    assert len(here) == 0


def test_a_device_filed_under_another_contact_is_refused(people):
    op = SigningKey.generate()
    carol, dave = people['carol'], people['dave']
    base = _contact(carol).mark_verified()
    adopt_operator(base, create_device_cert(op, carol))
    here = _store(base)
    link_device(here, dave.publish(), create_device_cert(op, dave))
    # A record for dave on his own would file him twice.
    assert sync.merge(here, sync.build(_store(_contact(dave))), now=NOW) == []
    assert here.get(str(dave.uuid)) is here.get(base.uuid)


def test_a_second_holder_of_one_operator_key_is_refused(people):
    op = SigningKey.generate()
    carol, dave = people['carol'], people['dave']
    mine = _contact(carol).mark_verified()
    adopt_operator(mine, create_device_cert(op, carol))
    theirs = _contact(dave).mark_verified()
    adopt_operator(theirs, create_device_cert(op, dave))
    here = _store(mine)
    assert sync.merge(here, sync.build(_store(theirs)), now=NOW) == []


def test_a_delta_carries_only_what_changed(people):
    b, c = _contact(people['bob']), _contact(people['carol'])
    s = _store(b, c)
    s.remove(c.uuid, at=NOW)
    d = sync.build(s, [c.uuid])
    assert d['contacts'] == {} and list(d['tombstones']) == [c.uuid]


@pytest.mark.parametrize('payload', [
    None, [], {}, {'v': 1}, {'v': 2, 'typename': sync.SYNC_TYPENAME},
    {'v': 1.0, 'typename': sync.SYNC_TYPENAME},
    {'v': True, 'typename': sync.SYNC_TYPENAME},
    {'v': 1, 'typename': sync.SYNC_TYPENAME, 'contacts': []},
    {'v': 1, 'typename': sync.SYNC_TYPENAME, 'tombstones': 'x'},
])
def test_not_a_sync_payload(payload):
    with pytest.raises(sync.InvalidSync):
        sync.merge(Contacts(), payload, now=NOW)


def test_malformed_records_inside_are_skipped(people):
    c = _contact(people['bob'])
    p = sync.build(_store(c))
    p['contacts']['junk'] = {'identity': 'nope'}
    p['contacts'][str(people['carol'].uuid)] = c.to_canonical()   # wrong key
    p['tombstones']['NOT-A-UUID'] = NOW
    here = Contacts()
    assert sync.merge(here, p, now=NOW) == [(c.uuid, 'added')]


def test_siblings_converge_whatever_order_edits_arrive(people):
    """Random edits on three devices, then everyone swaps with everyone:
    the address books agree."""
    rng = random.Random(4)
    idents = [people[n] for n in ('bob', 'carol', 'dave', 'erin')]
    devices = [Contacts() for _ in range(3)]
    t = NOW - 10_000
    for _ in range(60):
        t += rng.choice([0, 1, 5])
        s = rng.choice(devices)
        who = rng.choice(idents)
        c = s.contacts.get(str(who.uuid))
        op = rng.random()
        if c is None and op < 0.6:
            s.add(_contact(who, at=t))
        elif c is not None and op < 0.4:
            c.petname = 'p%d' % rng.randint(0, 9)
            c.touch(t)
        elif c is not None and op < 0.6:
            c.mark_verified()
            c.verified_at = t
        elif c is not None:
            s.remove(c.uuid, at=t)
    for _ in range(2):
        for a in devices:
            for b in devices:
                if a is not b:
                    sync.merge(b, sync.build(a), now=NOW)
    assert _book(devices[0]) == _book(devices[1]) == _book(devices[2])


# -- siblings -----------------------------------------------------------------

@pytest.fixture
def op():
    return SigningKey.generate()


def test_pair_with_a_sibling_under_our_operator(tmp_path, op, people):
    me, other = people['bob'], people['carol']
    sib = Siblings()
    assert sib.add(other.publish(), create_device_cert(op, other),
                   create_device_cert(op, me)) == ''
    assert str(other.uuid) in sib
    assert sib.operator == op.verify_key.encode().hex()
    sib.save(str(tmp_path))
    again = Siblings.load(str(tmp_path))
    assert again.uuids() == [str(other.uuid)] and again.operator == sib.operator
    # Pairing again is a no-op success.
    assert again.add(other.publish(), create_device_cert(op, other),
                     create_device_cert(op, me)) == ''
    assert len(again) == 1


def test_no_own_cert_no_siblings(op, people):
    other = people['carol']
    assert Siblings().add(other.publish(), create_device_cert(op, other),
                          None) == 'unknown_operator'


def test_another_operators_device_is_not_a_sibling(op, people):
    me, other = people['bob'], people['carol']
    assert Siblings().add(other.publish(),
                          create_device_cert(SigningKey.generate(), other),
                          create_device_cert(op, me)) == 'mismatch'


def test_a_cert_for_someone_else_is_refused(op, people):
    me, other, third = people['bob'], people['carol'], people['dave']
    assert Siblings().add(other.publish(), create_device_cert(op, third),
                          create_device_cert(op, me)) == 'mismatch'


def test_this_node_is_not_its_own_sibling(op, people):
    me = people['bob']
    assert Siblings().add(me.publish(), create_device_cert(op, me),
                          create_device_cert(op, me)) == 'known'


def test_a_forged_cert_is_refused(op, people):
    me, other = people['bob'], people['carol']
    wire = create_device_cert(op, other).to_wire()
    wire['sig'] = '00' * 64
    assert Siblings().add(other.publish(), wire,
                          create_device_cert(op, me)) == 'bad_signature'


def test_at_most_devices_max_siblings(op, people):
    me = people['bob']
    sib = Siblings()
    for i in range(DEVICES_MAX):
        d = make_identity('dev%d' % i)
        assert sib.add(d.publish(), create_device_cert(op, d),
                       create_device_cert(op, me)) == ''
    d = make_identity('one-too-many')
    assert sib.add(d.publish(), create_device_cert(op, d),
                   create_device_cert(op, me)) == 'full'


def test_a_new_operator_starts_the_list_over(op, people):
    me, other, third = people['bob'], people['carol'], people['dave']
    sib = Siblings()
    sib.add(other.publish(), create_device_cert(op, other), create_device_cert(op, me))
    op2 = SigningKey.generate()
    assert sib.add(third.publish(), create_device_cert(op2, third),
                   create_device_cert(op2, me)) == ''
    assert sib.uuids() == [str(third.uuid)]


def test_a_hand_added_sibling_does_not_load(tmp_path, op, people):
    me, other, third = people['bob'], people['carol'], people['dave']
    sib = Siblings()
    sib.add(other.publish(), create_device_cert(op, other), create_device_cert(op, me))
    d = sib.to_canonical()
    # Another operator's device, and a cert moved onto another identity.
    foreign = make_identity('foreign')
    d['devices'].append({'identity': d['devices'][0]['identity'],
                         'cert': create_device_cert(SigningKey.generate(),
                                                    other).to_wire(),
                         'added_at': 1.0})
    from autonomous_trust.core.identity.identity import public_identity_to_canonical
    d['devices'].append({'identity': public_identity_to_canonical(foreign.publish()),
                         'cert': create_device_cert(op, third).to_wire(),
                         'added_at': 1.0})
    assert Siblings.from_canonical(d).uuids() == [str(other.uuid)]


def test_no_operator_on_file_means_no_siblings(op, people):
    me, other = people['bob'], people['carol']
    sib = Siblings()
    sib.add(other.publish(), create_device_cert(op, other), create_device_cert(op, me))
    d = sib.to_canonical()
    d['operator'] = ''
    assert len(Siblings.from_canonical(d)) == 0


def test_no_file_no_siblings(tmp_path):
    assert len(Siblings.load(str(tmp_path))) == 0
    (tmp_path / 'siblings.cfg.json').write_text('{not json')
    assert len(Siblings.load(str(tmp_path))) == 0
