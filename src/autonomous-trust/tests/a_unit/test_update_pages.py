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
"""A catch-up reply too large for one datagram goes as pages.

Partition cohort part-3629127 (2026-10-14, ISSUES §2.67): the whole resident
window a `latest update` carries came to 104 KB once commit and placement
certificates rode on every entry, and the UDP transport cut each reply to
65,507 bytes. The island that had been behind never caught up. A window over
the page size now goes as {page, of, head, chain} pages, and the receiver
handles the window only once every page of one head from one sender is in.

The conformance harness resets the C reputation state before every step, so
assembly across pages is pinned here and in rep_update_pages_test.c.
"""
from uuid import uuid4

from autonomous_trust.core.config import from_json_string, to_json_string
from autonomous_trust.core.network import Message
from autonomous_trust.core.reputation.protocol import ReputationProtocol
from autonomous_trust.core.system import CfgIds

from autonomous_trust.core.reputation.reputation import (
    Transaction, TransactionHistory, placement_entry)

from tests.a_unit.test_commit_certificates import _ident, _node, _sent
from tests.a_unit.test_placement_acceptor import _roster_of
from tests.a_unit.test_placement_reconcile import _signed

ENTRIES = 20
_IDS = {}


def _id(name, n):
    """One identity per name for the module, so a receiver's roster and the
    signers of the window it is sent are the same keys."""
    if name not in _IDS:
        _IDS[name] = _ident(name, n)
    return _IDS[name]


def _raw(function, obj, sender):
    m = Message(CfgIds.reputation, function, obj, None, from_whom=sender)
    m.verified = True
    m.from_whom = sender
    return m


def _staged(me, other):
    """`me` holding ENTRIES placed entries, each placement certified by
    ada, bob and cal."""
    rp, q = _node(me, [other])
    hist = TransactionHistory()
    for i in range(ENTRIES):
        hist.apply_placed(hist.next_index, [placement_entry(Transaction(
            uuid4(), me.uuid, 0.3 + 0.01 * i, other.uuid, 0.9 - 0.01 * i))],
            {'voter': 'sig'})
    rp.history = _signed(hist, [_id('ada', 1), _id('bob', 2), _id('cal', 3)])
    return rp, q


def _ask(rp, q, asker, page_bytes):
    """What `rp` answers `asker`'s `update needed` with: the raw payloads."""
    rp.update_page_bytes = page_bytes
    rp.handle_outdated(q, _raw(ReputationProtocol.outdated, '0', asker))
    return [m.obj for m in _sent(q) if m.function == ReputationProtocol.update]


def _pages(me, bob):
    rp, q = _staged(me, bob)
    return _ask(rp, q, bob, 1000)


def _receiver():
    """cal, in a group of ada, bob and cal whose roster is in force."""
    ada, bob, cal = _id('ada', 1), _id('bob', 2), _id('cal', 3)
    rp, q = _node(cal, [ada, bob])
    rp.history.roster_anchor = _roster_of([ada, bob, cal])
    return rp, q


def _deliver(rp, q, obj, sender):
    rp.handle_update(q, _raw(ReputationProtocol.update, obj, sender))


def test_a_window_over_the_page_size_goes_in_pages():
    me, bob = _id('ada', 1), _id('bob', 2)
    rp, q = _staged(me, bob)
    whole = _ask(rp, q, bob, 10 ** 9)
    assert len(whole) == 1
    assert isinstance(from_json_string(whole[0]), list)      # unpaged, as before

    pages = [from_json_string(p) for p in _ask(rp, q, bob, 1000)]
    assert len(pages) > 1
    head = rp.history._head_hash
    head = head.decode() if isinstance(head, bytes) else head
    joined = []
    for i, page in enumerate(pages):
        assert page['page'] == i and page['of'] == len(pages)
        assert page['head'] == head and 'group' not in page
        # Within the page size, unless one entry is larger by itself.
        size = sum(len(to_json_string(e)) + 1 for e in page['chain'])
        assert size <= 1000 or len(page['chain']) == 1
        joined += page['chain']
    # Together, exactly the window an unpaged reply carries.
    assert to_json_string(joined) == to_json_string(from_json_string(whole[0]))
    assert len(joined) == ENTRIES


def test_pages_are_put_together_in_any_order():
    me, bob = _id('ada', 1), _id('bob', 2)
    pages = _pages(me, bob)
    assert len(pages) > 2
    rp, q = _receiver()
    for p in reversed(pages[1:]):               # last first, the first held back
        _deliver(rp, q, p, me)
        assert len(rp.history) == 0
    _deliver(rp, q, pages[0], me)
    assert len(rp.history) == ENTRIES


def test_a_page_of_another_head_starts_over():
    me, bob = _id('ada', 1), _id('bob', 2)
    pages = _pages(me, bob)
    assert len(pages) > 2
    rp, q = _receiver()
    for p in pages[:-1]:
        _deliver(rp, q, p, me)
    moved = from_json_string(pages[-1])
    moved['head'] = 'another head'
    _deliver(rp, q, to_json_string(moved), me)
    assert len(rp.history) == 0
    # The pages of the new head start over, so the earlier ones count for
    # nothing: the whole window again, and only then is it applied.
    for p in pages:
        assert len(rp.history) == 0
        _deliver(rp, q, p, me)
    assert len(rp.history) == ENTRIES


def test_pages_from_two_senders_do_not_mix():
    me, bob = _id('ada', 1), _id('bob', 2)
    pages = _pages(me, bob)
    assert len(pages) > 1
    rp, q = _receiver()
    for i, p in enumerate(pages):
        _deliver(rp, q, p, me if i % 2 == 0 else bob)
    assert len(rp.history) == 0
