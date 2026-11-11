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
"""A Transaction holds its peers' ids as strings, whatever it is handed.

Hostile-join run, 2026-11-04: identities carry their uuid as a string, but an
entry learned from another member's placement is decoded with ``UUID``
objects. The history indexed that entry under the ``UUID``, so every lookup by
a peer's string id missed: 107 bilateral entries on a joiner's chain, and every
peer still read 0 transactions, 0 bilateral txs for tit-for-tat, and tier 0.
The canonical bytes already render an id with ``str``, so the entry hash is the
same either way.
"""
import json
from unittest.mock import MagicMock
from uuid import uuid4

from autonomous_trust.core.reputation.placement import entry_from_dict, entry_to_dict
from autonomous_trust.core.reputation.reputation import Transaction, TransactionHistory

from tests.a_unit.test_placement_acceptor import (  # noqa: F401 (fixture)
    _certify, _entry, _placed, _placing, _value, four)


def _ids():
    a, b = sorted((uuid4(), uuid4()), key=str)
    return a, b


class TestTransaction:
    def test_uuid_ids_are_held_as_strings(self):
        a, b = _ids()
        s = uuid4()
        tx = Transaction(uuid4(), p1_id=a, p1_score_milli=900,
                         p2_id=b, p2_score_milli=100)
        att = Transaction(uuid4(), p1_id=a, p1_score_milli=300, attested=True,
                          subject_id=s, evidence_digest='a' * 64)
        assert (tx.p1_id, tx.p2_id, att.subject_id) == (str(a), str(b), str(s))

    def test_the_entry_hash_does_not_change(self):
        a, b = _ids()
        task = uuid4()
        as_uuid = Transaction(task, p1_id=a, p1_score_milli=900,
                              p2_id=b, p2_score_milli=100, index=3)
        as_str = Transaction(task, p1_id=str(a), p1_score_milli=900,
                             p2_id=str(b), p2_score_milli=100, index=3)
        assert as_uuid.entry_hash() == as_str.entry_hash()

    def test_a_half_added_by_uuid_is_held_as_a_string(self):
        a, b = _ids()
        tx = Transaction(uuid4())
        tx.add(a, 900)
        tx.add(b, 100)
        assert (tx.p1_id, tx.p2_id) == (str(a), str(b))


class TestHistory:
    def test_a_decoded_entry_is_found_by_either_form(self):
        a, b = _ids()
        tx = Transaction(uuid4(), p1_id=a, p1_score_milli=900,
                         p2_id=b, p2_score_milli=100)
        h = TransactionHistory()
        h._append_placed([entry_from_dict(entry_to_dict(tx))], {})
        assert len(h.by_peer(str(a))) == 1
        assert len(h.by_peer(b)) == 1

    def test_halves_by_uuid_and_by_string_pair(self):
        a, b = _ids()
        task = uuid4()
        h = TransactionHistory()
        h.record_half(task, a, 900)
        assert h.record_half(task, str(b), 100) == 'ready'


def test_a_learned_placement_counts_in_the_dump(four, monkeypatch):
    prop, obs = four[0], four[3]
    rp, q = _placing(obs, four)
    e = _entry(four, four[1], four[2])
    value = _value(e)
    _placed(rp, q, prop, value, _certify(value, 0, b'', four[:3]))
    monkeypatch.setenv('AT_REP_DUMP_SEC', '1')
    rp.logger = MagicMock()
    rp._last_rep_dump = 0
    rp._dump_reputation_trace(1e9)
    [call] = [c for c in rp.logger.info.call_args_list if c.args[0] == 'AT_REPDUMP %s']
    view = {v['s']: v['n'] for v in json.loads(call.args[1])['view']}
    assert view[str(four[1].uuid)] == 1 and view[str(four[2].uuid)] == 1


def test_the_dump_carries_the_primary_chain_length_and_head(four, monkeypatch):
    # Two nodes at the same chain length with different heads have forked;
    # the dump says which, so a live run can tell from the logs alone.
    prop, obs = four[0], four[3]
    rp, q = _placing(obs, four)
    monkeypatch.setenv('AT_REP_DUMP_SEC', '1')

    def dumped():
        rp.logger = MagicMock()
        rp._last_rep_dump = 0
        rp._dump_reputation_trace(1e9)
        [call] = [c for c in rp.logger.info.call_args_list
                  if c.args[0] == 'AT_REPDUMP %s']
        return json.loads(call.args[1])['chain']

    before = dumped()
    e = _entry(four, four[1], four[2])
    value = _value(e)
    _placed(rp, q, prop, value, _certify(value, 0, b'', four[:3]))
    after = dumped()
    assert after['len'] == before['len'] + 1 == rp.history.next_index
    assert after['head'] == rp.history.head_hash.hex()[:16]
    assert after['head'] != before['head']
