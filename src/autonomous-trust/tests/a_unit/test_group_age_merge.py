# ******************
#  Copyright 2025 Sean M. Brennan and contributors
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
"""Adopt the older/larger group on merge — ISSUES.md §3.1-b.

Membership size stays the PRIMARY merge signal (handled elsewhere / unchanged);
on a size TIE between different groups the OLDER group (smaller `created`
epoch) now wins, so the more-established group absorbs the younger one. When
neither carries a known age the merge falls back to the historical uuid
tiebreaker (deterministic, flood-safe). The group key rides along via the
existing wholesale-adopt-when-keyed path in handle_group_update.
"""
import logging
from unittest.mock import MagicMock

from autonomous_trust.core.identity import Identity, Peers, Group
from autonomous_trust.core.identity.encrypt import Encryptor
from autonomous_trust.core.identity.idprocess import IdentityProcess
from autonomous_trust.core.identity.protocol import IdentityProtocol
from autonomous_trust.core.network import Message
from autonomous_trust.core.system import CfgIds


def _keyed_group(uuid_str, addr_map, nick, created):
    return Group(uuid_str, dict(addr_map), nick, Encryptor.generate(),
                 _public_only=False, _created=created)


def _build_process(group):
    proc = object.__new__(IdentityProcess)
    proc.group = group
    proc.peers = Peers()
    proc.name = CfgIds.identity
    proc.logger = logging.getLogger('test.group.age')
    proc.q_cadence = 0.01
    proc.phase = 3
    proc._partition_recovery_in_progress = None
    proc._partition_probe_cooldown = {}
    proc._record_group = MagicMock()
    proc._update_group = MagicMock()
    return proc


def _update_msg(group):
    msg = MagicMock()
    msg.function = IdentityProtocol.update
    msg.obj = group  # non-str -> used directly by handle_group_update
    return msg


class TestGroupAgeMerge:
    def test_size_tie_older_wins(self):
        """Different groups, equal membership size: adopt theirs iff older."""
        mine = _keyed_group('11111111-1111-1111-1111-111111111111',
                            {'u1': '10.0.0.1'}, 'mine', created=200.0)
        theirs = _keyed_group('99999999-9999-9999-9999-999999999999',
                              {'u2': '10.0.0.2'}, 'theirs', created=100.0)
        proc = _build_process(mine)
        proc.handle_group_update({CfgIds.network: MagicMock()}, _update_msg(theirs))
        # theirs is OLDER (100 < 200) -> adopted, key and all
        assert proc.group.uuid == theirs.uuid
        assert proc.group.owns_private_key

    def test_size_tie_younger_loses(self):
        mine = _keyed_group('99999999-9999-9999-9999-999999999999',
                            {'u1': '10.0.0.1'}, 'mine', created=100.0)
        theirs = _keyed_group('11111111-1111-1111-1111-111111111111',
                              {'u2': '10.0.0.2'}, 'theirs', created=300.0)
        proc = _build_process(mine)
        proc.handle_group_update({CfgIds.network: MagicMock()}, _update_msg(theirs))
        # theirs is YOUNGER -> we keep ours (even though its uuid is larger,
        # which would have won under the pure-uuid tiebreak — proves age wins)
        assert proc.group.uuid == mine.uuid

    def test_size_tie_no_age_falls_back_to_uuid(self):
        """Ages absent (0.0): the historical uuid tiebreaker decides."""
        mine = _keyed_group('99999999-9999-9999-9999-999999999999',
                            {'u1': '10.0.0.1'}, 'mine', created=0.0)
        theirs = _keyed_group('11111111-1111-1111-1111-111111111111',
                              {'u2': '10.0.0.2'}, 'theirs', created=0.0)
        proc = _build_process(mine)
        proc.handle_group_update({CfgIds.network: MagicMock()}, _update_msg(theirs))
        # smaller uuid wins -> theirs (1111... < 9999...)
        assert proc.group.uuid == theirs.uuid

    def test_larger_beats_older(self):
        """Size is primary: a LARGER younger group still wins over a smaller
        older one."""
        mine = _keyed_group('11111111-1111-1111-1111-111111111111',
                            {'u1': '10.0.0.1'}, 'mine', created=1.0)  # old, small
        theirs = _keyed_group('99999999-9999-9999-9999-999999999999',
                              {'u2': '10.0.0.2', 'u3': '10.0.0.3'}, 'theirs',
                              created=999.0)  # young, larger
        proc = _build_process(mine)
        proc.handle_group_update({CfgIds.network: MagicMock()}, _update_msg(theirs))
        assert proc.group.uuid == theirs.uuid

    def test_created_round_trips_through_canonical(self):
        g = _keyed_group('22222222-2222-2222-2222-222222222222',
                         {'u1': '10.0.0.1'}, 'g', created=1234.5)
        restored = Group.from_canonical(g.to_canonical())
        assert restored.created == 1234.5
