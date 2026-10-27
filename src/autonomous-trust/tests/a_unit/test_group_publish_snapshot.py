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

"""IdentityProcess publishes its Group to the other processes as a snapshot.

With ``multiproc=False`` the process queues are plain ``queue.Queue`` objects
that carry references, so publishing ``self.group`` itself handed the network
thread the very object identity keeps mutating. Admission queues
``full_history`` to the joiner and only then calls ``group.add_address`` for
it; the network thread, encoding that already-queued message, could see the
joiner in the shared address map and pick the group's proto format for a node
that holds no group yet and reads JSON only. The joiner refused the frame and
minted its own group, so a proto-format cohort could not admit anyone live.
Multiproc mode pickles every queued object, which is why it never raced.
"""

import logging
import os
import threading
from uuid import uuid4

import pytest

from autonomous_trust.core.config import Configuration
from autonomous_trust.core.identity import Group
from autonomous_trust.core.identity.encrypt import Encryptor
from autonomous_trust.core.identity.idprocess import IdentityProcess
from autonomous_trust.core.system import CfgIds


class _History:
    """The history half of the saved pair; only its serialized form is read."""
    def to_dict(self):
        return {}


class _FakeQueue:
    def __init__(self):
        self.items = []

    def put(self, item, block=True, timeout=None):
        self.items.append(item)


@pytest.fixture
def proc(monkeypatch, tmp_path):
    monkeypatch.setenv(Configuration.ROOT_VARIABLE_NAME, str(tmp_path))
    os.makedirs(Configuration.get_cfg_dir(), exist_ok=True)
    p = object.__new__(IdentityProcess)
    p.name = CfgIds.identity
    p.logger = logging.getLogger('test.idproc.groupsnapshot')
    p.q_cadence = 0.01
    p.lock = threading.Lock()
    p.configs = {}
    return p


def _group():
    return Group(uuid4(), {str(uuid4()): '10.0.0.1'}, 'g',
                 Encryptor(b'ab' * 32, public_only=False),
                 _public_only=False, _wire_format='proto')


def test_a_later_add_address_does_not_reach_the_published_group(proc):
    group = _group()
    queues = {CfgIds.identity: _FakeQueue(), CfgIds.network: _FakeQueue()}

    proc._remember_activity(queues, CfgIds.group, (group, _History()))
    published = queues[CfgIds.network].items[-1]
    group.add_address(str(uuid4()), '10.0.0.2')

    assert isinstance(published, Group)
    assert published is not group
    assert '10.0.0.2' not in published.addresses
    assert published.wire_format_for_address('10.0.0.2') == 'json'


def test_the_published_group_carries_the_state_at_publish_time(proc):
    group = _group()
    queues = {CfgIds.identity: _FakeQueue(), CfgIds.network: _FakeQueue()}

    proc._remember_activity(queues, CfgIds.group, (group, _History()))
    published = queues[CfgIds.network].items[-1]

    assert published == group
    assert list(published.addresses) == list(group.addresses)
    assert published.wire_format == 'proto'
    assert published.key_epoch == group.key_epoch
    assert published.owns_private_key
