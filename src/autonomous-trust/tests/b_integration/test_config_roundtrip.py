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
import os
import pytest
from uuid import uuid4
import secrets

from autonomous_trust.core.config import Configuration
from autonomous_trust.core.identity import Identity, Peers, Signature, Encryptor
from autonomous_trust.core.reputation.reputation import (
    Transaction, TransactionHistory, Reputation, Reputations,
)
from autonomous_trust.core.negotiation.negotiation import TaskParameters, Task
from autonomous_trust.core.processes import ProcessTracker
from autonomous_trust.core.network.message import Message

from .. import TEST_DIR


def _random_identity():
    seed = secrets.token_hex(32)
    return Identity(uuid4(), '127.0.0.1', 'full name', Signature(seed), None, 'nick')


class TestConfigRoundtrip:
    def test_identity_yaml_roundtrip(self, setup_teardown):
        t1 = Identity.initialize('me.myself.i', 'myself', '127.0.0.1')
        filepath = os.path.join(TEST_DIR, 'rt_identity')
        t1.to_file(filepath)
        t2 = Configuration.from_file(filepath)
        assert repr(t1) == repr(t2)

    def test_peers_yaml_roundtrip(self, setup_teardown):
        peers = Peers()
        p1 = Identity(uuid4(), '10.0.0.1', 'peer1', Signature.generate(), Encryptor.generate(), 'p1')
        p2 = Identity(uuid4(), '10.0.0.2', 'peer2', Signature.generate(), Encryptor.generate(), 'p2')
        peers.add(p1)
        peers.add(p2)
        filepath = os.path.join(TEST_DIR, 'rt_peers')
        peers.to_file(filepath)
        loaded = Configuration.from_file(filepath)
        assert repr(peers) == repr(loaded)


class TestTransactionHistoryWorkflow:
    def test_full_workflow(self):
        history = TransactionHistory()
        p1, p2, p3 = uuid4(), uuid4(), uuid4()

        # Create transactions
        for i in range(5):
            tid = uuid4()
            history.update(tid, p1, 0.8 + i * 0.02)
            history.update(tid, p2, 0.7 + i * 0.03)

        assert len(history) == 5

        # Check by_peer - each update call for p1 maps the tx
        p1_txs = history.by_peer(p1)
        assert len(p1_txs) >= 5

        # Reputations
        reps = Reputations()
        reps.update(p1, 0.9)
        reps.update(p2, 0.85)
        assert p1 in reps
        assert reps[p1] == 0.9


class TestProcessTrackerRoundtrip:
    def test_yaml_roundtrip(self):
        pt = ProcessTracker()
        pt.register_subsystem('network', 'autonomous_trust.core.network.UDPNetworkProcess')
        yml = pt.to_yaml_string()
        pt2 = ProcessTracker()
        pt2.from_yaml_string(yml)
        assert len(pt2) == len(pt)
        assert 'network' in pt2


class TestMessageRoundtrip:
    def test_str_roundtrip(self):
        msg = Message('negotiation', 'start_task', 'task_data')
        raw = str(msg)
        parsed = Message.parse(raw, None, validate=False)
        assert parsed.process == 'negotiation'
        assert parsed.function == 'start_task'
        assert parsed.obj == 'task_data'

    def test_bytes_roundtrip(self):
        msg = Message('reputation', 'handle_request', 'score_data')
        raw = bytes(msg)
        parsed = Message.parse(raw, None, validate=False)
        assert parsed.process == 'reputation'
        assert parsed.function == 'handle_request'

    def test_with_identity_sender(self, setup_teardown):
        sender = _random_identity()
        msg = Message('proc', 'func', 'data', from_whom=sender)
        raw = str(msg)
        parsed = Message.parse(raw, sender)
        assert parsed.from_whom is sender
