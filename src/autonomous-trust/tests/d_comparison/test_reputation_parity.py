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

"""Compare native (C-backed) reputation operations."""

import uuid
import pytest

from .conftest import requires_native


@requires_native
class TestReputationParity:
    """Verify native reputation types work correctly."""

    def test_transaction_history_crud(self):
        """TransactionHistory: create, update, len."""
        from autonomous_trust.core._native.reputation import (
            NativeTransactionHistory as TransactionHistory,
        )

        hist = TransactionHistory()
        assert len(hist) == 0

        task_id = uuid.uuid4()
        peer_id = uuid.uuid4()

        hist.update(task_id, peer_id, 0.8)
        assert len(hist) == 1

        # Second update to same task creates a second slot in the transaction
        peer2 = uuid.uuid4()
        hist.update(task_id, peer2, 0.6)
        assert len(hist) == 1  # still 1 transaction, just with both peers

        # New task
        task2 = uuid.uuid4()
        hist.update(task2, peer_id, 0.9)
        assert len(hist) == 2

    def test_reputations_crud(self):
        """Reputations: create, update, get, contains."""
        from autonomous_trust.core._native.reputation import (
            NativeReputations as Reputations,
        )

        reps = Reputations()

        peer = uuid.uuid4()
        assert not reps.contains(peer)

        reps.update(peer, 0.75)
        assert reps.contains(peer)

        # Note: C stores as float internally, so precision is ~7 digits
        score = reps.get(peer)
        assert abs(score - 0.75) < 0.001

        # Update to new value
        reps.update(peer, 0.9)
        score = reps.get(peer)
        assert abs(score - 0.9) < 0.001

    def test_reputation_compute_default(self):
        """Default reputation for unknown peer is 0.5 (neutral)."""
        from autonomous_trust.core._native.reputation import (
            NativeTransactionHistory as TransactionHistory,
            NativeReputations as Reputations,
            native_reputation_compute as reputation_compute,
        )

        hist = TransactionHistory()
        reps = Reputations()

        self_id = uuid.uuid4()
        peer_id = uuid.uuid4()

        score = reputation_compute(hist, reps, self_id, peer_id)
        # No history → contrite TFT → 0.49
        assert abs(score - 0.49) < 0.01

    def test_reputation_compute_with_history(self):
        """Reputation after recording transactions."""
        from autonomous_trust.core._native.reputation import (
            NativeTransactionHistory as TransactionHistory,
            NativeReputations as Reputations,
            native_reputation_compute as reputation_compute,
        )

        hist = TransactionHistory()
        reps = Reputations()

        self_id = uuid.uuid4()
        peer_id = uuid.uuid4()
        task_id = uuid.uuid4()

        # Record a cooperative transaction
        hist.update(task_id, peer_id, 0.8)
        hist.update(task_id, self_id, 0.9)

        # Set initial reputation above trust threshold
        reps.update(peer_id, 0.7)
        reps.update(self_id, 0.8)

        score = reputation_compute(hist, reps, self_id, peer_id)
        # Trusted peer → uses pure socially-weighted average
        assert 0.0 <= score <= 1.0


@requires_native
class TestNegotiationParity:
    """Verify native negotiation types work correctly."""

    def test_job_queue_lifecycle(self):
        """JobQueue: create, count, clear."""
        from autonomous_trust.core._native.negotiation import (
            NativeJobQueue as JobQueue,
        )

        jq = JobQueue()
        assert len(jq) == 0

        jq.clear()
        assert len(jq) == 0

    def test_task_tracker_lifecycle(self):
        """TaskTracker: create, set_result, result_count."""
        from autonomous_trust.core._native.negotiation import (
            NativeTaskTracker as TaskTracker,
        )

        task_id = uuid.uuid4()
        tt = TaskTracker(task_id.bytes, expected=3)
        assert tt.result_count == 0

        peer1 = uuid.uuid4()
        tt.set_result(peer1.bytes, b'result from peer 1')
        assert tt.result_count == 1

        peer2 = uuid.uuid4()
        tt.set_result(peer2.bytes, b'result from peer 2')
        assert tt.result_count == 2
