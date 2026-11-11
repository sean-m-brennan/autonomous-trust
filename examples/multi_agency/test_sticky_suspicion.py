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

"""An anomaly makes the coordinator suspect its sender for a while.

The compromised sensor lies on several data types, but the validators catch
only an occasional temperature reading, so judging each batch alone scored
nearly all of its batches clean and its reputation never fell. After an
anomaly, every batch the sender's coordinator first sees within the
suspicion window is scored as anomalous, whatever its data type; batches
from other peers, and the sender's batches after the window, are not.

Run from the repo root:
    pytest examples/multi_agency/test_sticky_suspicion.py
"""
import collections
from types import SimpleNamespace
from uuid import uuid4

from autonomous_trust.core import CfgIds

from examples.multi_agency.coordinator import MultiAgencyCoordinator


class _Queue:
    def __init__(self):
        self.items = []

    def put(self, item, block=True, timeout=None):
        self.items.append(item)


def _coordinator():
    c = object.__new__(MultiAgencyCoordinator)
    c.identity = SimpleNamespace(uuid=uuid4())
    c._batch_state = {}
    c._batch_settle_ticks = 4
    c._ts_decimation = 1
    c._verdict_counts = collections.Counter()
    c._suspect_until = {}
    c._suspicion_ticks = 120
    c._tick_count = 0
    return c


def _batch(c, peer, first_tick, sender, anomalous=False):
    batch_id = str(uuid4())
    c._batch_state[batch_id] = {
        "submitted": False, "anomalous": anomalous, "first_tick": first_tick,
        "peer_name": peer, "sender_uuid": sender}
    return batch_id


def test_anomaly_taints_the_senders_batches_for_the_window():
    c = _coordinator()
    rogue, honest = uuid4(), uuid4()
    c._tick_count = 10
    c._mark_suspect("noaa-3")
    _batch(c, "noaa-3", 10, rogue, anomalous=True)
    _batch(c, "noaa-3", 60, rogue)                 # clean, inside the window
    _batch(c, "noaa-1", 60, honest)                # another peer
    _batch(c, "noaa-3", 10 + 120 + 1, rogue)       # clean, after the window
    c._tick_count = 10 + 120 + 1 + 4               # every batch settled
    q = _Queue()
    c._maybe_submit_batch_scores({CfgIds.reputation: q})

    by_subject = collections.defaultdict(list)
    for ts in q.items:
        by_subject[ts.subject_uuid].append(round(ts.score, 1))
    # TransactionScore carries the subject as a string.
    assert sorted(by_subject[str(rogue)]) == [0.3, 0.3, 0.8]
    assert by_subject[str(honest)] == [0.8]


def test_a_new_anomaly_extends_the_window():
    c = _coordinator()
    c._tick_count = 10
    c._mark_suspect("noaa-3")
    c._tick_count = 100
    c._mark_suspect("noaa-3")
    assert c._suspect_until["noaa-3"] == 100 + 120
