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

"""Keep a stream receiver's view of the cohort roster current.

A receiver (video, data) writes an inbound payload into the peer's stream queue,
which means it must first know which peer that is — and the roster it looks up
does NOT cross the process boundary on its own. One Cohort is constructed in the
parent and handed to the DAQ tracker, the receivers and the UI; each worker is
then pickled into its own process, so ``cohort.peers`` is a separate plain dict
per process. The tracker populates its own copy and the receivers' stayed empty,
so `if uuid in self.cohort.peers` was false for every payload and every frame was
dropped in silence.

The owner publishes roster deltas over pooled (pre-fork, manager-backed) queues,
one channel per consumer, because a queue has exactly one consumer. A receiver
subscribes under its own process name — from ``__init__``, which still runs in the
parent — and drains that channel on each pass of its loop.

See ``inspector/peer/daq.py`` (Cohort) and
``doc/architecture/`` for the wider design.
"""


class CohortSyncMixin(object):
    """Mixin for a Process that writes into per-peer cohort streams."""

    def subscribe_to_cohort(self):
        """Claim this process's delta channel. Call from ``__init__`` ONLY.

        The slot index must be recorded before the fork, or the copy that lands
        in the worker will not know about the channel. Tolerates a cohort
        implementation that has no delta channel (mocks, SimCohort).
        """
        subscribe = getattr(getattr(self, 'cohort', None), 'subscribe', None)
        if subscribe is None:
            return None
        try:
            return subscribe(self.name)
        except Exception as err:                                    # noqa: BLE001
            self.logger.warning('No cohort delta channel for %s: %s'
                                % (self.name, err))
            return None

    def sync_cohort(self):
        """Apply any roster deltas published since the last pass.

        Cheap when idle: an empty channel is one non-blocking get. Failure is
        logged, never raised — a receiver that cannot refresh its roster should
        keep serving the peers it already knows.
        """
        acquire = getattr(getattr(self, 'cohort', None), 'acquire_data', None)
        if acquire is None:
            return
        try:
            acquire(self.name)
        except TypeError:
            # A cohort whose acquire_data takes no consumer argument (SimCohort);
            # it has no delta channel to drain either.
            pass
        except Exception as err:                                    # noqa: BLE001
            self.logger.warning('Cohort roster sync failed for %s: %s'
                                % (self.name, err))
