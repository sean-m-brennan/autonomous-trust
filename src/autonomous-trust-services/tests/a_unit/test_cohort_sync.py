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
"""The roster-sync seam shared by the stream receivers.

Its own module deliberately: the mixin needs no cv2, and living in
test_video_service.py meant it skipped entirely wherever OpenCV is absent.
"""
from unittest.mock import MagicMock


class TestCohortSyncMixin:
    def _proc(self, cohort):
        from autonomous_trust.services.cohort_sync import CohortSyncMixin

        class _P(CohortSyncMixin):
            name = 'video-sink'
            logger = MagicMock()
        p = _P()
        p.cohort = cohort
        return p

    def test_subscribe_registers_under_the_process_name(self):
        cohort = MagicMock()
        cohort.subscribe.return_value = 4
        assert self._proc(cohort).subscribe_to_cohort() == 4
        cohort.subscribe.assert_called_once_with('video-sink')

    def test_sync_drains_this_consumers_channel(self):
        cohort = MagicMock()
        self._proc(cohort).sync_cohort()
        cohort.acquire_data.assert_called_once_with('video-sink')

    def test_a_cohort_without_a_delta_channel_is_tolerated(self):
        """SimCohort and the mocks have no subscribe/consumer-aware drain."""
        bare = object()
        p = self._proc(bare)
        assert p.subscribe_to_cohort() is None
        p.sync_cohort()                       # must not raise

    def test_a_consumerless_acquire_data_is_tolerated(self):
        cohort = MagicMock()
        cohort.acquire_data.side_effect = TypeError('takes no arguments')
        self._proc(cohort).sync_cohort()      # must not raise

    def test_a_failing_sync_is_logged_not_raised(self):
        cohort = MagicMock()
        cohort.acquire_data.side_effect = RuntimeError('manager gone')
        p = self._proc(cohort)
        p.sync_cohort()
        assert p.logger.warning.called
