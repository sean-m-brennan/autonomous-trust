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
"""The reputation task id for one requester-executor pair (ISSUES §2.50),
pinned with C's rep_attest_test test_pair_task_uuid_vector."""

from uuid import UUID

from autonomous_trust.core.reputation.reputation import pair_task_id

T = '11111111-1111-4111-8111-111111111111'
E = '22222222-2222-4222-8222-222222222222'


def test_the_pinned_vector():
    assert pair_task_id(T, E) == UUID('b783de4b-0f50-510f-81e3-d574b9f4db8f')
    assert pair_task_id(UUID(T), UUID(E)) == pair_task_id(T.upper(), E)


def test_each_executor_has_its_own_task():
    assert pair_task_id(T, E) != pair_task_id(E, T)
    assert pair_task_id(T, E) != pair_task_id(T, T)
