# ******************
#  Copyright 2024 TekFive, Inc. and contributors
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

import pytest

from autonomous_trust.core.network.ping import PingServer, ping
from autonomous_trust.core.network.async_ping import AsyncPingServer, async_ping


@pytest.mark.asyncio
async def test_async_ping():
    server = await AsyncPingServer('127.0.0.1')
    stats = await async_ping('127.0.0.1')
    server.close()
    assert stats.count == 1
    assert stats.min == stats.avg == stats.max
    assert stats.loss == 0.0


def test_ping_n():
    server = PingServer('127.0.0.1')
    server.start()
    count = 10
    stats = ping('127.0.0.1', count=count)
    server.stop()
    assert stats.count == count
    assert stats.min <= stats.avg <= stats.max
    assert stats.loss == 0.0
